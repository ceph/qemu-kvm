/*
 * qemu/kvm integration
 *
 * Copyright (C) 2006-2008 Qumranet Technologies
 *
 * Licensed under the terms of the GNU GPL version 2 or higher.
 */
#include "config.h"
#include "config-host.h"

int kvm_allowed = 1;
int kvm_irqchip = 1;
int kvm_pit = 1;

#include <string.h>
#include "hw/hw.h"
#include "sysemu.h"
#include "qemu-common.h"
#include "console.h"
#include "block.h"

#include "qemu-kvm.h"
#include <libkvm.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <sys/syscall.h>

extern void perror(const char *s);

kvm_context_t kvm_context;

extern int smp_cpus;

static int qemu_kvm_reset_requested;

pthread_mutex_t qemu_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t qemu_aio_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t qemu_vcpu_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t qemu_system_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t qemu_pause_cond = PTHREAD_COND_INITIALIZER;
__thread struct vcpu_info *vcpu;

static int qemu_system_ready;

#define SIG_IPI (SIGRTMIN+4)

struct vcpu_info {
    CPUState *env;
    int sipi_needed;
    int init;
    pthread_t thread;
    int signalled;
    int stop;
    int stopped;
    int reload_regs;
    int created;
} vcpu_info[256];

pthread_t io_thread;
static int io_thread_fd = -1;
static int io_thread_sigfd = -1;

static inline unsigned long kvm_get_thread_id(void)
{
    return syscall(SYS_gettid);
}

CPUState *qemu_kvm_cpu_env(int index)
{
    return vcpu_info[index].env;
}

static void sig_ipi_handler(int n)
{
}

void kvm_update_interrupt_request(CPUState *env)
{
    int signal = 0;

    if (env) {
        if (!vcpu)
            signal = 1;
        if (vcpu && env != vcpu->env && !vcpu_info[env->cpu_index].signalled)
            signal = 1;

        if (signal) {
            vcpu_info[env->cpu_index].signalled = 1;
                if (vcpu_info[env->cpu_index].thread)
                    pthread_kill(vcpu_info[env->cpu_index].thread, SIG_IPI);
        }
    }
}

void kvm_update_after_sipi(CPUState *env)
{
    vcpu_info[env->cpu_index].sipi_needed = 1;
    kvm_update_interrupt_request(env);
}

void kvm_apic_init(CPUState *env)
{
    if (env->cpu_index != 0)
	vcpu_info[env->cpu_index].init = 1;
    kvm_update_interrupt_request(env);
}

#include <signal.h>

static int try_push_interrupts(void *opaque)
{
    return kvm_arch_try_push_interrupts(opaque);
}

static void post_kvm_run(void *opaque, int vcpu)
{

    pthread_mutex_lock(&qemu_mutex);
    kvm_arch_post_kvm_run(opaque, vcpu);
}

static int pre_kvm_run(void *opaque, int vcpu)
{
    CPUState *env = qemu_kvm_cpu_env(vcpu);

    kvm_arch_pre_kvm_run(opaque, vcpu);

    if (env->interrupt_request & CPU_INTERRUPT_EXIT)
	return 1;
    pthread_mutex_unlock(&qemu_mutex);
    return 0;
}

void kvm_load_registers(CPUState *env)
{
    if (kvm_enabled())
	kvm_arch_load_regs(env);
}

void kvm_save_registers(CPUState *env)
{
    if (kvm_enabled())
	kvm_arch_save_regs(env);
}

int kvm_cpu_exec(CPUState *env)
{
    int r;

    r = kvm_run(kvm_context, env->cpu_index);
    if (r < 0) {
        printf("kvm_run returned %d\n", r);
        exit(1);
    }

    return 0;
}

extern int vm_running;

static int has_work(CPUState *env)
{
    if (!vm_running || (env && vcpu_info[env->cpu_index].stopped))
	return 0;
    if (!(env->hflags & HF_HALTED_MASK))
	return 1;
    return kvm_arch_has_work(env);
}

static int kvm_eat_signal(CPUState *env, int timeout)
{
    struct timespec ts;
    int r, e, ret = 0;
    siginfo_t siginfo;
    sigset_t waitset;

    ts.tv_sec = timeout / 1000;
    ts.tv_nsec = (timeout % 1000) * 1000000;
    sigemptyset(&waitset);
    sigaddset(&waitset, SIG_IPI);

    r = sigtimedwait(&waitset, &siginfo, &ts);
    if (r == -1 && (errno == EAGAIN || errno == EINTR) && !timeout)
	return 0;
    e = errno;

    pthread_mutex_lock(&qemu_mutex);
    if (env && vcpu)
        cpu_single_env = vcpu->env;
    if (r == -1 && !(errno == EAGAIN || errno == EINTR)) {
	printf("sigtimedwait: %s\n", strerror(e));
	exit(1);
    }
    if (r != -1)
	ret = 1;

    if (env && vcpu_info[env->cpu_index].stop) {
	vcpu_info[env->cpu_index].stop = 0;
	vcpu_info[env->cpu_index].stopped = 1;
	pthread_cond_signal(&qemu_pause_cond);
    }
    pthread_mutex_unlock(&qemu_mutex);

    return ret;
}


static void kvm_eat_signals(CPUState *env, int timeout)
{
    int r = 0;

    while (kvm_eat_signal(env, 0))
	r = 1;
    if (!r && timeout) {
	r = kvm_eat_signal(env, timeout);
	if (r)
	    while (kvm_eat_signal(env, 0))
		;
    }
}

static void kvm_main_loop_wait(CPUState *env, int timeout)
{
    pthread_mutex_unlock(&qemu_mutex);
    kvm_eat_signals(env, timeout);
    pthread_mutex_lock(&qemu_mutex);
    cpu_single_env = env;
    vcpu_info[env->cpu_index].signalled = 0;
}

static int all_threads_paused(void)
{
    int i;

    for (i = 0; i < smp_cpus; ++i)
	if (vcpu_info[i].stop)
	    return 0;
    return 1;
}

static void pause_all_threads(void)
{
    int i;

    for (i = 0; i < smp_cpus; ++i) {
	vcpu_info[i].stop = 1;
	pthread_kill(vcpu_info[i].thread, SIG_IPI);
    }
    while (!all_threads_paused()) {
	CPUState *env = cpu_single_env;
	pthread_cond_wait(&qemu_pause_cond, &qemu_mutex);
	cpu_single_env = env;
    }
}

static void resume_all_threads(void)
{
    int i;

    for (i = 0; i < smp_cpus; ++i) {
	vcpu_info[i].stop = 0;
	vcpu_info[i].stopped = 0;
	pthread_kill(vcpu_info[i].thread, SIG_IPI);
    }
}

static void kvm_vm_state_change_handler(void *context, int running)
{
    if (running)
	resume_all_threads();
    else
	pause_all_threads();
}

static void update_regs_for_sipi(CPUState *env)
{
    kvm_arch_update_regs_for_sipi(env);
    vcpu_info[env->cpu_index].sipi_needed = 0;
    vcpu_info[env->cpu_index].init = 0;
}

static void update_regs_for_init(CPUState *env)
{
    cpu_reset(env);
    kvm_arch_load_regs(env);
}

static void setup_kernel_sigmask(CPUState *env)
{
    sigset_t set;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGALRM);
    sigprocmask(SIG_BLOCK, &set, NULL);

    sigprocmask(SIG_BLOCK, NULL, &set);
    sigdelset(&set, SIG_IPI);
    
    kvm_set_signal_mask(kvm_context, env->cpu_index, &set);
}

void qemu_kvm_system_reset_request(void)
{
    int i;

    for (i = 0; i < smp_cpus; ++i) {
	vcpu_info[i].reload_regs = 1;
	pthread_kill(vcpu_info[i].thread, SIG_IPI);
    }
    qemu_system_reset();
}

static int kvm_main_loop_cpu(CPUState *env)
{
    struct vcpu_info *info = &vcpu_info[env->cpu_index];

    setup_kernel_sigmask(env);

    pthread_mutex_lock(&qemu_mutex);
    if (kvm_irqchip_in_kernel(kvm_context))
	env->hflags &= ~HF_HALTED_MASK;

    kvm_qemu_init_env(env);
    env->ready_for_interrupt_injection = 1;
#ifdef TARGET_I386
    kvm_tpr_vcpu_start(env);
#endif

    cpu_single_env = env;
    while (1) {
	while (!has_work(env))
	    kvm_main_loop_wait(env, 1000);
	if (env->interrupt_request & CPU_INTERRUPT_HARD)
	    env->hflags &= ~HF_HALTED_MASK;
	if (!kvm_irqchip_in_kernel(kvm_context) && info->sipi_needed)
	    update_regs_for_sipi(env);
	if (!kvm_irqchip_in_kernel(kvm_context) && info->init)
	    update_regs_for_init(env);
	if (!(env->hflags & HF_HALTED_MASK) && !info->init)
	    kvm_cpu_exec(env);
	env->interrupt_request &= ~CPU_INTERRUPT_EXIT;
	kvm_main_loop_wait(env, 0);
        if (info->reload_regs) {
	    info->reload_regs = 0;
	    if (env->cpu_index == 0) /* ap needs to be placed in INIT */
		kvm_arch_load_regs(env);
	}
    }
    pthread_mutex_unlock(&qemu_mutex);
    return 0;
}

static void *ap_main_loop(void *_env)
{
    CPUState *env = _env;
    sigset_t signals;

    vcpu = &vcpu_info[env->cpu_index];
    vcpu->env = env;
    vcpu->env->thread_id = kvm_get_thread_id();
    sigfillset(&signals);
    sigprocmask(SIG_BLOCK, &signals, NULL);
    kvm_create_vcpu(kvm_context, env->cpu_index);
    kvm_qemu_init_env(env);

    /* signal VCPU creation */
    pthread_mutex_lock(&qemu_mutex);
    vcpu->created = 1;
    pthread_cond_signal(&qemu_vcpu_cond);

    /* and wait for machine initialization */
    while (!qemu_system_ready)
	pthread_cond_wait(&qemu_system_cond, &qemu_mutex);
    pthread_mutex_unlock(&qemu_mutex);

    kvm_main_loop_cpu(env);
    return NULL;
}

void kvm_init_new_ap(int cpu, CPUState *env)
{
    pthread_create(&vcpu_info[cpu].thread, NULL, ap_main_loop, env);

    while (vcpu_info[cpu].created == 0)
	pthread_cond_wait(&qemu_vcpu_cond, &qemu_mutex);
}

int kvm_init_ap(void)
{
#ifdef TARGET_I386
    kvm_tpr_opt_setup();
#endif
    qemu_add_vm_change_state_handler(kvm_vm_state_change_handler, NULL);

    signal(SIG_IPI, sig_ipi_handler);
    return 0;
}

void qemu_kvm_notify_work(void)
{
    uint64_t value = 1;
    char buffer[8];
    size_t offset = 0;

    if (io_thread_fd == -1)
	return;

    memcpy(buffer, &value, sizeof(value));

    while (offset < 8) {
	ssize_t len;

	len = write(io_thread_fd, buffer + offset, 8 - offset);
	if (len == -1 && errno == EINTR)
	    continue;

	if (len <= 0)
	    break;

	offset += len;
    }

    if (offset != 8)
	fprintf(stderr, "failed to notify io thread\n");
}

static int received_signal;

/* QEMU relies on periodically breaking out of select via EINTR to poll for IO
   and timer signals.  Since we're now using a file descriptor to handle
   signals, select() won't be interrupted by a signal.  We need to forcefully
   break the select() loop when a signal is received hence
   kvm_check_received_signal(). */

int kvm_check_received_signal(void)
{
    if (received_signal) {
	received_signal = 0;
	return 1;
    }

    return 0;
}

/* If we have signalfd, we mask out the signals we want to handle and then
 * use signalfd to listen for them.  We rely on whatever the current signal
 * handler is to dispatch the signals when we receive them.
 */

static void sigfd_handler(void *opaque)
{
    int fd = (unsigned long)opaque;
    struct signalfd_siginfo info;
    struct sigaction action;
    ssize_t len;

    while (1) {
	do {
	    len = read(fd, &info, sizeof(info));
	} while (len == -1 && errno == EINTR);

	if (len == -1 && errno == EAGAIN)
	    break;

	if (len != sizeof(info)) {
	    printf("read from sigfd returned %ld: %m\n", len);
	    return;
	}

	sigaction(info.ssi_signo, NULL, &action);
	if (action.sa_handler)
	    action.sa_handler(info.ssi_signo);

	if (info.ssi_signo == SIGUSR2) {
	    pthread_cond_signal(&qemu_aio_cond);
	}
    }

    received_signal = 1;
}

/* Used to break IO thread out of select */
static void io_thread_wakeup(void *opaque)
{
    int fd = (unsigned long)opaque;
    char buffer[8];
    size_t offset = 0;

    while (offset < 8) {
	ssize_t len;

	len = read(fd, buffer + offset, 8 - offset);
	if (len == -1 && errno == EINTR)
	    continue;

	if (len <= 0)
	    break;

	offset += len;
    }

    received_signal = 1;
}

int kvm_main_loop(void)
{
    int fds[2];
    sigset_t mask;
    int sigfd;

    io_thread = pthread_self();
    qemu_system_ready = 1;

    if (kvm_eventfd(fds) == -1) {
	fprintf(stderr, "failed to create eventfd\n");
	return -errno;
    }

    qemu_set_fd_handler2(fds[0], NULL, io_thread_wakeup, NULL,
			 (void *)(unsigned long)fds[0]);

    io_thread_fd = fds[1];

    sigemptyset(&mask);
    sigaddset(&mask, SIGIO);
    sigaddset(&mask, SIGALRM);
    sigaddset(&mask, SIGUSR2);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    sigfd = kvm_signalfd(&mask);
    if (sigfd == -1) {
	fprintf(stderr, "failed to create signalfd\n");
	return -errno;
    }

    fcntl(sigfd, F_SETFL, O_NONBLOCK);

    qemu_set_fd_handler2(sigfd, NULL, sigfd_handler, NULL,
			 (void *)(unsigned long)sigfd);

    pthread_cond_broadcast(&qemu_system_cond);

    io_thread_sigfd = sigfd;
    cpu_single_env = NULL;

    while (1) {
        main_loop_wait(1000);
        if (qemu_shutdown_requested())
            break;
        else if (qemu_powerdown_requested())
            qemu_system_powerdown();
        else if (qemu_reset_requested()) {
            pthread_kill(vcpu_info[0].thread, SIG_IPI);
            qemu_kvm_reset_requested = 1;
        }
    }

    pause_all_threads();
    pthread_mutex_unlock(&qemu_mutex);

    return 0;
}

static int kvm_debug(void *opaque, int vcpu)
{
    CPUState *env = cpu_single_env;

    env->exception_index = EXCP_DEBUG;
    return 1;
}

static int kvm_inb(void *opaque, uint16_t addr, uint8_t *data)
{
    *data = cpu_inb(0, addr);
    return 0;
}

static int kvm_inw(void *opaque, uint16_t addr, uint16_t *data)
{
    *data = cpu_inw(0, addr);
    return 0;
}

static int kvm_inl(void *opaque, uint16_t addr, uint32_t *data)
{
    *data = cpu_inl(0, addr);
    return 0;
}

#define PM_IO_BASE 0xb000

static int kvm_outb(void *opaque, uint16_t addr, uint8_t data)
{
    if (addr == 0xb2) {
	switch (data) {
	case 0: {
	    cpu_outb(0, 0xb3, 0);
	    break;
	}
	case 0xf0: {
	    unsigned x;

	    /* enable acpi */
	    x = cpu_inw(0, PM_IO_BASE + 4);
	    x &= ~1;
	    cpu_outw(0, PM_IO_BASE + 4, x);
	    break;
	}
	case 0xf1: {
	    unsigned x;

	    /* enable acpi */
	    x = cpu_inw(0, PM_IO_BASE + 4);
	    x |= 1;
	    cpu_outw(0, PM_IO_BASE + 4, x);
	    break;
	}
	default:
	    break;
	}
	return 0;
    }
    cpu_outb(0, addr, data);
    return 0;
}

static int kvm_outw(void *opaque, uint16_t addr, uint16_t data)
{
    cpu_outw(0, addr, data);
    return 0;
}

static int kvm_outl(void *opaque, uint16_t addr, uint32_t data)
{
    cpu_outl(0, addr, data);
    return 0;
}

static int kvm_mmio_read(void *opaque, uint64_t addr, uint8_t *data, int len)
{
	cpu_physical_memory_rw(addr, data, len, 0);
	return 0;
}

static int kvm_mmio_write(void *opaque, uint64_t addr, uint8_t *data, int len)
{
	cpu_physical_memory_rw(addr, data, len, 1);
	return 0;
}

static int kvm_io_window(void *opaque)
{
    return 1;
}

 
static int kvm_halt(void *opaque, int vcpu)
{
    return kvm_arch_halt(opaque, vcpu);
}

static int kvm_shutdown(void *opaque, int vcpu)
{
    qemu_system_reset_request();
    return 1;
}
 
static struct kvm_callbacks qemu_kvm_ops = {
    .debug = kvm_debug,
    .inb   = kvm_inb,
    .inw   = kvm_inw,
    .inl   = kvm_inl,
    .outb  = kvm_outb,
    .outw  = kvm_outw,
    .outl  = kvm_outl,
    .mmio_read = kvm_mmio_read,
    .mmio_write = kvm_mmio_write,
    .halt  = kvm_halt,
    .shutdown = kvm_shutdown,
    .io_window = kvm_io_window,
    .try_push_interrupts = try_push_interrupts,
    .post_kvm_run = post_kvm_run,
    .pre_kvm_run = pre_kvm_run,
#ifdef TARGET_I386
    .tpr_access = handle_tpr_access,
#endif
#ifdef TARGET_PPC
    .powerpc_dcr_read = handle_powerpc_dcr_read,
    .powerpc_dcr_write = handle_powerpc_dcr_write,
#endif
};

int kvm_qemu_init()
{
    /* Try to initialize kvm */
    kvm_context = kvm_init(&qemu_kvm_ops, cpu_single_env);
    if (!kvm_context) {
      	return -1;
    }
    pthread_mutex_lock(&qemu_mutex);

    return 0;
}

int kvm_qemu_create_context(void)
{
    int r;
    if (!kvm_irqchip) {
        kvm_disable_irqchip_creation(kvm_context);
    }
    if (!kvm_pit) {
        kvm_disable_pit_creation(kvm_context);
    }
    if (kvm_create(kvm_context, phys_ram_size, (void**)&phys_ram_base) < 0) {
	kvm_qemu_destroy();
	return -1;
    }
    r = kvm_arch_qemu_create_context();
    if(r <0)
	kvm_qemu_destroy();
    return 0;
}

void kvm_qemu_destroy(void)
{
    kvm_finalize(kvm_context);
}

void kvm_cpu_register_physical_memory(target_phys_addr_t start_addr,
                                      unsigned long size,
                                      unsigned long phys_offset)
{
#ifdef KVM_CAP_USER_MEMORY
    int r = 0;

    r = kvm_check_extension(kvm_context, KVM_CAP_USER_MEMORY);
    if (r) {
        if (!(phys_offset & ~TARGET_PAGE_MASK)) {
                r = kvm_is_allocated_mem(kvm_context, start_addr, size);
            if (r)
                return;
            r = kvm_is_intersecting_mem(kvm_context, start_addr);
            if (r)
                kvm_create_mem_hole(kvm_context, start_addr, size);
            r = kvm_register_userspace_phys_mem(kvm_context, start_addr,
                                                phys_ram_base + phys_offset,
                                                size, 0);
        }
        if (phys_offset & IO_MEM_ROM) {
            phys_offset &= ~IO_MEM_ROM;
            r = kvm_is_intersecting_mem(kvm_context, start_addr);
            if (r)
                kvm_create_mem_hole(kvm_context, start_addr, size);
            r = kvm_register_userspace_phys_mem(kvm_context, start_addr,
                                                phys_ram_base + phys_offset,
                                                size, 0);
        }
        if (r < 0) {
            printf("kvm_cpu_register_physical_memory: failed\n");
            exit(1);
        }
        return;
    }
#endif
    if (phys_offset & IO_MEM_ROM) {
        phys_offset &= ~IO_MEM_ROM;
        memcpy(phys_ram_base + start_addr, phys_ram_base + phys_offset, size);
    }
}

int kvm_qemu_check_extension(int ext)
{
    return kvm_check_extension(kvm_context, ext);
}

int kvm_qemu_init_env(CPUState *cenv)
{
    return kvm_arch_qemu_init_env(cenv);
}

int kvm_update_debugger(CPUState *env)
{
    struct kvm_debug_guest dbg;
    int i;

    dbg.enabled = 0;
    if (env->nb_breakpoints || env->singlestep_enabled) {
	dbg.enabled = 1;
	for (i = 0; i < 4 && i < env->nb_breakpoints; ++i) {
	    dbg.breakpoints[i].enabled = 1;
	    dbg.breakpoints[i].address = env->breakpoints[i];
	}
	dbg.singlestep = env->singlestep_enabled;
    }
    return kvm_guest_debug(kvm_context, env->cpu_index, &dbg);
}


/*
 * dirty pages logging
 */
/* FIXME: use unsigned long pointer instead of unsigned char */
unsigned char *kvm_dirty_bitmap = NULL;
int kvm_physical_memory_set_dirty_tracking(int enable)
{
    int r = 0;

    if (!kvm_enabled())
        return 0;

    if (enable) {
        if (!kvm_dirty_bitmap) {
            unsigned bitmap_size = BITMAP_SIZE(phys_ram_size);
            kvm_dirty_bitmap = qemu_malloc(bitmap_size);
            if (kvm_dirty_bitmap == NULL) {
                perror("Failed to allocate dirty pages bitmap");
                r=-1;
            }
            else {
                r = kvm_dirty_pages_log_enable_all(kvm_context);
            }
        }
    }
    else {
        if (kvm_dirty_bitmap) {
            r = kvm_dirty_pages_log_reset(kvm_context);
            qemu_free(kvm_dirty_bitmap);
            kvm_dirty_bitmap = NULL;
        }
    }
    return r;
}

/* get kvm's dirty pages bitmap and update qemu's */
int kvm_get_dirty_pages_log_range(unsigned long start_addr,
                                  unsigned char *bitmap,
                                  unsigned int offset,
                                  unsigned long mem_size)
{
    unsigned int i, j, n=0;
    unsigned char c;
    unsigned page_number, addr, addr1;
    unsigned int len = ((mem_size/TARGET_PAGE_SIZE) + 7) / 8;

    /* 
     * bitmap-traveling is faster than memory-traveling (for addr...) 
     * especially when most of the memory is not dirty.
     */
    for (i=0; i<len; i++) {
        c = bitmap[i];
        while (c>0) {
            j = ffsl(c) - 1;
            c &= ~(1u<<j);
            page_number = i * 8 + j;
            addr1 = page_number * TARGET_PAGE_SIZE;
            addr  = offset + addr1;
            cpu_physical_memory_set_dirty(addr);
            n++;
        }
    }
    return 0;
}
int kvm_get_dirty_bitmap_cb(unsigned long start, unsigned long len,
                            void *bitmap, void *opaque)
{
    return kvm_get_dirty_pages_log_range(start, bitmap, start, len);
}

/* 
 * get kvm's dirty pages bitmap and update qemu's
 * we only care about physical ram, which resides in slots 0 and 3
 */
int kvm_update_dirty_pages_log(void)
{
    int r = 0;


    r = kvm_get_dirty_pages_range(kvm_context, 0, phys_ram_size,
                                  kvm_dirty_bitmap, NULL,
                                  kvm_get_dirty_bitmap_cb);
    return r;
}

int kvm_get_phys_ram_page_bitmap(unsigned char *bitmap)
{
    unsigned int bsize  = BITMAP_SIZE(phys_ram_size);
    unsigned int brsize = BITMAP_SIZE(ram_size);
    unsigned int extra_pages = (phys_ram_size - ram_size) / TARGET_PAGE_SIZE;
    unsigned int extra_bytes = (extra_pages +7)/8;
    unsigned int hole_start = BITMAP_SIZE(0xa0000);
    unsigned int hole_end   = BITMAP_SIZE(0xc0000);

    memset(bitmap, 0xFF, brsize + extra_bytes);
    memset(bitmap + hole_start, 0, hole_end - hole_start);
    memset(bitmap + brsize + extra_bytes, 0, bsize - brsize - extra_bytes);

    return 0;
}

#ifdef KVM_CAP_IRQCHIP

int kvm_set_irq(int irq, int level)
{
    return kvm_set_irq_level(kvm_context, irq, level);
}

#endif

void qemu_kvm_aio_wait_start(void)
{
}

void qemu_kvm_aio_wait(void)
{
    CPUState *cpu_single = cpu_single_env;

    if (!cpu_single_env) {
	if (io_thread_sigfd != -1) {
	    fd_set rfds;
	    int ret;

	    FD_ZERO(&rfds);
	    FD_SET(io_thread_sigfd, &rfds);

	    /* this is a rare case where we do want to hold qemu_mutex
	     * while sleeping.  We cannot allow anything else to run
	     * right now. */
	    ret = select(io_thread_sigfd + 1, &rfds, NULL, NULL, NULL);
	    if (ret > 0 && FD_ISSET(io_thread_sigfd, &rfds))
		sigfd_handler((void *)(unsigned long)io_thread_sigfd);
	}
	qemu_aio_poll();
    } else {
        pthread_cond_wait(&qemu_aio_cond, &qemu_mutex);
        cpu_single_env = cpu_single;
    }
}

void qemu_kvm_aio_wait_end(void)
{
}

int qemu_kvm_get_dirty_pages(unsigned long phys_addr, void *buf)
{
    return kvm_get_dirty_pages(kvm_context, phys_addr, buf);
}

void *kvm_cpu_create_phys_mem(target_phys_addr_t start_addr,
			      unsigned long size, int log, int writable)
{
    return kvm_create_phys_mem(kvm_context, start_addr, size, log, writable);
}

void kvm_cpu_destroy_phys_mem(target_phys_addr_t start_addr,
			      unsigned long size)
{
    kvm_destroy_phys_mem(kvm_context, start_addr, size);
}

void kvm_mutex_unlock(void)
{
    pthread_mutex_unlock(&qemu_mutex);
}

void kvm_mutex_lock(void)
{
    pthread_mutex_lock(&qemu_mutex);
    cpu_single_env = NULL;
}
