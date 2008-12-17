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

#include <assert.h>
#include <string.h>
#include "hw/hw.h"
#include "sysemu.h"
#include "qemu-common.h"
#include "console.h"
#include "block.h"
#include "compatfd.h"
#include "gdbstub.h"

#include "qemu-kvm.h"
#include <libkvm.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#define false 0
#define true 1

extern void perror(const char *s);

kvm_context_t kvm_context;

extern int smp_cpus;

pthread_mutex_t qemu_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t qemu_vcpu_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t qemu_system_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t qemu_pause_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t qemu_work_cond = PTHREAD_COND_INITIALIZER;
__thread struct CPUState *current_env;

static int qemu_system_ready;

#define SIG_IPI (SIGRTMIN+4)

pthread_t io_thread;
static int io_thread_fd = -1;
static int io_thread_sigfd = -1;

static CPUState *kvm_debug_cpu_requested;

/* The list of ioperm_data */
static LIST_HEAD(, ioperm_data) ioperm_head;

static inline unsigned long kvm_get_thread_id(void)
{
    return syscall(SYS_gettid);
}

static void qemu_cond_wait(pthread_cond_t *cond)
{
    CPUState *env = cpu_single_env;
    static const struct timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 100000,
    };

    pthread_cond_timedwait(cond, &qemu_mutex, &ts);
    cpu_single_env = env;
}

static void sig_ipi_handler(int n)
{
}

static void on_vcpu(CPUState *env, void (*func)(void *data), void *data)
{
    struct qemu_work_item wi;

    if (env == current_env) {
        func(data);
        return;
    }

    wi.func = func;
    wi.data = data;
    if (!env->kvm_cpu_state.queued_work_first)
        env->kvm_cpu_state.queued_work_first = &wi;
    else
        env->kvm_cpu_state.queued_work_last->next = &wi;
    env->kvm_cpu_state.queued_work_last = &wi;
    wi.next = NULL;
    wi.done = false;

    pthread_kill(env->kvm_cpu_state.thread, SIG_IPI);
    while (!wi.done)
        qemu_cond_wait(&qemu_work_cond);
}

static void inject_interrupt(void *data)
{
    cpu_interrupt(current_env, (int)data);
}

void kvm_inject_interrupt(CPUState *env, int mask)
{
    on_vcpu(env, inject_interrupt, (void *)mask);
}

void kvm_update_interrupt_request(CPUState *env)
{
    int signal = 0;

    if (env) {
        if (!current_env || !current_env->kvm_cpu_state.created)
            signal = 1;
        /*
         * Testing for created here is really redundant
         */
        if (current_env && current_env->kvm_cpu_state.created &&
            env != current_env && !env->kvm_cpu_state.signalled)
            signal = 1;

        if (signal) {
            env->kvm_cpu_state.signalled = 1;
            if (env->kvm_cpu_state.thread)
                pthread_kill(env->kvm_cpu_state.thread, SIG_IPI);
        }
    }
}

void kvm_update_after_sipi(CPUState *env)
{
    env->kvm_cpu_state.sipi_needed = 1;
    kvm_update_interrupt_request(env);
}

void kvm_apic_init(CPUState *env)
{
    if (env->cpu_index != 0)
	env->kvm_cpu_state.init = 1;
    kvm_update_interrupt_request(env);
}

#include <signal.h>

static int try_push_interrupts(void *opaque)
{
    return kvm_arch_try_push_interrupts(opaque);
}

static void post_kvm_run(void *opaque, void *data)
{
    CPUState *env = (CPUState *)data;

    pthread_mutex_lock(&qemu_mutex);
    kvm_arch_post_kvm_run(opaque, env);
}

static int pre_kvm_run(void *opaque, void *data)
{
    CPUState *env = (CPUState *)data;

    kvm_arch_pre_kvm_run(opaque, env);

    if (env->interrupt_request & CPU_INTERRUPT_EXIT)
	return 1;
    pthread_mutex_unlock(&qemu_mutex);
    return 0;
}

static void kvm_do_load_registers(void *_env)
{
    CPUState *env = _env;

    kvm_arch_load_regs(env);
}

void kvm_load_registers(CPUState *env)
{
    if (kvm_enabled() && qemu_system_ready)
        on_vcpu(env, kvm_do_load_registers, env);
}

static void kvm_do_save_registers(void *_env)
{
    CPUState *env = _env;

    kvm_arch_save_regs(env);
}

void kvm_save_registers(CPUState *env)
{
    if (kvm_enabled())
        on_vcpu(env, kvm_do_save_registers, env);
}

int kvm_cpu_exec(CPUState *env)
{
    int r;

    r = kvm_run(kvm_context, env->cpu_index, env);
    if (r < 0) {
        printf("kvm_run returned %d\n", r);
        exit(1);
    }

    return 0;
}

extern int vm_running;

static int has_work(CPUState *env)
{
    if (!vm_running || (env && env->kvm_cpu_state.stopped))
	return 0;
    if (!env->halted)
	return 1;
    return kvm_arch_has_work(env);
}

static void flush_queued_work(CPUState *env)
{
    struct qemu_work_item *wi;

    if (!env->kvm_cpu_state.queued_work_first)
        return;

    while ((wi = env->kvm_cpu_state.queued_work_first)) {
        env->kvm_cpu_state.queued_work_first = wi->next;
        wi->func(wi->data);
        wi->done = true;
    }
    env->kvm_cpu_state.queued_work_last = NULL;
    pthread_cond_broadcast(&qemu_work_cond);
}

static void kvm_main_loop_wait(CPUState *env, int timeout)
{
    struct timespec ts;
    int r, e;
    siginfo_t siginfo;
    sigset_t waitset;

    pthread_mutex_unlock(&qemu_mutex);

    ts.tv_sec = timeout / 1000;
    ts.tv_nsec = (timeout % 1000) * 1000000;
    sigemptyset(&waitset);
    sigaddset(&waitset, SIG_IPI);

    r = sigtimedwait(&waitset, &siginfo, &ts);
    e = errno;

    pthread_mutex_lock(&qemu_mutex);

    if (r == -1 && !(e == EAGAIN || e == EINTR)) {
	printf("sigtimedwait: %s\n", strerror(e));
	exit(1);
    }

    cpu_single_env = env;
    flush_queued_work(env);

    if (env->kvm_cpu_state.stop) {
	env->kvm_cpu_state.stop = 0;
	env->kvm_cpu_state.stopped = 1;
	pthread_cond_signal(&qemu_pause_cond);
    }

    env->kvm_cpu_state.signalled = 0;
}

static int all_threads_paused(void)
{
    CPUState *penv = first_cpu;

    while (penv) {
        if (penv->kvm_cpu_state.stop)
            return 0;
        penv = (CPUState *)penv->next_cpu;
    }

    return 1;
}

static void pause_all_threads(void)
{
    CPUState *penv = first_cpu;

    assert(!cpu_single_env);

    while (penv) {
        penv->kvm_cpu_state.stop = 1;
        pthread_kill(penv->kvm_cpu_state.thread, SIG_IPI);
        penv = (CPUState *)penv->next_cpu;
    }

    while (!all_threads_paused())
	qemu_cond_wait(&qemu_pause_cond);
}

static void resume_all_threads(void)
{
    CPUState *penv = first_cpu;

    assert(!cpu_single_env);

    while (penv) {
        penv->kvm_cpu_state.stop = 0;
        penv->kvm_cpu_state.stopped = 0;
        pthread_kill(penv->kvm_cpu_state.thread, SIG_IPI);
        penv = (CPUState *)penv->next_cpu;
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
    env->kvm_cpu_state.sipi_needed = 0;
}

static void update_regs_for_init(CPUState *env)
{
#ifdef TARGET_I386
    SegmentCache cs = env->segs[R_CS];
#endif

    cpu_reset(env);

#ifdef TARGET_I386
    /* restore SIPI vector */
    if(env->kvm_cpu_state.sipi_needed)
        env->segs[R_CS] = cs;
#endif

    env->kvm_cpu_state.init = 0;
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

void qemu_kvm_system_reset(void)
{
    CPUState *penv = first_cpu;

    pause_all_threads();

    qemu_system_reset();

    while (penv) {
        kvm_arch_cpu_reset(penv);
        penv = (CPUState *)penv->next_cpu;
    }

    resume_all_threads();
}

static int kvm_main_loop_cpu(CPUState *env)
{
    setup_kernel_sigmask(env);

    pthread_mutex_lock(&qemu_mutex);
    if (kvm_irqchip_in_kernel(kvm_context))
	env->halted = 0;

    kvm_qemu_init_env(env);
#ifdef TARGET_I386
    kvm_tpr_vcpu_start(env);
#endif

    cpu_single_env = env;
    kvm_load_registers(env);

    while (1) {
	while (!has_work(env))
	    kvm_main_loop_wait(env, 1000);
	if (env->interrupt_request & (CPU_INTERRUPT_HARD | CPU_INTERRUPT_NMI))
	    env->halted = 0;
    if (!kvm_irqchip_in_kernel(kvm_context)) {
	    if (env->kvm_cpu_state.init)
	        update_regs_for_init(env);
	    if (env->kvm_cpu_state.sipi_needed)
	        update_regs_for_sipi(env);
    }
	if (!env->halted && !env->kvm_cpu_state.init)
	    kvm_cpu_exec(env);
	env->interrupt_request &= ~CPU_INTERRUPT_EXIT;
	kvm_main_loop_wait(env, 0);
    }
    pthread_mutex_unlock(&qemu_mutex);
    return 0;
}

static void *ap_main_loop(void *_env)
{
    CPUState *env = _env;
    sigset_t signals;
    struct ioperm_data *data = NULL;

    current_env = env;
    env->thread_id = kvm_get_thread_id();
    sigfillset(&signals);
    sigprocmask(SIG_BLOCK, &signals, NULL);
    kvm_create_vcpu(kvm_context, env->cpu_index);
    kvm_qemu_init_env(env);

#ifdef USE_KVM_DEVICE_ASSIGNMENT
    /* do ioperm for io ports of assigned devices */
    LIST_FOREACH(data, &ioperm_head, entries)
	on_vcpu(env, kvm_arch_do_ioperm, data);
#endif

    /* signal VCPU creation */
    pthread_mutex_lock(&qemu_mutex);
    current_env->kvm_cpu_state.created = 1;
    pthread_cond_signal(&qemu_vcpu_cond);

    /* and wait for machine initialization */
    while (!qemu_system_ready)
	qemu_cond_wait(&qemu_system_cond);
    pthread_mutex_unlock(&qemu_mutex);

    kvm_main_loop_cpu(env);
    return NULL;
}

void kvm_init_vcpu(CPUState *env)
{
    int cpu = env->cpu_index;
    pthread_create(&env->kvm_cpu_state.thread, NULL, ap_main_loop, env);

    while (env->kvm_cpu_state.created == 0)
	qemu_cond_wait(&qemu_vcpu_cond);
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

/* If we have signalfd, we mask out the signals we want to handle and then
 * use signalfd to listen for them.  We rely on whatever the current signal
 * handler is to dispatch the signals when we receive them.
 */

static void sigfd_handler(void *opaque)
{
    int fd = (unsigned long)opaque;
    struct qemu_signalfd_siginfo info;
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

    }
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
}

int kvm_main_loop(void)
{
    int fds[2];
    sigset_t mask;
    int sigfd;

    io_thread = pthread_self();
    qemu_system_ready = 1;

    if (qemu_eventfd(fds) == -1) {
	fprintf(stderr, "failed to create eventfd\n");
	return -errno;
    }

    qemu_set_fd_handler2(fds[0], NULL, io_thread_wakeup, NULL,
			 (void *)(unsigned long)fds[0]);

    io_thread_fd = fds[1];

    sigemptyset(&mask);
    sigaddset(&mask, SIGIO);
    sigaddset(&mask, SIGALRM);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    sigfd = qemu_signalfd(&mask);
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
        else if (qemu_reset_requested())
	    qemu_kvm_system_reset();
	else if (kvm_debug_cpu_requested) {
	    gdb_set_stop_cpu(kvm_debug_cpu_requested);
	    vm_stop(EXCP_DEBUG);
	    kvm_debug_cpu_requested = NULL;
	}
    }

    pause_all_threads();
    pthread_mutex_unlock(&qemu_mutex);

    return 0;
}

#ifdef KVM_CAP_SET_GUEST_DEBUG
int kvm_debug(void *opaque, void *data, struct kvm_debug_exit_arch *arch_info)
{
    int handle = kvm_arch_debug(arch_info);
    struct CPUState *env = data;

    if (handle) {
	kvm_debug_cpu_requested = env;
	env->kvm_cpu_state.stopped = 1;
    }
    return handle;
}
#endif

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

static int kvm_shutdown(void *opaque, void *data)
{
    struct CPUState *env = (struct CPUState *)data;

    /* stop the current vcpu from going back to guest mode */
    env->kvm_cpu_state.stopped = 1;

    qemu_system_reset_request();
    return 1;
}
 
static struct kvm_callbacks qemu_kvm_ops = {
#ifdef KVM_CAP_SET_GUEST_DEBUG
    .debug = kvm_debug,
#endif
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
#ifdef KVM_CAP_USER_NMI
    .push_nmi = kvm_arch_push_nmi,
#endif
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

#ifdef TARGET_I386
static int destroy_region_works = 0;
#endif

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
#ifdef TARGET_I386
    destroy_region_works = kvm_destroy_memory_region_works(kvm_context);
#endif
    return 0;
}

void kvm_qemu_destroy(void)
{
    kvm_finalize(kvm_context);
}

#ifdef TARGET_I386
static int must_use_aliases_source(target_phys_addr_t addr)
{
    if (destroy_region_works)
        return false;
    if (addr == 0xa0000 || addr == 0xa8000)
        return true;
    return false;
}

static int must_use_aliases_target(target_phys_addr_t addr)
{
    if (destroy_region_works)
        return false;
    if (addr >= 0xe0000000 && addr < 0x100000000ull)
        return true;
    return false;
}

static struct mapping {
    target_phys_addr_t phys;
    ram_addr_t ram;
    ram_addr_t len;
} mappings[50];
static int nr_mappings;

static struct mapping *find_ram_mapping(ram_addr_t ram_addr)
{
    struct mapping *p;

    for (p = mappings; p < mappings + nr_mappings; ++p) {
        if (p->ram <= ram_addr && ram_addr < p->ram + p->len) {
            return p;
        }
    }
    return NULL;
}

static struct mapping *find_mapping(target_phys_addr_t start_addr)
{
    struct mapping *p;

    for (p = mappings; p < mappings + nr_mappings; ++p) {
        if (p->phys <= start_addr && start_addr < p->phys + p->len) {
            return p;
        }
    }
    return NULL;
}

static void drop_mapping(target_phys_addr_t start_addr)
{
    struct mapping *p = find_mapping(start_addr);

    if (p)
        *p = mappings[--nr_mappings];
}
#endif

void kvm_cpu_register_physical_memory(target_phys_addr_t start_addr,
                                      unsigned long size,
                                      unsigned long phys_offset)
{
    int r = 0;
    unsigned long area_flags = phys_offset & ~TARGET_PAGE_MASK;
#ifdef TARGET_I386
    struct mapping *p;
#endif

    phys_offset &= ~IO_MEM_ROM;

    if (area_flags == IO_MEM_UNASSIGNED) {
#ifdef TARGET_I386
        if (must_use_aliases_source(start_addr)) {
            kvm_destroy_memory_alias(kvm_context, start_addr);
            return;
        }
        if (must_use_aliases_target(start_addr))
            return;
#endif
        kvm_unregister_memory_area(kvm_context, start_addr, size);
        return;
    }

    r = kvm_is_containing_region(kvm_context, start_addr, size);
    if (r)
        return;

    if (area_flags >= TLB_MMIO)
        return;

#ifdef TARGET_I386
    if (must_use_aliases_source(start_addr)) {
        p = find_ram_mapping(phys_offset);
        if (p) {
            kvm_create_memory_alias(kvm_context, start_addr, size,
                                    p->phys + (phys_offset - p->ram));
        }
        return;
    }
#endif

    r = kvm_register_phys_mem(kvm_context, start_addr,
                              phys_ram_base + phys_offset,
                              size, 0);
    if (r < 0) {
        printf("kvm_cpu_register_physical_memory: failed\n");
        exit(1);
    }

#ifdef TARGET_I386
    drop_mapping(start_addr);
    p = &mappings[nr_mappings++];
    p->phys = start_addr;
    p->ram = phys_offset;
    p->len = size;
#endif

    return;
}

void kvm_cpu_unregister_physical_memory(target_phys_addr_t start_addr,
                                        target_phys_addr_t size,
                                        unsigned long phys_offset)
{
    kvm_unregister_memory_area(kvm_context, start_addr, size);
}

int kvm_setup_guest_memory(void *area, unsigned long size)
{
    int ret = 0;

#ifdef MADV_DONTFORK
    if (kvm_enabled() && !kvm_has_sync_mmu())
        ret = madvise(area, size, MADV_DONTFORK);
#endif

    if (ret)
        perror ("madvise");

    return ret;
}

int kvm_qemu_check_extension(int ext)
{
    return kvm_check_extension(kvm_context, ext);
}

int kvm_qemu_init_env(CPUState *cenv)
{
    return kvm_arch_qemu_init_env(cenv);
}

#ifdef KVM_CAP_SET_GUEST_DEBUG
struct kvm_sw_breakpoint_head kvm_sw_breakpoints =
    TAILQ_HEAD_INITIALIZER(kvm_sw_breakpoints);

struct kvm_sw_breakpoint *kvm_find_sw_breakpoint(target_ulong pc)
{
    struct kvm_sw_breakpoint *bp;

    TAILQ_FOREACH(bp, &kvm_sw_breakpoints, entry) {
	if (bp->pc == pc)
	    return bp;
    }
    return NULL;
}

struct kvm_set_guest_debug_data {
    struct kvm_guest_debug dbg;
    int err;
};

void kvm_invoke_set_guest_debug(void *data)
{
    struct kvm_set_guest_debug_data *dbg_data = data;

    dbg_data->err = kvm_set_guest_debug(kvm_context, cpu_single_env->cpu_index,
                                        &dbg_data->dbg);
}

int kvm_update_guest_debug(CPUState *env, unsigned long reinject_trap)
{
    struct kvm_set_guest_debug_data data;

    data.dbg.control = 0;
    if (env->singlestep_enabled)
	data.dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;

    kvm_arch_update_guest_debug(env, &data.dbg);
    data.dbg.control |= reinject_trap;

    on_vcpu(env, kvm_invoke_set_guest_debug, &data);
    return data.err;
}

int kvm_insert_breakpoint(CPUState *current_env, target_ulong addr,
                          target_ulong len, int type)
{
    struct kvm_sw_breakpoint *bp;
    CPUState *env;
    int err;

    if (type == GDB_BREAKPOINT_SW) {
	bp = kvm_find_sw_breakpoint(addr);
	if (bp) {
	    bp->use_count++;
	    return 0;
	}

	bp = qemu_malloc(sizeof(struct kvm_sw_breakpoint));
	if (!bp)
	    return -ENOMEM;

	bp->pc = addr;
	bp->use_count = 1;
	err = kvm_arch_insert_sw_breakpoint(current_env, bp);
	if (err) {
	    free(bp);
	    return err;
	}

	TAILQ_INSERT_HEAD(&kvm_sw_breakpoints, bp, entry);
    } else {
	err = kvm_arch_insert_hw_breakpoint(addr, len, type);
	if (err)
	    return err;
    }

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
	err = kvm_update_guest_debug(env, 0);
	if (err)
	    return err;
    }
    return 0;
}

int kvm_remove_breakpoint(CPUState *current_env, target_ulong addr,
                          target_ulong len, int type)
{
    struct kvm_sw_breakpoint *bp;
    CPUState *env;
    int err;

    if (type == GDB_BREAKPOINT_SW) {
	bp = kvm_find_sw_breakpoint(addr);
	if (!bp)
	    return -ENOENT;

	if (bp->use_count > 1) {
	    bp->use_count--;
	    return 0;
	}

	err = kvm_arch_remove_sw_breakpoint(current_env, bp);
	if (err)
	    return err;

	TAILQ_REMOVE(&kvm_sw_breakpoints, bp, entry);
	qemu_free(bp);
    } else {
	err = kvm_arch_remove_hw_breakpoint(addr, len, type);
	if (err)
	    return err;
    }

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
	err = kvm_update_guest_debug(env, 0);
	if (err)
	    return err;
    }
    return 0;
}

void kvm_remove_all_breakpoints(CPUState *current_env)
{
    struct kvm_sw_breakpoint *bp, *next;
    CPUState *env;

    TAILQ_FOREACH_SAFE(bp, &kvm_sw_breakpoints, entry, next) {
        if (kvm_arch_remove_sw_breakpoint(current_env, bp) != 0) {
            /* Try harder to find a CPU that currently sees the breakpoint. */
            for (env = first_cpu; env != NULL; env = env->next_cpu) {
                if (kvm_arch_remove_sw_breakpoint(env, bp) == 0)
                    break;
            }
        }
    }
    kvm_arch_remove_all_hw_breakpoints();

    for (env = first_cpu; env != NULL; env = env->next_cpu)
	kvm_update_guest_debug(env, 0);
}

#else /* !KVM_CAP_SET_GUEST_DEBUG */

int kvm_update_guest_debug(CPUState *env, unsigned long reinject_trap)
{
    return -EINVAL;
}

int kvm_insert_breakpoint(CPUState *current_env, target_ulong addr,
                          target_ulong len, int type)
{
    return -EINVAL;
}

int kvm_remove_breakpoint(CPUState *current_env, target_ulong addr,
                          target_ulong len, int type)
{
    return -EINVAL;
}

void kvm_remove_all_breakpoints(CPUState *current_env)
{
}
#endif /* !KVM_CAP_SET_GUEST_DEBUG */

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
    unsigned long page_number, addr, addr1;
    ram_addr_t ram_addr;
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
            ram_addr = cpu_get_physical_page_desc(addr);
            cpu_physical_memory_set_dirty(ram_addr);
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

void kvm_qemu_log_memory(target_phys_addr_t start, target_phys_addr_t size,
                         int log)
{
    if (log)
	kvm_dirty_pages_log_enable_slot(kvm_context, start, size);
    else {
#ifdef TARGET_I386
        if (must_use_aliases_target(start))
            return;
#endif
	kvm_dirty_pages_log_disable_slot(kvm_context, start, size);
    }
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
    assert(!cpu_single_env);
    pthread_mutex_unlock(&qemu_mutex);
}

void kvm_mutex_lock(void)
{
    pthread_mutex_lock(&qemu_mutex);
    cpu_single_env = NULL;
}

int qemu_kvm_register_coalesced_mmio(target_phys_addr_t addr, unsigned int size)
{
    return kvm_register_coalesced_mmio(kvm_context, addr, size);
}

int qemu_kvm_unregister_coalesced_mmio(target_phys_addr_t addr,
				       unsigned int size)
{
    return kvm_unregister_coalesced_mmio(kvm_context, addr, size);
}

int kvm_coalesce_mmio_region(target_phys_addr_t start, ram_addr_t size)
{
    return kvm_register_coalesced_mmio(kvm_context, start, size);
}

int kvm_uncoalesce_mmio_region(target_phys_addr_t start, ram_addr_t size)
{
    return kvm_unregister_coalesced_mmio(kvm_context, start, size);
}

#ifdef USE_KVM_DEVICE_ASSIGNMENT
void kvm_add_ioperm_data(struct ioperm_data *data)
{
    LIST_INSERT_HEAD(&ioperm_head, data, entries);
}

void kvm_ioperm(CPUState *env, void *data)
{
    if (kvm_enabled() && qemu_system_ready)
	on_vcpu(env, kvm_arch_do_ioperm, data);
}

#endif

void kvm_physical_sync_dirty_bitmap(target_phys_addr_t start_addr, target_phys_addr_t end_addr)
{
#ifndef TARGET_IA64
    void *buf;

#ifdef TARGET_I386
    if (must_use_aliases_source(start_addr))
        return;
#endif

    buf = qemu_malloc((end_addr - start_addr) / 8 + 2);
    kvm_get_dirty_pages_range(kvm_context, start_addr, end_addr - start_addr,
			      buf, NULL, kvm_get_dirty_bitmap_cb);
    qemu_free(buf);
#endif
}

int kvm_log_start(target_phys_addr_t phys_addr, target_phys_addr_t len)
{
#ifdef TARGET_I386
    if (must_use_aliases_source(phys_addr))
        return 0;
#endif
    kvm_qemu_log_memory(phys_addr, len, 1);
    return 0;
}

int kvm_log_stop(target_phys_addr_t phys_addr, target_phys_addr_t len)
{
#ifdef TARGET_I386
    if (must_use_aliases_source(phys_addr))
        return 0;
#endif
    kvm_qemu_log_memory(phys_addr, len, 0);
    return 0;
}

/* hack: both libkvm and upstream qemu define kvm_has_sync_mmu(), differently */
#undef kvm_has_sync_mmu
int qemu_kvm_has_sync_mmu(void)
{
    return kvm_has_sync_mmu(kvm_context);
}
