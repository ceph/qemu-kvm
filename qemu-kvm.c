/*
 * qemu/kvm integration
 *
 * Copyright (C) 2006-2008 Qumranet Technologies
 *
 * Licensed under the terms of the GNU GPL version 2 or higher.
 */
#include "config.h"
#include "config-host.h"

#include <assert.h>
#include <string.h>
#include "hw/hw.h"
#include "sysemu.h"
#include "qemu-common.h"
#include "console.h"
#include "block.h"
#include "compatfd.h"
#include "gdbstub.h"
#include "monitor.h"
#include "cpus.h"
#include "qemu-thread.h"

#include "qemu-kvm.h"

#include <pthread.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include "compatfd.h"
#include <sys/prctl.h>

#ifndef PR_MCE_KILL
#define PR_MCE_KILL 33
#endif

#ifndef BUS_MCEERR_AR
#define BUS_MCEERR_AR 4
#endif
#ifndef BUS_MCEERR_AO
#define BUS_MCEERR_AO 5
#endif

#define EXPECTED_KVM_API_VERSION 12

#if EXPECTED_KVM_API_VERSION != KVM_API_VERSION
#error libkvm: userspace and kernel version mismatch
#endif

int kvm_irqchip = 1;
int kvm_pit = 1;
int kvm_pit_reinject = 1;
int kvm_nested = 0;


KVMState *kvm_state;
kvm_context_t kvm_context;

pthread_mutex_t qemu_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t qemu_vcpu_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t qemu_system_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t qemu_pause_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t qemu_work_cond = PTHREAD_COND_INITIALIZER;
__thread CPUState *current_env;

static int qemu_system_ready;

#define SIG_IPI (SIGRTMIN+4)

CPUState *kvm_debug_cpu_requested;

#ifdef CONFIG_KVM_DEVICE_ASSIGNMENT
/* The list of ioperm_data */
static QLIST_HEAD(, ioperm_data) ioperm_head;
#endif

#define ALIGN(x, y) (((x)+(y)-1) & ~((y)-1))

static int handle_unhandled(uint64_t reason)
{
    fprintf(stderr, "kvm: unhandled exit %" PRIx64 "\n", reason);
    return -EINVAL;
}

#define VMX_INVALID_GUEST_STATE 0x80000021

static int handle_failed_vmentry(uint64_t reason)
{
    fprintf(stderr, "kvm: vm entry failed with error 0x%" PRIx64 "\n\n", reason);

    /* Perhaps we will need to check if this machine is intel since exit reason 0x21
       has a different interpretation on SVM */
    if (reason == VMX_INVALID_GUEST_STATE) {
        fprintf(stderr, "If you're runnning a guest on an Intel machine without\n");
        fprintf(stderr, "unrestricted mode support, the failure can be most likely\n");
        fprintf(stderr, "due to the guest entering an invalid state for Intel VT.\n");
        fprintf(stderr, "For example, the guest maybe running in big real mode\n");
        fprintf(stderr, "which is not supported on less recent Intel processors.\n\n");
    }

    return -EINVAL;
}

static inline void set_gsi(kvm_context_t kvm, unsigned int gsi)
{
    uint32_t *bitmap = kvm->used_gsi_bitmap;

    if (gsi < kvm->max_gsi)
        bitmap[gsi / 32] |= 1U << (gsi % 32);
    else
        DPRINTF("Invalid GSI %u\n", gsi);
}

static inline void clear_gsi(kvm_context_t kvm, unsigned int gsi)
{
    uint32_t *bitmap = kvm->used_gsi_bitmap;

    if (gsi < kvm->max_gsi)
        bitmap[gsi / 32] &= ~(1U << (gsi % 32));
    else
        DPRINTF("Invalid GSI %u\n", gsi);
}

static int kvm_create_context(void);

int kvm_init(void)
{
    int fd;
    int r, i;


    fd = open("/dev/kvm", O_RDWR);
    if (fd == -1) {
        perror("open /dev/kvm");
        return -1;
    }
    r = ioctl(fd, KVM_GET_API_VERSION, 0);
    if (r == -1) {
        fprintf(stderr,
                "kvm kernel version too old: "
                "KVM_GET_API_VERSION ioctl not supported\n");
        goto out_close;
    }
    if (r < EXPECTED_KVM_API_VERSION) {
        fprintf(stderr, "kvm kernel version too old: "
                "We expect API version %d or newer, but got "
                "version %d\n", EXPECTED_KVM_API_VERSION, r);
        goto out_close;
    }
    if (r > EXPECTED_KVM_API_VERSION) {
        fprintf(stderr, "kvm userspace version too old\n");
        goto out_close;
    }
    kvm_state = qemu_mallocz(sizeof(*kvm_state));
    kvm_context = &kvm_state->kvm_context;

    kvm_state->fd = fd;
    kvm_state->vmfd = -1;

#ifdef KVM_CAP_SET_GUEST_DEBUG
    QTAILQ_INIT(&kvm_state->kvm_sw_breakpoints);
#endif

    for (i = 0; i < ARRAY_SIZE(kvm_state->slots); i++) {
        kvm_state->slots[i].slot = i;
    }

#ifdef KVM_CAP_USER_MEMORY
    r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
    if (r <= 0) {
        fprintf(stderr,
                "Hypervisor too old: KVM_CAP_USER_MEMORY extension not supported\n");
        goto out_close;
    }
#else
#error Hypervisor too old: KVM_CAP_USER_MEMORY extension not supported
#endif

    cpu_register_phys_memory_client(&kvm_cpu_phys_memory_client);

    pthread_mutex_lock(&qemu_mutex);
    return kvm_create_context();

  out_close:
    close(fd);
    return -1;
}

static void kvm_finalize(KVMState *s)
{
    /* FIXME
       if (kvm->vcpu_fd[0] != -1)
           close(kvm->vcpu_fd[0]);
       if (kvm->vm_fd != -1)
           close(kvm->vm_fd);
     */
    close(s->fd);
    free(s);
}

static int kvm_set_boot_vcpu_id(kvm_context_t kvm, uint32_t id)
{
#ifdef KVM_CAP_SET_BOOT_CPU_ID
    int r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_SET_BOOT_CPU_ID);
    if (r > 0) {
        return kvm_vm_ioctl(kvm_state, KVM_SET_BOOT_CPU_ID, id);
    }
    return -ENOSYS;
#else
    return -ENOSYS;
#endif
}

static int kvm_init_irq_routing(kvm_context_t kvm)
{
#ifdef KVM_CAP_IRQ_ROUTING
    int r, gsi_count;

    gsi_count = kvm_check_extension(kvm_state, KVM_CAP_IRQ_ROUTING);
    if (gsi_count > 0) {
        int gsi_bits, i;

        /* Round up so we can search ints using ffs */
        gsi_bits = ALIGN(gsi_count, 32);
        kvm->used_gsi_bitmap = qemu_mallocz(gsi_bits / 8);
        kvm->max_gsi = gsi_bits;

        /* Mark any over-allocated bits as already in use */
        for (i = gsi_count; i < gsi_bits; i++) {
            set_gsi(kvm, i);
        }
    }

    kvm->irq_routes = qemu_mallocz(sizeof(*kvm_context->irq_routes));
    kvm->nr_allocated_irq_routes = 0;

    r = kvm_arch_init_irq_routing();
    if (r < 0) {
        return r;
    }
#endif

    return 0;
}

int kvm_create_irqchip(kvm_context_t kvm)
{
#ifdef KVM_CAP_IRQCHIP
    int r;

    if (!kvm_irqchip || !kvm_check_extension(kvm_state, KVM_CAP_IRQCHIP)) {
        return 0;
    }

    r = kvm_vm_ioctl(kvm_state, KVM_CREATE_IRQCHIP);
    if (r < 0) {
        fprintf(stderr, "Create kernel PIC irqchip failed\n");
        return r;
    }

    kvm->irqchip_inject_ioctl = KVM_IRQ_LINE;
#if defined(KVM_CAP_IRQ_INJECT_STATUS) && defined(KVM_IRQ_LINE_STATUS)
    if (kvm_check_extension(kvm_state, KVM_CAP_IRQ_INJECT_STATUS)) {
        kvm->irqchip_inject_ioctl = KVM_IRQ_LINE_STATUS;
    }
#endif
    kvm_state->irqchip_in_kernel = 1;

    r = kvm_init_irq_routing(kvm);
    if (r < 0) {
        return r;
    }
#endif

    return 0;
}

#ifdef KVM_CAP_IRQCHIP

int kvm_set_irq_level(kvm_context_t kvm, int irq, int level, int *status)
{
    struct kvm_irq_level event;
    int r;

    if (!kvm_state->irqchip_in_kernel) {
        return 0;
    }
    event.level = level;
    event.irq = irq;
    r = kvm_vm_ioctl(kvm_state, kvm->irqchip_inject_ioctl, &event);
    if (r < 0) {
        perror("kvm_set_irq_level");
    }

    if (status) {
#ifdef KVM_CAP_IRQ_INJECT_STATUS
        *status =
            (kvm->irqchip_inject_ioctl == KVM_IRQ_LINE) ? 1 : event.status;
#else
        *status = 1;
#endif
    }

    return 1;
}

int kvm_get_irqchip(kvm_context_t kvm, struct kvm_irqchip *chip)
{
    int r;

    if (!kvm_state->irqchip_in_kernel) {
        return 0;
    }
    r = kvm_vm_ioctl(kvm_state, KVM_GET_IRQCHIP, chip);
    if (r < 0) {
        perror("kvm_get_irqchip\n");
    }
    return r;
}

int kvm_set_irqchip(kvm_context_t kvm, struct kvm_irqchip *chip)
{
    int r;

    if (!kvm_state->irqchip_in_kernel) {
        return 0;
    }
    r = kvm_vm_ioctl(kvm_state, KVM_SET_IRQCHIP, chip);
    if (r < 0) {
        perror("kvm_set_irqchip\n");
    }
    return r;
}

#endif

static int handle_mmio(CPUState *env)
{
    unsigned long addr = env->kvm_run->mmio.phys_addr;
    struct kvm_run *kvm_run = env->kvm_run;
    void *data = kvm_run->mmio.data;

    /* hack: Red Hat 7.1 generates these weird accesses. */
    if ((addr > 0xa0000 - 4 && addr <= 0xa0000) && kvm_run->mmio.len == 3) {
        return 0;
    }

    cpu_physical_memory_rw(addr, data, kvm_run->mmio.len, kvm_run->mmio.is_write);
    return 0;
}

static int handle_io_window(kvm_context_t kvm)
{
    return 1;
}

static int handle_shutdown(kvm_context_t kvm, CPUState *env)
{
    /* stop the current vcpu from going back to guest mode */
    env->stopped = 1;

    qemu_system_reset_request();
    return 1;
}

static inline void push_nmi(kvm_context_t kvm)
{
#ifdef KVM_CAP_USER_NMI
    kvm_arch_push_nmi();
#endif                          /* KVM_CAP_USER_NMI */
}

static void post_kvm_run(kvm_context_t kvm, CPUState *env)
{
    pthread_mutex_lock(&qemu_mutex);
    kvm_arch_post_run(env, env->kvm_run);
    cpu_single_env = env;
}

static int pre_kvm_run(kvm_context_t kvm, CPUState *env)
{
    kvm_arch_pre_run(env, env->kvm_run);

    pthread_mutex_unlock(&qemu_mutex);
    return 0;
}

int kvm_is_ready_for_interrupt_injection(CPUState *env)
{
    return env->kvm_run->ready_for_interrupt_injection;
}

static int kvm_run(CPUState *env)
{
    int r;
    kvm_context_t kvm = &env->kvm_state->kvm_context;
    struct kvm_run *run = env->kvm_run;
    int fd = env->kvm_fd;

  again:
    if (env->kvm_vcpu_dirty) {
        kvm_arch_put_registers(env, KVM_PUT_RUNTIME_STATE);
        env->kvm_vcpu_dirty = 0;
    }
    push_nmi(kvm);
#if !defined(__s390__)
    if (!kvm_state->irqchip_in_kernel) {
        run->request_interrupt_window = kvm_arch_try_push_interrupts(env);
    }
#endif

    r = pre_kvm_run(kvm, env);
    if (r) {
        return r;
    }
    if (env->exit_request) {
        env->exit_request = 0;
        pthread_kill(env->thread->thread, SIG_IPI);
    }
    r = ioctl(fd, KVM_RUN, 0);

    if (r == -1 && errno != EINTR && errno != EAGAIN) {
        r = -errno;
        post_kvm_run(kvm, env);
        fprintf(stderr, "kvm_run: %s\n", strerror(-r));
        return r;
    }

    post_kvm_run(kvm, env);

    kvm_flush_coalesced_mmio_buffer();

#if !defined(__s390__)
    if (r == -1) {
        r = handle_io_window(kvm);
        goto more;
    }
#endif
    if (1) {
        switch (run->exit_reason) {
        case KVM_EXIT_UNKNOWN:
            r = handle_unhandled(run->hw.hardware_exit_reason);
            break;
        case KVM_EXIT_FAIL_ENTRY:
            r = handle_failed_vmentry(run->fail_entry.hardware_entry_failure_reason);
            break;
        case KVM_EXIT_EXCEPTION:
            fprintf(stderr, "exception %d (%x)\n", run->ex.exception,
                    run->ex.error_code);
            cpu_dump_state(env, stderr, fprintf, CPU_DUMP_CODE);
            abort();
            break;
        case KVM_EXIT_IO:
            kvm_handle_io(run->io.port,
                                (uint8_t *)run + run->io.data_offset,
                                run->io.direction,
                                run->io.size,
                                run->io.count);
            r = 0;
            break;
        case KVM_EXIT_MMIO:
            r = handle_mmio(env);
            break;
        case KVM_EXIT_HLT:
            r = kvm_arch_halt(env);
            break;
        case KVM_EXIT_IRQ_WINDOW_OPEN:
            break;
        case KVM_EXIT_SHUTDOWN:
            r = handle_shutdown(kvm, env);
            break;
#if defined(__s390__)
        case KVM_EXIT_S390_SIEIC:
            r = kvm_s390_handle_intercept(kvm, env, run);
            break;
        case KVM_EXIT_S390_RESET:
            r = kvm_s390_handle_reset(kvm, env, run);
            break;
#endif
	case KVM_EXIT_INTERNAL_ERROR:
            r = kvm_handle_internal_error(env, run);
	    break;
        default:
            r = kvm_arch_run(env);
            if (r < 0) {
                fprintf(stderr, "unhandled vm exit: 0x%x\n", run->exit_reason);
                cpu_dump_state(env, stderr, fprintf, CPU_DUMP_CODE);
                abort();
            }
            if (r > 0) {
                return r;
            }
            break;
        }
    }
more:
    if (!r) {
        goto again;
    }
    return r;
}

int kvm_inject_irq(CPUState *env, unsigned irq)
{
    struct kvm_interrupt intr;

    intr.irq = irq;
    return kvm_vcpu_ioctl(env, KVM_INTERRUPT, &intr);
}

int kvm_inject_nmi(CPUState *env)
{
#ifdef KVM_CAP_USER_NMI
    return kvm_vcpu_ioctl(env, KVM_NMI);
#else
    return -ENOSYS;
#endif
}

#ifdef KVM_CAP_DEVICE_ASSIGNMENT
int kvm_assign_pci_device(kvm_context_t kvm,
                          struct kvm_assigned_pci_dev *assigned_dev)
{
    return kvm_vm_ioctl(kvm_state, KVM_ASSIGN_PCI_DEVICE, assigned_dev);
}

static int kvm_old_assign_irq(kvm_context_t kvm,
                              struct kvm_assigned_irq *assigned_irq)
{
    return kvm_vm_ioctl(kvm_state, KVM_ASSIGN_IRQ, assigned_irq);
}

#ifdef KVM_CAP_ASSIGN_DEV_IRQ
int kvm_assign_irq(kvm_context_t kvm, struct kvm_assigned_irq *assigned_irq)
{
    int ret;

    ret = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_ASSIGN_DEV_IRQ);
    if (ret > 0) {
        return kvm_vm_ioctl(kvm_state, KVM_ASSIGN_DEV_IRQ, assigned_irq);
    }

    return kvm_old_assign_irq(kvm, assigned_irq);
}

int kvm_deassign_irq(kvm_context_t kvm, struct kvm_assigned_irq *assigned_irq)
{
    return kvm_vm_ioctl(kvm_state, KVM_DEASSIGN_DEV_IRQ, assigned_irq);
}
#else
int kvm_assign_irq(kvm_context_t kvm, struct kvm_assigned_irq *assigned_irq)
{
    return kvm_old_assign_irq(kvm, assigned_irq);
}
#endif
#endif

#ifdef KVM_CAP_DEVICE_DEASSIGNMENT
int kvm_deassign_pci_device(kvm_context_t kvm,
                            struct kvm_assigned_pci_dev *assigned_dev)
{
    return kvm_vm_ioctl(kvm_state, KVM_DEASSIGN_PCI_DEVICE, assigned_dev);
}
#endif

int kvm_reinject_control(kvm_context_t kvm, int pit_reinject)
{
#ifdef KVM_CAP_REINJECT_CONTROL
    int r;
    struct kvm_reinject_control control;

    control.pit_reinject = pit_reinject;

    r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_REINJECT_CONTROL);
    if (r > 0) {
        return kvm_vm_ioctl(kvm_state, KVM_REINJECT_CONTROL, &control);
    }
#endif
    return -ENOSYS;
}

int kvm_has_gsi_routing(void)
{
    int r = 0;

#ifdef KVM_CAP_IRQ_ROUTING
    r = kvm_check_extension(kvm_state, KVM_CAP_IRQ_ROUTING);
#endif
    return r;
}

int kvm_clear_gsi_routes(void)
{
#ifdef KVM_CAP_IRQ_ROUTING
    kvm_context_t kvm = kvm_context;

    kvm->irq_routes->nr = 0;
    return 0;
#else
    return -EINVAL;
#endif
}

int kvm_add_routing_entry(struct kvm_irq_routing_entry *entry)
{
#ifdef KVM_CAP_IRQ_ROUTING
    kvm_context_t kvm = kvm_context;
    struct kvm_irq_routing *z;
    struct kvm_irq_routing_entry *new;
    int n, size;

    if (kvm->irq_routes->nr == kvm->nr_allocated_irq_routes) {
        n = kvm->nr_allocated_irq_routes * 2;
        if (n < 64) {
            n = 64;
        }
        size = sizeof(struct kvm_irq_routing);
        size += n * sizeof(*new);
        z = realloc(kvm->irq_routes, size);
        if (!z) {
            return -ENOMEM;
        }
        kvm->nr_allocated_irq_routes = n;
        kvm->irq_routes = z;
    }
    n = kvm->irq_routes->nr++;
    new = &kvm->irq_routes->entries[n];
    memset(new, 0, sizeof(*new));
    new->gsi = entry->gsi;
    new->type = entry->type;
    new->flags = entry->flags;
    new->u = entry->u;

    set_gsi(kvm, entry->gsi);

    return 0;
#else
    return -ENOSYS;
#endif
}

int kvm_add_irq_route(int gsi, int irqchip, int pin)
{
#ifdef KVM_CAP_IRQ_ROUTING
    struct kvm_irq_routing_entry e;

    e.gsi = gsi;
    e.type = KVM_IRQ_ROUTING_IRQCHIP;
    e.flags = 0;
    e.u.irqchip.irqchip = irqchip;
    e.u.irqchip.pin = pin;
    return kvm_add_routing_entry(&e);
#else
    return -ENOSYS;
#endif
}

int kvm_del_routing_entry(struct kvm_irq_routing_entry *entry)
{
#ifdef KVM_CAP_IRQ_ROUTING
    kvm_context_t kvm = kvm_context;
    struct kvm_irq_routing_entry *e, *p;
    int i, gsi, found = 0;

    gsi = entry->gsi;

    for (i = 0; i < kvm->irq_routes->nr; ++i) {
        e = &kvm->irq_routes->entries[i];
        if (e->type == entry->type && e->gsi == gsi) {
            switch (e->type) {
            case KVM_IRQ_ROUTING_IRQCHIP:{
                    if (e->u.irqchip.irqchip ==
                        entry->u.irqchip.irqchip
                        && e->u.irqchip.pin == entry->u.irqchip.pin) {
                        p = &kvm->irq_routes->entries[--kvm->irq_routes->nr];
                        *e = *p;
                        found = 1;
                    }
                    break;
                }
            case KVM_IRQ_ROUTING_MSI:{
                    if (e->u.msi.address_lo ==
                        entry->u.msi.address_lo
                        && e->u.msi.address_hi ==
                        entry->u.msi.address_hi
                        && e->u.msi.data == entry->u.msi.data) {
                        p = &kvm->irq_routes->entries[--kvm->irq_routes->nr];
                        *e = *p;
                        found = 1;
                    }
                    break;
                }
            default:
                break;
            }
            if (found) {
                /* If there are no other users of this GSI
                 * mark it available in the bitmap */
                for (i = 0; i < kvm->irq_routes->nr; i++) {
                    e = &kvm->irq_routes->entries[i];
                    if (e->gsi == gsi)
                        break;
                }
                if (i == kvm->irq_routes->nr) {
                    clear_gsi(kvm, gsi);
                }

                return 0;
            }
        }
    }
    return -ESRCH;
#else
    return -ENOSYS;
#endif
}

int kvm_update_routing_entry(struct kvm_irq_routing_entry *entry,
                             struct kvm_irq_routing_entry *newentry)
{
#ifdef KVM_CAP_IRQ_ROUTING
    kvm_context_t kvm = kvm_context;
    struct kvm_irq_routing_entry *e;
    int i;

    if (entry->gsi != newentry->gsi || entry->type != newentry->type) {
        return -EINVAL;
    }

    for (i = 0; i < kvm->irq_routes->nr; ++i) {
        e = &kvm->irq_routes->entries[i];
        if (e->type != entry->type || e->gsi != entry->gsi) {
            continue;
        }
        switch (e->type) {
        case KVM_IRQ_ROUTING_IRQCHIP:
            if (e->u.irqchip.irqchip == entry->u.irqchip.irqchip &&
                e->u.irqchip.pin == entry->u.irqchip.pin) {
                memcpy(&e->u.irqchip, &newentry->u.irqchip,
                       sizeof e->u.irqchip);
                return 0;
            }
            break;
        case KVM_IRQ_ROUTING_MSI:
            if (e->u.msi.address_lo == entry->u.msi.address_lo &&
                e->u.msi.address_hi == entry->u.msi.address_hi &&
                e->u.msi.data == entry->u.msi.data) {
                memcpy(&e->u.msi, &newentry->u.msi, sizeof e->u.msi);
                return 0;
            }
            break;
        default:
            break;
        }
    }
    return -ESRCH;
#else
    return -ENOSYS;
#endif
}

int kvm_del_irq_route(int gsi, int irqchip, int pin)
{
#ifdef KVM_CAP_IRQ_ROUTING
    struct kvm_irq_routing_entry e;

    e.gsi = gsi;
    e.type = KVM_IRQ_ROUTING_IRQCHIP;
    e.flags = 0;
    e.u.irqchip.irqchip = irqchip;
    e.u.irqchip.pin = pin;
    return kvm_del_routing_entry(&e);
#else
    return -ENOSYS;
#endif
}

int kvm_commit_irq_routes(void)
{
#ifdef KVM_CAP_IRQ_ROUTING
    kvm_context_t kvm = kvm_context;

    kvm->irq_routes->flags = 0;
    return kvm_vm_ioctl(kvm_state, KVM_SET_GSI_ROUTING, kvm->irq_routes);
#else
    return -ENOSYS;
#endif
}

int kvm_get_irq_route_gsi(void)
{
    kvm_context_t kvm = kvm_context;
    int i, bit;
    uint32_t *buf = kvm->used_gsi_bitmap;

    /* Return the lowest unused GSI in the bitmap */
    for (i = 0; i < kvm->max_gsi / 32; i++) {
        bit = ffs(~buf[i]);
        if (!bit) {
            continue;
        }

        return bit - 1 + i * 32;
    }

    return -ENOSPC;
}

static void kvm_msi_routing_entry(struct kvm_irq_routing_entry *e,
                                  KVMMsiMessage *msg)

{
    e->gsi = msg->gsi;
    e->type = KVM_IRQ_ROUTING_MSI;
    e->flags = 0;
    e->u.msi.address_lo = msg->addr_lo;
    e->u.msi.address_hi = msg->addr_hi;
    e->u.msi.data = msg->data;
}

int kvm_msi_message_add(KVMMsiMessage *msg)
{
    struct kvm_irq_routing_entry e;
    int ret;

    ret = kvm_get_irq_route_gsi();
    if (ret < 0) {
        return ret;
    }
    msg->gsi = ret;

    kvm_msi_routing_entry(&e, msg);
    return kvm_add_routing_entry(&e);
}

int kvm_msi_message_del(KVMMsiMessage *msg)
{
    struct kvm_irq_routing_entry e;

    kvm_msi_routing_entry(&e, msg);
    return kvm_del_routing_entry(&e);
}

int kvm_msi_message_update(KVMMsiMessage *old, KVMMsiMessage *new)
{
    struct kvm_irq_routing_entry e1, e2;
    int ret;

    new->gsi = old->gsi;
    if (memcmp(old, new, sizeof(KVMMsiMessage)) == 0) {
        return 0;
    }

    kvm_msi_routing_entry(&e1, old);
    kvm_msi_routing_entry(&e2, new);

    ret = kvm_update_routing_entry(&e1, &e2);
    if (ret < 0) {
        return ret;
    }

    return 1;
}


#ifdef KVM_CAP_DEVICE_MSIX
int kvm_assign_set_msix_nr(kvm_context_t kvm,
                           struct kvm_assigned_msix_nr *msix_nr)
{
    return kvm_vm_ioctl(kvm_state, KVM_ASSIGN_SET_MSIX_NR, msix_nr);
}

int kvm_assign_set_msix_entry(kvm_context_t kvm,
                              struct kvm_assigned_msix_entry *entry)
{
    return kvm_vm_ioctl(kvm_state, KVM_ASSIGN_SET_MSIX_ENTRY, entry);
}
#endif

unsigned long kvm_get_thread_id(void)
{
    return syscall(SYS_gettid);
}

static void kvm_cond_wait(pthread_cond_t *cond)
{
    CPUState *env = cpu_single_env;

    pthread_cond_wait(cond, &qemu_mutex);
    cpu_single_env = env;
}

static void sig_ipi_handler(int n)
{
}

static void sigbus_reraise(void)
{
    sigset_t set;
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (!sigaction(SIGBUS, &action, NULL)) {
        raise(SIGBUS);
        sigemptyset(&set);
        sigaddset(&set, SIGBUS);
        sigprocmask(SIG_UNBLOCK, &set, NULL);
    }
    perror("Failed to re-raise SIGBUS!\n");
    abort();
}

static void sigbus_handler(int n, struct qemu_signalfd_siginfo *siginfo,
                           void *ctx)
{
    if (kvm_on_sigbus(siginfo->ssi_code, (void *)(intptr_t)siginfo->ssi_addr))
        sigbus_reraise();
}

void on_vcpu(CPUState *env, void (*func)(void *data), void *data)
{
    struct qemu_work_item wi;

    if (env == current_env) {
        func(data);
        return;
    }

    wi.func = func;
    wi.data = data;
    if (!env->kvm_cpu_state.queued_work_first) {
        env->kvm_cpu_state.queued_work_first = &wi;
    } else {
        env->kvm_cpu_state.queued_work_last->next = &wi;
    }
    env->kvm_cpu_state.queued_work_last = &wi;
    wi.next = NULL;
    wi.done = false;

    pthread_kill(env->thread->thread, SIG_IPI);
    while (!wi.done) {
        kvm_cond_wait(&qemu_work_cond);
    }
}

void kvm_update_interrupt_request(CPUState *env)
{
    int signal = 0;

    if (env) {
        if (!current_env || !current_env->created) {
            signal = 1;
        }
        /*
         * Testing for created here is really redundant
         */
        if (current_env && current_env->created &&
            env != current_env && !env->kvm_cpu_state.signalled) {
            signal = 1;
        }

        if (signal) {
            env->kvm_cpu_state.signalled = 1;
            if (env->thread) {
                pthread_kill(env->thread->thread, SIG_IPI);
            }
        }
    }
}

int kvm_cpu_exec(CPUState *env)
{
    int r;

    r = kvm_run(env);
    if (r < 0) {
        printf("kvm_run returned %d\n", r);
        cpu_dump_state(env, stderr, fprintf, CPU_DUMP_CODE);
        vm_stop(VMSTOP_PANIC);
    }

    return 0;
}

static int kvm_cpu_is_stopped(CPUState *env)
{
    return !vm_running || env->stopped;
}

static void flush_queued_work(CPUState *env)
{
    struct qemu_work_item *wi;

    if (!env->kvm_cpu_state.queued_work_first) {
        return;
    }

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
    sigset_t chkset;

    ts.tv_sec = timeout / 1000;
    ts.tv_nsec = (timeout % 1000) * 1000000;
    sigemptyset(&waitset);
    sigaddset(&waitset, SIG_IPI);
    sigaddset(&waitset, SIGBUS);

    do {
        pthread_mutex_unlock(&qemu_mutex);

        r = sigtimedwait(&waitset, &siginfo, &ts);
        e = errno;

        pthread_mutex_lock(&qemu_mutex);

        if (r == -1 && !(e == EAGAIN || e == EINTR)) {
            printf("sigtimedwait: %s\n", strerror(e));
            exit(1);
        }

        switch (r) {
        case SIGBUS:
            if (kvm_on_sigbus_vcpu(env, siginfo.si_code, siginfo.si_addr))
                sigbus_reraise();
            break;
        default:
            break;
        }

        r = sigpending(&chkset);
        if (r == -1) {
            printf("sigpending: %s\n", strerror(e));
            exit(1);
        }
    } while (sigismember(&chkset, SIG_IPI) || sigismember(&chkset, SIGBUS));

    cpu_single_env = env;
    flush_queued_work(env);

    if (env->stop) {
        env->stop = 0;
        env->stopped = 1;
        pthread_cond_signal(&qemu_pause_cond);
    }

    env->kvm_cpu_state.signalled = 0;
}

static int all_threads_paused(void)
{
    CPUState *penv = first_cpu;

    while (penv) {
        if (penv->stop) {
            return 0;
        }
        penv = (CPUState *) penv->next_cpu;
    }

    return 1;
}

static void pause_all_threads(void)
{
    CPUState *penv = first_cpu;

    while (penv) {
        if (penv != cpu_single_env) {
            penv->stop = 1;
            pthread_kill(penv->thread->thread, SIG_IPI);
        } else {
            penv->stop = 0;
            penv->stopped = 1;
            cpu_exit(penv);
        }
        penv = (CPUState *) penv->next_cpu;
    }

    while (!all_threads_paused()) {
        kvm_cond_wait(&qemu_pause_cond);
    }
}

static void resume_all_threads(void)
{
    CPUState *penv = first_cpu;

    assert(!cpu_single_env);

    while (penv) {
        penv->stop = 0;
        penv->stopped = 0;
        pthread_kill(penv->thread->thread, SIG_IPI);
        penv = (CPUState *) penv->next_cpu;
    }
}

static void kvm_vm_state_change_handler(void *context, int running, int reason)
{
    if (running) {
        resume_all_threads();
    } else {
        pause_all_threads();
    }
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
    sigdelset(&set, SIGBUS);

    kvm_set_signal_mask(env, &set);
}

static void qemu_kvm_system_reset(void)
{
    pause_all_threads();

    cpu_synchronize_all_states();
    qemu_system_reset();

    resume_all_threads();
}

static void process_irqchip_events(CPUState *env)
{
    kvm_arch_process_irqchip_events(env);
    if (kvm_arch_has_work(env))
        env->halted = 0;
}

static int kvm_main_loop_cpu(CPUState *env)
{
    while (1) {
        int run_cpu = !kvm_cpu_is_stopped(env);
        if (run_cpu) {
            kvm_arch_process_async_events(env);
            if (!kvm_irqchip_in_kernel()) {
                process_irqchip_events(env);
                run_cpu = !env->halted;
            }
        }
        if (run_cpu) {
            kvm_cpu_exec(env);
            kvm_main_loop_wait(env, 0);
        } else {
            kvm_main_loop_wait(env, 1000);
        }
    }
    pthread_mutex_unlock(&qemu_mutex);
    return 0;
}

static void *ap_main_loop(void *_env)
{
    CPUState *env = _env;
#ifdef CONFIG_KVM_DEVICE_ASSIGNMENT
    struct ioperm_data *data = NULL;
#endif

    current_env = env;
    env->thread_id = kvm_get_thread_id();

#ifdef CONFIG_KVM_DEVICE_ASSIGNMENT
    /* do ioperm for io ports of assigned devices */
    QLIST_FOREACH(data, &ioperm_head, entries)
        on_vcpu(env, kvm_arch_do_ioperm, data);
#endif

    pthread_mutex_lock(&qemu_mutex);
    cpu_single_env = env;

    if (kvm_create_vcpu(env) < 0) {
        abort();
    }
    setup_kernel_sigmask(env);

    /* signal VCPU creation */
    current_env->created = 1;
    pthread_cond_signal(&qemu_vcpu_cond);

    /* and wait for machine initialization */
    while (!qemu_system_ready) {
        kvm_cond_wait(&qemu_system_cond);
    }

    /* re-initialize cpu_single_env after re-acquiring qemu_mutex */
    cpu_single_env = env;

    kvm_main_loop_cpu(env);
    return NULL;
}

int kvm_init_vcpu(CPUState *env)
{
    env->thread = qemu_mallocz(sizeof(QemuThread));
    qemu_thread_create(env->thread, ap_main_loop, env);

    while (env->created == 0) {
        kvm_cond_wait(&qemu_vcpu_cond);
    }

    return 0;
}

#ifdef TARGET_I386
void kvm_hpet_disable_kpit(void)
{
    struct kvm_pit_state2 ps2;

    kvm_get_pit2(kvm_context, &ps2);
    ps2.flags |= KVM_PIT_FLAGS_HPET_LEGACY;
    kvm_set_pit2(kvm_context, &ps2);
}

void kvm_hpet_enable_kpit(void)
{
    struct kvm_pit_state2 ps2;

    kvm_get_pit2(kvm_context, &ps2);
    ps2.flags &= ~KVM_PIT_FLAGS_HPET_LEGACY;
    kvm_set_pit2(kvm_context, &ps2);
}
#endif

int kvm_init_ap(void)
{
    struct sigaction action;

    qemu_add_vm_change_state_handler(kvm_vm_state_change_handler, NULL);

    signal(SIG_IPI, sig_ipi_handler);

    memset(&action, 0, sizeof(action));
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = (void (*)(int, siginfo_t*, void*))sigbus_handler;
    sigaction(SIGBUS, &action, NULL);
    prctl(PR_MCE_KILL, 1, 1, 0, 0);
    return 0;
}

/* If we have signalfd, we mask out the signals we want to handle and then
 * use signalfd to listen for them.  We rely on whatever the current signal
 * handler is to dispatch the signals when we receive them.
 */

static void sigfd_handler(void *opaque)
{
    int fd = (unsigned long) opaque;
    struct qemu_signalfd_siginfo info;
    struct sigaction action;
    ssize_t len;

    while (1) {
        do {
            len = read(fd, &info, sizeof(info));
        } while (len == -1 && errno == EINTR);

        if (len == -1 && errno == EAGAIN) {
            break;
        }

        if (len != sizeof(info)) {
            printf("read from sigfd returned %zd: %m\n", len);
            return;
        }

        sigaction(info.ssi_signo, NULL, &action);
        if ((action.sa_flags & SA_SIGINFO) && action.sa_sigaction) {
            action.sa_sigaction(info.ssi_signo,
                                (siginfo_t *)&info, NULL);
        } else if (action.sa_handler) {
            action.sa_handler(info.ssi_signo);
        }
    }
}

int kvm_main_loop(void)
{
    sigset_t mask;
    int sigfd;

    qemu_system_ready = 1;

    sigemptyset(&mask);
    sigaddset(&mask, SIGIO);
    sigaddset(&mask, SIGALRM);
    sigaddset(&mask, SIGBUS);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    sigfd = qemu_signalfd(&mask);
    if (sigfd == -1) {
        fprintf(stderr, "failed to create signalfd\n");
        return -errno;
    }

    fcntl(sigfd, F_SETFL, O_NONBLOCK);

    qemu_set_fd_handler2(sigfd, NULL, sigfd_handler, NULL,
                         (void *)(unsigned long) sigfd);

    pthread_cond_broadcast(&qemu_system_cond);

    cpu_single_env = NULL;

    while (1) {
        main_loop_wait(0);
        if (qemu_shutdown_requested()) {
            monitor_protocol_event(QEVENT_SHUTDOWN, NULL);
            if (qemu_no_shutdown()) {
                vm_stop(VMSTOP_SHUTDOWN);
            } else {
                break;
            }
        } else if (qemu_powerdown_requested()) {
            monitor_protocol_event(QEVENT_POWERDOWN, NULL);
            qemu_irq_raise(qemu_system_powerdown);
        } else if (qemu_reset_requested()) {
            qemu_kvm_system_reset();
        } else if (kvm_debug_cpu_requested) {
            gdb_set_stop_cpu(kvm_debug_cpu_requested);
            vm_stop(VMSTOP_DEBUG);
            kvm_debug_cpu_requested = NULL;
        }
    }

    bdrv_close_all();
    pause_all_threads();
    pthread_mutex_unlock(&qemu_mutex);

    return 0;
}

#if !defined(TARGET_I386)
int kvm_arch_init_irq_routing(void)
{
    return 0;
}
#endif

static int kvm_create_context(void)
{
    static const char upgrade_note[] =
    "Please upgrade to at least kernel 2.6.29 or recent kvm-kmod\n"
    "(see http://sourceforge.net/projects/kvm).\n";

    int r;

    kvm_state->pit_in_kernel = kvm_pit;

    kvm_state->vmfd = kvm_ioctl(kvm_state, KVM_CREATE_VM, 0);
    if (kvm_state->vmfd < 0) {
        fprintf(stderr, "kvm_create_vm: %m\n");
        kvm_finalize(kvm_state);
        return -1;
    }

    r = kvm_arch_init(kvm_state);
    if (r < 0) {
        kvm_finalize(kvm_state);
        return r;
    }

    /* There was a nasty bug in < kvm-80 that prevents memory slots from being
     * destroyed properly.  Since we rely on this capability, refuse to work
     * with any kernel without this capability. */
    if (!kvm_check_extension(kvm_state, KVM_CAP_DESTROY_MEMORY_REGION_WORKS)) {
        fprintf(stderr,
                "KVM kernel module broken (DESTROY_MEMORY_REGION).\n%s",
                upgrade_note);
        return -EINVAL;
    }

    r = kvm_create_irqchip(kvm_context);
    if (r < 0) {
        return r;
    }

    kvm_state->coalesced_mmio = 0;
#ifdef KVM_CAP_COALESCED_MMIO
    kvm_state->coalesced_mmio =
        kvm_check_extension(kvm_state, KVM_CAP_COALESCED_MMIO);
#endif

    kvm_state->vcpu_events = 0;
#ifdef KVM_CAP_VCPU_EVENTS
    kvm_state->vcpu_events = kvm_check_extension(kvm_state, KVM_CAP_VCPU_EVENTS);
#endif

    kvm_state->debugregs = 0;
#ifdef KVM_CAP_DEBUGREGS
    kvm_state->debugregs = kvm_check_extension(kvm_state, KVM_CAP_DEBUGREGS);
#endif

    kvm_state->xsave = 0;
#ifdef KVM_CAP_XSAVE
    kvm_state->xsave = kvm_check_extension(kvm_state, KVM_CAP_XSAVE);
#endif

    kvm_state->xcrs = 0;
#ifdef KVM_CAP_XCRS
    kvm_state->xcrs = kvm_check_extension(kvm_state, KVM_CAP_XCRS);
#endif

    kvm_state->many_ioeventfds = kvm_check_many_ioeventfds();

    kvm_init_ap();

    return 0;
}

#ifdef KVM_CAP_IRQCHIP

int kvm_set_irq(int irq, int level, int *status)
{
    return kvm_set_irq_level(kvm_context, irq, level, status);
}

#endif

static void kvm_mutex_unlock(void)
{
    assert(!cpu_single_env);
    pthread_mutex_unlock(&qemu_mutex);
}

static void kvm_mutex_lock(void)
{
    pthread_mutex_lock(&qemu_mutex);
    cpu_single_env = NULL;
}

void qemu_mutex_unlock_iothread(void)
{
    if (kvm_enabled()) {
        kvm_mutex_unlock();
    }
}

void qemu_mutex_lock_iothread(void)
{
    if (kvm_enabled()) {
        kvm_mutex_lock();
    }
}

#ifdef CONFIG_KVM_DEVICE_ASSIGNMENT
void kvm_add_ioperm_data(struct ioperm_data *data)
{
    QLIST_INSERT_HEAD(&ioperm_head, data, entries);
}

void kvm_remove_ioperm_data(unsigned long start_port, unsigned long num)
{
    struct ioperm_data *data;

    data = QLIST_FIRST(&ioperm_head);
    while (data) {
        struct ioperm_data *next = QLIST_NEXT(data, entries);

        if (data->start_port == start_port && data->num == num) {
            QLIST_REMOVE(data, entries);
            qemu_free(data);
        }

        data = next;
    }
}

void kvm_ioperm(CPUState *env, void *data)
{
    if (kvm_enabled() && qemu_system_ready) {
        on_vcpu(env, kvm_arch_do_ioperm, data);
    }
}

#endif

int kvm_set_boot_cpu_id(uint32_t id)
{
    return kvm_set_boot_vcpu_id(kvm_context, id);
}

