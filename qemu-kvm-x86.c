/*
 * qemu/kvm integration, x86 specific code
 *
 * Copyright (C) 2006-2008 Qumranet Technologies
 *
 * Licensed under the terms of the GNU GPL version 2 or higher.
 */

#include "config.h"
#include "config-host.h"

#include <string.h>
#include "hw/hw.h"
#include "gdbstub.h"
#include <sys/io.h>

#include "qemu-kvm.h"
#include <pthread.h>
#include <sys/utsname.h>
#include <linux/kvm_para.h>
#include <sys/ioctl.h>

#include "kvm.h"
#include "hw/apic.h"

#define MSR_IA32_TSC            0x10

extern unsigned int kvm_shadow_memory;

static int kvm_set_tss_addr(kvm_context_t kvm, unsigned long addr)
{
    int r;

    r = kvm_vm_ioctl(kvm_state, KVM_SET_TSS_ADDR, addr);
    if (r < 0) {
        fprintf(stderr, "kvm_set_tss_addr: %m\n");
        return r;
    }
    return 0;
}

static int kvm_init_tss(kvm_context_t kvm)
{
    int r;

    r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_SET_TSS_ADDR);
    if (r > 0) {
        /*
         * this address is 3 pages before the bios, and the bios should present
         * as unavaible memory
         */
        r = kvm_set_tss_addr(kvm, 0xfeffd000);
        if (r < 0) {
            fprintf(stderr, "kvm_init_tss: unable to set tss addr\n");
            return r;
        }
    } else {
        fprintf(stderr, "kvm does not support KVM_CAP_SET_TSS_ADDR\n");
    }
    return 0;
}

static int kvm_set_identity_map_addr(kvm_context_t kvm, uint64_t addr)
{
#ifdef KVM_CAP_SET_IDENTITY_MAP_ADDR
    int r;

    r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_SET_IDENTITY_MAP_ADDR);
    if (r > 0) {
        r = kvm_vm_ioctl(kvm_state, KVM_SET_IDENTITY_MAP_ADDR, &addr);
        if (r == -1) {
            fprintf(stderr, "kvm_set_identity_map_addr: %m\n");
            return -errno;
        }
        return 0;
    }
#endif
    return -ENOSYS;
}

static int kvm_init_identity_map_page(kvm_context_t kvm)
{
#ifdef KVM_CAP_SET_IDENTITY_MAP_ADDR
    int r;

    r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_SET_IDENTITY_MAP_ADDR);
    if (r > 0) {
        /*
         * this address is 4 pages before the bios, and the bios should present
         * as unavaible memory
         */
        r = kvm_set_identity_map_addr(kvm, 0xfeffc000);
        if (r < 0) {
            fprintf(stderr, "kvm_init_identity_map_page: "
                    "unable to set identity mapping addr\n");
            return r;
        }
    }
#endif
    return 0;
}

static int kvm_create_pit(kvm_context_t kvm)
{
#ifdef KVM_CAP_PIT
    int r;

    if (kvm_pit_in_kernel()) {
        r = kvm_vm_ioctl(kvm_state, KVM_CREATE_PIT);
        if (r < 0) {
            fprintf(stderr, "Create kernel PIC irqchip failed\n");
            return r;
        }
        if (!kvm_pit_reinject) {
            r = kvm_reinject_control(kvm_context, 0);
            if (r < 0) {
                fprintf(stderr,
                        "failure to disable in-kernel PIT reinjection\n");
                return r;
            }
        }
    }
#endif
    return 0;
}

int kvm_arch_create(kvm_context_t kvm)
{
    struct utsname utsname;
    int r = 0;

    r = kvm_init_tss(kvm);
    if (r < 0) {
        return r;
    }

    r = kvm_init_identity_map_page(kvm);
    if (r < 0) {
        return r;
    }

    /*
     * Tell fw_cfg to notify the BIOS to reserve the range.
     */
    if (e820_add_entry(0xfeffc000, 0x4000, E820_RESERVED) < 0) {
        perror("e820_add_entry() table is full");
        exit(1);
    }

    r = kvm_create_pit(kvm);
    if (r < 0) {
        return r;
    }

    uname(&utsname);
    lm_capable_kernel = strcmp(utsname.machine, "x86_64") == 0;

    if (kvm_shadow_memory) {
        kvm_set_shadow_pages(kvm_context, kvm_shadow_memory);
    }

    /* initialize has_msr_star/has_msr_hsave_pa */
    r = kvm_get_supported_msrs(kvm_state);
    if (r < 0) {
        return r;
    }

    r = kvm_set_boot_cpu_id(0);
    if (r < 0 && r != -ENOSYS) {
        return r;
    }

    return 0;
}

#ifdef KVM_EXIT_TPR_ACCESS

static int kvm_handle_tpr_access(CPUState *env)
{
    struct kvm_run *run = env->kvm_run;
    kvm_tpr_access_report(env,
                          run->tpr_access.rip,
                          run->tpr_access.is_write);
    return 0;
}


int kvm_enable_vapic(CPUState *env, uint64_t vapic)
{
    struct kvm_vapic_addr va = {
        .vapic_addr = vapic,
    };

    return kvm_vcpu_ioctl(env, KVM_SET_VAPIC_ADDR, &va);
}

#endif

extern CPUState *kvm_debug_cpu_requested;

int kvm_arch_run(CPUState *env)
{
    int r = 0;
    struct kvm_run *run = env->kvm_run;

    switch (run->exit_reason) {
#ifdef KVM_EXIT_SET_TPR
    case KVM_EXIT_SET_TPR:
        break;
#endif
#ifdef KVM_EXIT_TPR_ACCESS
    case KVM_EXIT_TPR_ACCESS:
        r = kvm_handle_tpr_access(env);
        break;
#endif
#ifdef KVM_CAP_SET_GUEST_DEBUG
    case KVM_EXIT_DEBUG:
        DPRINTF("kvm_exit_debug\n");
        r = kvm_handle_debug(&run->debug.arch);
        if (r == EXCP_DEBUG) {
            kvm_debug_cpu_requested = env;
            env->stopped = 1;
        }
        break;
#endif /* KVM_CAP_SET_GUEST_DEBUG */
    default:
        r = -1;
        break;
    }

    return r;
}

#ifdef KVM_CAP_IRQCHIP

int kvm_get_lapic(CPUState *env, struct kvm_lapic_state *s)
{
    int r = 0;

    if (!kvm_irqchip_in_kernel()) {
        return r;
    }

    r = kvm_vcpu_ioctl(env, KVM_GET_LAPIC, s);
    if (r < 0) {
        fprintf(stderr, "KVM_GET_LAPIC failed\n");
    }
    return r;
}

int kvm_set_lapic(CPUState *env, struct kvm_lapic_state *s)
{
    int r = 0;

    if (!kvm_irqchip_in_kernel()) {
        return 0;
    }

    r = kvm_vcpu_ioctl(env, KVM_SET_LAPIC, s);

    if (r < 0) {
        fprintf(stderr, "KVM_SET_LAPIC failed\n");
    }
    return r;
}

#endif

#ifdef KVM_CAP_PIT

int kvm_get_pit(kvm_context_t kvm, struct kvm_pit_state *s)
{
    if (!kvm_pit_in_kernel()) {
        return 0;
    }
    return kvm_vm_ioctl(kvm_state, KVM_GET_PIT, s);
}

int kvm_set_pit(kvm_context_t kvm, struct kvm_pit_state *s)
{
    if (!kvm_pit_in_kernel()) {
        return 0;
    }
    return kvm_vm_ioctl(kvm_state, KVM_SET_PIT, s);
}

#ifdef KVM_CAP_PIT_STATE2
int kvm_get_pit2(kvm_context_t kvm, struct kvm_pit_state2 *ps2)
{
    if (!kvm_pit_in_kernel()) {
        return 0;
    }
    return kvm_vm_ioctl(kvm_state, KVM_GET_PIT2, ps2);
}

int kvm_set_pit2(kvm_context_t kvm, struct kvm_pit_state2 *ps2)
{
    if (!kvm_pit_in_kernel()) {
        return 0;
    }
    return kvm_vm_ioctl(kvm_state, KVM_SET_PIT2, ps2);
}

#endif
#endif

int kvm_has_pit_state2(kvm_context_t kvm)
{
    int r = 0;

#ifdef KVM_CAP_PIT_STATE2
    r = kvm_check_extension(kvm_state, KVM_CAP_PIT_STATE2);
#endif
    return r;
}

static void kvm_set_cr8(CPUState *env, uint64_t cr8)
{
    env->kvm_run->cr8 = cr8;
}

int kvm_set_shadow_pages(kvm_context_t kvm, unsigned int nrshadow_pages)
{
#ifdef KVM_CAP_MMU_SHADOW_CACHE_CONTROL
    int r;

    r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION,
                  KVM_CAP_MMU_SHADOW_CACHE_CONTROL);
    if (r > 0) {
        r = kvm_vm_ioctl(kvm_state, KVM_SET_NR_MMU_PAGES, nrshadow_pages);
        if (r < 0) {
            fprintf(stderr, "kvm_set_shadow_pages: %m\n");
            return r;
        }
        return 0;
    }
#endif
    return -1;
}

#ifdef KVM_CAP_VAPIC
static int kvm_enable_tpr_access_reporting(CPUState *env)
{
    int r;
    struct kvm_tpr_access_ctl tac = { .enabled = 1 };

    r = kvm_ioctl(env->kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_VAPIC);
    if (r <= 0) {
        return -ENOSYS;
    }
    return kvm_vcpu_ioctl(env, KVM_TPR_ACCESS_REPORTING, &tac);
}
#endif

static int _kvm_arch_init_vcpu(CPUState *env)
{
    kvm_arch_reset_vcpu(env);

#ifdef KVM_EXIT_TPR_ACCESS
    kvm_enable_tpr_access_reporting(env);
#endif
    return 0;
}

int kvm_arch_halt(CPUState *env)
{

    if (!((env->interrupt_request & CPU_INTERRUPT_HARD) &&
          (env->eflags & IF_MASK)) &&
        !(env->interrupt_request & CPU_INTERRUPT_NMI)) {
        env->halted = 1;
    }
    return 1;
}

void kvm_arch_pre_run(CPUState *env, struct kvm_run *run)
{
    if (!kvm_irqchip_in_kernel()) {
        kvm_set_cr8(env, cpu_get_apic_tpr(env->apic_state));
    }
}

int kvm_arch_has_work(CPUState *env)
{
    if (((env->interrupt_request & CPU_INTERRUPT_HARD) &&
         (env->eflags & IF_MASK)) ||
        (env->interrupt_request & CPU_INTERRUPT_NMI)) {
        return 1;
    }
    return 0;
}

int kvm_arch_try_push_interrupts(void *opaque)
{
    CPUState *env = cpu_single_env;
    int r, irq;

    if (kvm_is_ready_for_interrupt_injection(env) &&
        (env->interrupt_request & CPU_INTERRUPT_HARD) &&
        (env->eflags & IF_MASK)) {
        env->interrupt_request &= ~CPU_INTERRUPT_HARD;
        irq = cpu_get_pic_interrupt(env);
        if (irq >= 0) {
            r = kvm_inject_irq(env, irq);
            if (r < 0) {
                printf("cpu %d fail inject %x\n", env->cpu_index, irq);
            }
        }
    }

    return (env->interrupt_request & CPU_INTERRUPT_HARD) != 0;
}

#ifdef KVM_CAP_USER_NMI
void kvm_arch_push_nmi(void)
{
    CPUState *env = cpu_single_env;
    int r;

    if (likely(!(env->interrupt_request & CPU_INTERRUPT_NMI))) {
        return;
    }

    env->interrupt_request &= ~CPU_INTERRUPT_NMI;
    r = kvm_inject_nmi(env);
    if (r < 0) {
        printf("cpu %d fail inject NMI\n", env->cpu_index);
    }
}
#endif /* KVM_CAP_USER_NMI */

#ifdef CONFIG_KVM_DEVICE_ASSIGNMENT
void kvm_arch_do_ioperm(void *_data)
{
    struct ioperm_data *data = _data;
    ioperm(data->start_port, data->num, data->turn_on);
}
#endif

/*
 * Setup x86 specific IRQ routing
 */
int kvm_arch_init_irq_routing(void)
{
    int i, r;

    if (kvm_irqchip && kvm_has_gsi_routing()) {
        kvm_clear_gsi_routes();
        for (i = 0; i < 8; ++i) {
            if (i == 2) {
                continue;
            }
            r = kvm_add_irq_route(i, KVM_IRQCHIP_PIC_MASTER, i);
            if (r < 0) {
                return r;
            }
        }
        for (i = 8; i < 16; ++i) {
            r = kvm_add_irq_route(i, KVM_IRQCHIP_PIC_SLAVE, i - 8);
            if (r < 0) {
                return r;
            }
        }
        for (i = 0; i < 24; ++i) {
            if (i == 0 && irq0override) {
                r = kvm_add_irq_route(i, KVM_IRQCHIP_IOAPIC, 2);
            } else if (i != 2 || !irq0override) {
                r = kvm_add_irq_route(i, KVM_IRQCHIP_IOAPIC, i);
            }
            if (r < 0) {
                return r;
            }
        }
        kvm_commit_irq_routes();
    }
    return 0;
}

void kvm_arch_process_irqchip_events(CPUState *env)
{
    if (env->interrupt_request & CPU_INTERRUPT_INIT) {
        kvm_cpu_synchronize_state(env);
        do_cpu_init(env);
    }
    if (env->interrupt_request & CPU_INTERRUPT_SIPI) {
        kvm_cpu_synchronize_state(env);
        do_cpu_sipi(env);
    }
}

int kvm_arch_process_async_events(CPUState *env)
{
    if (env->interrupt_request & CPU_INTERRUPT_MCE) {
        /* We must not raise CPU_INTERRUPT_MCE if it's not supported. */
        assert(env->mcg_cap);

        env->interrupt_request &= ~CPU_INTERRUPT_MCE;

        kvm_cpu_synchronize_state(env);

        if (env->exception_injected == EXCP08_DBLE) {
            /* this means triple fault */
            qemu_system_reset_request();
            env->exit_request = 1;
            return 0;
        }
        env->exception_injected = EXCP12_MCHK;
        env->has_error_code = 0;

        env->halted = 0;
        if (kvm_irqchip_in_kernel() && env->mp_state == KVM_MP_STATE_HALTED) {
            env->mp_state = KVM_MP_STATE_RUNNABLE;
        }
    }
    return 0;
}
