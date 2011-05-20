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

static int kvm_create_pit(KVMState *s)
{
#ifdef KVM_CAP_PIT
    int r;

    if (kvm_pit) {
        r = kvm_vm_ioctl(s, KVM_CREATE_PIT);
        if (r < 0) {
            fprintf(stderr, "Create kernel PIC irqchip failed\n");
            return r;
        }
        if (!kvm_pit_reinject) {
            r = kvm_reinject_control(s, 0);
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

int kvm_get_pit(KVMState *s, struct kvm_pit_state *pit_state)
{
    if (!kvm_pit_in_kernel()) {
        return 0;
    }
    return kvm_vm_ioctl(s, KVM_GET_PIT, pit_state);
}

int kvm_set_pit(KVMState *s, struct kvm_pit_state *pit_state)
{
    if (!kvm_pit_in_kernel()) {
        return 0;
    }
    return kvm_vm_ioctl(s, KVM_SET_PIT, pit_state);
}

#ifdef KVM_CAP_PIT_STATE2
int kvm_get_pit2(KVMState *s, struct kvm_pit_state2 *ps2)
{
    if (!kvm_pit_in_kernel()) {
        return 0;
    }
    return kvm_vm_ioctl(s, KVM_GET_PIT2, ps2);
}

int kvm_set_pit2(KVMState *s, struct kvm_pit_state2 *ps2)
{
    if (!kvm_pit_in_kernel()) {
        return 0;
    }
    return kvm_vm_ioctl(s, KVM_SET_PIT2, ps2);
}

#endif
#endif

static void kvm_set_cr8(CPUState *env, uint64_t cr8)
{
    env->kvm_run->cr8 = cr8;
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

    if (kvm_has_gsi_routing()) {
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
            if (i == 0) {
                r = kvm_add_irq_route(i, KVM_IRQCHIP_IOAPIC, 2);
            } else if (i != 2) {
                r = kvm_add_irq_route(i, KVM_IRQCHIP_IOAPIC, i);
            }
            if (r < 0) {
                return r;
            }
        }
        kvm_commit_irq_routes();

        if (!kvm_has_pit_state2()) {
            no_hpet = 1;
        }
    } else {
        /* If kernel can't do irq routing, interrupt source
         * override 0->2 can not be set up as required by HPET.
         * so we have to disable it.
         */
        no_hpet = 1;
    }

    return 0;
}
