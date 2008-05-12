
#include "config.h"
#include "config-host.h"

#include <string.h>

#include "hw/hw.h"
#include "qemu-kvm.h"
#include <libkvm.h>
#include <pthread.h>
#include <sys/utsname.h>


extern kvm_context_t kvm_context;

int kvm_arch_qemu_create_context(void)
{
	return 0;
}

void kvm_arch_load_regs(CPUState *env)
{
}


void kvm_arch_save_regs(CPUState *env)
{
}

int kvm_arch_qemu_init_env(CPUState *cenv)
{
    return 0;
}

int kvm_arch_halt(void *opaque, int vcpu)
{
    CPUState *env = cpu_single_env;
    env->hflags |= HF_HALTED_MASK;
    env->exception_index = EXCP_HLT;
    return 1;
}

void kvm_arch_pre_kvm_run(void *opaque, int vcpu)
{
}

void kvm_arch_post_kvm_run(void *opaque, int vcpu)
{
}

int kvm_arch_has_work(CPUState *env)
{
	return 1;
}

int kvm_arch_try_push_interrupts(void *opaque)
{
	return 1;
}

void kvm_arch_update_regs_for_sipi(CPUState *env)
{
}

void kvm_arch_cpu_reset(CPUState *env)
{
}
