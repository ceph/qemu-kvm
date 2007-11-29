#include "libkvm.h"
#include "kvm-powerpc.h"
#include <errno.h>

int kvm_run_abi10(kvm_context_t kvm, int vcpu)
{
	return -ENOSYS;
}

void kvm_show_code(kvm_context_t kvm, int vcpu)
{
}

void kvm_show_regs(kvm_context_t kvm, int vcpu)
{
}

int kvm_arch_create(kvm_context_t kvm, unsigned long phys_mem_bytes,
			 void **vm_mem)
{
	return 0;
}

int kvm_arch_create_default_phys_mem(kvm_context_t kvm,
					unsigned long phys_mem_bytes,
					void **vm_mem)
{
	return 0;
}

int kvm_arch_run(struct kvm_run *run, kvm_context_t kvm, int vcpu)
{
	return 0;
}
