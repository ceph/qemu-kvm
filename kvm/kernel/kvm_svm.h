#ifndef __KVM_SVM_H
#define __KVM_SVM_H

#include <linux/types.h>
#include <linux/list.h>
#include <asm/msr.h>

#include "svm.h"
#include "kvm.h"

static const u32 host_save_msrs[] = {
	MSR_STAR, MSR_LSTAR, MSR_CSTAR, MSR_SYSCALL_MASK, MSR_KERNEL_GS_BASE,
	MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, MSR_IA32_SYSENTER_EIP,
	MSR_IA32_DEBUGCTLMSR, /*MSR_IA32_LASTBRANCHFROMIP,
	MSR_IA32_LASTBRANCHTOIP, MSR_IA32_LASTINTFROMIP,MSR_IA32_LASTINTTOIP,*/
	MSR_FS_BASE, MSR_GS_BASE,
};

#define NR_HOST_SAVE_MSRS (sizeof(host_save_msrs) / sizeof(*host_save_msrs))
#define NUM_AB_RSGS 4

struct vcpu_svm {
	struct vmcb *vmcb;
	unsigned long vmcb_pa;
	struct svm_cpu_data *svm_data;
	uint64_t asid_generation;

	unsigned long cr0;
	unsigned long cr4;
	unsigned long ab_regs[NUM_AB_RSGS];

	u64 next_rip;

	u64 host_msrs[NR_HOST_SAVE_MSRS];
	unsigned long host_cr2;
	unsigned long host_ab_regs[NUM_AB_RSGS];
	unsigned long host_dr6;
	unsigned long host_dr7;
};

#endif

