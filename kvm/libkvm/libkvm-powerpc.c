/*
 * This header is for functions & variables that will ONLY be
 * used inside libkvm for x86.
 * THESE ARE NOT EXPOSED TO THE USER AND ARE ONLY FOR USE
 * WITHIN LIBKVM.
 *
 * derived from libkvm.c
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *      Avi Kivity   <avi@qumranet.com>
 *      Yaniv Kamay  <yaniv@qumranet.com>
 *
 * Copyright 2007 IBM Corporation.
 * Added by & Authors:
 * 	Jerone Young <jyoung5@us.ibm.com>
 * 	Christian Ehrhardt <ehrhardt@linux.vnet.ibm.com>
 *
 *
 * This work is licensed under the GNU LGPL license, version 2.
 */

#include "libkvm.h"
#include "kvm-powerpc.h"
#include <errno.h>
#include <stdio.h>

int handle_dcr(struct kvm_run *run,  kvm_context_t kvm)
{
	int ret = 0;

	if (run->dcr.is_write)
		ret = kvm->callbacks->powerpc_dcr_write(run->dcr.dcrn,
							run->dcr.data);
	else
		ret = kvm->callbacks->powerpc_dcr_read(run->dcr.dcrn,
							&(run->dcr.data));

	return ret;
}

int kvm_alloc_kernel_memory(kvm_context_t kvm, unsigned long memory,
				void **vm_mem)
{
	fprintf(stderr, "%s: Operation not supported\n", __FUNCTION__);
	return -1;
}

void *kvm_create_kernel_phys_mem(kvm_context_t kvm, unsigned long phys_start,
				 unsigned long len, int log, int writable)
{
	fprintf(stderr, "%s: Operation not supported\n", __FUNCTION__);
	return NULL;
}

void kvm_show_code(kvm_context_t kvm, int vcpu)
{
	fprintf(stderr, "%s: Operation not supported\n", __FUNCTION__);
}

void kvm_show_regs(kvm_context_t kvm, int vcpu)
{
	struct kvm_regs regs;
	int i;

	if (kvm_get_regs(kvm, vcpu, &regs))
		return;

	for (i=0; i<32; i+=4)
	{
		fprintf(stderr, "gpr%02d: %08x %08x %08x %08x\n", i,
			regs.gpr[i],
			regs.gpr[i+1],
			regs.gpr[i+2],
			regs.gpr[i+3]);
	}

	fflush(stdout);
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
	int ret = 0;

	switch (run->exit_reason){
	case KVM_EXIT_DCR:
		ret = handle_dcr(run, kvm);
		break;
	default:
		ret = 1;
		break;
	}
	return ret;
}
