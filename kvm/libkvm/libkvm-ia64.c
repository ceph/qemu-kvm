/*
 * libkvm-ia64.c :Kernel-based Virtual Machine control library for ia64.
 *
 * This library provides an API to control the kvm hardware virtualization
 * module.
 *
 * Copyright (C) 2006 Qumranet
 *
 * Authors:
 *
 *  Avi Kivity <avi@qumranet.com>
 *  Yaniv Kamay <yaniv@qumranet.com>
 *
 * Copyright (C) 2007 Intel
 * Added by : Zhang Xiantao <xiantao.zhang@intel.com>
 *
 * This work is licensed under the GNU LGPL license, version 2.
 *
 */

#include "libkvm.h"
#include "kvm-ia64.h"
#include <errno.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/mman.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

int kvm_arch_create_default_phys_mem(kvm_context_t kvm,
				       unsigned long phys_mem_bytes,
				       void **vm_mem)
{
	int zfd;

	zfd = open("/dev/zero", O_RDONLY);
	if (zfd == -1) {
		perror("open /dev/zero");
		return -1;
	}
        mmap(*vm_mem + 0xa8000, 0x8000, PROT_READ|PROT_WRITE,
             MAP_PRIVATE|MAP_FIXED, zfd, 0);
        close(zfd);

	return 0;
}


int kvm_arch_create(kvm_context_t kvm, unsigned long phys_mem_bytes,
			void **vm_mem)
{
	return 0;
}

int kvm_arch_run(struct kvm_run *run,kvm_context_t kvm, int vcpu)
{
	int r = 0;

	switch (run->exit_reason) {
		default:
			r = 1;
			break;
	}

	return r;
}

void kvm_show_code(kvm_context_t kvm, int vcpu)
{
	fprintf(stderr, "kvm_show_code not supported yet!\n");
}

void kvm_show_regs(kvm_context_t kvm, int vcpu)
{
	fprintf(stderr,"kvm_show_regs not supportted today!\n");
}
