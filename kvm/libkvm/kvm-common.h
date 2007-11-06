/*
 * This header is for functions & variables that will ONLY be
 * used inside libkvm.
 *
 * derived from libkvm.c
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *	Avi Kivity   <avi@qumranet.com>
 *	Yaniv Kamay  <yaniv@qumranet.com>
 *
 *   This work is licensed under the GNU LGPL license, version 2.
 */

#ifndef KVM_COMMON_H
#define KVM_COMMON_H

/* FIXME: share this number with kvm */
/* FIXME: or dynamically alloc/realloc regions */
#define KVM_MAX_NUM_MEM_REGIONS 8u
#define MAX_VCPUS 4


/**
 * \brief The KVM context
 *
 * The verbose KVM context
 */

struct kvm_context {
	/// Filedescriptor to /dev/kvm
	int fd;
	int vm_fd;
	int vcpu_fd[MAX_VCPUS];
	struct kvm_run *run[MAX_VCPUS];
	/// Callbacks that KVM uses to emulate various unvirtualizable functionality
	struct kvm_callbacks *callbacks;
	void *opaque;
	/// A pointer to the memory used as the physical memory for the guest
	void *physical_memory;
	/// is dirty pages logging enabled for all regions or not
	int dirty_pages_log_all;
	/// memory regions parameters
	struct kvm_memory_region mem_regions[KVM_MAX_NUM_MEM_REGIONS];
	/// do not create in-kernel irqchip if set
	int no_irqchip_creation;
	/// in-kernel irqchip status
	int irqchip_in_kernel;
};

#endif
