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

/* kvm abi verison variable */
extern int kvm_abi;

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

void init_slots(void);
int get_free_slot(kvm_context_t kvm);
void register_slot(int slot, unsigned long phys_addr, unsigned long len,
		   int user_alloc, unsigned long userspace_addr);
void free_slot(int slot);
int get_slot(unsigned long phys_addr);
int kvm_arch_create(kvm_context_t kvm, unsigned long phys_mem_bytes,
                        void **vm_mem);
int kvm_arch_create_default_phys_mem(kvm_context_t kvm,
                                       unsigned long phys_mem_bytes,
                                       void **vm_mem);

int handle_halt(kvm_context_t kvm, int vcpu);
int handle_shutdown(kvm_context_t kvm, int vcpu);
void post_kvm_run(kvm_context_t kvm, int vcpu);
int pre_kvm_run(kvm_context_t kvm, int vcpu);
int handle_io_window(kvm_context_t kvm);
int handle_debug(kvm_context_t kvm, int vcpu);
int try_push_interrupts(kvm_context_t kvm);

#endif
