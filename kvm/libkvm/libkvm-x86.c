#include "libkvm.h"
#include "kvm-x86.h"
#include <unistd.h>
#include <stropts.h>
#include <sys/mman.h>
#include <stdio.h>

int kvm_alloc_kernel_memory(kvm_context_t kvm, unsigned long memory,
								void **vm_mem)
{
	unsigned long dosmem = 0xa0000;
	unsigned long exmem = 0xc0000;
	unsigned long pcimem = 0xe0000000;
	int r;
	int tss_ext;
	struct kvm_memory_region low_memory = {
		.memory_size = memory  < dosmem ? memory : dosmem,
		.guest_phys_addr = 0,
	};
	struct kvm_memory_region extended_memory = {
		.memory_size = memory < exmem ? 0 : memory - exmem,
		.guest_phys_addr = exmem,
	};
	struct kvm_memory_region above_4g_memory = {
		.memory_size = memory < pcimem ? 0 : memory - pcimem,
		.guest_phys_addr = 0x100000000ULL,
	};

#ifdef KVM_CAP_SET_TSS_ADDR
	tss_ext = ioctl(kvm->fd, KVM_CHECK_EXTENSION, KVM_CAP_SET_TSS_ADDR);
#else
	tss_ext = 0;
#endif

	if (memory >= pcimem)
		extended_memory.memory_size = pcimem - exmem;

	/* 640K should be enough. */
	low_memory.slot = get_free_slot(kvm);
	r = ioctl(kvm->vm_fd, KVM_SET_MEMORY_REGION, &low_memory);
	if (r == -1) {
		fprintf(stderr, "kvm_create_memory_region: %m\n");
		return -1;
	}
	register_slot(low_memory.slot, low_memory.guest_phys_addr);

	if (extended_memory.memory_size) {
		if (tss_ext > 0)
			extended_memory.slot = get_free_slot(kvm);
		else
			extended_memory.slot = 0;
		r = ioctl(kvm->vm_fd, KVM_SET_MEMORY_REGION, &extended_memory);
		if (r == -1) {
			fprintf(stderr, "kvm_create_memory_region: %m\n");
			return -1;
		}
		register_slot(extended_memory.slot,
			      extended_memory.guest_phys_addr);
	}

	if (above_4g_memory.memory_size) {
		above_4g_memory.slot = get_free_slot(kvm);
		r = ioctl(kvm->vm_fd, KVM_SET_MEMORY_REGION, &above_4g_memory);
		if (r == -1) {
			fprintf(stderr, "kvm_create_memory_region: %m\n");
			return -1;
		}
		register_slot(above_4g_memory.slot,
			      above_4g_memory.guest_phys_addr);
	}

	kvm_memory_region_save_params(kvm, &low_memory);
	kvm_memory_region_save_params(kvm, &extended_memory);
	kvm_memory_region_save_params(kvm, &above_4g_memory);
	if (above_4g_memory.memory_size)
		kvm_memory_region_save_params(kvm, &above_4g_memory);

	*vm_mem = mmap(NULL, memory, PROT_READ|PROT_WRITE, MAP_SHARED, kvm->vm_fd, 0);

	return 0;
}
