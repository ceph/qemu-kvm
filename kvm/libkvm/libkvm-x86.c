#include "libkvm.h"
#include "kvm-x86.h"
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


#ifdef KVM_CAP_USER_MEMORY

int kvm_alloc_userspace_memory(kvm_context_t kvm, unsigned long memory,
								void **vm_mem)
{
	unsigned long dosmem = 0xa0000;
	unsigned long exmem = 0xc0000;
	unsigned long pcimem = 0xe0000000;
	int r;
	int tss_ext;
	struct kvm_userspace_memory_region low_memory = {
		.memory_size = memory  < dosmem ? memory : dosmem,
		.guest_phys_addr = 0,
	};
	struct kvm_userspace_memory_region extended_memory = {
		.memory_size = memory < exmem ? 0 : memory - exmem,
		.guest_phys_addr = exmem,
	};
	struct kvm_userspace_memory_region above_4g_memory = {
		.memory_size = memory < pcimem ? 0 : memory - pcimem,
		.guest_phys_addr = 0x100000000ULL,
	};

#ifdef KVM_CAP_SET_TSS_ADDR
	tss_ext = ioctl(kvm->fd, KVM_CHECK_EXTENSION, KVM_CAP_SET_TSS_ADDR);
#else
	tss_ext = 0;
#endif

	if (memory >= pcimem) {
		extended_memory.memory_size = pcimem - exmem;
		*vm_mem = mmap(NULL, memory + 0x100000000ULL - pcimem,
				PROT_READ|PROT_WRITE, MAP_ANONYMOUS |
							MAP_SHARED, -1, 0);
	}
	else
		*vm_mem = mmap(NULL, memory, PROT_READ|PROT_WRITE, MAP_ANONYMOUS
							| MAP_SHARED, -1, 0);
	if (*vm_mem == MAP_FAILED) {
		fprintf(stderr, "kvm_alloc_userspace_memory: %s", strerror(errno));
		return -1;
	}

	low_memory.userspace_addr = (unsigned long)*vm_mem;
	low_memory.slot = get_free_slot(kvm);
	/* 640K should be enough. */
	r = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &low_memory);
	if (r == -1) {
		fprintf(stderr, "kvm_create_memory_region: %m\n");
		return -1;
	}
	register_slot(low_memory.slot, low_memory.guest_phys_addr);

	if (extended_memory.memory_size) {
		r = munmap(*vm_mem + dosmem, exmem - dosmem);
		if (r == -1) {
			fprintf(stderr, "kvm_alloc_userspace_memory: %s",
							strerror(errno));
			return -1;
		}
		extended_memory.userspace_addr = (unsigned long)(*vm_mem + exmem);
		if (tss_ext > 0)
			extended_memory.slot = get_free_slot(kvm);
		else
			extended_memory.slot = 0;
		r = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &extended_memory);
		if (r == -1) {
			fprintf(stderr, "kvm_create_memory_region: %m\n");
			return -1;
		}
		register_slot(extended_memory.slot,
			      extended_memory.guest_phys_addr);
	}

	if (above_4g_memory.memory_size) {
		r = munmap(*vm_mem + pcimem, 0x100000000ULL - pcimem);
		if (r == -1) {
			fprintf(stderr, "kvm_alloc_userspace_memory: %s",
							strerror(errno));
			return -1;
		}
		above_4g_memory.userspace_addr = (unsigned long)(*vm_mem + 0x100000000ULL);
		above_4g_memory.slot = get_free_slot(kvm);
		r = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &above_4g_memory);
		if (r == -1) {
			fprintf(stderr, "kvm_create_memory_region: %m\n");
			return -1;
		}
		register_slot(above_4g_memory.slot,
			      above_4g_memory.guest_phys_addr);
	}

	kvm_userspace_memory_region_save_params(kvm, &low_memory);
	kvm_userspace_memory_region_save_params(kvm, &extended_memory);
	if (above_4g_memory.memory_size)
		kvm_userspace_memory_region_save_params(kvm, &above_4g_memory);

	return 0;
}

#endif

int kvm_set_tss_addr(kvm_context_t kvm, unsigned long addr)
{
#ifdef KVM_CAP_SET_TSS_ADDR
	int r;

	r = ioctl(kvm->fd, KVM_CHECK_EXTENSION, KVM_CAP_SET_TSS_ADDR);
	if (r > 0) {
		r = ioctl(kvm->vm_fd, KVM_SET_TSS_ADDR, addr);
		if (r == -1) {
			fprintf(stderr, "kvm_set_tss_addr: %m\n");
			return -errno;
		}
		return 0;
	}
#endif
	return -ENOSYS;
}

static int kvm_init_tss(kvm_context_t kvm)
{
#ifdef KVM_CAP_SET_TSS_ADDR
	int r;

	r = ioctl(kvm->fd, KVM_CHECK_EXTENSION, KVM_CAP_SET_TSS_ADDR);
	if (r > 0) {
		/*
		 * this address is 3 pages before the bios, and the bios should present
		 * as unavaible memory
		 */
		r = kvm_set_tss_addr(kvm, 0xfffbd000);
		if (r < 0) {
			printf("kvm_init_tss: unable to set tss addr\n");
			return r;
		}

	}
#endif
	return 0;
}

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
	int r = 0;

	r = kvm_init_tss(kvm);
	if (r < 0)
		return r;

	return 0;
}

void *kvm_create_kernel_phys_mem(kvm_context_t kvm, unsigned long phys_start,
			unsigned long len, int log, int writable)
{
	int r;
	int prot = PROT_READ;
	void *ptr;
	struct kvm_memory_region memory = {
		.memory_size = len,
		.guest_phys_addr = phys_start,
		.flags = log ? KVM_MEM_LOG_DIRTY_PAGES : 0,
	};

	memory.slot = get_free_slot(kvm);
	r = ioctl(kvm->vm_fd, KVM_SET_MEMORY_REGION, &memory);
	if (r == -1) {
		fprintf(stderr, "create_kernel_phys_mem: %s", strerror(errno));
		return 0;
	}
	register_slot(memory.slot, memory.guest_phys_addr);
	kvm_memory_region_save_params(kvm, &memory);

	if (writable)
		prot |= PROT_WRITE;

	ptr = mmap(NULL, len, prot, MAP_SHARED, kvm->vm_fd, phys_start);
	if (ptr == MAP_FAILED) {
		fprintf(stderr, "create_kernel_phys_mem: %s", strerror(errno));
		return 0;
	}

	return ptr;
}

int kvm_create_memory_alias(kvm_context_t kvm,
			    uint64_t phys_addr,
			    uint64_t phys_start,
			    uint64_t len,
			    uint64_t target_phys)
{
	struct kvm_memory_alias alias = {
		.flags = 0,
		.guest_phys_addr = phys_start,
		.memory_size = len,
		.target_phys_addr = target_phys,
	};
	int fd = kvm->vm_fd;
	int r;

	alias.slot = get_slot(phys_addr);

	r = ioctl(fd, KVM_SET_MEMORY_ALIAS, &alias);
	if (r == -1)
	    return -errno;

	return 0;
}

int kvm_destroy_memory_alias(kvm_context_t kvm, uint64_t phys_addr)
{
	return kvm_create_memory_alias(kvm, phys_addr, 0, 0, 0);
}

