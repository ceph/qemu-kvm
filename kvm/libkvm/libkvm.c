/*
 * Kernel-based Virtual Machine control library
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
 * This work is licensed under the GNU LGPL license, version 2.
 */

#ifndef __user
#define __user /* temporary, until installed via make headers_install */
#endif

#include <linux/kvm.h>

#define EXPECTED_KVM_API_VERSION 12

#if EXPECTED_KVM_API_VERSION != KVM_API_VERSION
#error libkvm: userspace and kernel version mismatch
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "libkvm.h"
#include "kvm-abi-10.h"

#if defined(__x86_64__) || defined(__i386__)
#include "kvm-x86.h"
#endif

int kvm_abi = EXPECTED_KVM_API_VERSION;

struct slot_info {
	unsigned long phys_addr;
	unsigned long len;
	int user_alloc;
	unsigned long userspace_addr;
};

struct slot_info slots[KVM_MAX_NUM_MEM_REGIONS];

void init_slots(void)
{
	int i;

	for (i = 0; i < KVM_MAX_NUM_MEM_REGIONS; ++i)
		slots[i].len = 0;
}

int get_free_slot(kvm_context_t kvm)
{
	int i;
	int tss_ext;

#ifdef KVM_CAP_SET_TSS_ADDR
	tss_ext = ioctl(kvm->fd, KVM_CHECK_EXTENSION, KVM_CAP_SET_TSS_ADDR);
#else
	tss_ext = 0;
#endif

	/*
	 * on older kernels where the set tss ioctl is not supprted we must save
	 * slot 0 to hold the extended memory, as the vmx will use the last 3
	 * pages of this slot.
	 */
	if (tss_ext > 0)
		i = 0;
	else
		i = 1;

	for (; i < KVM_MAX_NUM_MEM_REGIONS; ++i)
		if (!slots[i].len)
			return i;
	return -1;
}

void register_slot(int slot, unsigned long phys_addr, unsigned long len,
		   int user_alloc, unsigned long userspace_addr)
{
	slots[slot].phys_addr = phys_addr;
	slots[slot].len = len;
	slots[slot].user_alloc = user_alloc;
	slots[slot].userspace_addr = userspace_addr;
}

void free_slot(int slot)
{
	slots[slot].len = 0;
}

int get_slot(unsigned long phys_addr)
{
	int i;

	for (i = 0; i < KVM_MAX_NUM_MEM_REGIONS ; ++i) {
		if (slots[i].len && slots[i].phys_addr <= phys_addr &&
	 	    (slots[i].phys_addr + slots[i].len) >= phys_addr)
			return i;
	}
	return -1;
}

/* 
 * dirty pages logging control 
 */
static int kvm_dirty_pages_log_change(kvm_context_t kvm, unsigned long phys_addr
				      , __u32 flag)
{
	int r;
	int slot;

	slot = get_slot(phys_addr);
	if (slot == -1) {
		fprintf(stderr, "BUG: %s: invalid parameters\n", __FUNCTION__);
		return 1;
	}
#ifdef KVM_CAP_USER_MEMORY
	if (slots[slot].user_alloc) {
		struct kvm_userspace_memory_region mem = {
			.slot = slot,
			.memory_size = slots[slot].len,
			.guest_phys_addr = slots[slot].phys_addr,
			.userspace_addr = slots[slot].userspace_addr,
			.flags = flag,
		};
		r = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &mem);
	}
#endif
	if (!slots[slot].user_alloc) {
		struct kvm_memory_region mem = {
			.slot = slot,
			.memory_size = slots[slot].len,
			.guest_phys_addr = slots[slot].phys_addr,
			.flags = flag,
		};
		r = ioctl(kvm->vm_fd, KVM_SET_MEMORY_REGION, &mem);
	}
	if (r == -1)
		fprintf(stderr, "%s: %m\n", __FUNCTION__);
	return r;
}

static int kvm_dirty_pages_log_change_all(kvm_context_t kvm, __u32 flag)
{
	int i, r;

	for (i=r=0; i<KVM_MAX_NUM_MEM_REGIONS && r==0; i++) {
		if (slots[i].len)
			r = kvm_dirty_pages_log_change(kvm, slots[i].phys_addr,
						       flag);
	}
	return r;
}

/**
 * Enable dirty page logging for all memory regions
 */
int kvm_dirty_pages_log_enable_all(kvm_context_t kvm)
{
	if (kvm->dirty_pages_log_all)
		return 0;
	kvm->dirty_pages_log_all = 1;
	return kvm_dirty_pages_log_change_all(kvm, KVM_MEM_LOG_DIRTY_PAGES);
}

/**
 * Enable dirty page logging only for memory regions that were created with
 *     dirty logging enabled (disable for all other memory regions).
 */
int kvm_dirty_pages_log_reset(kvm_context_t kvm)
{
	if (!kvm->dirty_pages_log_all)
		return 0;
	kvm->dirty_pages_log_all = 0;
	return kvm_dirty_pages_log_change_all(kvm, 0);
}


kvm_context_t kvm_init(struct kvm_callbacks *callbacks,
		       void *opaque)
{
	int fd;
	kvm_context_t kvm;
	int r;

	fd = open("/dev/kvm", O_RDWR);
	if (fd == -1) {
		perror("open /dev/kvm");
		return NULL;
	}
	r = ioctl(fd, KVM_GET_API_VERSION, 0);
	if (r == -1) {
	    fprintf(stderr, "kvm kernel version too old: "
		    "KVM_GET_API_VERSION ioctl not supported\n");
	    goto out_close;
	}
	if (r < EXPECTED_KVM_API_VERSION && r != 10) {
		fprintf(stderr, "kvm kernel version too old: "
			"We expect API version %d or newer, but got "
			"version %d\n",
			EXPECTED_KVM_API_VERSION, r);
	    goto out_close;
	}
	if (r > EXPECTED_KVM_API_VERSION) {
	    fprintf(stderr, "kvm userspace version too old\n");
	    goto out_close;
	}
	kvm_abi = r;
	kvm = malloc(sizeof(*kvm));
	kvm->fd = fd;
	kvm->vm_fd = -1;
	kvm->callbacks = callbacks;
	kvm->opaque = opaque;
	kvm->dirty_pages_log_all = 0;
	kvm->no_irqchip_creation = 0;
	memset(&kvm->mem_regions, 0, sizeof(kvm->mem_regions));

	return kvm;
 out_close:
	close(fd);
	return NULL;
}

void kvm_finalize(kvm_context_t kvm)
{
    	if (kvm->vcpu_fd[0] != -1)
		close(kvm->vcpu_fd[0]);
    	if (kvm->vm_fd != -1)
		close(kvm->vm_fd);
	close(kvm->fd);
	free(kvm);
}

void kvm_disable_irqchip_creation(kvm_context_t kvm)
{
	kvm->no_irqchip_creation = 1;
}

int kvm_create_vcpu(kvm_context_t kvm, int slot)
{
	long mmap_size;
	int r;

	r = ioctl(kvm->vm_fd, KVM_CREATE_VCPU, slot);
	if (r == -1) {
		r = -errno;
		fprintf(stderr, "kvm_create_vcpu: %m\n");
		return r;
	}
	kvm->vcpu_fd[slot] = r;
	mmap_size = ioctl(kvm->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (mmap_size == -1) {
		r = -errno;
		fprintf(stderr, "get vcpu mmap size: %m\n");
		return r;
	}
	kvm->run[slot] = mmap(NULL, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED,
			      kvm->vcpu_fd[slot], 0);
	if (kvm->run[slot] == MAP_FAILED) {
		r = -errno;
		fprintf(stderr, "mmap vcpu area: %m\n");
		return r;
	}
	return 0;
}

int kvm_set_shadow_pages(kvm_context_t kvm, unsigned int nrshadow_pages)
{
#ifdef KVM_CAP_MMU_SHADOW_CACHE_CONTROL
	int r;

	r = ioctl(kvm->fd, KVM_CHECK_EXTENSION,
		  KVM_CAP_MMU_SHADOW_CACHE_CONTROL);
	if (r > 0) {
		r = ioctl(kvm->vm_fd, KVM_SET_NR_MMU_PAGES, nrshadow_pages);
		if (r == -1) {
			fprintf(stderr, "kvm_set_shadow_pages: %m\n");
			return -errno;
		}
		return 0;
	}
#endif
	return -1;
}

int kvm_get_shadow_pages(kvm_context_t kvm, unsigned int *nrshadow_pages)
{
#ifdef KVM_CAP_MMU_SHADOW_CACHE_CONTROL
	int r;

	r = ioctl(kvm->fd, KVM_CHECK_EXTENSION,
		  KVM_CAP_MMU_SHADOW_CACHE_CONTROL);
	if (r > 0) {
		*nrshadow_pages = ioctl(kvm->vm_fd, KVM_GET_NR_MMU_PAGES);
		return 0;
	}
#endif
	return -1;
}


int kvm_create_vm(kvm_context_t kvm)
{
	int fd = kvm->fd;

	kvm->vcpu_fd[0] = -1;

	fd = ioctl(fd, KVM_CREATE_VM, 0);
	if (fd == -1) {
		fprintf(stderr, "kvm_create_vm: %m\n");
		return -1;
	}
	kvm->vm_fd = fd;
	return 0;
}

static int kvm_create_default_phys_mem(kvm_context_t kvm,
				       unsigned long phys_mem_bytes,
				       void **vm_mem)
{
	unsigned long memory = (phys_mem_bytes + PAGE_SIZE - 1) & PAGE_MASK;
	int r;

#ifdef KVM_CAP_USER_MEMORY
	r = ioctl(kvm->fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
	if (r > 0)
		r = kvm_alloc_userspace_memory(kvm, memory, vm_mem);
	else
#endif
		r = kvm_alloc_kernel_memory(kvm, memory, vm_mem);
	if (r < 0)
		return r;

	r = kvm_arch_create_default_phys_mem(kvm, phys_mem_bytes, vm_mem);
	if (r < 0)
		return r;

	kvm->physical_memory = *vm_mem;
	return 0;
}

void kvm_create_irqchip(kvm_context_t kvm)
{
	int r;

	kvm->irqchip_in_kernel = 0;
#ifdef KVM_CAP_IRQCHIP
	if (!kvm->no_irqchip_creation) {
		r = ioctl(kvm->fd, KVM_CHECK_EXTENSION, KVM_CAP_IRQCHIP);
		if (r > 0) {	/* kernel irqchip supported */
			r = ioctl(kvm->vm_fd, KVM_CREATE_IRQCHIP);
			if (r >= 0)
				kvm->irqchip_in_kernel = 1;
			else
				printf("Create kernel PIC irqchip failed\n");
		}
	}
#endif
}

int kvm_create(kvm_context_t kvm, unsigned long phys_mem_bytes, void **vm_mem)
{
	int r;
	
	r = kvm_create_vm(kvm);
	if (r < 0)
	        return r;
	r = kvm_arch_create(kvm, phys_mem_bytes, vm_mem);
	if (r < 0)
		return r;
	init_slots();
	r = kvm_create_default_phys_mem(kvm, phys_mem_bytes, vm_mem);
	if (r < 0)
	        return r;
	kvm_create_irqchip(kvm);
	r = kvm_create_vcpu(kvm, 0);
	if (r < 0)
		return r;

	return 0;
}


#ifdef KVM_CAP_USER_MEMORY

void *kvm_create_userspace_phys_mem(kvm_context_t kvm, unsigned long phys_start,
			unsigned long len, int log, int writable)
{
	int r;
	int prot = PROT_READ;
	void *ptr;
	struct kvm_userspace_memory_region memory = {
		.memory_size = len,
		.guest_phys_addr = phys_start,
		.flags = log ? KVM_MEM_LOG_DIRTY_PAGES : 0,
	};

	if (writable)
		prot |= PROT_WRITE;

	ptr = mmap(NULL, len, prot, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (ptr == MAP_FAILED) {
		fprintf(stderr, "create_userspace_phys_mem: %s", strerror(errno));
		return 0;
	}

	memset(ptr, 0, len);

	memory.userspace_addr = (unsigned long)ptr;
	memory.slot = get_free_slot(kvm);
	r = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &memory);
	if (r == -1) {
		fprintf(stderr, "create_userspace_phys_mem: %s", strerror(errno));
		return 0;
	}
	register_slot(memory.slot, memory.guest_phys_addr, memory.memory_size,
		      1, memory.userspace_addr);

        return ptr;
}

#endif

void *kvm_create_phys_mem(kvm_context_t kvm, unsigned long phys_start,
			  unsigned long len, int log, int writable)
{
#ifdef KVM_CAP_USER_MEMORY
	int r;

	r = ioctl(kvm->fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
	if (r > 0)
		return kvm_create_userspace_phys_mem(kvm, phys_start, len,
								log, writable);
	else
#endif
		return kvm_create_kernel_phys_mem(kvm, phys_start, len,
								log, writable);
}

int kvm_register_userspace_phys_mem(kvm_context_t kvm,
			unsigned long phys_start, void *userspace_addr,
			unsigned long len, int log)
{
#ifdef KVM_CAP_USER_MEMORY
	struct kvm_userspace_memory_region memory = {
		.memory_size = len,
		.guest_phys_addr = phys_start,
		.userspace_addr = (intptr_t)userspace_addr,
		.flags = log ? KVM_MEM_LOG_DIRTY_PAGES : 0,
	};
	int r;

	if (!kvm->physical_memory)
		kvm->physical_memory = userspace_addr - phys_start;

	memory.slot = get_free_slot(kvm);
	r = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &memory);
	if (r == -1) {
		fprintf(stderr, "create_userspace_phys_mem: %s\n", strerror(errno));
		return -1;
	}
	register_slot(memory.slot, memory.guest_phys_addr, memory.memory_size,
		      1, memory.userspace_addr);
        return 0;
#else
	return -ENOSYS;
#endif
}


/* destroy/free a whole slot.
 * phys_start, len and slot are the params passed to kvm_create_phys_mem()
 */
void kvm_destroy_phys_mem(kvm_context_t kvm, unsigned long phys_start, 
			  unsigned long len)
{
	int slot;
	struct kvm_memory_region *mem;

	slot = get_slot(phys_start);

	if (slot >= KVM_MAX_NUM_MEM_REGIONS) {
		fprintf(stderr, "BUG: %s: invalid parameters (slot=%d)\n",
			__FUNCTION__, slot);
		return;
	}
	mem = &kvm->mem_regions[slot];
	if (phys_start != mem->guest_phys_addr) {
		fprintf(stderr,
			"WARNING: %s: phys_start is 0x%lx expecting 0x%llx\n",
			__FUNCTION__, phys_start, mem->guest_phys_addr);
		phys_start = mem->guest_phys_addr;
	}
	kvm_create_phys_mem(kvm, phys_start, 0, 0, 0);
}

static int kvm_get_map(kvm_context_t kvm, int ioctl_num, int slot, void *buf)
{
	int r;
	struct kvm_dirty_log log = {
		.slot = slot,
	};

	log.dirty_bitmap = buf;

	r = ioctl(kvm->vm_fd, ioctl_num, &log);
	if (r == -1)
		return -errno;
	return 0;
}

int kvm_get_dirty_pages(kvm_context_t kvm, unsigned long phys_addr, void *buf)
{
	int slot;

	slot = get_slot(phys_addr);
	return kvm_get_map(kvm, KVM_GET_DIRTY_LOG, slot, buf);
}

int kvm_get_mem_map(kvm_context_t kvm, unsigned long phys_addr, void *buf)
{
	int slot;

	slot = get_slot(phys_addr);
#ifdef KVM_GET_MEM_MAP
	return kvm_get_map(kvm, KVM_GET_MEM_MAP, slot, buf);
#else /* not KVM_GET_MEM_MAP ==> fake it: all pages exist */
	unsigned long i, n, m, npages;
	unsigned char v;

	if (slot >= KVM_MAX_NUM_MEM_REGIONS) {
		errno = -EINVAL;
		return -1;
	}
	npages = kvm->mem_regions[slot].memory_size / PAGE_SIZE;
	n = npages / 8;
	m = npages % 8;
	memset(buf, 0xff, n); /* all pages exist */
	v = 0;
	for (i=0; i<=m; i++) /* last byte may not be "aligned" */
		v |= 1<<(7-i);
	if (v)
		*(unsigned char*)(buf+n) = v;
	return 0;
#endif /* KVM_GET_MEM_MAP */
}

#ifdef KVM_CAP_IRQCHIP

int kvm_set_irq_level(kvm_context_t kvm, int irq, int level)
{
	struct kvm_irq_level event;
	int r;

	if (!kvm->irqchip_in_kernel)
		return 0;
	event.level = level;
	event.irq = irq;
	r = ioctl(kvm->vm_fd, KVM_IRQ_LINE, &event);
	if (r == -1)
		perror("kvm_set_irq_level");
	return 1;
}

int kvm_get_irqchip(kvm_context_t kvm, struct kvm_irqchip *chip)
{
	int r;

	if (!kvm->irqchip_in_kernel)
		return 0;
	r = ioctl(kvm->vm_fd, KVM_GET_IRQCHIP, chip);
	if (r == -1) {
		r = -errno;
		perror("kvm_get_irqchip\n");
	}
	return r;
}

int kvm_set_irqchip(kvm_context_t kvm, struct kvm_irqchip *chip)
{
	int r;

	if (!kvm->irqchip_in_kernel)
		return 0;
	r = ioctl(kvm->vm_fd, KVM_SET_IRQCHIP, chip);
	if (r == -1) {
		r = -errno;
		perror("kvm_set_irqchip\n");
	}
	return r;
}

#endif

static int handle_io(kvm_context_t kvm, struct kvm_run *run, int vcpu)
{
	uint16_t addr = run->io.port;
	int r;
	int i;
	void *p = (void *)run + run->io.data_offset;

	for (i = 0; i < run->io.count; ++i) {
		switch (run->io.direction) {
		case KVM_EXIT_IO_IN:
			switch (run->io.size) {
			case 1:
				r = kvm->callbacks->inb(kvm->opaque, addr, p);
				break;
			case 2:
				r = kvm->callbacks->inw(kvm->opaque, addr, p);
				break;
			case 4:
				r = kvm->callbacks->inl(kvm->opaque, addr, p);
				break;
			default:
				fprintf(stderr, "bad I/O size %d\n", run->io.size);
				return -EMSGSIZE;
			}
			break;
		case KVM_EXIT_IO_OUT:
		    	switch (run->io.size) {
			case 1:
				r = kvm->callbacks->outb(kvm->opaque, addr,
						     *(uint8_t *)p);
				break;
			case 2:
				r = kvm->callbacks->outw(kvm->opaque, addr,
						     *(uint16_t *)p);
				break;
			case 4:
				r = kvm->callbacks->outl(kvm->opaque, addr,
						     *(uint32_t *)p);
				break;
			default:
				fprintf(stderr, "bad I/O size %d\n", run->io.size);
				return -EMSGSIZE;
			}
			break;
		default:
			fprintf(stderr, "bad I/O direction %d\n", run->io.direction);
			return -EPROTO;
		}

		p += run->io.size;
	}

	return 0;
}

int handle_debug(kvm_context_t kvm, int vcpu)
{
	return kvm->callbacks->debug(kvm->opaque, vcpu);
}

int kvm_get_regs(kvm_context_t kvm, int vcpu, struct kvm_regs *regs)
{
    return ioctl(kvm->vcpu_fd[vcpu], KVM_GET_REGS, regs);
}

int kvm_set_regs(kvm_context_t kvm, int vcpu, struct kvm_regs *regs)
{
    return ioctl(kvm->vcpu_fd[vcpu], KVM_SET_REGS, regs);
}

int kvm_get_fpu(kvm_context_t kvm, int vcpu, struct kvm_fpu *fpu)
{
    return ioctl(kvm->vcpu_fd[vcpu], KVM_GET_FPU, fpu);
}

int kvm_set_fpu(kvm_context_t kvm, int vcpu, struct kvm_fpu *fpu)
{
    return ioctl(kvm->vcpu_fd[vcpu], KVM_SET_FPU, fpu);
}

int kvm_get_sregs(kvm_context_t kvm, int vcpu, struct kvm_sregs *sregs)
{
    return ioctl(kvm->vcpu_fd[vcpu], KVM_GET_SREGS, sregs);
}

int kvm_set_sregs(kvm_context_t kvm, int vcpu, struct kvm_sregs *sregs)
{
    return ioctl(kvm->vcpu_fd[vcpu], KVM_SET_SREGS, sregs);
}

static int handle_mmio(kvm_context_t kvm, struct kvm_run *kvm_run)
{
	unsigned long addr = kvm_run->mmio.phys_addr;
	void *data = kvm_run->mmio.data;
	int r = -1;

	/* hack: Red Hat 7.1 generates these wierd accesses. */
	if (addr == 0xa0000 && kvm_run->mmio.len == 3)
	    return 0;

	if (kvm_run->mmio.is_write) {
		switch (kvm_run->mmio.len) {
		case 1:
			r = kvm->callbacks->writeb(kvm->opaque, addr, *(uint8_t *)data);
			break;
		case 2:
			r = kvm->callbacks->writew(kvm->opaque, addr, *(uint16_t *)data);
			break;
		case 4:
			r = kvm->callbacks->writel(kvm->opaque, addr, *(uint32_t *)data);
			break;
		case 8:
			r = kvm->callbacks->writeq(kvm->opaque, addr, *(uint64_t *)data);
			break;
		}
	} else {
		switch (kvm_run->mmio.len) {
		case 1:
			r = kvm->callbacks->readb(kvm->opaque, addr, (uint8_t *)data);
			break;
		case 2:
			r = kvm->callbacks->readw(kvm->opaque, addr, (uint16_t *)data);
			break;
		case 4:
			r = kvm->callbacks->readl(kvm->opaque, addr, (uint32_t *)data);
			break;
		case 8:
			r = kvm->callbacks->readq(kvm->opaque, addr, (uint64_t *)data);
			break;
		}
	}
	return r;
}

int handle_io_window(kvm_context_t kvm)
{
	return kvm->callbacks->io_window(kvm->opaque);
}

int handle_halt(kvm_context_t kvm, int vcpu)
{
	return kvm->callbacks->halt(kvm->opaque, vcpu);
}

int handle_shutdown(kvm_context_t kvm, int vcpu)
{
	return kvm->callbacks->shutdown(kvm->opaque, vcpu);
}

int try_push_interrupts(kvm_context_t kvm)
{
	return kvm->callbacks->try_push_interrupts(kvm->opaque);
}

void post_kvm_run(kvm_context_t kvm, int vcpu)
{
	kvm->callbacks->post_kvm_run(kvm->opaque, vcpu);
}

int pre_kvm_run(kvm_context_t kvm, int vcpu)
{
	return kvm->callbacks->pre_kvm_run(kvm->opaque, vcpu);
}

int kvm_get_interrupt_flag(kvm_context_t kvm, int vcpu)
{
	struct kvm_run *run = kvm->run[vcpu];

	if (kvm_abi == 10)
		return ((struct kvm_run_abi10 *)run)->if_flag;
	return run->if_flag;
}

int kvm_is_ready_for_interrupt_injection(kvm_context_t kvm, int vcpu)
{
	struct kvm_run *run = kvm->run[vcpu];

	if (kvm_abi == 10)
		return ((struct kvm_run_abi10 *)run)->ready_for_interrupt_injection;
	return run->ready_for_interrupt_injection;
}

int kvm_run(kvm_context_t kvm, int vcpu)
{
	int r;
	int fd = kvm->vcpu_fd[vcpu];
	struct kvm_run *run = kvm->run[vcpu];

	if (kvm_abi == 10)
		return kvm_run_abi10(kvm, vcpu);

again:
	if (!kvm->irqchip_in_kernel)
		run->request_interrupt_window = try_push_interrupts(kvm);
	r = pre_kvm_run(kvm, vcpu);
	if (r)
	    return r;
	r = ioctl(fd, KVM_RUN, 0);
	post_kvm_run(kvm, vcpu);

	if (r == -1 && errno != EINTR && errno != EAGAIN) {
		r = -errno;
		printf("kvm_run: %m\n");
		return r;
	}
	if (r == -1) {
		r = handle_io_window(kvm);
		goto more;
	}
	if (1) {
		switch (run->exit_reason) {
		case KVM_EXIT_UNKNOWN:
			fprintf(stderr, "unhandled vm exit: 0x%x vcpu_id %d\n",
				(unsigned)run->hw.hardware_exit_reason, vcpu);
			kvm_show_regs(kvm, vcpu);
			abort();
			break;
		case KVM_EXIT_FAIL_ENTRY:
			fprintf(stderr, "kvm_run: failed entry, reason %u\n", 
				(unsigned)run->fail_entry.hardware_entry_failure_reason & 0xffff);
			return -ENOEXEC;
			break;
		case KVM_EXIT_EXCEPTION:
			fprintf(stderr, "exception %d (%x)\n", 
			       run->ex.exception,
			       run->ex.error_code);
			kvm_show_regs(kvm, vcpu);
			kvm_show_code(kvm, vcpu);
			abort();
			break;
		case KVM_EXIT_IO:
			r = handle_io(kvm, run, vcpu);
			break;
		case KVM_EXIT_DEBUG:
			r = handle_debug(kvm, vcpu);
			break;
		case KVM_EXIT_MMIO:
			r = handle_mmio(kvm, run);
			break;
		case KVM_EXIT_HLT:
			r = handle_halt(kvm, vcpu);
			break;
		case KVM_EXIT_IRQ_WINDOW_OPEN:
			break;
		case KVM_EXIT_SHUTDOWN:
			r = handle_shutdown(kvm, vcpu);
			break;
#ifdef KVM_EXIT_SET_TPR
		case KVM_EXIT_SET_TPR:
			break;
#endif
		default:
			fprintf(stderr, "unhandled vm exit: 0x%x\n", run->exit_reason);
			kvm_show_regs(kvm, vcpu);
			abort();
			break;
		}
	}
more:
	if (!r)
		goto again;
	return r;
}

int kvm_inject_irq(kvm_context_t kvm, int vcpu, unsigned irq)
{
	struct kvm_interrupt intr;

	intr.irq = irq;
	return ioctl(kvm->vcpu_fd[vcpu], KVM_INTERRUPT, &intr);
}

int kvm_guest_debug(kvm_context_t kvm, int vcpu, struct kvm_debug_guest *dbg)
{
	return ioctl(kvm->vcpu_fd[vcpu], KVM_DEBUG_GUEST, dbg);
}

int kvm_set_signal_mask(kvm_context_t kvm, int vcpu, const sigset_t *sigset)
{
	struct kvm_signal_mask *sigmask;
	int r;

	if (!sigset) {
		r = ioctl(kvm->vcpu_fd[vcpu], KVM_SET_SIGNAL_MASK, NULL);
		if (r == -1)
			r = -errno;
		return r;
	}
	sigmask = malloc(sizeof(*sigmask) + sizeof(*sigset));
	if (!sigmask)
		return -ENOMEM;

	sigmask->len = 8;
	memcpy(sigmask->sigset, sigset, sizeof(*sigset));
	r = ioctl(kvm->vcpu_fd[vcpu], KVM_SET_SIGNAL_MASK, sigmask);
	if (r == -1)
		r = -errno;
	free(sigmask);
	return r;
}

int kvm_irqchip_in_kernel(kvm_context_t kvm)
{
    return kvm->irqchip_in_kernel;
}
