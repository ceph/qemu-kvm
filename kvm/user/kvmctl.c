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

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "kvmctl.h"

#define EXPECTED_KVM_API_VERSION 10

#if EXPECTED_KVM_API_VERSION != KVM_API_VERSION
#error libkvm: userspace and kernel version mismatch
#endif

#define PAGE_SIZE 4096ul

/* FIXME: share this number with kvm */
/* FIXME: or dynamically alloc/realloc regions */
#define KVM_MAX_NUM_MEM_REGIONS 4u

/**
 * \brief The KVM context
 *
 * The verbose KVM context
 */
struct kvm_context {
	/// Filedescriptor to /dev/kvm
	int fd;
	int vm_fd;
	int vcpu_fd[1];
	struct kvm_run *run[1];
	/// Callbacks that KVM uses to emulate various unvirtualizable functionality
	struct kvm_callbacks *callbacks;
	void *opaque;
	/// A pointer to the memory used as the physical memory for the guest
	void *physical_memory;
	/// is dirty pages logging enabled for all regions or not
	int dirty_pages_log_all;
	/// memory regions parameters
	struct kvm_memory_region mem_regions[KVM_MAX_NUM_MEM_REGIONS];
};

struct translation_cache {
	unsigned long linear;
	void *physical;
};

static void translation_cache_init(struct translation_cache *tr)
{
	tr->physical = 0;
}

static int translate(kvm_context_t kvm, int vcpu, struct translation_cache *tr,
		     unsigned long linear, void **physical)
{
	unsigned long page = linear & ~(PAGE_SIZE-1);
	unsigned long offset = linear & (PAGE_SIZE-1);

	if (!(tr->physical && tr->linear == page)) {
		struct kvm_translation kvm_tr;
		int r;

		kvm_tr.linear_address = page;
		
		r = ioctl(kvm->vcpu_fd[vcpu], KVM_TRANSLATE, &kvm_tr);
		if (r == -1)
			return -errno;

		if (!kvm_tr.valid)
			return -EFAULT;

		tr->linear = page;
		tr->physical = kvm->physical_memory + kvm_tr.physical_address;
	}
	*physical = tr->physical + offset;
	return 0;
}

/*
 * memory regions parameters
 */
static void kvm_memory_region_save_params(kvm_context_t kvm, 
					 struct kvm_memory_region *mem)
{
	if (!mem || (mem->slot >= KVM_MAX_NUM_MEM_REGIONS)) {
		fprintf(stderr, "BUG: %s: invalid parameters\n", __FUNCTION__);
		return;
	}
	kvm->mem_regions[mem->slot] = *mem;
}

static void kvm_memory_region_clear_params(kvm_context_t kvm, int regnum)
{
	if (regnum >= KVM_MAX_NUM_MEM_REGIONS) {
		fprintf(stderr, "BUG: %s: invalid parameters\n", __FUNCTION__);
		return;
	}
	kvm->mem_regions[regnum].memory_size = 0;
}

/* 
 * dirty pages logging control 
 */
static int kvm_dirty_pages_log_change(kvm_context_t kvm, int regnum, __u32 flag)
{
	int r;
	struct kvm_memory_region *mem;

	if (regnum >= KVM_MAX_NUM_MEM_REGIONS) {
		fprintf(stderr, "BUG: %s: invalid parameters\n", __FUNCTION__);
		return 1;
	}
	mem = &kvm->mem_regions[regnum];
	if (mem->memory_size == 0) /* not used */
		return 0;
	if (mem->flags & KVM_MEM_LOG_DIRTY_PAGES) /* log already enabled */
		return 0;
	mem->flags |= flag;  /* temporary turn on flag */
	r = ioctl(kvm->vm_fd, KVM_SET_MEMORY_REGION, mem);
	mem->flags &= ~flag; /* back to previous value */
	if (r == -1) {
		fprintf(stderr, "%s: %m\n", __FUNCTION__);
	}
	return r;
}

static int kvm_dirty_pages_log_change_all(kvm_context_t kvm, __u32 flag)
{
	int i, r;

	for (i=r=0; i<KVM_MAX_NUM_MEM_REGIONS && r==0; i++) {
		r = kvm_dirty_pages_log_change(kvm, i, flag);
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
	    fprintf(stderr, "kvm kernel version too old\n");
	    goto out_close;
	}
	if (r < EXPECTED_KVM_API_VERSION) {
	    fprintf(stderr, "kvm kernel version too old\n");
	    goto out_close;
	}
	if (r > EXPECTED_KVM_API_VERSION) {
	    fprintf(stderr, "kvm userspace version too old\n");
	    goto out_close;
	}
	kvm = malloc(sizeof(*kvm));
	kvm->fd = fd;
	kvm->vm_fd = -1;
	kvm->callbacks = callbacks;
	kvm->opaque = opaque;
	kvm->dirty_pages_log_all = 0;
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

int kvm_create(kvm_context_t kvm, unsigned long memory, void **vm_mem)
{
	unsigned long dosmem = 0xa0000;
	unsigned long exmem = 0xc0000;
	long mmap_size;
	int fd = kvm->fd;
	int zfd;
	int r;
	struct kvm_memory_region low_memory = {
		.slot = 3,
		.memory_size = memory  < dosmem ? memory : dosmem,
		.guest_phys_addr = 0,
	};
	struct kvm_memory_region extended_memory = {
		.slot = 0,
		.memory_size = memory < exmem ? 0 : memory - exmem,
		.guest_phys_addr = exmem,
	};

	kvm->vcpu_fd[0] = -1;

	fd = ioctl(fd, KVM_CREATE_VM, 0);
	if (fd == -1) {
		fprintf(stderr, "kvm_create_vm: %m\n");
		return -1;
	}
	kvm->vm_fd = fd;

	/* 640K should be enough. */
	r = ioctl(fd, KVM_SET_MEMORY_REGION, &low_memory);
	if (r == -1) {
		fprintf(stderr, "kvm_create_memory_region: %m\n");
		return -1;
	}
	if (extended_memory.memory_size) {
		r = ioctl(fd, KVM_SET_MEMORY_REGION, &extended_memory);
		if (r == -1) {
			fprintf(stderr, "kvm_create_memory_region: %m\n");
			return -1;
		}
	}

	kvm_memory_region_save_params(kvm, &low_memory);
	kvm_memory_region_save_params(kvm, &extended_memory);

	*vm_mem = mmap(0, memory, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (*vm_mem == MAP_FAILED) {
		fprintf(stderr, "mmap: %m\n");
		return -1;
	}
	kvm->physical_memory = *vm_mem;

	zfd = open("/dev/zero", O_RDONLY);
	mmap(*vm_mem + 0xa8000, 0x8000, PROT_READ|PROT_WRITE,
	     MAP_PRIVATE|MAP_FIXED, zfd, 0);
	close(zfd);

	r = ioctl(fd, KVM_CREATE_VCPU, 0);
	if (r == -1) {
		fprintf(stderr, "kvm_create_vcpu: %m\n");
		return -1;
	}
	kvm->vcpu_fd[0] = r;
	mmap_size = ioctl(kvm->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (mmap_size == -1) {
		fprintf(stderr, "get vcpu mmap size: %m\n");
		return -1;
	}
	kvm->run[0] = mmap(0, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED,
			   kvm->vcpu_fd[0], 0);
	if (kvm->run[0] == MAP_FAILED) {
		fprintf(stderr, "mmap vcpu area: %m\n");
		return -1;
	}
	return 0;
}

void *kvm_create_phys_mem(kvm_context_t kvm, unsigned long phys_start, 
			  unsigned long len, int slot, int log, int writable)
{
	void *ptr;
	int r;
	int fd = kvm->vm_fd;
	int prot = PROT_READ;
	struct kvm_memory_region memory = {
		.slot = slot,
		.memory_size = len,
		.guest_phys_addr = phys_start,
		.flags = log ? KVM_MEM_LOG_DIRTY_PAGES : 0,
	};

	r = ioctl(fd, KVM_SET_MEMORY_REGION, &memory);
	if (r == -1)
	    return 0;

	kvm_memory_region_save_params(kvm, &memory);

	if (writable)
		prot |= PROT_WRITE;

	ptr = mmap(0, len, prot, MAP_SHARED, fd, phys_start);
	if (ptr == MAP_FAILED)
		return 0;
	return ptr;
}

void kvm_destroy_phys_mem(kvm_context_t kvm, unsigned long phys_start, 
			  unsigned long len)
{
	//for each memory region in (phys_start, phys_start+len) do
	//    kvm_memory_region_clear_params(kvm, region);
	kvm_memory_region_clear_params(kvm, 0); /* avoid compiler warning */
	printf("kvm_destroy_phys_mem: implement me\n");
	exit(1);
}

int kvm_create_memory_alias(kvm_context_t kvm,
			    int slot,
			    uint64_t phys_start,
			    uint64_t len,
			    uint64_t target_phys)
{
	struct kvm_memory_alias alias = {
		.slot = slot,
		.flags = 0,
		.guest_phys_addr = phys_start,
		.memory_size = len,
		.target_phys_addr = target_phys,
	};
	int fd = kvm->vm_fd;
	int r;

	r = ioctl(fd, KVM_SET_MEMORY_ALIAS, &alias);
	if (r == -1)
	    return -errno;

	return 0;
}

int kvm_destroy_memory_alias(kvm_context_t kvm, int slot)
{
	return kvm_create_memory_alias(kvm, slot, 0, 0, 0);
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

int kvm_get_dirty_pages(kvm_context_t kvm, int slot, void *buf)
{
	return kvm_get_map(kvm, KVM_GET_DIRTY_LOG, slot, buf);
}

int kvm_get_mem_map(kvm_context_t kvm, int slot, void *buf)
{
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

	run->io_completed = 1;
	return 0;
}

int handle_debug(kvm_context_t kvm, struct kvm_run *run, int vcpu)
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

int kvm_get_sregs(kvm_context_t kvm, int vcpu, struct kvm_sregs *sregs)
{
    return ioctl(kvm->vcpu_fd[vcpu], KVM_GET_SREGS, sregs);
}

int kvm_set_sregs(kvm_context_t kvm, int vcpu, struct kvm_sregs *sregs)
{
    return ioctl(kvm->vcpu_fd[vcpu], KVM_SET_SREGS, sregs);
}

/*
 * Returns available msr list.  User must free.
 */
struct kvm_msr_list *kvm_get_msr_list(kvm_context_t kvm)
{
    struct kvm_msr_list sizer, *msrs;
    int r, e;

    sizer.nmsrs = 0;
    r = ioctl(kvm->fd, KVM_GET_MSR_INDEX_LIST, &sizer);
    if (r == -1 && errno != E2BIG)
	return 0;
    msrs = malloc(sizeof *msrs + sizer.nmsrs * sizeof *msrs->indices);
    if (!msrs) {
	errno = ENOMEM;
	return 0;
    }
    msrs->nmsrs = sizer.nmsrs;
    r = ioctl(kvm->fd, KVM_GET_MSR_INDEX_LIST, msrs);
    if (r == -1) {
	e = errno;
	free(msrs);
	errno = e;
	return 0;
    }
    return msrs;
}

int kvm_get_msrs(kvm_context_t kvm, int vcpu, struct kvm_msr_entry *msrs,
		 int n)
{
    struct kvm_msrs *kmsrs = malloc(sizeof *kmsrs + n * sizeof *msrs);
    int r, e;

    if (!kmsrs) {
	errno = ENOMEM;
	return -1;
    }
    kmsrs->nmsrs = n;
    memcpy(kmsrs->entries, msrs, n * sizeof *msrs);
    r = ioctl(kvm->vcpu_fd[vcpu], KVM_GET_MSRS, kmsrs);
    e = errno;
    memcpy(msrs, kmsrs->entries, n * sizeof *msrs);
    free(kmsrs);
    errno = e;
    return r;
}

int kvm_set_msrs(kvm_context_t kvm, int vcpu, struct kvm_msr_entry *msrs,
		 int n)
{
    struct kvm_msrs *kmsrs = malloc(sizeof *kmsrs + n * sizeof *msrs);
    int r, e;

    if (!kmsrs) {
	errno = ENOMEM;
	return -1;
    }
    kmsrs->nmsrs = n;
    memcpy(kmsrs->entries, msrs, n * sizeof *msrs);
    r = ioctl(kvm->vcpu_fd[vcpu], KVM_SET_MSRS, kmsrs);
    e = errno;
    free(kmsrs);
    errno = e;
    return r;
}

static void print_seg(FILE *file, const char *name, struct kvm_segment *seg)
{
    	fprintf(stderr,
		"%s %04x (%08llx/%08x p %d dpl %d db %d s %d type %x l %d"
		" g %d avl %d)\n",
		name, seg->selector, seg->base, seg->limit, seg->present,
		seg->dpl, seg->db, seg->s, seg->type, seg->l, seg->g,
		seg->avl);
}

static void print_dt(FILE *file, const char *name, struct kvm_dtable *dt)
{
    	fprintf(stderr, "%s %llx/%x\n", name, dt->base, dt->limit);
}

void kvm_show_regs(kvm_context_t kvm, int vcpu)
{
	int fd = kvm->vcpu_fd[vcpu];
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	int r;

	r = ioctl(fd, KVM_GET_REGS, &regs);
	if (r == -1) {
		perror("KVM_GET_REGS");
		return;
	}
	fprintf(stderr,
		"rax %016llx rbx %016llx rcx %016llx rdx %016llx\n"
		"rsi %016llx rdi %016llx rsp %016llx rbp %016llx\n"
		"r8  %016llx r9  %016llx r10 %016llx r11 %016llx\n"
		"r12 %016llx r13 %016llx r14 %016llx r15 %016llx\n"
		"rip %016llx rflags %08llx\n",
		regs.rax, regs.rbx, regs.rcx, regs.rdx,
		regs.rsi, regs.rdi, regs.rsp, regs.rbp,
		regs.r8,  regs.r9,  regs.r10, regs.r11,
		regs.r12, regs.r13, regs.r14, regs.r15,
		regs.rip, regs.rflags);
	r = ioctl(fd, KVM_GET_SREGS, &sregs);
	if (r == -1) {
		perror("KVM_GET_SREGS");
		return;
	}
	print_seg(stderr, "cs", &sregs.cs);
	print_seg(stderr, "ds", &sregs.ds);
	print_seg(stderr, "es", &sregs.es);
	print_seg(stderr, "ss", &sregs.ss);
	print_seg(stderr, "fs", &sregs.fs);
	print_seg(stderr, "gs", &sregs.gs);
	print_seg(stderr, "tr", &sregs.tr);
	print_seg(stderr, "ldt", &sregs.ldt);
	print_dt(stderr, "gdt", &sregs.gdt);
	print_dt(stderr, "idt", &sregs.idt);
	fprintf(stderr, "cr0 %llx cr2 %llx cr3 %llx cr4 %llx cr8 %llx"
		" efer %llx\n",
		sregs.cr0, sregs.cr2, sregs.cr3, sregs.cr4, sregs.cr8,
		sregs.efer);
}

static int handle_mmio(kvm_context_t kvm, struct kvm_run *kvm_run)
{
	unsigned long addr = kvm_run->mmio.phys_addr;
	void *data = kvm_run->mmio.data;
	int r = -1;

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
		kvm_run->io_completed = 1;
	}
	return r;
}

static int handle_io_window(kvm_context_t kvm, struct kvm_run *kvm_run)
{
	return kvm->callbacks->io_window(kvm->opaque);
}

static int handle_halt(kvm_context_t kvm, struct kvm_run *kvm_run, int vcpu)
{
	return kvm->callbacks->halt(kvm->opaque, vcpu);
}

static int handle_shutdown(kvm_context_t kvm, struct kvm_run *kvm_run,
			   int vcpu)
{
	return kvm->callbacks->shutdown(kvm->opaque, vcpu);
}

int try_push_interrupts(kvm_context_t kvm)
{
	return kvm->callbacks->try_push_interrupts(kvm->opaque);
}

static void post_kvm_run(kvm_context_t kvm, struct kvm_run *kvm_run)
{
	kvm->callbacks->post_kvm_run(kvm->opaque, kvm_run);
}

static void pre_kvm_run(kvm_context_t kvm, struct kvm_run *kvm_run)
{
	kvm->callbacks->pre_kvm_run(kvm->opaque, kvm_run);
}

int kvm_run(kvm_context_t kvm, int vcpu)
{
	int r;
	int fd = kvm->vcpu_fd[vcpu];
	struct kvm_run *run = kvm->run[vcpu];

again:
	run->request_interrupt_window = try_push_interrupts(kvm);
	pre_kvm_run(kvm, run);
	r = ioctl(fd, KVM_RUN, 0);
	post_kvm_run(kvm, run);

	run->io_completed = 0;
	if (r == -1 && errno != EINTR) {
		r = -errno;
		printf("kvm_run: %m\n");
		return r;
	}
	if (r == -1) {
		r = handle_io_window(kvm, run);
		goto more;
	}
	if (1) {
		switch (run->exit_reason) {
		case KVM_EXIT_UNKNOWN:
			fprintf(stderr, "unhandled vm exit:  0x%x\n", 
				(unsigned)run->hw.hardware_exit_reason);
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
			abort();
			break;
		case KVM_EXIT_IO:
			r = handle_io(kvm, run, vcpu);
			break;
		case KVM_EXIT_DEBUG:
			r = handle_debug(kvm, run, vcpu);
			break;
		case KVM_EXIT_MMIO:
			r = handle_mmio(kvm, run);
			break;
		case KVM_EXIT_HLT:
			r = handle_halt(kvm, run, vcpu);
			break;
		case KVM_EXIT_IRQ_WINDOW_OPEN:
			break;
		case KVM_EXIT_SHUTDOWN:
			r = handle_shutdown(kvm, run, vcpu);
			break;
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

int kvm_setup_cpuid(kvm_context_t kvm, int vcpu, int nent,
		    struct kvm_cpuid_entry *entries)
{
	struct kvm_cpuid *cpuid;
	int r;

	cpuid = malloc(sizeof(*cpuid) + nent * sizeof(*entries));
	if (!cpuid)
		return -ENOMEM;

	cpuid->nent = nent;
	memcpy(cpuid->entries, entries, nent * sizeof(*entries));
	r = ioctl(kvm->vcpu_fd[vcpu], KVM_SET_CPUID, cpuid);

	free(cpuid);
	return r;
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
