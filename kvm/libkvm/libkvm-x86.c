#include "libkvm.h"
#include "kvm-x86.h"
#include "kvm-abi-10.h"
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
	register_slot(low_memory.slot, low_memory.guest_phys_addr,
		      low_memory.memory_size, 0, 0);


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
			      extended_memory.guest_phys_addr,
			      extended_memory.memory_size, 0, 0);
	}

	if (above_4g_memory.memory_size) {
		above_4g_memory.slot = get_free_slot(kvm);
		r = ioctl(kvm->vm_fd, KVM_SET_MEMORY_REGION, &above_4g_memory);
		if (r == -1) {
			fprintf(stderr, "kvm_create_memory_region: %m\n");
			return -1;
		}
 		register_slot(above_4g_memory.slot,
			      above_4g_memory.guest_phys_addr,
			      above_4g_memory.memory_size, 0, 0);
	}

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
	register_slot(low_memory.slot, low_memory.guest_phys_addr,
		      low_memory.memory_size, 1, low_memory.userspace_addr);

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
			      extended_memory.guest_phys_addr,
			      extended_memory.memory_size, 1,
			      extended_memory.userspace_addr);
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
			      above_4g_memory.guest_phys_addr,
			      above_4g_memory.memory_size, 1,
			      above_4g_memory.userspace_addr);
	}

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
	register_slot(memory.slot, memory.guest_phys_addr, memory.memory_size,
		      0, 0);

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

#ifdef KVM_CAP_IRQCHIP

int kvm_get_lapic(kvm_context_t kvm, int vcpu, struct kvm_lapic_state *s)
{
	int r;
	if (!kvm->irqchip_in_kernel)
		return 0;
	r = ioctl(kvm->vcpu_fd[vcpu], KVM_GET_LAPIC, s);
	if (r == -1) {
		r = -errno;
		perror("kvm_get_lapic");
	}
	return r;
}

int kvm_set_lapic(kvm_context_t kvm, int vcpu, struct kvm_lapic_state *s)
{
	int r;
	if (!kvm->irqchip_in_kernel)
		return 0;
	r = ioctl(kvm->vcpu_fd[vcpu], KVM_SET_LAPIC, s);
	if (r == -1) {
		r = -errno;
		perror("kvm_set_lapic");
	}
	return r;
}

#endif

static int handle_io_abi10(kvm_context_t kvm, struct kvm_run_abi10 *run,
			   int vcpu)
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

static int handle_mmio_abi10(kvm_context_t kvm, struct kvm_run_abi10 *kvm_run)
{
	unsigned long addr = kvm_run->mmio.phys_addr;
	void *data = kvm_run->mmio.data;
	int r = -1;

	if (kvm_run->mmio.is_write) {
		switch (kvm_run->mmio.len) {
		case 1:
			r = kvm->callbacks->writeb(kvm->opaque, addr,
							*(uint8_t *)data);
			break;
		case 2:
			r = kvm->callbacks->writew(kvm->opaque, addr,
							*(uint16_t *)data);
			break;
		case 4:
			r = kvm->callbacks->writel(kvm->opaque, addr,
							*(uint32_t *)data);
			break;
		case 8:
			r = kvm->callbacks->writeq(kvm->opaque, addr,
							*(uint64_t *)data);
			break;
		}
	} else {
		switch (kvm_run->mmio.len) {
		case 1:
			r = kvm->callbacks->readb(kvm->opaque, addr,
							(uint8_t *)data);
			break;
		case 2:
			r = kvm->callbacks->readw(kvm->opaque, addr,
							(uint16_t *)data);
			break;
		case 4:
			r = kvm->callbacks->readl(kvm->opaque, addr,
							(uint32_t *)data);
			break;
		case 8:
			r = kvm->callbacks->readq(kvm->opaque, addr,
							(uint64_t *)data);
			break;
		}
		kvm_run->io_completed = 1;
	}
	return r;
}

int kvm_run_abi10(kvm_context_t kvm, int vcpu)
{
	int r;
	int fd = kvm->vcpu_fd[vcpu];
	struct kvm_run_abi10 *run = (struct kvm_run_abi10 *)kvm->run[vcpu];

again:
	run->request_interrupt_window = try_push_interrupts(kvm);
	r = pre_kvm_run(kvm, vcpu);
	if (r)
	    return r;
	r = ioctl(fd, KVM_RUN, 0);
	post_kvm_run(kvm, vcpu);

	run->io_completed = 0;
	if (r == -1 && errno != EINTR) {
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
			r = handle_io_abi10(kvm, run, vcpu);
			break;
		case KVM_EXIT_DEBUG:
			r = handle_debug(kvm, vcpu);
			break;
		case KVM_EXIT_MMIO:
			r = handle_mmio_abi10(kvm, run);
			break;
		case KVM_EXIT_HLT:
			r = handle_halt(kvm, vcpu);
			break;
		case KVM_EXIT_IRQ_WINDOW_OPEN:
			break;
		case KVM_EXIT_SHUTDOWN:
			r = handle_shutdown(kvm, vcpu);
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


void kvm_show_code(kvm_context_t kvm, int vcpu)
{
#define CR0_PE_MASK	(1ULL<<0)
	int fd = kvm->vcpu_fd[vcpu];
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	int r;
	unsigned char code[50];
	int back_offset;
	char code_str[sizeof(code) * 3 + 1];
	unsigned long rip;

	r = ioctl(fd, KVM_GET_SREGS, &sregs);
	if (r == -1) {
		perror("KVM_GET_SREGS");
		return;
	}
	if (sregs.cr0 & CR0_PE_MASK)
		return;

	r = ioctl(fd, KVM_GET_REGS, &regs);
	if (r == -1) {
		perror("KVM_GET_REGS");
		return;
	}
	rip = sregs.cs.base + regs.rip;
	back_offset = regs.rip;
	if (back_offset > 20)
	    back_offset = 20;
	memcpy(code, kvm->physical_memory + rip - back_offset, sizeof code);
	*code_str = 0;
	for (r = 0; r < sizeof code; ++r) {
	    	if (r == back_offset)
			strcat(code_str, " -->");
		sprintf(code_str + strlen(code_str), " %02x", code[r]);
	}
	fprintf(stderr, "code:%s\n", code_str);
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
		return NULL;
	msrs = malloc(sizeof *msrs + sizer.nmsrs * sizeof *msrs->indices);
	if (!msrs) {
		errno = ENOMEM;
		return NULL;
	}
	msrs->nmsrs = sizer.nmsrs;
	r = ioctl(kvm->fd, KVM_GET_MSR_INDEX_LIST, msrs);
	if (r == -1) {
		e = errno;
		free(msrs);
		errno = e;
		return NULL;
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

uint64_t kvm_get_apic_base(kvm_context_t kvm, int vcpu)
{
	struct kvm_run *run = kvm->run[vcpu];

	if (kvm_abi == 10)
		return ((struct kvm_run_abi10 *)run)->apic_base;
	return run->apic_base;
}

void kvm_set_cr8(kvm_context_t kvm, int vcpu, uint64_t cr8)
{
	struct kvm_run *run = kvm->run[vcpu];

	if (kvm_abi == 10) {
		((struct kvm_run_abi10 *)run)->cr8 = cr8;
		return;
	}
	run->cr8 = cr8;
}

__u64 kvm_get_cr8(kvm_context_t kvm, int vcpu)
{
	return kvm->run[vcpu]->cr8;
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

