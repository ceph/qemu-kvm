#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include "hvmctl.h"

#define PAGE_SIZE 4096ul

struct hvm_context {
	int fd;
	struct hvm_callbacks *callbacks;
	void *opaque;
	void *physical_memory;
};

struct translation_cache {
	unsigned long linear;
	void *physical;
};

static void translation_cache_init(struct translation_cache *tr)
{
	tr->physical = 0;
}

static int translate(hvm_context_t hvm, int vcpu, struct translation_cache *tr,
		     unsigned long linear, void **physical)
{
	unsigned long page = linear & ~(PAGE_SIZE-1);
	unsigned long offset = linear & (PAGE_SIZE-1);

	if (!(tr->physical && tr->linear == page)) {
		struct hvm_translation hvm_tr;
		int r;

		hvm_tr.linear_address = page;
		hvm_tr.vcpu = vcpu;
		
		r = ioctl(hvm->fd, HVM_TRANSLATE, &hvm_tr);
		if (r == -1)
			return -errno;

		if (!hvm_tr.valid)
			return -EFAULT;

		tr->linear = page;
		tr->physical = hvm->physical_memory + hvm_tr.physical_address;
	}
	*physical = tr->physical + offset;
	return 0;
}

hvm_context_t hvm_init(struct hvm_callbacks *callbacks,
		       void *opaque)
{
	int fd;
	hvm_context_t hvm;

	fd = open("/dev/hvm", O_RDWR);
	if (fd == -1) {
		printf("open: %m\n");
		exit(1);
	}
	hvm = malloc(sizeof(*hvm));
	hvm->fd = fd;
	hvm->callbacks = callbacks;
	hvm->opaque = opaque;
	return hvm;
}

int hvm_create(hvm_context_t hvm, unsigned long memory, void **vm_mem)
{
	int fd = hvm->fd;
	int r;
	struct hvm_create create = {
		.memory_size = memory,
	};

	r = ioctl(fd, HVM_CREATE, &create);
	if (r == -1) {
		printf("hvm_create: %m\n");
		exit(1);
	}
	*vm_mem = mmap(0, memory, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (*vm_mem == MAP_FAILED) {
		printf("mmap: %m\n");
		exit(1);
	}
	hvm->physical_memory = *vm_mem;
	memset(*vm_mem, 0, memory);
	return 0;
}

static int more_io(struct hvm_run *run, int first_time)
{
	if (!run->io.rep)
		return first_time;
	else
		return run->io.count != 0;
}

void handle_io(hvm_context_t hvm, struct hvm_run *run)
{
	uint16_t addr = run->io.port;
	struct hvm_regs regs;
	int first_time = 1;
	int delta;
	struct translation_cache tr;

	translation_cache_init(&tr);

	regs.vcpu = run->vcpu;
	ioctl(hvm->fd, HVM_GET_REGS, &regs);

	delta = run->io.string_down ? -run->io.size : run->io.size;

	while (more_io(run, first_time)) {
		void *value_addr;
		int r;

		if (!run->io.string)
			value_addr = &regs.rax;
		else {
			r = translate(hvm, run->vcpu, &tr, run->io.address, 
				      &value_addr);
			if (r) {
				printf("failed translating I/O address %x\n",
				       run->io.address);
				exit(1);
			}
		}

		switch (run->io.direction) {
		case HVM_EXIT_IO_IN: {
			switch (run->io.size) {
			case 1: {
				uint8_t value;
				hvm->callbacks->inb(hvm->opaque, addr, &value);
				*(uint8_t *)value_addr = value;
				break;
			}
			case 2: {
				uint16_t value;
				hvm->callbacks->inw(hvm->opaque, addr, &value);
				*(uint16_t *)value_addr = value;
				break;
			}
			case 4: {
				uint32_t value;
				hvm->callbacks->inl(hvm->opaque, addr, &value);
				*(uint32_t *)value_addr = value;
				break;
			}
			default:
				printf("bad I/O size\n");
				exit(1);
			}
			break;
		}
		case HVM_EXIT_IO_OUT:
			switch (run->io.size) {
			case 1:
				hvm->callbacks->outb(hvm->opaque, addr,
						     *(uint8_t *)value_addr);
				break;
			case 2:
				hvm->callbacks->outw(hvm->opaque, addr,
						     *(uint16_t *)value_addr);
				break;
			case 4:
				hvm->callbacks->outl(hvm->opaque, addr,
						     *(uint32_t *)value_addr);
				break;
			default:
				printf("bad I/O size\n");
				exit(1);
			}
			break;
		default:
			printf("bad I/O size\n");
			exit(1);
		}
		if (run->io.string) {
			run->io.address += delta;
			switch (run->io.direction) {
			case HVM_EXIT_IO_IN:  regs.rdi += delta; break;
			case HVM_EXIT_IO_OUT: regs.rsi += delta; break;
			}
			if (run->io.rep) {
				--regs.rcx;
				--run->io.count;
			}
		}
		first_time = 0;
	}

	ioctl(hvm->fd, HVM_SET_REGS, &regs);
	run->emulated = 1;
}

void handle_debug(hvm_context_t hvm, struct hvm_run *run)
{
	hvm->callbacks->debug(hvm->opaque, run->vcpu);
}

int hvm_get_regs(hvm_context_t hvm, int vcpu, struct hvm_regs *regs)
{
    regs->vcpu = vcpu;
    return ioctl(hvm->fd, HVM_GET_REGS, regs);
}

int hvm_set_regs(hvm_context_t hvm, int vcpu, struct hvm_regs *regs)
{
    regs->vcpu = vcpu;
    return ioctl(hvm->fd, HVM_SET_REGS, regs);
}

int hvm_get_sregs(hvm_context_t hvm, int vcpu, struct hvm_sregs *sregs)
{
    sregs->vcpu = vcpu;
    return ioctl(hvm->fd, HVM_GET_SREGS, sregs);
}

int hvm_set_sregs(hvm_context_t hvm, int vcpu, struct hvm_sregs *sregs)
{
    sregs->vcpu = vcpu;
    return ioctl(hvm->fd, HVM_SET_SREGS, sregs);
}

void hvm_show_regs(hvm_context_t hvm, int vcpu)
{
	int fd = hvm->fd;
	struct hvm_regs regs;
	int r;

	regs.vcpu = vcpu;
	r = ioctl(fd, HVM_GET_REGS, &regs);
	if (r == -1) {
		perror("HVM_GET_REGS");
		exit(1);
	}
	printf("rax %016llx rbx %016llx rcx %016llx rdx %016llx\n"
	       "rsi %016llx rdi %016llx rsp %016llx rbp %016llx\n"
	       "r8  %016llx r9  %016llx r10 %016llx r11 %016llx\n"
	       "r12 %016llx r13 %016llx r14 %016llx r15 %016llx\n"
	       "rip %016llx rflags %08llx\n",
	       regs.rax, regs.rbx, regs.rcx, regs.rdx,
	       regs.rsi, regs.rdi, regs.rsp, regs.rbp,
	       regs.r8,  regs.r9,  regs.r10, regs.r11,
	       regs.r12, regs.r13, regs.r14, regs.r15,
	       regs.rip, regs.rflags);
}

static void handle_cpuid(hvm_context_t hvm, struct hvm_run *run)
{
	struct hvm_regs regs;
	uint32_t orig_eax;

	hvm_get_regs(hvm, run->vcpu, &regs);
	orig_eax = regs.rax;
	hvm->callbacks->cpuid(hvm->opaque, 
			      &regs.rax, &regs.rbx, &regs.rcx, &regs.rdx);
	if (orig_eax == 1)
		regs.rdx &= ~(1ull << 12); /* disable mtrr support */
	hvm_set_regs(hvm, run->vcpu, &regs);
	run->emulated = 1;
}

static void handle_emulate_one_instruction(hvm_context_t hvm, 
					   struct hvm_run *hvm_run)
{
	hvm->callbacks->emulate_one_instruction(hvm->opaque);
}

static void handle_mmio(hvm_context_t hvm, struct hvm_run *hvm_run)
{
	unsigned long addr = hvm_run->mmio.phys_addr;
	void *data = hvm_run->mmio.data;

	if (hvm_run->mmio.is_write) {
		switch (hvm_run->mmio.len) {
		case 1:
			hvm->callbacks->writeb(hvm->opaque, addr, *(uint8_t *)data);
			break;
		case 2:
			hvm->callbacks->writew(hvm->opaque, addr, *(uint16_t *)data);
			break;
		case 4:
			hvm->callbacks->writel(hvm->opaque, addr, *(uint32_t *)data);
			break;
		case 8:
			hvm->callbacks->writeq(hvm->opaque, addr, *(uint64_t *)data);
			break;
		}
	} else {
		switch (hvm_run->mmio.len) {
		case 1:
			hvm->callbacks->readb(hvm->opaque, addr, (uint8_t *)data);
			break;
		case 2:
			hvm->callbacks->readw(hvm->opaque, addr, (uint16_t *)data);
			break;
		case 4:
			hvm->callbacks->readl(hvm->opaque, addr, (uint32_t *)data);
			break;
		case 8:
			hvm->callbacks->readq(hvm->opaque, addr, (uint64_t *)data);
			break;
		}
		hvm_run->mmio_completed = 1;
	}
}

static void handle_io_window(hvm_context_t hvm, struct hvm_run *hvm_run)
{
	hvm->callbacks->io_window(hvm->opaque);
}

static void handle_halt(hvm_context_t hvm, struct hvm_run *hvm_run)
{
	hvm->callbacks->halt(hvm->opaque, hvm_run->vcpu);
}

int hvm_run(hvm_context_t hvm, int vcpu)
{
	int r;
	int fd = hvm->fd;
	struct hvm_run hvm_run = {
		.vcpu = vcpu,
		.emulated = 0,
		.mmio_completed = 0,
	};

again:
	r = ioctl(fd, HVM_RUN, &hvm_run);
	hvm_run.emulated = 0;
	hvm_run.mmio_completed = 0;
	if (r == -1 && errno != EINTR) {
		printf("hvm_run: %m\n");
		exit(1);
	}
	if (r == -1) {
		handle_io_window(hvm, &hvm_run);
		goto again;
	}
	switch (hvm_run.exit_type) {
	case HVM_EXIT_TYPE_FAIL_ENTRY:
		printf("hvm_run: failed entry, reason %u\n", 
		       hvm_run.exit_reason & 0xffff);
		break;
	case HVM_EXIT_TYPE_VM_EXIT:
		switch (hvm_run.exit_reason) {
		case HVM_EXIT_UNKNOWN:
			printf("unhandled vm exit: %d\n", 
			       hvm_run.hw.hardware_exit_reason);
			abort();
			break;
		case HVM_EXIT_EXCEPTION:
			printf("exception %d (%x)\n", 
			       hvm_run.ex.exception,
			       hvm_run.ex.error_code);
			break;
		case HVM_EXIT_IO:
			handle_io(hvm, &hvm_run);
			goto again;
		case HVM_EXIT_CPUID:
			handle_cpuid(hvm, &hvm_run);
			goto again;
		case HVM_EXIT_DEBUG:
			handle_debug(hvm, &hvm_run);
			goto again;
		case HVM_EXIT_EMULATE_ONE_INSTRUCTION:
			handle_emulate_one_instruction(hvm, &hvm_run);
			goto again;
		case HVM_EXIT_MMIO:
			handle_mmio(hvm, &hvm_run);
			goto again;
		case HVM_EXIT_HLT:
			handle_halt(hvm, &hvm_run);
			goto again;
		case HVM_EXIT_REAL_MODE:
			handle_emulate_one_instruction(hvm, &hvm_run);
			goto again;
		default:
			printf("unhandled vm exit: %d\n", hvm_run.exit_reason);
			break;
		}
	}
	hvm_show_regs(hvm, vcpu);
	return 0;
}

int hvm_inject_irq(hvm_context_t hvm, int vcpu, unsigned irq)
{
	struct hvm_interrupt intr;

	intr.vcpu = vcpu;
	intr.irq = irq;
	return ioctl(hvm->fd, HVM_INTERRUPT, &intr);
}

int hvm_guest_debug(hvm_context_t hvm, int vcpu, struct hvm_debug_guest *dbg)
{
	dbg->vcpu = vcpu;

	return ioctl(hvm->fd, HVM_DEBUG_GUEST, dbg);
}
