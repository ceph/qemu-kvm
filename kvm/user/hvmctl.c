#include <linux/hvm.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>

unsigned char testprog[] = {
	0xb0, 0,                    // mov $0, %al
	0xbb, 0x10, 0x27, 0, 0,     // mov $10000, %ebx
/* 1: */
	0x48, 0x89, 0xd9,           // mov %rbx, %rcx
/* 2: */
	0xe2, 0xfe,                 // loop 2b
	0xe6, 0x80,                 // out %al, $0x80
	0xfe, 0xc0,                 // inc %al
	0x48, 0x81, 0xc3, 0x10, 0x27, 0, 0, // add $10000, %rbx
	0xeb, 0xee,                 // jmp 1b
};

void hvm_create(int fd, unsigned long memory, void **vm_mem)
{
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
	memset(*vm_mem, 0, memory);
	memcpy(*vm_mem, testprog, sizeof testprog);
}

void handle_io(int fd, struct hvm_run *run)
{
	struct hvm_regs regs;

	if (!run->io.string)
		printf("%s port %x value %llx\n",
		       (run->io.direction == HVM_EXIT_IO_IN ? "in" : "out"),
		       run->io.port, run->io.value);
	else
		printf("%ss port %x data %llx count %llx dir %s\n",
		       (run->io.direction == HVM_EXIT_IO_IN ? "in" : "out"),
		       run->io.port, run->io.address, run->io.count,
		       (run->io.string_down ? "down" : ""));

	regs.vcpu = run->vcpu;
	ioctl(fd, HVM_GET_REGS, &regs);
	regs.rip += run->instruction_length;
	ioctl(fd, HVM_SET_REGS, &regs);
}

void show_regs(int fd, int vcpu)
{
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

void hvm_run(int fd, int vcpu)
{
	int r;
	struct hvm_run hvm_run = {
		.vcpu = vcpu,
	};

	r = ioctl(fd, HVM_RUN, &hvm_run);
	if (r == -1) {
		printf("hvm_run: %m\n");
		exit(1);
	}
	switch (hvm_run.exit_type) {
	case HVM_EXIT_TYPE_FAIL_ENTRY:
		printf("hvm_run: failed entry, reason %u\n", 
		       hvm_run.exit_reason & 0xffff);
		break;
	case HVM_EXIT_TYPE_VM_EXIT:
		switch (hvm_run.exit_reason) {
		case HVM_EXIT_EXCEPTION:
			printf("exception %d (%x)\n", 
			       hvm_run.ex.exception,
			       hvm_run.ex.error_code);
			break;
		case HVM_EXIT_IO:
			handle_io(fd, &hvm_run);
			break;
		default:
			printf("unhandled vm exit: %d\n", hvm_run.exit_reason);
			break;
		}
		printf("instruction length: %d\n", hvm_run.instruction_length);
	}
	show_regs(fd, vcpu);
}

int main(int ac, char **av)
{
	int fd;
	void *vm_mem;

	fd = open("/dev/hvm", O_RDWR);
	if (fd == -1) {
		printf("open: %m\n");
		exit(1);
	}
	hvm_create(fd, 128 * 1024 * 1024, &vm_mem);
	show_regs(fd, 0);
	hvm_run(fd, 0);
}
