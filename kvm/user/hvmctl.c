#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include "hvmctl.h"

struct hvm_context {
	int fd;
};

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

#if 0

unsigned char testprog[] = {
// <start>:
   0x49, 0xc7, 0xc0, 0x00, 0x10, 0x00, 0x00,   	// mov    $0x1000,%r8
   0xb9, 0x0a, 0x00, 0x00, 0x00,          	//mov    $0x0a,%ecx

//<init_page>:
   0xff, 0xc9,                   		//dec    %ecx
   0x75, 0x09,                   		//jne    19 <no_io>
   0xb0, 0x00,                   		//mov    $0x0,%al
   0xe6, 0x80,                   		//out    %al,$0x80
   0xb9, 0x0a, 0x00, 0x00, 0x00,          	//mov    $0x0a,%ecx

// <no_io>:
   0x4d, 0x89, 0x00,                		//mov    %r8,(%r8)
   0x49, 0x81, 0xc0, 0x00, 0x10, 0x00, 0x00,    //add    $0x1000,%r8
   0x49, 0x81, 0xf8, 0x00, 0x00, 0x00, 0x08,    //cmp    $0x8000000,%r8
   0x75, 0xe0,                   		//jne    c <init_page>
   0x49, 0xc7, 0xc0, 0x00, 0x10, 0x00, 0x00,    //mov    $0x1000,%r8
   0xb9, 0x0a, 0x00, 0x00, 0x00,          	//mov    $0x0a,%ecx

// <test_loop>:
  0xff, 0xc9,                   		//dec    %ecx
  0x75, 0x09,                   		//jne    45 <no_io2>
  0xb0, 0x00,                   		//mov    $0x0,%al
  0xe6, 0x80,                   		//out    %al,$0x80
  0xb9, 0x0a, 0x00, 0x00, 0x00,          	//mov    $0x0a,%ecx

// <no_io2>:
  0x4d, 0x8b, 0x08,                		//mov    (%r8),%r9
  0x4d, 0x39, 0xc1,                		//cmp    %r8,%r9
  0x75, 0x19,                   		//jne    66 <err>
  0x49, 0x81, 0xc0, 0x00, 0x10, 0x00, 0x00,    	//add    $0x1000,%r8
  0x49, 0x81, 0xf8, 0x00, 0x00, 0x00, 0x08,    	//cmp    $0x8000000,%r8
  0x75, 0xdb,                   		//jne    38 <test_loop>
  0x49, 0xc7, 0xc0, 0x00, 0x10, 0x00, 0x00,    	//mov    $0x1000,%r8
  0xeb, 0xd2,                   		//jmp    38 <test_loop>

// <err>:
  0x49, 0xc7, 0xc4, 0xff, 0xff, 0xff, 0xff,    	//mov    $0xffffffffffffffff,%r12
  0x49, 0xc7, 0xc5, 0xff, 0xff, 0xff, 0xff,    	//mov    $0xffffffffffffffff,%r13
  0xb0, 0x00,                   		//mov    $0x0,%al
  0xe6, 0x80,                   		//out    %al,$0x80
  0xeb, 0xec,                   		//jmp    66 <err>
};

#endif

hvm_context_t hvm_init()
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
	memset(*vm_mem, 0, memory);
	memcpy(*vm_mem, testprog, sizeof testprog);
	return 0;
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

int hvm_run(hvm_context_t hvm, int vcpu)
{
	int r;
	int fd = hvm->fd;
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
	hvm_show_regs(hvm, vcpu);
	return 0;
}

int main(int ac, char **av)
{
	hvm_context_t hvm;
	void *vm_mem;

	hvm = hvm_init();
	hvm_create(hvm, 128 * 1024 * 1024, &vm_mem);
	hvm_show_regs(hvm, 0);
	while (1)
		hvm_run(hvm, 0);
}
