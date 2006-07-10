#include "hvmctl.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

static void test_cpuid(void *opaque, uint64_t *rax, uint64_t *rbx, 
		       uint64_t *rcx, uint64_t *rdx)
{
    printf("cpuid 0x%lx\n", (uint32_t)*rax);
}

static void test_inb(void *opaque, uint16_t addr, uint8_t *value)
{
    printf("inb 0x%x\n", addr);
}

static void test_inw(void *opaque, uint16_t addr, uint16_t *value)
{
    printf("inw 0x%x\n", addr);
}

static void test_inl(void *opaque, uint16_t addr, uint32_t *value)
{
    printf("inl 0x%x\n", addr);
}

static void test_outb(void *opaque, uint16_t addr, uint8_t value)
{
    printf("outb $0x%x, 0x%x\n", value, addr);
}

static void test_outw(void *opaque, uint16_t addr, uint16_t value)
{
    printf("outw $0x%x, 0x%x\n", value, addr);
}

static void test_outl(void *opaque, uint16_t addr, uint32_t value)
{
    printf("outl $0x%x, 0x%x\n", value, addr);
}

static struct hvm_callbacks test_callbacks = {
    .cpuid       = test_cpuid,
    .inb         = test_inb,
    .inw         = test_inw,
    .inl         = test_inl,
    .outb        = test_outb,
    .outw        = test_outw,
    .outl        = test_outl,
};

static void load_file(void *mem, const char *fname)
{
    int r;
    int fd;

    fd = open(fname, O_RDONLY);
    if (fd == -1) {
	perror("open");
	exit(1);
    }
    while ((r = read(fd, mem, 4096)) != -1 && r != 0)
	mem += r;
    if (r == -1) {
	perror("read");
	exit(1);
    }
}

int main(int ac, char **av)
{
	hvm_context_t hvm;
	void *vm_mem;

	hvm = hvm_init(&test_callbacks, 0);
	hvm_create(hvm, 128 * 1024 * 1024, &vm_mem);
	if (ac > 1)
	    load_file(vm_mem, av[1]);
	hvm_show_regs(hvm, 0);
	while (1)
		hvm_run(hvm, 0);
}
