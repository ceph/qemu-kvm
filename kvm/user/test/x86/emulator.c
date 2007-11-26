#include "ioram.h"
#include "vm.h"
#include "printf.h"

int fails, tests;

void report(const char *name, int result)
{
	++tests;
	if (result)
		printf("PASS: %s\n", name);
	else {
		printf("FAIL: %s\n", name);
		++fails;
	}
}

int main()
{
	void *mem;
	unsigned long t1, t2;

	setup_vm();
	mem = vmap(IORAM_BASE_PHYS, IORAM_LEN);

	// test mov reg, r/m and mov r/m, reg
	t1 = 0x123456789abcdef;
	asm volatile("mov %[t1], (%[mem]) \n\t"
		     "mov (%[mem]), %[t2]"
		     : [t2]"=r"(t2)
		     : [t1]"r"(t1), [mem]"r"(mem)
		     : "memory");
	report("mov reg, r/m (1)", t2 == 0x123456789abcdef);

	printf("\nSUMMARY: %d tests, %d failures\n", tests, fails);
	return fails ? 1 : 0;
}
