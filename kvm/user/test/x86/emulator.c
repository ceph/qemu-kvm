#include "ioram.h"
#include "vm.h"
#include "printf.h"

#define memset __builtin_memset

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

void test_cmps(void *mem)
{
	unsigned char *m1 = mem, *m2 = mem + 1024;
	unsigned char m3[1024];
	void *rsi, *rdi;
	long rcx, tmp;

	for (int i = 0; i < 100; ++i)
		m1[i] = m2[i] = m3[i] = i;
	for (int i = 100; i < 200; ++i)
		m1[i] = (m3[i] = m2[i] = i) + 1;

	rsi = m1; rdi = m3; rcx = 30;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsb"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsb (1)", rcx == 0 && rsi == m1 + 30 && rdi == m3 + 30);

	rsi = m1; rdi = m3; rcx = 15;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsw"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsw (1)", rcx == 0 && rsi == m1 + 30 && rdi == m3 + 30);

	rsi = m1; rdi = m3; rcx = 7;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsl"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpll (1)", rcx == 0 && rsi == m1 + 28 && rdi == m3 + 28);

	rsi = m1; rdi = m3; rcx = 4;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsq"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsq (1)", rcx == 0 && rsi == m1 + 32 && rdi == m3 + 32);

	rsi = m1; rdi = m3; rcx = 130;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsb"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsb (2)",
	       rcx == 29 && rsi == m1 + 101 && rdi == m3 + 101);

	rsi = m1; rdi = m3; rcx = 65;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsw"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsw (2)",
	       rcx == 14 && rsi == m1 + 102 && rdi == m3 + 102);

	rsi = m1; rdi = m3; rcx = 32;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsl"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpll (2)",
	       rcx == 6 && rsi == m1 + 104 && rdi == m3 + 104);

	rsi = m1; rdi = m3; rcx = 16;
	asm volatile("xor %[tmp], %[tmp] \n\t"
		     "repe/cmpsq"
		     : "+S"(rsi), "+D"(rdi), "+c"(rcx), [tmp]"=&r"(tmp)
		     : : "cc");
	report("repe/cmpsq (2)",
	       rcx == 3 && rsi == m1 + 104 && rdi == m3 + 104);

}

void test_cr8(void)
{
	unsigned long src, dst;

	dst = 777;
	src = 3;
	asm volatile("mov %[src], %%cr8; mov %%cr8, %[dst]"
		     : [dst]"+r"(dst), [src]"+r"(src));
	report("mov %cr8", dst == 3 && src == 3);
}

void test_push(void *mem)
{
	unsigned long tmp;
	unsigned long *stack_top = mem + 4096;
	unsigned long *new_stack_top;
	unsigned long memw = 0x123456789abcdeful;

	memset(mem, 0x55, (void *)stack_top - mem);

	asm volatile("mov %%rsp, %[tmp] \n\t"
		     "mov %[stack_top], %%rsp \n\t"
		     "pushq $-7 \n\t"
		     "pushq %[reg] \n\t"
		     "pushq (%[mem]) \n\t"
		     "mov %%rsp, %[new_stack_top] \n\t"
		     "mov %[tmp], %%rsp"
		     : [tmp]"=&r"(tmp), [new_stack_top]"=r"(new_stack_top)
		     : [stack_top]"r"(stack_top),
		       [reg]"r"(-17l), [mem]"r"(&memw)
		     : "memory");

	report("push $imm8", stack_top[-1] == -7ul);
	report("push %reg", stack_top[-2] == -17ul);
	report("push mem", stack_top[-3] == 0x123456789abcdeful);
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

	test_cmps(mem);

	test_push(mem);

	test_cr8();

	printf("\nSUMMARY: %d tests, %d failures\n", tests, fails);
	return fails ? 1 : 0;
}
