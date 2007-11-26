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

void test_cmps(void *mem)
{
	unsigned char *m1 = mem, *m2 = mem + 1024;
	unsigned char m3[1024];
	void *rsi, *rdi;
	long rcx, tmp;
	int i;

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

	printf("\nSUMMARY: %d tests, %d failures\n", tests, fails);
	return fails ? 1 : 0;
}
