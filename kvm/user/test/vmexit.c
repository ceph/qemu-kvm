
#include "printf.h"

static inline unsigned long long rdtsc()
{
	long long r;

	asm volatile ("rdtsc" : "=A"(r));
	return r;
}

#define N (1 << 21)

int main()
{
	int i;
	unsigned long long t1, t2;

	t1 = rdtsc();
	for (i = 0; i < N; ++i)
		asm volatile ("cpuid" : : : "eax", "ebx", "ecx", "edx");
	t2 = rdtsc();
	printf("vmexit latency: %d\n", (int)((t2 - t1) / N));
	return 0;
}
