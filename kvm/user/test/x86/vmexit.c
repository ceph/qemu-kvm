
#include "libcflat.h"

static inline unsigned long long rdtsc()
{
	long long r;

#ifdef __x86_64__
	unsigned a, d;

	asm volatile ("rdtsc" : "=a"(a), "=d"(d));
	r = a | ((long long)d << 32);
#else
	asm volatile ("rdtsc" : "=A"(r));
#endif
	return r;
}

#define N (1 << 22)

#ifdef __x86_64__
#  define R "r"
#else
#  define R "e"
#endif

static void cpuid(void)
{
	asm volatile ("push %%"R "bx; cpuid; pop %%"R "bx"
		      : : : "eax", "ecx", "edx");
}

static struct test {
	void (*func)(void);
	const char *name;
} tests[] = {
	{ cpuid, "cpuid", },
};

static void do_test(struct test *test)
{
	int i;
	unsigned long long t1, t2;
        void (*func)(void) = test->func;

	t1 = rdtsc();
	for (i = 0; i < N; ++i)
            func();
	t2 = rdtsc();
	printf("%s %d\n", test->name, (int)((t2 - t1) / N));
}

#define ARRAY_SIZE(_x) (sizeof(_x) / sizeof((_x)[0]))

int main(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tests); ++i)
		do_test(&tests[i]);

	return 0;
}
