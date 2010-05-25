
#include "libcflat.h"
#include "smp.h"

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

static unsigned int inl(unsigned short port)
{
    unsigned int val;
    asm volatile("inl %w1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

#define GOAL (1ull << 30)

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

static void vmcall(void)
{
	unsigned long a = 0, b, c, d;

	asm volatile ("vmcall" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
}

static void mov_from_cr8(void)
{
	unsigned long cr8;

	asm volatile ("mov %%cr8, %0" : "=r"(cr8));
}

static void mov_to_cr8(void)
{
	unsigned long cr8 = 0;

	asm volatile ("mov %0, %%cr8" : : "r"(cr8));
}

static int is_smp(void)
{
	return cpu_count() > 1;
}

static void nop(void *junk)
{
}

static void ipi(void)
{
	on_cpu(1, nop, 0);
}

static void ipi_halt(void)
{
	unsigned long long t;

	on_cpu(1, nop, 0);
	t = rdtsc() + 2000;
	while (rdtsc() < t)
		;
}

static void inl_pmtimer(void)
{
    inl(0xb008);
}

static struct test {
	void (*func)(void);
	const char *name;
	int (*valid)(void);
	int parallel;
} tests[] = {
	{ cpuid, "cpuid", .parallel = 1,  },
	{ vmcall, "vmcall", .parallel = 1, },
	{ mov_from_cr8, "mov_from_cr8", .parallel = 1, },
	{ mov_to_cr8, "mov_to_cr8" , .parallel = 1, },
	{ inl_pmtimer, "inl_from_pmtimer", .parallel = 1, },
	{ ipi, "ipi", is_smp, .parallel = 0, },
	{ ipi_halt, "ipi+halt", is_smp, .parallel = 0, },
};

unsigned iterations;
volatile int nr_cpus_done;

static void run_test(void *_func)
{
    int i;
    void (*func)(void) = _func;

    for (i = 0; i < iterations; ++i)
        func();

    nr_cpus_done++;
}

static void do_test(struct test *test)
{
	int i;
	unsigned long long t1, t2;
        void (*func)(void) = test->func;

        iterations = 32;

        if (test->valid && !test->valid()) {
		printf("%s (skipped)\n", test->name);
		return;
	}

	do {
		iterations *= 2;
		t1 = rdtsc();

		if (!test->parallel) {
			for (i = 0; i < iterations; ++i)
				func();
		} else {
			nr_cpus_done = 0;
			for (i = cpu_count(); i > 0; i--)
				on_cpu_async(i-1, run_test, func);
			while (nr_cpus_done < cpu_count())
				;
		}
		t2 = rdtsc();
	} while ((t2 - t1) < GOAL);
	printf("%s %d\n", test->name, (int)((t2 - t1) / iterations));
}

#define ARRAY_SIZE(_x) (sizeof(_x) / sizeof((_x)[0]))

int main(void)
{
	int i;

	smp_init();

	for (i = 0; i < ARRAY_SIZE(tests); ++i)
		do_test(&tests[i]);

	return 0;
}
