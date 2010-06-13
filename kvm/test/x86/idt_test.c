#include "libcflat.h"
#include "idt.h"

int test_ud2(void)
{
    asm volatile(ASM_TRY("1f")
                 "ud2 \n\t"
                 "1:" :);
    return exception_vector();
}

int test_gp(void)
{
    unsigned long tmp;

    asm volatile("mov $0xffffffff, %0 \n\t"
                 ASM_TRY("1f")
		 "mov %0, %%cr4\n\t"
                 "1:"
                 : "=a"(tmp));
    return exception_vector();
}

static int nr_fail, nr_test;

static void report(int cond, const char *name)
{
    ++nr_test;
    if (!cond) {
        ++nr_fail;
        printf("%s: FAIL\n", name);
    } else {
        printf("%s: PASS\n", name);
    }
}

int main(void)
{
    int r;

    printf("Starting IDT test\n");
    setup_idt();
    r = test_gp();
    report(r == GP_VECTOR, "Testing #GP");
    r = test_ud2();
    report(r == UD_VECTOR, "Testing #UD");
    printf("%d failures of %d tests\n", nr_fail, nr_test);
    return !nr_fail ? 0 : 1;
}
