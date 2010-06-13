#include "libcflat.h"
#include "idt.h"

#ifdef __x86_64__
#define uint64_t unsigned long
#else
#define uint64_t unsigned long long
#endif

static inline void __cpuid(unsigned int *eax, unsigned int *ebx,
        unsigned int *ecx, unsigned int *edx)
{
    /* ecx is often an input as well as an output. */
    asm volatile("cpuid"
            : "=a" (*eax),
            "=b" (*ebx),
            "=c" (*ecx),
            "=d" (*edx)
            : "0" (*eax), "2" (*ecx));
}

/*
 * Generic CPUID function
 * clear %ecx since some cpus (Cyrix MII) do not set or clear %ecx
 * resulting in stale register contents being returned.
 */
void cpuid(unsigned int op,
        unsigned int *eax, unsigned int *ebx,
        unsigned int *ecx, unsigned int *edx)
{
    *eax = op;
    *ecx = 0;
    __cpuid(eax, ebx, ecx, edx);
}

/* Some CPUID calls want 'count' to be placed in ecx */
void cpuid_count(unsigned int op, int count,
        unsigned int *eax, unsigned int *ebx,
        unsigned int *ecx, unsigned int *edx)
{
    *eax = op;
    *ecx = count;
    __cpuid(eax, ebx, ecx, edx);
}

int xgetbv_checking(u32 index, u64 *result)
{
    u32 eax, edx;

    asm volatile(ASM_TRY("1f")
            ".byte 0x0f,0x01,0xd0\n\t" /* xgetbv */
            "1:"
            : "=a" (eax), "=d" (edx)
            : "c" (index));
    *result = eax + ((u64)edx << 32);
    return exception_vector();
}

int xsetbv_checking(u32 index, u64 value)
{
    u32 eax = value;
    u32 edx = value >> 32;

    asm volatile(ASM_TRY("1f")
            ".byte 0x0f,0x01,0xd1\n\t" /* xsetbv */
            "1:"
            : : "a" (eax), "d" (edx), "c" (index));
    return exception_vector();
}

unsigned long read_cr4(void)
{
    unsigned long val;
    asm volatile("mov %%cr4,%0" : "=r" (val));
    return val;
}

int write_cr4_checking(unsigned long val)
{
    asm volatile(ASM_TRY("1f")
            "mov %0,%%cr4\n\t"
            "1:": : "r" (val));
    return exception_vector();
}

#define CPUID_1_ECX_XSAVE	    (1 << 26)
#define CPUID_1_ECX_OSXSAVE	    (1 << 27)
int check_cpuid_1_ecx(unsigned int bit)
{
    unsigned int eax, ebx, ecx, edx;
    cpuid(1, &eax, &ebx, &ecx, &edx);
    if (ecx & bit)
        return 1;
    return 0;
}

uint64_t get_supported_xcr0(void)
{
    unsigned int eax, ebx, ecx, edx;
    cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx);
    printf("eax %x, ebx %x, ecx %x, edx %x\n",
            eax, ebx, ecx, edx);
    return eax + ((u64)edx << 32);
}

#define X86_CR4_OSXSAVE			0x00040000
#define XCR_XFEATURE_ENABLED_MASK       0x00000000
#define XCR_XFEATURE_ILLEGAL_MASK       0x00000010

#define XSTATE_FP       0x1
#define XSTATE_SSE      0x2
#define XSTATE_YMM      0x4

static int total_tests, fail_tests;

void pass_if(int condition)
{
    total_tests ++;
    if (condition)
        printf("Pass!\n");
    else {
        printf("Fail!\n");
        fail_tests ++;
    }
}

void test_xsave(void)
{
    unsigned long cr4;
    uint64_t supported_xcr0;
    uint64_t test_bits;
    u64 xcr0;
    int r;

    printf("Legal instruction testing:\n");
    supported_xcr0 = get_supported_xcr0();
    printf("Supported XCR0 bits: 0x%x\n", supported_xcr0);

    printf("Check minimal XSAVE required bits: ");
    test_bits = XSTATE_FP | XSTATE_SSE;
    pass_if((supported_xcr0 & test_bits) == test_bits);

    printf("Set CR4 OSXSAVE: ");
    cr4 = read_cr4();
    r = write_cr4_checking(cr4 | X86_CR4_OSXSAVE);
    pass_if(r == 0);

    printf("Check CPUID.1.ECX.OSXSAVE - expect 1: ");
    pass_if(check_cpuid_1_ecx(CPUID_1_ECX_OSXSAVE));

    printf("    Legal tests\n");
    printf("        xsetbv(XCR_XFEATURE_ENABLED_MASK, XSTATE_FP): ");
    test_bits = XSTATE_FP;
    r = xsetbv_checking(XCR_XFEATURE_ENABLED_MASK, test_bits);
    pass_if(r == 0);
    printf("        xsetbv(XCR_XFEATURE_ENABLED_MASK, "
            "XSTATE_FP | XSTATE_SSE): ");
    test_bits = XSTATE_FP | XSTATE_SSE;
    r = xsetbv_checking(XCR_XFEATURE_ENABLED_MASK, test_bits);
    pass_if(r == 0);
    printf("        xgetbv(XCR_XFEATURE_ENABLED_MASK): ");
    r = xgetbv_checking(XCR_XFEATURE_ENABLED_MASK, &xcr0);
    pass_if(r == 0);
    printf("    Illegal tests\n");
    printf("        xsetbv(XCR_XFEATURE_ENABLED_MASK, 0) - expect #GP: ");
    test_bits = 0;
    r = xsetbv_checking(XCR_XFEATURE_ENABLED_MASK, test_bits);
    pass_if(r == GP_VECTOR);
    printf("        xsetbv(XCR_XFEATURE_ENABLED_MASK, XSTATE_SSE) "
            "- expect #GP: ");
    test_bits = XSTATE_SSE;
    r = xsetbv_checking(XCR_XFEATURE_ENABLED_MASK, test_bits);
    pass_if(r == GP_VECTOR);
    if (supported_xcr0 & XSTATE_YMM) {
        printf("        xsetbv(XCR_XFEATURE_ENABLED_MASK, "
                "XSTATE_YMM) - expect #GP: ");
        test_bits = XSTATE_YMM;
        r = xsetbv_checking(XCR_XFEATURE_ENABLED_MASK, test_bits);
        pass_if(r == GP_VECTOR);
        printf("        xsetbv(XCR_XFEATURE_ENABLED_MASK, "
                "XSTATE_FP | XSTATE_YMM) - expect #GP: ");
        test_bits = XSTATE_FP | XSTATE_YMM;
        r = xsetbv_checking(XCR_XFEATURE_ENABLED_MASK, test_bits);
        pass_if(r == GP_VECTOR);
    }
    printf("        xsetbv(XCR_XFEATURE_ILLEGAL_MASK, XSTATE_FP) "
            "- expect #GP: ");
    test_bits = XSTATE_SSE;
    r = xsetbv_checking(XCR_XFEATURE_ILLEGAL_MASK, test_bits);
    pass_if(r == GP_VECTOR);
    printf("        xgetbv(XCR_XFEATURE_ILLEGAL_MASK, XSTATE_FP) "
            "- expect #GP: ");
    test_bits = XSTATE_SSE;
    r = xsetbv_checking(XCR_XFEATURE_ILLEGAL_MASK, test_bits);
    pass_if(r == GP_VECTOR);

    printf("Unset CR4 OSXSAVE: ");
    cr4 &= ~X86_CR4_OSXSAVE;
    r = write_cr4_checking(cr4);
    pass_if(r == 0);
    printf("Check CPUID.1.ECX.OSXSAVE - expect 0: ");
    pass_if(check_cpuid_1_ecx(CPUID_1_ECX_OSXSAVE) == 0);
    printf("    Illegal tests:\n");
    printf("        xsetbv(XCR_XFEATURE_ENABLED_MASK, XSTATE_FP) - expect #UD: ");
    test_bits = XSTATE_FP;
    r = xsetbv_checking(XCR_XFEATURE_ENABLED_MASK, test_bits);
    pass_if(r == UD_VECTOR);
    printf("        xsetbv(XCR_XFEATURE_ENABLED_MASK, "
            "XSTATE_FP | XSTATE_SSE) - expect #UD: ");
    test_bits = XSTATE_FP | XSTATE_SSE;
    r = xsetbv_checking(XCR_XFEATURE_ENABLED_MASK, test_bits);
    pass_if(r == UD_VECTOR);
    printf("    Illegal tests:\n");
    printf("	xgetbv(XCR_XFEATURE_ENABLED_MASK) - expect #UD: ");
    r = xgetbv_checking(XCR_XFEATURE_ENABLED_MASK, &xcr0);
    pass_if(r == UD_VECTOR);
}

void test_no_xsave(void)
{
    unsigned long cr4;
    u64 xcr0;
    int r;

    printf("Check CPUID.1.ECX.OSXSAVE - expect 0: ");
    pass_if(check_cpuid_1_ecx(CPUID_1_ECX_OSXSAVE) == 0);

    printf("Illegal instruction testing:\n");

    printf("Set OSXSAVE in CR4 - expect #GP: ");
    cr4 = read_cr4();
    r = write_cr4_checking(cr4 | X86_CR4_OSXSAVE);
    pass_if(r == GP_VECTOR);

    printf("Execute xgetbv - expect #UD: ");
    r = xgetbv_checking(XCR_XFEATURE_ENABLED_MASK, &xcr0);
    pass_if(r == UD_VECTOR);

    printf("Execute xsetbv - expect #UD: ");
    r = xsetbv_checking(XCR_XFEATURE_ENABLED_MASK, 0x3);
    pass_if(r == UD_VECTOR);
}

int main(void)
{
    setup_idt();
    if (check_cpuid_1_ecx(CPUID_1_ECX_XSAVE)) {
        printf("CPU has XSAVE feature\n");
        test_xsave();
    } else {
        printf("CPU don't has XSAVE feature\n");
        test_no_xsave();
    }
    printf("Total test: %d\n", total_tests);
    if (fail_tests == 0)
        printf("ALL PASS!\n");
    else {
        printf("Fail %d tests.\n", fail_tests);
        return 1;
    }
    return 0;
}
