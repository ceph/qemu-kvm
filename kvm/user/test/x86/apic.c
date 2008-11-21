#include "libcflat.h"
#include "apic.h"
#include "vm.h"

static void *g_apic;

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned u32;

static int g_fail;
static int g_tests;

static void report(const char *msg, int pass)
{
    ++g_tests;
    printf("%s: %s\n", msg, (pass ? "PASS" : "FAIL"));
    if (!pass)
        ++g_fail;
}

static u32 apic_read(unsigned reg)
{
    return *(volatile u32 *)(g_apic + reg);
}

static void apic_write(unsigned reg, u32 val)
{
    *(volatile u32 *)(g_apic + reg) = val;
}

static void test_lapic_existence(void)
{
    u32 lvr;

    lvr = apic_read(APIC_LVR);
    printf("apic version: %x\n", lvr);
    report("apic existence", (u16)lvr == 0x14);
}

int main()
{
    setup_vm();

    g_apic = vmap(0xfee00000, 0x1000);

    test_lapic_existence();

    printf("\nsummary: %d tests, %d failures\n", g_tests, g_fail);

    return g_fail != 0;
}
