#include "libcflat.h"
#include "apic.h"
#include "vm.h"

static void *g_apic;

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned u32;
typedef unsigned long ulong;

typedef struct {
    unsigned short offset0;
    unsigned short selector;
    unsigned short ist : 3;
    unsigned short : 5;
    unsigned short type : 4;
    unsigned short : 1;
    unsigned short dpl : 2;
    unsigned short p : 1;
    unsigned short offset1;
#ifdef __x86_64__
    unsigned offset2;
    unsigned reserved;
#endif
} idt_entry_t;

typedef struct {
    ulong rflags;
    ulong cs;
    ulong rip;
    ulong func;
    ulong regs[sizeof(ulong)*2];
} isr_regs_t;

#ifdef __x86_64__
#  define R "r"
#else
#  define R "e"
#endif

extern char isr_entry_point[];

asm (
    "isr_entry_point: \n"
#ifdef __x86_64__
    "push %r15 \n\t"
    "push %r14 \n\t"
    "push %r13 \n\t"
    "push %r12 \n\t"
    "push %r11 \n\t"
    "push %r10 \n\t"
    "push %r9  \n\t"
    "push %r8  \n\t"
#endif
    "push %"R"di \n\t"
    "push %"R"si \n\t"
    "push %"R"bp \n\t"
    "push %"R"sp \n\t"
    "push %"R"bx \n\t"
    "push %"R"dx \n\t"
    "push %"R"cx \n\t"
    "push %"R"ax \n\t"
#ifdef __x86_64__
    "mov %rsp, %rdi \n\t"
    "callq *8*16(%rsp) \n\t"
#else
    "push %esp \n\t"
    "calll *4+4*8(%esp) \n\t"
    "add $4, %esp \n\t"
#endif
    "pop %"R"ax \n\t"
    "pop %"R"cx \n\t"
    "pop %"R"dx \n\t"
    "pop %"R"bx \n\t"
    "pop %"R"bp \n\t"
    "pop %"R"bp \n\t"
    "pop %"R"si \n\t"
    "pop %"R"di \n\t"
#ifdef __x86_64__
    "pop %r8  \n\t"
    "pop %r9  \n\t"
    "pop %r10 \n\t"
    "pop %r11 \n\t"
    "pop %r12 \n\t"
    "pop %r13 \n\t"
    "pop %r14 \n\t"
    "pop %r15 \n\t"
#endif
#ifdef __x86_64__
    "add $8, %rsp \n\t"
    "iretq \n\t"
#else
    "add $4, %esp \n\t"
    "iretl \n\t"
#endif
    );

static idt_entry_t idt[256];

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

static u16 read_cs(void)
{
    u16 v;

    asm("mov %%cs, %0" : "=rm"(v));
    return v;
}

static void init_idt(void)
{
    struct {
        u16 limit;
        ulong idt;
    } __attribute__((packed)) idt_ptr = {
        sizeof(idt_entry_t) * 256 - 1,
        (ulong)&idt,
    };

    asm volatile("lidt %0" : : "m"(idt_ptr));
}

static void set_idt_entry(unsigned vec, void (*func)(isr_regs_t *regs))
{
    u8 *thunk = vmalloc(50);
    ulong ptr = (ulong)thunk;
    idt_entry_t ent = {
        .offset0 = ptr,
        .selector = read_cs(),
        .ist = 0,
        .type = 14,
        .dpl = 0,
        .p = 1,
        .offset1 = ptr >> 16,
#ifdef __x86_64__
        .offset2 = ptr >> 32,
#endif
    };
#ifdef __x86_64__
    /* sub $8, %rsp */
    *thunk++ = 0x48; *thunk++ = 0x83; *thunk++ = 0xec; *thunk++ = 0x08;
    /* mov $func_low, %(rsp) */
    *thunk++ = 0xc7; *thunk++ = 0x04; *thunk++ = 0x24;
    *(u32 *)thunk = (ulong)func; thunk += 4;
    /* mov $func_high, %(rsp+4) */
    *thunk++ = 0xc7; *thunk++ = 0x44; *thunk++ = 0x24; *thunk++ = 0x04;
    *(u32 *)thunk = (ulong)func >> 32; thunk += 4;
    /* jmp isr_entry_point */
    *thunk ++ = 0xe9;
    *(u32 *)thunk = (ulong)isr_entry_point - (ulong)(thunk + 4);
#else
    /* push $func */
    *thunk++ = 0x68;
    *(u32 *)thunk = (ulong)func;
    /* jmp isr_entry_point */
    *thunk ++ = 0xe9;
    *(u32 *)thunk = (ulong)isr_entry_point - (ulong)(thunk + 4);
#endif
    idt[vec] = ent;
}

static void irq_enable(void)
{
    asm volatile("sti");
}

static void eoi(void)
{
    apic_write(APIC_EOI, 0);
}

static int ipi_count;

static void self_ipi_isr(isr_regs_t *regs)
{
    ++ipi_count;
    eoi();
}

static void test_self_ipi(void)
{
    int vec = 0xf1;

    set_idt_entry(vec, self_ipi_isr);
    irq_enable();
    apic_write(APIC_ICR,
               APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_FIXED | vec);
    asm volatile ("nop");
    report("self ipi", ipi_count == 1);
}

static void enable_apic(void)
{
    apic_write(0xf0, 0x1ff); /* spurious vector register */
}

int main()
{
    setup_vm();

    g_apic = vmap(0xfee00000, 0x1000);

    test_lapic_existence();

    enable_apic();
    init_idt();

    test_self_ipi();

    printf("\nsummary: %d tests, %d failures\n", g_tests, g_fail);

    return g_fail != 0;
}
