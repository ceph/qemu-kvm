#include "libcflat.h"
#include "apic.h"
#include "vm.h"

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
    ulong regs[sizeof(ulong)*2];
    ulong func;
    ulong rip;
    ulong cs;
    ulong rflags;
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
    "push %"R "di \n\t"
    "push %"R "si \n\t"
    "push %"R "bp \n\t"
    "push %"R "sp \n\t"
    "push %"R "bx \n\t"
    "push %"R "dx \n\t"
    "push %"R "cx \n\t"
    "push %"R "ax \n\t"
#ifdef __x86_64__
    "mov %rsp, %rdi \n\t"
    "callq *8*16(%rsp) \n\t"
#else
    "push %esp \n\t"
    "calll *4+4*8(%esp) \n\t"
    "add $4, %esp \n\t"
#endif
    "pop %"R "ax \n\t"
    "pop %"R "cx \n\t"
    "pop %"R "dx \n\t"
    "pop %"R "bx \n\t"
    "pop %"R "bp \n\t"
    "pop %"R "bp \n\t"
    "pop %"R "si \n\t"
    "pop %"R "di \n\t"
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

static void outb(unsigned char data, unsigned short port)
{
    asm volatile ("out %0, %1" : : "a"(data), "d"(port));
}

static void report(const char *msg, int pass)
{
    ++g_tests;
    printf("%s: %s\n", msg, (pass ? "PASS" : "FAIL"));
    if (!pass)
        ++g_fail;
}

static void test_lapic_existence(void)
{
    u32 lvr;

    lvr = apic_read(APIC_LVR);
    printf("apic version: %x\n", lvr);
    report("apic existence", (u16)lvr == 0x14);
}

#define MSR_APIC_BASE 0x0000001b

void test_enable_x2apic(void)
{
    if (enable_x2apic()) {
        printf("x2apic enabled\n");
    } else {
        printf("x2apic not detected\n");
    }
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

static void irq_disable(void)
{
    asm volatile("cli");
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
    apic_icr_write(APIC_DEST_SELF | APIC_DEST_PHYSICAL | APIC_DM_FIXED | vec,
                   0);
    asm volatile ("nop");
    report("self ipi", ipi_count == 1);
}

static void set_ioapic_redir(unsigned line, unsigned vec)
{
    ioapic_redir_entry_t e = {
        .vector = vec,
        .delivery_mode = 0,
        .trig_mode = 0,
    };

    ioapic_write_redir(line, e);
}

static void set_irq_line(unsigned line, int val)
{
    asm volatile("out %0, %1" : : "a"((u8)val), "d"((u16)(0x2000 + line)));
}

static void toggle_irq_line(unsigned line)
{
    set_irq_line(line, 1);
    set_irq_line(line, 0);
}

static int g_isr_77;

static void ioapic_isr_77(isr_regs_t *regs)
{
    ++g_isr_77;
    eoi();
}

static void test_ioapic_intr(void)
{
    set_idt_entry(0x77, ioapic_isr_77);
    set_ioapic_redir(0x10, 0x77);
    toggle_irq_line(0x10);
    asm volatile ("nop");
    report("ioapic interrupt", g_isr_77 == 1);
}

static int g_78, g_66, g_66_after_78;
static ulong g_66_rip, g_78_rip;

static void ioapic_isr_78(isr_regs_t *regs)
{
    ++g_78;
    g_78_rip = regs->rip;
    eoi();
}

static void ioapic_isr_66(isr_regs_t *regs)
{
    ++g_66;
    if (g_78)
        ++g_66_after_78;
    g_66_rip = regs->rip;
    eoi();
}

static void test_ioapic_simultaneous(void)
{
    set_idt_entry(0x78, ioapic_isr_78);
    set_idt_entry(0x66, ioapic_isr_66);
    set_ioapic_redir(0x10, 0x78);
    set_ioapic_redir(0x11, 0x66);
    irq_disable();
    toggle_irq_line(0x11);
    toggle_irq_line(0x10);
    irq_enable();
    asm volatile ("nop");
    report("ioapic simultaneous interrupt",
           g_66 && g_78 && g_66_after_78 && g_66_rip == g_78_rip);
}

int main()
{
    setup_vm();

    test_lapic_existence();

    mask_pic_interrupts();
    enable_apic();
    test_enable_x2apic();
    init_idt();

    test_self_ipi();

    test_ioapic_intr();
    test_ioapic_simultaneous();

    printf("\nsummary: %d tests, %d failures\n", g_tests, g_fail);

    return g_fail != 0;
}
