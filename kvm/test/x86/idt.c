#include "idt.h"
#include "libcflat.h"

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
    unsigned offset2;
    unsigned reserved;
} idt_entry_t;

static idt_entry_t idt[256];

typedef struct {
    unsigned short limit;
    unsigned long linear_addr;
} __attribute__((packed)) descriptor_table_t;

void lidt(idt_entry_t *idt, int nentries)
{
    descriptor_table_t dt;

    dt.limit = nentries * sizeof(*idt) - 1;
    dt.linear_addr = (unsigned long)idt;
    asm volatile ("lidt %0" : : "m"(dt));
}

unsigned short read_cs()
{
    unsigned short r;

    asm volatile ("mov %%cs, %0" : "=r"(r));
    return r;
}

void memset(void *a, unsigned char v, int n)
{
    unsigned char *x = a;

    while (n--)
	*x++ = v;
}

void set_idt_entry(idt_entry_t *e, void *addr, int dpl)
{
    memset(e, 0, sizeof *e);
    e->offset0 = (unsigned long)addr;
    e->selector = read_cs();
    e->ist = 0;
    e->type = 14;
    e->dpl = dpl;
    e->p = 1;
    e->offset1 = (unsigned long)addr >> 16;
    e->offset2 = (unsigned long)addr >> 32;
}

struct ex_regs {
    unsigned long rax, rcx, rdx, rbx;
    unsigned long dummy, rbp, rsi, rdi;
    unsigned long r8, r9, r10, r11;
    unsigned long r12, r13, r14, r15;
    unsigned long vector;
    unsigned long error_code;
    unsigned long rip;
    unsigned long cs;
    unsigned long rflags;
};

struct ex_record {
    unsigned long rip;
    unsigned long handler;
};

extern struct ex_record exception_table_start, exception_table_end;

void do_handle_exception(struct ex_regs *regs)
{
    struct ex_record *ex;
    unsigned ex_val;

    ex_val = regs->vector | (regs->error_code << 16);

    asm("mov %0, %%gs:4" : : "r"(ex_val));

    for (ex = &exception_table_start; ex != &exception_table_end; ++ex) {
        if (ex->rip == regs->rip) {
            regs->rip = ex->handler;
            return;
        }
    }
    printf("unhandled excecption\n");
    exit(7);
}

asm (".pushsection .text \n\t"
     "ud_fault: \n\t"
     "pushq $0 \n\t"
     "pushq $6 \n\t"
     "jmp handle_exception \n\t"

     "gp_fault: \n\t"
     "pushq $13 \n\t"
     "jmp handle_exception \n\t"

     "handle_exception: \n\t"
     "push %r15; push %r14; push %r13; push %r12 \n\t"
     "push %r11; push %r10; push %r9; push %r8 \n\t"
     "push %rdi; push %rsi; push %rbp; sub $8, %rsp \n\t"
     "push %rbx; push %rdx; push %rcx; push %rax \n\t"
     "mov %rsp, %rdi \n\t"
     "call do_handle_exception \n\t"
     "pop %rax; pop %rcx; pop %rdx; pop %rbx \n\t"
     "add $8, %rsp; pop %rbp; pop %rsi; pop %rdi \n\t"
     "pop %r8; pop %r9; pop %r10; pop %r11 \n\t"
     "pop %r12; pop %r13; pop %r14; pop %r15 \n\t"
     "add $16, %rsp \n\t"
     "iretq \n\t"
     ".popsection");


void setup_idt(void)
{
    extern char ud_fault, gp_fault;

    lidt(idt, 256);
    set_idt_entry(&idt[6], &ud_fault, 0);
    set_idt_entry(&idt[13], &gp_fault, 0);
}

unsigned exception_vector(void)
{
    unsigned short vector;

    asm("mov %%gs:4, %0" : "=rm"(vector));
    return vector;
}

unsigned exception_error_code(void)
{
    unsigned short error_code;

    asm("mov %%gs:6, %0" : "=rm"(error_code));
    return error_code;
}
