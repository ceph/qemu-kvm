/*
 * Copyright 2010 Siemens AG
 * Author: Jan Kiszka
 *
 * Released under GPLv2.
 */

#include "libcflat.h"

#define FIRST_SPARE_SEL		0x18

struct exception_frame {
	unsigned long error_code;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
};

struct tss32 {
	unsigned short prev;
	unsigned short res1;
	unsigned long esp0;
	unsigned short ss0;
	unsigned short res2;
	unsigned long esp1;
	unsigned short ss1;
	unsigned short res3;
	unsigned long esp2;
	unsigned short ss2;
	unsigned short res4;
	unsigned long cr3;
	unsigned long eip;
	unsigned long eflags;
	unsigned long eax, ecx, edx, ebx, esp, ebp, esi, edi;
	unsigned short es;
	unsigned short res5;
	unsigned short cs;
	unsigned short res6;
	unsigned short ss;
	unsigned short res7;
	unsigned short ds;
	unsigned short res8;
	unsigned short fs;
	unsigned short res9;
	unsigned short gs;
	unsigned short res10;
	unsigned short ldt;
	unsigned short res11;
	unsigned short t:1;
	unsigned short res12:15;
	unsigned short iomap_base;
};

static char main_stack[4096];
static char fault_stack[4096];
static struct tss32 main_tss;
static struct tss32 fault_tss;

static unsigned long long gdt[] __attribute__((aligned(16))) = {
	0,
	0x00cf9b000000ffffull,
	0x00cf93000000ffffull,
	0, 0,	/* TSS segments */
	0,	/* task return gate */
};

static unsigned long long gdtr;

void fault_entry(void);

static __attribute__((used, regparm(1))) void
fault_handler(unsigned long error_code)
{
	unsigned short *desc;

	printf("fault at %x:%x, prev task %x, error code %x\n",
	       main_tss.cs, main_tss.eip, fault_tss.prev, error_code);

	main_tss.eip += 2;

	desc = (unsigned short *)&gdt[3];
	desc[2] &= ~0x0200;

	desc = (unsigned short *)&gdt[5];
	desc[0] = 0;
	desc[1] = fault_tss.prev;
	desc[2] = 0x8500;
	desc[3] = 0;
}

asm (
	"fault_entry:\n"
	"	mov (%esp),%eax\n"
	"	call fault_handler\n"
	"	jmp $0x28, $0\n"
);

static void setup_tss(struct tss32 *tss, void *entry,
		      void *stack_base, unsigned long stack_size)
{
	unsigned long cr3;
	unsigned short cs, ds;

	asm ("mov %%cr3,%0" : "=r" (cr3));
	asm ("mov %%cs,%0" : "=r" (cs));
	asm ("mov %%ds,%0" : "=r" (ds));

	tss->ss0 = tss->ss1 = tss->ss2 = tss->ss = ds;
	tss->esp0 = tss->esp1 = tss->esp2 = tss->esp =
		(unsigned long)stack_base + stack_size;
	tss->ds = tss->es = tss->fs = tss->gs = ds;
	tss->cs = cs;
	tss->eip = (unsigned long)entry;
	tss->cr3 = cr3;
}

static void setup_tss_desc(unsigned short tss_sel, struct tss32 *tss)
{
	unsigned long addr = (unsigned long)tss;
	unsigned short *desc;

	desc = (unsigned short *)&gdt[tss_sel/8];
	desc[0] = sizeof(*tss) - 1;
	desc[1] = addr;
	desc[2] = 0x8900 | ((addr & 0x00ff0000) >> 16);
	desc[3] = (addr & 0xff000000) >> 16;
}

static void set_intr_task(unsigned short tss_sel, int intr, struct tss32 *tss)
{
	unsigned short *desc = (void *)(intr* sizeof(long) * 2);

	setup_tss_desc(tss_sel, tss);

	desc[0] = 0;
	desc[1] = tss_sel;
	desc[2] = 0x8500;
	desc[3] = 0;
}

int main(int ac, char **av)
{
	const long invalid_segment = 0x1234;

	gdtr = ((unsigned long long)(unsigned long)&gdt << 16) |
		(sizeof(gdt) - 1);
	asm ("lgdt %0" : : "m" (gdtr));

	setup_tss(&main_tss, 0, main_stack, sizeof(main_stack));
	setup_tss_desc(FIRST_SPARE_SEL, &main_tss);
	asm ("ltr %0" : : "r" ((unsigned short)FIRST_SPARE_SEL));

	setup_tss(&fault_tss, fault_entry, fault_stack, sizeof(fault_stack));
	set_intr_task(FIRST_SPARE_SEL+8, 13, &fault_tss);

	asm (
		"mov %0,%%es\n"
		: : "r" (invalid_segment) : "edi"
	);

	printf("post fault\n");

	return 0;
}
