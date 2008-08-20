asm(".code16gcc");

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned u32;
typedef unsigned long long u64;

static int strlen(const char *str)
{
	int n;

	for (n = 0; *str; ++str)
		++n;
	return n;
}

static void print_serial(const char *buf)
{
	unsigned long len = strlen(buf);

	asm volatile ("addr32/rep/outsb" : "+S"(buf), "+c"(len) : "d"(0xf1));
}

static void exit(int code)
{
        asm volatile("out %0, %1" : : "a"(code), "d"((short)0xf4));
}

struct regs {
	u32 eax, ebx, ecx, edx;
	u32 esi, edi, esp, ebp;
	u32 eip, eflags;
};

static u64 gdt[] = {
	0,
	0x00cf9b000000ffffull, // flat 32-bit code segment
	0x00cf93000000ffffull, // flat 32-bit data segment
};

static struct {
	u16 limit;
	void *base;
} __attribute__((packed)) gdt_descr = {
	sizeof(gdt) - 1,
	gdt,
};

static void exec_in_big_real_mode(const struct regs *inregs,
				  struct regs *outregs,
				  const u8 *insn, int insn_len)
{
	unsigned long tmp;
	static struct regs save;
	int i;
	extern u8 test_insn[], test_insn_end[];

	for (i = 0; i < insn_len; ++i)
		test_insn[i] = insn[i];
	for (; i < test_insn_end - test_insn; ++i)
		test_insn[i] = 0x90; // nop

	save = *inregs;
	asm volatile(
		"lgdtl %[gdt_descr] \n\t"
		"mov %%cr0, %[tmp] \n\t"
		"or $1, %[tmp] \n\t"
		"mov %[tmp], %%cr0 \n\t"
		"mov %[bigseg], %%gs \n\t"
		"and $-2, %[tmp] \n\t"
		"mov %[tmp], %%cr0 \n\t"

		"xchg %%eax, %[save]+0 \n\t"
		"xchg %%ebx, %[save]+4 \n\t"
		"xchg %%ecx, %[save]+8 \n\t"
		"xchg %%edx, %[save]+12 \n\t"
		"xchg %%esi, %[save]+16 \n\t"
		"xchg %%edi, %[save]+20 \n\t"
		"xchg %%esp, %[save]+24 \n\t"
		"xchg %%ebp, %[save]+28 \n\t"

		"test_insn: . = . + 16\n\t"
		"test_insn_end: \n\t"

		"xchg %%eax, %[save]+0 \n\t"
		"xchg %%ebx, %[save]+4 \n\t"
		"xchg %%ecx, %[save]+8 \n\t"
		"xchg %%edx, %[save]+12 \n\t"
		"xchg %%esi, %[save]+16 \n\t"
		"xchg %%edi, %[save]+20 \n\t"
		"xchg %%esp, %[save]+24 \n\t"
		"xchg %%ebp, %[save]+28 \n\t"

		"xor %[tmp], %[tmp] \n\t"
		"mov %[tmp], %%gs \n\t"
		: [tmp]"=&r"(tmp), [save]"+m"(save)
		: [gdt_descr]"m"(gdt_descr), [bigseg]"r"((short)16)
		: "cc", "memory"
		);
	*outregs = save;
}

void start(void)
{
	struct regs regs = { 0 };

	print_serial("abc\n");
	exec_in_big_real_mode(&regs, &regs, 0, 0);
	exit(0);
}

asm(
	".data \n\t"
	". = . + 4096 \n\t"
	"stacktop: \n\t"
	".text \n\t"
	"init: \n\t"
	"xor %ax, %ax \n\t"
	"mov %ax, %ds \n\t"
	"mov %ax, %es \n\t"
	"mov %ax, %ss \n\t"
	"mov $0x4000, %cx \n\t"
	"xor %esi, %esi \n\t"
	"mov %esi, %edi \n\t"
	"rep/addr32/cs/movsl \n\t"
	"mov $stacktop, %sp\n\t"
	"ljmp $0, $start \n\t"
	".pushsection .boot, \"ax\" \n\t"
	"ljmp $0xf000, $init \n\t"
	".popsection"
	);
