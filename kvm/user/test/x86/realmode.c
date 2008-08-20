asm(".code16gcc");

typedef unsigned u32;

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

void start(void)
{
	print_serial("abc\n");
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
