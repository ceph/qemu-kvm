
#include "printf.h"

typedef unsigned long pt_element_t;

#define PAGE_SIZE ((pt_element_t)4096)
#define PAGE_MASK (~(PAGE_SIZE-1))

#define PT_BASE_ADDR_MASK ((pt_element_t)((((pt_element_t)1 << 40) - 1) & PAGE_MASK))

#define PT_PRESENT_MASK    ((pt_element_t)1 << 0)
#define PT_WRITABLE_MASK   ((pt_element_t)1 << 1)
#define PT_USER_MASK       ((pt_element_t)1 << 2)

#define CR0_WP_MASK (1UL << 16)

/*
 * page table access check tests
 */

enum {
    AC_PTE_PRESENT,
    // AC_PTE_WRITABLE,
    // AC_PTE_USER,
    // AC_PTE_ACCESSED,
    // AC_PTE_DIRTY,
    // AC_PTE_NX,

    // AC_CPU_CR0_WP,
    // AC_CPU_EFER_NX,

    // AC_ACCESS_USER,
    // AC_ACCESS_WRITE,
    // AC_ACCESS_FETCH,
    // AC_ACCESS_PTE,

    NR_AC_FLAGS
};

const char *ac_names[] = {
    [AC_PTE_PRESENT] = "pte.p",
};

static inline void *va(pt_element_t phys)
{
    return (void *)phys;
}

static unsigned long read_cr0()
{
    unsigned long cr0;

    asm volatile ("mov %%cr0, %0" : "=r"(cr0));

    return cr0;
}

static void write_cr0(unsigned long cr0)
{
    asm volatile ("mov %0, %%cr0" : : "r"(cr0));
}

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

typedef struct {
    unsigned flags[NR_AC_FLAGS];
    void *virt;
    pt_element_t phys;
    pt_element_t pt_pool;
    idt_entry_t idt[256];
} ac_test_t;

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

void memset(void *a, unsigned char v, int n)
{
    unsigned char *x = a;

    while (n--)
	*x++ = v;
}

unsigned short read_cs()
{
    unsigned short r;

    asm volatile ("mov %%cs, %0" : "=r"(r));
}

void set_idt_entry(idt_entry_t *e, void *addr)
{
    memset(e, 0, sizeof *e);
    e->offset0 = (unsigned long)addr;
    e->selector = read_cs();
    e->ist = 0;
    e->type = 14;
    e->dpl = 0;
    e->p = 1;
    e->offset1 = (unsigned long)addr >> 16;
    e->offset2 = (unsigned long)addr >> 32;
}

void set_cr0_wp(int wp)
{
    unsigned long cr0 = read_cr0();

    cr0 &= ~CR0_WP_MASK;
    if (wp)
	cr0 |= CR0_WP_MASK;
    write_cr0(cr0);
}

void ac_test_init(ac_test_t *at)
{
    printf("init\n");
    set_cr0_wp(1);
    for (int i = 0; i < NR_AC_FLAGS; ++i)
	at->flags[i] = 0;
    at->virt = (void *)0x123400000000;
    at->phys = 32 * 1024 * 1024;
    at->pt_pool = 33 * 1024 * 1024;
    memset(at->idt, 0, sizeof at->idt);
    printf("lidt\n");
    lidt(at->idt, 256);
    extern char page_fault;
    set_idt_entry(&at->idt[14], &page_fault);
    printf("ok\n");
}

int ac_test_bump(ac_test_t *at)
{
    for (int i = 0; i < NR_AC_FLAGS; ++i)
	if (!at->flags[i]) {
	    at->flags[i] = 1;
	    return 1;
	} else
	    at->flags[i] = 0;
    return 0;
}

unsigned long read_cr3()
{
    unsigned long cr3;

    asm volatile ("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

void invlpg(void *addr)
{
    asm volatile ("invlpg (%0)" : : "r"(addr));
}

pt_element_t ac_test_alloc_pt(ac_test_t *at)
{
    pt_element_t ret = at->pt_pool;
    at->pt_pool += PAGE_SIZE;
    return ret;
}

void ac_test_setup_pte(ac_test_t *at)
{
    unsigned long root = read_cr3();

    printf("setting up pte\n");
    for (int i = 4; i >= 1; --i) {
	pt_element_t *vroot = va(root & PT_BASE_ADDR_MASK);
	unsigned index = ((unsigned long)at->virt >> (12 + (i-1) * 9)) & 511;
	pt_element_t pte;
	if (i != 1) {
	    pte = vroot[index];
	    if (!(pte & PT_PRESENT_MASK))
		pte = ac_test_alloc_pt(at) | PT_PRESENT_MASK;
	    pte |= PT_WRITABLE_MASK | PT_USER_MASK;
	} else {
	    pte = at->phys & PT_BASE_ADDR_MASK;
	    if (at->flags[AC_PTE_PRESENT])
		pte |= PT_PRESENT_MASK;
	    
	}
	vroot[index] = pte;
	root = vroot[index];
    }
    invlpg(at->virt);
}

int ac_test_do_access(ac_test_t *at, unsigned *error_code)
{
    static unsigned unique = 42;
    int ret = 1;
    unsigned e;

    ++unique;

    printf("attempting access\n");
    unsigned r = unique;
    asm volatile ("fault1: mov (%[addr]), %[reg] \n\t"
		  "fixed1:"
		  : [reg]"+r"(r), "=m"(*error_code), "+a"(ret), "=b"(e)
		  : [addr]"r"(at->virt));

    asm volatile (".section .text.pf \n\t"
		  "page_fault: \n\t"
		  "pop %rbx \n\t"
		  "movq $fixed1, (%rsp) \n\t"
		  "movl $0, %eax \n\t"
		  "iretq \n\t"
		  ".section .text");
    *error_code = e;

    return ret;
}

void ac_test_exec(ac_test_t *at)
{
    int r;
    unsigned error_code;

    printf("test");
    for (int i = 0; i < NR_AC_FLAGS; ++i)
	if (at->flags[i])
	    printf(" %s", ac_names[i]);
    printf(" - ");
    ac_test_setup_pte(at);
    r = ac_test_do_access(at, &error_code);
    if (r)
	printf("accessed");
    else
	printf("faulted %x", error_code);
    printf("\n");
}

void ac_test_run()
{
    static ac_test_t at;

    printf("run\n");
    ac_test_init(&at);
    do {
	ac_test_exec(&at);
    } while (ac_test_bump(&at));
}

int main()
{
    printf("starting test\n\n");
    ac_test_run();
    return 0;
}
