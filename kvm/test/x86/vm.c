#include "vm.h"
#include "libcflat.h"

#define PAGE_SIZE 4096ul
#ifdef __x86_64__
#define LARGE_PAGE_SIZE (512 * PAGE_SIZE)
#else
#define LARGE_PAGE_SIZE (1024 * PAGE_SIZE)
#endif

#define X86_CR0_PE      0x00000001
#define X86_CR0_PG      0x80000000
#define X86_CR4_PSE     0x00000010
static void *free = 0;
static void *vfree_top = 0;

static void free_memory(void *mem, unsigned long size)
{
    while (size >= PAGE_SIZE) {
	*(void **)mem = free;
	free = mem;
	mem += PAGE_SIZE;
	size -= PAGE_SIZE;
    }
}

void *alloc_page()
{
    void *p;

    if (!free)
	return 0;
    
    p = free;
    free = *(void **)free;

    return p;
}

void free_page(void *page)
{
    *(void **)page = free;
    free = page;
}

extern char edata;
static unsigned long end_of_memory;

#ifdef __x86_64__
#define	PAGE_LEVEL	4
#define	PGDIR_WIDTH	9
#define	PGDIR_MASK	511
#else
#define	PAGE_LEVEL	2
#define	PGDIR_WIDTH	10
#define	PGDIR_MASK	1023
#endif

void install_pte(unsigned long *cr3,
		 int pte_level,
		 void *virt,
		 unsigned long pte,
		 unsigned long *pt_page)
{
    int level;
    unsigned long *pt = cr3;
    unsigned offset;

    for (level = PAGE_LEVEL; level > pte_level; --level) {
	offset = ((unsigned long)virt >> ((level-1) * PGDIR_WIDTH + 12)) & PGDIR_MASK;
	if (!(pt[offset] & PTE_PRESENT)) {
	    unsigned long *new_pt = pt_page;
            if (!new_pt)
                new_pt = alloc_page();
            else
                pt_page = 0;
	    memset(new_pt, 0, PAGE_SIZE);
	    pt[offset] = virt_to_phys(new_pt) | PTE_PRESENT | PTE_WRITE;
	}
	pt = phys_to_virt(pt[offset] & 0xffffffffff000ull);
    }
    offset = ((unsigned long)virt >> ((level-1) * PGDIR_WIDTH + 12)) & PGDIR_MASK;
    pt[offset] = pte;
}

static unsigned long get_pte(unsigned long *cr3, void *virt)
{
    int level;
    unsigned long *pt = cr3, pte;
    unsigned offset;

    for (level = PAGE_LEVEL; level > 1; --level) {
	offset = ((unsigned long)virt >> (((level-1) * PGDIR_WIDTH) + 12)) & PGDIR_MASK;
	pte = pt[offset];
	if (!(pte & PTE_PRESENT))
	    return 0;
	if (level == 2 && (pte & PTE_PSE))
	    return pte;
	pt = phys_to_virt(pte & 0xffffffffff000ull);
    }
    offset = ((unsigned long)virt >> (((level-1) * PGDIR_WIDTH) + 12)) & PGDIR_MASK;
    pte = pt[offset];
    return pte;
}

void install_large_page(unsigned long *cr3,
                              unsigned long phys,
                              void *virt)
{
    install_pte(cr3, 2, virt, phys | PTE_PRESENT | PTE_WRITE | PTE_PSE, 0);
}

void install_page(unsigned long *cr3,
                  unsigned long phys,
                  void *virt)
{
    install_pte(cr3, 1, virt, phys | PTE_PRESENT | PTE_WRITE, 0);
}


static inline void load_gdt(unsigned long *table, int nent)
{
    struct descriptor_table_ptr descr;

    descr.limit = nent * 8 - 1;
    descr.base = (ulong)table;
    lgdt(&descr);
}

#define SEG_CS_32 8
#define SEG_CS_64 16

struct ljmp {
    void *ofs;
    unsigned short seg;
};

static void setup_mmu(unsigned long len)
{
    unsigned long *cr3 = alloc_page();
    unsigned long phys = 0;

    if (len < (1ul << 32))
        len = 1ul << 32;  /* map mmio 1:1 */

    memset(cr3, 0, PAGE_SIZE);
    while (phys + LARGE_PAGE_SIZE <= len) {
	install_large_page(cr3, phys, (void *)phys);
	phys += LARGE_PAGE_SIZE;
    }
    while (phys + PAGE_SIZE <= len) {
	install_page(cr3, phys, (void *)phys);
	phys += PAGE_SIZE;
    }
    write_cr3(virt_to_phys(cr3));
#ifndef __x86_64__
    write_cr4(X86_CR4_PSE);
#endif
    write_cr0(X86_CR0_PG |X86_CR0_PE);

    printf("paging enabled\n");
    printf("cr0 = %x\n", read_cr0());
    printf("cr3 = %x\n", read_cr3());
    printf("cr4 = %x\n", read_cr4());
}

static unsigned int inl(unsigned short port)
{
    unsigned int val;
    asm volatile("inl %w1, %0" : "=a"(val) : "Nd"(port));
    return val;
}

void setup_vm()
{
    end_of_memory = inl(0xd1);
    free_memory(&edata, end_of_memory - (unsigned long)&edata);
    setup_mmu(end_of_memory);
}

void *vmalloc(unsigned long size)
{
    void *mem, *p;
    unsigned pages;

    size += sizeof(unsigned long);
    
    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    vfree_top -= size;
    mem = p = vfree_top;
    pages = size / PAGE_SIZE;
    while (pages--) {
	install_page(phys_to_virt(read_cr3()), virt_to_phys(alloc_page()), p);
	p += PAGE_SIZE;
    }
    *(unsigned long *)mem = size;
    mem += sizeof(unsigned long);
    return mem;
}

void vfree(void *mem)
{
    unsigned long size = ((unsigned long *)mem)[-1];
    
    while (size) {
	free_page(phys_to_virt(get_pte(phys_to_virt(read_cr3()), mem) & PTE_ADDR));
	mem += PAGE_SIZE;
	size -= PAGE_SIZE;
    }
}

void *vmap(unsigned long long phys, unsigned long size)
{
    void *mem, *p;
    unsigned pages;

    size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    vfree_top -= size;
    phys &= ~(unsigned long long)(PAGE_SIZE - 1);

    mem = p = vfree_top;
    pages = size / PAGE_SIZE;
    while (pages--) {
	install_page(phys_to_virt(read_cr3()), phys, p);
	phys += PAGE_SIZE;
	p += PAGE_SIZE;
    }
    return mem;
}
