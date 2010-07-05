#ifndef VM_H
#define VM_H

#define PAGE_SIZE 4096ul
#ifdef __x86_64__
#define LARGE_PAGE_SIZE (512 * PAGE_SIZE)
#else
#define LARGE_PAGE_SIZE (1024 * PAGE_SIZE)
#endif

#define PTE_PRESENT (1ull << 0)
#define PTE_PSE     (1ull << 7)
#define PTE_WRITE   (1ull << 1)
#define PTE_ADDR    (0xffffffffff000ull)

void setup_vm();

void *vmalloc(unsigned long size);
void vfree(void *mem);
void *vmap(unsigned long long phys, unsigned long size);

void install_pte(unsigned long *cr3,
                        int pte_level,
                        void *virt,
                        unsigned long pte,
                        unsigned long *pt_page);

void *alloc_page();

void install_large_page(unsigned long *cr3,unsigned long phys,
                               void *virt);
void install_page(unsigned long *cr3, unsigned long phys, void *virt);

static inline unsigned long virt_to_phys(const void *virt)
{
    return (unsigned long)virt;
}

static inline void *phys_to_virt(unsigned long phys)
{
    return (void *)phys;
}


static inline void load_cr3(unsigned long cr3)
{
    asm ( "mov %0, %%cr3" : : "r"(cr3) );
}

static inline unsigned long read_cr3()
{
    unsigned long cr3;

    asm volatile ( "mov %%cr3, %0" : "=r"(cr3) );
    return cr3;
}

static inline void load_cr0(unsigned long cr0)
{
    asm volatile ( "mov %0, %%cr0" : : "r"(cr0) );
}

static inline unsigned long read_cr0()
{
    unsigned long cr0;

    asm volatile ( "mov %%cr0, %0" : "=r"(cr0) );
    return cr0;
}


static inline void load_cr4(unsigned long cr4)
{
    asm volatile ( "mov %0, %%cr4" : : "r"(cr4) );
}

static inline unsigned long read_cr4()
{
    unsigned long cr4;

    asm volatile ( "mov %%cr4, %0" : "=r"(cr4) );
    return cr4;
}

#endif
