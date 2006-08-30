#include <linux/types.h>
#include <linux/string.h>
#include <asm/page.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/module.h>

#include "vmx.h"
#include "hvm.h"

#define pgprintk(x...) do { } while (0)

#define ASSERT(x)  							     \
	if (!(x)) { 							     \
		printk("assertion failed %s:%d: %s\n", __FILE__, __LINE__, #x);\
	}

#define FALSE 0
#define TRUE 1


#define PT64_ENT_PER_PAGE 512
#define PT32_ENT_PER_PAGE 1024

#define PT_WRITABLE_SHIFT 1

#define PT_PRESENT_MASK (1ULL << 0)
#define PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define PT_USER_MASK (1ULL << 2)
#define PT_PWT_MASK (1ULL << 3)
#define PT_PCD_MASK (1ULL << 4)
#define PT_ACCESSED_MASK (1ULL << 5)
#define PT_DIRTY_MASK (1ULL << 6)
#define PT_PAGE_SIZE_MASK (1ULL << 7)
#define PT_PAT_MASK (1ULL << 7)
#define PT_GLOBAL_MASK (1ULL << 8)
#define PT64_NX_MASK (1ULL << 63)

#define PT_PAT_SHIFT 7
#define PT_DIR_PAT_SHIFT 12
#define PT_DIR_PAT_MASK (1ULL << PT_DIR_PAT_SHIFT)

#define PT32_DIR_PSE36_SIZE 4
#define PT32_DIR_PSE36_SHIFT 13
#define PT32_DIR_PSE36_MASK (((1ULL << PT32_DIR_PSE36_SIZE) - 1) << PT32_DIR_PSE36_SHIFT)


#define PT32_PTE_COPY_MASK \
	(PT_PRESENT_MASK | PT_PWT_MASK | PT_PCD_MASK | \
	PT_ACCESSED_MASK | PT_DIRTY_MASK | PT_PAT_MASK | \
	PT_GLOBAL_MASK )

#define PT32_NON_PTE_COPY_MASK \
	(PT_PRESENT_MASK | PT_PWT_MASK | PT_PCD_MASK | \
	PT_ACCESSED_MASK | PT_DIRTY_MASK)


#define PT64_PTE_COPY_MASK \
	(PT64_NX_MASK | PT32_PTE_COPY_MASK)

#define PT64_NON_PTE_COPY_MASK \
	(PT64_NX_MASK | PT32_NON_PTE_COPY_MASK)



#define PT_FIRST_AVAIL_BITS_SHIFT 9
#define PT64_SECOND_AVAIL_BITS_SHIFT 52

#define PT_SHADOW_PS_MARK (1ULL << PT_FIRST_AVAIL_BITS_SHIFT)
#define PT_SHADOW_IO_MARK (1ULL << PT_FIRST_AVAIL_BITS_SHIFT)

#define PT_SHADOW_WRITABLE_SHIFT (PT_FIRST_AVAIL_BITS_SHIFT + 1)
#define PT_SHADOW_WRITABLE_MASK (1ULL << PT_SHADOW_WRITABLE_SHIFT)

#define PT_SHADOW_USER_SHIFT (PT_SHADOW_WRITABLE_SHIFT + 1)
#define PT_SHADOW_USER_MASK (1ULL << (PT_SHADOW_USER_SHIFT))

#define PT_SHADOW_BITS_OFFSET (PT_SHADOW_WRITABLE_SHIFT - PT_WRITABLE_SHIFT)

#define VALID_PAGE(x) ((x) != INVALID_PAGE)

#define PT64_LEVEL_BITS 9

#define PT64_LEVEL_SHIFT(level) \
		( PAGE_SHIFT + (level - 1) * PT64_LEVEL_BITS )

#define PT64_LEVEL_MASK(level) \
		(((1ULL << PT64_LEVEL_BITS) - 1) << PT64_LEVEL_SHIFT(level))

#define PT64_INDEX(address, level)\
	(((address) >> PT64_LEVEL_SHIFT(level)) & ((1 << PT64_LEVEL_BITS) - 1))


#define PT32_LEVEL_BITS 10

#define PT32_LEVEL_SHIFT(level) \
		( PAGE_SHIFT + (level - 1) * PT32_LEVEL_BITS )

#define PT32_LEVEL_MASK(level) \
		(((1ULL << PT32_LEVEL_BITS) - 1) << PT32_LEVEL_SHIFT(level))

#define PT32_INDEX(address, level)\
	(((address) >> PT32_LEVEL_SHIFT(level)) & ((1 << PT32_LEVEL_BITS) - 1))


#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & PAGE_MASK)
#define PT64_DIR_BASE_ADDR_MASK \
	(PT64_BASE_ADDR_MASK & ~((1ULL << (PAGE_SHIFT + PT64_LEVEL_BITS)) - 1))

#define PT32_BASE_ADDR_MASK PAGE_MASK
#define PT32_DIR_BASE_ADDR_MASK \
	(PAGE_MASK & ~((1ULL << (PAGE_SHIFT + PT32_LEVEL_BITS)) - 1))


#define PFERR_PRESENT_MASK (1U << 0)
#define PFERR_WRITE_MASK (1U << 1)
#define PFERR_USER_MASK (1U << 2)

#define PT64_ROOT_LEVEL 4
#define PT32_ROOT_LEVEL 2
#define PT32E_ROOT_LEVEL 3

#define PT_DIRECTORY_LEVEL 2
#define PT_PAGE_TABLE_LEVEL 1

#define P_TO_V(address)\
	page_address(pfn_to_page((address) >> PAGE_SHIFT))


static inline int is_write_protection(void)
{
	return guest_cr0() & CR0_WP_MASK;
}


static inline int is_cpuid_PSE36(void)
{
	return TRUE;
}


static inline int is_present_pte(unsigned long pte)
{
	return pte & PT_PRESENT_MASK;
}


static inline int is_writeble_pte(unsigned long pte)
{
	return pte & PT_WRITABLE_MASK;
}


static inline int is_dirty_pte(unsigned long pte)
{
	return pte & PT_DIRTY_MASK;
}


static inline int is_io_pte(unsigned long pte)
{
	return pte & PT_SHADOW_IO_MARK;
}


static void hvm_mmu_free_page(struct hvm_vcpu *vcpu, hpa_t page_hpa)
{
	page_link_t *page_link;

	ASSERT(!list_empty(&vcpu->free_page_links));
	page_link = list_entry(vcpu->free_page_links.next,
				     page_link_t, 
				     link);
	list_del(&page_link->link);
	page_link->page_hpa = page_hpa;
	list_add(&page_link->link, &vcpu->free_pages);
}


static int is_empty_shadow_page(hpa_t page_hpa)
{
	uint32_t *pos;
	uint32_t *end; 
	for (pos = __va(page_hpa), end = pos + PAGE_SIZE / sizeof(uint32_t);
		      pos != end; pos++) {
		if (*pos != 0) {
			return FALSE;
		}
	}
	return TRUE;
}


static hpa_t hvm_mmu_alloc_page(struct hvm_vcpu *vcpu)
{
	hpa_t page_addr;
	page_link_t *page_link;

	if (list_empty(&vcpu->free_pages)) {
		return INVALID_PAGE; 
	}
	
	page_link = list_entry(vcpu->free_pages.next,
				     page_link_t, 
				     link);
	list_del(&page_link->link);
	page_addr = page_link->page_hpa;
	page_link->page_hpa = INVALID_PAGE;
	list_add(&page_link->link, &vcpu->free_page_links);
	ASSERT(is_empty_shadow_page(page_addr));
	return page_addr;
}



static inline int is_io_mem(struct hvm_vcpu *vcpu, unsigned long addr)
{

	if ((addr >> PAGE_SHIFT) >= vcpu->hvm->phys_mem_pages ) {
		return TRUE;
	}

	return (addr >= 0xa0000ULL && addr < 0xe0000ULL) || 
		(addr >= 0xf0000ULL && addr < 0x100000ULL) ||
		(addr >= 0xffff0000ULL && addr < 0x100000000ULL);
}


static hpa_t gpa_to_hpa(struct hvm_vcpu *vcpu, gpa_t gpa)
{
	struct page *page;

	ASSERT(vcpu);
	ASSERT((gpa & ~PT64_BASE_ADDR_MASK) == 0)

	if (is_io_mem(vcpu, gpa)) {
		return hvm_bad_page_addr;
	}

	page = vcpu->hvm->phys_mem[gpa >> PAGE_SHIFT];
	return page_to_pfn(page) << PAGE_SHIFT;  
}

hpa_t gva_to_hpa(struct hvm_vcpu *vcpu, gva_t gva)
{
	uint64_t pte = vcpu->paging_context.fetch_pte64(vcpu, gva);
	return gpa_to_hpa(vcpu, pte & PT64_BASE_ADDR_MASK);
}



static void releas_pt_page_64(struct hvm_vcpu *vcpu, hpa_t page_hpa, int level)
{
	ASSERT(vcpu);
	ASSERT(VALID_PAGE(page_hpa));
	ASSERT(level <= PT64_ROOT_LEVEL && level > 0);

	if (level == 1) {
		memset(__va(page_hpa), 0, PAGE_SIZE);
	} else {
		uint64_t *pos;
		uint64_t *end;

		for (pos = __va(page_hpa), end = pos + PT64_ENT_PER_PAGE;
		      pos != end; pos++) {
			uint64_t current_ent = *pos;
			*pos = 0;
			if (is_present_pte(current_ent)) {
				releas_pt_page_64(vcpu,
						  current_ent & 
						  PT64_BASE_ADDR_MASK,
						  level - 1);
			}
		}
	}
	hvm_mmu_free_page(vcpu, page_hpa);  
}


static void nonpaging_new_cr3(struct hvm_vcpu *vcpu)
{    
}


static int nonpaging_map(struct hvm_vcpu *vcpu, gva_t v, hpa_t p)
{
	int level = PT32E_ROOT_LEVEL;
	hpa_t table_addr = vcpu->paging_context.root_hpa;

	for (; ; level--) {
		uint32_t index = PT64_INDEX(v, level);
		uint64_t *table;

		ASSERT(VALID_PAGE(table_addr));
		table = __va(table_addr);

		if (level == 1) {
			table[index] = p | 
					PT_PRESENT_MASK | 
					PT_WRITABLE_MASK;
			return 0;
		}

		if (table[index] == 0) {
			hpa_t new_table = hvm_mmu_alloc_page(vcpu);
			if (!VALID_PAGE(new_table)) {
				pgprintk("nonpaging_map: ENOMEM\n");
				return -ENOMEM;
			}

			if (level == PT32E_ROOT_LEVEL) {
				table[index] = new_table | PT_PRESENT_MASK;
			} else {
				table[index] = new_table |
					PT_PRESENT_MASK | PT_WRITABLE_MASK;
			}
		}
		table_addr = table[index] & PT64_BASE_ADDR_MASK;
	}
}


static void nonpaging_flush(struct hvm_vcpu *vcpu)
{
	hpa_t root = vcpu->paging_context.root_hpa;

	++hvm_stat.tlb_flush;
	pgprintk("nonpaging_flush\n");
	ASSERT(VALID_PAGE(root));
	releas_pt_page_64(vcpu, root, vcpu->paging_context.shadow_root_level);
	root = hvm_mmu_alloc_page(vcpu);
	ASSERT(VALID_PAGE(root));
	vcpu->paging_context.root_hpa = root;
	if (is_paging()) {
		root |= (vcpu->cr3 & (CR3_PCD_MASK | CR3_WPT_MASK));
	} 
	vmcs_writel(GUEST_CR3, root);
}

static u64 nonpaging_fetch_pte64(struct hvm_vcpu *vcpu, unsigned long vaddr)
{
	return (vaddr & PAGE_MASK) 
		| PT_PRESENT_MASK
		| PT_WRITABLE_MASK
		| PT_ACCESSED_MASK
		| PT_DIRTY_MASK;
}

static int nonpaging_page_fault(struct hvm_vcpu *vcpu, gva_t gva,
			       uint32_t error_code)
{
     int ret;
     gpa_t addr = gva;

     ASSERT(vcpu);
     ASSERT(VALID_PAGE(vcpu->paging_context.root_hpa));

     for (;;) {
	     hpa_t paddr = gpa_to_hpa(vcpu, addr & PT64_BASE_ADDR_MASK);
	     if (paddr == hvm_bad_page_addr) {
		     return 1;
	     }
	     ret = nonpaging_map(vcpu, 
		   addr & PAGE_MASK, paddr);
	     if (ret) {
		     nonpaging_flush(vcpu);
		     continue;
	     }
	     break;
     }
     return ret;
}


static void nonpaging_inval_page(struct hvm_vcpu *vcpu, gva_t addr)
{
	
}


static void nonpaging_free(struct hvm_vcpu *vcpu)
{
	hpa_t root;

	ASSERT(vcpu);
	root = vcpu->paging_context.root_hpa;
	if (VALID_PAGE(root)) {
		releas_pt_page_64(vcpu, root,
				  vcpu->paging_context.shadow_root_level);
	}
	vcpu->paging_context.root_hpa = INVALID_PAGE;
}


static int nonpaging_init_context(struct hvm_vcpu *vcpu)
{
	paging_context_t *context = &vcpu->paging_context;

	context->new_cr3 = nonpaging_new_cr3;
	context->page_fault = nonpaging_page_fault;
	context->inval_page = nonpaging_inval_page;
	context->fetch_pte64 = nonpaging_fetch_pte64;
	context->free = nonpaging_free;
	context->root_level = PT32E_ROOT_LEVEL;
	context->shadow_root_level = PT32E_ROOT_LEVEL;
	context->root_hpa = hvm_mmu_alloc_page(vcpu);
	ASSERT(VALID_PAGE(context->root_hpa));
	vmcs_writel(GUEST_CR3, context->root_hpa);
	return 0;
}


static void paging_new_cr3(struct hvm_vcpu *vcpu)
{
    nonpaging_flush(vcpu);
}


static inline void set_pte_common(struct hvm_vcpu *vcpu,
			     uint64_t *shadow_pte,
			     gpa_t gaddr,
			     uint64_t access_bits)
{
	hpa_t paddr;

	*shadow_pte |= access_bits << PT_SHADOW_BITS_OFFSET;
	*shadow_pte |= access_bits & ~PT_WRITABLE_MASK;

	paddr = gpa_to_hpa(vcpu, gaddr);

	if (paddr == hvm_bad_page_addr) {
		*shadow_pte |= gaddr;
		*shadow_pte |= PT_SHADOW_IO_MARK;
		*shadow_pte &= ~PT_PRESENT_MASK;
	} else {
		*shadow_pte |= paddr;
	}
}


static void inject_page_fault(struct hvm_vcpu *vcpu, 
			      uint64_t addr, 
			      uint32_t err_code)
{
	uint32_t vect_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);

	pgprintk("inject_page_fault: 0x%llx err 0x%x\n", addr, err_code);
	
	++hvm_stat.pf_guest;

	if (is_page_fault(vect_info)) {
		printk("inject_page_fault: double fault 0x%llx @ 0x%lx\n",
		       addr, vmcs_readl(GUEST_RIP));
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			     DF_VECTOR |
			     INTR_TYPE_EXCEPTION |
			     INTR_INFO_DELIEVER_CODE_MASK |
			     INTR_INFO_VALID_MASK);
		return;
	}
	vcpu->regs[VCPU_REGS_CR2] = addr; 
	vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, err_code);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		     PF_VECTOR |
		     INTR_TYPE_EXCEPTION |
		     INTR_INFO_DELIEVER_CODE_MASK |
		     INTR_INFO_VALID_MASK);
	
}


static inline int fix_read_pf(uint64_t *shadow_ent)
{
	if ((*shadow_ent & PT_SHADOW_USER_MASK) && 
	    !(*shadow_ent & PT_USER_MASK)) {
		*shadow_ent |= PT_USER_MASK;
		*shadow_ent &= ~PT_WRITABLE_MASK;

		return 1;
		
	}
	return 0;
}


static int access_test(uint64_t pte, int write, int user)
{
	
	if (user && !(pte & PT_USER_MASK)) {
		return 0;
	}

	if (write && !(pte & PT_WRITABLE_MASK)) {
		return 0;
	}

	return 1;
}


static void paging_inval_page(struct hvm_vcpu *vcpu, gva_t addr)
{
	hpa_t page_addr = vcpu->paging_context.root_hpa;
	int level = vcpu->paging_context.shadow_root_level;

	++hvm_stat.invlpg;

	for (; ; level--) {
		uint32_t index = PT64_INDEX(addr, level);
		uint64_t *table = __va(page_addr);

		if (!is_present_pte(table[index])) {
			return;
		}

		if (level == PT_PAGE_TABLE_LEVEL ) {
			table[index] = 0;
			return;
		}

		if (level == PT_DIRECTORY_LEVEL && 
			  (table[index] & PT_SHADOW_PS_MARK)) {
			hpa_t page_addr = table[index] & PT64_BASE_ADDR_MASK;
			table[index] = 0;
			releas_pt_page_64(vcpu, page_addr, PT_PAGE_TABLE_LEVEL);
			return;
		}

		page_addr = table[index] & PT64_BASE_ADDR_MASK;
	}
}


static void paging_free(struct hvm_vcpu *vcpu)
{
	nonpaging_free(vcpu);
}

#define PTTYPE 64
#include "hvm_paging_tmpl.h"
#undef PTTYPE

#define PTTYPE 32
#include "hvm_paging_tmpl.h"
#undef PTTYPE


static int paging64_init_context(struct hvm_vcpu *vcpu)
{
	paging_context_t *context = &vcpu->paging_context;

	ASSERT(is_pae());
	context->new_cr3 = paging_new_cr3;
	context->page_fault = paging64_page_fault;
	context->inval_page = paging_inval_page;
	context->fetch_pte64 = paging64_fetch_pte;
	context->free = paging_free;
	context->root_level = PT64_ROOT_LEVEL;
	context->shadow_root_level = PT64_ROOT_LEVEL;
	context->root_hpa = hvm_mmu_alloc_page(vcpu);
	ASSERT(VALID_PAGE(context->root_hpa));
	vmcs_writel(GUEST_CR3, context->root_hpa | 
		    (vcpu->cr3 & (CR3_PCD_MASK | CR3_WPT_MASK)));
	return 0;
}


static int paging32_init_context(struct hvm_vcpu *vcpu)
{
	paging_context_t *context = &vcpu->paging_context;

	context->new_cr3 = paging_new_cr3;
	context->page_fault = paging32_page_fault;
	context->inval_page = paging_inval_page;
	context->fetch_pte64 = paging32_fetch_pte;
	context->free = paging_free;
	context->root_level = PT32_ROOT_LEVEL;
	context->shadow_root_level = PT32E_ROOT_LEVEL;
	context->root_hpa = hvm_mmu_alloc_page(vcpu);
	ASSERT(VALID_PAGE(context->root_hpa));
	vmcs_writel(GUEST_CR3, context->root_hpa | 
		    (vcpu->cr3 & (CR3_PCD_MASK | CR3_WPT_MASK)));
	return 0;
}


static int paging32E_init_context(struct hvm_vcpu *vcpu)
{
	int ret;

	if ((ret = paging64_init_context(vcpu))) {
		return ret;
	}

	vcpu->paging_context.root_level = PT32E_ROOT_LEVEL;
	vcpu->paging_context.shadow_root_level = PT32E_ROOT_LEVEL;
	return 0;
}


static int init_paging_context(struct hvm_vcpu *vcpu)
{
	ASSERT(vcpu);
	ASSERT(!VALID_PAGE(vcpu->paging_context.root_hpa));

	vcpu_printf(vcpu, "init_paging_context:%s%s%s\n",
	       is_paging() ? " paging" : "",
	       is_long_mode() ? " 64bit" : "",
	       is_pae() ? " PAE" : "");
	if (!is_paging() ) {
		return nonpaging_init_context(vcpu);
	} else if (is_long_mode()) {
		return paging64_init_context(vcpu);
	} else if (is_pae() ) {
		return paging32E_init_context(vcpu); 
	} else {
		return paging32_init_context(vcpu);
	}
}

static void destroy_paging_context(struct hvm_vcpu *vcpu)
{
	ASSERT(vcpu);
	if (VALID_PAGE(vcpu->paging_context.root_hpa)) {
		vcpu->paging_context.free(vcpu);
		vcpu->paging_context.root_hpa = INVALID_PAGE;
	}
}


int hvm_mmu_reset_context(struct hvm_vcpu *vcpu)
{
	destroy_paging_context(vcpu);
	return init_paging_context(vcpu);
}


static void free_mmu_pages(struct hvm_vcpu *vcpu)
{
	while (!list_empty(&vcpu->free_pages)) {

		   page_link_t *page_link;

		   page_link = list_entry(vcpu->free_pages.next,
					  page_link_t, link);
		   list_del(&page_link->link);
		   __free_page(pfn_to_page(page_link->page_hpa >> PAGE_SHIFT));
		   page_link->page_hpa = INVALID_PAGE;
		   list_add(&page_link->link, &vcpu->free_page_links);
	}
}


static int alloc_mmu_pages(struct hvm_vcpu *vcpu)
{
	int i;

	ASSERT(vcpu);

	for (i = 0; i < HVM_NUM_MMU_PAGES; i++) {
		struct page *page;

		page_link_t *page_link = &vcpu->page_link_buf[i];
		INIT_LIST_HEAD(&page_link->link);
		if ((page = alloc_page(GFP_KERNEL)) == NULL)
		    goto error_1;
		page_link->page_hpa = page_to_pfn(page) << PAGE_SHIFT;
		memset(__va(page_link->page_hpa), 0, PAGE_SIZE);
		list_add(&page_link->link, &vcpu->free_pages);
	}
	return 0;

error_1:
	free_mmu_pages(vcpu);
	return -ENOMEM;
}


int hvm_mmu_init(struct hvm_vcpu *vcpu)
{
	int r;

	ASSERT(vcpu);
	ASSERT(!VALID_PAGE(vcpu->paging_context.root_hpa));
	ASSERT(list_empty(&vcpu->free_pages));
	ASSERT(list_empty(&vcpu->free_page_links));

	if ((r = alloc_mmu_pages(vcpu))) {
		return r;
	}

	if ((r = init_paging_context(vcpu))) {
		free_mmu_pages(vcpu);
		return r;
	}
	return 0;
}


void hvm_mmu_destroy(struct hvm_vcpu *vcpu)
{
	ASSERT(vcpu);

	destroy_paging_context(vcpu);
	free_mmu_pages(vcpu);
}

