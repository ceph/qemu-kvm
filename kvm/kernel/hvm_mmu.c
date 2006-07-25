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
		pgprintk("assertion failed %s:%d: %s\n", __FILE__, __LINE__, #x);\
	}

#define FALSE 0
#define TRUE 1

#define PT64_ENT_PER_PAGE 512

#define PT64_WRITABLE_SHIFT 1

#define PT64_PRESENT_MASK (1ULL << 0)
#define PT64_WRITABLE_MASK (1ULL << PT64_WRITABLE_SHIFT)
#define PT64_USER_MASK (1ULL << 2)
#define PT64_PWT_MASK (1ULL << 3)
#define PT64_PCD_MASK (1ULL << 4)
#define PT64_ACCESSED_MASK (1ULL << 5)
#define PT64_DIRTY_MASK (1ULL << 6)
#define PT64_PAGE_SIZE_MASK (1ULL << 7)
#define PT64_PAT_MASK (1ULL << 7)
#define PT64_GLOBAL_MASK (1ULL << 8)
#define PT64_NX_MASK (1ULL << 63)

#define PT64_PAT_SHIFT 7
#define PT64_DIR_PAT_SHIFT 12
#define PT64_DIR_PAT_MASK (1ULL << PT64_DIR_PAT_SHIFT)

#define PT64_ROOT_LEVEL 4
#define PT64_DIRECTORY_LEVEL 2
#define PT64_PAGE_TABLE_LEVEL 1

#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & PAGE_MASK)
#define PT64_DIR_BASE_ADDR_MASK (PT64_BASE_ADDR_MASK & ~PT64_DIR_PAT_MASK)

#define PT64_PTE_COPY_MASK \
	(PT64_PRESENT_MASK | PT64_PWT_MASK | PT64_PCD_MASK | \
	PT64_ACCESSED_MASK | PT64_DIRTY_MASK | PT64_PAT_MASK | \
	PT64_GLOBAL_MASK | PT64_NX_MASK)

#define PT64_NON_PTE_COPY_MASK \
	(PT64_PRESENT_MASK | PT64_PWT_MASK | PT64_PCD_MASK | \
	PT64_ACCESSED_MASK | PT64_DIRTY_MASK | PT64_NX_MASK)

#define PT64_FIRST_AVILE_BITS_SHIFT 9
#define PT64_SECOND_AVILE_BITS_SHIFT 52

#define PT64_SHADOW_PS_MARK (1ULL << PT64_FIRST_AVILE_BITS_SHIFT)
#define PT64_SHADOW_IO_MARK (1ULL << PT64_FIRST_AVILE_BITS_SHIFT)

#define PT64_SHADOW_WRITABLE_SHIFT (PT64_FIRST_AVILE_BITS_SHIFT + 1)
#define PT64_SHADOW_WRITABLE_MASK (1ULL << PT64_SHADOW_WRITABLE_SHIFT)

#define PT64_SHADOW_USER_SHIFT (PT64_SHADOW_WRITABLE_SHIFT + 1)
#define PT64_SHADOW_USER_MASK (1ULL << (PT64_SHADOW_USER_SHIFT))

#define PT64_SHADOW_BITS_OFFSET (PT64_SHADOW_WRITABLE_SHIFT - PT64_WRITABLE_SHIFT)

#define VALID_PAGE(x) ((x) != INVALID_PAGE)

#define PT64_LEVEL_BITS 9

#define PT64_LEVEL_SHIFT(level) \
		( PAGE_SHIFT + (level - 1) * PT64_LEVEL_BITS )

#define PT64_LEVEL_MASK(level) \
		(((1 << PT64_LEVEL_BITS) - 1) << PT64_LEVEL_SHIFT(level))

#define PT64_INDEX(address, level)\
	(((address) >> PT64_LEVEL_SHIFT(level)) & ((1 << PT64_LEVEL_BITS) - 1))


#define PFERR_PRESENT_MASK (1 << 0)
#define PFERR_WRITE_MASK (1 << 1)
#define PFERR_USER_MASK (1 << 2)

#define P_TO_V(address)\
	page_address(pfn_to_page((address) >> PAGE_SHIFT))


#define CR0_PG_MASK (1 << 31)
#define CR0_WP_MASK (1 << 16)
#define CR4_PAE_MASK (1 << 5)
#define CR4_PGE_MASK (1 << 7)

#define VM_ENTRY_CONTROLS_IA32E_MASK (1 << 9)

static int is_paging(struct hvm_vcpu *vcpu)
{
	return vcpu->cr0 & CR0_PG_MASK;
}


static int is_64bit(struct hvm_vcpu *vcpu)
{
	return vmcs_read32(VM_ENTRY_CONTROLS) & VM_ENTRY_CONTROLS_IA32E_MASK;
}


static int is_pae(struct hvm_vcpu *vcpu)
{
	return vcpu->cr4 & CR4_PAE_MASK;
}


static int is_write_protection(struct hvm_vcpu *vcpu)
{
	return vcpu->cr0 & CR0_WP_MASK;
}


static void hvm_mmu_free_page(struct hvm_vcpu *vcpu, paddr_t page_addr)
{
	page_link_t *page_link;

	ASSERT(!list_empty(&vcpu->free_page_links));
	page_link = list_entry(vcpu->free_page_links.next,
				     page_link_t, 
				     link);
	list_del(&page_link->link);
	page_link->page_addr = page_addr;
	list_add(&page_link->link, &vcpu->free_pages);
}


static int is_empty_shadow_page(paddr_t page_addr)
{
	uint32_t *pos;
	uint32_t *end; 
	for (pos = __va(page_addr), end = pos + PAGE_SIZE / sizeof(uint32_t);
		      pos != end; pos++) {
		if (*pos != 0) {
			return FALSE;
		}
	}
	return TRUE;
}


static paddr_t hvm_mmu_alloc_page(struct hvm_vcpu *vcpu)
{
	paddr_t page_addr;
	page_link_t *page_link;

	if (list_empty(&vcpu->free_pages)) {
		return INVALID_PAGE; 
	}
	
	page_link = list_entry(vcpu->free_pages.next,
				     page_link_t, 
				     link);
	list_del(&page_link->link);
	page_addr = page_link->page_addr;
	page_link->page_addr = INVALID_PAGE;
	list_add(&page_link->link, &vcpu->free_page_links);
	ASSERT(is_empty_shadow_page(page_addr));
	return page_addr;
}


static paddr_t gaddr_to_paddr(struct hvm_vcpu *vcpu, gaddr_t addr)
{
	uint64_t page_index = (addr & ((1ULL << 48) - 1)) >> PAGE_SHIFT;
	struct page *page;
	
	ASSERT(vcpu);

	if (page_index >= vcpu->hvm->phys_mem_pages) {
		extern struct page *hvm_bad_page;

		pgprintk("gaddr_to_paddr: bad page index,"
		       " phys_mem_pages %lu gaddr 0x%llx\n",
			vcpu->hvm->phys_mem_pages, addr);
		page = hvm_bad_page;
	} else {
		page = vcpu->hvm->phys_mem[page_index];
	}
	return page_to_pfn(page) << PAGE_SHIFT;
}


static void releas_pt_page_64(struct hvm_vcpu *vcpu, paddr_t page_addr,int level)
{
	ASSERT(vcpu);
	ASSERT(VALID_PAGE(page_addr));
	ASSERT(level <= PT64_ROOT_LEVEL && level > 0);

	if (level == 1) {
		memset(__va(page_addr), 0, PAGE_SIZE);
	} else {
		uint64_t *pos;
		uint64_t *end;

		for (pos = __va(page_addr), end = pos + PT64_ENT_PER_PAGE;
		      pos != end; pos++) {
			uint64_t current_ent = *pos;
			*pos = 0;
			if (current_ent & PT64_PRESENT_MASK) {
				releas_pt_page_64(vcpu,
						  current_ent & 
						  PT64_BASE_ADDR_MASK,
						  level - 1);
			}
		}
	}
	hvm_mmu_free_page(vcpu, page_addr);  
}


static void nonpaging_new_cr3(struct hvm_vcpu *vcpu)
{    
}


static int nonpaging_map(struct hvm_vcpu *vcpu, vaddr_t v, paddr_t p)
{
	int level = PT64_ROOT_LEVEL;
	paddr_t table_addr = vcpu->paging_context.root;

	for (; ; level--) {
		uint32_t index = PT64_INDEX(v, level);
		uint64_t *table;

		ASSERT(VALID_PAGE(table_addr));
		table = __va(table_addr);

		if (level == 1) {
			table[index] = p | 
					PT64_PRESENT_MASK | 
					PT64_WRITABLE_MASK;
			return 0;
		}

		if (table[index] == 0) {
			paddr_t new_table = hvm_mmu_alloc_page(vcpu);
			if (!VALID_PAGE(new_table)) {
				pgprintk("nonpaging_map: ENOMEM\n");
				return -ENOMEM;
			}
			table[index] = new_table | 
					PT64_PRESENT_MASK | 
					PT64_WRITABLE_MASK;
		}
		table_addr = table[index] & PT64_BASE_ADDR_MASK;
	}
}


static void nonpaging_flush(struct hvm_vcpu *vcpu)
{
	paddr_t root = vcpu->paging_context.root;

	pgprintk("nonpaging_flush\n");
	ASSERT(VALID_PAGE(root));
	releas_pt_page_64(vcpu, root, PT64_ROOT_LEVEL);
	root = hvm_mmu_alloc_page(vcpu);
	ASSERT(VALID_PAGE(root));
	vcpu->paging_context.root = root;
	vmcs_writel(GUEST_CR3, root);
}

static int nonpaging_page_fault(struct hvm_vcpu *vcpu, uint64_t addr,
			       uint32_t error_code)
{
     int ret;

     ASSERT(vcpu);
     ASSERT(VALID_PAGE(vcpu->paging_context.root));

     for (;;) {
	     ret = nonpaging_map(vcpu, 
		   addr & PAGE_MASK, gaddr_to_paddr(vcpu, addr));
	     if (ret) {
		     nonpaging_flush(vcpu);
		     continue;
	     }
	     break;
     }
     return ret;
}


static void nonpaging_inval_page(struct hvm_vcpu *vcpu, uint64_t addr)
{
	
}


static void nonpaging_free(struct hvm_vcpu *vcpu)
{
	paddr_t root;

	ASSERT(vcpu);
	root = vcpu->paging_context.root;
	if (VALID_PAGE(root)) {
		releas_pt_page_64(vcpu, root, PT64_ROOT_LEVEL);
	}
	vcpu->paging_context.root = INVALID_PAGE;
}


static int nonpaging_init_context(struct hvm_vcpu *vcpu)
{
	paging_context_t *context = &vcpu->paging_context;

	context->new_cr3 = nonpaging_new_cr3;
	context->page_fault = nonpaging_page_fault;
	context->inval_page = nonpaging_inval_page;
	context->free = nonpaging_free;
	context->root_level = PT64_ROOT_LEVEL;
	context->root = hvm_mmu_alloc_page(vcpu);
	ASSERT(VALID_PAGE(context->root));
	vmcs_writel(GUEST_CR3, context->root);
	return 0;
}


static void paging64_new_cr3(struct hvm_vcpu *vcpu)
{
    nonpaging_flush(vcpu);
}



static inline int is_present_pte64(uint64_t pte)
{
	return pte & PT64_PRESENT_MASK;
}

static inline int is_writeble_pte64(uint64_t pte)
{
	return pte & PT64_WRITABLE_MASK;
}

static inline int is_dirty_pte64(uint64_t pte)
{
	return pte & PT64_DIRTY_MASK;
}

static inline int is_io_pte64(uint64_t pte)
{
	return pte & PT64_SHADOW_IO_MARK;
}


static inline void set_pte_common64(struct hvm_vcpu *vcpu,
			     uint64_t *shadow_pte,
			     gaddr_t gaddr,
			     uint64_t access_bits)
{
	paddr_t paddr;

	*shadow_pte |= access_bits << PT64_SHADOW_BITS_OFFSET;
	*shadow_pte |= access_bits & ~PT64_WRITABLE_MASK;

	paddr = gaddr_to_paddr(vcpu, gaddr);

	if (paddr == hvm_bad_page_addr) {
		*shadow_pte |= gaddr;
		*shadow_pte |= PT64_SHADOW_IO_MARK;
		*shadow_pte &= ~PT64_PRESENT_MASK;
	} else {
		*shadow_pte |= paddr;
	}
}


static inline void set_pte64(struct hvm_vcpu *vcpu,
			     uint64_t guest_pte,
			     uint64_t *shadow_pte,
			     uint64_t access_bits)
{
	ASSERT(*shadow_pte == 0);
	access_bits &= guest_pte;
	*shadow_pte = (guest_pte & PT64_PTE_COPY_MASK);
	set_pte_common64(vcpu, shadow_pte, guest_pte & PT64_BASE_ADDR_MASK,
			 access_bits);
}


static inline void set_pde64(struct hvm_vcpu *vcpu,
			     uint64_t guest_pde,
			     uint64_t *shadow_pte,
			     uint64_t access_bits,
			     int index)
{
	gaddr_t gaddr;
       
	ASSERT(*shadow_pte == 0);
	access_bits &= guest_pde;
	gaddr = (guest_pde & PT64_DIR_BASE_ADDR_MASK) + PAGE_SIZE * index;
	*shadow_pte = (guest_pde & PT64_NON_PTE_COPY_MASK) |
				((guest_pde & PT64_DIR_PAT_MASK) >> 
				 (PT64_DIR_PAT_SHIFT - PT64_PAT_SHIFT));
	set_pte_common64(vcpu, shadow_pte, gaddr, access_bits);
}


static void inject_page_fault(struct hvm_vcpu *vcpu, 
			      uint64_t addr, 
			      uint32_t err_code)
{
	#define PF_VECTOR 14 

	pgprintk("inject_page_fault: 0x%llx err 0x%x\n", addr, err_code);
	vcpu->regs[VCPU_REGS_CR2] = addr; 
	vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, err_code);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		     PF_VECTOR |
		     INTR_TYPE_EXCEPTION |
		     INTR_INFO_DELIEVER_CODE_MASK |
		     INTR_INFO_VALID_MASK);
	
}


typedef struct guets_walker_s {	
	int level;
	uint64_t *table;
} guets_walker_t;


static uint64_t *fetch_guest64(struct hvm_vcpu *vcpu,
			       guets_walker_t *walker, 
			       int level,
			       uint64_t addr)
{

	ASSERT(level > 0  && level <= walker->level);

	for (;;) {
		int index = PT64_INDEX(addr, walker->level);
		paddr_t paddr;

		if (level == walker->level || 
		    !is_present_pte64(walker->table[index]) || 
		    (walker->level == PT64_DIRECTORY_LEVEL && 
		    (walker->table[index] & PT64_PAGE_SIZE_MASK))) {
			return &walker->table[index];
		}

		paddr = gaddr_to_paddr(vcpu, walker->table[index] & 
				       PT64_BASE_ADDR_MASK);
		kunmap_atomic(walker->table, KM_USER0);
		walker->table = kmap_atomic(pfn_to_page(paddr >> PAGE_SHIFT),
					    KM_USER0);
		--walker->level;
	} 
}


static uint64_t *fetch64(struct hvm_vcpu *vcpu,
			 uint64_t addr,
			 guets_walker_t *walker,
			 int *enomem)
{
	paddr_t shadow_addr;
	int level;

	uint64_t access_bits = PT64_USER_MASK | PT64_WRITABLE_MASK;

	shadow_addr = vcpu->paging_context.root;
	level = vcpu->paging_context.root_level;

	for (; ; level--) {
		uint32_t index = PT64_INDEX(addr, level);
		uint64_t *shadow_ent = ((uint64_t *)__va(shadow_addr)) + index;
		uint64_t *gues_ent;

		if (is_present_pte64(*shadow_ent) || is_io_pte64(*shadow_ent)) {
			if (level == PT64_PAGE_TABLE_LEVEL) {
				return shadow_ent;
			}
			access_bits &= *shadow_ent >> PT64_SHADOW_BITS_OFFSET;
			shadow_addr = *shadow_ent & PT64_BASE_ADDR_MASK;
			continue;
		}

		gues_ent = fetch_guest64(vcpu, walker, level, addr);

		if (!is_present_pte64(*gues_ent)) {
			*enomem = 0;
			return NULL;
		}

		*gues_ent |= PT64_ACCESSED_MASK;

		if (level == PT64_PAGE_TABLE_LEVEL) {

			if (walker->level == PT64_DIRECTORY_LEVEL) {
				*gues_ent |= PT64_SHADOW_PS_MARK;
				set_pde64(vcpu, *gues_ent, shadow_ent, access_bits,
					  PT64_INDEX(addr, PT64_PAGE_TABLE_LEVEL));
			} else {
				ASSERT(walker->level == PT64_PAGE_TABLE_LEVEL);
				set_pte64(vcpu, *gues_ent, shadow_ent, access_bits);
			}
			return shadow_ent;
		}

		shadow_addr = hvm_mmu_alloc_page(vcpu);
		if (!VALID_PAGE(shadow_addr)) {
			*enomem = 1;
			return NULL;
		}
		*shadow_ent = shadow_addr | 
				(*gues_ent & PT64_NON_PTE_COPY_MASK);
		*shadow_ent |= ( PT64_WRITABLE_MASK | PT64_USER_MASK);

		access_bits &= *gues_ent;
		*shadow_ent |= access_bits << PT64_SHADOW_BITS_OFFSET;
	}
}


static inline int fix_read_pf64(uint64_t *shadow_ent)
{
	if ((*shadow_ent & PT64_SHADOW_USER_MASK) && 
	    !(*shadow_ent & PT64_USER_MASK)) {
		*shadow_ent |= PT64_USER_MASK;
		*shadow_ent &= ~PT64_WRITABLE_MASK;

		return 1;
		
	}
	return 0;
}


static inline int fix_write_pf64(struct hvm_vcpu *vcpu,
				 uint64_t *shadow_ent,
				 guets_walker_t *walker,
				 uint64_t addr,
				 int user)
{
	uint64_t *guest_ent;
	int writable_shadow;

	if (is_writeble_pte64(*shadow_ent)) {
		return 0;
	}
	writable_shadow = *shadow_ent & PT64_SHADOW_WRITABLE_MASK; 
	if (user) {
		if (!(*shadow_ent & PT64_SHADOW_USER_MASK) || !writable_shadow) {
			return 0;
		}
		ASSERT(*shadow_ent & PT64_USER_MASK);
	} else {
		if (!writable_shadow) {
			if (is_write_protection(vcpu)) {
				return 0;
			}
			*shadow_ent &= ~PT64_USER_MASK;
		}
	}

	guest_ent = fetch_guest64(vcpu, walker, PT64_PAGE_TABLE_LEVEL, addr);

	if (!is_present_pte64(*guest_ent)) {
		*shadow_ent = 0;
		return 0;
	}

	*shadow_ent |= PT64_WRITABLE_MASK;
	*guest_ent |= PT64_DIRTY_MASK;

	return 1;
}


static inline void realase_walker(guets_walker_t *walker)
{
	kunmap_atomic(walker->table, KM_USER0);
}

static int access_test(uint64_t pte, int write, int user)
{
	
	if (user && !(pte & PT64_USER_MASK)) {
		return 0;
	}

	if (write && !(pte & PT64_WRITABLE_MASK)) {
		return 0;
	}

	return 1;
}


static int paging64_page_fault(struct hvm_vcpu *vcpu, uint64_t addr,
			       uint32_t error_code)
{
	int write_fault = error_code & PFERR_WRITE_MASK;
	int pte_present = error_code & PFERR_PRESENT_MASK;
	int user_fault = error_code & PFERR_USER_MASK;
	guets_walker_t walker;
	uint64_t *shadow_pte;
	int fixed;

	for (;;) {
		int enomem;

		walker.level = vcpu->paging_context.root_level;
		walker.table = kmap_atomic(
			pfn_to_page(gaddr_to_paddr(vcpu, vcpu->cr3) >> PAGE_SHIFT),
					   KM_USER0);
		shadow_pte = fetch64(vcpu, addr, &walker, &enomem);
		if (!shadow_pte && enomem) {
			nonpaging_flush(vcpu);
			realase_walker(&walker);
			continue;
		}
		break;
	}

	pgprintk("paging64_page_fault: 0x%llx pc 0x%lx error_code 0x%x\n",
	       addr, vmcs_readl(GUEST_RIP), error_code);
	if (!shadow_pte) {
		inject_page_fault(vcpu, addr, error_code);
		realase_walker(&walker);
		return 0;
	}

	if (write_fault) {
		fixed = fix_write_pf64(vcpu, shadow_pte, &walker, addr,
				       user_fault);
	} else {
		fixed = fix_read_pf64(shadow_pte);
	}

	realase_walker(&walker);

	if (is_io_pte64(*shadow_pte)) {
		if (access_test(*shadow_pte, write_fault, user_fault)) {
			paddr_t io_addr = *shadow_pte & PT64_BASE_ADDR_MASK;
			pgprintk("paging64_page_fault: io work"
			       " v 0x%llx p 0x%llx\n", addr, io_addr); 
			return 1;
		      
		}
		pgprintk("paging64_page_fault: io work, no access\n");
		inject_page_fault(vcpu, addr,
					error_code | PFERR_PRESENT_MASK);
		return 0;
	}

	if (pte_present && !fixed) {
		inject_page_fault(vcpu, addr, error_code);     
	}
	return 0;	
}


static void paging64_inval_page(struct hvm_vcpu *vcpu, uint64_t addr)
{
	paddr_t page_addr = vcpu->paging_context.root;
	int level = vcpu->paging_context.root_level;

	pgprintk("paging64_inval_page: 0x%llx pc 0x%lx\n",
	       addr, vmcs_readl(GUEST_RIP));

	for (; ; level--) {
		uint32_t index = PT64_INDEX(addr, level);
		uint64_t *table = __va(page_addr);

		if (!(table[index] & PT64_PRESENT_MASK)) {
			return;
		}

		if (level == 1 ) {
			table[index] = 0;
			return;
		}

		if (level == PT64_DIRECTORY_LEVEL && 
			  (table[index] & PT64_SHADOW_PS_MARK)) {
			paddr_t page_addr = table[index] & PT64_BASE_ADDR_MASK;
			table[index] = 0;
			releas_pt_page_64(vcpu, page_addr, PT64_PAGE_TABLE_LEVEL);
			return;
		}

		page_addr = table[index] & PT64_BASE_ADDR_MASK;
	}
}


static void paging64_free(struct hvm_vcpu *vcpu)
{
	nonpaging_free(vcpu);
} 


static int paging64_init_context(struct hvm_vcpu *vcpu)
{
	paging_context_t *context = &vcpu->paging_context;

	ASSERT(is_pae(vcpu));
	context->new_cr3 = paging64_new_cr3;
	context->page_fault = paging64_page_fault;
	context->inval_page = paging64_inval_page;
	context->free = paging64_free;
	context->root_level = PT64_ROOT_LEVEL;
	context->root = hvm_mmu_alloc_page(vcpu);
	ASSERT(VALID_PAGE(context->root));
	vmcs_writel(GUEST_CR3, context->root);
	return 0;
}


static int paging32_init_context(struct hvm_vcpu *vcpu)
{
	return -1;
}


static int paging32E_init_context(struct hvm_vcpu *vcpu)
{
	return -1;
}


static int init_paging_context(struct hvm_vcpu *vcpu)
{
	ASSERT(vcpu);
	ASSERT(!VALID_PAGE(vcpu->paging_context.root));

	pgprintk("init_paging_context: %s %s %s\n",
	       is_paging(vcpu) ? "paging" : "",
	       is_64bit(vcpu) ? "64bit" : "",
	       is_pae(vcpu) ? "PAE" : "");
	if (!is_paging(vcpu) ) {
		return nonpaging_init_context(vcpu);
	} else if (is_64bit(vcpu)) {
		return paging64_init_context(vcpu);
	} else if (is_pae(vcpu) ) {
		return paging32E_init_context(vcpu); 
	} else {
		return paging32_init_context(vcpu);
	}
}

static void destroy_paging_context(struct hvm_vcpu *vcpu)
{
	ASSERT(vcpu);
	if (VALID_PAGE(vcpu->paging_context.root)) {
		vcpu->paging_context.free(vcpu);
		vcpu->paging_context.root = INVALID_PAGE;
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
		   __free_page(pfn_to_page(page_link->page_addr >> PAGE_SHIFT));
		   page_link->page_addr = INVALID_PAGE;
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
		page_link->page_addr = page_to_pfn(page) << PAGE_SHIFT;
		memset(__va(page_link->page_addr), 0, PAGE_SIZE);
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
	ASSERT(!VALID_PAGE(vcpu->paging_context.root));
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

