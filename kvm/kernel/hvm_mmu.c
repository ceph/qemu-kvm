#include <linux/types.h>
#include <linux/string.h>
#include <asm/page.h>
#include <linux/mm.h>
#include <linux/module.h>

#include "vmx.h"
#include "hvm.h"


#define ASSERT(x)  							     \
	if (!(x)) { 							     \
		printk("assertion failed %s:%d: %s\n", __FILE__, __LINE__, #x);\
	}

#define PT64_ENT_PER_PAGE 512

#define PT64_PRESENT_MASK (1ULL << 0)
#define PT64_WRITABLE_MASK (1ULL << 1)
#define PT64_USER_MASK (1ULL << 2)
#define PT64_ACCESSED_MASK (1ULL << 5)
#define PT64_DIRTY_MASK (1ULL << 6)
#define PT64_PAGE_SIZE_MASK (1ULL << 7)
#define PT64_GLOBAL_MASK (1ULL << 8)

#define PT64_PAT_SHIFT 7
#define PT64_DIR_PAT_SHIFT 12
#define PT64_DIR_PAT_MASK (1ULL << PT64_DIR_PAT_SHIFT)

#define PT64_ROOT_LEVEL 4
#define PT64_DIRECTORY_LEVEL 2
#define PT64_PAGE_TABLE_LEVEL 1

#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & PAGE_MASK)
#define PT64_DIR_BASE_ADDR_MASK (PT64_BASE_ADDR_MASK & ~PT64_DIR_PAT_MASK)

#define PT64_PTE_COPY_MASK ((1ULL << 8) - 1)
#define PT64_NON_PTE_COPY_MASK ((1ULL << 7) - 1)

#define PT64_FIRST_AVILE_BIT 9
#define PT64_SHADOW_PS_MARK (1 << PT64_FIRST_AVILE_BIT)

#define INVALID_PAGE (~(paddr_t)0)
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


#define P_TO_V(address)\
	page_address(pfn_to_page((address) >> PAGE_SHIFT))


#define CR0_PG_MASK (1 << 31)
#define CR4_PAE_MASK (1 << 5)

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
	return page_addr;
}

static paddr_t gaddr_to_paddr(struct hvm_vcpu *vcpu, gaddr_t addr)
{
	uint64_t page_index = (addr & ((1ULL << 48) - 1)) >> PAGE_SHIFT;
	struct page *page;
	
	ASSERT(vcpu);

	if (page_index >= vcpu->hvm->phys_mem_pages) {
		extern struct page *hvm_bad_page;

		printk("gaddr_to_paddr: bad page index,"
		       " phys_mem_pages %lu address %llu\n",
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
	paddr_t table_addr = vcpu->paging_context->root;

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
				printk("nonpaging_map: ENOMEM\n");
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
	paddr_t root = vcpu->paging_context->root;

	printk("nonpaging_flush\n");
	ASSERT(VALID_PAGE(root));
	releas_pt_page_64(vcpu, root, PT64_ROOT_LEVEL);
	root = hvm_mmu_alloc_page(vcpu);
	ASSERT(VALID_PAGE(root));
	vcpu->paging_context->root = root;
	vmcs_writel(GUEST_CR3, root);
}

static int nonpaging_page_fault(struct hvm_vcpu *vcpu, uint64_t addr,
			       uint32_t error_code)
{
     int ret;

     ASSERT(vcpu);
     ASSERT(vcpu->paging_context);

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
	ASSERT(vcpu->paging_context);
	
	root = vcpu->paging_context->root;
	if (VALID_PAGE(root)) {
		releas_pt_page_64(vcpu, root, PT64_ROOT_LEVEL);
	}
	kfree(vcpu->paging_context);
	vcpu->paging_context = NULL;
}


static int create_nonpaging_context(struct hvm_vcpu *vcpu)
{
	paging_context_t *context;

	context = kmalloc(sizeof(paging_context_t), GFP_KERNEL);

	if (!context) {
		return -ENOMEM;
	}

	context->new_cr3 = nonpaging_new_cr3;
	context->page_fault = nonpaging_page_fault;
	context->inval_page = nonpaging_inval_page;
	context->free = nonpaging_free;
	context->root_level = PT64_ROOT_LEVEL;
	context->root = hvm_mmu_alloc_page(vcpu);
	ASSERT(VALID_PAGE(context->root));
	vcpu->paging_context = context;
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


static uint64_t *fetch64(struct hvm_vcpu *vcpu, uint64_t addr)
{
	paddr_t  shadow_addr = vcpu->paging_context->root;
	int level = vcpu->paging_context->root_level;

	for (; ; level--) {
		uint64_t *table = __va(shadow_addr);
		int index = PT64_INDEX(addr, level);

		if (level == PT64_PAGE_TABLE_LEVEL) {
			return &table[index];
		}

		if (!(table[index] & PT64_PRESENT_MASK)) {
		     return NULL;   
		}
		shadow_addr = table[index] & PT64_BASE_ADDR_MASK;
	}
}


static uint64_t *fetch_guest64(struct hvm_vcpu *vcpu, uint64_t addr)
{
	paddr_t  guest_addr = gaddr_to_paddr(vcpu, vcpu->cr3);
	int level = vcpu->paging_context->root_level;

	for (; ; level--) {
		uint64_t *table = P_TO_V(guest_addr);
		int index = PT64_INDEX(addr, level);

		if (level == PT64_PAGE_TABLE_LEVEL) {
			return &table[index];
		}

		if (!is_present_pte64(table[index])) {
		     return NULL;   
		}

		if (level == PT64_DIRECTORY_LEVEL && 
				 (table[index] & PT64_PAGE_SIZE_MASK)) {
			return &table[index];
		}

		guest_addr = gaddr_to_paddr(vcpu, table[index] & PT64_BASE_ADDR_MASK);
	}
}


static inline int paging64_handle_present_pf(struct hvm_vcpu *vcpu, 
					     uint64_t addr,
					     int write_fault)
{
	uint64_t *shadow_ent;
	uint64_t *guest_ent;

	
	ASSERT(fetch64(vcpu, addr) && is_present_pte64(*fetch64(vcpu, addr)));

	if (!write_fault) {
		return 1;
	}

	shadow_ent = fetch64(vcpu, addr);
       
        if (is_writeble_pte64(*shadow_ent)) {
		return 1;
	}

	guest_ent = fetch_guest64(vcpu, addr);
	if (!guest_ent || !is_present_pte64(*guest_ent)) {
		*shadow_ent = 0;
		return 1;
	}

	if (!is_writeble_pte64(*guest_ent)) {
		return 1;
	}

	*shadow_ent |= PT64_WRITABLE_MASK;
	*guest_ent |= PT64_DIRTY_MASK; 

	return 0;
}


static inline void set_pte64(struct hvm_vcpu *vcpu,
			     uint64_t *guest_pte,
			     uint64_t *shadow_pte,
			     int write_fault)
{
	ASSERT(*shadow_pte == 0);

	*shadow_pte = gaddr_to_paddr(vcpu, *guest_pte & PT64_BASE_ADDR_MASK);
	*shadow_pte |= *guest_pte & PT64_PTE_COPY_MASK;

	if (!is_dirty_pte64(*guest_pte)) {
		if (write_fault) {
			*guest_pte |= PT64_DIRTY_MASK;
		} else {
			*shadow_pte &= ~PT64_WRITABLE_MASK;
		}
	}
}

static inline void set_pde64(struct hvm_vcpu *vcpu,
			     uint64_t *guest_pde,
			     paddr_t pt_address,
			     uint32_t index,
			     int write_fault)
{
	uint64_t *page_table = __va(pt_address);

	ASSERT(page_table[index] == 0);

	page_table[index] = gaddr_to_paddr(vcpu, 
		(*guest_pde & PT64_DIR_BASE_ADDR_MASK) + PAGE_SIZE * index);

	page_table[index] |= (*guest_pde & PT64_NON_PTE_COPY_MASK) | 
				((*guest_pde & PT64_DIR_PAT_MASK) >> 
				 (PT64_DIR_PAT_SHIFT - PT64_PAT_SHIFT));

	if (!is_dirty_pte64(*guest_pde)) {
		if (write_fault) {
			*guest_pde |= PT64_DIRTY_MASK;
		} else {
			page_table[index] &= ~PT64_WRITABLE_MASK;
		}
	}
}

static void inject_page_fault(struct hvm_vcpu *vcpu, 
			      uint64_t addr, 
			      uint32_t err_code)
{
	#define PF_VECTOR 14 

	vcpu->cr2 = addr; 
	vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, err_code);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		     PF_VECTOR |
		     INTR_TYPE_EXCEPTION |
		     INTR_INFO_DELIEVER_CODE_MASK |
		     INTR_INFO_VALID_MASK);
	
}



static int paging64_page_fault(struct hvm_vcpu *vcpu, uint64_t addr,
			       uint32_t error_code)
{
	int write_fault = error_code & PFERR_WRITE_MASK;
	paddr_t guest_addr;
	paddr_t shadow_addr;
	int level;

	if (error_code & PFERR_PRESENT_MASK) {
		int inject;

		inject = paging64_handle_present_pf(vcpu, addr, write_fault);
		if (inject) {
			inject_page_fault(vcpu, addr, error_code);
		}
		return 0;
	}

	guest_addr = gaddr_to_paddr(vcpu, vcpu->cr3);
	shadow_addr = vcpu->paging_context->root;
	level = vcpu->paging_context->root_level;

	for (; ; level--) {
		uint32_t index = PT64_INDEX(addr,level);
		uint64_t *guest_table;
		uint64_t *shadow_table;

		guest_table = P_TO_V(guest_addr);

		if (!(guest_table[index] & PT64_PRESENT_MASK)) {
			inject_page_fault(vcpu, addr, error_code);
			return 0;
		}
		guest_table[index] |= PT64_ACCESSED_MASK;

		shadow_table = __va(shadow_addr);

		if (level == PT64_PAGE_TABLE_LEVEL) {
			set_pte64(vcpu,
				  &guest_table[index], 
				  &shadow_table[index], 
				  write_fault);
			return 0;
		}

		if (!(shadow_table[index] & PT64_PRESENT_MASK)) {
			shadow_addr = hvm_mmu_alloc_page(vcpu);
			if (!VALID_PAGE(shadow_addr)) {
				nonpaging_flush(vcpu);
				return paging64_page_fault(vcpu, addr, 
							    error_code);
			}
			shadow_table[index] = shadow_addr | 
				(guest_table[index] & PT64_NON_PTE_COPY_MASK);

		} else {
		     shadow_addr = shadow_table[index] & PT64_BASE_ADDR_MASK;   
		}

		if (level == PT64_DIRECTORY_LEVEL && 
				 (guest_table[index] & PT64_PAGE_SIZE_MASK)) {
			shadow_table[index] |= PT64_SHADOW_PS_MARK;
			set_pde64(vcpu,
				  &guest_table[index], 
				  shadow_addr,
				  PT64_INDEX(addr, PT64_PAGE_TABLE_LEVEL),
				  write_fault);
			return 0;
		}

		guest_addr = 
			gaddr_to_paddr(vcpu,
				       guest_table[index] & PT64_BASE_ADDR_MASK);
	}
}


static void paging64_inval_page(struct hvm_vcpu *vcpu, uint64_t addr)
{
	paddr_t page_addr = vcpu->paging_context->root;
	int level = vcpu->paging_context->root_level;

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


static int create_paging64_context(struct hvm_vcpu *vcpu)
{
	paging_context_t *context;

	ASSERT(is_pae(vcpu));

	context = kmalloc(sizeof(paging_context_t), GFP_KERNEL);

	if (!context) {
		return -ENOMEM;
	}

	context->new_cr3 = paging64_new_cr3;
	context->page_fault = paging64_page_fault;
	context->inval_page = paging64_inval_page;
	context->free = paging64_free;
	context->root_level = PT64_ROOT_LEVEL;
	context->root = hvm_mmu_alloc_page(vcpu);
	ASSERT(VALID_PAGE(context->root));
	vcpu->paging_context = context;
	vmcs_writel(GUEST_CR3, context->root);
	return 0;
}


static int create_paging32_context(struct hvm_vcpu *vcpu)
{
	return -1;
}


static int create_paging32E_context(struct hvm_vcpu *vcpu)
{
	return -1;
}


int create_paging_context(struct hvm_vcpu *vcpu)
{
	ASSERT(vcpu);
	ASSERT(vcpu->paging_context == NULL);

	printk("create_paging_context: %s %s %s\n",
	       is_paging(vcpu) ? "paging" : "",
	       is_64bit(vcpu) ? "64bit" : "",
	       is_pae(vcpu) ? "PAE" : "");
	if (!is_paging(vcpu) ) {
		return create_nonpaging_context(vcpu);
	} else if (is_64bit(vcpu)) {
		return create_paging64_context(vcpu);
	} else if (is_pae(vcpu) ) {
		return create_paging32E_context(vcpu); 
	} else {
		return create_paging32_context(vcpu);
	}
}


void free_paging_context(struct hvm_vcpu *vcpu)
{
	ASSERT(vcpu);
	if (vcpu->paging_context) {
		vcpu->paging_context->free(vcpu);
		vcpu->paging_context = NULL;
	}
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
	vcpu->cr3 = 0;
	vcpu->paging_context = NULL;

	ASSERT(list_empty(&vcpu->free_pages));
	ASSERT(list_empty(&vcpu->free_page_links));

	if ((r = alloc_mmu_pages(vcpu))) {
		return r;
	}

	if ((r = create_paging_context(vcpu))) {
		free_mmu_pages(vcpu);
		return r;
	}
	return 0;
}


void hvm_mmu_destroy(struct hvm_vcpu *vcpu)
{
	ASSERT(vcpu);

	free_paging_context(vcpu);
	free_mmu_pages(vcpu);
}

