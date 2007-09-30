#include <linux/types.h>
#include <linux/string.h>
#include <asm/page.h>
#include <linux/module.h>

#include "vmx.h"
#include "hvm.h"


#define ASSERT(x)  							     \
	if (!(x)) { 							     \
		printk("assertion failed %s:%d: %s", __FILE__, __LINE__, #x);\
	}

#define PT64_ENT_PER_PAGE 512

#define PT64_PRESENT_MASK (1ULL << 0)
#define PT64_WRITABLE_MASK (1ULL << 1)
#define PT64_USER_MASK (1ULL << 2)
#define PT64_PAGE_SIZE_MASK (1ULL << 7)

#define PT64_ROOT_LEVEL 4
#define PT64_DIRECTORY_LEVEL 2
#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & PAGE_MASK)

#define INVALID_PAGE (~(paddr_t)0)
#define VALID_PAGE(x) ((x) != INVALID_PAGE)

#define PT64_LEVEL_BITS 9

#define PT64_LEVEL_SHIFT(level) \
		( PAGE_SHIFT + (level - 1) * PT64_LEVEL_BITS )

#define PT64_LEVEL_MASK(level) \
		(((1 << PT64_LEVEL_BITS) - 1) << PT64_LEVEL_SHIFT(level))


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
				if (level != PT64_DIRECTORY_LEVEL || 
				    (current_ent & PT64_PAGE_SIZE_MASK) == 0) {
					releas_pt_page_64(vcpu,
						       current_ent & 
						       PT64_BASE_ADDR_MASK,
						       level - 1);
				}
			}
		}
	}
	hvm_mmu_free_page(vcpu, page_addr);  
}


static void nonpaging_set_cr3(struct hvm_vcpu *vcpu)
{

}


static int nonpaging_map(struct hvm_vcpu *vcpu, vaddr_t v, paddr_t p)
{
	int level = PT64_ROOT_LEVEL;
	paddr_t table_addr = vcpu->paging_context->root;

	for (; ; level--) {
		uint32_t offset = (v & PT64_LEVEL_MASK(level)) >> 
							PT64_LEVEL_SHIFT(level);
		uint64_t *table;

		ASSERT(VALID_PAGE(table_addr));
		table = __va(table_addr);

		if (level == 1) {
			table[offset] = p | 
					PT64_PRESENT_MASK | 
					PT64_WRITABLE_MASK;
			return 0;
		}

		if (table[offset] == 0) {
			paddr_t new_table = hvm_mmu_alloc_page(vcpu);
			if (!VALID_PAGE(new_table)) {
				printk("nonpaging_map: ENOMEM\n");
				return -ENOMEM;
			}
			table[offset] = new_table | 
					PT64_PRESENT_MASK | 
					PT64_WRITABLE_MASK;
		}
		table_addr = table[offset] & PT64_BASE_ADDR_MASK;
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


static int nonpaging_pf(struct hvm_vcpu *vcpu, uint64_t addr,
			       uint32_t error_code)
{
     uint64_t page_index = (addr & ((1ULL << 48) - 1)) >> PAGE_SHIFT;

     int ret;

     ASSERT(vcpu);
     ASSERT(vcpu->paging_context);

     if (page_index >= vcpu->hvm->phys_mem_pages ) {
	     printk("nonpaging_pf: page_index >= vcpu->hvm->phys_mem_pages, %llu\n",
		     page_index);
	     // todo: map to non present page
	     return 1;
     }

     for (;;) {
	     ret = nonpaging_map(vcpu, 
		   addr & PAGE_MASK, 
		   page_to_pfn(vcpu->hvm->phys_mem[page_index]) << PAGE_SHIFT);
	     if (ret) {
		     nonpaging_flush(vcpu);
		     continue;
	     }
	     break;
     }
     return ret;

}


static void nonpaging_inval_pg(struct hvm_vcpu *vcpu)
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


static int create_paging_context(struct hvm_vcpu *vcpu)
{
	paging_context_t *context;
	ASSERT(vcpu);
	ASSERT(vcpu->paging_context == NULL);

	context = kmalloc(sizeof(paging_context_t), GFP_KERNEL);
	context->set_cr3 = nonpaging_set_cr3;
	context->pf = nonpaging_pf;
	context->inval_pg = nonpaging_inval_pg;
	context->free = nonpaging_free;
	context->root = hvm_mmu_alloc_page(vcpu);
	ASSERT(VALID_PAGE(context->root));
	vcpu->paging_context = context;
	vmcs_writel(GUEST_CR3, context->root);
	return 0;
}


static void free_paging_context(struct hvm_vcpu *vcpu)
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

