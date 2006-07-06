#ifndef __HVM_H
#define __HVM_H

#define HVM_MAX_VCPUS 4
#define HVM_NUM_MMU_PAGES 256

#include <linux/types.h>
#include <linux/list.h>

typedef uint64_t paddr_t;
typedef paddr_t gaddr_t;

typedef uint64_t vaddr_t;


typedef struct page_link_s {
	struct list_head link;
	paddr_t page_addr;
} page_link_t;


struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

struct hvm_vcpu;

typedef struct paging_context_s {
	void (*set_cr3)(struct hvm_vcpu *vcpu);
	int (*pf)(struct hvm_vcpu *vcpu, uint64_t vaddr, uint32_t err);
	void (*inval_pg)(struct hvm_vcpu *vcpu);
	void (*free)(struct hvm_vcpu *vcpu);
	paddr_t root;
}paging_context_t;

struct hvm_vcpu {
	struct hvm *hvm;
	struct vmcs *vmcs;
	int   cpu;
	int   launched;
	unsigned long regs[16]; /* for rsp needs vcpu_load_rsp_rip() */
	unsigned long rip;      /* needs vcpu_load_rsp_rip() */

	gaddr_t cr3;
	unsigned long cr0, cr2, cr4, cr8;

	struct list_head free_page_links;
	struct list_head free_pages;
	page_link_t page_link_buf[HVM_NUM_MMU_PAGES];
	paging_context_t *paging_context;
};

struct hvm {
	unsigned created : 1;
	unsigned long phys_mem_pages;
	struct page **phys_mem;
	int nvcpus;
	struct hvm_vcpu vcpus[HVM_MAX_VCPUS];
};

void hvm_mmu_destroy(struct hvm_vcpu *vcpu);
int hvm_mmu_init(struct hvm_vcpu *vcpu);
void vmcs_writel(unsigned long field, unsigned long value);

#endif
