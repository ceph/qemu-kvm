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

struct vmx_msr_entry {
	u32 index;
	u32 reserved;
	u64 data;
};

struct hvm_vcpu;

typedef struct paging_context_s {
	void (*new_cr3)(struct hvm_vcpu *vcpu);
	int (*page_fault)(struct hvm_vcpu *vcpu, uint64_t vaddr, uint32_t err);
	void (*inval_page)(struct hvm_vcpu *vcpu, uint64_t addr);
	void (*free)(struct hvm_vcpu *vcpu);
	paddr_t root;
	int root_level;
}paging_context_t;

struct hvm_guest_debug {
	int enabled;
	unsigned long bp[4];
	int singlestep;
};

enum {
	VCPU_REGS_RAX = 0,
	VCPU_REGS_RCX = 1,
	VCPU_REGS_RDX = 2,
	VCPU_REGS_RBX = 3,
	VCPU_REGS_RSP = 4,
	VCPU_REGS_RBP = 5,
	VCPU_REGS_RSI = 6,
	VCPU_REGS_RDI = 7,
	VCPU_REGS_R8 = 8,
	VCPU_REGS_R9 = 9,
	VCPU_REGS_R10 = 10,
	VCPU_REGS_R11 = 11,
	VCPU_REGS_R12 = 12,
	VCPU_REGS_R13 = 13,
	VCPU_REGS_R14 = 14,
	VCPU_REGS_R15 = 15,
	VCPU_REGS_CR2 = 16,
};

struct hvm_vcpu {
	struct hvm *hvm;
	struct vmcs *vmcs;
	int   cpu;
	int   launched;
	unsigned long irq_summary; /* bit vector: 1 per word in irq_pending */ 
#define NR_IRQ_WORDS (256 / BITS_PER_LONG)
	unsigned long irq_pending[NR_IRQ_WORDS];
	unsigned long regs[17]; /* for rsp needs vcpu_load_rsp_rip() */
	unsigned long rip;      /* needs vcpu_load_rsp_rip() */

	gaddr_t cr3;
	unsigned long cr0, cr4, cr8;
	struct vmx_msr_entry *guest_msrs;
	struct vmx_msr_entry *host_msrs;

	struct list_head free_page_links;
	struct list_head free_pages;
	page_link_t page_link_buf[HVM_NUM_MMU_PAGES];
	paging_context_t *paging_context;

	struct hvm_guest_debug guest_debug;
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

void free_paging_context(struct hvm_vcpu *vcpu);
int create_paging_context(struct hvm_vcpu *vcpu);

void vmcs_writel(unsigned long field, unsigned long value);
unsigned long vmcs_readl(unsigned long field);

static inline u32 vmcs_read32(unsigned long field)
{
	return vmcs_readl(field);
}

static inline void vmcs_write32(unsigned long field, u32 value)
{
	vmcs_writel(field, value);
}

extern paddr_t hvm_bad_page_addr;

#endif
