#ifndef __HVM_H
#define __HVM_H

#include <linux/types.h>
#include <linux/list.h>

#include "vmx.h"

#define CR0_PE_MASK (1ULL << 0)
#define CR0_TS_MASK (1ULL << 3)
#define CR0_NE_MASK (1ULL << 5)
#define CR0_WP_MASK (1ULL << 16)
#define CR0_NW_MASK (1ULL << 29)
#define CR0_CD_MASK (1ULL << 30)
#define CR0_PG_MASK (1ULL << 31)

#define CR3_WPT_MASK (1ULL << 3)
#define CR3_PCD_MASK (1ULL << 4)

#define CR4_PSE_MASK (1ULL << 4)
#define CR4_PAE_MASK (1ULL << 5)
#define CR4_PGE_MASK (1ULL << 7)
#define CR4_VMXE_MASK (1ULL << 13)

#define HVM_GUEST_CR0_MASK \
	(CR0_PG_MASK | CR0_PE_MASK | CR0_WP_MASK | CR0_NE_MASK)
#define HVM_VM_CR0_ALWAYS_ON HVM_GUEST_CR0_MASK

#define HVM_GUEST_CR4_MASK \
	(CR4_PSE_MASK | CR4_PAE_MASK | CR4_PGE_MASK | CR4_VMXE_MASK)

#define INVALID_PAGE (~(paddr_t)0)

#define HVM_MAX_VCPUS 4
#define HVM_NUM_MMU_PAGES 256

#define FX_IMAGE_SIZE 512
#define FX_IMAGE_ALIGN 16
#define FX_BUF_SIZE (2 * FX_IMAGE_SIZE + FX_IMAGE_ALIGN)

#define DE_VECTOR 0
#define DF_VECTOR 8
#define TS_VECTOR 10
#define NP_VECTOR 11
#define SS_VECTOR 12
#define GP_VECTOR 13
#define PF_VECTOR 14

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
	u64 (*fetch_pte64)(struct hvm_vcpu *vcpu, unsigned long vaddr);
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
	unsigned long cr8;
	u64 shadow_efer;
	struct vmx_msr_entry *guest_msrs;
	struct vmx_msr_entry *host_msrs;

	struct list_head free_page_links;
	struct list_head free_pages;
	page_link_t page_link_buf[HVM_NUM_MMU_PAGES];
	paging_context_t paging_context;

	struct hvm_guest_debug guest_debug;

	char fx_buf[FX_BUF_SIZE];
	char *host_fx_image;
	char *guest_fx_image;
};

struct hvm {
	unsigned created : 1;
	unsigned long phys_mem_pages;
	struct page **phys_mem;
	int nvcpus;
	struct hvm_vcpu vcpus[HVM_MAX_VCPUS];
	struct file *log_file;
	char *log_buf;
};

struct hvm_stat {
	u32 pf_fixed;
	u32 pf_guest;
	u32 tlb_flush;
	u32 invlpg;

	u32 exits;
	u32 io_exits;
	u32 mmio_exits;
	u32 signal_exits;
	u32 irq_exits;
};

extern struct hvm_stat hvm_stat;

int hvm_printf(struct hvm *hvm, const char *fmt, ...);

void hvm_mmu_destroy(struct hvm_vcpu *vcpu);
int hvm_mmu_init(struct hvm_vcpu *vcpu);

int hvm_mmu_reset_context(struct hvm_vcpu *vcpu);

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

static inline int is_long_mode(void)
{
	return vmcs_read32(VM_ENTRY_CONTROLS) & VM_ENTRY_CONTROLS_IA32E_MASK;
}

static inline unsigned long guest_cr4(void)
{
	return vmcs_readl(GUEST_CR4) & ~CR4_VMXE_MASK;
}

static inline int is_pae(void)
{
	return guest_cr4() & CR4_PAE_MASK;
}

static inline int is_pse(void)
{
	return guest_cr4() & CR4_PSE_MASK;
}

static inline unsigned long guest_cr0(void)
{
	return (vmcs_readl(CR0_READ_SHADOW) & HVM_GUEST_CR0_MASK) | 
		(vmcs_readl(GUEST_CR0) & ~HVM_GUEST_CR0_MASK);     
}

static int is_paging(void)
{
	return guest_cr0() & CR0_PG_MASK;
}

static inline int is_page_fault(uint32_t intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) == 
		(INTR_TYPE_EXCEPTION | PF_VECTOR | INTR_INFO_VALID_MASK);
}

static inline int is_external_interrupt(uint32_t intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VALID_MASK)) 
		== (INTR_TYPE_EXT_INTR | INTR_INFO_VALID_MASK);
}


extern paddr_t hvm_bad_page_addr;

#endif
