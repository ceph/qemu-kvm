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

#define CR3_RESEVED_BITS 0x07ULL
#define CR3_L_MODE_RESEVED_BITS (~((1ULL << 40) - 1) | 0x0fe7ULL)

#define CR4_PSE_MASK (1ULL << 4)
#define CR4_PAE_MASK (1ULL << 5)
#define CR4_PGE_MASK (1ULL << 7)
#define CR4_VMXE_MASK (1ULL << 13)

#define HVM_GUEST_CR0_MASK \
	(CR0_PG_MASK | CR0_PE_MASK | CR0_WP_MASK | CR0_NE_MASK)
#define HVM_VM_CR0_ALWAYS_ON HVM_GUEST_CR0_MASK

#define HVM_GUEST_CR4_MASK \
	(CR4_PSE_MASK | CR4_PAE_MASK | CR4_PGE_MASK | CR4_VMXE_MASK)
#define HVM_VM_CR4_ALWAYS_ON (CR4_VMXE_MASK | CR4_PAE_MASK)

#define INVALID_PAGE (~(hpa_t)0)

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

/*
 * Address types:
 *
 *  gva - guest virtual address
 *  gpa - guest physical address
 *  gfn - guest frame number
 *  hva - host virtual address
 *  hpa - host physical address
 *  hfn - host frame number
 */

typedef unsigned long  gva_t;
typedef u64            gpa_t;
typedef unsigned long  gfn_t;

typedef unsigned long  hva_t;
typedef u64            hpa_t;
typedef unsigned long  hfn_t;

typedef struct page_link_s {
	struct list_head link;
	hpa_t page_hpa;
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
	int (*page_fault)(struct hvm_vcpu *vcpu, gva_t gva, uint32_t err);
	void (*inval_page)(struct hvm_vcpu *vcpu, gva_t gva);
	void (*free)(struct hvm_vcpu *vcpu);
	u64 (*fetch_pte64)(struct hvm_vcpu *vcpu, gva_t gva);
	hpa_t root_hpa;
	int root_level;
	int shadow_root_level;
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

	gpa_t cr3;
	unsigned long cr8;
	u64 shadow_efer;
	u64 apic_base;
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

	int fix_segs;
	int first_sreg_fix;

	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_size;
	unsigned char mmio_data[8];
	unsigned long mmio_phys_addr;
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
#define vcpu_printf(vcpu, fmt...) hvm_printf(vcpu->hvm, fmt)

void hvm_mmu_destroy(struct hvm_vcpu *vcpu);
int hvm_mmu_init(struct hvm_vcpu *vcpu);

int hvm_mmu_reset_context(struct hvm_vcpu *vcpu);

hpa_t gva_to_hpa(struct hvm_vcpu *vcpu, gva_t gva);

void vmcs_writel(unsigned long field, unsigned long value);
unsigned long vmcs_readl(unsigned long field);

static inline u16 vmcs_read16(unsigned long field)
{
	return vmcs_readl(field);
}

static inline u32 vmcs_read32(unsigned long field)
{
	return vmcs_readl(field);
}

static inline u64 vmcs_read64(unsigned long field)
{
#ifdef __x86_64__
	return vmcs_readl(field);
#else
	return vmcs_readl(field) | ((u64)vmcs_readl(field+1) << 32);
#endif
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
	return (vmcs_readl(CR4_READ_SHADOW) & HVM_GUEST_CR4_MASK) | 
		(vmcs_readl(GUEST_CR4) & ~HVM_GUEST_CR4_MASK);  
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


extern hpa_t hvm_bad_page_addr;


/* The Xen-based x86 emulator wants register state in a struct cpu_user_regs */

#ifdef __x86_64__
#define DECLARE_REG(basename) \
	union { \
		u64 r##basename; \
		u64 e##basename; \
	}
#else
#define DECLARE_REG(basename) u32 e#basename
#endif

struct cpu_user_regs {
	DECLARE_REG(ax);
	DECLARE_REG(bx);
	DECLARE_REG(cx);
	DECLARE_REG(dx);
	DECLARE_REG(si);
	DECLARE_REG(di);
	DECLARE_REG(sp);
	DECLARE_REG(bp);
	DECLARE_REG(ip);
	DECLARE_REG(flags);
#ifdef __x86_64__
	u64 r8, r9, r10, r11, r12, r13, r14, r15;
#endif
	u16 cs, ds, es, fs, gs, ss;
	u16 error_code;
};

#undef DECLARE_REG

#endif
