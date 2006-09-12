#ifndef __KVM_H
#define __KVM_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>

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
#define CR3_FLAGS_MASK ((1ULL << 5) - 1)

#define CR4_PSE_MASK (1ULL << 4)
#define CR4_PAE_MASK (1ULL << 5)
#define CR4_PGE_MASK (1ULL << 7)
#define CR4_VMXE_MASK (1ULL << 13)

#define KVM_GUEST_CR0_MASK \
	(CR0_PG_MASK | CR0_PE_MASK | CR0_WP_MASK | CR0_NE_MASK)
#define KVM_VM_CR0_ALWAYS_ON KVM_GUEST_CR0_MASK

#define KVM_GUEST_CR4_MASK \
	(CR4_PSE_MASK | CR4_PAE_MASK | CR4_PGE_MASK | CR4_VMXE_MASK)
#define KVM_VM_CR4_ALWAYS_ON (CR4_VMXE_MASK | CR4_PAE_MASK)

#define INVALID_PAGE (~(hpa_t)0)

#define KVM_MAX_VCPUS 1
#define KVM_MEMORY_SLOTS 4
#define KVM_NUM_MMU_PAGES 256

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

#define SELECTOR_TI_MASK (1 << 2)
#define SELECTOR_RPL_MASK 0x03

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

struct kvm_mmu_page_link {
	struct list_head link;
	hpa_t page_hpa;
};

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

struct kvm_vcpu;

/*
 * x86 supports 3 paging modes (4-level 64-bit, 3-level 64-bit, and 2-level
 * 32-bit).  The kvm_mmu structure abstracts the details of the current mmu
 * mode.
 */
struct kvm_mmu {
	void (*new_cr3)(struct kvm_vcpu *vcpu);
	int (*page_fault)(struct kvm_vcpu *vcpu, gva_t gva, uint32_t err);
	void (*inval_page)(struct kvm_vcpu *vcpu, gva_t gva);
	void (*free)(struct kvm_vcpu *vcpu);
	u64 (*fetch_pte64)(struct kvm_vcpu *vcpu, gva_t gva);
	hpa_t root_hpa;
	int root_level;
	int shadow_root_level;
};

struct kvm_guest_debug {
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

struct kvm_vcpu {
	struct kvm *kvm;
	struct vmcs *vmcs;
	struct mutex mutex;
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
	struct kvm_mmu_page_link page_link_buf[KVM_NUM_MMU_PAGES];
	struct kvm_mmu mmu;

	struct kvm_guest_debug guest_debug;

	char fx_buf[FX_BUF_SIZE];
	char *host_fx_image;
	char *guest_fx_image;

	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_size;
	unsigned char mmio_data[8];
	unsigned long mmio_phys_addr;
};

struct kvm_memory_slot {
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long flags;
	struct page **phys_mem;
};

struct kvm {
	int nmemslots;
	struct kvm_memory_slot memslots[KVM_MEMORY_SLOTS];
	int nvcpus;
	struct kvm_vcpu vcpus[KVM_MAX_VCPUS];
	struct file *log_file;
	char *log_buf;
};

struct kvm_stat {
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

extern struct kvm_stat kvm_stat;

int kvm_printf(struct kvm *kvm, const char *fmt, ...);
int kvm_vprintf(struct kvm *kvm, const char *fmt, va_list args);
int vcpu_printf(struct kvm_vcpu *vcpu, const char *fmt, ...);

void kvm_mmu_destroy(struct kvm_vcpu *vcpu);
int kvm_mmu_init(struct kvm_vcpu *vcpu);

int kvm_mmu_reset_context(struct kvm_vcpu *vcpu);

gpa_t gva_to_gpa(struct kvm_vcpu *vcpu, gva_t gva);
hpa_t gva_to_hpa(struct kvm_vcpu *vcpu, gva_t gva);

struct page *gfn_to_page(struct kvm *kvm, gfn_t gfn);

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
	return (vmcs_readl(CR4_READ_SHADOW) & KVM_GUEST_CR4_MASK) | 
		(vmcs_readl(GUEST_CR4) & ~KVM_GUEST_CR4_MASK);  
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
	return (vmcs_readl(CR0_READ_SHADOW) & KVM_GUEST_CR0_MASK) | 
		(vmcs_readl(GUEST_CR0) & ~KVM_GUEST_CR0_MASK);     
}

static inline unsigned guest_cpl(void)
{
	return vmcs_read16(GUEST_CS_SELECTOR) & SELECTOR_RPL_MASK;     
}

static inline int is_paging(void)
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


extern hpa_t kvm_bad_page_addr;


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
