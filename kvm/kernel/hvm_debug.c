
#include <linux/highmem.h>

#include "hvm.h"
#include "hvm_debug.h"

#ifdef KVM_DEBUG

static const char *vmx_msr_name[] = { 
	"MSR_EFER", "MSR_STAR", "MSR_CSTAR",
	"MSR_KERNEL_GS_BASE", "MSR_SYSCALL_MASK", "MSR_LSTAR"
};

#define NR_VMX_MSR (sizeof(vmx_msr_name) / sizeof(char*))

void show_msrs(struct hvm_vcpu *vcpu)
{
	int i;

	for (i = 0; i < NR_VMX_MSR; ++i) {
		hvm_printf(vcpu->hvm, "%s: %s=0x%llx\n",
		       __FUNCTION__,
		       vmx_msr_name[i],
		       vcpu->guest_msrs[i].data);
	}
}

int read_guest(struct hvm_vcpu *vcpu,
			     vaddr_t addr,
			     unsigned long size,
			     void *dest)
{
	unsigned char *host_buf = dest;

	while (size) {
		paddr_t paddr;
		unsigned now;
		unsigned offset;
		vaddr_t guest_buf;

		paddr = guest_v_to_host_p(vcpu, addr);
		if ( paddr == hvm_bad_page_addr ) {
			return 0;
		}
		guest_buf = (vaddr_t)kmap_atomic(
					pfn_to_page(paddr >> PAGE_SHIFT),
					KM_USER0);
		offset = addr & ~PAGE_MASK;
		guest_buf |= offset;
		now = min(size, PAGE_SIZE - offset);
		memcpy(host_buf, (void*)guest_buf, now);
		host_buf += now;
		addr += now;
		size -= now;
		kunmap_atomic(guest_buf & PAGE_MASK, KM_USER0);
	}
	return 1;
}

int write_guest(struct hvm_vcpu *vcpu,
			     vaddr_t addr,
			     unsigned long size,
			     void *data)
{
	unsigned char *host_buf = data;

	while (size) {
		paddr_t paddr;
		unsigned now;
		unsigned offset;
		vaddr_t guest_buf;

		paddr = guest_v_to_host_p(vcpu, addr);
		if ( paddr == hvm_bad_page_addr ) {
			return 0;
		}
		guest_buf = (vaddr_t)kmap_atomic(
					pfn_to_page(paddr >> PAGE_SHIFT),
					KM_USER0);
		offset = addr & ~PAGE_MASK;
		guest_buf |= offset;
		now = min(size, PAGE_SIZE - offset);
		memcpy((void*)guest_buf, host_buf, now);
		host_buf += now;
		addr += now;
		size -= now;
		kunmap_atomic(guest_buf & PAGE_MASK, KM_USER0);
	}
	return 1;
}

struct gate_struct {          
	u16 offset_low;
	u16 segment; 
	unsigned ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
	u16 offset_middle;
	u32 offset_high;
	u32 zero1; 
} __attribute__((packed));

void show_irq(struct hvm_vcpu *vcpu,  int irq)
{
	unsigned long idt_base = vmcs_readl(GUEST_IDTR_BASE);
	unsigned long idt_limit = vmcs_readl(GUEST_IDTR_LIMIT);
	struct gate_struct gate;

	if (!is_long_mode()) {
		hvm_printf(vcpu->hvm, "%s: not in long mode\n", __FUNCTION__);
	}

	if (!is_long_mode() || idt_limit < irq * sizeof(gate)) {
		hvm_printf(vcpu->hvm, "%s: 0x%x read_guest err\n",
			   __FUNCTION__,
			   irq);
		return;
	}

	if (!read_guest(vcpu, idt_base + irq * sizeof(gate), sizeof(gate), &gate)) {
		hvm_printf(vcpu->hvm, "%s: 0x%x read_guest err\n",
			   __FUNCTION__,
			   irq);
		return;
	}
	hvm_printf(vcpu->hvm, "%s: 0x%x handler 0x%llx\n",
		   __FUNCTION__,
		   irq,
		   ((uint64_t)gate.offset_high << 32) | 
		   ((uint64_t)gate.offset_middle << 16) | 
		   gate.offset_low); 
}

void show_page(struct hvm_vcpu *vcpu,
			     vaddr_t addr)
{
	uint64_t *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);

	if (!buf) {
		return;
	}
	addr &= PAGE_MASK;
	if (read_guest(vcpu, addr, PAGE_SIZE, buf)) {
		int i;
		for (i = 0; i <  PAGE_SIZE / sizeof(uint64_t) ; i++) {
			uint8_t *ptr = (uint8_t*)&buf[i];
			int j;
			hvm_printf(vcpu->hvm, " 0x%16.16x:",
				   addr + i * sizeof(uint64_t));
			for (j = 0; j < sizeof(uint64_t) ; j++) {
				hvm_printf(vcpu->hvm, " 0x%2.2x", ptr[j]);
			}
			hvm_printf(vcpu->hvm, "\n");
		}
	}
	kfree(buf);
}

#define IA32_DEBUGCTL_RESERVED_BITS 0xfffffffffffffe3c

static int is_canonical(unsigned long addr)
{
       return  addr == ((long)addr << 16) >> 16;
}

int vm_entry_test(struct hvm_vcpu *vcpu)
{
	unsigned long cr0;
	unsigned long cr4;
	unsigned long cr3;
	unsigned long dr7;
	uint64_t ia32_debugctl;
	unsigned long sysenter_esp;
	unsigned long sysenter_eip;
	unsigned long rflags;

	int long_mode;
	int virtual8086;

	#define RFLAGS_VM (1 << 17)
	#define RFLAGS_RF (1 << 9)
	#define SELECTOR_TI_MASK (1 << 2)
	#define SELECTOR_RPL_MASK 0x03
	

	#define VIR8086_SEG_BASE_TEST(seg)\
		if (vmcs_readl(GUEST_##seg##_BASE) != \
		    (unsigned long)vmcs_read16(GUEST_##seg##_SELECTOR) << 4) {\
			hvm_printf(vcpu->hvm, "%s: "#seg" base 0x%lx in "\
				   "virtual8086 is not "#seg" selector 0x%lx"\
				   " shifted right 4 bits\n",\
			   __FUNCTION__,\
			   vmcs_readl(GUEST_##seg##_BASE),\
			   vmcs_read16(GUEST_##seg##_SELECTOR));\
			return 0;\
		}

	#define VIR8086_SEG_LIMIT_TEST(seg)\
		if (vmcs_readl(GUEST_##seg##_LIMIT) != 0x0ffff) { \
			hvm_printf(vcpu->hvm, "%s: "#seg" limit 0x%lx in "\
				   "virtual8086 is not 0xffff\n",\
			   __FUNCTION__,\
			   vmcs_readl(GUEST_##seg##_LIMIT));\
			return 0;\
		}

	#define VIR8086_SEG_AR_TEST(seg)\
		if (vmcs_read32(GUEST_##seg##_AR_BYTES) != 0x0f3) { \
			hvm_printf(vcpu->hvm, "%s: "#seg" AR 0x%x in "\
				   "virtual8086 is not 0xf3\n",\
			   __FUNCTION__,\
			   vmcs_read32(GUEST_##seg##_AR_BYTES));\
			return 0;\
		}


	//hvm_printf(vcpu->hvm, "%s: start %d\n", __FUNCTION__, vm_entry_test_id);

	cr0 = vmcs_readl(GUEST_CR0);

	if (!(cr0 & CR0_PG_MASK)) {
		hvm_printf(vcpu->hvm, "%s: cr0 0x%lx, PG is not set\n",
			   __FUNCTION__, cr0);
		return 0;
	}

	if (!(cr0 & CR0_PE_MASK)) {
		hvm_printf(vcpu->hvm, "%s: cr0 0x%lx, PE is not set\n",
			   __FUNCTION__, cr0);
		return 0;
	}

	if (!(cr0 & CR0_NE_MASK)) {
		hvm_printf(vcpu->hvm, "%s: cr0 0x%lx, NE is not set\n",
			   __FUNCTION__, cr0);
		return 0;
	}

	if (!(cr0 & CR0_WP_MASK)) {
		hvm_printf(vcpu->hvm, "%s: cr0 0x%lx, WP is not set\n",
			   __FUNCTION__, cr0);
	}

	cr4 = vmcs_readl(GUEST_CR4);

	if (!(cr4 & CR4_VMXE_MASK)) {
		hvm_printf(vcpu->hvm, "%s: cr4 0x%lx, VMXE is not set\n",
			   __FUNCTION__, cr4);
		return 0;
	}

	if (!(cr4 & CR4_PAE_MASK)) {
		hvm_printf(vcpu->hvm, "%s: cr4 0x%lx, PAE is not set\n",
			   __FUNCTION__, cr4);
	}

	ia32_debugctl = vmcs_read64(GUEST_IA32_DEBUGCTL);

	if (ia32_debugctl & IA32_DEBUGCTL_RESERVED_BITS ) {
		hvm_printf(vcpu->hvm, "%s: ia32_debugctl 0x%llx, reserve bits\n",
			   __FUNCTION__, ia32_debugctl);
		return 0;
	}

	long_mode = is_long_mode();

	if (long_mode) {
	}

	if ( long_mode && !(cr4 & CR4_PAE_MASK)) {
		hvm_printf(vcpu->hvm, "%s: long mode and not PAE\n",
			   __FUNCTION__);
		return 0;
	}

	cr3 = vmcs_readl(GUEST_CR3);

	if (cr3 & CR3_L_MODE_RESEVED_BITS) {
		hvm_printf(vcpu->hvm, "%s: cr3 0x%lx, reserved bits\n",
			   __FUNCTION__, cr3);
		return 0;
	}

	dr7 = vmcs_readl(GUEST_DR7);

	if (dr7 & ~((1UL << 32) - 1)) {
		hvm_printf(vcpu->hvm, "%s: dr7 0x%lx, reserved bits\n",
			   __FUNCTION__, dr7);
		return 0;
	}

	sysenter_esp = vmcs_readl(GUEST_SYSENTER_ESP);

	if (!is_canonical(sysenter_esp)) {
		hvm_printf(vcpu->hvm, "%s: sysenter_esp 0x%lx, not canonical\n",
			   __FUNCTION__, sysenter_esp);
		return 0;
	}

	sysenter_eip = vmcs_readl(GUEST_SYSENTER_EIP);

	if (!is_canonical(sysenter_eip)) {
		hvm_printf(vcpu->hvm, "%s: sysenter_eip 0x%lx, not canonical\n",
			   __FUNCTION__, sysenter_eip);
		return 0;
	}

	rflags = vmcs_readl(GUEST_RFLAGS);
	virtual8086 = rflags & RFLAGS_VM;


	if (vmcs_read16(GUEST_TR_SELECTOR) & SELECTOR_TI_MASK) {
	       hvm_printf(vcpu->hvm, "%s: tr selctor 0x%x, TI is set\n",
			   __FUNCTION__, vmcs_read16(GUEST_TR_SELECTOR));
	       return 0;
	}

	if (!(vmcs_read32(GUEST_LDTR_AR_BYTES) & AR_UNUSABLE_MASK) &&
	      vmcs_read16(GUEST_LDTR_SELECTOR) & SELECTOR_TI_MASK) {
	       hvm_printf(vcpu->hvm, "%s: ldtr selctor 0x%x,"
				     " is usable and TI is set\n",
			   __FUNCTION__, vmcs_read16(GUEST_LDTR_SELECTOR));
	       return 0;
	}

	if (!virtual8086 && 
	    (vmcs_read16(GUEST_SS_SELECTOR) & SELECTOR_RPL_MASK) != 
	    (vmcs_read16(GUEST_CS_SELECTOR) & SELECTOR_RPL_MASK)) {
		hvm_printf(vcpu->hvm, "%s: ss selctor 0x%x cs selctor 0x%x,"
				     " not same RPL\n",
			   __FUNCTION__,
			   vmcs_read16(GUEST_SS_SELECTOR),
			   vmcs_read16(GUEST_CS_SELECTOR));
		return 0;
	}

	if (virtual8086) {
		VIR8086_SEG_BASE_TEST(CS);
		VIR8086_SEG_BASE_TEST(SS);
		VIR8086_SEG_BASE_TEST(DS);
		VIR8086_SEG_BASE_TEST(ES);
		VIR8086_SEG_BASE_TEST(FS);
		VIR8086_SEG_BASE_TEST(GS);
	}

	if (!is_canonical(vmcs_readl(GUEST_TR_BASE)) || 
	    !is_canonical(vmcs_readl(GUEST_FS_BASE)) ||
	    !is_canonical(vmcs_readl(GUEST_GS_BASE)) ) {
		hvm_printf(vcpu->hvm, "%s: TR 0x%lx FS 0x%lx or GS 0x%lx base"
				      " is not canonical\n",
			   __FUNCTION__,
			   vmcs_readl(GUEST_TR_BASE),
			   vmcs_readl(GUEST_FS_BASE),
			   vmcs_readl(GUEST_GS_BASE));
		return 0;

	}

	if (!(vmcs_read32(GUEST_LDTR_AR_BYTES) & AR_UNUSABLE_MASK) && 
	    !is_canonical(vmcs_readl(GUEST_LDTR_BASE))) {
		hvm_printf(vcpu->hvm, "%s: LDTR base 0x%lx, usable and is not"
				      " canonical\n",
			   __FUNCTION__,
			   vmcs_readl(GUEST_LDTR_BASE));
		return 0;
	}

	if ((vmcs_readl(GUEST_CS_BASE) & ~((1ULL << 32) - 1))) {
		hvm_printf(vcpu->hvm, "%s: CS base 0x%lx, not all bits 63-32"
				      " are zero\n",
			   __FUNCTION__,
			   vmcs_readl(GUEST_CS_BASE));
		return 0;
	}

	#define SEG_BASE_TEST(seg)\
	if ( !(vmcs_read32(GUEST_##seg##_AR_BYTES) & AR_UNUSABLE_MASK) &&\
	     (vmcs_readl(GUEST_##seg##_BASE) & ~((1ULL << 32) - 1))) {\
		hvm_printf(vcpu->hvm, "%s: "#seg" base 0x%lx, is usable and not"\
						" all bits 63-32 are zero\n",\
			   __FUNCTION__,\
			   vmcs_readl(GUEST_##seg##_BASE));\
		return 0;\
	}
	SEG_BASE_TEST(SS);
	SEG_BASE_TEST(DS);
	SEG_BASE_TEST(ES);

	if (virtual8086) {
		VIR8086_SEG_LIMIT_TEST(CS);
		VIR8086_SEG_LIMIT_TEST(SS);
		VIR8086_SEG_LIMIT_TEST(DS);
		VIR8086_SEG_LIMIT_TEST(ES);
		VIR8086_SEG_LIMIT_TEST(FS);
		VIR8086_SEG_LIMIT_TEST(GS);
	}

	if (virtual8086) {
		VIR8086_SEG_AR_TEST(CS);
		VIR8086_SEG_AR_TEST(SS);
		VIR8086_SEG_AR_TEST(DS);
		VIR8086_SEG_AR_TEST(ES);
		VIR8086_SEG_AR_TEST(FS);
		VIR8086_SEG_AR_TEST(GS);
	} else {

		uint32_t cs_ar = vmcs_read32(GUEST_CS_AR_BYTES);
		uint32_t ss_ar = vmcs_read32(GUEST_SS_AR_BYTES);
		uint32_t tr_ar = vmcs_read32(GUEST_TR_AR_BYTES);
		uint32_t ldtr_ar = vmcs_read32(GUEST_LDTR_AR_BYTES);

		#define SEG_G_TEST(seg) {					\
		uint32_t lim = vmcs_read32(GUEST_##seg##_LIMIT);		\
		uint32_t ar = vmcs_read32(GUEST_##seg##_AR_BYTES);		\
		int err = 0;							\
		if (((lim & ~PAGE_MASK) != ~PAGE_MASK) && (ar & AR_G_MASK)) {	\
			err = 1;						\
		}								\
		if ((lim & ~((1u << 20) - 1)) && !(ar & AR_G_MASK)) {		\
			err = 1;						\
		}								\
		if (err) {							\
			hvm_printf(vcpu->hvm, "%s: "#seg" AR 0x%x, G err. lim"	\
							" is 0x%x\n",		\
						   __FUNCTION__,		\
						   ar, lim);			\
			return 0;						\
		}								\
		}


		if (!(cs_ar & AR_TYPE_ACCESSES_MASK)) {
			hvm_printf(vcpu->hvm, "%s: cs AR 0x%x, accesses is clear\n",
			   __FUNCTION__,
			   cs_ar);
			return 0;
		}

		if (!(cs_ar & AR_TYPE_CODE_MASK)) {
			hvm_printf(vcpu->hvm, "%s: cs AR 0x%x, code is clear\n",
			   __FUNCTION__,
			   cs_ar);
			return 0;
		}

		if (!(cs_ar & AR_S_MASK)) {
			hvm_printf(vcpu->hvm, "%s: cs AR 0x%x, type is sys\n",
			   __FUNCTION__,
			   cs_ar);
			return 0;
		}

		if ((cs_ar & AR_TYPE_MASK) >= 8 && (cs_ar & AR_TYPE_MASK) < 12 && 
		    AR_DPL(cs_ar) != 
		    (vmcs_read16(GUEST_CS_SELECTOR) & SELECTOR_RPL_MASK) ) {
			hvm_printf(vcpu->hvm, "%s: cs AR 0x%x, "
					      "DPL not as RPL\n",
				   __FUNCTION__,
				   cs_ar);
			return 0;
		}

		if ((cs_ar & AR_TYPE_MASK) >= 13 && (cs_ar & AR_TYPE_MASK) < 16 && 
		    AR_DPL(cs_ar) > 
		    (vmcs_read16(GUEST_CS_SELECTOR) & SELECTOR_RPL_MASK) ) {
			hvm_printf(vcpu->hvm, "%s: cs AR 0x%x, "
					      "DPL greater than RPL\n",
				   __FUNCTION__,
				   cs_ar);
			return 0;
		}

		if (!(cs_ar & AR_P_MASK)) {
				hvm_printf(vcpu->hvm, "%s: CS AR 0x%x, not "
						      "present\n",
					   __FUNCTION__,
					   cs_ar);
				return 0;
		}

		if ((cs_ar & AR_RESERVD_MASK)) {
				hvm_printf(vcpu->hvm, "%s: CS AR 0x%x, reseved"
						      " bits are set\n",
					   __FUNCTION__,
					   cs_ar);
				return 0;
		}

		if (long_mode & (cs_ar & AR_L_MASK) && (cs_ar & AR_DB_MASK)) {
			hvm_printf(vcpu->hvm, "%s: CS AR 0x%x, DB and L are set"
					      " in long mode\n",
					   __FUNCTION__,
					   cs_ar);
			return 0;

		}

		SEG_G_TEST(CS);

		if (!(ss_ar & AR_UNUSABLE_MASK)) { 
		    if ((ss_ar & AR_TYPE_MASK) != 3 && 
			(ss_ar & AR_TYPE_MASK) != 7 ) {
			hvm_printf(vcpu->hvm, "%s: ss AR 0x%x, usable and type"
					      " is not 3 or 7\n",
			   __FUNCTION__,
			   ss_ar);
			return 0;
		    }

		    if (!(ss_ar & AR_S_MASK)) {
			hvm_printf(vcpu->hvm, "%s: ss AR 0x%x, usable and"
					      " is sys\n",
			   __FUNCTION__,
			   ss_ar);
			return 0;
		    }
		    if (!(ss_ar & AR_P_MASK)) {
				hvm_printf(vcpu->hvm, "%s: SS AR 0x%x, usable"
						      " and  not present\n",
					   __FUNCTION__,
					   ss_ar);
				return 0;
		    }

		    if ((ss_ar & AR_RESERVD_MASK)) {
					hvm_printf(vcpu->hvm, "%s: SS AR 0x%x, reseved"
							      " bits are set\n",
						   __FUNCTION__,
						   ss_ar);
					return 0;
		    }

		    SEG_G_TEST(SS);

		}

		if (AR_DPL(ss_ar) != 
		    (vmcs_read16(GUEST_SS_SELECTOR) & SELECTOR_RPL_MASK) ) {
			hvm_printf(vcpu->hvm, "%s: SS AR 0x%x, "
					      "DPL not as RPL\n",
				   __FUNCTION__,
				   ss_ar);
			return 0;
		}

		#define SEG_AR_TEST(seg) {\
		uint32_t ar = vmcs_read32(GUEST_##seg##_AR_BYTES);\
		if (!(ar & AR_UNUSABLE_MASK)) {\
			if (!(ar & AR_TYPE_ACCESSES_MASK)) {\
				hvm_printf(vcpu->hvm, "%s: "#seg" AR 0x%x, "\
						"usable and not accesses\n",\
					   __FUNCTION__,\
					   ar);\
				return 0;\
			}\
			if ((ar & AR_TYPE_CODE_MASK) &&\
			    !(ar & AR_TYPE_READABLE_MASK)) {\
				hvm_printf(vcpu->hvm, "%s: "#seg" AR 0x%x, "\
						"code and not readable\n",\
					   __FUNCTION__,\
					   ar);\
				return 0;\
			}\
			if (!(ar & AR_S_MASK)) {\
				hvm_printf(vcpu->hvm, "%s: "#seg" AR 0x%x, usable and"\
					      " is sys\n",\
					   __FUNCTION__,\
					   ar);\
				return 0;\
			}\
			if ((ar & AR_TYPE_MASK) >= 0 && \
			    (ar & AR_TYPE_MASK) < 12 && \
			    AR_DPL(ar) < (vmcs_read16(GUEST_##seg##_SELECTOR) & \
					  SELECTOR_RPL_MASK) ) {\
				    hvm_printf(vcpu->hvm, "%s: "#seg" AR 0x%x, "\
					      "DPL less than RPL\n",\
					       __FUNCTION__,\
					       ar);\
				    return 0;\
			}\
			if (!(ar & AR_P_MASK)) {\
				hvm_printf(vcpu->hvm, "%s: "#seg" AR 0x%x, usable and"\
					      " not present\n",\
					   __FUNCTION__,\
					   ar);\
				return 0;\
			}\
			if ((ar & AR_RESERVD_MASK)) {\
					hvm_printf(vcpu->hvm, "%s: "#seg" AR"\
							" 0x%x, reseved"\
							" bits are set\n",\
						   __FUNCTION__,\
						   ar);\
					return 0;\
			}\
			SEG_G_TEST(seg)\
		}\
		}

		SEG_AR_TEST(DS);
		SEG_AR_TEST(ES);
		SEG_AR_TEST(FS);
		SEG_AR_TEST(GS);

		// TR test
		if (long_mode) {
			if ((tr_ar & AR_TYPE_MASK) != AR_TYPE_BUSY_64_TSS) {
				hvm_printf(vcpu->hvm, "%s: TR AR 0x%x, long"
						      " mode and not 64bit busy"
						      " tss\n",
				   __FUNCTION__,
				   tr_ar);
				return 0;
			}
		} else {
			if ((tr_ar & AR_TYPE_MASK) != AR_TYPE_BUSY_32_TSS && 
			    (tr_ar & AR_TYPE_MASK) != AR_TYPE_BUSY_16_TSS) {
				hvm_printf(vcpu->hvm, "%s: TR AR 0x%x, long"
						      " mode and not 16/32bit "
						      "busy tss\n",
				   __FUNCTION__,
				   tr_ar);
				return 0;
			}

		}
		if ((tr_ar & AR_S_MASK)) {
			hvm_printf(vcpu->hvm, "%s: TR AR 0x%x, S is set\n",
				   __FUNCTION__,
				   tr_ar);
			return 0;
		}
		if (!(tr_ar & AR_P_MASK)) {
			hvm_printf(vcpu->hvm, "%s: TR AR 0x%x, P is not set\n",
				   __FUNCTION__,
				   tr_ar);
			return 0;
		}

		if ((tr_ar & (AR_RESERVD_MASK| AR_UNUSABLE_MASK))) {
			hvm_printf(vcpu->hvm, "%s: TR AR 0x%x, reserved bit are"
					      " set\n",
				   __FUNCTION__,
				   tr_ar);
			return 0;
		}
		SEG_G_TEST(TR);

		// TR test
		if (!(ldtr_ar & AR_UNUSABLE_MASK)) {

			if ((ldtr_ar & AR_TYPE_MASK) != AR_TYPE_LDT) {
				hvm_printf(vcpu->hvm, "%s: LDTR AR 0x%x,"
						      " bad type\n",
					   __FUNCTION__,
					   ldtr_ar);
			    return 0;
			}

			if ((ldtr_ar & AR_S_MASK)) {
				hvm_printf(vcpu->hvm, "%s: LDTR AR 0x%x,"
						      " S is set\n",
					   __FUNCTION__,
					   ldtr_ar);
				return 0;
			}

			if (!(ldtr_ar & AR_P_MASK)) {
				hvm_printf(vcpu->hvm, "%s: LDTR AR 0x%x,"
						      " P is not set\n",
					   __FUNCTION__,
					   ldtr_ar);
				return 0;
			}
			if ((ldtr_ar & AR_RESERVD_MASK)) {
				hvm_printf(vcpu->hvm, "%s: LDTR AR 0x%x,"
						      " reserved bit are  set\n",
					   __FUNCTION__,
					   ldtr_ar);
				return 0;
			}
			SEG_G_TEST(LDTR);
		}
	}

	// GDTR and IDTR


	#define IDT_GDT_TEST(reg)\
	if (!is_canonical(vmcs_readl(GUEST_##reg##_BASE))) {\
		hvm_printf(vcpu->hvm, "%s: "#reg" BASE 0x%lx, not canonical\n",\
					   __FUNCTION__,\
					   vmcs_readl(GUEST_##reg##_BASE));\
		return 0;\
	}\
	if (vmcs_read32(GUEST_##reg##_LIMIT) >> 16) {\
		hvm_printf(vcpu->hvm, "%s: "#reg" LIMIT 0x%x, size err\n",\
				   __FUNCTION__,\
				   vmcs_read32(GUEST_##reg##_LIMIT));\
		return 0;\
	}\

	IDT_GDT_TEST(GDTR);
	IDT_GDT_TEST(IDTR);


	// RIP

	if ((!long_mode || !(vmcs_read32(GUEST_CS_AR_BYTES) & AR_L_MASK)) && 
	    vmcs_readl(GUEST_RIP) & ~((1ULL << 32) - 1) ){
		hvm_printf(vcpu->hvm, "%s: RIP 0x%lx, size err\n",
				   __FUNCTION__,
				   vmcs_readl(GUEST_RIP));
		return 0;    
	}

	if (!is_canonical(vmcs_readl(GUEST_RIP))) {
		hvm_printf(vcpu->hvm, "%s: RIP 0x%lx, not canonical\n",
				   __FUNCTION__,
				   vmcs_readl(GUEST_RIP));
		return 0; 
	}

	// RFLAGS
	#define RFLAGS_RESEVED_CLEAR_BITS\
		(~((1ULL << 22) - 1) | (1ULL << 15) | (1ULL << 5) | (1ULL << 3))
	#define RFLAGS_RESEVED_SET_BITS (1 << 1)

	if ((rflags & RFLAGS_RESEVED_CLEAR_BITS) || 
	    !(rflags & RFLAGS_RESEVED_SET_BITS)) {
		hvm_printf(vcpu->hvm, "%s: RFLAGS 0x%lx, reserved bits 0x%lx 0x%lx\n",
			   __FUNCTION__,
			   rflags,
			   RFLAGS_RESEVED_CLEAR_BITS,
			   RFLAGS_RESEVED_SET_BITS);
		return 0; 
	}

	if (long_mode && virtual8086) {
		hvm_printf(vcpu->hvm, "%s: RFLAGS 0x%lx, vm and long mode\n",
				   __FUNCTION__,
				   rflags);
		return 0; 
	}

	
	if (!(rflags & RFLAGS_RF)) {
		uint32_t vm_entry_info = vmcs_read32(VM_ENTRY_INTR_INFO_FIELD);
		if ((vm_entry_info & INTR_INFO_VALID_MASK) && 
		    (vm_entry_info & INTR_INFO_INTR_TYPE_MASK) == 
		    INTR_TYPE_EXT_INTR) {
			hvm_printf(vcpu->hvm, "%s: RFLAGS 0x%lx, external"
					      " interrupt and RF is clear\n",
				   __FUNCTION__,
				   rflags);
			return 0; 
		}

	}

	// to be continued from Checks on Guest Non-Register State (22.3.1.5)
	return 1;
}

#endif

