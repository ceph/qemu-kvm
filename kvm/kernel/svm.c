/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * AMD SVM support
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Avi Kivity   <avi@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <asm/desc.h>

#include "kvm_svm.h"
#include "x86_emulate.h"

static void set_efer(struct kvm_vcpu *vcpu, u64 efer);

#define IOPM_ALLOC_ORDER 2
#define MSRPM_ALLOC_ORDER 1

unsigned long iopm_base;
unsigned long msrpm_base;

struct svm_cpu_data {
	int cpu;

	uint64_t asid_generation;
	uint32_t max_asid;
	uint32_t next_asid;
	struct ldttss_desc *tss_desc;

	struct page *save_area;
};

static DEFINE_PER_CPU(struct svm_cpu_data *, svm_data);


static unsigned get_addr_size(struct kvm_vcpu *vcpu)
{
	struct vmcb_save_area *sa = &vcpu->arch.vmcb->save;
	u16 cs_atrib;

	if (!(sa->cr0 & CR0_PE_MASK) ||(sa->rflags & X86_EFLAGS_VM)) {
		return 2;
	}

	cs_atrib = sa->cs.atrib;

	return (cs_atrib & SVM_SELECTOR_L_MASK) ? 8 :	
				(cs_atrib & SVM_SELECTOR_DB_MASK) ? 4 : 2;
}

static inline u8 pop_irq(struct kvm_vcpu *vcpu)
{
	int word_index = __ffs(vcpu->irq_summary);
	int bit_index = __ffs(vcpu->irq_pending[word_index]);
	int irq = word_index * BITS_PER_LONG + bit_index;

	clear_bit(bit_index, &vcpu->irq_pending[word_index]);
	if (!vcpu->irq_pending[word_index])
		clear_bit(word_index, &vcpu->irq_summary);
	return irq;
}

static inline void push_irq(struct kvm_vcpu *vcpu, u8 irq)
{
	set_bit(irq, vcpu->irq_pending);
	set_bit(irq / BITS_PER_LONG, &vcpu->irq_summary);
}

static inline void clgi(void)
{
	asm ( "clgi" );
}

static inline void stgi(void)
{
	asm ( "stgi" );
}

static inline void invlpga(unsigned long addr, u32 asid)
{
	asm ( "invlpga \n\t" :: "a"(addr), "c"(asid));
}

static inline unsigned long read_cr2(void)
{ 
	unsigned long cr2;
	asm volatile("mov %%cr2, %0" : "=r" (cr2));
	return cr2;
} 

static inline void write_cr2(unsigned long val) 
{ 
	asm volatile("mov %0, %%cr2" :: "r" (val));
}

static inline unsigned long read_dr6(void)
{ 
	unsigned long dr6;
	asm volatile("mov %%dr6, %0" : "=r" (dr6));
	return dr6;
} 

static inline void write_dr6(unsigned long val) 
{ 
	asm volatile("mov %0, %%dr6" :: "r" (val));
}

static inline unsigned long read_dr7(void)
{ 
	unsigned long dr7;
	asm volatile("mov %%dr7, %0" : "=r" (dr7));
	return dr7;
} 

static inline void write_dr7(unsigned long val) 
{ 
	asm volatile("mov %0, %%dr7" :: "r" (val));
}

static inline int is_long_mode(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.vmcb->save.efer & EFER_LMA;
}

static inline void force_new_asid(struct kvm_vcpu *vcpu)
{
    vcpu->arch.asid_generation--;
}

static inline void flush_guest_tlb(struct kvm_vcpu *vcpu)
{
	force_new_asid(vcpu);
}

static inline unsigned long guest_cr0(struct kvm_vcpu *vcpu)
{
	// for now selective cr0 is disable
	/*return = (vcpu->arch.cr0 & ~SVM_CR0_SELECTIVE_MASK) | 
		(vcpu->arch.vmcb->save.cr0 & SVM_CR0_SELECTIVE_MASK);*/

	return vcpu->arch.cr0;
}

static inline int is_paging(struct kvm_vcpu *vcpu)
{
	return guest_cr0(vcpu) & CR0_PG_MASK;
}

static inline unsigned long guest_cr4(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.cr4;
}

static inline unsigned long guest_cr2(struct kvm_vcpu *vcpu)
{
	printk("%s: unexpected\n", __FUNCTION__);
	return vcpu->arch.vmcb->save.cr2;
}

static inline void set_cr2(struct kvm_vcpu *vcpu, unsigned long cr2)
{
	printk("%s: unexpected\n", __FUNCTION__);
	vcpu->arch.vmcb->save.cr2 = cr2;
}

static void set_vm_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	if (!(efer & EFER_LMA))
	    efer &= ~EFER_LME;

	vcpu->arch.vmcb->save.efer = efer | MSR_EFER_SVME_MASK;
}

static inline int is_pae(struct kvm_vcpu *vcpu)
{
	return guest_cr4(vcpu) & CR4_PAE_MASK;
}

static inline int is_pse(struct kvm_vcpu *vcpu)
{
	return guest_cr4(vcpu) & CR4_PSE_MASK;
}

static void inject_gp(struct kvm_vcpu *vcpu)
{
	
	vcpu->arch.vmcb->control.event_inj = 	SVM_EVTINJ_VALID |
						SVM_EVTINJ_VALID_ERR |
						SVM_EVTINJ_TYPE_EXEPT |
						GP_VECTOR;
	vcpu->arch.vmcb->control.event_inj_err = 0;	
}

static void inject_ud(struct kvm_vcpu *vcpu)
{	
	vcpu->arch.vmcb->control.event_inj = 	SVM_EVTINJ_VALID |
						SVM_EVTINJ_TYPE_EXEPT |
						UD_VECTOR;
}

static void inject_db(struct kvm_vcpu *vcpu)
{	
	vcpu->arch.vmcb->control.event_inj = 	SVM_EVTINJ_VALID |
						SVM_EVTINJ_TYPE_EXEPT |
						DB_VECTOR;
}

static int is_page_fault(uint32_t info)
{
	info &= (SVM_EVTINJ_VEC_MASK | SVM_EVTINJ_TYPE_MASK | SVM_EVTINJ_VALID);
	return info == (PF_VECTOR | SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_EXEPT);
}


static int is_external_interrupt(u32 info)
{
	info &= SVM_EVTINJ_TYPE_MASK | SVM_EVTINJ_VALID;
	return info == (SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_INTR);
}

static void skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.next_rip) {
		printk("%s: NOP\n", __FUNCTION__);
		return;
	}
	if (vcpu->arch.next_rip - vcpu->arch.vmcb->save.rip > 15) {
		printk("%s: ip 0x%llx next 0x%llx\n",
		       __FUNCTION__,
		       vcpu->arch.vmcb->save.rip,
		       vcpu->arch.next_rip);
	}
	
	vcpu->rip = vcpu->arch.vmcb->save.rip = vcpu->arch.next_rip;
	vcpu->arch.vmcb->control.int_state &= ~SVM_INTERRUPT_SHADOW_MASK;
}

void realmode_lgdt(struct kvm_vcpu *vcpu, u16 limit, unsigned long base)
{
	printk("%s: unexpected\n", __FUNCTION__);
}

void realmode_lidt(struct kvm_vcpu *vcpu, u16 limit, unsigned long base)
{
       printk("%s: unexpected\n", __FUNCTION__);
}


static int has_svm(void)
{
	uint32_t eax, ebx, ecx, edx;

	if (current_cpu_data.x86_vendor != X86_VENDOR_AMD) {
		printk("has_svm: not amd\n");
		return 0;
	}
	
	cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
	if (eax < SVM_CPUID_FUNC) {
		printk("has_svm: can't execute cpuid_8000000a\n");
		return 0;
	}

	cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
	if (!(ecx & (1 << SVM_CPUID_FEATURE_SHIFT))) {
		printk("has_svm: has\n");
		return 0;
	}
	return 1;
}


static void svm_cpu_exit(void *data)
{
	struct svm_cpu_data *svm_data = per_cpu(svm_data, raw_smp_processor_id());

	if (svm_data) {
		uint64_t efer;

		wrmsrl(MSR_VM_HSAVE_PA, 0);
		rdmsrl(MSR_EFER, efer);
		wrmsrl(MSR_EFER, efer & ~MSR_EFER_SVME_MASK);
		per_cpu(svm_data, raw_smp_processor_id()) = 0;
		__free_page(svm_data->save_area);
		kfree(svm_data);
	}
}

static void svm_cpus_exit(void)
{
	on_each_cpu(svm_cpu_exit, 0, 0, 1);
}

struct svm_init_data {
	int cpu;
	int r;
};

static void __svm_cpu_init(void *data)
{
	
	struct svm_init_data *init_data = data;
	struct svm_cpu_data *svm_data;
	uint64_t efer;
	struct desc_ptr gdt_descr;
	struct desc_struct *gdt;
	int me = raw_smp_processor_id();
	
	if (me != init_data->cpu) {
		return;
	}

	if (!has_svm()) {
		printk("svm_cpu_init: err EOPNOTSUPP on %d\n",
		       me);
		init_data->r = -EOPNOTSUPP;
		return;
	}
	svm_data = per_cpu(svm_data, me);

	if (!svm_data) {
		printk("svm_cpu_init: svm_data is NULL on %d\n",
		       me);
		init_data->r = -EINVAL;
		return;
	}

	svm_data->asid_generation = 1;
	svm_data->max_asid = cpuid_ebx(SVM_CPUID_FUNC) - 1;
	svm_data->next_asid = svm_data->max_asid + 1;

	asm ( "sgdt %0" : "=m"(gdt_descr) );
	gdt = (struct desc_struct *)gdt_descr.address;
	svm_data->tss_desc = (struct ldttss_desc *)(gdt + GDT_ENTRY_TSS);

	rdmsrl(MSR_EFER, efer);
	wrmsrl(MSR_EFER, efer | MSR_EFER_SVME_MASK);

	wrmsrl(MSR_VM_HSAVE_PA, page_to_pfn(svm_data->save_area) << PAGE_SHIFT);

	init_data->r = 0;
	return;
}


static int svm_cpu_init(int cpu)
{
	struct svm_cpu_data *svm_data;
	struct svm_init_data init_data;
	int r;

	svm_data = kzalloc(sizeof(struct svm_cpu_data), GFP_KERNEL);
	if (!svm_data) {
		return -ENOMEM;
	}
	svm_data->cpu = cpu;
	svm_data->save_area = alloc_page(GFP_KERNEL);
	if (!svm_data->save_area) {
		r = -ENOMEM;
		goto err_1;
	}

	per_cpu(svm_data, cpu) = svm_data;

	init_data.cpu = cpu;
	init_data.r = -ENOENT;

	// missing smp_call_function_single
	on_each_cpu(__svm_cpu_init, &init_data, 0, 1); 
	r = init_data.r;

	if (r) {
		goto err_2;
	}
	return 0;

err_2:
	per_cpu(svm_data, cpu) = 0;
	__free_page(svm_data->save_area);
err_1:
	kfree(svm_data);
	return r;
	
}


static u32 msrpm_ranges[] = {0, 0xc0000000, 0xc0010000};
#define NUM_MSR_MAPS (sizeof(msrpm_ranges) / sizeof(*msrpm_ranges))
#define MSRS_RANGE_SIZE 2048 
#define MSRS_IN_RANGE (MSRS_RANGE_SIZE * 8 / 2)

int set_msr_interception(u32 *msrpm, unsigned msr,
			int read, int write)
{
	int i;

	for (i = 0; i < NUM_MSR_MAPS; i++) {
		if (msr >= msrpm_ranges[i] && 
		    msr < msrpm_ranges[i] + MSRS_IN_RANGE) {
			u32 msr_offset = (i * MSRS_IN_RANGE + msr - 
					  msrpm_ranges[i]) * 2;
			
			u32 *base = msrpm + (msr_offset / 32);
			u32 msr_shift = msr_offset % 32;
			u32 mask = ((write) ? 0 : 2) | ((read) ? 0 : 1); 
			*base = (*base & ~(0x3 << msr_shift)) | 
				(mask << msr_shift);
			return 1;
		}
	}
	printk("%s: not found 0x%x\n", __FUNCTION__, msr);
	return 0;
}


static __init int kvm_arch_init(void)
{
	int cpu;
	struct page *iopm_pages;
	struct page *msrpm_pages;
	void *msrpm_va;
	int r;
	

	iopm_pages = alloc_pages(GFP_KERNEL, IOPM_ALLOC_ORDER);

	if (!iopm_pages) {
		return -ENOMEM;
	}
	memset(page_address(iopm_pages), 0xff, 
					PAGE_SIZE * (1 << IOPM_ALLOC_ORDER));
	iopm_base = page_to_pfn(iopm_pages) << PAGE_SHIFT;


	msrpm_pages = alloc_pages(GFP_KERNEL, MSRPM_ALLOC_ORDER);

	if (!msrpm_pages) {
		r = -ENOMEM;
		goto err_1;
	}
	msrpm_va = page_address(msrpm_pages);
	memset(msrpm_va, 0xff, PAGE_SIZE * (1 << MSRPM_ALLOC_ORDER));
	msrpm_base = page_to_pfn(msrpm_pages) << PAGE_SHIFT;

	set_msr_interception(msrpm_va, MSR_GS_BASE, 1, 1);
	set_msr_interception(msrpm_va, MSR_FS_BASE, 1, 1);
	set_msr_interception(msrpm_va, MSR_KERNEL_GS_BASE, 1, 1);
	set_msr_interception(msrpm_va, MSR_STAR, 1, 1);
	set_msr_interception(msrpm_va, MSR_LSTAR, 1, 1);
	set_msr_interception(msrpm_va, MSR_CSTAR, 1, 1);
	set_msr_interception(msrpm_va, MSR_SYSCALL_MASK, 1, 1);
	set_msr_interception(msrpm_va, MSR_IA32_SYSENTER_CS, 1, 1);
	set_msr_interception(msrpm_va, MSR_IA32_SYSENTER_ESP, 1, 1);
	set_msr_interception(msrpm_va, MSR_IA32_SYSENTER_EIP, 1, 1);
	
	for_each_online_cpu(cpu) {
		r = svm_cpu_init(cpu);
		if (r) {
			goto err_2;			
		}
	}
	return 0;

err_2:
	svm_cpus_exit();
	__free_pages(msrpm_pages, MSRPM_ALLOC_ORDER);
	msrpm_base = 0;
err_1:
	__free_pages(iopm_pages, IOPM_ALLOC_ORDER);
	iopm_base = 0;
	return r;
}

static __exit void kvm_arch_exit(void)
{
	svm_cpus_exit();
	__free_pages(pfn_to_page(msrpm_base >> PAGE_SHIFT) , MSRPM_ALLOC_ORDER);
	__free_pages(pfn_to_page(iopm_base >> PAGE_SHIFT) , IOPM_ALLOC_ORDER);
	iopm_base = msrpm_base = 0;
}

static void init_seg(struct vmcb_seg *seg)
{
	seg->selector = 0;
	seg->atrib = SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK |
		SVM_SELECTOR_WRITE_MASK; //Read/Write Data Segment
	seg->limit = 0xffff;
	seg->base = 0;
}

static void init_sys_seg(struct vmcb_seg *seg, uint32_t type)
{
	seg->selector = 0;
	seg->atrib = SVM_SELECTOR_P_MASK | type;
	seg->limit = 0xffff;
	seg->base = 0;
}

#define SEG_TYPE_LDT 2
#define SEG_TYPE_BUSY_TSS16 3

static void init_vmcb(struct vmcb *vmcb)
{
	struct vmcb_control_area *control = &vmcb->control;
	struct vmcb_save_area *save = &vmcb->save;
	u64 tsc;

	control->intercept_cr_read = 	INTERCEPT_CR0_MASK |
					INTERCEPT_CR3_MASK |
					INTERCEPT_CR4_MASK;

	control->intercept_cr_write = 	INTERCEPT_CR0_MASK |
					INTERCEPT_CR3_MASK |
					INTERCEPT_CR4_MASK;

	control->intercept_dr_read = 	INTERCEPT_DR0_MASK |
					INTERCEPT_DR1_MASK |
					INTERCEPT_DR2_MASK |
					INTERCEPT_DR3_MASK;

	control->intercept_dr_write = 	INTERCEPT_DR0_MASK |
					INTERCEPT_DR1_MASK |
					INTERCEPT_DR2_MASK |
					INTERCEPT_DR3_MASK |
					INTERCEPT_DR5_MASK |
					INTERCEPT_DR7_MASK;

	control->intercept_exceptions = 1 << PF_VECTOR;

 
	control->intercept = 	(1ULL << INTERCEPT_INTR) |
				(1ULL << INTERCEPT_NMI) |
		// selective cr0 intercept bug? 
		//    	0:   0f 22 d8                mov    %eax,%cr3
		//	3:   0f 20 c0                mov    %cr0,%eax
		//	6:   0d 00 00 00 80          or     $0x80000000,%eax
		//	b:   0f 22 c0                mov    %eax,%cr0
		// set cr3 ->interception
		// get cr0 ->interception
		// set cr0 -> no interception
				//(1ULL << INTERCEPT_SELECTIVE_CR0) |
				(1ULL << INTERCEPT_CPUID) |
				(1ULL << INTERCEPT_HLT) |
				(1ULL << INTERCEPT_INVLPG) |
				(1ULL << INTERCEPT_INVLPGA) |
				(1ULL << INTERCEPT_IOIO_PROT) |
				(1ULL << INTERCEPT_MSR_PROT) |
				(1ULL << INTERCEPT_TASK_SWITCH) |
				(1ULL << INTERCEPT_VMRUN) |
				(1ULL << INTERCEPT_VMMCALL) |
				(1ULL << INTERCEPT_VMLOAD) |
				(1ULL << INTERCEPT_VMSAVE) |
				(1ULL << INTERCEPT_STGI) |
				(1ULL << INTERCEPT_CLGI) |
				(1ULL << INTERCEPT_SKINIT);
 
	control->iopm_base_pa = iopm_base;
	control->msrpm_base_pa = msrpm_base;
	rdtscll(tsc);
	control->tsc_offset = -tsc;
	control->int_ctl = V_INTR_MASKING_MASK;

	init_seg(&save->es);
	init_seg(&save->ss);
	init_seg(&save->ds);
	init_seg(&save->fs);
	init_seg(&save->gs);

	save->cs.selector = 0xf000;
	//Executable/Readable Code Segment
	save->cs.atrib = SVM_SELECTOR_READ_MASK | SVM_SELECTOR_P_MASK |
		SVM_SELECTOR_S_MASK | SVM_SELECTOR_CODE_MASK; 
	save->cs.limit = 0xffff;
	save->cs.base = 0xffff0000;

	save->gdtr.limit = 0xffff;
	save->idtr.limit = 0xffff;

	init_sys_seg(&save->ldtr, SEG_TYPE_LDT);
	init_sys_seg(&save->tr, SEG_TYPE_BUSY_TSS16);

	save->efer = MSR_EFER_SVME_MASK;

        save->dr6 = 0xffff0ff0;
	save->dr7 = 0x400;
	save->rflags = 2;
	save->rip = 0x0000fff0;

	save->cr0 = 0x00000010 | CR0_PG_MASK; 	// cr0 val on cpu init should 
						// be 0x60000010, we enable cpu 
						// cache by default. the orderly 
						// way is to enable cache in 
						// bios.
	save->cr4 = CR4_PAE_MASK;
	 // rdx = ??
}

static int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct page *page;;


	get_cpu(); 

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		return -ENOMEM;
	}

	vcpu->arch.vmcb = page_address(page);
	memset(vcpu->arch.vmcb, 0, PAGE_SIZE);
	vcpu->arch.vmcb_pa = page_to_pfn(page) << PAGE_SHIFT;
	vcpu->arch.cr0 = 0x00000010;
	vcpu->arch.asid_generation = 0;
	memset(vcpu->arch.ab_regs, 0, sizeof(vcpu->arch.ab_regs));
	init_vmcb(vcpu->arch.vmcb);
	
	return 0;
}

static void kvm_arch_free_vcpu(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.vmcb) {
		__free_page(pfn_to_page(vcpu->arch.vmcb_pa >> PAGE_SHIFT));
		vcpu->arch.vmcb = 0;
	}
}


/*
 * Switches to specified vcpu, until a matching vcpu_put()
 */
static struct kvm_vcpu *vcpu_load(struct kvm *kvm, int vcpu_slot)
{
	struct kvm_vcpu *vcpu = &kvm->vcpus[vcpu_slot];
	
	mutex_lock(&vcpu->mutex);
	if (unlikely(!vcpu->kvm)) {
		mutex_unlock(&vcpu->mutex);
		return 0;
	}
	get_cpu();
	return vcpu;
}

static void vcpu_put(struct kvm_vcpu *vcpu)
{
	put_cpu();
	mutex_unlock(&vcpu->mutex);
}

void kvm_store_regs(struct kvm_vcpu *vcpu)
{
	vcpu->regs[VCPU_REGS_RAX] = vcpu->arch.vmcb->save.rax;
	vcpu->regs[VCPU_REGS_RSP] = vcpu->arch.vmcb->save.rsp;
	vcpu->rip = vcpu->arch.vmcb->save.rip;
	vcpu->rflags = vcpu->arch.vmcb->save.rflags;
}

void kvm_load_regs(struct kvm_vcpu *vcpu)
{
	vcpu->arch.vmcb->save.rax = vcpu->regs[VCPU_REGS_RAX];
	vcpu->arch.vmcb->save.rsp = vcpu->regs[VCPU_REGS_RSP];
	vcpu->arch.vmcb->save.rip = vcpu->rip;
	vcpu->arch.vmcb->save.rflags = vcpu->rflags;
}

static void kvm_get_sregs(struct kvm_vcpu *vcpu, struct kvm_sregs *sregs)
{
	
#define get_segment(var, seg) \
	do { \
		sregs->var.base = seg.base; \
		sregs->var.limit = seg.limit; \
		sregs->var.selector = seg.selector; \
		sregs->var.type = seg.atrib & SVM_SELECTOR_TYP_MASK; \
		sregs->var.s = (seg.atrib >> SVM_SELECTOR_S_SHIFT) & 1; \
		sregs->var.dpl = (seg.atrib >> SVM_SELECTOR_DPL_SHIFT) & 3; \
		sregs->var.present = (seg.atrib >> SVM_SELECTOR_P_SHIFT) & 1; \
		sregs->var.avl = (seg.atrib >> SVM_SELECTOR_AVL_SHIFT) & 1; \
		sregs->var.l = (seg.atrib >> SVM_SELECTOR_L_SHIFT) & 1; \
		sregs->var.db = (seg.atrib >> SVM_SELECTOR_DB_SHIFT) & 1; \
		sregs->var.g = (seg.atrib >> SVM_SELECTOR_G_SHIFT) & 1; \
		sregs->var.unusable = !sregs->var.present; \
	} while (0);

	get_segment(cs, vcpu->arch.vmcb->save.cs);
	get_segment(ds, vcpu->arch.vmcb->save.ds);
	get_segment(es, vcpu->arch.vmcb->save.es);
	get_segment(fs, vcpu->arch.vmcb->save.fs);
	get_segment(gs, vcpu->arch.vmcb->save.gs);
	get_segment(ss, vcpu->arch.vmcb->save.ss);

	get_segment(tr, vcpu->arch.vmcb->save.tr);
	get_segment(ldt, vcpu->arch.vmcb->save.ldtr);
#undef get_segment

#define get_dtable(var, seg) \
	sregs->var.limit = seg.limit; sregs->var.base = seg.base

	get_dtable(idt, vcpu->arch.vmcb->save.idtr);
	get_dtable(gdt, vcpu->arch.vmcb->save.gdtr);
#undef get_dtable

	sregs->cr0 = guest_cr0(vcpu);
	sregs->cr2 = vcpu->arch.vmcb->save.cr2;
	sregs->cr3 = vcpu->cr3;
	sregs->cr4 = guest_cr4(vcpu);
	sregs->cr8 = vcpu->arch.vmcb->control.int_ctl & V_TPR_MASK;
	sregs->efer = vcpu->shadow_efer;
	sregs->apic_base = vcpu->apic_base;

}

static void __set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
#ifdef __x86_64__
	if (vcpu->shadow_efer & EFER_LME) {
		if (!is_paging(vcpu) && (cr0 & CR0_PG_MASK)) {
			vcpu->shadow_efer |= EFER_LMA;
			vcpu->arch.vmcb->save.efer |= EFER_LMA | EFER_LME;
		}

		if (is_paging(vcpu) && !(cr0 & CR0_PG_MASK) ) {
			vcpu->shadow_efer &= ~EFER_LMA;
			vcpu->arch.vmcb->save.efer &= ~(EFER_LMA | EFER_LME);
		}	
	}
#endif
	vcpu->arch.cr0 = cr0;
	vcpu->arch.vmcb->save.cr0 = cr0 | CR0_PG_MASK;
}

static void __set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
       vcpu->arch.cr4 = cr4;
       vcpu->arch.vmcb->save.cr4 = cr4 | CR4_PAE_MASK;
}

static void __set_efer(struct kvm_vcpu *vcpu, unsigned long efer)
{
	vcpu->shadow_efer = efer;
	set_vm_efer(vcpu, efer);
}

static void lmsw(struct kvm_vcpu *vcpu, unsigned long msw)
{
	unsigned long cr0;

	cr0 = guest_cr0(vcpu);
	msw |= (cr0 & CR0_PE_MASK);
	msw &= 0x0f;
	__set_cr0(vcpu, (cr0 & ~0x0f) |  msw);
}

void realmode_lmsw(struct kvm_vcpu *vcpu, unsigned long msw,
		   unsigned long *rflags)
{
	lmsw(vcpu, msw);
}


static void kvm_set_sregs(struct kvm_vcpu *vcpu, struct kvm_sregs *sregs)
{
	int mmu_reset_needed = 0;

#define set_segment(var, seg) \
	do { \
		seg.base = sregs->var.base;  \
		seg.limit = sregs->var.limit; \
		seg.selector = sregs->var.selector; \
		if (sregs->var.unusable) { \
			seg.atrib = 0; \
		} else { \
			seg.atrib = (sregs->var.type & SVM_SELECTOR_TYP_MASK); \
			seg.atrib |= (sregs->var.s & 1) << SVM_SELECTOR_S_SHIFT; \
			seg.atrib |= (sregs->var.dpl & 3) << SVM_SELECTOR_DPL_SHIFT; \
			seg.atrib |= (sregs->var.present & 1) << SVM_SELECTOR_P_SHIFT; \
			seg.atrib |= (sregs->var.avl & 1) << SVM_SELECTOR_AVL_SHIFT; \
			seg.atrib |= (sregs->var.l & 1) << SVM_SELECTOR_L_SHIFT; \
			seg.atrib |= (sregs->var.db & 1) << SVM_SELECTOR_DB_SHIFT; \
			seg.atrib |= (sregs->var.g & 1) << SVM_SELECTOR_G_SHIFT; \
		} \
	} while (0);

	set_segment(cs, vcpu->arch.vmcb->save.cs);
	set_segment(ds, vcpu->arch.vmcb->save.ds);
	set_segment(es, vcpu->arch.vmcb->save.es);
	set_segment(fs, vcpu->arch.vmcb->save.fs);
	set_segment(gs, vcpu->arch.vmcb->save.gs);
	set_segment(ss, vcpu->arch.vmcb->save.ss);

	set_segment(tr, vcpu->arch.vmcb->save.tr);

	set_segment(ldt, vcpu->arch.vmcb->save.ldtr);
#undef set_segment

#define set_dtable(var, seg) \
	seg.limit = sregs->var.limit; seg.base = sregs->var.base

	set_dtable(idt, vcpu->arch.vmcb->save.idtr);
	set_dtable(gdt, vcpu->arch.vmcb->save.gdtr);
#undef set_dtable

	vcpu->arch.vmcb->save.cr2 = sregs->cr2;
	mmu_reset_needed |= vcpu->cr3 != sregs->cr3;
	vcpu->cr3 = sregs->cr3;

	vcpu->arch.vmcb->control.int_ctl &= ~V_TPR_MASK;
	vcpu->arch.vmcb->control.int_ctl |= (sregs->cr8 & V_TPR_MASK);

	mmu_reset_needed |= sregs->efer != vcpu->shadow_efer;
#ifdef __x86_64__
	__set_efer(vcpu, sregs->efer);
#endif
	vcpu->apic_base = sregs->apic_base;

	mmu_reset_needed |= guest_cr0(vcpu) != sregs->cr0;
	__set_cr0(vcpu, sregs->cr0);

	mmu_reset_needed |=  guest_cr4(vcpu) != sregs->cr4;
	__set_cr4(vcpu, sregs->cr4);

	vcpu->arch.vmcb->save.cpl = (vcpu->arch.vmcb->save.cs.atrib >> 
				     SVM_SELECTOR_DPL_SHIFT) & 3;
	if (mmu_reset_needed)
		kvm_mmu_reset_context(vcpu);

}

static void kvm_debug_guest_ctl(struct kvm_vcpu *vcpu,
				struct kvm_debug_guest *dbg)
{

}

static void load_hots_msrs(struct kvm_vcpu *vcpu)
{
	int i;

	for ( i = 0; i < NR_HOST_SAVE_MSRS; i++) {
		wrmsrl(host_save_msrs[i], vcpu->arch.host_msrs[i]);
	}
}

static void save_hots_msrs(struct kvm_vcpu *vcpu)
{
	int i;

	for ( i = 0; i < NR_HOST_SAVE_MSRS; i++)
		rdmsrl(host_save_msrs[i], vcpu->arch.host_msrs[i]);
}

static void new_asid(struct kvm_vcpu *vcpu, struct svm_cpu_data *svm_data)
{
	if (svm_data->next_asid > svm_data->max_asid) {
		++svm_data->asid_generation;
		svm_data->next_asid = 1;
		vcpu->arch.vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
	}

	vcpu->cpu = svm_data->cpu;
	vcpu->arch.asid_generation = svm_data->asid_generation;
	vcpu->arch.vmcb->control.asid = svm_data->next_asid++;
}

enum emulation_result {
	EMULATE_DONE,       /* no further processing */
	EMULATE_DO_MMIO,      /* kvm_run filled with mmio request */
	EMULATE_FAIL,         /* can't emulate this instruction */
};


static int emulator_clts(struct x86_emulate_ctxt *ctxt, unsigned long next_rip)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;
	unsigned long cr0 = guest_cr0(vcpu);

	cr0 &= ~CR0_TS_MASK;
	__set_cr0(vcpu, cr0);
	vcpu->arch.next_rip = next_rip;
	skip_emulated_instruction(vcpu);
	return 0;
}

static int emulator_invlpg(struct x86_emulate_ctxt * ctxt,
			  unsigned long address,
			  unsigned long next_rip)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	spin_lock(&vcpu->kvm->lock);
	vcpu->mmu.inval_page(vcpu, address);
	spin_unlock(&vcpu->kvm->lock);
	invlpga(address, vcpu->arch.vmcb->control.asid); // is needed?
	vcpu->arch.next_rip = next_rip;
	skip_emulated_instruction(vcpu);
	return 0;
}

static int emulator_get_dr(struct x86_emulate_ctxt * ctxt,
			   unsigned dr,
			   unsigned reg,
			   unsigned long next_rip)
{
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	switch (dr) {
	case 0 ... 3:
		if (reg > 15) {
			printk("%s: unexpected reg %u dr %u\n",
			       __FUNCTION__, reg, dr);
			inject_ud(vcpu);
			return 0;
		}
		vcpu->regs[reg] = vcpu->arch.ab_regs[dr];
		vcpu->arch.next_rip = next_rip;
		skip_emulated_instruction(vcpu);
		return 0;
	default:
		printk("%s: unexpected dr %u reg %u\n", __FUNCTION__, dr, reg);
		return -1;
	}
}

static int emulator_set_dr(struct x86_emulate_ctxt * ctxt,
			   unsigned dr,
			   unsigned reg,
			   unsigned long next_rip)
{
	unsigned long mask = (ctxt->mode == X86EMUL_MODE_PROT64) ? ~0ULL : ~0U;
	struct kvm_vcpu *vcpu = ctxt->vcpu;

	if (reg >= 8) {
		printk("%s: unexpected reg %u dr %u\n",
		       __FUNCTION__, reg, dr);
		inject_ud(vcpu);
		return 0;
	}

	if (vcpu->arch.vmcb->save.dr7 & DR7_GD_MASK) {
		vcpu->arch.vmcb->save.dr7 &= ~DR7_GD_MASK;
		vcpu->arch.vmcb->save.dr6 |= DR6_BD_MASK;
		inject_db(vcpu);
		return 0;
	}

	switch (dr) {
	case 0 ... 3:
		vcpu->arch.ab_regs[dr] = vcpu->regs[reg] & mask;
		vcpu->arch.next_rip = next_rip;
		skip_emulated_instruction(vcpu);
		return 0;
	case 5:
		if (guest_cr4(vcpu) & CR4_DE_MASK) {
			inject_ud(vcpu);
			return 0;
		}
	case 7: {
		unsigned long dr7 = vcpu->regs[reg] & mask;

		if (dr7 & ~((1ULL << 32) - 1)) {
			inject_gp(vcpu);
			return 0;
		}
		vcpu->arch.vmcb->save.dr7 = dr7;
		vcpu->arch.next_rip = next_rip;
		skip_emulated_instruction(vcpu);
		return 0;
	}
	default:
		printk("%s: unexpected dr %u reg %u\n", __FUNCTION__, dr, reg);
		return -1;
	}
}

static int emulate_instruction(struct kvm_vcpu *vcpu,
			       struct kvm_run *run,
			       unsigned long cr2,
			       u16 error_code)
{
	struct x86_emulate_ctxt emulate_ctxt;
	int r;
	struct vmcb_save_area *save_area = &vcpu->arch.vmcb->save;
	u16 cs_atrib;

	kvm_store_regs(vcpu);

	emulate_ctxt.vcpu = vcpu;
	emulate_ctxt.eflags = vcpu->rflags;
	emulate_ctxt.cr2 = cr2;

	cs_atrib = save_area->cs.atrib;
	emulate_ctxt.mode = (!(guest_cr0(vcpu) & CR0_PE_MASK) || 
			     (emulate_ctxt.eflags & X86_EFLAGS_VM)) 
		? X86EMUL_MODE_REAL : (cs_atrib & SVM_SELECTOR_L_MASK) 
		? X86EMUL_MODE_PROT64 :	(cs_atrib & SVM_SELECTOR_DB_MASK) 
		? X86EMUL_MODE_PROT32 : X86EMUL_MODE_PROT16;

	if (emulate_ctxt.mode == X86EMUL_MODE_PROT64) {
		emulate_ctxt.cs_base = 0;
		emulate_ctxt.ds_base = 0;
		emulate_ctxt.es_base = 0;
		emulate_ctxt.ss_base = 0;
	} else {
		emulate_ctxt.cs_base = save_area->cs.base;
		emulate_ctxt.ds_base = save_area->ds.base;
		emulate_ctxt.es_base = save_area->es.base;
		emulate_ctxt.ss_base = save_area->ss.base;
		
	}
	emulate_ctxt.gs_base = save_area->gs.base;
	emulate_ctxt.fs_base = save_area->fs.base;

	vcpu->mmio_is_write = 0;

	r = x86_emulate_memop(&emulate_ctxt, &emulate_ops);

	if ((r || vcpu->mmio_is_write) && run) {
		run->mmio.phys_addr = vcpu->mmio_phys_addr;
		memcpy(run->mmio.data, vcpu->mmio_data, 8);
		run->mmio.len = vcpu->mmio_size;
		run->mmio.is_write = vcpu->mmio_is_write;
	}

	if (r) {
		if (!vcpu->mmio_needed) {
			printk("%s: emulation failure\n", __FUNCTION__);
			return EMULATE_FAIL;
		}
		return EMULATE_DO_MMIO;
	}

	vcpu->rflags = emulate_ctxt.eflags;
	kvm_load_regs(vcpu);

	if (vcpu->mmio_is_write)
		return EMULATE_DO_MMIO;

	return EMULATE_DONE;
}

static int pf_interception(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	u32 exit_int_info = vcpu->arch.vmcb->control.exit_int_info;
	u64 fault_address;
	u32 error_code;
	enum emulation_result er;

	if (is_external_interrupt(exit_int_info)) {
		push_irq(vcpu, exit_int_info & SVM_EVTINJ_VEC_MASK);
	}

	spin_lock(&vcpu->kvm->lock);

	fault_address  = vcpu->arch.vmcb->control.exit_info_2;
	error_code = vcpu->arch.vmcb->control.exit_info_1;
	if (!vcpu->mmu.page_fault(vcpu, fault_address, error_code)) {
		spin_unlock(&vcpu->kvm->lock);
		return 1;
	}
	er = emulate_instruction(vcpu, kvm_run, fault_address, error_code);
	spin_unlock(&vcpu->kvm->lock);

	switch (er) {
	case EMULATE_DONE:
		return 1;
	case EMULATE_DO_MMIO:
		++kvm_stat.mmio_exits;
		kvm_run->exit_reason = KVM_EXIT_MMIO;
		return 0;
	case EMULATE_FAIL:
		vcpu_printf(vcpu, "%s: emulate fail\n", __FUNCTION__);
		break;
	default:
		BUG();
	}

	kvm_run->exit_reason = KVM_EXIT_UNKNOWN;
	return 0;
}

#define MAX_INST_SIZE 15
static int io_get_override(struct kvm_vcpu *vcpu,
			  struct vmcb_seg **seg,
			  int *addr_override)
{
	u8 inst[MAX_INST_SIZE];
	unsigned ins_length;
	gva_t rip;
	int i;
	
	rip =  vcpu->arch.vmcb->save.rip;
	ins_length = vcpu->arch.next_rip - rip;
	rip += vcpu->arch.vmcb->save.cs.base;
	
	if (ins_length > MAX_INST_SIZE) {
		printk("%s: inst length err, cs base 0x%llx rip 0x%llx "
		       "next rip 0x%llx ins_length %u\n",
		       __FUNCTION__,
		       vcpu->arch.vmcb->save.cs.base,
		       vcpu->arch.vmcb->save.rip,
		       vcpu->arch.vmcb->control.exit_info_2,
		       ins_length);
	}

	if (kvm_read_guest(vcpu, rip, ins_length, inst) != ins_length) {
		//#PF
		return 0;
	}

	*addr_override = 0;
	*seg = 0;
	for (i = 0; i < ins_length; i++) {
		switch (inst[i]) {
		case 0xf0:
		case 0xf2:
		case 0xf3:
		case 0x66:
			continue;
		case 0x67:
			*addr_override = 1;
			continue;
		case 0x2e:
			*seg = &vcpu->arch.vmcb->save.cs;
			continue;
		case 0x36:
			*seg = &vcpu->arch.vmcb->save.ss;
			continue;
		case 0x3e:
			*seg = &vcpu->arch.vmcb->save.ds;
			continue;
		case 0x26:
			*seg = &vcpu->arch.vmcb->save.es;
			continue;
		case 0x64:
			*seg = &vcpu->arch.vmcb->save.fs;
			continue;
		case 0x65:
			*seg = &vcpu->arch.vmcb->save.gs;
			continue;
		default:
			return 1;
		}
	}
	printk("%s: unexpected\n", __FUNCTION__);
	return 0;
}

static unsigned long io_adress(struct kvm_vcpu *vcpu, int ins, u64 *address)
{
	unsigned long addr_mask;
	unsigned long *reg;
	struct vmcb_seg *seg;
	int addr_override;
	struct vmcb_save_area *save_area = &vcpu->arch.vmcb->save;
	u16 cs_atrib = save_area->cs.atrib;
	unsigned addr_size = get_addr_size(vcpu);

	if (!io_get_override(vcpu, &seg, &addr_override)) {
		return 0;
	}

	if (addr_override) {
		addr_size = (addr_size == 2) ? 4: (addr_size >> 1);
	}

	if (ins) {
		reg = &vcpu->regs[VCPU_REGS_RDI];
		seg = &vcpu->arch.vmcb->save.es;
	} else {
		reg = &vcpu->regs[VCPU_REGS_RSI];
		seg = (seg) ? seg : &vcpu->arch.vmcb->save.ds;
	}
	
	addr_mask = ~0ULL >> (64 - (addr_size * 8));

	if ((cs_atrib & SVM_SELECTOR_L_MASK) &&
	    !(vcpu->arch.vmcb->save.rflags & X86_EFLAGS_VM)) {
		*address = (*reg & addr_mask);
		return addr_mask;
	}
	
	if (!(seg->atrib & SVM_SELECTOR_P_SHIFT)) {
		inject_gp(vcpu);
		return 0;
	}
	
	*address = (*reg & addr_mask) + seg->base;
	return addr_mask;
}

static int io_interception(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	u32 io_info = vcpu->arch.vmcb->control.exit_info_1; //address size bug?
	int _in = io_info & SVM_IOIO_TYPE_MASK;

	++kvm_stat.io_exits;

	vcpu->arch.next_rip = vcpu->arch.vmcb->control.exit_info_2;

	kvm_run->exit_reason = KVM_EXIT_IO;
	kvm_run->io.port = io_info >> 16;
	kvm_run->io.direction = (_in) ? KVM_EXIT_IO_IN : KVM_EXIT_IO_OUT;
	kvm_run->io.size = ((io_info & SVM_IOIO_SIZE_MASK) >> SVM_IOIO_SIZE_SHIFT);
	kvm_run->io.string = (io_info & SVM_IOIO_STR_MASK) != 0;
	kvm_run->io.rep = (io_info & SVM_IOIO_REP_MASK) != 0;

	if (kvm_run->io.string) {
		unsigned addr_maks;

		addr_maks = io_adress(vcpu, _in, &kvm_run->io.address);
		if (!addr_maks) {
			printk("%s: get io address failed\n", __FUNCTION__);
			return 1;
		}

		if (kvm_run->io.rep) { 
			kvm_run->io.count = vcpu->regs[VCPU_REGS_RCX] & addr_maks;
			kvm_run->io.string_down = (vcpu->arch.vmcb->save.rflags
						   & X86_EFLAGS_DF) != 0;
		}
	} else {
		kvm_run->io.value = vcpu->arch.vmcb->save.rax;
	}
	return 0;
}


static int nop_on_interception(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	return 1;
}

static int halt_interception(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	vcpu->arch.next_rip = vcpu->arch.vmcb->save.rip + 1;
	skip_emulated_instruction(vcpu);
	if (vcpu->irq_summary && (vcpu->arch.vmcb->save.rflags & X86_EFLAGS_IF))
		return 1;
	
	kvm_run->exit_reason = KVM_EXIT_HLT;
	return 0;
}

static int invalid_op_interception(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	inject_ud(vcpu);
	return 1;
}

static int task_switch_interception(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	printk("%s: task swiche is unsupported\n", __FUNCTION__);
	kvm_run->exit_reason = KVM_EXIT_UNKNOWN;
	return 0;
}

static int cpuid_interception(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	vcpu->arch.next_rip = vcpu->arch.vmcb->save.rip + 2;
	kvm_run->exit_reason = KVM_EXIT_CPUID;
	return 0;
}

static int emulate_on_interception(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	if (emulate_instruction(vcpu, 0, 0, 0) != EMULATE_DONE) {
		       printk("%s: failed\n", __FUNCTION__);
	}
	return 1;
}

static int rdmsr_interception(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	u32 ecx = vcpu->regs[VCPU_REGS_RCX];
	u64 data;

	switch (ecx) {
	case MSR_IA32_MC0_CTL:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MCG_CAP:
	case MSR_IA32_MC0_MISC:
	case MSR_IA32_MC0_MISC+4:
	case MSR_IA32_MC0_MISC+8:
	case MSR_IA32_MC0_MISC+12:
	case MSR_IA32_MC0_MISC+16:
	case MSR_IA32_UCODE_REV:
		/* MTRR registers */
	case 0xfe:
	case 0x200 ... 0x2ff:
		data = 0;
		break;
	case MSR_EFER:
		data = vcpu->shadow_efer;
		break;
	case MSR_IA32_APICBASE:
		data = vcpu->apic_base;
		break;
	default:
		printk(KERN_ERR "kvm: unhandled rdmsr: 0x%x\n", ecx);
		inject_gp(vcpu);
		return 1;
	}
	vcpu->arch.vmcb->save.rax = data & 0xffffffff;
	vcpu->regs[VCPU_REGS_RDX] = data >> 32;
	vcpu->arch.next_rip = vcpu->arch.vmcb->save.rip + 2;
	skip_emulated_instruction(vcpu);
	return 1;
}

static int wrmsr_interception(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	u32 ecx = vcpu->regs[VCPU_REGS_RCX];
	u64 data = (vcpu->arch.vmcb->save.rax & -1u)
		| ((u64)(vcpu->regs[VCPU_REGS_RDX] & -1u) << 32);

	switch (ecx) {
	case MSR_EFER:
		set_efer(vcpu, data);
		break;
	case MSR_IA32_MC0_STATUS:
		printk(KERN_WARNING "%s: MSR_IA32_MC0_STATUS 0x%llx, nop\n"
			    , __FUNCTION__, data);
		break;
	case MSR_IA32_TIME_STAMP_COUNTER: {
		u64 tsc;

		rdtscll(tsc);
		vcpu->arch.vmcb->control.tsc_offset = data - tsc;
		break;
	}
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_UCODE_WRITE:
	case 0x200 ... 0x2ff: /* MTRRs */
		break;
	case MSR_IA32_APICBASE:
		vcpu->apic_base = data;
		break;
	default:
		printk(KERN_ERR "kvm: unhandled wrmsr: %x\n", ecx);
		inject_gp(vcpu);
		return 1;
	}
	vcpu->arch.next_rip = vcpu->arch.vmcb->save.rip + 2;
	skip_emulated_instruction(vcpu);
	return 1;
}

static int msr_interception(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	if (vcpu->arch.vmcb->control.exit_info_1) {
		return wrmsr_interception(vcpu, kvm_run);
	} else {
		return rdmsr_interception(vcpu, kvm_run);
	}
}


static int (*svm_exit_handlers[])(struct kvm_vcpu *vcpu,
				      struct kvm_run *kvm_run) = {
	[SVM_EXIT_READ_CR0]           		= emulate_on_interception,
	[SVM_EXIT_READ_CR3]           		= emulate_on_interception,
	[SVM_EXIT_READ_CR4]           		= emulate_on_interception,
	[SVM_EXIT_WRITE_CR0]          		= emulate_on_interception, //for now
	[SVM_EXIT_WRITE_CR3]          		= emulate_on_interception,
	[SVM_EXIT_WRITE_CR4]          		= emulate_on_interception,
	[SVM_EXIT_READ_DR0] 			= emulate_on_interception,
	[SVM_EXIT_READ_DR1]			= emulate_on_interception,
	[SVM_EXIT_READ_DR2]			= emulate_on_interception,
	[SVM_EXIT_READ_DR3]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR0]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR1]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR2]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR3]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR5]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR7]			= emulate_on_interception,
	[SVM_EXIT_EXCP_BASE + PF_VECTOR] 	= pf_interception,
	[SVM_EXIT_INTR] 			= nop_on_interception,
	[SVM_EXIT_NMI]				= nop_on_interception,
	[SVM_EXIT_SMI]				= nop_on_interception,
	[SVM_EXIT_INIT]				= nop_on_interception,
	//[SVM_EXIT_CR0_SEL_WRITE]		= emulate_on_interception,
	[SVM_EXIT_CPUID]			= cpuid_interception,
	[SVM_EXIT_HLT]				= halt_interception,
	[SVM_EXIT_INVLPG]			= emulate_on_interception,
	[SVM_EXIT_INVLPGA]			= invalid_op_interception,
	[SVM_EXIT_IOIO] 		  	= io_interception,      
	[SVM_EXIT_MSR]				= msr_interception,
	[SVM_EXIT_TASK_SWITCH]			= task_switch_interception,
	[SVM_EXIT_VMRUN]			= invalid_op_interception,
	[SVM_EXIT_VMMCALL]			= invalid_op_interception,
	[SVM_EXIT_VMLOAD]			= invalid_op_interception,
	[SVM_EXIT_VMSAVE]			= invalid_op_interception,
	[SVM_EXIT_STGI]				= invalid_op_interception,
	[SVM_EXIT_CLGI]				= invalid_op_interception,
	[SVM_EXIT_SKINIT]			= invalid_op_interception,
};


static int handle_exit(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	u32 exit_code = vcpu->arch.vmcb->control.exit_code;

	kvm_run->exit_type = KVM_EXIT_TYPE_VM_EXIT;

	if (is_external_interrupt(vcpu->arch.vmcb->control.exit_int_info) &&
	    exit_code != SVM_EXIT_EXCP_BASE + PF_VECTOR) {
		printk("%s: unexpected exit_ini_info 0x%x exit_code 0x%x\n",
		       __FUNCTION__,
		       vcpu->arch.vmcb->control.exit_int_info,
		       exit_code);
	}

	if (exit_code >= sizeof(svm_exit_handlers) / sizeof(*svm_exit_handlers) 
	    || svm_exit_handlers[exit_code] == 0) {
		kvm_run->exit_reason = KVM_EXIT_UNKNOWN;
		printk("%s: 0x%x @ 0x%llx cr0 0x%lx rflags 0x%llx\n",
		       __FUNCTION__,
		       exit_code,
		       vcpu->arch.vmcb->save.rip,
		       guest_cr0(vcpu),
		       vcpu->arch.vmcb->save.rflags);
		return 0;
	}
	return svm_exit_handlers[exit_code](vcpu, kvm_run);
}

static void reload_tss(struct kvm_vcpu *vcpu)
{
	int cpu = raw_smp_processor_id();

	struct svm_cpu_data *svm_data = per_cpu(svm_data, cpu);
	svm_data->tss_desc->type = 9; //available 32/64-bit TSS
	load_TR_desc();
}

static void pre_svm_run(struct kvm_vcpu *vcpu)
{
	int cpu = raw_smp_processor_id();

	struct svm_cpu_data *svm_data = per_cpu(svm_data, cpu);

	vcpu->arch.vmcb->control.tlb_ctl = TLB_CONTROL_DO_NOTHING;
	if (vcpu->cpu != cpu || 
	    vcpu->arch.asid_generation != svm_data->asid_generation) {
		new_asid(vcpu, svm_data);
	}
}


static inline void kvm_try_inject_irq(struct kvm_vcpu *vcpu)
{
	struct vmcb_control_area *control;

	if (!vcpu->irq_summary) {
		return;
	}
	control = &vcpu->arch.vmcb->control;

	control->int_vector = pop_irq(vcpu);
	control->int_ctl &= ~V_INTR_PRIO_MASK;
	control->int_ctl |= V_IRQ_MASK | 
		((/*control->int_vector >> 4*/ 0xf) << V_INTR_PRIO_SHIFT); 
}

static void kvm_reput_irq(struct kvm_vcpu *vcpu)
{
	struct vmcb_control_area *control = &vcpu->arch.vmcb->control;

	if (control->int_ctl & V_IRQ_MASK) {
		control->int_ctl &= ~V_IRQ_MASK;
		push_irq(vcpu, control->int_vector);
	}
}

static void save_ab_regs(unsigned long *ab_regs)
{
	asm ( "mov %%dr0, %%rax \n\t"
	      "mov %%rax, %[dr0] \n\t"
	      "mov %%dr1, %%rax \n\t"
	      "mov %%rax, %[dr1] \n\t"
	      "mov %%dr2, %%rax \n\t"
	      "mov %%rax, %[dr2] \n\t"
	      "mov %%dr3, %%rax \n\t"
	      "mov %%rax, %[dr3] \n\t"
	      :
	      [dr0] "=m"(ab_regs[0]),
	      [dr1] "=m"(ab_regs[1]),
	      [dr2] "=m"(ab_regs[2]),
	      [dr3] "=m"(ab_regs[3]));
}

static void load_ab_regs(unsigned long *ab_regs)
{
	asm ( "mov %[dr0], %%dr0 \n\t"
	      "mov %[dr1], %%dr1 \n\t"
	      "mov %[dr2], %%dr2 \n\t"
	      "mov %[dr3], %%dr3 \n\t"
	       ::
		[dr0] "r"(ab_regs[0]),
		[dr1] "r"(ab_regs[1]), 
		[dr2] "r"(ab_regs[2]),
		[dr3] "r"(ab_regs[3]));
}

static int kvm_do_run(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	u16 fs_selector;
	u16 gs_selector;
	u16 ldt_selector;

	kvm_try_inject_irq(vcpu);

	clgi();

	pre_svm_run(vcpu);

	save_hots_msrs(vcpu);
	fs_selector = read_fs();
	gs_selector = read_gs();
	ldt_selector = read_ldt();
	vcpu->arch.host_cr2 = read_cr2();
	vcpu->arch.host_dr6 = read_dr6();
	vcpu->arch.host_dr7 = read_dr7();

	if (vcpu->arch.vmcb->save.dr7 & 0xff) {
		write_dr7(0);
		save_ab_regs(vcpu->arch.host_ab_regs);
		load_ab_regs(vcpu->arch.ab_regs);
	}
	asm (
#ifdef __x86_64__
		"push %%rbx; push %%rcx; push %%rdx;"
		"push %%rsi; push %%rdi; push %%rbp;"
		"push %%r8;  push %%r9;  push %%r10; push %%r11;"
		"push %%r12; push %%r13; push %%r14; push %%r15;"
#else
		"push %%ebx; push %%rcx push %%edx;"
		"push %%esi; push %%edi; push %%ebp;"
#endif

#ifdef __x86_64__
		"mov %c[rbx](%[vcpu]), %%rbx \n\t"
		"mov %c[rcx](%[vcpu]), %%rcx \n\t"
		"mov %c[rdx](%[vcpu]), %%rdx \n\t"	
		"mov %c[rsi](%[vcpu]), %%rsi \n\t"	
		"mov %c[rdi](%[vcpu]), %%rdi \n\t"	
		"mov %c[rbp](%[vcpu]), %%rbp \n\t"	
		"mov %c[r8](%[vcpu]),  %%r8  \n\t"	
		"mov %c[r9](%[vcpu]),  %%r9  \n\t"	
		"mov %c[r10](%[vcpu]), %%r10 \n\t"
		"mov %c[r11](%[vcpu]), %%r11 \n\t"
		"mov %c[r12](%[vcpu]), %%r12 \n\t"
		"mov %c[r13](%[vcpu]), %%r13 \n\t"
		"mov %c[r14](%[vcpu]), %%r14 \n\t"
		"mov %c[r15](%[vcpu]), %%r15 \n\t"
#else
		"mov %c[rbx](%[vcpu]), %%ebx \n\t"
		"mov %c[rcx](%[vcpu]), %%ecx \n\t"
		"mov %c[rdx](%[vcpu]), %%edx \n\t"
		"mov %c[rsi](%[vcpu]), %%esi \n\t"
		"mov %c[rdi](%[vcpu]), %%edi \n\t"
		"mov %c[rbp](%[vcpu]), %%ebp \n\t"   
#endif

		/* Enter guest mode */
		"push %%rax \n\t"
		"mov %c[vmcb](%[vcpu]), %%rax \n\t"
		"vmload \n\t"
		"vmrun \n\t"
		"vmsave \n\t"
		"pop %%rax \n\t"

		/* Save guest registers, load host registers */
#ifdef __x86_64__
		"mov %%rbx, %c[rbx](%[vcpu]) \n\t"
		"mov %%rcx, %c[rcx](%[vcpu]) \n\t"
		"mov %%rdx, %c[rdx](%[vcpu]) \n\t"
		"mov %%rsi, %c[rsi](%[vcpu]) \n\t"
		"mov %%rdi, %c[rdi](%[vcpu]) \n\t"
		"mov %%rbp, %c[rbp](%[vcpu]) \n\t"
		"mov %%r8,  %c[r8](%[vcpu]) \n\t"
		"mov %%r9,  %c[r9](%[vcpu]) \n\t"
		"mov %%r10, %c[r10](%[vcpu]) \n\t"
		"mov %%r11, %c[r11](%[vcpu]) \n\t"
		"mov %%r12, %c[r12](%[vcpu]) \n\t"
		"mov %%r13, %c[r13](%[vcpu]) \n\t"
		"mov %%r14, %c[r14](%[vcpu]) \n\t"
		"mov %%r15, %c[r15](%[vcpu]) \n\t"

		"pop  %%r15; pop  %%r14; pop  %%r13; pop  %%r12;"
		"pop  %%r11; pop  %%r10; pop  %%r9;  pop  %%r8;"	
		"pop  %%rbp; pop  %%rdi; pop  %%rsi;"	
		"pop  %%rdx; pop  %%rcx; pop  %%rbx; \n\t"
#else
		"mov %%ebx, %c[rbx](%3) \n\t"
		"mov %%ecx, %c[rcx](%3) \n\t"
		"mov %%edx, %c[rdx](%3) \n\t"
		"mov %%esi, %c[rsi](%3) \n\t"
		"mov %%edi, %c[rdi](%3) \n\t"
		"mov %%ebp, %c[rbp](%3) \n\t"

		"pop  %%ebp; pop  %%edi; pop  %%esi;"	
		"pop  %%edx; pop  %%ecx; pop  %%ebx; \n\t"
#endif
	      : : [vcpu]"a"(vcpu),
		[vmcb]"i"(offsetof(struct kvm_vcpu, arch.vmcb_pa)),
		[rbx]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_RBP])),
#ifdef __x86_64__
		[r8 ]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_R8 ])),
		[r9 ]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_R9 ])),
		[r10]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct kvm_vcpu, regs[VCPU_REGS_R15]))
#endif
	      : "cc", "memory" );

	if ((vcpu->arch.vmcb->save.dr7 & 0xff)) {
		load_ab_regs(vcpu->arch.host_ab_regs);
	}
	write_dr6(vcpu->arch.host_dr6);
	write_dr7(vcpu->arch.host_dr7);
	write_cr2(vcpu->arch.host_cr2);

	load_fs(fs_selector);
	load_gs(gs_selector);
	load_ldt(ldt_selector);
	load_hots_msrs(vcpu);

	reload_tss(vcpu);

	stgi();

	kvm_reput_irq(vcpu);

	vcpu->arch.next_rip = 0;
	
	if (vcpu->arch.vmcb->control.exit_code == SVM_EXIT_ERR) {
		kvm_run->exit_type = KVM_EXIT_TYPE_FAIL_ENTRY;
		kvm_run->exit_reason = vcpu->arch.vmcb->control.exit_code;
		return 0;
	}

	return handle_exit(vcpu, kvm_run);
}

struct debugfs_ent debugfs_vec[] = {
	{ 0, 0, 0 }
};

#include "kvm_main.c"
#include "x86_emulate.c"

static void flush_vm_tlb(struct kvm_vcpu *vcpu)
{
	force_new_asid(vcpu);
}


static void load_vm_cr3(struct kvm_vcpu *vcpu, unsigned long root)
{
	vcpu->arch.vmcb->save.cr3 = root;
	force_new_asid(vcpu);
}


static void inject_page_fault(struct kvm_vcpu *vcpu,
			      uint64_t addr,
			      uint32_t err_code)
{
	uint32_t exit_int_info = vcpu->arch.vmcb->control.exit_int_info;
	
	++kvm_stat.pf_guest;

	if (is_page_fault(exit_int_info)) {

		vcpu->arch.vmcb->control.event_inj_err = 0; 
		vcpu->arch.vmcb->control.event_inj = 	SVM_EVTINJ_VALID |
							SVM_EVTINJ_VALID_ERR |
							SVM_EVTINJ_TYPE_EXEPT |
							DF_VECTOR;
		return;
	}
	vcpu->arch.vmcb->save.cr2 = addr;
	vcpu->arch.vmcb->control.event_inj = 	SVM_EVTINJ_VALID |
						SVM_EVTINJ_VALID_ERR |
						SVM_EVTINJ_TYPE_EXEPT |
						PF_VECTOR;
	vcpu->arch.vmcb->control.event_inj_err = err_code;	
}

#include "mmu.c"

