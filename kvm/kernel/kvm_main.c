/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 */

#include "kvm.h"

#include <linux/kvm.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <asm/processor.h>
#include <linux/percpu.h>
#include <linux/gfp.h>
#include <asm/msr.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <linux/reboot.h>
#include <asm/io.h>
#include <linux/debugfs.h>
#include <linux/highmem.h>
#include <linux/file.h>

#include "vmx.h"
#include "x86_emulate.h"
#include "mmu.h"

MODULE_AUTHOR("Qumranet");
MODULE_LICENSE("GPL");

static struct dentry *debugfs_dir;
static struct dentry *debugfs_pf_fixed;
static struct dentry *debugfs_pf_guest;
static struct dentry *debugfs_tlb_flush;
static struct dentry *debugfs_invlpg;
static struct dentry *debugfs_exits;
static struct dentry *debugfs_io_exits;
static struct dentry *debugfs_mmio_exits;
static struct dentry *debugfs_signal_exits;
static struct dentry *debugfs_irq_exits;

struct kvm_stat kvm_stat;

#define KVM_LOG_BUF_SIZE PAGE_SIZE

static const u32 vmx_msr_index[] = {
	MSR_EFER, MSR_STAR, MSR_CSTAR,
	MSR_KERNEL_GS_BASE, MSR_SYSCALL_MASK, MSR_LSTAR
};
#define NR_VMX_MSR (sizeof(vmx_msr_index) / sizeof(*vmx_msr_index))


#define NUM_AUTO_MSRS 4 // avoid save/load MSR_SYSCALL_MASK and MSR_LSTAR
			// by std vt mechanism (cpu bug AA24)


static struct vmx_msr_entry *find_msr_entry(struct kvm_vcpu *vcpu, u32 msr)
{
	int i;

	for (i = 0; i < NR_VMX_MSR; ++i)
		if (vmx_msr_index[i] == msr)
			return &vcpu->guest_msrs[i];
	return 0;
}

struct descriptor_table {
	u16 limit;
	unsigned long base;
} __attribute__((packed));

static void get_gdt(struct descriptor_table *table)
{
	asm ( "sgdt %0" : "=m"(*table) );
}

static void get_idt(struct descriptor_table *table)
{
	asm ( "sidt %0" : "=m"(*table) );
}

static u16 read_fs(void)
{
	u16 seg;
	asm ( "mov %%fs, %0" : "=g"(seg) );
	return seg;
}

static u16 read_gs(void)
{
	u16 seg;
	asm ( "mov %%gs, %0" : "=g"(seg) );
	return seg;
}

static unsigned long get_eflags(void)
{
	unsigned long x;
	asm ( "pushf; pop %0" : "=m"(x) );
	return x;
}

static void fx_save(void *image)
{
	asm ( "fxsave (%0)":: "r" (image));
}

static void fx_restore(void *image)
{
	asm ( "fxrstor (%0)":: "r" (image));
}

struct segment_descriptor {
	u16 limit_low;
	u16 base_low;
	u8  base_mid;
	u8  type : 4;
	u8  system : 1;
	u8  dpl : 2;
	u8  present : 1;
	u8  limit_high : 4;
	u8  avl : 1;
	u8  long_mode : 1;
	u8  default_op : 1;
	u8  granularity : 1;
	u8  base_high;
} __attribute__((packed));

#ifdef __x86_64__
// LDT or TSS descriptor in the GDT. 16 bytes.
struct segment_descriptor_64 {
	struct segment_descriptor s;
	u32 base_higher;
	u32 pad_zero;
} __attribute__((packed));

#endif

static unsigned long segment_base(u16 selector)
{
	struct descriptor_table gdt;
	struct segment_descriptor *d;
	unsigned long table_base;
	typedef unsigned long ul;
	unsigned long v;

	asm ( "sgdt %0" : "=m"(gdt) );
	table_base = gdt.base;

	if (selector & 4) {           /* from ldt */
		u16 ldt_selector;

		asm ( "sldt %0" : "=g"(ldt_selector) );
		table_base = segment_base(ldt_selector);
	}
	d = (struct segment_descriptor *)(table_base + (selector & ~7));
	v = d->base_low | ((ul)d->base_mid << 16) | ((ul)d->base_high << 24);
	if (d->system == 0
	    && (d->type == 2 || d->type == 9 || d->type == 11))
		v |= ((ul)((struct segment_descriptor_64 *)d)->base_higher) << 32;
	return v;
}

static unsigned long read_tr_base(void)
{
	u16 tr;
	asm ( "str %0" : "=g"(tr) );
	return segment_base(tr);
}

DEFINE_PER_CPU(struct vmcs *, vmxarea);
DEFINE_PER_CPU(struct vmcs *, current_vmcs);

static struct vmcs_descriptor {
	int size;
	int order;
	u32 revision_id;
} vmcs_descriptor;

#define MSR_IA32_FEATURE_CONTROL 0x03a
#define MSR_IA32_VMX_BASIC_MSR   0x480

static unsigned long read_msr(unsigned long msr)
{
	u64 value;
	
	rdmsrl(msr, value);
	return value;
}

static __init void setup_vmcs_descriptor(void)
{
	u32 vmx_msr_low, vmx_msr_high;

	rdmsr(MSR_IA32_VMX_BASIC_MSR, vmx_msr_low, vmx_msr_high);
	vmcs_descriptor.size = vmx_msr_high & 0x1fff;
	vmcs_descriptor.order = get_order(vmcs_descriptor.size);
	vmcs_descriptor.revision_id = vmx_msr_low;
};

static void vmcs_clear(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile ( "vmclear %1; setna %0"
		       : "=m"(error) : "m"(phys_addr) : "cc", "memory" );
	if (error)
		printk(KERN_ERR "kvm: vmclear fail: %p/%llx\n",
		       vmcs, phys_addr);
}

static void __vcpu_clear(void *arg)
{
	struct kvm_vcpu *vcpu = arg;
	int cpu = smp_processor_id();

	if (vcpu->cpu == cpu)
		vmcs_clear(vcpu->vmcs);
	if (per_cpu(current_vmcs, cpu) == vcpu->vmcs)
		per_cpu(current_vmcs, cpu) = 0;
}

/*
 * Switches to specified vcpu, until a matching vcpu_put()
 */
static void vcpu_load(struct kvm_vcpu *vcpu)
{
	u64 phys_addr = __pa(vcpu->vmcs);
	int cpu;
	
	mutex_lock(&vcpu->mutex);
	
	cpu = get_cpu();
	
	if (vcpu->cpu != cpu) {
		smp_call_function(__vcpu_clear, vcpu, 0, 1);
		vcpu->launched = 0;
	}

	if (per_cpu(current_vmcs, cpu) != vcpu->vmcs) {
		u8 error;

		per_cpu(current_vmcs, cpu) = vcpu->vmcs;
		asm volatile ( "vmptrld %1; setna %0"
			       : "=m"(error) : "m"(phys_addr) : "cc" );
		if (error)
			printk(KERN_ERR "kvm: vmptrld %p/%llx fail\n",
			       vcpu->vmcs, phys_addr);
	}

	if (vcpu->cpu != cpu) {
		struct descriptor_table dt;

		vcpu->cpu = cpu;
		/*
		 * Linux uses per-cpu TSS and GDT, so set these when switching
		 * processors.
		 */
		vmcs_writel(HOST_TR_BASE, read_tr_base()); /* 22.2.4 */
		get_gdt(&dt);
		vmcs_writel(HOST_GDTR_BASE, dt.base);   /* 22.2.4 */
	}
}

static void vcpu_put(struct kvm_vcpu *vcpu)
{
	put_cpu();
	mutex_unlock(&vcpu->mutex);
}

static struct vmcs *alloc_vmcs_cpu(int cpu)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	struct vmcs *vmcs;

	pages = alloc_pages_node(node, GFP_KERNEL, vmcs_descriptor.order);
	if (!pages)
		return 0;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_descriptor.size);
	vmcs->revision_id = vmcs_descriptor.revision_id; /* vmcs revision id */
	return vmcs;
}

static struct vmcs *alloc_vmcs(void)
{
	return alloc_vmcs_cpu(smp_processor_id());
}

static void free_vmcs(struct vmcs *vmcs)
{
	free_pages((unsigned long)vmcs, vmcs_descriptor.order);
}

static __init int cpu_has_kvm_support(void)
{
	unsigned long ecx = cpuid_ecx(1);
	return test_bit(5, &ecx); /* CPUID.1:ECX.VMX[bit 5] -> VT */
}

static __exit void free_kvm_area(void)
{
	int cpu;

	for_each_online_cpu(cpu)
		free_vmcs(per_cpu(vmxarea, cpu));
}

static __init int alloc_kvm_area(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct vmcs *vmcs;

		vmcs = alloc_vmcs_cpu(cpu);
		if (!vmcs) {
			free_kvm_area();
			return -ENOMEM;
		}
		
		per_cpu(vmxarea, cpu) = vmcs;
	}
	return 0;
}

static __init int vmx_disabled_by_bios(void)
{
	u64 msr;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, msr);
	return (msr & 5) == 1; /* locked but not enabled */
}		

#define CR4_VMXE 0x2000

static __init void kvm_enable(void *garbage)
{
	int cpu = raw_smp_processor_id();
	u64 phys_addr = __pa(per_cpu(vmxarea, cpu));
	u64 old;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);
	if ((old & 5) == 0)
		/* enable and lock */
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | 5);
	write_cr4(read_cr4() | CR4_VMXE); /* FIXME: not cpu hotplug safe */
	asm volatile ( "vmxon %0" : : "m"(phys_addr) : "memory", "cc" );
}

static void kvm_disable(void *garbage)
{
	asm volatile ( "vmxoff" : : : "cc" );
}

static int kvm_dev_open(struct inode *inode, struct file *filp)
{
	struct kvm *kvm = kzalloc(sizeof(struct kvm), GFP_KERNEL);

	if (!kvm)
		return -ENOMEM;
	
	INIT_LIST_HEAD(&kvm->active_mmu_pages);
	filp->private_data = kvm;
	return 0;
}

static void kvm_free_physmem_slot(struct kvm *kvm, int slot)
{
	struct kvm_memory_slot *memslot = &kvm->memslots[slot];
	unsigned long i;

	if (!memslot->npages)
		return;

	for (i = 0; i < memslot->npages; ++i)
		__free_page(memslot->phys_mem[i]);
	vfree(memslot->phys_mem);
	memslot->phys_mem = 0;
	memslot->npages = 0;
	vfree(memslot->dirty_bitmap);
	memslot->dirty_bitmap = 0;
}

static void kvm_free_physmem(struct kvm *kvm)
{
	int i;
	
	for (i = 0; i < kvm->nmemslots; ++i)
		kvm_free_physmem_slot(kvm, i);
}

static void kvm_free_vmcs(struct kvm_vcpu *vcpu)
{
	if (vcpu->vmcs) {
		on_each_cpu(__vcpu_clear, vcpu, 0, 1);
		free_vmcs(vcpu->vmcs);
		vcpu->vmcs = 0;
	}
}

static void kvm_free_vcpu(struct kvm_vcpu *vcpu)
{
	kvm_free_vmcs(vcpu);
	kvm_mmu_destroy(vcpu);
}

static void kvm_free_vcpus(struct kvm *kvm)
{
	unsigned int i;

	for (i = 0; i < kvm->nvcpus; ++i)
		kvm_free_vcpu(&kvm->vcpus[i]);
}

void kvm_log(struct kvm *kvm, const char *data, size_t count)
{
	struct file* f = kvm->log_file;

	mm_segment_t fs = get_fs();
	ssize_t ret;
		
	if (!f)
		return;

	set_fs(KERNEL_DS);
	ret = vfs_write(f, data, count, &f->f_pos);
	set_fs(fs);
	if (ret != count) {
		printk("%s: ret(%ld) != count(%ld) \n",
		       __FUNCTION__,
		       ret,
		       count);
	}
}

int kvm_vprintf(struct kvm *kvm, const char *fmt, va_list args)
{
	int i;

	if (!kvm->log_file)
		return 0;

	i = vsnprintf(kvm->log_buf, KVM_LOG_BUF_SIZE, fmt, args);
	kvm_log(kvm, kvm->log_buf, strlen(kvm->log_buf));

	return i;
}

/**
 * Writes text to the kvm log file.  Must not be called under vcpu_load()
 * context.
 */
int kvm_printf(struct kvm *kvm, const char *fmt, ...)
{
	va_list args;
	int i;

	if (!kvm->log_file)
		return 0;

	va_start(args, fmt);

	i = kvm_vprintf(kvm, fmt, args);

	va_end(args);
	return i;
}

/**
 * Writes text to the kvm log file.  Must be called under vcpu_load() context.
 */
int vcpu_printf(struct kvm_vcpu *vcpu, const char *fmt, ...)
{
	va_list args;
	int i;

	if (!vcpu->kvm->log_file)
		return 0;

	vcpu_put(vcpu);

	va_start(args, fmt);
	i = kvm_vprintf(vcpu->kvm, fmt, args);
	va_end(args);

	vcpu_load(vcpu);

	return i;
}

static int kvm_dev_release(struct inode *inode, struct file *filp)
{
	struct kvm *kvm = filp->private_data;
	
	kvm_free_vcpus(kvm);
	kvm_free_physmem(kvm);
	if (kvm->log_file)
		fput(kvm->log_file);
	kfree(kvm->log_buf);
	kfree(kvm);
	return 0;
}

unsigned long vmcs_readl(unsigned long field)
{
	unsigned long value;
	
	asm volatile ( "vmread %1, %0" : "=g"(value) : "r"(field) : "cc" );
	return value;
}

void vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile ( "vmwrite %1, %2; setna %0"
		       : "=g"(error) : "r"(value), "r"(field) : "cc" );
	if (error)
		printk(KERN_ERR "vmwrite error: reg %lx value %lx (err %d)\n",
		       field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
}

static void vmcs_write16(unsigned long field, u16 value)
{
	vmcs_writel(field, value);
}

static void vmcs_write64(unsigned long field, u64 value)
{
#ifdef __x86_64__
	vmcs_writel(field, value);
#else
	vmcs_writel(field, value);
	asm volatile ( "" );
	vmcs_writel(field+1, value >> 32);
#endif
}

#ifdef __x86_64__
#define HOST_IS_64 1
#else
#define HOST_IS_64 0
#endif
	
#define GUEST_IS_64 HOST_IS_64

/*
 * Sets up the vmcs for a 64-bit (or 32-bit on i386) guest.  All of the
 * required registers are set.  Some will be overwritten since the vcpu
 * will typically start from a different state.
 */
static int kvm_vcpu_setup(struct kvm_vcpu *vcpu)
{
	extern asmlinkage void kvm_vmx_return(void);
	u32 host_sysenter_cs;
	u32 junk;
	unsigned long a;
	struct descriptor_table dt;
	int i;
	int ret;
	u64 tsc;
	
	vcpu_load(vcpu);

	vcpu->cr8 = 0;
	vcpu->shadow_efer = read_msr(MSR_EFER);
	fx_save(vcpu->guest_fx_image);

	/* Segments */
	vmcs_write16(GUEST_CS_SELECTOR, 16);
	vmcs_write16(GUEST_DS_SELECTOR, 24);
	vmcs_write16(GUEST_ES_SELECTOR, 24);
	vmcs_write16(GUEST_FS_SELECTOR, 24);
	vmcs_write16(GUEST_GS_SELECTOR, 24);
	vmcs_write16(GUEST_SS_SELECTOR, 24);

	vmcs_write16(GUEST_TR_SELECTOR, 8);  /* 22.3.1.2 */
	vmcs_writel(GUEST_TR_BASE, 0);  /* 22.3.1.2 */
	vmcs_write16(GUEST_LDTR_SELECTOR, 0);  /* 22.3.1.2 */
	vmcs_writel(GUEST_LDTR_BASE, 0);  /* 22.3.1.2 */

	vmcs_write32(GUEST_CS_LIMIT, -1u);
	vmcs_write32(GUEST_DS_LIMIT, -1u);
	vmcs_write32(GUEST_ES_LIMIT, -1u);
	vmcs_write32(GUEST_FS_LIMIT, -1u);
	vmcs_write32(GUEST_GS_LIMIT, -1u);
	vmcs_write32(GUEST_SS_LIMIT, -1u);

	vmcs_writel(GUEST_CS_BASE, 0);  /* 22.3.1.2 */
	vmcs_writel(GUEST_DS_BASE, 0);  /* 22.3.1.2 */
	vmcs_writel(GUEST_ES_BASE, 0);  /* 22.3.1.2 */
	vmcs_writel(GUEST_FS_BASE, 0);  /* 22.3.1.2 */
	vmcs_writel(GUEST_GS_BASE, 0);  /* 22.3.1.2 */
	vmcs_writel(GUEST_SS_BASE, 0);  /* 22.3.1.2 */

	vmcs_write32(GUEST_LDTR_LIMIT, 0);
	vmcs_write32(GUEST_TR_LIMIT, 4095); /* 22.3.1.1 */

	vmcs_write32(GUEST_CS_AR_BYTES, 0x809b
		     | (GUEST_IS_64 << 13)    /* L bit; 22.3.1.2 */
		     | (!GUEST_IS_64 << 14)); /* 22.3.1.2 */
	vmcs_write32(GUEST_DS_AR_BYTES, 0xc093);  /* 22.3.1.2 */
	vmcs_write32(GUEST_ES_AR_BYTES, 0xc093);  /* 22.3.1.2 */
	vmcs_write32(GUEST_FS_AR_BYTES, 0xc093);  /* 22.3.1.2 */
	vmcs_write32(GUEST_GS_AR_BYTES, 0xc093);  /* 22.3.1.2 */
	vmcs_write32(GUEST_SS_AR_BYTES, 0xc093);  /* 22.3.1.2 */

	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x1c082); /* 22.3.1.2 */
	vmcs_write32(GUEST_TR_AR_BYTES, 0x808b);   /* 22.3.1.2 */

	vmcs_write32(GUEST_SYSENTER_CS, 0);  /* 22.3.1.1 */
	vmcs_writel(GUEST_SYSENTER_ESP, 0);  /* 22.3.1.1 */
	vmcs_writel(GUEST_SYSENTER_EIP, 0);  /* 22.3.1.1 */

	vmcs_writel(GUEST_RFLAGS, get_eflags() & ~0x200ul);  /* 22.3.1.2 , 22.3.1.4*/
	vmcs_writel(GUEST_RIP, 0); /* 22.3.1.4 */
	vmcs_writel(GUEST_RSP, 0);

	vmcs_writel(GUEST_CR0, read_cr0());  /* 22.3.1.1 */
	vmcs_writel(CR0_READ_SHADOW, read_cr0() & ~CR0_PG_MASK);
	vmcs_writel(GUEST_CR4, read_cr4());  /* 22.3.1.1, 22.3.1.6 */
	vmcs_writel(CR4_READ_SHADOW, read_cr4());
	vmcs_writel(GUEST_CR3, 0);  /* 22.3.1.1; */
	vmcs_writel(GUEST_DR7, 0x400);

	vmcs_writel(GUEST_GDTR_BASE, 0);   /* 22.3.1.3 */
	vmcs_write32(GUEST_GDTR_LIMIT, 0xffff);  /* 22.3.1.3 */
	vmcs_writel(GUEST_IDTR_BASE, 0);   /* 22.3.1.3 */
	vmcs_write32(GUEST_IDTR_LIMIT, 0xffff);  /* 22.3.1.3 */

	vmcs_write32(GUEST_ACTIVITY_STATE, 0); /* 22.3.1.5 */
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0); /* 22.3.1.5 */
	vmcs_write32(GUEST_PENDING_DBG_EXCEPTIONS, 0); /* 22.3.1.5 */

	/* I/O */
	vmcs_write64(IO_BITMAP_A, 0);
	vmcs_write64(IO_BITMAP_B, 0);

	rdtscll(tsc);
	vmcs_write64(TSC_OFFSET, -tsc);

	/* vmcs link (?) */
	vmcs_write64(VMCS_LINK_POINTER, -1ull); /* 22.3.1.5 */

	/* Special registers */
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	/* Control */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
		     PIN_BASED_EXT_INTR_MASK   /* 20.6.1 */
		     | PIN_BASED_NMI_EXITING   /* 20.6.1 */
		     | 0x16   /* reserved, 22.2.1, 20.6.1 */
		);
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
		     CPU_BASED_HLT_EXITING         /* 20.6.2 */
		     | CPU_BASED_CR8_LOAD_EXITING    /* 20.6.2 */
		     | CPU_BASED_CR8_STORE_EXITING   /* 20.6.2 */
		     | CPU_BASED_UNCOND_IO_EXITING   /* 20.6.2 */
		     | CPU_BASED_INVDPG_EXITING
		     | CPU_BASED_MOV_DR_EXITING
		     | CPU_BASED_USE_TSC_OFFSETING   /* 21.3 */
		     | 0x401e172    /* reserved, 22.2.1, 20.6.2 */
		);
	vmcs_write32(EXCEPTION_BITMAP, 1 << 14); /* want page faults */
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	vmcs_write32(CR3_TARGET_COUNT, 0);           /* 22.2.1 */

	vmcs_writel(HOST_CR0, read_cr0());  /* 22.2.3 */
	vmcs_writel(HOST_CR4, read_cr4());  /* 22.2.3, 22.2.5 */
	vmcs_writel(HOST_CR3, read_cr3());  /* 22.2.3  FIXME: shadow tables */

	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);  /* 22.2.4 */
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_FS_SELECTOR, read_fs());    /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, read_gs());    /* 22.2.4 */
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
#ifdef __x86_64__
	rdmsrl(MSR_FS_BASE, a);
	vmcs_writel(HOST_FS_BASE, a); /* 22.2.4 */
	rdmsrl(MSR_GS_BASE, a);
	vmcs_writel(HOST_GS_BASE, a); /* 22.2.4 */
#else
	vmcs_writel(HOST_FS_BASE, 0); /* 22.2.4 */
	vmcs_writel(HOST_GS_BASE, 0); /* 22.2.4 */
#endif

	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);  /* 22.2.4 */

	get_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.base);   /* 22.2.4 */


	vmcs_writel(HOST_RIP, (unsigned long)kvm_vmx_return); /* 22.2.5 */

	rdmsr(MSR_IA32_SYSENTER_CS, host_sysenter_cs, junk);
	vmcs_write32(HOST_IA32_SYSENTER_CS, host_sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_ESP, a);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, a);   /* 22.2.3 */
	rdmsrl(MSR_IA32_SYSENTER_EIP, a);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, a);   /* 22.2.3 */

	vmcs_write32(VM_EXIT_CONTROLS,   /* 20.7.1 */
		     (HOST_IS_64 << 9)   /* address space size */
		     | 0x36dff           /* reserved, 22.2,1, 20.7.1 */
		);
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, NUM_AUTO_MSRS); /* 22.2.2 */
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, NUM_AUTO_MSRS);  /* 22.2.2 */
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, NUM_AUTO_MSRS); /* 22.2.2 */

	ret = -ENOMEM;
	vcpu->guest_msrs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!vcpu->guest_msrs)
		goto out;
	vcpu->host_msrs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!vcpu->host_msrs)
		goto out_free_guest_msrs;

	for (i = 0; i < NR_VMX_MSR; ++i) {
		u32 index = vmx_msr_index[i];
		u64 data;

		rdmsrl(index, data);
		vcpu->host_msrs[i].index = index;
		vcpu->host_msrs[i].reserved = 0;
		vcpu->host_msrs[i].data = data;
		vcpu->guest_msrs[i] = vcpu->host_msrs[i];
	}

	/* unused for now due to a VT bug */
	vmcs_writel(VM_ENTRY_MSR_LOAD_ADDR, virt_to_phys(vcpu->guest_msrs));
	vmcs_writel(VM_EXIT_MSR_STORE_ADDR, virt_to_phys(vcpu->guest_msrs));
	vmcs_writel(VM_EXIT_MSR_LOAD_ADDR, virt_to_phys(vcpu->host_msrs));

	vmcs_write32(VM_ENTRY_CONTROLS, /* 20.8.1 */
		     (GUEST_IS_64 << 9) /* address space size, 22.2.5 */
		     | 0x11ff           /* reserved, 22.2.1, 20.8.1 */
		);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);  /* 22.2.1 */

	vmcs_writel(CR0_GUEST_HOST_MASK, KVM_GUEST_CR0_MASK);
	vmcs_writel(CR4_GUEST_HOST_MASK, KVM_GUEST_CR4_MASK);

	vmcs_writel(VIRTUAL_APIC_PAGE_ADDR, 0);
	vmcs_writel(TPR_THRESHOLD, 0);

	ret = kvm_mmu_init(vcpu);

	vcpu_put(vcpu);
	return ret;

out_free_guest_msrs:
	kfree(vcpu->guest_msrs);
out:
	vcpu_put(vcpu);
	return ret;
}

/*
 * Sync the rsp and rip registers into the vcpu structure.  This allows
 * registers to be accessed by indexing vcpu->regs.
 */
static void vcpu_load_rsp_rip(struct kvm_vcpu *vcpu)
{
	vcpu->regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
	vcpu->rip = vmcs_readl(GUEST_RIP);
}

/*
 * Syncs rsp and rip back into the vmcs.  Should be called after possible
 * modification.
 */
static void vcpu_put_rsp_rip(struct kvm_vcpu *vcpu)
{
	vmcs_writel(GUEST_RSP, vcpu->regs[VCPU_REGS_RSP]);
	vmcs_writel(GUEST_RIP, vcpu->rip);
}

/*
 * Sets up an fd to act as a log file.  Optional.
 */
static int kvm_dev_ioctl_set_logfd(struct kvm *kvm, int fd)
{
	int r;

	r = -ENOMEM;
	if (!kvm->log_buf)
		kvm->log_buf = kmalloc(KVM_LOG_BUF_SIZE, GFP_KERNEL);
	if (!kvm->log_buf)
		goto out;

	if (kvm->log_file)
		fput(kvm->log_file);

	kvm->log_file = fget(fd);

        kvm_printf(kvm, "%s: kvm log start.\n", __FUNCTION__);

	return 0;

out:
	return r;
}

/*
 * Creates some virtual cpus.  Good luck creating more than one.
 */
static int kvm_dev_ioctl_create_vcpus(struct kvm *kvm, int n)
{
	int i, r;

	r = -EINVAL;
	if (n < 0 || kvm->nvcpus + n > KVM_MAX_VCPUS)
		goto out;

	for (i = kvm->nvcpus; i < kvm->nvcpus + n; ++i) {
		struct kvm_vcpu *vcpu = &kvm->vcpus[i];
		struct vmcs *vmcs;

		mutex_init(&vcpu->mutex);
		INIT_LIST_HEAD(&vcpu->free_pages);
		vcpu->mmu.root_hpa = INVALID_PAGE;

		vcpu->host_fx_image = (char*)ALIGN((hva_t)vcpu->fx_buf,
						   FX_IMAGE_ALIGN);
		vcpu->guest_fx_image = vcpu->host_fx_image + FX_IMAGE_SIZE;


		vcpu->cpu = -1;  /* First load will set up TR */
		vcpu->kvm = kvm;
		vmcs = alloc_vmcs();
		if (!vmcs)
			goto out_free_vcpus;
		vmcs_clear(vmcs);
		vcpu->vmcs = vmcs;
		vcpu->launched = 0;

		r = kvm_vcpu_setup(vcpu);
		if (r < 0)
			goto out_free_vcpus;
	}

	kvm->nvcpus = i;

	return 0;

out_free_vcpus:
	for ( ; i >= kvm->nvcpus; --i)
		kvm_free_vcpu(&kvm->vcpus[i]);
out:
	return r;
}		

/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 */
static int kvm_dev_ioctl_set_memory_region(struct kvm *kvm,
					   struct kvm_memory_region *mem)
{
	int r;
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long i;
	struct kvm_memory_slot *memslot;

	r = -EINVAL;
	/* General sanity checks */
	if (mem->memory_size & (PAGE_SIZE - 1))
		goto out;
	if (mem->guest_phys_addr & (PAGE_SIZE - 1))
		goto out;
	if (mem->slot >= KVM_MEMORY_SLOTS)
		goto out;
	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		goto out;

	memslot = &kvm->memslots[mem->slot];
	base_gfn = mem->guest_phys_addr >> PAGE_SHIFT;
	npages = mem->memory_size >> PAGE_SHIFT;

	/* Disallow changing a memory slot's size. */
	if (npages && memslot->npages && npages != memslot->npages)
		goto out;

	/* Check for overlaps */
	r = -EEXIST;
	for (i = 0; i < KVM_MEMORY_SLOTS; ++i) {
		struct kvm_memory_slot *s = &kvm->memslots[i];

		if (s == memslot)
			continue;
		if (!((base_gfn + npages <= s->base_gfn) ||
		      (base_gfn >= s->base_gfn + s->npages)))
			goto out;
	}

	/* Deallocate if slot is being removed */
	if (memslot->phys_mem && npages)
		kvm_free_physmem_slot(kvm, mem->slot);
		
	/* Free page dirty bitmap if unneeded */
	if (!(mem->flags & KVM_MEM_LOG_DIRTY_PAGES) && memslot->dirty_bitmap) {
		vfree(memslot->dirty_bitmap);
		memslot->dirty_bitmap = 0;	
	}

	memslot->base_gfn = base_gfn;
	memslot->npages = npages;
	memslot->flags = mem->flags;

	r = -ENOMEM;

	/* Allocate if a slot is being created */
	if (npages && !memslot->phys_mem) {
		memslot->phys_mem = vmalloc(npages * sizeof(struct page *));

		if (!memslot->phys_mem)
			goto out;

		memset(memslot->phys_mem, 0, npages * sizeof(struct page *));
		for (i = 0; i < npages; ++i) {
			memslot->phys_mem[i] = alloc_page(GFP_HIGHUSER);
			if (!memslot->phys_mem[i])
				goto out_free_physmem;
		}
	}

	/* Allocate page dirty bitmap if needed */
	if ((memslot->flags & KVM_MEM_LOG_DIRTY_PAGES) &&
	    !memslot->dirty_bitmap) {
		unsigned dirty_bytes = ALIGN(npages, BITS_PER_LONG) / 8;

		memslot->dirty_bitmap = vmalloc(dirty_bytes);
		if (!memslot->dirty_bitmap)
			goto out;
		memset(memslot->dirty_bitmap, 0, dirty_bytes);
	}

	if (mem->slot >= kvm->nmemslots)
		kvm->nmemslots = mem->slot + 1;

	for (i = 0; i < kvm->nvcpus; ++i) {
		struct kvm_vcpu *vcpu = &kvm->vcpus[i];
		
		vcpu_load(vcpu);
		kvm_mmu_reset_context(vcpu);
		vcpu_put(vcpu);
	}

	return 0;

out_free_physmem:
	kvm_free_physmem_slot(kvm, mem->slot);
out:
	return r;
}

/*
 * Get (and clear) the dirty memory log for a memory slot.
 */
static int kvm_dev_ioctl_get_dirty_log(struct kvm *kvm,
				       struct kvm_dirty_log *log)
{
	struct kvm_memory_slot *memslot;
	int r, i;
	int n;
	unsigned long any = 0;

	r = -EINVAL;
	if (log->slot >= KVM_MEMORY_SLOTS)
		goto out;

	memslot = &kvm->memslots[log->slot];
	r = -ENOENT;
	if (!memslot->dirty_bitmap)
		goto out;

	n = ALIGN(memslot->npages, 8) / 8;

	for (i = 0; !any && i < n; ++i)
		any = memslot->dirty_bitmap[i];

	r = -EFAULT;
	if (copy_to_user(log->dirty_bitmap, memslot->dirty_bitmap, n))
		goto out;


	if (any) {
		for (i = 0; i < kvm->nvcpus; ++i) {
			struct kvm_vcpu *vcpu = &kvm->vcpus[i];

			vcpu_load(vcpu);
			vmcs_writel(HOST_CR3, vmcs_readl(HOST_CR3));
			vcpu_put(vcpu);
		}
		kvm_mmu_slot_remove_write_access(kvm, log->slot);
		memset(memslot->dirty_bitmap, 0, n);
	}

	return 0;

out:
	return r;
}

struct page *gfn_to_page(struct kvm *kvm, gfn_t gfn)
{
	int i;

	for (i = 0; i < kvm->nmemslots; ++i) {
		struct kvm_memory_slot *memslot = &kvm->memslots[i];

		if (gfn >= memslot->base_gfn
		    && gfn < memslot->base_gfn + memslot->npages)
			return memslot->phys_mem[gfn - memslot->base_gfn];
	}
	return 0;
}

int gfn_to_memslot(struct kvm *kvm, gfn_t gfn)
{
	int i;

	for (i = 0; i < kvm->nmemslots; ++i) {
		struct kvm_memory_slot *memslot = &kvm->memslots[i];

		if (gfn >= memslot->base_gfn
		    && gfn < memslot->base_gfn + memslot->npages)
			return i;
	}
	return -1;
}

void mark_page_dirty(struct kvm *kvm, gfn_t gfn)
{
	int i;
	struct kvm_memory_slot *memslot = 0;
	unsigned long rel_gfn;

	for (i = 0; i < kvm->nmemslots; ++i) {
		memslot = &kvm->memslots[i];

		if (gfn >= memslot->base_gfn
		    && gfn < memslot->base_gfn + memslot->npages) {

			if (!memslot || !memslot->dirty_bitmap)
				return;

			rel_gfn = gfn - memslot->base_gfn;

			/* avoid RMW */
			if (!test_bit(rel_gfn, memslot->dirty_bitmap))
				set_bit(rel_gfn, memslot->dirty_bitmap);
			return;
		}
	}
}

static void skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	unsigned long rip;
	u32 interruptibility;
	
	rip = vmcs_readl(GUEST_RIP);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	vmcs_writel(GUEST_RIP, rip);

	/*
	 * We emulated an instruction, so temporary interrupt blocking
	 * should be removed, if set.
	 */
	interruptibility = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	if (interruptibility & 3)
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO,
			     interruptibility & ~3);
}

struct kvm_x86_emulate_ctxt {
	struct x86_emulate_ctxt x;
	struct kvm_vcpu *vcpu;
};

static struct kvm_vcpu *vcpu_from_ctxt(struct x86_emulate_ctxt *ctxt)
{
	struct kvm_x86_emulate_ctxt *kvm_ctxt
		= container_of(ctxt, struct kvm_x86_emulate_ctxt, x);
	return kvm_ctxt->vcpu;
}

static int emulator_read_std(unsigned long addr,
			     unsigned long *val,
			     unsigned int bytes,
			     struct x86_emulate_ctxt *ctxt)
{
	struct kvm_vcpu *vcpu = vcpu_from_ctxt(ctxt);
	void *data = val;

	while (bytes) {
		u64 pte = vcpu->mmu.fetch_pte64(vcpu, addr);
		unsigned offset = addr & (PAGE_SIZE-1);
		unsigned tocopy = min(bytes, (unsigned)PAGE_SIZE - offset);
		unsigned long pfn;
		void *page;

		if (!(pte & PT_PRESENT_MASK))
			return vcpu_printf(vcpu, "not present\n"), X86EMUL_PROPAGATE_FAULT;
		pfn = (pte & PT64_BASE_ADDR_MASK) >> PAGE_SHIFT;
		page = kmap_atomic(gfn_to_page(vcpu->kvm, pfn), KM_USER0);

		memcpy(data, page + offset, tocopy);

		kunmap_atomic(page, KM_USER0);

		bytes -= tocopy;
		data += tocopy;
		addr += tocopy;
	}
	
	return X86EMUL_CONTINUE;
}

static int emulator_write_std(unsigned long addr,
			      unsigned long val,
			      unsigned int bytes,
			      struct x86_emulate_ctxt *ctxt)
{
	printk(KERN_ERR "emulator_write_std: addr %lx n %d\n",
	       addr, bytes);
	return X86EMUL_UNHANDLEABLE;
}

static int emulator_read_emulated(unsigned long addr,
				  unsigned long *val,
				  unsigned int bytes,
				  struct x86_emulate_ctxt *ctxt)
{
	struct kvm_vcpu *vcpu = vcpu_from_ctxt(ctxt);

	if (vcpu->mmio_read_completed) {
		memcpy(val, vcpu->mmio_data, bytes);
		vcpu->mmio_read_completed = 0;
		return X86EMUL_CONTINUE;
	} else {
		u64 pte = vcpu->mmu.fetch_pte64(vcpu, addr);
		unsigned offset = addr & (PAGE_SIZE-1);

		if (!(pte & PT_PRESENT_MASK))
			return vcpu_printf(vcpu, "not present\n"), X86EMUL_PROPAGATE_FAULT;
		vcpu->mmio_needed = 1;
		vcpu->mmio_phys_addr = (pte & PT64_BASE_ADDR_MASK) | offset;
		vcpu->mmio_size = bytes;
		vcpu->mmio_is_write = 0;

		return X86EMUL_UNHANDLEABLE;
	}
}

static int emulator_write_emulated(unsigned long addr,
				   unsigned long val,
				   unsigned int bytes,
				   struct x86_emulate_ctxt *ctxt)
{
	struct kvm_vcpu *vcpu = vcpu_from_ctxt(ctxt);

	u64 pte = vcpu->mmu.fetch_pte64(vcpu, addr);
	unsigned offset = addr & (PAGE_SIZE-1);
	
	if (!(pte & PT_PRESENT_MASK))
		return vcpu_printf(vcpu, "not present\n"), X86EMUL_PROPAGATE_FAULT;
	
	vcpu->mmio_needed = 1;
	vcpu->mmio_phys_addr = (pte & PT64_BASE_ADDR_MASK) | offset;
	vcpu->mmio_size = bytes;
	vcpu->mmio_is_write = 1;
	memcpy(vcpu->mmio_data, &val, bytes);

	return X86EMUL_CONTINUE;
}

static int emulator_cmpxchg_emulated(unsigned long addr,
				     unsigned long old,
				     unsigned long new,
				     unsigned int bytes,
				     struct x86_emulate_ctxt *ctxt)
{
	printk(KERN_ERR "emulator_write_emulated: addr %lx n %d\n",
	       addr, bytes);
	return X86EMUL_UNHANDLEABLE;
}

struct x86_emulate_ops emulate_ops = {
	.read_std            = emulator_read_std,
	.write_std           = emulator_write_std,
	.read_emulated       = emulator_read_emulated,
	.write_emulated      = emulator_write_emulated,
	.cmpxchg_emulated    = emulator_cmpxchg_emulated,
};

enum emulation_result {
	EMULATE_DONE,       /* no further processing */
	EMULATE_DO_MMIO,      /* kvm_run filled with mmio request */
	EMULATE_FAIL,         /* can't emulate this instruction */
};

static int emulate_instruction(struct kvm_vcpu *vcpu,
			       struct kvm_run *run,
			       unsigned long cr2,
			       u16 error_code)
{
	struct cpu_user_regs regs;
	struct kvm_x86_emulate_ctxt emulate_ctxt;
	int r;
	uint32_t cs_ar;

	regs.eax = vcpu->regs[VCPU_REGS_RAX];
	regs.ebx = vcpu->regs[VCPU_REGS_RBX];
	regs.ecx = vcpu->regs[VCPU_REGS_RCX];
	regs.edx = vcpu->regs[VCPU_REGS_RDX];
	regs.esi = vcpu->regs[VCPU_REGS_RSI];
	regs.edi = vcpu->regs[VCPU_REGS_RDI];
	regs.esp = vmcs_readl(GUEST_RSP);
	regs.ebp = vcpu->regs[VCPU_REGS_RBP];
	regs.eip = vmcs_readl(GUEST_RIP);
	regs.eflags = vmcs_readl(GUEST_RFLAGS);
#ifdef __x86_64__
	regs.r8 = vcpu->regs[VCPU_REGS_R8];
	regs.r9 = vcpu->regs[VCPU_REGS_R9];
	regs.r10 = vcpu->regs[VCPU_REGS_R10];
	regs.r11 = vcpu->regs[VCPU_REGS_R11];
	regs.r12 = vcpu->regs[VCPU_REGS_R12];
	regs.r13 = vcpu->regs[VCPU_REGS_R13];
	regs.r14 = vcpu->regs[VCPU_REGS_R14];
	regs.r15 = vcpu->regs[VCPU_REGS_R15];
#endif
	regs.cs = vmcs_read16(GUEST_CS_SELECTOR);
	regs.ds = vmcs_read16(GUEST_DS_SELECTOR);
	regs.es = vmcs_read16(GUEST_ES_SELECTOR);
	regs.fs = vmcs_read16(GUEST_FS_SELECTOR);
	regs.gs = vmcs_read16(GUEST_GS_SELECTOR);
	regs.ss = vmcs_read16(GUEST_SS_SELECTOR);

	cs_ar = vmcs_read32(GUEST_CS_AR_BYTES);

	emulate_ctxt.x.regs = &regs;
	emulate_ctxt.x.cr2 = cr2;
	emulate_ctxt.x.mode = (regs.eflags & X86_EFLAGS_VM) ? X86EMUL_MODE_REAL:
			      (cs_ar & AR_L_MASK) ? X86EMUL_MODE_PROT64:
			      (cs_ar & AR_DB_MASK) ? X86EMUL_MODE_PROT32:
			      X86EMUL_MODE_PROT16;

	if (emulate_ctxt.x.mode == X86EMUL_MODE_PROT64) {
		emulate_ctxt.x.cs_base = 0;
		emulate_ctxt.x.ds_base = 0;
		emulate_ctxt.x.es_base = 0;
		emulate_ctxt.x.ss_base = 0;
		emulate_ctxt.x.gs_base = 0;
		emulate_ctxt.x.fs_base = 0;
	} else {
		emulate_ctxt.x.cs_base = vmcs_readl(GUEST_CS_BASE);
		emulate_ctxt.x.ds_base = vmcs_readl(GUEST_DS_BASE);
		emulate_ctxt.x.es_base = vmcs_readl(GUEST_ES_BASE);
		emulate_ctxt.x.ss_base = vmcs_readl(GUEST_SS_BASE);
		emulate_ctxt.x.gs_base = vmcs_readl(GUEST_GS_BASE);
		emulate_ctxt.x.fs_base = vmcs_readl(GUEST_FS_BASE);
	}

	emulate_ctxt.vcpu = vcpu;

	vcpu->mmio_is_write = 0;
	r = x86_emulate_memop(&emulate_ctxt.x, &emulate_ops);

	if (r || vcpu->mmio_is_write) {
		run->mmio.phys_addr = vcpu->mmio_phys_addr;
		memcpy(run->mmio.data, vcpu->mmio_data, 8);
		run->mmio.len = vcpu->mmio_size;
		run->mmio.is_write = vcpu->mmio_is_write;
	}

	if (r) {
		if (!vcpu->mmio_needed) {
			static int reported;

			if (!reported) {
				u8 opcodes[4];

				emulator_read_std(vmcs_readl(GUEST_RIP),
						  (unsigned long *)opcodes,
						  4,
						  &emulate_ctxt.x);

				printk(KERN_ERR "emulation failed but "
						"!mmio_needed? rip %lx %02x"
						" %02x %02x %02x\n",
				       vmcs_readl(GUEST_RIP),
				       opcodes[0],
				       opcodes[1],
				       opcodes[2],
				       opcodes[3]);
				reported = 1;
			}
			return EMULATE_FAIL;
		}
		return EMULATE_DO_MMIO;
	}

	vcpu->regs[VCPU_REGS_RAX] = regs.eax;
	vcpu->regs[VCPU_REGS_RBX] = regs.ebx;
	vcpu->regs[VCPU_REGS_RCX] = regs.ecx;
	vcpu->regs[VCPU_REGS_RDX] = regs.edx;
	vcpu->regs[VCPU_REGS_RSI] = regs.esi;
	vcpu->regs[VCPU_REGS_RDI] = regs.edi;
	vmcs_writel(GUEST_RSP, regs.esp);
	vcpu->regs[VCPU_REGS_RBP] = regs.ebp;
	vmcs_writel(GUEST_RIP, regs.eip);
	vmcs_writel(GUEST_RFLAGS, regs.eflags);
#ifdef __x86_64__
	vcpu->regs[VCPU_REGS_R8] = regs.r8;
	vcpu->regs[VCPU_REGS_R9] = regs.r9;
	vcpu->regs[VCPU_REGS_R10] = regs.r10;
	vcpu->regs[VCPU_REGS_R11] = regs.r11;
	vcpu->regs[VCPU_REGS_R12] = regs.r12;
	vcpu->regs[VCPU_REGS_R13] = regs.r13;
	vcpu->regs[VCPU_REGS_R14] = regs.r14;
	vcpu->regs[VCPU_REGS_R15] = regs.r15;
#endif

	if (vcpu->mmio_is_write)
		return EMULATE_DO_MMIO;

	return EMULATE_DONE;
}

static int handle_exception(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	u32 intr_info, error_code;
	unsigned long cr2, rip;
	u32 vect_info;
	enum emulation_result er;

	vect_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);
	intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	if ((vect_info & VECTORING_INFO_VALID_MASK) &&
						!is_page_fault(intr_info)) {
		printk("%s: unexpected, vectoring info 0x%x intr info 0x%x\n",
			       __FUNCTION__, vect_info, intr_info);
	}

	if (is_external_interrupt(vect_info)) {
		int irq = vect_info & VECTORING_INFO_VECTOR_MASK;
		set_bit(irq, vcpu->irq_pending);
		set_bit(irq / BITS_PER_LONG, &vcpu->irq_summary);
	}

	if ((intr_info & INTR_INFO_INTR_TYPE_MASK) == 0x200) { /* nmi */
		asm ( "int $2" );
		return 1;
	}
	error_code = 0;
	rip = vmcs_readl(GUEST_RIP);
	if (intr_info & INTR_INFO_DELIEVER_CODE_MASK)
		error_code = vmcs_read32(VM_EXIT_INTR_ERROR_CODE);
	if (is_page_fault(intr_info)) {
		cr2 = vmcs_readl(EXIT_QUALIFICATION);

		if (!vcpu->mmu.page_fault(vcpu, cr2, error_code))
			return 1;

		er = emulate_instruction(vcpu, kvm_run, cr2, error_code);

		switch (er) {
		case EMULATE_DONE:
			return 1;
		case EMULATE_DO_MMIO:
			++kvm_stat.mmio_exits;
			kvm_run->exit_reason = KVM_EXIT_MMIO;
			return 0;
		 case EMULATE_FAIL:
			vcpu_printf(vcpu, "%s: emulate fail\n");
			break;
		default:
			BUG();
		}
	}
	if ((intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK)) == (INTR_TYPE_EXCEPTION | 1)) {
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		return 0;
	}
	kvm_run->exit_reason = KVM_EXIT_EXCEPTION;
	kvm_run->ex.exception = intr_info & INTR_INFO_VECTOR_MASK;
	kvm_run->ex.error_code = error_code;
	return 0;
}

static int handle_external_interrupt(struct kvm_vcpu *vcpu,
				     struct kvm_run *kvm_run)
{
	++kvm_stat.irq_exits;
	return 1;
}

static int handle_io(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	u64 exit_qualification;

	++kvm_stat.io_exits;
	exit_qualification = vmcs_read64(EXIT_QUALIFICATION);
	kvm_run->exit_reason = KVM_EXIT_IO;
	if (exit_qualification & 8)
		kvm_run->io.direction = KVM_EXIT_IO_IN;
	else
		kvm_run->io.direction = KVM_EXIT_IO_OUT;
	kvm_run->io.size = (exit_qualification & 7) + 1;
	kvm_run->io.string = (exit_qualification & 16) != 0;
	kvm_run->io.string_down
		= (vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_DF) != 0;
	kvm_run->io.rep = (exit_qualification & 32) != 0;
	kvm_run->io.port = exit_qualification >> 16;
	kvm_run->io.count = vcpu->regs[VCPU_REGS_RCX]; /* rcx. FIXME: mask? */
	if (kvm_run->io.string)
		kvm_run->io.address = vmcs_readl(GUEST_LINEAR_ADDRESS);
	else
		kvm_run->io.value = vcpu->regs[VCPU_REGS_RAX]; /* rax */
	return 0;
}


static int handle_invlpg(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	uint64_t address = vmcs_read64(EXIT_QUALIFICATION);
	int instruction_length = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	vcpu->mmu.inval_page(vcpu, address);
	vmcs_writel(GUEST_RIP, vmcs_readl(GUEST_RIP) + instruction_length);
	return 1;
}


static void inject_gp(struct kvm_vcpu *vcpu)
{
	printk("inject_general_protection: rip 0x%lx\n",
		 vmcs_readl(GUEST_RIP));
	vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		     GP_VECTOR |
		     INTR_TYPE_EXCEPTION |
		     INTR_INFO_DELIEVER_CODE_MASK |
		     INTR_INFO_VALID_MASK);
}

static int pdptrs_have_reserved_bits_set(struct kvm_vcpu *vcpu, gpa_t cr3)
{
	gfn_t pdpt_gfn = cr3 >> PAGE_SHIFT;
	unsigned offset = (cr3 & (PAGE_SIZE-1)) >> 5;
	int i;
	u64 pdpte;
	u64 *pdpt;

	pdpt = kmap_atomic(gfn_to_page(vcpu->kvm, pdpt_gfn), KM_USER0);

	for (i = 0; i < 4; ++i) {
		pdpte = pdpt[offset + i];
		if ((pdpte & 1) && (pdpte & 0xfffffff0000001e6ull))
			break;
	}

	kunmap_atomic(pdpt, KM_USER0);

	return i != 4;
}

#define CR0_RESEVED_BITS 0xffffffff1ffaffc0ULL

static int set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	if (cr0 & CR0_RESEVED_BITS) {
		printk("set_cr0: 0x%lx #GP, reserved bits (0x%lx)\n", cr0, guest_cr0());
		inject_gp(vcpu);
		return 1;
	}

	if ((cr0 & CR0_NW_MASK) && !(cr0 & CR0_CD_MASK)) {
		printk("set_cr0: #GP, CD == 0 && NW == 1\n");
		inject_gp(vcpu);
		return 1;
	}

	if ((cr0 & CR0_PG_MASK) && !(cr0 & CR0_PE_MASK)) {
		printk("set_cr0: #GP, set PG flag and a clear PE flag\n");
		inject_gp(vcpu);
		return 1;
	}

	if ((cr0 & CR0_PG_MASK) && !(guest_cr0() & CR0_PE_MASK)) {
		printk("set_cr0: #GP, set PG flag and not in protected mode\n");
		inject_gp(vcpu);
		return 1;
	}

	if (is_paging()) {
		if (!(cr0 & CR0_PG_MASK)) {
			vcpu->shadow_efer &= ~EFER_LMA;
			vmcs_write32(VM_ENTRY_CONTROLS,
				     vmcs_read32(VM_ENTRY_CONTROLS) &
				     ~VM_ENTRY_CONTROLS_IA32E_MASK);
		}
	} else if ((cr0 & CR0_PG_MASK)) {
		if ((vcpu->shadow_efer & EFER_LME)) {
			uint32_t guest_cs_ar;
			uint32_t guest_tr_ar;
			if (!is_pae()) {
				printk("set_cr0: #GP, start paging in "
				       "long mode while PAE is disabled\n");
				inject_gp(vcpu);
				return 1;
			}
			guest_cs_ar = vmcs_read32(GUEST_CS_AR_BYTES);
			if (guest_cs_ar & SEGMENT_AR_L_MASK) {
				printk("set_cr0: #GP, start paging in "
				       "long mode while CS.L == 1\n");
				inject_gp(vcpu);
				return 1;

			}
			guest_tr_ar = vmcs_read32(GUEST_TR_AR_BYTES);
			if ((guest_tr_ar & AR_TYPE_MASK) != AR_TYPE_BUSY_64_TSS) {
				printk("%s: tss fixup for long mode. \n",
				       __FUNCTION__);
				vmcs_write32(GUEST_TR_AR_BYTES,
					     (guest_tr_ar & ~AR_TYPE_MASK) |
					     AR_TYPE_BUSY_64_TSS);
			}
			vcpu->shadow_efer |= EFER_LMA;
                        find_msr_entry(vcpu, MSR_EFER)->data |=
							EFER_LMA | EFER_LME;
			vmcs_write32(VM_ENTRY_CONTROLS,
				     vmcs_read32(VM_ENTRY_CONTROLS) |
				     VM_ENTRY_CONTROLS_IA32E_MASK);

		} else if (is_pae() &&
			   pdptrs_have_reserved_bits_set(vcpu, vcpu->cr3)) {
			printk("set_cr0: #GP, pdptrs reserved bits\n");
			inject_gp(vcpu);
			return 1;
		}

	}

	if (!(cr0 & CR0_PE_MASK)) {
		vcpu_printf(vcpu, "%s: enter real mode\n", __FUNCTION__);
		return 0;
	}
	vmcs_writel(GUEST_CR0, cr0 | KVM_VM_CR0_ALWAYS_ON);
	vmcs_writel(CR0_READ_SHADOW, cr0 & KVM_GUEST_CR0_MASK);
	kvm_mmu_reset_context(vcpu);
	skip_emulated_instruction(vcpu);
	return 1;
}

static void lmsw(struct kvm_vcpu *vcpu, unsigned long msw)
{
	unsigned long cr0 = guest_cr0();

	if ((msw & CR0_PE_MASK) && !(cr0 & CR0_PE_MASK)) {
	      vmcs_writel(CR0_READ_SHADOW, cr0 | CR0_PE_MASK);
	      printk("lmsw: enter protected mode\n");
	      // enter protected mode
	} else
		printk("lmsw: unexpected\n");

	#define LMSW_GUEST_MASK 0x0eULL

	vmcs_writel(GUEST_CR0, (vmcs_readl(GUEST_CR0) & ~LMSW_GUEST_MASK)
				| (msw & LMSW_GUEST_MASK));

	skip_emulated_instruction(vcpu);
}

#define CR4_RESEVED_BITS (~((1ULL << 11) - 1))

static void set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	if (cr4 & CR4_RESEVED_BITS) {
		printk("set_cr4: #GP, reserved bits\n");
		inject_gp(vcpu);
		return;
	}

	if (is_long_mode()) {
		if (!(cr4 & CR4_PAE_MASK)) {
			printk("set_cr4: #GP, clearing PAE while in long mode\n");
			inject_gp(vcpu);
			return;
		}
	} else if (is_paging() && !is_pae() && (cr4 & CR4_PAE_MASK)
		   && pdptrs_have_reserved_bits_set(vcpu, vcpu->cr3)) {
		printk("set_cr4: #GP, pdptrs reserved bits\n");
		inject_gp(vcpu);
	}

	if (cr4 & CR4_VMXE_MASK) {
		printk("set_cr4: #GP, setting VMXE\n");
		inject_gp(vcpu);
		return;
	}
	vmcs_writel(GUEST_CR4, cr4 | KVM_VM_CR4_ALWAYS_ON);
	vmcs_writel(CR4_READ_SHADOW, cr4);
	kvm_mmu_reset_context(vcpu);
	skip_emulated_instruction(vcpu);
}

static void set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	if (is_long_mode()) {
		if ( cr3 & CR3_L_MODE_RESEVED_BITS) {
			printk("set_cr3: #GP, reserved bits\n");
			inject_gp(vcpu);
			return;
		}
	} else {
		if (cr3 & CR3_RESEVED_BITS) {
			printk("set_cr3: #GP, reserved bits\n");
			inject_gp(vcpu);
			return;
		}
		if (is_paging() && is_pae() &&
		    pdptrs_have_reserved_bits_set(vcpu, cr3)) {
			printk("set_cr3: #GP, pdptrs reserved bits\n");
			inject_gp(vcpu);
			return;
		}
	}

	vcpu->cr3 = cr3;
	vcpu->mmu.new_cr3(vcpu);
	skip_emulated_instruction(vcpu);
}

#define CR8_RESEVED_BITS (~0x0fULL)

static void set_cr8(struct kvm_vcpu *vcpu, unsigned long cr8)
{
	if ( cr8 & CR8_RESEVED_BITS) {
		printk("set_cr8: #GP, reserved bits 0x%lx\n", cr8);
		inject_gp(vcpu);
		return;
	}
	vcpu->cr8 = cr8;
	skip_emulated_instruction(vcpu);
}


static void __set_cr0(unsigned long cr0)
{
	vmcs_writel(CR0_READ_SHADOW, cr0 & KVM_GUEST_CR0_MASK);
	vmcs_writel(GUEST_CR0, cr0 | KVM_VM_CR0_ALWAYS_ON);
}

static void __set_cr4(unsigned long cr4)
{
	vmcs_writel(CR4_READ_SHADOW, cr4);
	vmcs_writel(GUEST_CR4, cr4 | KVM_VM_CR4_ALWAYS_ON);
}

static int handle_cr(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	u64 exit_qualification;
	int cr;
	int reg;

#ifdef KVM_DEBUG
	if (guest_cpl() != 0) {
		vcpu_printf(vcpu, "%s: not supervisor\n", __FUNCTION__);
		inject_gp(vcpu);
		return 1;
	}
#endif

	exit_qualification = vmcs_read64(EXIT_QUALIFICATION);
	cr = exit_qualification & 15;
	reg = (exit_qualification >> 8) & 15;
	switch ((exit_qualification >> 4) & 3) {
	case 0: /* mov to cr */
		switch (cr) {
		case 0:
			vcpu_load_rsp_rip(vcpu);
			if (!set_cr0(vcpu, vcpu->regs[reg])) {
				kvm_run->exit_reason = KVM_EXIT_REAL_MODE;
				return 0;
			}
			return 1;
		case 3:
			vcpu_load_rsp_rip(vcpu);
			set_cr3(vcpu, vcpu->regs[reg]);
			return 1;
		case 4:
			vcpu_load_rsp_rip(vcpu);
			set_cr4(vcpu, vcpu->regs[reg]);
			return 1;
		case 8:
			vcpu_load_rsp_rip(vcpu);
			set_cr8(vcpu, vcpu->regs[reg]);
			return 1;
		};
		break;
	case 1: /*mov from cr*/
		switch (cr) {
		case 3:
			vcpu_load_rsp_rip(vcpu);
			vcpu->regs[reg] = vcpu->cr3;
			vcpu_put_rsp_rip(vcpu);
			skip_emulated_instruction(vcpu);
			return 1;
		case 8:
			printk("handle_cr: read CR8 cpu bug (AA15) !!!!!!!!!!!!!!!!!\n");
			vcpu_load_rsp_rip(vcpu);
			vcpu->regs[reg] = vcpu->cr8;
			vcpu_put_rsp_rip(vcpu);
			skip_emulated_instruction(vcpu);
			return 1;
		}
		break;
	case 3: /* lmsw */
		lmsw(vcpu, (exit_qualification >> LMSW_SOURCE_DATA_SHIFT) & 0x0f);
		return 1;
	default:
		break;
	}
	kvm_run->exit_reason = 0;
	printk(KERN_ERR "kvm: unhandled control register: op %d cr %d\n",
	       (int)(exit_qualification >> 4) & 3, cr);
	return 0;
}

static int handle_dr(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	u64 exit_qualification;
	unsigned long val;
	int dr, reg;
	
	/*
	 * FIXME: this code assumes the host is debugging the guest.
	 *        need to deal with guest debugging itself too.
	 */
	exit_qualification = vmcs_read64(EXIT_QUALIFICATION);
	dr = exit_qualification & 7;
	reg = (exit_qualification >> 8) & 15;
	vcpu_load_rsp_rip(vcpu);
	if (exit_qualification & 16) {
		/* mov from dr */
		switch (dr) {
		case 6:
			val = 0xffff0ff0;
			break;
		case 7:
			val = 0x400;
			break;
		default:
			val = 0;
		}
		vcpu->regs[reg] = val;
	} else {
		/* mov to dr */
	}
	vcpu_put_rsp_rip(vcpu);
	skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_cpuid(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	kvm_run->exit_reason = KVM_EXIT_CPUID;
	return 0;
}

static int handle_rdmsr(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	u32 ecx = vcpu->regs[VCPU_REGS_RCX];
	struct vmx_msr_entry *msr = find_msr_entry(vcpu, ecx);
	u64 data;

#ifdef KVM_DEBUG
	if (guest_cpl() != 0) {
		vcpu_printf(vcpu, "%s: not supervisor\n", __FUNCTION__);
		inject_gp(vcpu);
		return 1;
	}
#endif

	switch (ecx) {
	case MSR_FS_BASE:
		data = vmcs_readl(GUEST_FS_BASE);
		break;
	case MSR_GS_BASE:
		data = vmcs_readl(GUEST_GS_BASE);
		break;
	case MSR_IA32_SYSENTER_CS:
		data = vmcs_read32(GUEST_SYSENTER_CS);
		break;
	case MSR_IA32_SYSENTER_EIP:
		data = vmcs_read32(GUEST_SYSENTER_EIP);
		break;
	case MSR_IA32_SYSENTER_ESP:
		data = vmcs_read32(GUEST_SYSENTER_ESP);
		break;
	case MSR_IA32_MC0_CTL:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MCG_CAP:
	case MSR_IA32_MC0_MISC:
	case MSR_IA32_MC0_MISC+4:
	case MSR_IA32_MC0_MISC+8:
	case MSR_IA32_MC0_MISC+12:
	case MSR_IA32_MC0_MISC+16:
		/* MTRR registers */
	case 0xfe:
	case 0x200 ... 0x2ff:
		data = 0;
		break;
	case MSR_IA32_APICBASE:
		data = vcpu->apic_base;
		break;
	default:
		if (msr) {
			data = msr->data;
			break;
		}
		printk(KERN_ERR "kvm: unhandled rdmsr: %x\n", ecx);
		inject_gp(vcpu);
		return 1;
	}
	
	/* FIXME: handling of bits 32:63 of rax, rdx */
	vcpu->regs[VCPU_REGS_RAX] = data & -1u;
	vcpu->regs[VCPU_REGS_RDX] = (data >> 32) & -1u;
	skip_emulated_instruction(vcpu);
	return 1;
}

#define EFER_RESERVED_BITS 0xfffffffffffff2fe

static void set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	struct vmx_msr_entry *msr;

	if (efer & EFER_RESERVED_BITS) {
		printk("set_efer: 0x%llx #GP, reserved bits\n", efer);
		inject_gp(vcpu);
		return;
	}

	if (is_paging() && (vcpu->shadow_efer & EFER_LME) != (efer & EFER_LME)) {
		printk("set_efer: #GP, change LME while paging\n");
		inject_gp(vcpu);
		return;
	}

	efer &= ~EFER_LMA;
	efer |= vcpu->shadow_efer & EFER_LMA;

	vcpu->shadow_efer = efer;

	msr = find_msr_entry(vcpu, MSR_EFER);

	if (!(efer & EFER_LMA))
	    efer &= ~EFER_LME;
	msr->data = efer;
	skip_emulated_instruction(vcpu);
}

static void __set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	struct vmx_msr_entry *msr = find_msr_entry(vcpu, MSR_EFER);

	vcpu->shadow_efer = efer;
	if (efer & EFER_LMA) {
		vmcs_write32(VM_ENTRY_CONTROLS,
				     vmcs_read32(VM_ENTRY_CONTROLS) |
				     VM_ENTRY_CONTROLS_IA32E_MASK);
		msr->data = efer;

	} else {
		vmcs_write32(VM_ENTRY_CONTROLS,
				     vmcs_read32(VM_ENTRY_CONTROLS) &
				     ~VM_ENTRY_CONTROLS_IA32E_MASK);

		msr->data = efer & ~EFER_LME;
	}
}

#define MSR_IA32_TIME_STAMP_COUNTER 0x10

static int handle_wrmsr(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	u32 ecx = vcpu->regs[VCPU_REGS_RCX];
	struct vmx_msr_entry *msr;
	u64 data = (vcpu->regs[VCPU_REGS_RAX] & -1u)
		| ((u64)(vcpu->regs[VCPU_REGS_RDX] & -1u) << 32);

#ifdef KVM_DEBUG
	if (guest_cpl() != 0) {
		vcpu_printf(vcpu, "%s: not supervisor\n", __FUNCTION__);
		inject_gp(vcpu);
		return 1;
	}
#endif

	switch (ecx) {
	case MSR_FS_BASE:
		vmcs_writel(GUEST_FS_BASE, data);
		break;
	case MSR_GS_BASE:
		vmcs_writel(GUEST_GS_BASE, data);
		break;
	case MSR_IA32_SYSENTER_CS:
		vmcs_write32(GUEST_SYSENTER_CS, data);
		break;
	case MSR_IA32_SYSENTER_EIP:
		vmcs_write32(GUEST_SYSENTER_EIP, data);
		break;
	case MSR_IA32_SYSENTER_ESP:
		vmcs_write32(GUEST_SYSENTER_ESP, data);
		break;
	case MSR_EFER:
		set_efer(vcpu, data);
		return 1;
	case MSR_IA32_MC0_STATUS:
		vcpu_printf(vcpu, "%s: MSR_IA32_MC0_STATUS 0x%llx, nop\n"
			    , __FUNCTION__, data);
		break;
	case MSR_IA32_TIME_STAMP_COUNTER: {
		u64 tsc;

		rdtscll(tsc);
		vmcs_write64(TSC_OFFSET, data - tsc);
		break;
	}
	case 0x200 ... 0x2ff: /* MTRRs */
		break;
	default:
		msr = find_msr_entry(vcpu, ecx);
		if (msr) {
			msr->data = data;
			break;
		}
		printk(KERN_ERR "kvm: unhandled wrmsr: %x\n", ecx);
		inject_gp(vcpu);
		return 1;
	}
	skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_interrupt_window(struct kvm_vcpu *vcpu,
				   struct kvm_run *kvm_run)
{
	/* Turn off interrupt window reporting. */
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
		     vmcs_read32(CPU_BASED_VM_EXEC_CONTROL)
		     & ~CPU_BASED_VIRTUAL_INTR_PENDING);
	return 1;
}

static int handle_halt(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	if (vcpu->irq_summary && (vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF)) {
		skip_emulated_instruction(vcpu);
		return 1;
	}

	kvm_run->exit_reason = KVM_EXIT_HLT;
	return 0;
}

/*
 * The exit handlers return 1 if the exit was handled fully and guest execution
 * may resume.  Otherwise they set the kvm_run parameter to indicate what needs
 * to be done to userspace and return 0.
 */
static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu,
				      struct kvm_run *kvm_run) = {
	[EXIT_REASON_EXCEPTION_NMI]           = handle_exception,
	[EXIT_REASON_EXTERNAL_INTERRUPT]      = handle_external_interrupt,
	[EXIT_REASON_IO_INSTRUCTION]          = handle_io,
	[EXIT_REASON_INVLPG]                  = handle_invlpg,
	[EXIT_REASON_CR_ACCESS]               = handle_cr,
	[EXIT_REASON_DR_ACCESS]               = handle_dr,
	[EXIT_REASON_CPUID]                   = handle_cpuid,
	[EXIT_REASON_MSR_READ]                = handle_rdmsr,
	[EXIT_REASON_MSR_WRITE]               = handle_wrmsr,
	[EXIT_REASON_PENDING_INTERRUPT]       = handle_interrupt_window,
	[EXIT_REASON_HLT]                     = handle_halt,
};

static const int kvm_vmx_max_exit_handlers =
	sizeof(kvm_vmx_exit_handlers) / sizeof(*kvm_vmx_exit_handlers);

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
static int kvm_handle_exit(struct kvm_run *kvm_run, struct kvm_vcpu *vcpu)
{
	u32 vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);
	u32 exit_reason = vmcs_read32(VM_EXIT_REASON);

	if ( (vectoring_info & VECTORING_INFO_VALID_MASK) &&
				exit_reason != EXIT_REASON_EXCEPTION_NMI )
		printk("%s: unexpected, valid vectoring info and exit"
		       " reason is 0x%x\n", __FUNCTION__, exit_reason);
	kvm_run->instruction_length = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	if (exit_reason < kvm_vmx_max_exit_handlers
	    && kvm_vmx_exit_handlers[exit_reason])
		return kvm_vmx_exit_handlers[exit_reason](vcpu, kvm_run);
	else {
		kvm_run->exit_reason = KVM_EXIT_UNKNOWN;
		kvm_run->hw.hardware_exit_reason = exit_reason;
		printk(KERN_ERR "kvm: unhandled exit reason 0x%x\n",
		       exit_reason);
	}
	return 0;
}

static void kvm_do_inject_irq(struct kvm_vcpu *vcpu)
{
	int word_index = __ffs(vcpu->irq_summary);
	int bit_index = __ffs(vcpu->irq_pending[word_index]);
	int irq = word_index * BITS_PER_LONG + bit_index;

	clear_bit(bit_index, &vcpu->irq_pending[word_index]);
	if (!vcpu->irq_pending[word_index])
		clear_bit(word_index, &vcpu->irq_summary);

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			irq | INTR_TYPE_EXT_INTR | INTR_INFO_VALID_MASK);
}

static void kvm_try_inject_irq(struct kvm_vcpu *vcpu)
{
	if ((vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF)
	    && (vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) & 3) == 0)
		/*
		 * Interrupts enabled, and not blocked by sti or mov ss. Good.
		 */
		kvm_do_inject_irq(vcpu);
	else
		/*
		 * Interrupts blocked.  Wait for unblock.
		 */
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
			     vmcs_read32(CPU_BASED_VM_EXEC_CONTROL)
			     | CPU_BASED_VIRTUAL_INTR_PENDING);
}

static void kvm_guest_debug_pre(struct kvm_vcpu *vcpu)
{
	struct kvm_guest_debug *dbg = &vcpu->guest_debug;

	set_debugreg(dbg->bp[0], 0);
	set_debugreg(dbg->bp[1], 1);
	set_debugreg(dbg->bp[2], 2);
	set_debugreg(dbg->bp[3], 3);

	if (dbg->singlestep) {
		unsigned long flags;

		flags = vmcs_readl(GUEST_RFLAGS);
		flags |= X86_EFLAGS_TF | X86_EFLAGS_RF;
		vmcs_writel(GUEST_RFLAGS, flags);
	}
}

static void load_msrs(struct vmx_msr_entry *e)
{
	int i;

	for (i = NUM_AUTO_MSRS; i < NR_VMX_MSR; ++i)
		wrmsrl(e[i].index, e[i].data);
}

static void save_msrs(struct vmx_msr_entry *e, int msr_index)
{
	for (; msr_index < NR_VMX_MSR; ++msr_index)
		rdmsrl(e[msr_index].index, e[msr_index].data);
}

static int kvm_dev_ioctl_run(struct kvm *kvm, struct kvm_run *kvm_run)
{
	struct kvm_vcpu *vcpu;
	u8 fail;

	if (kvm_run->vcpu < 0 || kvm_run->vcpu >= kvm->nvcpus)
		return -EINVAL;
	vcpu = &kvm->vcpus[kvm_run->vcpu];

	vcpu_load(vcpu);

	if (kvm_run->emulated) {
		skip_emulated_instruction(vcpu);
		kvm_run->emulated = 0;
	}

	if (kvm_run->mmio_completed) {
		memcpy(vcpu->mmio_data, kvm_run->mmio.data, 8);
		vcpu->mmio_read_completed = 1;
	}

	vcpu->mmio_needed = 0;
	
again:

#ifdef __x86_64__
	vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));
	vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));
#endif

	if (vcpu->irq_summary &&
	    !(vmcs_read32(VM_ENTRY_INTR_INFO_FIELD) & INTR_INFO_VALID_MASK))
		kvm_try_inject_irq(vcpu);

	if (vcpu->guest_debug.enabled)
		kvm_guest_debug_pre(vcpu);

#ifdef __x86_64__
#define SP "rsp"
#define PUSHA "push %%rax; push %%rbx; push %%rdx;" \
              "push %%rsi; push %%rdi; push %%rbp;" \
	      "push %%r8;  push %%r9;  push %%r10; push %%r11;" \
              "push %%r12; push %%r13; push %%r14; push %%r15; push %%rcx"
#define POPA  "pop  %%rcx; pop  %%r15; pop  %%r14; pop  %%r13; pop  %%r12;" \
	      "pop  %%r11; pop  %%r10; pop  %%r9;  pop  %%r8;"	\
	      "pop  %%rbp; pop  %%rdi; pop  %%rsi;"	       \
	      "pop  %%rdx; pop  %%rbx; pop  %%rax"
#define LOAD_GUEST_REGS \
	"mov 128(%3), %%rax \n\t" \
	"mov %%rax, %%cr2 \n\t"   \
	"mov  0(%3),  %%rax \n\t" \
	"mov  24(%3), %%rbx \n\t" \
	"mov  16(%3), %%rdx \n\t" \
	"mov  48(%3), %%rsi \n\t" \
	"mov  56(%3), %%rdi \n\t" \
	"mov  40(%3), %%rbp \n\t" \
	"mov  64(%3), %%r8  \n\t" \
	"mov  72(%3), %%r9  \n\t" \
	"mov  80(%3), %%r10 \n\t" \
	"mov  88(%3), %%r11 \n\t" \
	"mov  96(%3), %%r12 \n\t" \
	"mov 104(%3), %%r13 \n\t" \
	"mov 112(%3), %%r14 \n\t" \
	"mov 120(%3), %%r15 \n\t" \
	"mov 8(%3),  %%rcx \n\t" /* kills %3 (rcx) */

#define STORE_GUEST_REGS \
	"xchg %3,     0(%%rsp) \n\t" \
	"mov %%rax,   0(%3) \n\t" \
	"mov %%rbx,  24(%3) \n\t" \
	"pushq 0(%%rsp); popq 8(%3) \n\t" \
	"mov %%rdx,  16(%3) \n\t" \
	"mov %%rsi,  48(%3) \n\t" \
	"mov %%rdi,  56(%3) \n\t" \
	"mov %%rbp,  40(%3) \n\t" \
	"mov %%r8,   64(%3) \n\t" \
	"mov %%r9,   72(%3) \n\t" \
	"mov %%r10,  80(%3) \n\t" \
	"mov %%r11,  88(%3) \n\t" \
	"mov %%r12,  96(%3) \n\t" \
	"mov %%r13, 104(%3) \n\t" \
	"mov %%r14, 112(%3) \n\t" \
	"mov %%r15, 120(%3) \n\t" \
	"mov %%cr2, %%rax   \n\t" \
	"mov %%rax, 128(%3) \n\t" \
	"mov 0(%%rsp), %3 \n\t"
#else
#define SP "esp"
#define PUSHA "pusha; push %%ecx"
#define POPA  "pop %%ecx; popa"

#define LOAD_GUEST_REGS \
	"mov 0(%3),   %%eax \n\t" \
	"mov 12(%3),  %%ebx \n\t" \
	"mov 8(%3),   %%edx \n\t" \
	"mov 16(%3),  %%esi \n\t" \
	"mov 20(%3),  %%edi \n\t" \
	"mov 28(%3),  %%ebp \n\t" \
	"mov 4(%3),   %%ecx \n\t" /* kills %3 (ecx) */

#define STORE_GUEST_REGS \
	"xchg %3, 0(%%esp) \n\t" \
	"mov %%eax,  0(%3) \n\t" \
	"mov %%ebx, 12(%3) \n\t" \
	"pushl 0(%%esp); popl 4(%3) \n\t" \
	"mov %%edx,  8(%3) \n\t" \
	"mov %%esi, 16(%3) \n\t" \
	"mov %%edi, 20(%3) \n\t" \
	"mov %%ebp, 28(%3) \n\t" \
	"mov 0(%%esp), %3"

#endif
	fx_save(vcpu->host_fx_image);
	fx_restore(vcpu->guest_fx_image);

	save_msrs(vcpu->host_msrs, 0);
	load_msrs(vcpu->guest_msrs);

	asm ( "pushf; " PUSHA "\n\t"
	      "vmwrite %%" SP ", %2 \n\t"
	      "cmp $0, %1 \n\t"
	      LOAD_GUEST_REGS "\n\t"
	      "jne launched \n\t"
	      "vmlaunch \n\t"
	      "jmp error \n\t"
	      "launched: vmresume \n\t"
	      "error: " STORE_GUEST_REGS "; " POPA "; popf \n\t"
	      "mov $1, %0 \n\t"
	      "jmp done \n\t"
	      ".globl kvm_vmx_return \n\t"
	      "kvm_vmx_return: " STORE_GUEST_REGS "; " POPA "; popf \n\t"
              "mov $0, %0 \n\t"
	      "done:"
	      : "=g" (fail)
	      : "r"(vcpu->launched), "r"((unsigned long)HOST_RSP),
		"c"(vcpu->regs)
	      : "cc", "memory" );

	++kvm_stat.exits;

	save_msrs(vcpu->guest_msrs, NUM_AUTO_MSRS);
	load_msrs(vcpu->host_msrs);

	fx_save(vcpu->guest_fx_image);
	fx_restore(vcpu->host_fx_image);

	kvm_run->exit_type = 0;
	if (fail) {
		kvm_run->exit_type = KVM_EXIT_TYPE_FAIL_ENTRY;
		kvm_run->exit_reason = vmcs_read32(VM_INSTRUCTION_ERROR);
	} else {
		vcpu->launched = 1;
		kvm_run->exit_type = KVM_EXIT_TYPE_VM_EXIT;
		if (kvm_handle_exit(kvm_run, vcpu)) {
			/* Give scheduler a change to reschedule. */
			vcpu_put(vcpu);
			if (signal_pending(current)) {
				++kvm_stat.signal_exits;
				return -EINTR;
			}
			cond_resched();
			vcpu_load(vcpu);
			goto again;
		}
	}

	vcpu_put(vcpu);
	return 0;
}

static int kvm_dev_ioctl_get_regs(struct kvm *kvm, struct kvm_regs *regs)
{
	struct kvm_vcpu *vcpu;

	if (regs->vcpu < 0 || regs->vcpu >= kvm->nvcpus)
		return -EINVAL;
	vcpu = &kvm->vcpus[regs->vcpu];

	vcpu_load(vcpu);

	regs->rax = vcpu->regs[VCPU_REGS_RAX];
	regs->rbx = vcpu->regs[VCPU_REGS_RBX];
	regs->rcx = vcpu->regs[VCPU_REGS_RCX];
	regs->rdx = vcpu->regs[VCPU_REGS_RDX];
	regs->rsi = vcpu->regs[VCPU_REGS_RSI];
	regs->rdi = vcpu->regs[VCPU_REGS_RDI];
	regs->rsp = vmcs_readl(GUEST_RSP);
	regs->rbp = vcpu->regs[VCPU_REGS_RBP];
	regs->r8 = vcpu->regs[VCPU_REGS_R8];
	regs->r9 = vcpu->regs[VCPU_REGS_R9];
	regs->r10 = vcpu->regs[VCPU_REGS_R10];
	regs->r11 = vcpu->regs[VCPU_REGS_R11];
	regs->r12 = vcpu->regs[VCPU_REGS_R12];
	regs->r13 = vcpu->regs[VCPU_REGS_R13];
	regs->r14 = vcpu->regs[VCPU_REGS_R14];
	regs->r15 = vcpu->regs[VCPU_REGS_R15];
	
	regs->rip = vmcs_readl(GUEST_RIP);
	regs->rflags = vmcs_readl(GUEST_RFLAGS);

	/*
	 * Don't leak debug flags in case they were set for guest debugging
	 */
	if (vcpu->guest_debug.enabled && vcpu->guest_debug.singlestep)
		regs->rflags &= ~(X86_EFLAGS_TF | X86_EFLAGS_RF);

	vcpu_put(vcpu);

	return 0;
}

static int kvm_dev_ioctl_set_regs(struct kvm *kvm, struct kvm_regs *regs)
{
	struct kvm_vcpu *vcpu;

	if (regs->vcpu < 0 || regs->vcpu >= kvm->nvcpus)
		return -EINVAL;
	vcpu = &kvm->vcpus[regs->vcpu];

	vcpu_load(vcpu);

	vcpu->regs[VCPU_REGS_RAX] = regs->rax;
	vcpu->regs[VCPU_REGS_RBX] = regs->rbx;
	vcpu->regs[VCPU_REGS_RCX] = regs->rcx;
	vcpu->regs[VCPU_REGS_RDX] = regs->rdx;
	vcpu->regs[VCPU_REGS_RSI] = regs->rsi;
	vcpu->regs[VCPU_REGS_RDI] = regs->rdi;
	vmcs_writel(GUEST_RSP, regs->rsp);
	vcpu->regs[VCPU_REGS_RBP] = regs->rbp;
	vcpu->regs[VCPU_REGS_R8] = regs->r8;
	vcpu->regs[VCPU_REGS_R9] = regs->r9;
	vcpu->regs[VCPU_REGS_R10] = regs->r10;
	vcpu->regs[VCPU_REGS_R11] = regs->r11;
	vcpu->regs[VCPU_REGS_R12] = regs->r12;
	vcpu->regs[VCPU_REGS_R13] = regs->r13;
	vcpu->regs[VCPU_REGS_R14] = regs->r14;
	vcpu->regs[VCPU_REGS_R15] = regs->r15;
	
	vmcs_writel(GUEST_RIP, regs->rip);
	vmcs_writel(GUEST_RFLAGS, regs->rflags);

	vcpu_put(vcpu);

	return 0;
}

static int kvm_dev_ioctl_get_sregs(struct kvm *kvm, struct kvm_sregs *sregs)
{
	struct kvm_vcpu *vcpu;

	if (sregs->vcpu < 0 || sregs->vcpu >= kvm->nvcpus)
		return -EINVAL;
	vcpu = &kvm->vcpus[sregs->vcpu];

	vcpu_load(vcpu);

#define get_segment(var, seg) \
	do { \
		u32 ar; \
		\
		sregs->var.base = vmcs_readl(GUEST_##seg##_BASE); \
		sregs->var.limit = vmcs_read32(GUEST_##seg##_LIMIT); \
		sregs->var.selector = vmcs_read16(GUEST_##seg##_SELECTOR); \
		ar = vmcs_read32(GUEST_##seg##_AR_BYTES); \
		if (ar & AR_UNUSABLE_MASK) ar = 0; \
		sregs->var.type = ar & 15; \
		sregs->var.s = (ar >> 4) & 1; \
		sregs->var.dpl = (ar >> 5) & 3; \
		sregs->var.present = (ar >> 7) & 1; \
		sregs->var.avl = (ar >> 12) & 1; \
		sregs->var.l = (ar >> 13) & 1; \
		sregs->var.db = (ar >> 14) & 1; \
		sregs->var.g = (ar >> 15) & 1; \
		sregs->var.unusable = (ar >> 16) & 1; \
	} while (0);

	get_segment(cs, CS);
	get_segment(ds, DS);
	get_segment(es, ES);
	get_segment(fs, FS);
	get_segment(gs, GS);
	get_segment(ss, SS);

	get_segment(tr, TR);
	get_segment(ldt, LDTR);
#undef get_segment

#define get_dtable(var, table) \
	sregs->var.limit = vmcs_read32(GUEST_##table##_LIMIT), \
		sregs->var.base = vmcs_readl(GUEST_##table##_BASE)

	get_dtable(idt, IDTR);
	get_dtable(gdt, GDTR);
#undef get_dtable

	sregs->cr0 = guest_cr0();
	sregs->cr2 = vcpu->regs[VCPU_REGS_CR2];
	sregs->cr3 = vcpu->cr3;
	sregs->cr4 = guest_cr4();
	sregs->cr8 = vcpu->cr8;
	sregs->efer = vcpu->shadow_efer;
	sregs->apic_base = vcpu->apic_base;

	sregs->pending_int = vcpu->irq_summary != 0;

	vcpu_put(vcpu);

	return 0;
}

static int kvm_dev_ioctl_set_sregs(struct kvm *kvm, struct kvm_sregs *sregs)
{
	struct kvm_vcpu *vcpu;
	int mmu_reset_needed = 0;

	if (sregs->vcpu < 0 || sregs->vcpu >= kvm->nvcpus)
		return -EINVAL;
	vcpu = &kvm->vcpus[sregs->vcpu];

	vcpu_load(vcpu);

#define set_segment(var, seg) \
	do { \
		u32 ar; \
		\
		vmcs_writel(GUEST_##seg##_BASE, sregs->var.base);  \
		vmcs_write32(GUEST_##seg##_LIMIT, sregs->var.limit); \
		vmcs_write16(GUEST_##seg##_SELECTOR, sregs->var.selector); \
		if (sregs->var.unusable) { \
			ar = (1 << 16); \
		} else { \
			ar = (sregs->var.type & 15); \
			ar |= (sregs->var.s & 1) << 4; \
			ar |= (sregs->var.dpl & 3) << 5; \
			ar |= (sregs->var.present & 1) << 7; \
			ar |= (sregs->var.avl & 1) << 12; \
			ar |= (sregs->var.l & 1) << 13; \
			ar |= (sregs->var.db & 1) << 14; \
			ar |= (sregs->var.g & 1) << 15; \
		} \
		vmcs_write32(GUEST_##seg##_AR_BYTES, ar); \
	} while (0);

	set_segment(cs, CS);
	set_segment(ds, DS);
	set_segment(es, ES);
	set_segment(fs, FS);
	set_segment(gs, GS);
	set_segment(ss, SS);

	set_segment(tr, TR);

	set_segment(ldt, LDTR);
#undef set_segment

#define set_dtable(var, table) \
	vmcs_write32(GUEST_##table##_LIMIT, sregs->var.limit), \
	vmcs_writel(GUEST_##table##_BASE, sregs->var.base)

	set_dtable(idt, IDTR);
	set_dtable(gdt, GDTR);
#undef set_dtable

	mmu_reset_needed |= guest_cr0() != sregs->cr0;
	__set_cr0(sregs->cr0);
	vcpu->regs[VCPU_REGS_CR2] = sregs->cr2;
	mmu_reset_needed |= vcpu->cr3 != sregs->cr3;
	vcpu->cr3 = sregs->cr3;

	mmu_reset_needed |=  guest_cr4() != sregs->cr4;
	__set_cr4(sregs->cr4);
	vcpu->cr8 = sregs->cr8;

	mmu_reset_needed |= vcpu->shadow_efer != sregs->efer;
	__set_efer(vcpu, sregs->efer);
	vcpu->apic_base = sregs->apic_base;

	if (mmu_reset_needed)
		kvm_mmu_reset_context(vcpu);
	vcpu_put(vcpu);

	return 0;
}

/*
 * Translate a guest virtual address to a guest physical address.
 */
static int kvm_dev_ioctl_translate(struct kvm *kvm, struct kvm_translation *tr)
{
	unsigned long vaddr = tr->linear_address;
	struct kvm_vcpu *vcpu = &kvm->vcpus[tr->vcpu];
	u64 pte;

	vcpu_load(vcpu);
	pte = vcpu->mmu.fetch_pte64(vcpu, vaddr);
	tr->physical_address = (pte & 0xfffffffff000) | (vaddr & ~PAGE_MASK);
	tr->valid = pte & 1;
	tr->writeable = 1;
	tr->usermode = 0;
	vcpu_put(vcpu);

	return 0;
}

static int kvm_dev_ioctl_interrupt(struct kvm *kvm, struct kvm_interrupt *irq)
{
	struct kvm_vcpu *vcpu;

	if (irq->vcpu < 0 || irq->vcpu >= kvm->nvcpus)
		return -EINVAL;
	if (irq->irq < 0 || irq->irq >= 256)
		return -EINVAL;
	vcpu = &kvm->vcpus[irq->vcpu];

	vcpu_load(vcpu);

	set_bit(irq->irq, vcpu->irq_pending);
	set_bit(irq->irq / BITS_PER_LONG, &vcpu->irq_summary);

	vcpu_put(vcpu);

	return 0;
}

static int kvm_dev_ioctl_debug_guest(struct kvm *kvm,
				     struct kvm_debug_guest *dbg)
{
	struct kvm_vcpu *vcpu;
	unsigned long dr7 = 0x400;
	u32 exception_bitmap;
	int old_singlestep;

	if (dbg->vcpu < 0 || dbg->vcpu >= kvm->nvcpus)
		return -EINVAL;
	vcpu = &kvm->vcpus[dbg->vcpu];

	vcpu_load(vcpu);

	exception_bitmap = vmcs_read32(EXCEPTION_BITMAP);
	old_singlestep = vcpu->guest_debug.singlestep;

	vcpu->guest_debug.enabled = dbg->enabled;
	if (vcpu->guest_debug.enabled) {
		int i;

		dr7 |= 0x200;  /* exact */
		for (i = 0; i < 4; ++i) {
			if (!dbg->breakpoints[i].enabled)
				continue;
			vcpu->guest_debug.bp[i] = dbg->breakpoints[i].address;
			dr7 |= 2 << (i*2);    /* global enable */
			dr7 |= 0 << (i*4+16); /* execution breakpoint */
		}

		exception_bitmap |= (1u << 1);  /* Trap debug exceptions */

		vcpu->guest_debug.singlestep = dbg->singlestep;
	} else {
		exception_bitmap &= ~(1u << 1); /* Ignore debug exceptions */
		vcpu->guest_debug.singlestep = 0;
	}

	if (old_singlestep && !vcpu->guest_debug.singlestep) {
		unsigned long flags;

		flags = vmcs_readl(GUEST_RFLAGS);
		flags &= ~(X86_EFLAGS_TF | X86_EFLAGS_RF);
		vmcs_writel(GUEST_RFLAGS, flags);
	}

	vmcs_write32(EXCEPTION_BITMAP, exception_bitmap);
	vmcs_writel(GUEST_DR7, dr7);

	vcpu_put(vcpu);

	return 0;
}

static long kvm_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	int r = -EINVAL;

	switch (ioctl) {
	case KVM_SET_LOG_FD: {
		r = kvm_dev_ioctl_set_logfd(kvm, arg);
		if (r)
			goto out;
		break;
	}
	case KVM_CREATE_VCPUS: {
		r = kvm_dev_ioctl_create_vcpus(kvm, arg);
		if (r)
			goto out;
		break;
	}
	case KVM_RUN: {
		struct kvm_run kvm_run;
	
		r = -EFAULT;
		if (copy_from_user(&kvm_run, (void *)arg, sizeof kvm_run))
			goto out;
		r = kvm_dev_ioctl_run(kvm, &kvm_run);
		if (r < 0)
			goto out;
		r = -EFAULT;
		if (copy_to_user((void *)arg, &kvm_run, sizeof kvm_run))
			goto out;
		r = 0;
		break;
	}
	case KVM_GET_REGS: {
		struct kvm_regs kvm_regs;
	
		r = -EFAULT;
		if (copy_from_user(&kvm_regs, (void *)arg, sizeof kvm_regs))
			goto out;
		r = kvm_dev_ioctl_get_regs(kvm, &kvm_regs);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user((void *)arg, &kvm_regs, sizeof kvm_regs))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_REGS: {
		struct kvm_regs kvm_regs;
	
		r = -EFAULT;
		if (copy_from_user(&kvm_regs, (void *)arg, sizeof kvm_regs))
			goto out;
		r = kvm_dev_ioctl_set_regs(kvm, &kvm_regs);
		if (r)
			goto out;
		r = 0;
		break;
	}
	case KVM_GET_SREGS: {
		struct kvm_sregs kvm_sregs;
	
		r = -EFAULT;
		if (copy_from_user(&kvm_sregs, (void *)arg, sizeof kvm_sregs))
			goto out;
		r = kvm_dev_ioctl_get_sregs(kvm, &kvm_sregs);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user((void *)arg, &kvm_sregs, sizeof kvm_sregs))
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_SREGS: {
		struct kvm_sregs kvm_sregs;
	
		r = -EFAULT;
		if (copy_from_user(&kvm_sregs, (void *)arg, sizeof kvm_sregs))
			goto out;
		r = kvm_dev_ioctl_set_sregs(kvm, &kvm_sregs);
		if (r)
			goto out;
		r = 0;
		break;
	}
	case KVM_TRANSLATE: {
		struct kvm_translation tr;
	
		r = -EFAULT;
		if (copy_from_user(&tr, (void *)arg, sizeof tr))
			goto out;
		r = kvm_dev_ioctl_translate(kvm, &tr);
		if (r)
			goto out;
		r = -EFAULT;
		if (copy_to_user((void *)arg, &tr, sizeof tr))
			goto out;
		r = 0;
		break;
	}
	case KVM_INTERRUPT: {
		struct kvm_interrupt irq;
	
		r = -EFAULT;
		if (copy_from_user(&irq, (void *)arg, sizeof irq))
			goto out;
		r = kvm_dev_ioctl_interrupt(kvm, &irq);
		if (r)
			goto out;
		r = 0;
		break;
	}
	case KVM_DEBUG_GUEST: {
		struct kvm_debug_guest dbg;
	
		r = -EFAULT;
		if (copy_from_user(&dbg, (void *)arg, sizeof dbg))
			goto out;
		r = kvm_dev_ioctl_debug_guest(kvm, &dbg);
		if (r)
			goto out;
		r = 0;
		break;
	}
	case KVM_SET_MEMORY_REGION: {
		struct kvm_memory_region kvm_mem;
	
		r = -EFAULT;
		if (copy_from_user(&kvm_mem, (void *)arg, sizeof kvm_mem))
			goto out;
		r = kvm_dev_ioctl_set_memory_region(kvm, &kvm_mem);
		if (r)
			goto out;
		break;
	}
	case KVM_GET_DIRTY_LOG: {
		struct kvm_dirty_log log;
	
		r = -EFAULT;
		if (copy_from_user(&log, (void *)arg, sizeof log))
			goto out;
		r = kvm_dev_ioctl_get_dirty_log(kvm, &log);
		if (r)
			goto out;
		break;
	}
	default:
		;
	}
 out:
	return r;
}

static struct page *kvm_dev_nopage(struct vm_area_struct *vma,
				   unsigned long address,
				   int *type)
{
	struct kvm *kvm = vma->vm_file->private_data;
	unsigned long pgoff;
	struct page *page;

	*type = VM_FAULT_MINOR;
	pgoff = ((address - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
	page = gfn_to_page(kvm, pgoff);
	if (page)
		get_page(page);
	else
		page = NOPAGE_SIGBUS;
	return page;
}

static struct vm_operations_struct kvm_dev_vm_ops = {
	.nopage = kvm_dev_nopage,
};

static int kvm_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &kvm_dev_vm_ops;
	return 0;
}

static struct file_operations kvm_chardev_ops = {
	.owner		= THIS_MODULE,
	.open		= kvm_dev_open,
	.release        = kvm_dev_release,
	.unlocked_ioctl = kvm_dev_ioctl,
	.mmap           = kvm_dev_mmap,
};

static struct miscdevice kvm_dev = {
	MISC_DYNAMIC_MINOR,
	"kvm",
	&kvm_chardev_ops,
};

static int kvm_reboot(struct notifier_block *notifier, unsigned long val,
                       void *v)
{
	if (val == SYS_RESTART) {
		/*
		 * Some (well, at least mine) BIOSes hang on reboot if
		 * in vmx root mode.
		 */
		printk(KERN_INFO "kvm: exiting vmx mode\n");
		on_each_cpu(kvm_disable, 0, 0, 1);
	}
	return NOTIFY_OK;
}

static struct notifier_block kvm_reboot_notifier = {
	.notifier_call = kvm_reboot,
	.priority = 0,
};

struct page *kvm_bad_page;
hpa_t kvm_bad_page_addr;

static __init void kvm_init_debug(void)
{
	debugfs_dir = debugfs_create_dir("kvm", 0);
	debugfs_pf_fixed = debugfs_create_u32("pf_fixed", 0444, debugfs_dir,
					      &kvm_stat.pf_fixed);
	debugfs_pf_guest = debugfs_create_u32("pf_guest", 0444, debugfs_dir,
					      &kvm_stat.pf_guest);
	debugfs_tlb_flush = debugfs_create_u32("tlb_flush", 0444, debugfs_dir,
					       &kvm_stat.tlb_flush);
	debugfs_invlpg = debugfs_create_u32("invlpg", 0444, debugfs_dir,
					      &kvm_stat.invlpg);
	debugfs_exits = debugfs_create_u32("exits", 0444, debugfs_dir,
					   &kvm_stat.exits);
	debugfs_io_exits = debugfs_create_u32("io_exits", 0444, debugfs_dir,
					      &kvm_stat.io_exits);
	debugfs_mmio_exits = debugfs_create_u32("mmio_exits", 0444,
						debugfs_dir,
						&kvm_stat.mmio_exits);
	debugfs_signal_exits = debugfs_create_u32("signal_exits", 0444,
						  debugfs_dir,
						  &kvm_stat.signal_exits);
	debugfs_irq_exits = debugfs_create_u32("irq_exits", 0444, debugfs_dir,
					       &kvm_stat.irq_exits);
}

static void kvm_exit_debug(void)
{
	debugfs_remove(debugfs_signal_exits);
	debugfs_remove(debugfs_irq_exits);
	debugfs_remove(debugfs_mmio_exits);
	debugfs_remove(debugfs_io_exits);
	debugfs_remove(debugfs_exits);
	debugfs_remove(debugfs_pf_fixed);
	debugfs_remove(debugfs_pf_guest);
	debugfs_remove(debugfs_tlb_flush);
	debugfs_remove(debugfs_invlpg);
	debugfs_remove(debugfs_dir);
}

static __init int kvm_init(void)
{
	int r = 0;

	if (!cpu_has_kvm_support()) {
		printk(KERN_ERR "kvm: no hardware support\n");
		return -EOPNOTSUPP;
	}
	if (vmx_disabled_by_bios()) {
		printk(KERN_ERR "kvm: disabled by bios\n");
		return -EOPNOTSUPP;
	}

	kvm_init_debug();

	setup_vmcs_descriptor();
	r = alloc_kvm_area();
	if (r)
		goto out;
	on_each_cpu(kvm_enable, 0, 0, 1);
	register_reboot_notifier(&kvm_reboot_notifier);

	if ((kvm_bad_page = alloc_page(GFP_KERNEL)) == NULL)
		    goto out_free;

	kvm_bad_page_addr = page_to_pfn(kvm_bad_page) << PAGE_SHIFT;
	r = misc_register(&kvm_dev);
	if (r) {
		printk (KERN_ERR "kvm: misc device register failed\n");
		goto out_free_bad_page;
	}

	return r;

out_free_bad_page:
	__free_page(kvm_bad_page);
out_free:
	free_kvm_area();
out:
	kvm_exit_debug();
	return r;
}

static __exit void kvm_exit(void)
{
	kvm_exit_debug();
	misc_deregister(&kvm_dev);
	unregister_reboot_notifier(&kvm_reboot_notifier);
	on_each_cpu(kvm_disable, 0, 0, 1);
	free_kvm_area();
	__free_page(kvm_bad_page);
}

module_init(kvm_init)
module_exit(kvm_exit)
