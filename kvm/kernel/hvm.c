/* hardware virtual machine support module */

#include "hvm.h"

#include <linux/hvm.h>
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

#include "vmx.h"

static unsigned long read_tr_base(void);
static void vmcs_writel(unsigned long field, unsigned long value);
static void hvm_free_1to1_mapping(struct hvm *hvm);

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
		printk(KERN_ERR "hvm: vmclear fail: %p/%llx\n", 
		       vmcs, phys_addr);
}

static void __vcpu_clear(void *arg)
{
	struct hvm_vcpu *vcpu = arg;
	int cpu = smp_processor_id();

	if (vcpu->cpu == smp_processor_id())
		vmcs_clear(vcpu->vmcs);
	if (per_cpu(current_vmcs, cpu) == vcpu->vmcs)
		per_cpu(current_vmcs, cpu) = 0;
}

/*
 * Switches to specified vcpu, until a matching vcpu_put()
 */
static void vcpu_load(struct hvm_vcpu *vcpu)
{
	u64 phys_addr = __pa(vcpu->vmcs);
	int cpu = get_cpu();
	
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
			printk(KERN_ERR "hvm: vmptrld %p/%llx fail\n",
			       vcpu->vmcs, phys_addr);
	}

	if (vcpu->cpu != cpu) {
		vcpu->cpu = cpu;
		/* 
		 * Linux uses per-cpu TSS, so set this when switching
		 * processors.
		 */
		vmcs_writel(HOST_TR_BASE, read_tr_base()); /* 22.2.4 */
	}
}

static void vcpu_put(void)
{
	put_cpu();
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

static __init int cpu_has_hvm_support(void)
{
	unsigned long ecx = cpuid_ecx(1);
	return test_bit(5, &ecx); /* CPUID.1:ECX.VMX[bit 5] -> VT */
}

static __exit void free_hvm_area(void)
{
	int cpu;

	for_each_online_cpu(cpu)
		free_vmcs(per_cpu(vmxarea, cpu));
}

static __init int alloc_hvm_area(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct vmcs *vmcs;

		vmcs = alloc_vmcs_cpu(cpu);
		if (!vmcs) {
			free_hvm_area();
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

static __init void hvm_enable(void *garbage)
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

static void hvm_disable(void *garbage)
{
	asm volatile ( "vmxoff" : : : "cc" );
}

static int hvm_dev_open(struct inode *inode, struct file *filp)
{
	filp->private_data = kzalloc(sizeof(struct hvm), GFP_KERNEL);
	if (!filp->private_data)
		return -ENOMEM;
	return 0;
}

static void hvm_free_physmem(struct hvm *hvm)
{
	unsigned long i;

	for (i = 0; i < hvm->phys_mem_pages; ++i)
		__free_page(hvm->phys_mem[i]);
	vfree(hvm->phys_mem);
}

static void hvm_free_vmcs(struct hvm *hvm)
{
	unsigned int i;

	for (i = 0; i < hvm->nvcpus; ++i) {
		struct vmcs *vmcs = hvm->vcpus[i].vmcs;

		if (vmcs) {
			vmcs_clear(vmcs);
			free_vmcs(vmcs);
		}
	}
}

static int hvm_dev_release(struct inode *inode, struct file *filp)
{
	struct hvm *hvm = filp->private_data;
	
	if (hvm->created) {
		hvm_free_vmcs(hvm);
		hvm_free_physmem(hvm);
		hvm_free_1to1_mapping(hvm);
	}
	kfree(hvm);
	return 0;
}

static unsigned long vmcs_readl(unsigned long field)
{
	unsigned long value;
	
	asm ( "vmread %1, %0" : "=g"(value) : "r"(field) : "cc" );
	return value;
}

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

static void vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm ( "vmwrite %1, %2; setna %0" 
	      : "=g"(error) : "r"(value), "r"(field) : "cc" );
	if (error)
		printk(KERN_ERR "vmwrite error: reg %lx value %lx\n",
		       field, value);
}

static inline void vmcs_write16(unsigned long field, u16 value)
{
	vmcs_writel(field, value);
}

static inline void vmcs_write32(unsigned long field, u32 value)
{
	vmcs_writel(field, value);
}

static inline void vmcs_write64(unsigned long field, u64 value)
{
#ifdef __x86_64__
	vmcs_writel(field, value);
#else
	vmcs_writel(field, value);
	asm volatile ( "" );
	vmcs_writel(field+1, value >> 32);
#endif
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

#ifdef __x86_64__
#define HOST_IS_64 1
#else
#define HOST_IS_64 0
#endif
	
#define GUEST_IS_64 HOST_IS_64
	
static void hvm_vcpu_setup(struct hvm_vcpu *vcpu)
{
	extern asmlinkage void hvm_vmx_return(void);
	struct hvm *hvm = vcpu->hvm;
	u32 host_sysenter_cs;
	u32 junk;
	unsigned long a;
	struct descriptor_table dt;
	
	vcpu_load(vcpu);

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

	vmcs_write32(GUEST_CS_AR_BYTES, 0x809d 
		     | (GUEST_IS_64 << 13)
		     | (!GUEST_IS_64 << 14)); /* 22.3.1.2 */
	vmcs_write32(GUEST_DS_AR_BYTES, 0xc093);  /* 22.3.1.2 */
	vmcs_write32(GUEST_ES_AR_BYTES, 0xc093);  /* 22.3.1.2 */
	vmcs_write32(GUEST_FS_AR_BYTES, 0xc093);  /* 22.3.1.2 */
	vmcs_write32(GUEST_GS_AR_BYTES, 0xc093);  /* 22.3.1.2 */
	vmcs_write32(GUEST_SS_AR_BYTES, 0xc093);  /* 22.3.1.2 */

	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x1c082); /* 22.3.1.2 */
	vmcs_write32(GUEST_TR_AR_BYTES, 0xc08b);   /* 22.3.1.2 */

	vmcs_write32(GUEST_SYSENTER_CS, 0);  /* 22.3.1.1 */
	vmcs_writel(GUEST_SYSENTER_ESP, 0);  /* 22.3.1.1 */
	vmcs_writel(GUEST_SYSENTER_EIP, 0);  /* 22.3.1.1 */

	vmcs_writel(GUEST_RFLAGS, get_eflags() & ~0x200ul);  /* 22.3.1.2 , 22.3.1.4*/
	vmcs_writel(GUEST_RIP, 0); /* 22.3.1.4 */

	vmcs_writel(GUEST_CR0, read_cr0());  /* 22.3.1.1 */
	vmcs_writel(CR0_READ_SHADOW, read_cr0());
	vmcs_writel(GUEST_CR4, read_cr4());  /* 22.3.1.1, 22.3.1.6 */
	vmcs_writel(CR4_READ_SHADOW, read_cr4());
	vmcs_writel(GUEST_CR3, __pa(hvm->map_1to1[0]));  /* 22.3.1.1; FIXME: shadow */
	vmcs_write64(GUEST_DR7, 0);

	vmcs_writel(GUEST_GDTR_BASE, 0);   /* 22.3.1.3 */
	vmcs_write32(GUEST_GDTR_LIMIT, 0);  /* 22.3.1.3 */
	vmcs_writel(GUEST_IDTR_BASE, 0);   /* 22.3.1.3 */
	vmcs_write32(GUEST_IDTR_LIMIT, 0);  /* 22.3.1.3 */

	vmcs_write32(GUEST_ACTIVITY_STATE, 0); /* 22.3.1.5 */
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 1); /* 22.3.1.5 */
	vmcs_write32(GUEST_PENDING_DBG_EXCEPTIONS, 0); /* 22.3.1.5 */

	/* I/O */
	vmcs_write64(IO_BITMAP_A, 0);
	vmcs_write64(IO_BITMAP_B, 0);

	vmcs_write64(TSC_OFFSET, 0);

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
		     CPU_BASED_VIRTUAL_INTR_PENDING  /* 20.6.2 */
		     | CPU_BASED_HLT_EXITING         /* 20.6.2 */
		     | CPU_BASED_CR8_LOAD_EXITING    /* 20.6.2 */
		     | CPU_BASED_CR8_STORE_EXITING   /* 20.6.2 */
		     /* | CPU_BASED_TPR_SHADOW */    /* 20.6.2 */
		     | CPU_BASED_UNCOND_IO_EXITING   /* 20.6.2 */
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
	vmcs_writel(HOST_FS_BASE, 0); /* 22.2.4; FIXME: x86-64? */
	vmcs_writel(HOST_GS_BASE, 0); /* 22.2.4; FIXME: x86-64? */

	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);  /* 22.2.4 */

	get_gdt(&dt);
	vmcs_writel(HOST_GDTR_BASE, dt.base);   /* 22.2.4 */
	get_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.base);   /* 22.2.4 */


	vmcs_writel(HOST_RIP, (unsigned long)hvm_vmx_return); /* 22.2.5 */

	rdmsr(MSR_IA32_SYSENTER_CS, host_sysenter_cs, junk);
	vmcs_write32(HOST_IA32_SYSENTER_CS, host_sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_ESP, a);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, a);   /* 22.2.3 */
	rdmsrl(MSR_IA32_SYSENTER_EIP, a);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, a);   /* 22.2.3 */

	vmcs_write32(VM_EXIT_CONTROLS,   /* 20.7.1 */
		     (HOST_IS_64 << 9)   /* address space size */
		     | (1 << 15)         /* ack interrupts */
		     | 0x3edff           /* reserved, 22.2,1, 20.7.1 */
		);
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0); /* 22.2.2 */
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);  /* 22.2.2 */
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0); /* 22.2.2 */

	vmcs_write32(VM_ENTRY_CONTROLS, /* 20.8.1 */
		     (GUEST_IS_64 << 9) /* address space size, 22.2.5 */
		     | 0x11ff           /* reserved, 22.2.1, 20.8.1 */
		);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);  /* 22.2.1 */

	vmcs_writel(CR0_GUEST_HOST_MASK, -1ul);
	vmcs_writel(CR4_GUEST_HOST_MASK, -1ul);

	vcpu_put();
}

static void hvm_free_1to1_mapping(struct hvm *hvm)
{
	int i;

	for (i = 0; i < 4; ++i)
		free_page((unsigned long)hvm->map_1to1[i]);
}

static __init int hvm_setup_1to1_mapping(struct hvm *hvm)
{
	int i;

	for (i = 0; i < 4; ++i) {
		struct page *page;

		page = alloc_page(GFP_KERNEL);
		if (!page)
			goto out_free;
		hvm->map_1to1[i] = page_address(page);
		memset(hvm->map_1to1[i], 0, PAGE_SIZE);
	}
	hvm->map_1to1[0][0] = __pa(hvm->map_1to1[1]) | 0x23;
	hvm->map_1to1[1][0] = __pa(hvm->map_1to1[2]) | 0x23;
	hvm->map_1to1[2][0] = __pa(hvm->map_1to1[3]) | 0x23;
	for (i = 0; i < 512; ++i)
		hvm->map_1to1[3][i] = __pa(page_address(hvm->phys_mem[i])) | 0x163;
	return 0;
out_free:
	hvm_free_1to1_mapping(hvm);
	return -ENOMEM;
}

static int hvm_dev_ioctl_create(struct hvm *hvm, struct hvm_create *hvm_create)
{
	int r;
	unsigned long pages = ((hvm_create->memory_size-1) >> PAGE_SHIFT) + 1;
	unsigned long i;

	r = -EEXIST;
	if (hvm->created)
		goto out;
	r = -EINVAL;
	if (!hvm_create->memory_size)
		goto out;
	hvm->phys_mem_pages = pages;
	hvm->phys_mem = vmalloc(pages * sizeof(struct page *));
	r = -ENOMEM;
	if (!hvm->phys_mem)
		goto out;
	memset(hvm->phys_mem, 0, pages * sizeof(struct page *));
	for (i = 0; i < pages; ++i) {
		hvm->phys_mem[i] = alloc_page(GFP_HIGHUSER);
		if (!hvm->phys_mem[i])
			goto out_free_physmem;
	}
	r = hvm_setup_1to1_mapping(hvm);
	if (r)
		goto out_free_physmem;
	hvm->nvcpus = 1;
	for (i = 0; i < hvm->nvcpus; ++i) {
		struct vmcs *vmcs;

		hvm->vcpus[i].hvm = hvm;
		vmcs = alloc_vmcs();
		if (!vmcs)
			goto out_free_vmcs;
		vmcs_clear(vmcs);
		hvm->vcpus[i].vmcs = vmcs;
		hvm->vcpus[i].launched = 0;

		hvm_vcpu_setup(&hvm->vcpus[i]);
	}
		
	hvm->created = 1;
	return 0;

out_free_vmcs:
	hvm_free_vmcs(hvm);
out_free_physmem:
	hvm_free_physmem(hvm);
out:
	return r;
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

static int hvm_dev_ioctl_run(struct hvm *hvm, struct hvm_run *hvm_run)
{
	struct hvm_vcpu *vcpu;
	u8 fail;

	if (hvm_run->vcpu < 0 || hvm_run->vcpu >= hvm->nvcpus)
		return -EINVAL;
	vcpu = &hvm->vcpus[hvm_run->vcpu];
	
	vcpu_load(vcpu);

#ifdef __x86_64__
	vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));
	vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));
#endif

#ifdef __x86_64__
#define SP "rsp"
#define PUSHA "push %%rax; push %%rbx; push %%rcx; push %%rdx;" \
              "push %%rsi; push %%rdi; push %%rbp;" \
	      "push %%r8;  push %%r9;  push %%r10; push %%r11;" \
              "push %%r12; push %%r13; push %%r14; push %%r15"
#define POPA  "pop  %%r15; pop  %%r14; pop  %%r13; pop  %%r12;" \
	      "pop  %%r11; pop  %%r10; pop  %%r9;  pop  %%r8;"	\
	      "pop  %%rbp; pop  %%rdi; pop  %%rsi;"	       \
	      "pop  %%rdx; pop  %%rcx; pop  %%rbx; pop  %%rax"
#else
#define SP "esp"
#define PUSHA "pusha"
#define POPA  "popa"
#endif

	asm ( PUSHA "\n\t"
	      "vmwrite %%" SP ", %2 \n\t"
	      "cmp $0, %1 \n\t"
	      "jne launched \n\t"
	      "vmlaunch \n\t"
	      "jmp error \n\t"
	      "launched: vmresume \n\t"
	      "error: " POPA " \n\t"
	      "mov $1, %1 \n\t"
	      "jmp done \n\t"
	      ".globl hvm_vmx_return \n\t"
	      "hvm_vmx_return: " POPA " \n\t"
              "mov $0, %0 \n\t"
	      "done:"
	      : "=g" (fail) 
	      : "r"(vcpu->launched), "r"((unsigned long)HOST_RSP) 
	      : "cc" );

	hvm_run->exit_type = 0;
	if (fail) {
		hvm_run->exit_type = HVM_EXIT_TYPE_FAIL_ENTRY;
		hvm_run->exit_reason = vmcs_read32(VM_INSTRUCTION_ERROR);
	} else {
		vcpu->launched = 1;
		hvm_run->exit_type = HVM_EXIT_TYPE_VM_EXIT;
		hvm_run->exit_reason = vmcs_read32(VM_EXIT_REASON);
	}

	vcpu_put();
	return 0;
}

static int hvm_dev_ioctl(struct inode *inode, struct file *filp,
                         unsigned int ioctl, unsigned long arg)
{
	struct hvm *hvm = filp->private_data;
	int r = -EINVAL;

	switch (ioctl) {
	case HVM_CREATE: {
		struct hvm_create hvm_create;
	
		r = -EFAULT;
		if (copy_from_user(&hvm_create, (void *)arg, sizeof hvm_create))
			goto out;
		r = hvm_dev_ioctl_create(hvm, &hvm_create);
		if (r)
			goto out;
		break;
	}
	case HVM_RUN: {
		struct hvm_run hvm_run;
	
		r = -EFAULT;
		if (copy_from_user(&hvm_run, (void *)arg, sizeof hvm_run))
			goto out;
		r = hvm_dev_ioctl_run(hvm, &hvm_run);
		r = -EFAULT;
		if (copy_to_user((void *)arg, &hvm_run, sizeof hvm_run))
			goto out;
		r = 0;
		break;
	}
	default:
		;
	}
 out:
	return r;
}

static struct page *hvm_dev_nopage(struct vm_area_struct *vma, 
				   unsigned long address, 
				   int *type)
{
	struct hvm *hvm = vma->vm_file->private_data;
	unsigned long pgoff;
	struct page *page = NOPAGE_SIGBUS;

	*type = VM_FAULT_MINOR;
	pgoff = (address - vma->vm_start) >> PAGE_SHIFT;
	if (pgoff >= hvm->phys_mem_pages)
		goto out;
	page = hvm->phys_mem[pgoff];
	get_page(page);
out:
	return page;
}

static struct vm_operations_struct hvm_dev_vm_ops = {
	.nopage = hvm_dev_nopage,
};

static int hvm_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &hvm_dev_vm_ops;
	return 0;
}

static struct file_operations hvm_chardev_ops = {
	.owner		= THIS_MODULE,
	.open		= hvm_dev_open,
	.release        = hvm_dev_release,
	.ioctl          = hvm_dev_ioctl,
	.mmap           = hvm_dev_mmap,
};

static struct miscdevice hvm_dev = {
	MISC_DYNAMIC_MINOR,
	"hvm",
	&hvm_chardev_ops,
};

static int hvm_reboot(struct notifier_block *notifier, unsigned long val,
                       void *v)
{
	if (val == SYS_RESTART) {
		printk(KERN_INFO "hvm: exiting vmx mode\n");
		on_each_cpu(hvm_disable, 0, 0, 1);
	}
	return NOTIFY_OK;
}

static struct notifier_block hvm_reboot_notifier = {
	.notifier_call = hvm_reboot,
	.priority = 0,
};

static __init int hvm_init(void)
{
	int r = 0;

	if (!cpu_has_hvm_support()) {
		printk(KERN_ERR "hvm: no hardware support\n");
		return -EOPNOTSUPP;
	}
	if (vmx_disabled_by_bios()) {
		printk(KERN_ERR "hvm: disabled by bios\n");
		return -EOPNOTSUPP;
	}

	setup_vmcs_descriptor();
	r = alloc_hvm_area();
	if (r)
		goto out;
	on_each_cpu(hvm_enable, 0, 0, 1);
	register_reboot_notifier(&hvm_reboot_notifier);

	r = misc_register(&hvm_dev);
	if (r) {
		printk (KERN_ERR "hvm: misc device register failed\n");
		goto out_free;
	}

	return r;
out_free:
	free_hvm_area();
out:
	return r;
}

static __exit void hvm_exit(void)
{
	misc_deregister(&hvm_dev);
	unregister_reboot_notifier(&hvm_reboot_notifier);
	on_each_cpu(hvm_disable, 0, 0, 1);
	free_hvm_area();
}

module_init(hvm_init)
module_exit(hvm_exit)
