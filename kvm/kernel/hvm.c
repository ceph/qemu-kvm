/* hardware virtual machine support module */

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

#define HVM_MAX_VCPUS 4

struct hvm {
	unsigned created : 1;
	unsigned long phys_mem_pages;
	struct page **phys_mem;
	int nvcpus;
	void *vmcs[HVM_MAX_VCPUS];
};

DEFINE_PER_CPU(void *, vmxarea);

static struct vmcs_descriptor {
	int size;
	int order;
	u32 revision_id;
} vmcs_descriptor;

#define MSR_IA32_FEATURE_CONTROL 0x03a
#define MSR_IA32_VMX_BASIC_MSR   0x480

static __init void setup_vmcs_descriptor(void)
{
	u32 vmx_msr_low, vmx_msr_high;

	rdmsr(MSR_IA32_VMX_BASIC_MSR, vmx_msr_low, vmx_msr_high);
	vmcs_descriptor.size = vmx_msr_high & 0x1fff;
	vmcs_descriptor.order = get_order(vmcs_descriptor.size);
	vmcs_descriptor.revision_id = vmx_msr_low;
};

static void vmcs_clear(void *vmcs)
{
	u64 phys_addr = __pa(vmcs);

	asm volatile ( "vmclear %0" : : "m"(phys_addr) : "cc", "memory" );
}

static void *alloc_vmcs_cpu(int cpu)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	void *vmcs;

	pages = alloc_pages_node(node, GFP_KERNEL, vmcs_descriptor.order);
	if (!pages)
		return 0;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_descriptor.size);
	*(u32 *)vmcs = vmcs_descriptor.revision_id; /* vmcs revision id */
	return vmcs;
}

static void *alloc_vmcs(void)
{
	return alloc_vmcs_cpu(smp_processor_id());
}

static void free_vmcs(void *vmcs)
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
		void *vmcs;

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

static __exit void hvm_disable(void *garbage)
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
		void *vmcs = hvm->vmcs[i];

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
	}
	kfree(hvm);
	return 0;
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
	hvm->nvcpus = 1;
	for (i = 0; i < hvm->nvcpus; ++i) {
		void *vmcs;

		vmcs = alloc_vmcs();
		if (!vmcs)
			goto out_free_vmcs;
		vmcs_clear(vmcs);
		hvm->vmcs[i] = vmcs;
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
