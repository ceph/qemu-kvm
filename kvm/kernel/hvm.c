/* hardware virtual machine support module */

#include <linux/module.h>
#include <linux/errno.h>
#include <asm/processor.h>
#include <linux/percpu.h>
#include <linux/gfp.h>
#include <asm/msr.h>
#include <linux/mm.h>

DEFINE_PER_CPU(void *, vmxarea);
static int vmcs_order;

static __init int cpu_has_hvm_support(void)
{
	unsigned long ecx = cpuid_ecx(1);
	return test_bit(5, &ecx); /* CPUID.1:ECX.VMX[bit 5] -> VT */
}

static __exit void free_hvm_area(void)
{
	int cpu;

	for_each_online_cpu(cpu)
		free_pages((unsigned long)per_cpu(vmxarea, cpu), 0);
}

#define MSR_IA32_FEATURE_CONTROL 0x03a
#define MSR_IA32_VMX_BASIC_MSR   0x480

static __init int alloc_hvm_area(void)
{
	int cpu;
	u32 vmx_msr_low, vmx_msr_high;
	int vmcs_size;

	rdmsr(MSR_IA32_VMX_BASIC_MSR, vmx_msr_low, vmx_msr_high);
	vmcs_size = vmx_msr_high & 0x1fff;
	vmcs_order = get_order(vmcs_size);

	for_each_online_cpu(cpu) {
		void *vmcs;
		int node = cpu_to_node(cpu);

		vmcs = page_address(alloc_pages_node(node, GFP_KERNEL, 0));
		if (!vmcs) {
			free_hvm_area();
			return -ENOMEM;
		}
		
		per_cpu(vmxarea, cpu) = vmcs;
		memset(vmcs, 0, vmcs_size);

		*(u32 *)vmcs = vmx_msr_low; /* vmcs revision id */
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
	asm volatile ( "vmxon %0" : : "m"(phys_addr) );
}

static __exit void hvm_disable(void *garbage)
{
	asm volatile ( "vmxoff" );
}

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

	r = alloc_hvm_area();
	if (r)
		goto out;
	on_each_cpu(hvm_enable, 0, 0, 1);
out:
	return r;
}

static __exit void hvm_exit(void)
{
	on_each_cpu(hvm_disable, 0, 0, 1);
	free_hvm_area();
}

module_init(hvm_init)
module_exit(hvm_exit)
