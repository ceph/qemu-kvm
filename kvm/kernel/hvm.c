/* hardware virtual machine support module */

#include <linux/module.h>
#include <linux/errno.h>

static int cpu_has_hvm_support(void)
{
	return 0;
}

static __init int hvm_init(void)
{
	if (!cpu_has_hvm_support()) {
		printk(KERN_ERR "hvm: no hardware support\n");
		return -EOPNOTSUPP;
	}
	/* VMXON */
	return 0;
}

static __exit void hvm_exit(void)
{
	/* VMXOFF */
}

module_init(hvm_init)
module_exit(hvm_exit)
