/*
 * Compatibility header for building as an external module.
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#error "KVM/IA-64 Can't be compiled if kernel version < 2.6.26"
#endif

#ifndef CONFIG_PREEMPT_NOTIFIERS
/*Now, Just print an error message if no preempt notifiers configured!!
  TODO: Implement it later! */
#error "KVM/IA-64 depends on preempt notifiers in kernel."
#endif
