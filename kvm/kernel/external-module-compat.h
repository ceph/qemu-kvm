
/*
 * Compatibility header for building as an external module.
 */

/*
 * Avoid picking up the kernel's kvm.h in case we have a newer one.
 */

#include <linux/compiler.h>
#include "include/linux/kvm.h"

