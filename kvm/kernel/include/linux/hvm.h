#ifndef __LINUX_HVM_H
#define __LINUX_HVM_H

#include <asm/types.h>

/* for HVM_CREATE */
struct hvm_create {
	__u64 memory_size; /* bytes */
};

#define HVM_CREATE 1

#endif
