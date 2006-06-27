#ifndef __LINUX_HVM_H
#define __LINUX_HVM_H

#include <asm/types.h>

/* for HVM_CREATE */
struct hvm_create {
	__u64 memory_size; /* bytes */
};

#define HVM_EXIT_TYPE_FAIL_ENTRY 1
#define HVM_EXIT_TYPE_VM_EXIT    2

/* for HVM_RUN */
struct hvm_run {
	/* in */
	int vcpu;
	/* out */
	int exit_type;
	int exit_reason;
};

#define HVM_CREATE 1
#define HVM_RUN    2

#endif
