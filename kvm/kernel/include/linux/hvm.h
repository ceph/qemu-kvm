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
	__u32 exit_reason;
};

/* for HVM_GET_REGS and HVM_SET_REGS */
struct hvm_regs {
	/* in */
	int vcpu;
	
	/* out (HVM_GET_REGS) / in (HVM_SET_REGS) */
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8,  r9,  r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;
};

#define HVM_CREATE 1
#define HVM_RUN    2
#define HVM_GET_REGS 3
#define HVM_SET_REGS 4

#endif
