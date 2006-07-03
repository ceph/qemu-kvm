#ifndef __LINUX_HVM_H
#define __LINUX_HVM_H

#include <asm/types.h>

/* for HVM_CREATE */
struct hvm_create {
	__u64 memory_size; /* bytes */
};

#define HVM_EXIT_TYPE_FAIL_ENTRY 1
#define HVM_EXIT_TYPE_VM_EXIT    2

enum hvm_exit_reason {
	HVM_EXIT_UNKNOWN,
	HVM_EXIT_EXCEPTION,
	HVM_EXIT_IO,
};

/* for HVM_RUN */
struct hvm_run {
	/* in */
	int vcpu;
	/* out */
	int exit_type;
	__u32 exit_reason;
	union {
		/* HVM_EXIT_EXCEPTION */
		struct {
			__u32 exception;
			__u32 error_code;
		} ex;
		/* HVM_EXIT_IO */
		struct {
#define HVM_EXIT_IO_IN  0
#define HVM_EXIT_IO_OUT 1
			__u8 direction;
			__u8 size; /* bytes */
			__u8 string;
			__u8 string_down;
			__u8 rep;
			__u8 pad;
			__u16 port;
			__u64 count;
			union {
				__u64 address;
				__u32 value;
			};
		} io;
	};
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
