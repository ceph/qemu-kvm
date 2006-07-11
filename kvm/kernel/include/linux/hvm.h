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
	HVM_EXIT_CPUID,
};

/* for HVM_RUN */
struct hvm_run {
	/* in */
	int vcpu;
	/* out */
	int exit_type;
	__u32 exit_reason;
	__u32 instruction_length;
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

struct hvm_segment {
	__u64 base;
	__u32 limit;
	__u16 selector;
	__u8  type;
	__u8  present, dpl, db, s, l, g, avl;
	__u8  unusable;
};

struct hvm_dtable {
	__u64 base;
	__u16 limit;
};

/* for HVM_GET_SREGS and HVM_SET_SREGS */
struct hvm_sregs {
	/* in */
	int vcpu;

	/* out (HVM_GET_SREGS) / in (HVM_SET_SREGS) */
	struct hvm_segment cs, ds, es, fs, gs, ss;
	struct hvm_segment tr, ldt;
	struct hvm_dtable gdt, idt;
	__u64 cr0, cr2, cr3, cr4, cr8;
};

/* for HVM_TRANSLATE */
struct hvm_translation {
	/* in */
	__u64 linear_address;
	int   vcpu;

	/* out */
	__u64 physical_address;
	__u8  valid;
	__u8  writeable;
	__u8  usermode;
};

/* for HVM_INTERRUPT */
struct hvm_interrupt {
	/* in */
	int vcpu;
	__u8 irq;
};

#define HVM_CREATE 1
#define HVM_RUN    2
#define HVM_GET_REGS 3
#define HVM_SET_REGS 4
#define HVM_GET_SREGS 5
#define HVM_SET_SREGS 6
#define HVM_TRANSLATE 7
#define HVM_INTERRUPT 8

#endif
