#ifndef __LINUX_KVM_H
#define __LINUX_KVM_H

#include <asm/types.h>
#include <linux/ioctl.h>

/* for KVM_CREATE_MEMORY_REGION */
struct kvm_memory_region {
	__u64 guest_phys_addr;
	__u64 memory_size; /* bytes */
};


#define KVM_EXIT_TYPE_FAIL_ENTRY 1
#define KVM_EXIT_TYPE_VM_EXIT    2

enum kvm_exit_reason {
	KVM_EXIT_UNKNOWN,
	KVM_EXIT_EXCEPTION,
	KVM_EXIT_IO,
	KVM_EXIT_CPUID,
	KVM_EXIT_EMULATE_ONE_INSTRUCTION,
	KVM_EXIT_DEBUG,
	KVM_EXIT_HLT,
	KVM_EXIT_MMIO,
	KVM_EXIT_REAL_MODE,
};

/* for KVM_RUN */
struct kvm_run {
	/* in */
	int vcpu;
	int emulated;  /* skip current instruction */
	int mmio_completed; /* mmio request completed */

	/* out */
	int exit_type;
	__u32 exit_reason;
	__u32 instruction_length;
	union {
		/* KVM_EXIT_UNKNOWN */
		struct {
			__u32 hardware_exit_reason;
		} hw;
		/* KVM_EXIT_EXCEPTION */
		struct {
			__u32 exception;
			__u32 error_code;
		} ex;
		/* KVM_EXIT_IO */
		struct {
#define KVM_EXIT_IO_IN  0
#define KVM_EXIT_IO_OUT 1
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
		struct {
		} debug;
		/* KVM_EXIT_MMIO */
		struct {
			__u64 phys_addr;
			__u8  data[8];
			__u32 len;
			__u8  is_write;
		} mmio;
	};
};

/* for KVM_GET_REGS and KVM_SET_REGS */
struct kvm_regs {
	/* in */
	int vcpu;
	
	/* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8,  r9,  r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;
};

struct kvm_segment {
	__u64 base;
	__u32 limit;
	__u16 selector;
	__u8  type;
	__u8  present, dpl, db, s, l, g, avl;
	__u8  unusable;
};

struct kvm_dtable {
	__u64 base;
	__u16 limit;
};

/* for KVM_GET_SREGS and KVM_SET_SREGS */
struct kvm_sregs {
	/* in */
	int vcpu;

	/* out (KVM_GET_SREGS) / in (KVM_SET_SREGS) */
	struct kvm_segment cs, ds, es, fs, gs, ss;
	struct kvm_segment tr, ldt;
	struct kvm_dtable gdt, idt;
	__u64 cr0, cr2, cr3, cr4, cr8;
	__u64 efer;
	__u64 apic_base;

	/* out (KVM_GET_SREGS) */
	int pending_int;
};

/* for KVM_TRANSLATE */
struct kvm_translation {
	/* in */
	__u64 linear_address;
	int   vcpu;

	/* out */
	__u64 physical_address;
	__u8  valid;
	__u8  writeable;
	__u8  usermode;
};

/* for KVM_INTERRUPT */
struct kvm_interrupt {
	/* in */
	int vcpu;
	__u8 irq;
};

struct kvm_breakpoint {
	__u32 enabled;
	__u64 address;
};

/* for KVM_DEBUG_GUEST */
struct kvm_debug_guest {
	/* int */
	int vcpu;
	int enabled;
	struct kvm_breakpoint breakpoints[4];
	int singlestep;
};

#define KVM_SET_LOG_FD            _IOW( 'q', 1, int) /* arg = fd */
#define KVM_RUN                   _IOWR('q', 2, struct kvm_run)
#define KVM_GET_REGS              _IOWR('q', 3, struct kvm_regs)
#define KVM_SET_REGS              _IOW( 'q', 4, struct kvm_regs)
#define KVM_GET_SREGS             _IOWR('q', 5, struct kvm_sregs)
#define KVM_SET_SREGS             _IOW( 'q', 6, struct kvm_sregs)
#define KVM_TRANSLATE             _IOWR('q', 7, struct kvm_translation)
#define KVM_INTERRUPT             _IOW( 'q', 8, struct kvm_interrupt)
#define KVM_DEBUG_GUEST           _IOW( 'q', 9, struct kvm_debug_guest)
#define KVM_CREATE_MEMORY_REGION  _IOW( 'q', 10, struct kvm_memory_region)
#define KVM_CREATE_VCPUS           _IOW( 'q', 11, int) /* arg = nvcpus */

#endif
