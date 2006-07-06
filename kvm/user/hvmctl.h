#ifndef HVMCTL_H
#define HVMCTL_H

#include <linux/hvm.h>
#include <stdint.h>

struct hvm_context;

typedef struct hvm_context *hvm_context_t;

struct hvm_callbacks {
    void (*cpuid)(void *opaque, 
		  uint64_t *rax, uint64_t *rbx, uint64_t *rcx, uint64_t *rdx);
};

hvm_context_t hvm_init(struct hvm_callbacks *callbacks,
		       void *opaque);
int hvm_create(hvm_context_t hvm,
	       unsigned long phys_mem_bytes,
	       void **phys_mem);
int hvm_run(hvm_context_t hvm, int vcpu);
int hvm_get_regs(hvm_context_t, int vcpu, struct hvm_regs *regs);
int hvm_set_regs(hvm_context_t, int vcpu, struct hvm_regs *regs);
int hvm_get_sregs(hvm_context_t, int vcpu, struct hvm_sregs *regs);
int hvm_set_sregs(hvm_context_t, int vcpu, struct hvm_sregs *regs);
void hvm_show_regs(hvm_context_t, int vcpu);

#endif
