#ifndef HVMCTL_H
#define HVMCTL_H

#include <linux/hvm.h>

struct hvm_context;

typedef struct hvm_context *hvm_context_t;

hvm_context_t hvm_init();
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
