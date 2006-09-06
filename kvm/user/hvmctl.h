#ifndef HVMCTL_H
#define HVMCTL_H

#include <linux/kvm.h>
#include <stdint.h>

struct hvm_context;

typedef struct hvm_context *hvm_context_t;

struct hvm_callbacks {
    void (*cpuid)(void *opaque, 
		  uint64_t *rax, uint64_t *rbx, uint64_t *rcx, uint64_t *rdx);
    void (*inb)(void *opaque, uint16_t addr, uint8_t *data);
    void (*inw)(void *opaque, uint16_t addr, uint16_t *data);
    void (*inl)(void *opaque, uint16_t addr, uint32_t *data);
    void (*outb)(void *opaque, uint16_t addr, uint8_t data);
    void (*outw)(void *opaque, uint16_t addr, uint16_t data);
    void (*outl)(void *opaque, uint16_t addr, uint32_t data);
    void (*readb)(void *opaque, uint64_t addr, uint8_t *data);
    void (*readw)(void *opaque, uint64_t addr, uint16_t *data);
    void (*readl)(void *opaque, uint64_t addr, uint32_t *data);
    void (*readq)(void *opaque, uint64_t addr, uint64_t *data);
    void (*writeb)(void *opaque, uint64_t addr, uint8_t data);
    void (*writew)(void *opaque, uint64_t addr, uint16_t data);
    void (*writel)(void *opaque, uint64_t addr, uint32_t data);
    void (*writeq)(void *opaque, uint64_t addr, uint64_t data);
    void (*debug)(void *opaque, int vcpu);
    void (*emulate_one_instruction)(void *opaque);
    void (*halt)(void *opaque, int vcpu);
    void (*io_window)(void *opaque);
};

hvm_context_t hvm_init(struct hvm_callbacks *callbacks,
		       void *opaque);
int hvm_create(hvm_context_t hvm,
	       unsigned long phys_mem_bytes,
	       void **phys_mem,
	       int log_fd);
int hvm_run(hvm_context_t hvm, int vcpu);
int hvm_get_regs(hvm_context_t, int vcpu, struct hvm_regs *regs);
int hvm_set_regs(hvm_context_t, int vcpu, struct hvm_regs *regs);
int hvm_get_sregs(hvm_context_t, int vcpu, struct hvm_sregs *regs);
int hvm_set_sregs(hvm_context_t, int vcpu, struct hvm_sregs *regs);
int hvm_inject_irq(hvm_context_t, int vcpu, unsigned irq);
int hvm_guest_debug(hvm_context_t, int vcpu, struct hvm_debug_guest *dbg);
void hvm_show_regs(hvm_context_t, int vcpu);

#endif
