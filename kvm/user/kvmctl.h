#ifndef KVMCTL_H
#define KVMCTL_H

#include <linux/kvm.h>
#include <stdint.h>

struct kvm_context;

typedef struct kvm_context *kvm_context_t;

struct kvm_callbacks {
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

kvm_context_t kvm_init(struct kvm_callbacks *callbacks,
		       void *opaque);
int kvm_create(kvm_context_t kvm,
	       unsigned long phys_mem_bytes,
	       void **phys_mem,
	       int log_fd);
int kvm_run(kvm_context_t kvm, int vcpu);
int kvm_get_regs(kvm_context_t, int vcpu, struct kvm_regs *regs);
int kvm_set_regs(kvm_context_t, int vcpu, struct kvm_regs *regs);
int kvm_get_sregs(kvm_context_t, int vcpu, struct kvm_sregs *regs);
int kvm_set_sregs(kvm_context_t, int vcpu, struct kvm_sregs *regs);
int kvm_inject_irq(kvm_context_t, int vcpu, unsigned irq);
int kvm_guest_debug(kvm_context_t, int vcpu, struct kvm_debug_guest *dbg);
void kvm_show_regs(kvm_context_t, int vcpu);
void *kvm_create_phys_mem(kvm_context_t, unsigned long phys_start, 
			  unsigned long len, int slot, int writable);
void kvm_destroy_phys_mem(kvm_context_t, unsigned long phys_start, 
			  unsigned long len);

#endif
