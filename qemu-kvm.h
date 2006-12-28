#ifndef QEMU_KVM_H
#define QEMU_KVM_H

#include "kvmctl.h"

int kvm_qemu_init(void);
int kvm_qemu_create_context(void);
void kvm_qemu_destroy(void);
void kvm_load_registers(CPUState *env);
void kvm_save_registers(CPUState *env);
int kvm_cpu_exec(CPUState *env);
int kvm_update_debugger(CPUState *env);

#endif
