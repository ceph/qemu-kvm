#ifndef QEMU_KVM_H
#define QEMU_KVM_H

#include "kvmctl.h"

void kvm_qemu_init(void);
int kvm_cpu_exec(CPUState *env);
int kvm_update_debugger(CPUState *env);

#endif
