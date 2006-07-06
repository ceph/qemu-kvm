#ifndef QEMU_KVM_H
#define QEMU_KVM_H

int kvm_is_ok(CPUState *env);
int kvm_cpu_exec(CPUState *env);

#endif
