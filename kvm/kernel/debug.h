#ifndef __KVM_DEBUG_H
#define __KVM_DEBUG_H

#ifdef KVM_DEBUG

void show_msrs(struct kvm_vcpu *vcpu);
int read_guest(struct kvm_vcpu *vcpu,
	       gva_t addr,
	       unsigned long size,
	       void *dest);

int write_guest(struct kvm_vcpu *vcpu,
		gva_t addr,
		unsigned long size,
		void *data);

void show_irq(struct kvm_vcpu *vcpu,  int irq);
void show_page(struct kvm_vcpu *vcpu, gva_t addr);
void show_code(struct kvm_vcpu *vcpu);
int vm_entry_test(struct kvm_vcpu *vcpu);

void vmcs_dump(struct kvm_vcpu *vcpu);
void regs_dump(struct kvm_vcpu *vcpu);
void sregs_dump(struct kvm_vcpu *vcpu);

#endif

#endif
