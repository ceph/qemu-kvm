#ifndef __HVM_DEBUG_H
#define __HVM_DEBUG_H

#ifdef KVM_DEBUG

void show_msrs(struct hvm_vcpu *vcpu);
int read_guest(struct hvm_vcpu *vcpu,
	       vaddr_t addr,
	       unsigned long size,
	       void *dest);
int write_guest(struct hvm_vcpu *vcpu,
			     vaddr_t addr,
			     unsigned long size,
			     void *dest);
void show_irq(struct hvm_vcpu *vcpu,  int irq);
void show_page(struct hvm_vcpu *vcpu, vaddr_t addr);
int vm_entry_test(struct hvm_vcpu *vcpu);

#endif

#endif
