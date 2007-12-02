#include "printf.h"

#define KVM_HYPERCALL ".byte 0x0f,0x01,0xc1"

static inline long kvm_hypercall0(unsigned int nr)
{
	long ret;
	asm volatile(KVM_HYPERCALL
		     : "=a"(ret)
		     : "a"(nr));
	return ret;
}

int main(int ac, char **av)
{
	kvm_hypercall0(-1u);
	printf("Hypercall: OK\n");
	return 0;
}
