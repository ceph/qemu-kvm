#ifndef __HVM_H
#define __HVM_H

#define HVM_MAX_VCPUS 4

struct hvm_vcpu {
	void *vmcs;
	int   cpu;
	int   launched;
};

struct hvm {
	unsigned created : 1;
	unsigned long phys_mem_pages;
	struct page **phys_mem;
	int nvcpus;
	struct hvm_vcpu vcpus[HVM_MAX_VCPUS];
};

#endif
