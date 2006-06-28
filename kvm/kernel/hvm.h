#ifndef __HVM_H
#define __HVM_H

#define HVM_MAX_VCPUS 4

#include <linux/types.h>

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

struct hvm_vcpu {
	struct vmcs *vmcs;
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
