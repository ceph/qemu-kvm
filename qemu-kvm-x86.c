
#include "config.h"
#include "config-host.h"

extern int kvm_allowed;
extern int kvm_irqchip;

#ifdef USE_KVM

#include <string.h>
#include "vl.h"

#include "qemu-kvm.h"
#include <libkvm.h>
#include <pthread.h>
#include <sys/utsname.h>

static struct kvm_msr_list *kvm_msr_list;
extern unsigned int kvm_shadow_memory;
extern kvm_context_t kvm_context;
extern int kvm_has_msr_star;

int kvm_arch_qemu_create_context(void)
{
    int i;
    if (kvm_shadow_memory)
        kvm_set_shadow_pages(kvm_context, kvm_shadow_memory);

    kvm_msr_list = kvm_get_msr_list(kvm_context);
    if (!kvm_msr_list)
		return -1;
    for (i = 0; i < kvm_msr_list->nmsrs; ++i)
	if (kvm_msr_list->indices[i] == MSR_STAR)
	    kvm_has_msr_star = 1;
	return 0;
}

#endif
