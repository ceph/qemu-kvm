/*
 * qemu/kvm integration, x86 specific code
 *
 * Copyright (C) 2006-2008 Qumranet Technologies
 *
 * Licensed under the terms of the GNU GPL version 2 or higher.
 */

#include "config.h"
#include "config-host.h"

#include <string.h>
#include "hw/hw.h"

#include "qemu-kvm.h"
#include <libkvm.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <linux/kvm_para.h>

#define MSR_IA32_TSC		0x10

static struct kvm_msr_list *kvm_msr_list;
extern unsigned int kvm_shadow_memory;
extern kvm_context_t kvm_context;
static int kvm_has_msr_star;

static int lm_capable_kernel;

int kvm_arch_qemu_create_context(void)
{
    int i;
    struct utsname utsname;

    uname(&utsname);
    lm_capable_kernel = strcmp(utsname.machine, "x86_64") == 0;

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

static void set_msr_entry(struct kvm_msr_entry *entry, uint32_t index,
                          uint64_t data)
{
    entry->index = index;
    entry->data  = data;
}

/* returns 0 on success, non-0 on failure */
static int get_msr_entry(struct kvm_msr_entry *entry, CPUState *env)
{
        switch (entry->index) {
        case MSR_IA32_SYSENTER_CS:
            env->sysenter_cs  = entry->data;
            break;
        case MSR_IA32_SYSENTER_ESP:
            env->sysenter_esp = entry->data;
            break;
        case MSR_IA32_SYSENTER_EIP:
            env->sysenter_eip = entry->data;
            break;
        case MSR_STAR:
            env->star         = entry->data;
            break;
#ifdef TARGET_X86_64
        case MSR_CSTAR:
            env->cstar        = entry->data;
            break;
        case MSR_KERNELGSBASE:
            env->kernelgsbase = entry->data;
            break;
        case MSR_FMASK:
            env->fmask        = entry->data;
            break;
        case MSR_LSTAR:
            env->lstar        = entry->data;
            break;
#endif
        case MSR_IA32_TSC:
            env->tsc          = entry->data;
            break;
        default:
            printf("Warning unknown msr index 0x%x\n", entry->index);
            return 1;
        }
        return 0;
}

#ifdef TARGET_X86_64
#define MSR_COUNT 9
#else
#define MSR_COUNT 5
#endif

static void set_v8086_seg(struct kvm_segment *lhs, const SegmentCache *rhs)
{
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->type = 3;
    lhs->present = 1;
    lhs->dpl = 3;
    lhs->db = 0;
    lhs->s = 1;
    lhs->l = 0;
    lhs->g = 0;
    lhs->avl = 0;
    lhs->unusable = 0;
}

static void set_seg(struct kvm_segment *lhs, const SegmentCache *rhs)
{
    unsigned flags = rhs->flags;
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->type = (flags >> DESC_TYPE_SHIFT) & 15;
    lhs->present = (flags & DESC_P_MASK) != 0;
    lhs->dpl = rhs->selector & 3;
    lhs->db = (flags >> DESC_B_SHIFT) & 1;
    lhs->s = (flags & DESC_S_MASK) != 0;
    lhs->l = (flags >> DESC_L_SHIFT) & 1;
    lhs->g = (flags & DESC_G_MASK) != 0;
    lhs->avl = (flags & DESC_AVL_MASK) != 0;
    lhs->unusable = 0;
}

static void get_seg(SegmentCache *lhs, const struct kvm_segment *rhs)
{
    lhs->selector = rhs->selector;
    lhs->base = rhs->base;
    lhs->limit = rhs->limit;
    lhs->flags =
	(rhs->type << DESC_TYPE_SHIFT)
	| (rhs->present * DESC_P_MASK)
	| (rhs->dpl << DESC_DPL_SHIFT)
	| (rhs->db << DESC_B_SHIFT)
	| (rhs->s * DESC_S_MASK)
	| (rhs->l << DESC_L_SHIFT)
	| (rhs->g * DESC_G_MASK)
	| (rhs->avl * DESC_AVL_MASK);
}

void kvm_arch_load_regs(CPUState *env)
{
    struct kvm_regs regs;
    struct kvm_fpu fpu;
    struct kvm_sregs sregs;
    struct kvm_msr_entry msrs[MSR_COUNT];
    int rc, n, i;

    regs.rax = env->regs[R_EAX];
    regs.rbx = env->regs[R_EBX];
    regs.rcx = env->regs[R_ECX];
    regs.rdx = env->regs[R_EDX];
    regs.rsi = env->regs[R_ESI];
    regs.rdi = env->regs[R_EDI];
    regs.rsp = env->regs[R_ESP];
    regs.rbp = env->regs[R_EBP];
#ifdef TARGET_X86_64
    regs.r8 = env->regs[8];
    regs.r9 = env->regs[9];
    regs.r10 = env->regs[10];
    regs.r11 = env->regs[11];
    regs.r12 = env->regs[12];
    regs.r13 = env->regs[13];
    regs.r14 = env->regs[14];
    regs.r15 = env->regs[15];
#endif

    regs.rflags = env->eflags;
    regs.rip = env->eip;

    kvm_set_regs(kvm_context, env->cpu_index, &regs);

    memset(&fpu, 0, sizeof fpu);
    fpu.fsw = env->fpus & ~(7 << 11);
    fpu.fsw |= (env->fpstt & 7) << 11;
    fpu.fcw = env->fpuc;
    for (i = 0; i < 8; ++i)
	fpu.ftwx |= (!env->fptags[i]) << i;
    memcpy(fpu.fpr, env->fpregs, sizeof env->fpregs);
    memcpy(fpu.xmm, env->xmm_regs, sizeof env->xmm_regs);
    fpu.mxcsr = env->mxcsr;
    kvm_set_fpu(kvm_context, env->cpu_index, &fpu);

    memcpy(sregs.interrupt_bitmap, env->kvm_interrupt_bitmap, sizeof(sregs.interrupt_bitmap));

    if ((env->eflags & VM_MASK)) {
	    set_v8086_seg(&sregs.cs, &env->segs[R_CS]);
	    set_v8086_seg(&sregs.ds, &env->segs[R_DS]);
	    set_v8086_seg(&sregs.es, &env->segs[R_ES]);
	    set_v8086_seg(&sregs.fs, &env->segs[R_FS]);
	    set_v8086_seg(&sregs.gs, &env->segs[R_GS]);
	    set_v8086_seg(&sregs.ss, &env->segs[R_SS]);
    } else {
	    set_seg(&sregs.cs, &env->segs[R_CS]);
	    set_seg(&sregs.ds, &env->segs[R_DS]);
	    set_seg(&sregs.es, &env->segs[R_ES]);
	    set_seg(&sregs.fs, &env->segs[R_FS]);
	    set_seg(&sregs.gs, &env->segs[R_GS]);
	    set_seg(&sregs.ss, &env->segs[R_SS]);

	    if (env->cr[0] & CR0_PE_MASK) {
		/* force ss cpl to cs cpl */
		sregs.ss.selector = (sregs.ss.selector & ~3) |
			(sregs.cs.selector & 3);
		sregs.ss.dpl = sregs.ss.selector & 3;
	    }
    }

    set_seg(&sregs.tr, &env->tr);
    set_seg(&sregs.ldt, &env->ldt);

    sregs.idt.limit = env->idt.limit;
    sregs.idt.base = env->idt.base;
    sregs.gdt.limit = env->gdt.limit;
    sregs.gdt.base = env->gdt.base;

    sregs.cr0 = env->cr[0];
    sregs.cr2 = env->cr[2];
    sregs.cr3 = env->cr[3];
    sregs.cr4 = env->cr[4];

    sregs.cr8 = cpu_get_apic_tpr(env);
    sregs.apic_base = cpu_get_apic_base(env);

    sregs.efer = env->efer;

    kvm_set_sregs(kvm_context, env->cpu_index, &sregs);

    /* msrs */
    n = 0;
    set_msr_entry(&msrs[n++], MSR_IA32_SYSENTER_CS,  env->sysenter_cs);
    set_msr_entry(&msrs[n++], MSR_IA32_SYSENTER_ESP, env->sysenter_esp);
    set_msr_entry(&msrs[n++], MSR_IA32_SYSENTER_EIP, env->sysenter_eip);
    if (kvm_has_msr_star)
	set_msr_entry(&msrs[n++], MSR_STAR,              env->star);
    set_msr_entry(&msrs[n++], MSR_IA32_TSC, env->tsc);
#ifdef TARGET_X86_64
    if (lm_capable_kernel) {
        set_msr_entry(&msrs[n++], MSR_CSTAR,             env->cstar);
        set_msr_entry(&msrs[n++], MSR_KERNELGSBASE,      env->kernelgsbase);
        set_msr_entry(&msrs[n++], MSR_FMASK,             env->fmask);
        set_msr_entry(&msrs[n++], MSR_LSTAR  ,           env->lstar);
    }
#endif

    rc = kvm_set_msrs(kvm_context, env->cpu_index, msrs, n);
    if (rc == -1)
        perror("kvm_set_msrs FAILED");
}

void kvm_save_mpstate(CPUState *env)
{
#ifdef KVM_CAP_MP_STATE
    int r;
    struct kvm_mp_state mp_state;

    r = kvm_get_mpstate(kvm_context, env->cpu_index, &mp_state);
    if (r < 0)
        env->mp_state = -1;
    else
        env->mp_state = mp_state.mp_state;
#endif
}

void kvm_load_mpstate(CPUState *env)
{
#ifdef KVM_CAP_MP_STATE
    struct kvm_mp_state mp_state = { .mp_state = env->mp_state };

    /*
     * -1 indicates that the host did not support GET_MP_STATE ioctl,
     *  so don't touch it.
     */
    if (env->mp_state != -1)
        kvm_set_mpstate(kvm_context, env->cpu_index, &mp_state);
#endif
}

void kvm_arch_save_regs(CPUState *env)
{
    struct kvm_regs regs;
    struct kvm_fpu fpu;
    struct kvm_sregs sregs;
    struct kvm_msr_entry msrs[MSR_COUNT];
    uint32_t hflags;
    uint32_t i, n, rc;

    kvm_get_regs(kvm_context, env->cpu_index, &regs);

    env->regs[R_EAX] = regs.rax;
    env->regs[R_EBX] = regs.rbx;
    env->regs[R_ECX] = regs.rcx;
    env->regs[R_EDX] = regs.rdx;
    env->regs[R_ESI] = regs.rsi;
    env->regs[R_EDI] = regs.rdi;
    env->regs[R_ESP] = regs.rsp;
    env->regs[R_EBP] = regs.rbp;
#ifdef TARGET_X86_64
    env->regs[8] = regs.r8;
    env->regs[9] = regs.r9;
    env->regs[10] = regs.r10;
    env->regs[11] = regs.r11;
    env->regs[12] = regs.r12;
    env->regs[13] = regs.r13;
    env->regs[14] = regs.r14;
    env->regs[15] = regs.r15;
#endif

    env->eflags = regs.rflags;
    env->eip = regs.rip;

    kvm_get_fpu(kvm_context, env->cpu_index, &fpu);
    env->fpstt = (fpu.fsw >> 11) & 7;
    env->fpus = fpu.fsw;
    env->fpuc = fpu.fcw;
    for (i = 0; i < 8; ++i)
	env->fptags[i] = !((fpu.ftwx >> i) & 1);
    memcpy(env->fpregs, fpu.fpr, sizeof env->fpregs);
    memcpy(env->xmm_regs, fpu.xmm, sizeof env->xmm_regs);
    env->mxcsr = fpu.mxcsr;

    kvm_get_sregs(kvm_context, env->cpu_index, &sregs);

    memcpy(env->kvm_interrupt_bitmap, sregs.interrupt_bitmap, sizeof(env->kvm_interrupt_bitmap));

    get_seg(&env->segs[R_CS], &sregs.cs);
    get_seg(&env->segs[R_DS], &sregs.ds);
    get_seg(&env->segs[R_ES], &sregs.es);
    get_seg(&env->segs[R_FS], &sregs.fs);
    get_seg(&env->segs[R_GS], &sregs.gs);
    get_seg(&env->segs[R_SS], &sregs.ss);

    get_seg(&env->tr, &sregs.tr);
    get_seg(&env->ldt, &sregs.ldt);

    env->idt.limit = sregs.idt.limit;
    env->idt.base = sregs.idt.base;
    env->gdt.limit = sregs.gdt.limit;
    env->gdt.base = sregs.gdt.base;

    env->cr[0] = sregs.cr0;
    env->cr[2] = sregs.cr2;
    env->cr[3] = sregs.cr3;
    env->cr[4] = sregs.cr4;

    cpu_set_apic_base(env, sregs.apic_base);

    env->efer = sregs.efer;
    //cpu_set_apic_tpr(env, sregs.cr8);

#define HFLAG_COPY_MASK ~( \
			HF_CPL_MASK | HF_PE_MASK | HF_MP_MASK | HF_EM_MASK | \
			HF_TS_MASK | HF_TF_MASK | HF_VM_MASK | HF_IOPL_MASK | \
			HF_OSFXSR_MASK | HF_LMA_MASK | HF_CS32_MASK | \
			HF_SS32_MASK | HF_CS64_MASK | HF_ADDSEG_MASK)



    hflags = (env->segs[R_CS].flags >> DESC_DPL_SHIFT) & HF_CPL_MASK;
    hflags |= (env->cr[0] & CR0_PE_MASK) << (HF_PE_SHIFT - CR0_PE_SHIFT);
    hflags |= (env->cr[0] << (HF_MP_SHIFT - CR0_MP_SHIFT)) &
	    (HF_MP_MASK | HF_EM_MASK | HF_TS_MASK);
    hflags |= (env->eflags & (HF_TF_MASK | HF_VM_MASK | HF_IOPL_MASK));
    hflags |= (env->cr[4] & CR4_OSFXSR_MASK) <<
	    (HF_OSFXSR_SHIFT - CR4_OSFXSR_SHIFT);

    if (env->efer & MSR_EFER_LMA) {
        hflags |= HF_LMA_MASK;
    }

    if ((hflags & HF_LMA_MASK) && (env->segs[R_CS].flags & DESC_L_MASK)) {
        hflags |= HF_CS32_MASK | HF_SS32_MASK | HF_CS64_MASK;
    } else {
        hflags |= (env->segs[R_CS].flags & DESC_B_MASK) >>
		(DESC_B_SHIFT - HF_CS32_SHIFT);
        hflags |= (env->segs[R_SS].flags & DESC_B_MASK) >>
		(DESC_B_SHIFT - HF_SS32_SHIFT);
        if (!(env->cr[0] & CR0_PE_MASK) ||
                   (env->eflags & VM_MASK) ||
                   !(hflags & HF_CS32_MASK)) {
                hflags |= HF_ADDSEG_MASK;
            } else {
                hflags |= ((env->segs[R_DS].base |
                                env->segs[R_ES].base |
                                env->segs[R_SS].base) != 0) <<
                    HF_ADDSEG_SHIFT;
            }
    }
    env->hflags = (env->hflags & HFLAG_COPY_MASK) | hflags;
    env->cc_src = env->eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    env->df = 1 - (2 * ((env->eflags >> 10) & 1));
    env->cc_op = CC_OP_EFLAGS;
    env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);

    /* msrs */
    n = 0;
    msrs[n++].index = MSR_IA32_SYSENTER_CS;
    msrs[n++].index = MSR_IA32_SYSENTER_ESP;
    msrs[n++].index = MSR_IA32_SYSENTER_EIP;
    if (kvm_has_msr_star)
	msrs[n++].index = MSR_STAR;
    msrs[n++].index = MSR_IA32_TSC;
#ifdef TARGET_X86_64
    if (lm_capable_kernel) {
        msrs[n++].index = MSR_CSTAR;
        msrs[n++].index = MSR_KERNELGSBASE;
        msrs[n++].index = MSR_FMASK;
        msrs[n++].index = MSR_LSTAR;
    }
#endif
    rc = kvm_get_msrs(kvm_context, env->cpu_index, msrs, n);
    if (rc == -1) {
        perror("kvm_get_msrs FAILED");
    }
    else {
        n = rc; /* actual number of MSRs */
        for (i=0 ; i<n; i++) {
            if (get_msr_entry(&msrs[i], env))
                return;
        }
    }
}

static void host_cpuid(uint32_t function, uint32_t *eax, uint32_t *ebx,
		       uint32_t *ecx, uint32_t *edx)
{
    uint32_t vec[4];

#ifdef __x86_64__
    asm volatile("cpuid"
		 : "=a"(vec[0]), "=b"(vec[1]),
		   "=c"(vec[2]), "=d"(vec[3])
		 : "0"(function) : "cc");
#else
    asm volatile("pusha \n\t"
		 "cpuid \n\t"
		 "mov %%eax, 0(%1) \n\t"
		 "mov %%ebx, 4(%1) \n\t"
		 "mov %%ecx, 8(%1) \n\t"
		 "mov %%edx, 12(%1) \n\t"
		 "popa"
		 : : "a"(function), "S"(vec)
		 : "memory", "cc");
#endif

    if (eax)
	*eax = vec[0];
    if (ebx)
	*ebx = vec[1];
    if (ecx)
	*ecx = vec[2];
    if (edx)
	*edx = vec[3];
}


static void do_cpuid_ent(struct kvm_cpuid_entry *e, uint32_t function,
			 CPUState *env)
{
    env->regs[R_EAX] = function;
    qemu_kvm_cpuid_on_env(env);
    e->function = function;
    e->eax = env->regs[R_EAX];
    e->ebx = env->regs[R_EBX];
    e->ecx = env->regs[R_ECX];
    e->edx = env->regs[R_EDX];
    if (function == 0x80000001) {
	uint32_t h_eax, h_edx;

	host_cpuid(function, &h_eax, NULL, NULL, &h_edx);

	// long mode
	if ((h_edx & 0x20000000) == 0 || !lm_capable_kernel)
	    e->edx &= ~0x20000000u;
	// syscall
	if ((h_edx & 0x00000800) == 0)
	    e->edx &= ~0x00000800u;
	// nx
	if ((h_edx & 0x00100000) == 0)
	    e->edx &= ~0x00100000u;
	// svm
	if (e->ecx & 4)
	    e->ecx &= ~4u;
    }
    // sysenter isn't supported on compatibility mode on AMD.  and syscall
    // isn't supported in compatibility mode on Intel.  so advertise the
    // actuall cpu, and say goodbye to migration between different vendors
    // is you use compatibility mode.
    if (function == 0) {
	uint32_t bcd[3];

	host_cpuid(0, NULL, &bcd[0], &bcd[1], &bcd[2]);
	e->ebx = bcd[0];
	e->ecx = bcd[1];
	e->edx = bcd[2];
    }
    // "Hypervisor present" bit for Microsoft guests
    if (function == 1)
	e->ecx |= (1u << 31);

    // 3dnow isn't properly emulated yet
    if (function == 0x80000001)
	e->edx &= ~0xc0000000;
}

struct kvm_para_features {
	int cap;
	int feature;
} para_features[] = {
#ifdef KVM_CAP_CLOCKSOURCE
	{ KVM_CAP_CLOCKSOURCE, KVM_FEATURE_CLOCKSOURCE },
#endif
#ifdef KVM_CAP_NOP_IO_DELAY
	{ KVM_CAP_NOP_IO_DELAY, KVM_FEATURE_NOP_IO_DELAY },
#endif
#ifdef KVM_CAP_PV_MMU
	{ KVM_CAP_PV_MMU, KVM_FEATURE_MMU_OP },
#endif
#ifdef KVM_CAP_CR3_CACHE
	{ KVM_CAP_CR3_CACHE, KVM_FEATURE_CR3_CACHE },
#endif
	{ -1, -1 }
};

static int get_para_features(kvm_context_t kvm_context)
{
	int i, features = 0;

	for (i = 0; i < ARRAY_SIZE(para_features)-1; i++) {
		if (kvm_check_extension(kvm_context, para_features[i].cap))
			features |= (1 << para_features[i].feature);
	}

	return features;
}

int kvm_arch_qemu_init_env(CPUState *cenv)
{
    struct kvm_cpuid_entry cpuid_ent[100];
#ifdef KVM_CPUID_SIGNATURE
    struct kvm_cpuid_entry *pv_ent;
    uint32_t signature[3];
#endif
    int cpuid_nent = 0;
    CPUState copy;
    uint32_t i, limit;

    copy = *cenv;

#ifdef KVM_CPUID_SIGNATURE
    /* Paravirtualization CPUIDs */
    memcpy(signature, "KVMKVMKVM", 12);
    pv_ent = &cpuid_ent[cpuid_nent++];
    memset(pv_ent, 0, sizeof(*pv_ent));
    pv_ent->function = KVM_CPUID_SIGNATURE;
    pv_ent->eax = 0;
    pv_ent->ebx = signature[0];
    pv_ent->ecx = signature[1];
    pv_ent->edx = signature[2];

    pv_ent = &cpuid_ent[cpuid_nent++];
    memset(pv_ent, 0, sizeof(*pv_ent));
    pv_ent->function = KVM_CPUID_FEATURES;
    pv_ent->eax = get_para_features(kvm_context);
#endif

    copy.regs[R_EAX] = 0;
    qemu_kvm_cpuid_on_env(&copy);
    limit = copy.regs[R_EAX];

    for (i = 0; i <= limit; ++i)
	do_cpuid_ent(&cpuid_ent[cpuid_nent++], i, &copy);

    copy.regs[R_EAX] = 0x80000000;
    qemu_kvm_cpuid_on_env(&copy);
    limit = copy.regs[R_EAX];

    for (i = 0x80000000; i <= limit; ++i)
	do_cpuid_ent(&cpuid_ent[cpuid_nent++], i, &copy);

    kvm_setup_cpuid(kvm_context, cenv->cpu_index, cpuid_nent, cpuid_ent);
    return 0;
}

int kvm_arch_halt(void *opaque, int vcpu)
{
    CPUState *env = cpu_single_env;

    if (!((env->interrupt_request & CPU_INTERRUPT_HARD) &&
	  (env->eflags & IF_MASK))) {
	    env->hflags |= HF_HALTED_MASK;
	    env->exception_index = EXCP_HLT;
    }
    return 1;
}

void kvm_arch_pre_kvm_run(void *opaque, int vcpu)
{
    CPUState *env = cpu_single_env;

    if (!kvm_irqchip_in_kernel(kvm_context))
	kvm_set_cr8(kvm_context, vcpu, cpu_get_apic_tpr(env));
}

void kvm_arch_post_kvm_run(void *opaque, int vcpu)
{
    CPUState *env = qemu_kvm_cpu_env(vcpu);
    cpu_single_env = env;

    env->eflags = kvm_get_interrupt_flag(kvm_context, vcpu)
	? env->eflags | IF_MASK : env->eflags & ~IF_MASK;
    env->ready_for_interrupt_injection
	= kvm_is_ready_for_interrupt_injection(kvm_context, vcpu);

    cpu_set_apic_tpr(env, kvm_get_cr8(kvm_context, vcpu));
    cpu_set_apic_base(env, kvm_get_apic_base(kvm_context, vcpu));
}

int kvm_arch_has_work(CPUState *env)
{
    if ((env->interrupt_request & (CPU_INTERRUPT_HARD | CPU_INTERRUPT_EXIT)) &&
	(env->eflags & IF_MASK))
	return 1;
    return 0;
}

int kvm_arch_try_push_interrupts(void *opaque)
{
    CPUState *env = cpu_single_env;
    int r, irq;

    if (env->ready_for_interrupt_injection &&
        (env->interrupt_request & CPU_INTERRUPT_HARD) &&
        (env->eflags & IF_MASK)) {
            env->interrupt_request &= ~CPU_INTERRUPT_HARD;
	    irq = cpu_get_pic_interrupt(env);
	    if (irq >= 0) {
		r = kvm_inject_irq(kvm_context, env->cpu_index, irq);
		if (r < 0)
		    printf("cpu %d fail inject %x\n", env->cpu_index, irq);
	    }
    }

    return (env->interrupt_request & CPU_INTERRUPT_HARD) != 0;
}

void kvm_arch_update_regs_for_sipi(CPUState *env)
{
    SegmentCache cs = env->segs[R_CS];

    kvm_arch_save_regs(env);
    env->segs[R_CS] = cs;
    env->eip = 0;
    kvm_arch_load_regs(env);
}

int handle_tpr_access(void *opaque, int vcpu,
			     uint64_t rip, int is_write)
{
    kvm_tpr_access_report(cpu_single_env, rip, is_write);
    return 0;
}
