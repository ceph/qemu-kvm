
#include "config.h"
#include "config-host.h"

#ifdef USE_KVM

#include "exec.h"

#include "qemu-kvm.h"
#include <kvmctl.h>
#include <string.h>

#define MSR_IA32_TSC		0x10

extern void perror(const char *s);

int kvm_allowed = 1;
kvm_context_t kvm_context;

#define NR_CPU 16
static CPUState *saved_env[NR_CPU];

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

static void load_regs(CPUState *env)
{
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    struct kvm_msr_entry msrs[MSR_COUNT];
    int rc;

    /* hack: save env */
    if (!saved_env[0])
	saved_env[0] = env;

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

    kvm_set_regs(kvm_context, 0, &regs);

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

    kvm_set_sregs(kvm_context, 0, &sregs);

    /* msrs */
    set_msr_entry(&msrs[0], MSR_IA32_SYSENTER_CS,  env->sysenter_cs);
    set_msr_entry(&msrs[1], MSR_IA32_SYSENTER_ESP, env->sysenter_esp);
    set_msr_entry(&msrs[2], MSR_IA32_SYSENTER_EIP, env->sysenter_eip);
    set_msr_entry(&msrs[3], MSR_STAR,              env->star);
    set_msr_entry(&msrs[4], MSR_IA32_TSC, env->tsc);
#ifdef TARGET_X86_64
    set_msr_entry(&msrs[5], MSR_CSTAR,             env->cstar);
    set_msr_entry(&msrs[6], MSR_KERNELGSBASE,      env->kernelgsbase);
    set_msr_entry(&msrs[7], MSR_FMASK,             env->fmask);
    set_msr_entry(&msrs[8], MSR_LSTAR  ,           env->lstar);
#endif

    rc = kvm_set_msrs(kvm_context, 0, msrs, MSR_COUNT);
    if (rc == -1)
        perror("kvm_set_msrs FAILED");
}

static void save_regs(CPUState *env)
{
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    struct kvm_msr_entry msrs[MSR_COUNT];
    uint32_t hflags;
    uint32_t i, n, rc;

    kvm_get_regs(kvm_context, 0, &regs);

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

    kvm_get_sregs(kvm_context, 0, &sregs);

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

    cpu_set_apic_tpr(env, sregs.cr8);
    cpu_set_apic_base(env, sregs.apic_base);

    env->efer = sregs.efer;

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
    CC_SRC = env->eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    DF = 1 - (2 * ((env->eflags >> 10) & 1));
    CC_OP = CC_OP_EFLAGS;
    env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);

    tlb_flush(env, 1);

    /* msrs */    
    msrs[0].index = MSR_IA32_SYSENTER_CS;
    msrs[1].index = MSR_IA32_SYSENTER_ESP;
    msrs[2].index = MSR_IA32_SYSENTER_EIP;
    msrs[3].index = MSR_STAR;
    msrs[4].index = MSR_IA32_TSC;
#ifdef TARGET_X86_64
    msrs[5].index = MSR_CSTAR;
    msrs[6].index = MSR_KERNELGSBASE;
    msrs[7].index = MSR_FMASK;
    msrs[8].index = MSR_LSTAR;
#endif
    rc = kvm_get_msrs(kvm_context, 0, msrs, MSR_COUNT);
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

#include <signal.h>

static int kvm_interrupt_pending(CPUState *env)
{
    int i;

    for (i = 0; i < NR_IRQ_WORDS; ++i)
	if (env->kvm_interrupt_bitmap[i])
	    return 1;
    return 0;
}

static inline void push_interrupts(CPUState *env)
{
    if (!(env->interrupt_request & CPU_INTERRUPT_HARD) ||
	!(env->eflags & IF_MASK) || kvm_interrupt_pending(env)) {
    	if ((env->interrupt_request & CPU_INTERRUPT_EXIT)) {
	    env->interrupt_request &= ~CPU_INTERRUPT_EXIT;
	    env->exception_index = EXCP_INTERRUPT;
	    cpu_loop_exit();
        }
        return;
    }

    do {
        env->interrupt_request &= ~CPU_INTERRUPT_HARD;

        // for now using cpu 0
	kvm_inject_irq(kvm_context, 0, cpu_get_pic_interrupt(env)); 
    } while ( (env->interrupt_request & CPU_INTERRUPT_HARD) && (env->cr[0] & CR0_PG_MASK) );
}

void kvm_load_registers(CPUState *env)
{
    load_regs(env);
}

int kvm_cpu_exec(CPUState *env)
{

    push_interrupts(env);

    if (!saved_env[0])
	saved_env[0] = env;

    kvm_run(kvm_context, 0);

    save_regs(env);

    return 0;
}


static int kvm_cpuid(void *opaque, uint64_t *rax, uint64_t *rbx, 
		      uint64_t *rcx, uint64_t *rdx)
{
    CPUState **envs = opaque;
    CPUState *saved_env;

    saved_env = env;
    env = envs[0];

    env->regs[R_EAX] = *rax;
    env->regs[R_EBX] = *rbx;
    env->regs[R_ECX] = *rcx;
    env->regs[R_EDX] = *rdx;
    helper_cpuid();
    *rdx = env->regs[R_EDX];
    *rcx = env->regs[R_ECX];
    *rbx = env->regs[R_EBX];
    *rax = env->regs[R_EAX];
    env = saved_env;
    return 0;
}

static int kvm_debug(void *opaque, int vcpu)
{
    CPUState **envs = opaque;

    env = envs[0];
    save_regs(env);
    env->exception_index = EXCP_DEBUG;
    return 1;
}

static int kvm_inb(void *opaque, uint16_t addr, uint8_t *data)
{
    *data = cpu_inb(0, addr);
    return 0;
}

static int kvm_inw(void *opaque, uint16_t addr, uint16_t *data)
{
    *data = cpu_inw(0, addr);
    return 0;
}

static int kvm_inl(void *opaque, uint16_t addr, uint32_t *data)
{
    *data = cpu_inl(0, addr);
    return 0;
}

static int kvm_outb(void *opaque, uint16_t addr, uint8_t data)
{
    cpu_outb(0, addr, data);
    return 0;
}

static int kvm_outw(void *opaque, uint16_t addr, uint16_t data)
{
    cpu_outw(0, addr, data);
    return 0;
}

static int kvm_outl(void *opaque, uint16_t addr, uint32_t data)
{
    cpu_outl(0, addr, data);
    return 0;
}

static int kvm_readb(void *opaque, uint64_t addr, uint8_t *data)
{
    *data = ldub_phys(addr);
    return 0;
}
 
static int kvm_readw(void *opaque, uint64_t addr, uint16_t *data)
{
    *data = lduw_phys(addr);
    return 0;
}

static int kvm_readl(void *opaque, uint64_t addr, uint32_t *data)
{
    *data = ldl_phys(addr);
    return 0;
}

static int kvm_readq(void *opaque, uint64_t addr, uint64_t *data)
{
    *data = ldq_phys(addr);
    return 0;
}

static int kvm_writeb(void *opaque, uint64_t addr, uint8_t data)
{
    stb_phys(addr, data);
    return 0;
}

static int kvm_writew(void *opaque, uint64_t addr, uint16_t data)
{
    stw_phys(addr, data);
    return 0;
}

static int kvm_writel(void *opaque, uint64_t addr, uint32_t data)
{
    stl_phys(addr, data);
    return 0;
}

static int kvm_writeq(void *opaque, uint64_t addr, uint64_t data)
{
    stq_phys(addr, data);
    return 0;
}

static int kvm_io_window(void *opaque)
{
    return 1;
}

 
static int kvm_halt(void *opaque, int vcpu)
{
    CPUState **envs = opaque, *env;

    env = envs[0];
    save_regs(env);

    if (!((kvm_interrupt_pending(env) || 
	   (env->interrupt_request & CPU_INTERRUPT_HARD)) && 
	  (env->eflags & IF_MASK))) {
	    env->hflags |= HF_HALTED_MASK;
	    env->exception_index = EXCP_HLT;
    }
    return 1;
}
 
static struct kvm_callbacks qemu_kvm_ops = {
    .cpuid = kvm_cpuid,
    .debug = kvm_debug,
    .inb   = kvm_inb,
    .inw   = kvm_inw,
    .inl   = kvm_inl,
    .outb  = kvm_outb,
    .outw  = kvm_outw,
    .outl  = kvm_outl,
    .readb = kvm_readb,
    .readw = kvm_readw,
    .readl = kvm_readl,
    .readq = kvm_readq,
    .writeb = kvm_writeb,
    .writew = kvm_writew,
    .writel = kvm_writel,
    .writeq = kvm_writeq,
    .halt  = kvm_halt,
    .io_window = kvm_io_window,
};

int kvm_qemu_init()
{
    /* Try to initialize kvm */
    kvm_context = kvm_init(&qemu_kvm_ops, saved_env);
    if (!kvm_context) {
      	return -1;
    }

    return 0;
}

int kvm_qemu_create_context(void)
{
    if (kvm_create(kvm_context, phys_ram_size, (void**)&phys_ram_base) < 0) {
	kvm_qemu_destroy();
	return -1;
    }

    return 0;
}

void kvm_qemu_destroy(void)
{
    kvm_finalize(kvm_context);
}

int kvm_update_debugger(CPUState *env)
{
    struct kvm_debug_guest dbg;
    int i;

    dbg.enabled = 0;
    if (env->nb_breakpoints || env->singlestep_enabled) {
	dbg.enabled = 1;
	for (i = 0; i < 4 && i < env->nb_breakpoints; ++i) {
	    dbg.breakpoints[i].enabled = 1;
	    dbg.breakpoints[i].address = env->breakpoints[i];
	}
	dbg.singlestep = env->singlestep_enabled;
    }
    return kvm_guest_debug(kvm_context, 0, &dbg);
}


#endif
