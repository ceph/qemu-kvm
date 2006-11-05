
#include "config.h"
#include "config-host.h"

#ifdef USE_KVM

#include "exec.h"

#include "qemu-kvm.h"
#include <kvmctl.h>
#include <string.h>

int kvm_allowed = 1;
kvm_context_t kvm_context;

#define NR_CPU 16
static CPUState *saved_env[NR_CPU];

static void load_regs(CPUState *env)
{
    struct kvm_regs regs;
    struct kvm_sregs sregs;

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

#define set_seg(var, seg, default_s, default_type)	\
  do {				    \
      unsigned flags = env->seg.flags; \
      unsigned valid = flags & ~DESC_P_MASK; \
    sregs.var.selector = env->seg.selector; \
    sregs.var.base = env->seg.base; \
    sregs.var.limit = env->seg.limit; \
    sregs.var.type = valid ? (flags >> DESC_TYPE_SHIFT) & 15 : default_type; \
    sregs.var.present = valid ? (flags & DESC_P_MASK) != 0 : 1; \
    sregs.var.dpl = env->seg.selector & 3; \
    sregs.var.db = valid ? (flags >> DESC_B_SHIFT) & 1 : 0; \
    sregs.var.s = valid ? (flags & DESC_S_MASK) != 0 : default_s;   \
    sregs.var.l = valid ? (flags >> DESC_L_SHIFT) & 1 : 0;    \
    sregs.var.g = valid ? (flags & DESC_G_MASK) != 0 : 0;      \
    sregs.var.avl = (flags & DESC_AVL_MASK) != 0; \
    sregs.var.unusable = 0; \
  } while (0)


#define set_v8086_seg(var, seg) \
  do { \
    sregs.var.selector = env->seg.selector; \
    sregs.var.base = env->seg.base; \
    sregs.var.limit = env->seg.limit; \
    sregs.var.type = 3; \
    sregs.var.present = 1; \
    sregs.var.dpl = 3; \
    sregs.var.db = 0; \
    sregs.var.s = 1; \
    sregs.var.l = 0; \
    sregs.var.g = 0; \
    sregs.var.avl = 0; \
    sregs.var.unusable = 0; \
  } while (0)


    if ((env->eflags & VM_MASK)) {
	    set_v8086_seg(cs, segs[R_CS]);
	    set_v8086_seg(ds, segs[R_DS]);
	    set_v8086_seg(es, segs[R_ES]);
	    set_v8086_seg(fs, segs[R_FS]);
	    set_v8086_seg(gs, segs[R_GS]);
	    set_v8086_seg(ss, segs[R_SS]);
    } else {
	    set_seg(cs, segs[R_CS], 1, 11);
	    set_seg(ds, segs[R_DS], 1, 3);
	    set_seg(es, segs[R_ES], 1, 3);
	    set_seg(fs, segs[R_FS], 1, 3);
	    set_seg(gs, segs[R_GS], 1, 3);
	    set_seg(ss, segs[R_SS], 1, 3);

	    if (env->cr[0] & CR0_PE_MASK) {
		/* force ss cpl to cs cpl */
		sregs.ss.selector = (sregs.ss.selector & ~3) | 
			(sregs.cs.selector & 3);
		sregs.ss.dpl = sregs.ss.selector & 3;
	    }
    }

    set_seg(tr, tr, 0, 3);
    set_seg(ldt, ldt, 0, 2);

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
}

static void save_regs(CPUState *env)
{
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    uint32_t hflags;

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

#define get_seg(var, seg) \
    env->seg.selector = sregs.var.selector; \
    env->seg.base = sregs.var.base; \
    env->seg.limit = sregs.var.limit ; \
    env->seg.flags = \
	(sregs.var.type << DESC_TYPE_SHIFT) \
	| (sregs.var.present * DESC_P_MASK) \
	| (sregs.var.dpl << DESC_DPL_SHIFT) \
	| (sregs.var.db << DESC_B_SHIFT) \
	| (sregs.var.s * DESC_S_MASK) \
	| (sregs.var.l << DESC_L_SHIFT) \
	| (sregs.var.g * DESC_G_MASK) \
	| (sregs.var.avl * DESC_AVL_MASK)
    
    get_seg(cs, segs[R_CS]);
    get_seg(ds, segs[R_DS]);
    get_seg(es, segs[R_ES]);
    get_seg(fs, segs[R_FS]);
    get_seg(gs, segs[R_GS]);
    get_seg(ss, segs[R_SS]);

    get_seg(tr, tr);
    get_seg(ldt, ldt);
    
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

    env->kvm_pending_int = sregs.pending_int;
}


#include <signal.h>

static inline void push_interrupts(CPUState *env)
{
    if (!(env->interrupt_request & CPU_INTERRUPT_HARD) ||
	!(env->eflags & IF_MASK) || env->kvm_pending_int) {
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
    } while ( (env->interrupt_request & CPU_INTERRUPT_HARD) && (env->cr[2] & CR0_PG_MASK) );
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

    if (!((env->kvm_pending_int || 
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

void kvm_qemu_init()
{
    kvm_context = kvm_init(&qemu_kvm_ops, saved_env);
    kvm_create(kvm_context, phys_ram_size, (void**)&phys_ram_base);
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
