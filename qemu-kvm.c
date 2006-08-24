
#include "config.h"
#include "config-host.h"

#ifdef USE_KVM

#include "exec.h"

#include "qemu-kvm.h"
#include <hvmctl.h>
#include <string.h>

hvm_context_t hvm_context;

#define NR_CPU 16
static CPUState *saved_env[NR_CPU];

int kvm_is_ok(CPUState *env)
{
    return (env->efer & MSR_EFER_LMA) && !env->kvm_emulate_one_instruction;
}

void kvm_handled_mmio(CPUState *env)
{
    env->kvm_emulate_one_instruction = 0;
}

static void load_regs(CPUState *env)
{
    struct hvm_regs regs;
    struct hvm_sregs sregs;

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
    regs.r8 = env->regs[8];
    regs.r9 = env->regs[9];
    regs.r10 = env->regs[10];
    regs.r11 = env->regs[11];
    regs.r12 = env->regs[12];
    regs.r13 = env->regs[13];
    regs.r14 = env->regs[14];
    regs.r15 = env->regs[15];
    
    regs.rflags = env->eflags;
    regs.rip = env->eip;

    hvm_set_regs(hvm_context, 0, &regs);

#define set_seg(var, seg) \
    sregs.var.selector = env->seg.selector; \
    sregs.var.base = env->seg.base; \
    sregs.var.limit = env->seg.limit; \
    sregs.var.type = (env->seg.flags >> DESC_TYPE_SHIFT) & 15; \
    sregs.var.present = (env->seg.flags & DESC_P_MASK) != 0; \
    sregs.var.dpl = (env->seg.flags >> DESC_DPL_SHIFT) & 3; \
    sregs.var.db = (env->seg.flags >> DESC_B_SHIFT) & 1; \
    sregs.var.s = (env->seg.flags & DESC_S_MASK) != 0; \
    sregs.var.l = (env->seg.flags >> DESC_L_SHIFT) & 1; \
    sregs.var.g = (env->seg.flags & DESC_G_MASK) != 0; \
    sregs.var.avl = (env->seg.flags & DESC_AVL_MASK) != 0; \
    sregs.var.unusable = env->seg.selector == 0
    
    set_seg(cs, segs[R_CS]);
    set_seg(ds, segs[R_DS]);
    set_seg(es, segs[R_ES]);
    set_seg(fs, segs[R_FS]);
    set_seg(gs, segs[R_GS]);
    set_seg(ss, segs[R_SS]);

    set_seg(tr, tr);
    sregs.tr.unusable = 0;
    set_seg(ldt, ldt);
    
    sregs.idt.limit = env->idt.limit;
    sregs.idt.base = env->idt.base;
    sregs.gdt.limit = env->gdt.limit;
    sregs.gdt.base = env->gdt.base;

    sregs.cr0 = env->cr[0];
    sregs.cr2 = env->cr[2];
    sregs.cr3 = env->cr[3];
    sregs.cr4 = env->cr[4];
    sregs.cr8 = cpu_get_apic_tpr(env);

    sregs.efer = env->efer;

    hvm_set_sregs(hvm_context, 0, &sregs);
}

static void save_regs(CPUState *env)
{
    struct hvm_regs regs;
    struct hvm_sregs sregs;
    uint32_t hflags;

    hvm_get_regs(hvm_context, 0, &regs);

    env->regs[R_EAX] = regs.rax;
    env->regs[R_EBX] = regs.rbx;
    env->regs[R_ECX] = regs.rcx;
    env->regs[R_EDX] = regs.rdx;
    env->regs[R_ESI] = regs.rsi;
    env->regs[R_EDI] = regs.rdi;
    env->regs[R_ESP] = regs.rsp;
    env->regs[R_EBP] = regs.rbp;
    env->regs[8] = regs.r8;
    env->regs[9] = regs.r9;
    env->regs[10] = regs.r10;
    env->regs[11] = regs.r11;
    env->regs[12] = regs.r12;
    env->regs[13] = regs.r13;
    env->regs[14] = regs.r14;
    env->regs[15] = regs.r15;

    env->eflags = regs.rflags;
    env->eip = regs.rip;

    hvm_get_sregs(hvm_context, 0, &sregs);

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
}


#include <signal.h>

static inline void push_interrupts(CPUState *env)
{
    if (!(env->interrupt_request & CPU_INTERRUPT_HARD)) {
    	if ((env->interrupt_request & CPU_INTERRUPT_EXIT)) {
	    env->interrupt_request &= ~CPU_INTERRUPT_EXIT;
	    env->exception_index = EXCP_INTERRUPT;
	    cpu_loop_exit();
        }
        return;
    }

    do {
        int intno;

        env->interrupt_request &= ~CPU_INTERRUPT_HARD;
        intno = cpu_get_pic_interrupt(env);
        hvm_inject_irq(hvm_context, 0, intno); // for now using cpu 0
    } while ((env->interrupt_request & CPU_INTERRUPT_HARD));
}

int kvm_cpu_exec(CPUState *env)
{

    push_interrupts(env);

    load_regs(env);

    hvm_run(hvm_context, 0);

    save_regs(env);

    printf("exec returned rip %lx\n", env->eip);

    exit(0);

    return 0;
}


static void kvm_cpuid(void *opaque, uint64_t *rax, uint64_t *rbx, 
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
}

static void kvm_debug(void *opaque, int vcpu)
{
    CPUState **envs = opaque;

    env = envs[0];
    save_regs(env);
    env->exception_index = EXCP_DEBUG;
    cpu_loop_exit();
}

static void kvm_inb(void *opaque, uint16_t addr, uint8_t *data)
{
    *data = cpu_inb(0, addr);
}

static void kvm_inw(void *opaque, uint16_t addr, uint16_t *data)
{
    *data = cpu_inw(0, addr);
}

static void kvm_inl(void *opaque, uint16_t addr, uint32_t *data)
{
    *data = cpu_inl(0, addr);
}

static void kvm_outb(void *opaque, uint16_t addr, uint8_t data)
{
    cpu_outb(0, addr, data);
}

static void kvm_outw(void *opaque, uint16_t addr, uint16_t data)
{
    cpu_outw(0, addr, data);
}

static void kvm_outl(void *opaque, uint16_t addr, uint32_t data)
{
    cpu_outl(0, addr, data);
}

static void kvm_readb(void *opaque, uint64_t addr, uint8_t *data)
{
    *data = ldub_phys(addr);
}
 
static void kvm_readw(void *opaque, uint64_t addr, uint16_t *data)
{
    *data = lduw_phys(addr);
}

static void kvm_readl(void *opaque, uint64_t addr, uint32_t *data)
{
    *data = ldl_phys(addr);
}

static void kvm_readq(void *opaque, uint64_t addr, uint64_t *data)
{
    *data = ldq_phys(addr);
}

static void kvm_writeb(void *opaque, uint64_t addr, uint8_t data)
{
    stb_phys(addr, data);
}

static void kvm_writew(void *opaque, uint64_t addr, uint16_t data)
{
    stw_phys(addr, data);
}

static void kvm_writel(void *opaque, uint64_t addr, uint32_t data)
{
    stl_phys(addr, data);
}

static void kvm_writeq(void *opaque, uint64_t addr, uint64_t data)
{
    stq_phys(addr, data);
}

static void kvm_io_window(void *opaque)
{
    CPUState **envs = opaque;

    env = envs[0];
    save_regs(env);
    cpu_loop_exit();
}

static void kvm_emulate_one_instruction(void *opaque)
{
    CPUState **envs = opaque;

    env = envs[0];
    save_regs(env);
    env->kvm_emulate_one_instruction = 1;
    cpu_loop_exit();
}
 
static void kvm_halt(void *opaque, int vcpu)
{
    CPUState **envs = opaque;

    env = envs[0];
    save_regs(env);
    ++env->eip;
    cpu_loop_exit();
}
 
static struct hvm_callbacks qemu_kvm_ops = {
    .cpuid = kvm_cpuid,
    .debug = kvm_debug,
    .inb   = kvm_inb,
    .inw   = kvm_inw,
    .inl   = kvm_inl,
    .outb  = kvm_outb,
    .outw  = kvm_outw,
    .outl  = kvm_outl,
    .emulate_one_instruction = kvm_emulate_one_instruction,
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

void kvm_init()
{
    hvm_context = hvm_init(&qemu_kvm_ops, saved_env);
    hvm_create(hvm_context, phys_ram_size, (void**)&phys_ram_base);
}

int kvm_update_debugger(CPUState *env)
{
    struct hvm_debug_guest dbg;
    int i;

    memset(&dbg, 0, sizeof dbg);
    if (env->nb_breakpoints || env->singlestep_enabled) {
	dbg.enabled = 1;
	for (i = 0; i < 4 && i < env->nb_breakpoints; ++i) {
	    dbg.breakpoints[i].enabled = 1;
	    dbg.breakpoints[i].address = env->breakpoints[i];
	}
	dbg.singlestep = env->singlestep_enabled;
    }
    return hvm_guest_debug(hvm_context, 0, &dbg);
}


#endif
