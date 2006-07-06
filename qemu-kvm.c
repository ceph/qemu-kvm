
#include "config.h"
#include "config-host.h"

#ifdef USE_KVM

#include "exec.h"

#include "qemu-kvm.h"
#include <hvmctl.h>

hvm_context_t hvm_context;

int kvm_is_ok(CPUState *env)
{
    return (env->segs[R_CS].flags & DESC_L_MASK) != 0;
}

int kvm_cpu_exec(CPUState *env)
{
    struct hvm_regs regs;
    struct hvm_sregs sregs;

    printf("exec into rip %lx\n", env->eip);

    regs.rax = env->regs[R_EAX];
    regs.rbx = env->regs[R_EBX];
    regs.rcx = env->regs[R_ECX];
    regs.rdx = env->regs[R_EDX];
    regs.rsi = env->regs[R_ESI];
    regs.rdi = env->regs[R_EDI];
    regs.rsp = env->regs[R_ESP];
    regs.rbp = env->regs[R_EBP];
    regs.rflags = env->eflags;
    regs.rip = env->eip;

    hvm_set_regs(hvm_context, 0, &regs);

#define set_seg(var, seg) \
    sregs.var.selector = env->segs[seg].selector; \
    sregs.var.base = env->sregs[seg].base; \
    sregs.var.limit = env->sregs[seg].limit; \
    sregs.var.type = (env->sregs[seg].flags >> DESC_TYPE_SHIFT) & 15; \
    sregs.var.present = (env->sregs[seg].flags & DESC_P_MASK) != 0; \
    sregs.var.dpl = (env->sregs[seg].flags >> DESC_DPL_SHIFT) & 3; \
    sregs.var.db = (env->sregs[seg].flags >> DESC_B_SHIFT) & 1; \
    sregs.var.s = (env->sregs[seg].flags & DESC_S_MASK) != 0; \
    sregs.var.l = (env->sregs[seg].flags >> DESC_L_SHIFT) & 1; \
    sregs.var.g = (env->sregs[seg].flags >> DESC_G_SHIFT) & 1; \
    sregs.var.avl = (env->sregs[seg].flags & DESC_AVL_MASK) != 0; \
    sregs.var.unusable = sregs.var.selector == 0; 
    
    hvm_set_sregs(hvm_context, 0, &sregs);

    hvm_run(hvm_context, 0);

    hvm_get_regs(hvm_context, 0, &regs);
    printf("exec returned rip %lx\n", regs.rip);

    return 0;
}


#endif
