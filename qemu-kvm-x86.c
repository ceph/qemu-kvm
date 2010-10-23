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
#include "gdbstub.h"
#include <sys/io.h>

#include "qemu-kvm.h"
#include "libkvm.h"
#include <pthread.h>
#include <sys/utsname.h>
#include <linux/kvm_para.h>
#include <sys/ioctl.h>

#include "kvm.h"
#include "hw/apic.h"

#define MSR_IA32_TSC            0x10

static struct kvm_msr_list *kvm_msr_list;
extern unsigned int kvm_shadow_memory;
static int kvm_has_msr_star;
static int kvm_has_vm_hsave_pa;

static int _lm_capable_kernel;

int kvm_set_tss_addr(kvm_context_t kvm, unsigned long addr)
{
    int r;
    /*
     * Tell fw_cfg to notify the BIOS to reserve the range.
     */
    if (e820_add_entry(addr, 0x4000, E820_RESERVED) < 0) {
        perror("e820_add_entry() table is full");
        exit(1);
    }

    r = kvm_vm_ioctl(kvm_state, KVM_SET_TSS_ADDR, addr);
    if (r < 0) {
        fprintf(stderr, "kvm_set_tss_addr: %m\n");
        return r;
    }
    return 0;
}

static int kvm_init_tss(kvm_context_t kvm)
{
    int r;

    r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_SET_TSS_ADDR);
    if (r > 0) {
        /*
         * this address is 3 pages before the bios, and the bios should present
         * as unavaible memory
         */
        r = kvm_set_tss_addr(kvm, 0xfeffd000);
        if (r < 0) {
            fprintf(stderr, "kvm_init_tss: unable to set tss addr\n");
            return r;
        }
    } else {
        fprintf(stderr, "kvm does not support KVM_CAP_SET_TSS_ADDR\n");
    }
    return 0;
}

static int kvm_set_identity_map_addr(kvm_context_t kvm, uint64_t addr)
{
#ifdef KVM_CAP_SET_IDENTITY_MAP_ADDR
    int r;

    r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_SET_IDENTITY_MAP_ADDR);
    if (r > 0) {
        r = kvm_vm_ioctl(kvm_state, KVM_SET_IDENTITY_MAP_ADDR, &addr);
        if (r == -1) {
            fprintf(stderr, "kvm_set_identity_map_addr: %m\n");
            return -errno;
        }
        return 0;
    }
#endif
    return -ENOSYS;
}

static int kvm_init_identity_map_page(kvm_context_t kvm)
{
#ifdef KVM_CAP_SET_IDENTITY_MAP_ADDR
    int r;

    r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_SET_IDENTITY_MAP_ADDR);
    if (r > 0) {
        /*
         * this address is 4 pages before the bios, and the bios should present
         * as unavaible memory
         */
        r = kvm_set_identity_map_addr(kvm, 0xfeffc000);
        if (r < 0) {
            fprintf(stderr, "kvm_init_identity_map_page: "
                    "unable to set identity mapping addr\n");
            return r;
        }
    }
#endif
    return 0;
}

static int kvm_create_pit(kvm_context_t kvm)
{
#ifdef KVM_CAP_PIT
    int r;

    kvm_state->pit_in_kernel = 0;
    if (!kvm->no_pit_creation) {
        r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_PIT);
        if (r > 0) {
            r = kvm_vm_ioctl(kvm_state, KVM_CREATE_PIT);
            if (r >= 0) {
                kvm_state->pit_in_kernel = 1;
            } else {
                fprintf(stderr, "Create kernel PIC irqchip failed\n");
                return r;
            }
        }
    }
#endif
    return 0;
}

int kvm_arch_create(kvm_context_t kvm, unsigned long phys_mem_bytes,
                        void **vm_mem)
{
    int r = 0;

    r = kvm_init_tss(kvm);
    if (r < 0) {
        return r;
    }

    r = kvm_init_identity_map_page(kvm);
    if (r < 0) {
        return r;
    }

    r = kvm_create_pit(kvm);
    if (r < 0) {
        return r;
    }

    r = kvm_init_coalesced_mmio(kvm);
    if (r < 0) {
        return r;
    }

    return 0;
}

#ifdef KVM_EXIT_TPR_ACCESS

static int kvm_handle_tpr_access(CPUState *env)
{
    struct kvm_run *run = env->kvm_run;
    kvm_tpr_access_report(env,
                          run->tpr_access.rip,
                          run->tpr_access.is_write);
    return 0;
}


int kvm_enable_vapic(CPUState *env, uint64_t vapic)
{
    struct kvm_vapic_addr va = {
        .vapic_addr = vapic,
    };

    return kvm_vcpu_ioctl(env, KVM_SET_VAPIC_ADDR, &va);
}

#endif

int kvm_arch_run(CPUState *env)
{
    int r = 0;
    struct kvm_run *run = env->kvm_run;

    switch (run->exit_reason) {
#ifdef KVM_EXIT_SET_TPR
    case KVM_EXIT_SET_TPR:
        break;
#endif
#ifdef KVM_EXIT_TPR_ACCESS
    case KVM_EXIT_TPR_ACCESS:
        r = kvm_handle_tpr_access(env);
        break;
#endif
    default:
        r = 1;
        break;
    }

    return r;
}

#ifdef KVM_CAP_IRQCHIP

int kvm_get_lapic(CPUState *env, struct kvm_lapic_state *s)
{
    int r = 0;

    if (!kvm_irqchip_in_kernel()) {
        return r;
    }

    r = kvm_vcpu_ioctl(env, KVM_GET_LAPIC, s);
    if (r < 0) {
        fprintf(stderr, "KVM_GET_LAPIC failed\n");
    }
    return r;
}

int kvm_set_lapic(CPUState *env, struct kvm_lapic_state *s)
{
    int r = 0;

    if (!kvm_irqchip_in_kernel()) {
        return 0;
    }

    r = kvm_vcpu_ioctl(env, KVM_SET_LAPIC, s);

    if (r < 0) {
        fprintf(stderr, "KVM_SET_LAPIC failed\n");
    }
    return r;
}

#endif

#ifdef KVM_CAP_PIT

int kvm_get_pit(kvm_context_t kvm, struct kvm_pit_state *s)
{
    if (!kvm_pit_in_kernel()) {
        return 0;
    }
    return kvm_vm_ioctl(kvm_state, KVM_GET_PIT, s);
}

int kvm_set_pit(kvm_context_t kvm, struct kvm_pit_state *s)
{
    if (!kvm_pit_in_kernel()) {
        return 0;
    }
    return kvm_vm_ioctl(kvm_state, KVM_SET_PIT, s);
}

#ifdef KVM_CAP_PIT_STATE2
int kvm_get_pit2(kvm_context_t kvm, struct kvm_pit_state2 *ps2)
{
    if (!kvm_pit_in_kernel()) {
        return 0;
    }
    return kvm_vm_ioctl(kvm_state, KVM_GET_PIT2, ps2);
}

int kvm_set_pit2(kvm_context_t kvm, struct kvm_pit_state2 *ps2)
{
    if (!kvm_pit_in_kernel()) {
        return 0;
    }
    return kvm_vm_ioctl(kvm_state, KVM_SET_PIT2, ps2);
}

#endif
#endif

int kvm_has_pit_state2(kvm_context_t kvm)
{
    int r = 0;

#ifdef KVM_CAP_PIT_STATE2
    r = kvm_check_extension(kvm_state, KVM_CAP_PIT_STATE2);
#endif
    return r;
}

void kvm_show_code(CPUState *env)
{
#define SHOW_CODE_LEN 50
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    int r, n;
    int back_offset;
    unsigned char code;
    char code_str[SHOW_CODE_LEN * 3 + 1];
    unsigned long rip;

    r = kvm_vcpu_ioctl(env, KVM_GET_SREGS, &sregs);
    if (r < 0 ) {
        perror("KVM_GET_SREGS");
        return;
    }
    r = kvm_vcpu_ioctl(env, KVM_GET_REGS, &regs);
    if (r < 0) {
        perror("KVM_GET_REGS");
        return;
    }
    rip = sregs.cs.base + regs.rip;
    back_offset = regs.rip;
    if (back_offset > 20) {
        back_offset = 20;
    }
    *code_str = 0;
    for (n = -back_offset; n < SHOW_CODE_LEN-back_offset; ++n) {
        if (n == 0) {
            strcat(code_str, " -->");
        }
        cpu_physical_memory_rw(rip + n, &code, 1, 1);
        sprintf(code_str + strlen(code_str), " %02x", code);
    }
    fprintf(stderr, "code:%s\n", code_str);
}


/*
 * Returns available msr list.  User must free.
 */
static struct kvm_msr_list *kvm_get_msr_list(void)
{
    struct kvm_msr_list sizer, *msrs;
    int r;

    sizer.nmsrs = 0;
    r = kvm_ioctl(kvm_state, KVM_GET_MSR_INDEX_LIST, &sizer);
    if (r < 0 && r != -E2BIG) {
        return NULL;
    }
    /* Old kernel modules had a bug and could write beyond the provided
       memory. Allocate at least a safe amount of 1K. */
    msrs = qemu_malloc(MAX(1024, sizeof(*msrs) +
                           sizer.nmsrs * sizeof(*msrs->indices)));

    msrs->nmsrs = sizer.nmsrs;
    r = kvm_ioctl(kvm_state, KVM_GET_MSR_INDEX_LIST, msrs);
    if (r < 0) {
        free(msrs);
        errno = r;
        return NULL;
    }
    return msrs;
}

int kvm_get_msrs(CPUState *env, struct kvm_msr_entry *msrs, int n)
{
    struct kvm_msrs *kmsrs = qemu_malloc(sizeof *kmsrs + n * sizeof *msrs);
    int r;

    kmsrs->nmsrs = n;
    memcpy(kmsrs->entries, msrs, n * sizeof *msrs);
    r = kvm_vcpu_ioctl(env, KVM_GET_MSRS, kmsrs);
    memcpy(msrs, kmsrs->entries, n * sizeof *msrs);
    free(kmsrs);
    return r;
}

int kvm_set_msrs(CPUState *env, struct kvm_msr_entry *msrs, int n)
{
    struct kvm_msrs *kmsrs = qemu_malloc(sizeof *kmsrs + n * sizeof *msrs);
    int r;

    kmsrs->nmsrs = n;
    memcpy(kmsrs->entries, msrs, n * sizeof *msrs);
    r = kvm_vcpu_ioctl(env, KVM_SET_MSRS, kmsrs);
    free(kmsrs);
    return r;
}

static void print_seg(FILE *file, const char *name, struct kvm_segment *seg)
{
    fprintf(stderr,
            "%s %04x (%08llx/%08x p %d dpl %d db %d s %d type %x l %d"
            " g %d avl %d)\n",
            name, seg->selector, seg->base, seg->limit, seg->present,
            seg->dpl, seg->db, seg->s, seg->type, seg->l, seg->g,
            seg->avl);
}

static void print_dt(FILE *file, const char *name, struct kvm_dtable *dt)
{
    fprintf(stderr, "%s %llx/%x\n", name, dt->base, dt->limit);
}

void kvm_show_regs(CPUState *env)
{
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    int r;

    r = kvm_vcpu_ioctl(env, KVM_GET_REGS, &regs);
    if (r < 0) {
        perror("KVM_GET_REGS");
        return;
    }
    fprintf(stderr,
            "rax %016llx rbx %016llx rcx %016llx rdx %016llx\n"
            "rsi %016llx rdi %016llx rsp %016llx rbp %016llx\n"
            "r8  %016llx r9  %016llx r10 %016llx r11 %016llx\n"
            "r12 %016llx r13 %016llx r14 %016llx r15 %016llx\n"
            "rip %016llx rflags %08llx\n",
            regs.rax, regs.rbx, regs.rcx, regs.rdx,
            regs.rsi, regs.rdi, regs.rsp, regs.rbp,
            regs.r8,  regs.r9,  regs.r10, regs.r11,
            regs.r12, regs.r13, regs.r14, regs.r15,
            regs.rip, regs.rflags);
    r = kvm_vcpu_ioctl(env, KVM_GET_SREGS, &sregs);
    if (r < 0) {
        perror("KVM_GET_SREGS");
        return;
    }
    print_seg(stderr, "cs", &sregs.cs);
    print_seg(stderr, "ds", &sregs.ds);
    print_seg(stderr, "es", &sregs.es);
    print_seg(stderr, "ss", &sregs.ss);
    print_seg(stderr, "fs", &sregs.fs);
    print_seg(stderr, "gs", &sregs.gs);
    print_seg(stderr, "tr", &sregs.tr);
    print_seg(stderr, "ldt", &sregs.ldt);
    print_dt(stderr, "gdt", &sregs.gdt);
    print_dt(stderr, "idt", &sregs.idt);
    fprintf(stderr, "cr0 %llx cr2 %llx cr3 %llx cr4 %llx cr8 %llx"
            " efer %llx\n",
            sregs.cr0, sregs.cr2, sregs.cr3, sregs.cr4, sregs.cr8,
            sregs.efer);
}

static void kvm_set_cr8(CPUState *env, uint64_t cr8)
{
    env->kvm_run->cr8 = cr8;
}

int kvm_setup_cpuid(CPUState *env, int nent,
                    struct kvm_cpuid_entry *entries)
{
    struct kvm_cpuid *cpuid;
    int r;

    cpuid = qemu_malloc(sizeof(*cpuid) + nent * sizeof(*entries));

    cpuid->nent = nent;
    memcpy(cpuid->entries, entries, nent * sizeof(*entries));
    r = kvm_vcpu_ioctl(env, KVM_SET_CPUID, cpuid);

    free(cpuid);
    return r;
}

int kvm_setup_cpuid2(CPUState *env, int nent,
                     struct kvm_cpuid_entry2 *entries)
{
    struct kvm_cpuid2 *cpuid;
    int r;

    cpuid = qemu_malloc(sizeof(*cpuid) + nent * sizeof(*entries));

    cpuid->nent = nent;
    memcpy(cpuid->entries, entries, nent * sizeof(*entries));
    r = kvm_vcpu_ioctl(env, KVM_SET_CPUID2, cpuid);
    free(cpuid);
    return r;
}

int kvm_set_shadow_pages(kvm_context_t kvm, unsigned int nrshadow_pages)
{
#ifdef KVM_CAP_MMU_SHADOW_CACHE_CONTROL
    int r;

    r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION,
                  KVM_CAP_MMU_SHADOW_CACHE_CONTROL);
    if (r > 0) {
        r = kvm_vm_ioctl(kvm_state, KVM_SET_NR_MMU_PAGES, nrshadow_pages);
        if (r < 0) {
            fprintf(stderr, "kvm_set_shadow_pages: %m\n");
            return r;
        }
        return 0;
    }
#endif
    return -1;
}

int kvm_get_shadow_pages(kvm_context_t kvm, unsigned int *nrshadow_pages)
{
#ifdef KVM_CAP_MMU_SHADOW_CACHE_CONTROL
    int r;

    r = kvm_ioctl(kvm_state, KVM_CHECK_EXTENSION,
                  KVM_CAP_MMU_SHADOW_CACHE_CONTROL);
    if (r > 0) {
        *nrshadow_pages = kvm_vm_ioctl(kvm_state, KVM_GET_NR_MMU_PAGES);
        return 0;
    }
#endif
    return -1;
}

#ifdef KVM_CAP_VAPIC
static int kvm_enable_tpr_access_reporting(CPUState *env)
{
    int r;
    struct kvm_tpr_access_ctl tac = { .enabled = 1 };

    r = kvm_ioctl(env->kvm_state, KVM_CHECK_EXTENSION, KVM_CAP_VAPIC);
    if (r <= 0) {
        return -ENOSYS;
    }
    return kvm_vcpu_ioctl(env, KVM_TPR_ACCESS_REPORTING, &tac);
}
#endif

#ifdef KVM_CAP_ADJUST_CLOCK
static struct kvm_clock_data kvmclock_data;

static void kvmclock_pre_save(void *opaque)
{
    struct kvm_clock_data *cl = opaque;

    kvm_vm_ioctl(kvm_state, KVM_GET_CLOCK, cl);
}

static int kvmclock_post_load(void *opaque, int version_id)
{
    struct kvm_clock_data *cl = opaque;

    return kvm_vm_ioctl(kvm_state, KVM_SET_CLOCK, cl);
}

static const VMStateDescription vmstate_kvmclock= {
    .name = "kvmclock",
    .version_id = 1,
    .minimum_version_id = 1,
    .minimum_version_id_old = 1,
    .pre_save = kvmclock_pre_save,
    .post_load = kvmclock_post_load,
    .fields      = (VMStateField []) {
        VMSTATE_U64(clock, struct kvm_clock_data),
        VMSTATE_END_OF_LIST()
    }
};
#endif

int kvm_arch_qemu_create_context(void)
{
    int i, r;
    struct utsname utsname;

    uname(&utsname);
    _lm_capable_kernel = strcmp(utsname.machine, "x86_64") == 0;

    if (kvm_shadow_memory) {
        kvm_set_shadow_pages(kvm_context, kvm_shadow_memory);
    }

    kvm_msr_list = kvm_get_msr_list();
    if (!kvm_msr_list) {
        return -1;
    }
    for (i = 0; i < kvm_msr_list->nmsrs; ++i) {
        if (kvm_msr_list->indices[i] == MSR_STAR) {
            kvm_has_msr_star = 1;
        }
        if (kvm_msr_list->indices[i] == MSR_VM_HSAVE_PA) {
            kvm_has_vm_hsave_pa = 1;
        }
    }

#ifdef KVM_CAP_ADJUST_CLOCK
    if (kvm_check_extension(kvm_state, KVM_CAP_ADJUST_CLOCK)) {
        vmstate_register(NULL, 0, &vmstate_kvmclock, &kvmclock_data);
    }
#endif

    r = kvm_set_boot_cpu_id(0);
    if (r < 0 && r != -ENOSYS) {
        return r;
    }

    return 0;
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
    case MSR_VM_HSAVE_PA:
        env->vm_hsave     = entry->data;
        break;
    case MSR_KVM_SYSTEM_TIME:
        env->system_time_msr = entry->data;
        break;
    case MSR_KVM_WALL_CLOCK:
        env->wall_clock_msr = entry->data;
        break;
#ifdef KVM_CAP_MCE
    case MSR_MCG_STATUS:
        env->mcg_status = entry->data;
        break;
    case MSR_MCG_CTL:
        env->mcg_ctl = entry->data;
        break;
#endif
    default:
#ifdef KVM_CAP_MCE
        if (entry->index >= MSR_MC0_CTL &&
            entry->index < MSR_MC0_CTL + (env->mcg_cap & 0xff) * 4) {
            env->mce_banks[entry->index - MSR_MC0_CTL] = entry->data;
            break;
        }
#endif
        printf("Warning unknown msr index 0x%x\n", entry->index);
        return 1;
    }
    return 0;
}

static void kvm_arch_save_mpstate(CPUState *env)
{
#ifdef KVM_CAP_MP_STATE
    int r;
    struct kvm_mp_state mp_state;

    r = kvm_get_mpstate(env, &mp_state);
    if (r < 0) {
        env->mp_state = -1;
    } else {
        env->mp_state = mp_state.mp_state;
        if (kvm_irqchip_in_kernel()) {
            env->halted = (env->mp_state == KVM_MP_STATE_HALTED);
        }
    }
#else
    env->mp_state = -1;
#endif
}

static void kvm_arch_load_mpstate(CPUState *env)
{
#ifdef KVM_CAP_MP_STATE
    struct kvm_mp_state mp_state;

    /*
     * -1 indicates that the host did not support GET_MP_STATE ioctl,
     *  so don't touch it.
     */
    if (env->mp_state != -1) {
        mp_state.mp_state = env->mp_state;
        kvm_set_mpstate(env, &mp_state);
    }
#endif
}

static void kvm_reset_mpstate(CPUState *env)
{
#ifdef KVM_CAP_MP_STATE
    if (kvm_check_extension(kvm_state, KVM_CAP_MP_STATE)) {
        if (kvm_irqchip_in_kernel()) {
            env->mp_state = cpu_is_bsp(env) ? KVM_MP_STATE_RUNNABLE :
                                              KVM_MP_STATE_UNINITIALIZED;
        } else {
            env->mp_state = KVM_MP_STATE_RUNNABLE;
        }
    }
#endif
}

#define XSAVE_CWD_RIP     2
#define XSAVE_CWD_RDP     4
#define XSAVE_MXCSR       6
#define XSAVE_ST_SPACE    8
#define XSAVE_XMM_SPACE   40
#define XSAVE_XSTATE_BV   128
#define XSAVE_YMMH_SPACE  144

void kvm_arch_load_regs(CPUState *env, int level)
{
    struct kvm_msr_entry msrs[100];
    int rc, n, i;

    assert(kvm_cpu_is_stopped(env) || env->thread_id == kvm_get_thread_id());

    kvm_getput_regs(env, 1);

    kvm_put_xsave(env);
    kvm_put_xcrs(env);

    kvm_put_sregs(env);
    /* msrs */
    n = 0;
    /* Remember to increase msrs size if you add new registers below */
    kvm_msr_entry_set(&msrs[n++], MSR_IA32_SYSENTER_CS,  env->sysenter_cs);
    kvm_msr_entry_set(&msrs[n++], MSR_IA32_SYSENTER_ESP, env->sysenter_esp);
    kvm_msr_entry_set(&msrs[n++], MSR_IA32_SYSENTER_EIP, env->sysenter_eip);
    if (kvm_has_msr_star) {
        kvm_msr_entry_set(&msrs[n++], MSR_STAR,              env->star);
    }
    if (kvm_has_vm_hsave_pa) {
        kvm_msr_entry_set(&msrs[n++], MSR_VM_HSAVE_PA, env->vm_hsave);
    }
#ifdef TARGET_X86_64
    if (_lm_capable_kernel) {
        kvm_msr_entry_set(&msrs[n++], MSR_CSTAR,             env->cstar);
        kvm_msr_entry_set(&msrs[n++], MSR_KERNELGSBASE,      env->kernelgsbase);
        kvm_msr_entry_set(&msrs[n++], MSR_FMASK,             env->fmask);
        kvm_msr_entry_set(&msrs[n++], MSR_LSTAR  ,           env->lstar);
    }
#endif
    if (level == KVM_PUT_FULL_STATE) {
        /*
         * KVM is yet unable to synchronize TSC values of multiple VCPUs on
         * writeback. Until this is fixed, we only write the offset to SMP
         * guests after migration, desynchronizing the VCPUs, but avoiding
         * huge jump-backs that would occur without any writeback at all.
         */
        if (smp_cpus == 1 || env->tsc != 0) {
            kvm_msr_entry_set(&msrs[n++], MSR_IA32_TSC, env->tsc);
        }
        kvm_msr_entry_set(&msrs[n++], MSR_KVM_SYSTEM_TIME, env->system_time_msr);
        kvm_msr_entry_set(&msrs[n++], MSR_KVM_WALL_CLOCK, env->wall_clock_msr);
    }
#ifdef KVM_CAP_MCE
    if (env->mcg_cap) {
        if (level == KVM_PUT_RESET_STATE) {
            kvm_msr_entry_set(&msrs[n++], MSR_MCG_STATUS, env->mcg_status);
        } else if (level == KVM_PUT_FULL_STATE) {
            kvm_msr_entry_set(&msrs[n++], MSR_MCG_STATUS, env->mcg_status);
            kvm_msr_entry_set(&msrs[n++], MSR_MCG_CTL, env->mcg_ctl);
            for (i = 0; i < (env->mcg_cap & 0xff) * 4; i++) {
                kvm_msr_entry_set(&msrs[n++], MSR_MC0_CTL + i, env->mce_banks[i]);
            }
        }
    }
#endif

    rc = kvm_set_msrs(env, msrs, n);
    if (rc == -1) {
        perror("kvm_set_msrs FAILED");
    }

    if (level >= KVM_PUT_RESET_STATE) {
        kvm_arch_load_mpstate(env);
        kvm_load_lapic(env);
    }
    if (level == KVM_PUT_FULL_STATE) {
        if (env->kvm_vcpu_update_vapic) {
            kvm_tpr_enable_vapic(env);
        }
    }

    kvm_put_vcpu_events(env, level);
    kvm_put_debugregs(env);

    /* must be last */
    kvm_guest_debug_workarounds(env);
}

void kvm_arch_save_regs(CPUState *env)
{
    struct kvm_msr_entry msrs[100];
    uint32_t i, n, rc;

    assert(kvm_cpu_is_stopped(env) || env->thread_id == kvm_get_thread_id());

    kvm_getput_regs(env, 0);

    kvm_get_xsave(env);
    kvm_get_xcrs(env);

    kvm_get_sregs(env);

    /* msrs */
    n = 0;
    /* Remember to increase msrs size if you add new registers below */
    msrs[n++].index = MSR_IA32_SYSENTER_CS;
    msrs[n++].index = MSR_IA32_SYSENTER_ESP;
    msrs[n++].index = MSR_IA32_SYSENTER_EIP;
    if (kvm_has_msr_star) {
        msrs[n++].index = MSR_STAR;
    }
    msrs[n++].index = MSR_IA32_TSC;
    if (kvm_has_vm_hsave_pa)
        msrs[n++].index = MSR_VM_HSAVE_PA;
#ifdef TARGET_X86_64
    if (_lm_capable_kernel) {
        msrs[n++].index = MSR_CSTAR;
        msrs[n++].index = MSR_KERNELGSBASE;
        msrs[n++].index = MSR_FMASK;
        msrs[n++].index = MSR_LSTAR;
    }
#endif
    msrs[n++].index = MSR_KVM_SYSTEM_TIME;
    msrs[n++].index = MSR_KVM_WALL_CLOCK;

#ifdef KVM_CAP_MCE
    if (env->mcg_cap) {
        msrs[n++].index = MSR_MCG_STATUS;
        msrs[n++].index = MSR_MCG_CTL;
        for (i = 0; i < (env->mcg_cap & 0xff) * 4; i++)
            msrs[n++].index = MSR_MC0_CTL + i;
    }
#endif

    rc = kvm_get_msrs(env, msrs, n);
    if (rc == -1) {
        perror("kvm_get_msrs FAILED");
    } else {
        n = rc; /* actual number of MSRs */
        for (i=0 ; i<n; i++) {
            if (get_msr_entry(&msrs[i], env)) {
                return;
            }
        }
    }
    kvm_arch_save_mpstate(env);
    kvm_save_lapic(env);
    kvm_get_vcpu_events(env);
    kvm_get_debugregs(env);
}

static int _kvm_arch_init_vcpu(CPUState *env)
{
    kvm_arch_reset_vcpu(env);

#ifdef KVM_EXIT_TPR_ACCESS
    kvm_enable_tpr_access_reporting(env);
#endif
    kvm_reset_mpstate(env);
    return 0;
}

int kvm_arch_halt(CPUState *env)
{

    if (!((env->interrupt_request & CPU_INTERRUPT_HARD) &&
          (env->eflags & IF_MASK)) &&
        !(env->interrupt_request & CPU_INTERRUPT_NMI)) {
        env->halted = 1;
    }
    return 1;
}

int kvm_arch_pre_run(CPUState *env, struct kvm_run *run)
{
    if (!kvm_irqchip_in_kernel()) {
        kvm_set_cr8(env, cpu_get_apic_tpr(env->apic_state));
    }
    return 0;
}

int kvm_arch_has_work(CPUState *env)
{
    if (((env->interrupt_request & CPU_INTERRUPT_HARD) &&
         (env->eflags & IF_MASK)) ||
        (env->interrupt_request & CPU_INTERRUPT_NMI)) {
        return 1;
    }
    return 0;
}

int kvm_arch_try_push_interrupts(void *opaque)
{
    CPUState *env = cpu_single_env;
    int r, irq;

    if (kvm_is_ready_for_interrupt_injection(env) &&
        (env->interrupt_request & CPU_INTERRUPT_HARD) &&
        (env->eflags & IF_MASK)) {
        env->interrupt_request &= ~CPU_INTERRUPT_HARD;
        irq = cpu_get_pic_interrupt(env);
        if (irq >= 0) {
            r = kvm_inject_irq(env, irq);
            if (r < 0) {
                printf("cpu %d fail inject %x\n", env->cpu_index, irq);
            }
        }
    }

    return (env->interrupt_request & CPU_INTERRUPT_HARD) != 0;
}

#ifdef KVM_CAP_USER_NMI
void kvm_arch_push_nmi(void *opaque)
{
    CPUState *env = cpu_single_env;
    int r;

    if (likely(!(env->interrupt_request & CPU_INTERRUPT_NMI))) {
        return;
    }

    env->interrupt_request &= ~CPU_INTERRUPT_NMI;
    r = kvm_inject_nmi(env);
    if (r < 0) {
        printf("cpu %d fail inject NMI\n", env->cpu_index);
    }
}
#endif /* KVM_CAP_USER_NMI */

static int kvm_reset_msrs(CPUState *env)
{
    struct {
        struct kvm_msrs info;
        struct kvm_msr_entry entries[100];
    } msr_data;
    int n;
    struct kvm_msr_entry *msrs = msr_data.entries;
    uint32_t index;
    uint64_t data;

    if (!kvm_msr_list) {
        return -1;
    }

    for (n = 0; n < kvm_msr_list->nmsrs; n++) {
        index = kvm_msr_list->indices[n];
        switch (index) {
        case MSR_PAT:
            data = 0x0007040600070406ULL;
            break;
        default:
            data = 0;
        }
        kvm_msr_entry_set(&msrs[n], kvm_msr_list->indices[n], data);
    }

    msr_data.info.nmsrs = n;

    return kvm_vcpu_ioctl(env, KVM_SET_MSRS, &msr_data);
}


void kvm_arch_cpu_reset(CPUState *env)
{
    kvm_reset_msrs(env);
    kvm_arch_reset_vcpu(env);
    kvm_reset_mpstate(env);
}

#ifdef CONFIG_KVM_DEVICE_ASSIGNMENT
void kvm_arch_do_ioperm(void *_data)
{
    struct ioperm_data *data = _data;
    ioperm(data->start_port, data->num, data->turn_on);
}
#endif

/*
 * Setup x86 specific IRQ routing
 */
int kvm_arch_init_irq_routing(void)
{
    int i, r;

    if (kvm_irqchip && kvm_has_gsi_routing()) {
        kvm_clear_gsi_routes();
        for (i = 0; i < 8; ++i) {
            if (i == 2) {
                continue;
            }
            r = kvm_add_irq_route(i, KVM_IRQCHIP_PIC_MASTER, i);
            if (r < 0) {
                return r;
            }
        }
        for (i = 8; i < 16; ++i) {
            r = kvm_add_irq_route(i, KVM_IRQCHIP_PIC_SLAVE, i - 8);
            if (r < 0) {
                return r;
            }
        }
        for (i = 0; i < 24; ++i) {
            if (i == 0 && irq0override) {
                r = kvm_add_irq_route(i, KVM_IRQCHIP_IOAPIC, 2);
            } else if (i != 2 || !irq0override) {
                r = kvm_add_irq_route(i, KVM_IRQCHIP_IOAPIC, i);
            }
            if (r < 0) {
                return r;
            }
        }
        kvm_commit_irq_routes();
    }
    return 0;
}

void kvm_arch_process_irqchip_events(CPUState *env)
{
    if (env->interrupt_request & CPU_INTERRUPT_INIT) {
        kvm_cpu_synchronize_state(env);
        do_cpu_init(env);
    }
    if (env->interrupt_request & CPU_INTERRUPT_SIPI) {
        kvm_cpu_synchronize_state(env);
        do_cpu_sipi(env);
    }
}
