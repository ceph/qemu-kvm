#include "svm.h"
#include "libcflat.h"
#include "processor.h"
#include "msr.h"
#include "vm.h"
#include "smp.h"

static void setup_svm(void)
{
    void *hsave = alloc_page();

    wrmsr(MSR_VM_HSAVE_PA, virt_to_phys(hsave));
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_SVME);
}

static void vmcb_set_seg(struct vmcb_seg *seg, u16 selector,
                         u64 base, u32 limit, u32 attr)
{
    seg->selector = selector;
    seg->attrib = attr;
    seg->limit = limit;
    seg->base = base;
}

static void vmcb_ident(struct vmcb *vmcb)
{
    u64 vmcb_phys = virt_to_phys(vmcb);
    struct vmcb_save_area *save = &vmcb->save;
    struct vmcb_control_area *ctrl = &vmcb->control;
    u32 data_seg_attr = 3 | SVM_SELECTOR_S_MASK | SVM_SELECTOR_P_MASK
        | SVM_SELECTOR_DB_MASK | SVM_SELECTOR_G_MASK;
    u32 code_seg_attr = 9 | SVM_SELECTOR_S_MASK | SVM_SELECTOR_P_MASK
        | SVM_SELECTOR_L_MASK | SVM_SELECTOR_G_MASK;
    struct descriptor_table_ptr desc_table_ptr;

    memset(vmcb, 0, sizeof(*vmcb));
    asm volatile ("vmsave" : : "a"(vmcb_phys) : "memory");
    vmcb_set_seg(&save->es, read_es(), 0, -1U, data_seg_attr);
    vmcb_set_seg(&save->cs, read_cs(), 0, -1U, code_seg_attr);
    vmcb_set_seg(&save->ss, read_ss(), 0, -1U, data_seg_attr);
    vmcb_set_seg(&save->ds, read_ds(), 0, -1U, data_seg_attr);
    sgdt(&desc_table_ptr);
    vmcb_set_seg(&save->gdtr, 0, desc_table_ptr.base, desc_table_ptr.limit, 0);
    sidt(&desc_table_ptr);
    vmcb_set_seg(&save->idtr, 0, desc_table_ptr.base, desc_table_ptr.limit, 0);
    save->cpl = 0;
    save->efer = rdmsr(MSR_EFER);
    save->cr4 = read_cr4();
    save->cr3 = read_cr3();
    save->cr0 = read_cr0();
    save->dr7 = read_dr7();
    save->dr6 = read_dr6();
    save->cr2 = read_cr2();
    save->g_pat = rdmsr(MSR_IA32_CR_PAT);
    save->dbgctl = rdmsr(MSR_IA32_DEBUGCTLMSR);
    ctrl->intercept = (1ULL << INTERCEPT_VMRUN) | (1ULL << INTERCEPT_VMMCALL);
}

struct test {
    const char *name;
    bool (*supported)(void);
    void (*prepare)(struct test *test);
    void (*guest_func)(struct test *test);
    bool (*finished)(struct test *test);
    bool (*succeeded)(struct test *test);
    struct vmcb *vmcb;
    int exits;
    ulong scratch;
};

static void test_thunk(struct test *test)
{
    test->guest_func(test);
    asm volatile ("vmmcall" : : : "memory");
}

static bool test_run(struct test *test, struct vmcb *vmcb)
{
    u64 vmcb_phys = virt_to_phys(vmcb);
    u64 guest_stack[10000];
    bool success;

    test->vmcb = vmcb;
    test->prepare(test);
    vmcb->save.rip = (ulong)test_thunk;
    vmcb->save.rsp = (ulong)(guest_stack + ARRAY_SIZE(guest_stack));
    do {
        asm volatile (
            "clgi \n\t"
            "vmload \n\t"
            "push %%rbp \n\t"
            "push %1 \n\t"
            "vmrun \n\t"
            "pop %1 \n\t"
            "pop %%rbp \n\t"
            "vmsave \n\t"
            "stgi"
            : : "a"(vmcb_phys), "D"(test)
            : "rbx", "rcx", "rdx", "rsi",
              "r8", "r9", "r10", "r11" , "r12", "r13", "r14", "r15",
              "memory");
        ++test->exits;
    } while (!test->finished(test));

    success = test->succeeded(test);

    printf("%s: %s\n", test->name, success ? "PASS" : "FAIL");

    return success;
}

static bool default_supported(void)
{
    return true;
}

static void default_prepare(struct test *test)
{
    vmcb_ident(test->vmcb);
    cli();
}

static bool default_finished(struct test *test)
{
    return true; /* one vmexit */
}

static void null_test(struct test *test)
{
}

static bool null_check(struct test *test)
{
    return test->vmcb->control.exit_code == SVM_EXIT_VMMCALL;
}

static void prepare_no_vmrun_int(struct test *test)
{
    test->vmcb->control.intercept &= ~(1ULL << INTERCEPT_VMRUN);
}

static bool check_no_vmrun_int(struct test *test)
{
    return test->vmcb->control.exit_code == SVM_EXIT_ERR;
}

static void test_vmrun(struct test *test)
{
    asm volatile ("vmrun" : : "a"(virt_to_phys(test->vmcb)));
}

static bool check_vmrun(struct test *test)
{
    return test->vmcb->control.exit_code == SVM_EXIT_VMRUN;
}

static void prepare_cr3_intercept(struct test *test)
{
    default_prepare(test);
    test->vmcb->control.intercept_cr_read |= 1 << 3;
}

static void test_cr3_intercept(struct test *test)
{
    asm volatile ("mov %%cr3, %0" : "=r"(test->scratch) : : "memory");
}

static bool check_cr3_intercept(struct test *test)
{
    return test->vmcb->control.exit_code == SVM_EXIT_READ_CR3;
}

static bool check_cr3_nointercept(struct test *test)
{
    return null_check(test) && test->scratch == read_cr3();
}

static void corrupt_cr3_intercept_bypass(void *_test)
{
    struct test *test = _test;
    extern volatile u32 mmio_insn;

    while (!__sync_bool_compare_and_swap(&test->scratch, 1, 2))
        pause();
    pause();
    pause();
    pause();
    mmio_insn = 0x90d8200f;  // mov %cr3, %rax; nop
}

static void prepare_cr3_intercept_bypass(struct test *test)
{
    default_prepare(test);
    test->vmcb->control.intercept_cr_read |= 1 << 3;
    on_cpu_async(1, corrupt_cr3_intercept_bypass, test);
}

static void test_cr3_intercept_bypass(struct test *test)
{
    ulong a = 0xa0000;

    test->scratch = 1;
    while (test->scratch != 2)
        barrier();

    asm volatile ("mmio_insn: mov %0, (%0); nop"
                  : "+a"(a) : : "memory");
    test->scratch = a;
}

static struct test tests[] = {
    { "null", default_supported, default_prepare, null_test,
      default_finished, null_check },
    { "vmrun", default_supported, default_prepare, test_vmrun,
       default_finished, check_vmrun },
    { "vmrun intercept check", default_supported, prepare_no_vmrun_int,
      null_test, default_finished, check_no_vmrun_int },
    { "cr3 read intercept", default_supported, prepare_cr3_intercept,
      test_cr3_intercept, default_finished, check_cr3_intercept },
    { "cr3 read nointercept", default_supported, default_prepare,
      test_cr3_intercept, default_finished, check_cr3_nointercept },
    { "cr3 read intercept emulate", default_supported,
      prepare_cr3_intercept_bypass, test_cr3_intercept_bypass,
      default_finished, check_cr3_intercept },
};

int main(int ac, char **av)
{
    int i, nr, passed, done;
    struct vmcb *vmcb;

    setup_vm();
    smp_init();

    if (!(cpuid(0x80000001).c & 4)) {
        printf("SVM not availble\n");
        return 0;
    }

    setup_svm();

    vmcb = alloc_page();

    nr = ARRAY_SIZE(tests);
    passed = done = 0;
    for (i = 0; i < nr; ++i) {
        if (!tests[i].supported())
            continue;
        done += 1;
        passed += test_run(&tests[i], vmcb);
    }

    printf("\nSUMMARY: %d TESTS, %d FAILURES\n", done, (done - passed));
    return passed == done ? 0 : 1;
}
