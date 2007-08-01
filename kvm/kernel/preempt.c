
#ifndef CONFIG_PREEMPT_NOTIFIERS

#include <linux/sched.h>
#include <linux/percpu.h>

static DEFINE_SPINLOCK(pn_lock);
static LIST_HEAD(pn_list);
static DEFINE_PER_CPU(int, notifier_enabled);
static DEFINE_PER_CPU(struct task_struct *, last_tsk);

#define dprintk(fmt) do {						\
		if (0)							\
			printk("%s (%d/%d): " fmt, __FUNCTION__,	\
			       current->pid, raw_smp_processor_id());	\
	} while (0)

static void preempt_enable_notifiers(void)
{
	int cpu = raw_smp_processor_id();

	if (per_cpu(notifier_enabled, cpu))
		return;

	dprintk("\n");
	per_cpu(notifier_enabled, cpu) = 1;
	asm volatile ("mov %0, %%db0" : : "r"(schedule));
	asm volatile ("mov %0, %%db7" : : "r"(0x702ul));
}

void special_reload_dr7(void)
{
	asm volatile ("mov %0, %%db7" : : "r"(0x702ul));
}
EXPORT_SYMBOL_GPL(special_reload_dr7);

static void preempt_disable_notifiers(void)
{
	int cpu = raw_smp_processor_id();

	if (!per_cpu(notifier_enabled, cpu))
		return;

	dprintk("\n");
	per_cpu(notifier_enabled, cpu) = 0;
	asm volatile ("mov %0, %%db7" : : "r"(0x400ul));
}

static void  __attribute__((used)) preempt_notifier_trigger(void)
{
	struct preempt_notifier *pn;
	int cpu = raw_smp_processor_id();
	int found = 0;
	unsigned long flags;

	dprintk(" - in\n");
	//dump_stack();
	spin_lock_irqsave(&pn_lock, flags);
	list_for_each_entry(pn, &pn_list, link)
		if (pn->tsk == current) {
			found = 1;
			break;
		}
	spin_unlock_irqrestore(&pn_lock, flags);
	preempt_disable_notifiers();
	if (found) {
		dprintk("sched_out\n");
		pn->ops->sched_out(pn, NULL);
		per_cpu(last_tsk, cpu) = NULL;
	}
	dprintk(" - out\n");
}

unsigned long orig_int1_handler;

#ifdef CONFIG_X86_64

#define SAVE_REGS \
	"push %rax; push %rbx; push %rcx; push %rdx; " \
	"push %rsi; push %rdi; push %rbp; " \
	"push %r8;  push %r9;  push %r10; push %r11; " \
	"push %r12; push %r13; push %r14; push %r15"

#define RESTORE_REGS \
	"pop %r15; pop %r14; pop %r13; pop %r12; " \
	"pop %r11; pop %r10; pop %r9;  pop %r8; " \
	"pop %rbp; pop %rdi; pop %rsi; " \
	"pop %rdx; pop %rcx; pop %rbx; pop %rax "

#define TMP "%rax"

#else

#define SAVE_REGS "pusha"
#define RESTORE_REGS "popa"
#define TMP "%eax"

#endif

asm ("pn_int1_handler:  \n\t"
     "push "  TMP " \n\t"
     "mov %db6, " TMP " \n\t"
     "test $1, " TMP " \n\t"
     "pop "  TMP " \n\t"
     "jz .Lnotme \n\t"
     SAVE_REGS "\n\t"
     "call preempt_notifier_trigger \n\t"
     RESTORE_REGS "\n\t"
#ifdef CONFIG_X86_64
     "orq $0x10000, 16(%rsp) \n\t"
     "iretq \n\t"
#else
     "orl $0x10000, 8(%esp) \n\t"
     "iret \n\t"
#endif
     ".Lnotme: \n\t"
#ifdef CONFIG_X86_64
     "jmpq *orig_int1_handler\n\t"
#else
     "jmpl *orig_int1_handler\n\t"
#endif
	);

void in_special_section(void)
{
	struct preempt_notifier *pn;
	int cpu = raw_smp_processor_id();
	int found = 0;
	unsigned long flags;

	if (per_cpu(last_tsk, cpu) == current)
		return;

	dprintk(" - in\n");
	spin_lock_irqsave(&pn_lock, flags);
	list_for_each_entry(pn, &pn_list, link)
		if (pn->tsk == current) {
			found = 1;
			break;
		}
	spin_unlock_irqrestore(&pn_lock, flags);
	if (found) {
		dprintk("\n");
		per_cpu(last_tsk, cpu) = current;
		pn->ops->sched_in(pn, cpu);
		preempt_enable_notifiers();
	}
	dprintk(" - out\n");
}
EXPORT_SYMBOL_GPL(in_special_section);

void start_special_insn(void)
{
	preempt_disable();
	in_special_section();
}
EXPORT_SYMBOL_GPL(start_special_insn);

void end_special_insn(void)
{
	preempt_enable();
}
EXPORT_SYMBOL_GPL(end_special_insn);

void preempt_notifier_register(struct preempt_notifier *notifier)
{
	int cpu = get_cpu();
	unsigned long flags;

	dprintk(" - in\n");
	spin_lock_irqsave(&pn_lock, flags);
	preempt_enable_notifiers();
	notifier->tsk = current;
	list_add(&notifier->link, &pn_list);
	spin_unlock_irqrestore(&pn_lock, flags);
	per_cpu(last_tsk, cpu) = current;
	put_cpu();
	dprintk(" - out\n");
}

void preempt_notifier_unregister(struct preempt_notifier *notifier)
{
	int cpu = get_cpu();
	unsigned long flags;

	dprintk(" - in\n");
	spin_lock_irqsave(&pn_lock, flags);
	list_del(&notifier->link);
	spin_unlock_irqrestore(&pn_lock, flags);
	per_cpu(last_tsk, cpu) = NULL;
	preempt_disable_notifiers();
	put_cpu();
	dprintk(" - out\n");
}

struct intr_gate {
	u16 offset0;
	u16 segment;
	u16 junk;
	u16 offset1;
#ifdef CONFIG_X86_64
	u32 offset2;
	u32 blah;
#endif
} __attribute__((packed));

struct idt_desc {
	u16 limit;
	struct intr_gate *gates;
} __attribute__((packed));

static struct intr_gate orig_int1_gate;

void pn_int1_handler(void);

void preempt_notifier_sys_init(void)
{
	struct idt_desc idt_desc;
	struct intr_gate *int1_gate;

	dprintk("\n");
	asm ("sidt %0" : "=m"(idt_desc));
	int1_gate = &idt_desc.gates[1];
	orig_int1_gate = *int1_gate;
	orig_int1_handler = int1_gate->offset0
		| ((u32)int1_gate->offset1 << 16);
#ifdef CONFIG_X86_64
	orig_int1_handler |= (u64)int1_gate->offset2 << 32;
#endif
	int1_gate->offset0 = (unsigned long)pn_int1_handler;
	int1_gate->offset1 = (unsigned long)pn_int1_handler >> 16;
#ifdef CONFIG_X86_64
	int1_gate->offset2 = (unsigned long)pn_int1_handler >> 32;
#endif
}

static void do_disable(void *blah)
{
	preempt_disable_notifiers();
}

void preempt_notifier_sys_exit(void)
{
	struct idt_desc idt_desc;

	dprintk("\n");
	on_each_cpu(do_disable, NULL, 1, 1);
	asm ("sidt %0" : "=m"(idt_desc));
	idt_desc.gates[1] = orig_int1_gate;
}

#endif
