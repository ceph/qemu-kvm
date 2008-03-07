
/*
 * Compatibility header for building as an external module.
 */

/*
 * Avoid picking up the kernel's kvm.h in case we have a newer one.
 */

#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <linux/cpu.h>
#include <asm/processor.h>
#include <linux/hrtimer.h>
#include <asm/bitops.h>

/*
 * 2.6.16 does not have GFP_NOWAIT
 */

#include <linux/gfp.h>

#ifndef GFP_NOWAIT
#define GFP_NOWAIT (GFP_ATOMIC & ~__GFP_HIGH)
#endif


/*
 * kvm profiling support needs 2.6.20
 */
#include <linux/profile.h>

#ifndef KVM_PROFILING
#define KVM_PROFILING 1234
#define prof_on       4321
#endif

/*
 * smp_call_function_single() is not exported below 2.6.20
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)

#include <linux/spinlock.h>
#include <linux/smp.h>

struct scfs_thunk_info {
	int cpu;
	void (*func)(void *info);
	void *info;
};

static inline void scfs_thunk(void *_thunk)
{
	struct scfs_thunk_info *thunk = _thunk;

	if (raw_smp_processor_id() == thunk->cpu)
		thunk->func(thunk->info);
}

static inline int smp_call_function_single1(int cpu, void (*func)(void *info),
					   void *info, int nonatomic, int wait)
{
	int r, this_cpu;
	struct scfs_thunk_info thunk;

	this_cpu = get_cpu();
	if (cpu == this_cpu) {
		r = 0;
		local_irq_disable();
		func(info);
		local_irq_enable();
	} else {
		thunk.cpu = cpu;
		thunk.func = func;
		thunk.info = info;
		r = smp_call_function(scfs_thunk, &thunk, 0, 1);
	}
	put_cpu();
	return r;
}

#define smp_call_function_single smp_call_function_single1

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
/*
 * pre 2.6.23 doesn't handle smp_call_function_single on current cpu
 */

#include <linux/smp.h>

static inline int smp_call_function_single2(int cpu, void (*func)(void *info),
					    void *info, int nonatomic, int wait)
{
	int this_cpu, r;

	this_cpu = get_cpu();
	if (cpu == this_cpu) {
		r = 0;
		local_irq_disable();
		func(info);
		local_irq_enable();
	} else
		r = smp_call_function_single(cpu, func, info, nonatomic, wait);
	put_cpu();
	return r;
}

#define smp_call_function_single smp_call_function_single2

#endif

/*
 * The cpu hotplug stubs are broken if !CONFIG_CPU_HOTPLUG
 */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,15)
#define DEFINE_MUTEX(a) DECLARE_MUTEX(a)
#define mutex_lock_interruptible(a) down_interruptible(a)
#define mutex_unlock(a) up(a)
#define mutex_lock(a) down(a)
#define mutex_init(a) init_MUTEX(a)
#define mutex_trylock(a) down_trylock(a)
#define mutex semaphore
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
#ifndef kzalloc
#define kzalloc(size,flags)			\
({						\
	void *__ret = kmalloc(size, flags);	\
	if (__ret)				\
		memset(__ret, 0, size);		\
	__ret;					\
})
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#ifndef kmem_cache_zalloc
#define kmem_cache_zalloc(cache,flags)			  \
({							  \
	void *__ret = kmem_cache_alloc(cache, flags);	  \
	if (__ret)                                        \
		memset(__ret, 0, kmem_cache_size(cache)); \
	__ret;                                            \
})
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)

#ifndef CONFIG_HOTPLUG_CPU
#define register_cpu_notifier(nb) (0)
#endif

#endif

#include <linux/miscdevice.h>
#ifndef KVM_MINOR
#define KVM_MINOR 232
#endif

#include <linux/notifier.h>
#ifndef CPU_TASKS_FROZEN

#define CPU_TASKS_FROZEN       0x0010
#define CPU_ONLINE_FROZEN      (CPU_ONLINE | CPU_TASKS_FROZEN)
#define CPU_UP_PREPARE_FROZEN  (CPU_UP_PREPARE | CPU_TASKS_FROZEN)
#define CPU_UP_CANCELED_FROZEN (CPU_UP_CANCELED | CPU_TASKS_FROZEN)
#define CPU_DOWN_PREPARE_FROZEN        (CPU_DOWN_PREPARE | CPU_TASKS_FROZEN)
#define CPU_DOWN_FAILED_FROZEN (CPU_DOWN_FAILED | CPU_TASKS_FROZEN)
#define CPU_DEAD_FROZEN                (CPU_DEAD | CPU_TASKS_FROZEN)

#endif

#ifndef CPU_DYING
#define CPU_DYING 0x000A
#define CPU_DYING_FROZEN (CPU_DYING | CPU_TASKS_FROZEN)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

#ifndef _EFER_SCE
#define _EFER_SCE		0  /* SYSCALL/SYSRET */
#endif

#ifndef EFER_SCE
#define EFER_SCE		(1<<_EFER_SCE)
#endif

#endif

/*
 * For set_64bit(), which is in a new file asm/cmpxchg.h in newer kernels.
 */
#include <asm/system.h>

#define anon_inode_getfd kvm_anon_inode_getfd
int kvm_init_anon_inodes(void);
void kvm_exit_anon_inodes(void);

#include <linux/smp.h>

#define on_cpu kvm_on_cpu

/*
 * Call a function on one processor, which might be the currently executing
 * processor.
 */
static inline int on_cpu(int cpu, void (*func) (void *info), void *info,
			 int retry, int wait)
{
	int ret;
	int this_cpu;

	this_cpu = get_cpu();
	if (this_cpu == cpu) {
		local_irq_disable();
		func(info);
		local_irq_enable();
		ret = 0;
	} else
		ret = smp_call_function_single(cpu, func, info, retry, wait);
	put_cpu();
	return ret;
}

#ifndef X86_CR0_PE
#define X86_CR0_PE 0x00000001
#endif

#ifndef X86_CR0_MP
#define X86_CR0_MP 0x00000002
#endif

#ifndef X86_CR0_EM
#define X86_CR0_EM 0x00000004
#endif

#ifndef X86_CR0_TS
#define X86_CR0_TS 0x00000008
#endif

#ifndef X86_CR0_ET
#define X86_CR0_ET 0x00000010
#endif

#ifndef X86_CR0_NE
#define X86_CR0_NE 0x00000020
#endif

#ifndef X86_CR0_WP
#define X86_CR0_WP 0x00010000
#endif

#ifndef X86_CR0_AM
#define X86_CR0_AM 0x00040000
#endif

#ifndef X86_CR0_NW
#define X86_CR0_NW 0x20000000
#endif

#ifndef X86_CR0_CD
#define X86_CR0_CD 0x40000000
#endif

#ifndef X86_CR0_PG
#define X86_CR0_PG 0x80000000
#endif

#ifndef X86_CR3_PWT
#define X86_CR3_PWT 0x00000008
#endif

#ifndef X86_CR3_PCD
#define X86_CR3_PCD 0x00000010
#endif

#ifndef X86_CR4_VMXE
#define X86_CR4_VMXE 0x00002000
#endif

#undef X86_CR8_TPR
#define X86_CR8_TPR 0x0f

/*
 * 2.6.23 removed the cache destructor
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#  define kmem_cache_create(name, size, align, flags, ctor) \
	kmem_cache_create(name, size, align, flags, ctor, NULL)
#endif

/*
 * 2.6.22 does not define set_64bit() under nonpae
 */
#ifdef CONFIG_X86_32

#include <asm/cmpxchg.h>

static inline void __kvm_set_64bit(u64 *ptr, u64 val)
{
	unsigned int low = val;
	unsigned int high = val >> 32;

	__asm__ __volatile__ (
		"\n1:\t"
		"movl (%0), %%eax\n\t"
		"movl 4(%0), %%edx\n\t"
		"lock cmpxchg8b (%0)\n\t"
		"jnz 1b"
		: /* no outputs */
		:	"D"(ptr),
			"b"(low),
			"c"(high)
		:	"ax","dx","memory");
}

#undef  set_64bit
#define set_64bit __kvm_set_64bit

static inline unsigned long long __kvm_cmpxchg64(volatile void *ptr,
						 unsigned long long old,
						 unsigned long long new)
{
	unsigned long long prev;
	__asm__ __volatile__(LOCK_PREFIX "cmpxchg8b %3"
			     : "=A"(prev)
			     : "b"((unsigned long)new),
			       "c"((unsigned long)(new >> 32)),
			       "m"(*__xg(ptr)),
			       "0"(old)
			     : "memory");
	return prev;
}

#define kvm_cmpxchg64(ptr,o,n)\
	((__typeof__(*(ptr)))__kvm_cmpxchg64((ptr),(unsigned long long)(o),\
					(unsigned long long)(n)))

#undef cmpxchg64
#define cmpxchg64(ptr, o, n) kvm_cmpxchg64(ptr, o, n)

#endif

#ifndef CONFIG_PREEMPT_NOTIFIERS
/*
 * Include sched|preempt.h before defining CONFIG_PREEMPT_NOTIFIERS to avoid
 * a miscompile.
 */
#include <linux/sched.h>
#include <linux/preempt.h>
#define CONFIG_PREEMPT_NOTIFIERS
#define CONFIG_PREEMPT_NOTIFIERS_COMPAT

struct preempt_notifier;

struct preempt_ops {
	void (*sched_in)(struct preempt_notifier *notifier, int cpu);
	void (*sched_out)(struct preempt_notifier *notifier,
			  struct task_struct *next);
};

struct preempt_notifier {
	struct list_head link;
	struct task_struct *tsk;
	struct preempt_ops *ops;
};

void preempt_notifier_register(struct preempt_notifier *notifier);
void preempt_notifier_unregister(struct preempt_notifier *notifier);

static inline void preempt_notifier_init(struct preempt_notifier *notifier,
				     struct preempt_ops *ops)
{
	notifier->ops = ops;
}

void start_special_insn(void);
void end_special_insn(void);
void in_special_section(void);
void special_reload_dr7(void);

void preempt_notifier_sys_init(void);
void preempt_notifier_sys_exit(void);

#else

static inline void start_special_insn(void) {}
static inline void end_special_insn(void) {}
static inline void in_special_section(void) {}
static inline void special_reload_dr7(void) {}

static inline void preempt_notifier_sys_init(void) {}
static inline void preempt_notifier_sys_exit(void) {}

#endif

/* HRTIMER_MODE_ABS started life with a different name */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
#define HRTIMER_MODE_ABS HRTIMER_ABS
#endif

/* div64_64 is fairly new */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,21)

#ifdef CONFIG_64BIT

static inline uint64_t div64_64(uint64_t dividend, uint64_t divisor)
{
	return dividend / divisor;
}

#else

/* 64bit divisor, dividend and result. dynamic precision */
static inline uint64_t div64_64(uint64_t dividend, uint64_t divisor)
{
	uint32_t high, d;

	high = divisor >> 32;
	if (high) {
		unsigned int shift = fls(high);

		d = divisor >> shift;
		dividend >>= shift;
	} else
		d = divisor;

	do_div(dividend, d);

	return dividend;
}

#endif

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)

typedef _Bool bool;

#endif

/*
 * PF_VCPU is a Linux 2.6.24 addition
 */

#include <linux/sched.h>

#ifndef PF_VCPU
#define PF_VCPU 0
#endif

/*
 * smp_call_function_mask() is not defined/exported below 2.6.24
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)

#include <linux/smp.h>

struct kvm_call_data_struct {
	void (*func) (void *info);
	void *info;
	atomic_t started;
	atomic_t finished;
	int wait;
};

static void kvm_ack_smp_call(void *_data)
{
	struct kvm_call_data_struct *data = _data;
	/* if wait == 0, data can be out of scope
	 * after atomic_inc(info->started)
	 */
	void (*func) (void *info) = data->func;
	void *info = data->info;
	int wait = data->wait;

	smp_mb();
	atomic_inc(&data->started);
	(*func)(info);
	if (wait) {
		smp_mb();
		atomic_inc(&data->finished);
	}
}

static inline int kvm_smp_call_function_mask(cpumask_t mask,
	void (*func) (void *info), void *info, int wait)
{
	struct kvm_call_data_struct data;
	cpumask_t allbutself;
	int cpus;
	int cpu;
	int me;

	me = get_cpu();
	allbutself = cpu_online_map;
	cpu_clear(me, allbutself);

	cpus_and(mask, mask, allbutself);
	cpus = cpus_weight(mask);

	if (!cpus)
		goto out;

	data.func = func;
	data.info = info;
	atomic_set(&data.started, 0);
	data.wait = wait;
	if (wait)
		atomic_set(&data.finished, 0);

	for (cpu = first_cpu(mask); cpu != NR_CPUS; cpu = next_cpu(cpu, mask))
		smp_call_function_single(cpu, kvm_ack_smp_call, &data, 1, 0);

	while (atomic_read(&data.started) != cpus) {
		cpu_relax();
		barrier();
	}

	if (!wait)
		goto out;

	while (atomic_read(&data.finished) != cpus) {
		cpu_relax();
		barrier();
	}
out:
	put_cpu();
	return 0;
}

#define smp_call_function_mask kvm_smp_call_function_mask

#endif

/* CONFIG_HAS_IOMEM is apparently fairly new too (2.6.21 for x86_64). */
#ifndef CONFIG_HAS_IOMEM
#define CONFIG_HAS_IOMEM 1
#endif

/* empty_zero_page isn't exported in all kernels */
#include <asm/pgtable.h>

#define empty_zero_page kvm_empty_zero_page

static char empty_zero_page[PAGE_SIZE];

static inline void blahblah(void)
{
	(void)empty_zero_page[0];
}

/* __mmdrop() is not exported before 2.6.25 */
#include <linux/sched.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#define mmdrop(x) do { (void)(x); } while (0)
#define mmget(x) do { (void)(x); } while (0)

#else

#define mmget(x) do { atomic_inc(x); } while (0)

#endif

/* X86_FEATURE_NX is missing in some x86_64 kernels */

#include <asm/cpufeature.h>

#ifndef X86_FEATURE_NX
#define X86_FEATURE_NX (1*32+20)
#endif

#undef true
#define true 1
#undef false
#define false 0

/* EFER_LMA and EFER_LME are missing in pre 2.6.24 i386 kernels */
#ifndef EFER_LME
#define _EFER_LME           8  /* Long mode enable */
#define _EFER_LMA           10 /* Long mode active (read-only) */
#define EFER_LME            (1<<_EFER_LME)
#define EFER_LMA            (1<<_EFER_LMA)
#endif

/* pagefault_enable(), page_fault_disable() - 2.6.20 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)

#define pagefault_enable()  do {} while (0)
#define pagefault_disable() do {} while (0)

#endif

/* vm ops ->fault() was introduced in 2.6.23. */
#include <linux/mm.h>

#ifdef KVM_MAIN
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)

struct vm_fault {
	unsigned int flags;
	pgoff_t pgoff;
	void __user *virtual_address;
	struct page *page;
};

static int kvm_vcpu_fault(struct vm_area_struct *vma, struct vm_fault *vmf);
static int kvm_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf);

static inline struct page *kvm_nopage_to_fault(
	int (*fault)(struct vm_area_struct *vma, struct vm_fault *vmf),
	struct vm_area_struct *vma,
	unsigned long address,
	int *type)
{
	struct vm_fault vmf;
	int ret;

	vmf.pgoff = ((address - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
	vmf.virtual_address = (void __user *)address;
	ret = fault(vma, &vmf);
	if (ret)
		return NOPAGE_SIGBUS;
	*type = VM_FAULT_MINOR;
	return vmf.page;
}

static inline struct page *__kvm_vcpu_fault(struct vm_area_struct *vma,
					    unsigned long address,
					    int *type)
{
	return kvm_nopage_to_fault(kvm_vcpu_fault, vma, address, type);
}

static inline struct page *__kvm_vm_fault(struct vm_area_struct *vma,
					  unsigned long address,
					  int *type)
{
	return kvm_nopage_to_fault(kvm_vm_fault, vma, address, type);
}

#define VMA_OPS_FAULT(x) nopage
#define VMA_OPS_FAULT_FUNC(x) __##x

#else

#define VMA_OPS_FAULT(x) x
#define VMA_OPS_FAULT_FUNC(x) x

#endif
#endif

/* simple vfs attribute getter signature has changed to add a return code */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#define MAKE_SIMPLE_ATTRIBUTE_GETTER(x)       \
	static u64 x(void *v)                 \
	{				      \
		u64 ret = 0;		      \
					      \
		__##x(v, &ret);		      \
		return ret;		      \
	}

#else

#define MAKE_SIMPLE_ATTRIBUTE_GETTER(x)       \
	static int x(void *v, u64 *val)	      \
	{				      \
		return __##x(v, val);	      \
	}

#endif

/* set_kset_name() is gone in 2.6.25 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)

#define set_kset_name(x) .name = x

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#ifndef FASTCALL
#define FASTCALL(x)	x
#define fastcall
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)

#define kvm_tsc_khz 2000000

#else

#define kvm_tsc_khz tsc_khz

#endif

struct kvm_desc_struct {
	union {
		struct { unsigned int a, b; };
		struct {
			u16 limit0;
			u16 base0;
			unsigned base1: 8, type: 4, s: 1, dpl: 2, p: 1;
			unsigned limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
		};

	};
} __attribute__((packed));

struct kvm_ldttss_desc64 {
	u16 limit0;
	u16 base0;
	unsigned base1 : 8, type : 5, dpl : 2, p : 1;
	unsigned limit1 : 4, zero0 : 3, g : 1, base2 : 8;
	u32 base3;
	u32 zero1;
} __attribute__((packed));

struct kvm_desc_ptr {
	unsigned short size;
	unsigned long address;
} __attribute__((packed));

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,21)

#include <linux/ktime.h>
#include <linux/hrtimer.h>

#define ktime_get kvm_ktime_get

static inline ktime_t ktime_get(void)
{
	struct timespec now;

	ktime_get_ts(&now);

	return timespec_to_ktime(now);
}

#endif

