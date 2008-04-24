
/*
 * smp_call_function_single() is not exported below 2.6.20.
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)

#undef smp_call_function_single

#include <linux/spinlock.h>
#include <linux/smp.h>

struct scfs_thunk_info {
	int cpu;
	void (*func)(void *info);
	void *info;
};

static void scfs_thunk(void *_thunk)
{
	struct scfs_thunk_info *thunk = _thunk;

	if (raw_smp_processor_id() == thunk->cpu)
		thunk->func(thunk->info);
}

int kvm_smp_call_function_single(int cpu, void (*func)(void *info),
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

#define smp_call_function_single kvm_smp_call_function_single

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
/*
 * pre 2.6.23 doesn't handle smp_call_function_single on current cpu
 */

#undef smp_call_function_single

#include <linux/smp.h>

int kvm_smp_call_function_single(int cpu, void (*func)(void *info),
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

#define smp_call_function_single kvm_smp_call_function_single

#endif
