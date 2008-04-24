
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
	WARN_ON(irqs_disabled());
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
	WARN_ON(irqs_disabled());
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

/* div64_64 is fairly new */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,21)

#ifndef CONFIG_64BIT

/* 64bit divisor, dividend and result. dynamic precision */
uint64_t div64_64(uint64_t dividend, uint64_t divisor)
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

int kvm_smp_call_function_mask(cpumask_t mask,
			       void (*func) (void *info), void *info, int wait)
{
	struct kvm_call_data_struct data;
	cpumask_t allbutself;
	int cpus;
	int cpu;
	int me;

	me = get_cpu();
	WARN_ON(irqs_disabled());
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

#endif
