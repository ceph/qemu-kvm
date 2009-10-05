
#include <libcflat.h>
#include "smp.h"
#include "apic.h"
#include "fwcfg.h"

#define IPI_VECTOR 0x20

static struct spinlock ipi_lock;
static void (*ipi_function)(void *data);
static void *ipi_data;
static volatile int ipi_done;

static __attribute__((used)) void ipi()
{
    ipi_function(ipi_data);
    apic_write(APIC_EOI, 0);
    ipi_done = 1;
}

asm (
     "ipi_entry: \n"
     "   call ipi \n"
#ifndef __x86_64__
     "   iret"
#else
     "   iretq"
#endif
     );


static void set_ipi_descriptor(void (*ipi_entry)(void))
{
    unsigned short *desc = (void *)(IPI_VECTOR * sizeof(long) * 2);
    unsigned short cs;
    unsigned long ipi = (unsigned long)ipi_entry;

    asm ("mov %%cs, %0" : "=r"(cs));
    desc[0] = ipi;
    desc[1] = cs;
    desc[2] = 0x8e00;
    desc[3] = ipi >> 16;
#ifdef __x86_64__
    desc[4] = ipi >> 32;
    desc[5] = ipi >> 48;
    desc[6] = 0;
    desc[7] = 0;
#endif
}

void spin_lock(struct spinlock *lock)
{
    int v = 1;

    do {
	asm volatile ("xchg %1, %0" : "+m"(lock->v), "+r"(v));
    } while (v);
    asm volatile ("" : : : "memory");
}

void spin_unlock(struct spinlock *lock)
{
    asm volatile ("" : : : "memory");
    lock->v = 0;
}

int cpu_count(void)
{
    return fwcfg_get_nb_cpus();
}

int smp_id(void)
{
    unsigned id;

    asm ("mov %%gs:0, %0" : "=r"(id));
    return id;
}

static void setup_smp_id(void *data)
{
    asm ("mov %0, %%gs:0" : : "r"(apic_id()) : "memory");
}

static void __on_cpu(int cpu, void (*function)(void *data), void *data,
                     int wait)
{
    spin_lock(&ipi_lock);
    if (cpu == smp_id())
	function(data);
    else {
	ipi_done = 0;
	ipi_function = function;
	ipi_data = data;
	apic_icr_write(APIC_INT_ASSERT | APIC_DEST_PHYSICAL | APIC_DM_FIXED
                       | IPI_VECTOR,
                       cpu);
	if (wait) {
		while (!ipi_done)
		    ;
	}
    }
    spin_unlock(&ipi_lock);
}

void on_cpu(int cpu, void (*function)(void *data), void *data)
{
    __on_cpu(cpu, function, data, 1);
}

void on_cpu_async(int cpu, void (*function)(void *data), void *data)
{
    __on_cpu(cpu, function, data, 0);
}


void smp_init(void)
{
    int i;
    void ipi_entry(void);

    set_ipi_descriptor(ipi_entry);

    setup_smp_id(0);
    for (i = 1; i < cpu_count(); ++i)
        on_cpu(i, setup_smp_id, 0);

}
