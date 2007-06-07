

#include "apic.h"
#include "printf.h"

#define IPI_VECTOR 0x20

static int apic_read(int reg)
{
    unsigned short port = APIC_BASE + reg;
    unsigned v;

    asm volatile ("in %1, %0" : "=a"(v) : "d"(port));
    return v;
}

static void apic_write(int reg, unsigned v)
{
    unsigned short port = APIC_BASE + reg;

    asm volatile ("out %0, %1" : : "a"(v), "d"(port));
}

static int apic_get_cpu_count()
{
    return apic_read(APIC_REG_NCPU);
}

static int apic_get_id()
{
    return apic_read(APIC_REG_ID);
}

static void apic_set_ipi_vector(int vector)
{
    apic_write(APIC_REG_IPI_VECTOR, vector);
}

static void apic_send_ipi(int cpu)
{
    apic_write(APIC_REG_SEND_IPI, cpu);
}

static __attribute__((used)) void ipi()
{
    printf("ipi called, cpu %d\n", apic_get_id());
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


static void set_ipi_descriptor()
{
    unsigned short *desc = (void *)(IPI_VECTOR * sizeof(long) * 2);
    unsigned short cs;
    void ipi_entry();
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

int main()
{
    int ncpus;
    int i;

    ncpus = apic_get_cpu_count();
    printf("found %d cpus\n", ncpus);
    apic_set_ipi_vector(IPI_VECTOR);
    set_ipi_descriptor();
    for (i = 1; i < ncpus; ++i)
	apic_send_ipi(i);
}
