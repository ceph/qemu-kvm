#include "hw/hw.h"
#include "hw/boards.h"

#include "exec-all.h"
#include "qemu-kvm.h"

void register_machines(void)
{
    qemu_register_machine(&ipf_machine);
}

void cpu_save(QEMUFile *f, void *opaque)
{
    CPUState *env = opaque;

    if (kvm_enabled()) {
        kvm_save_registers(env);
        kvm_save_mpstate(env);
    }
}

int cpu_load(QEMUFile *f, void *opaque, int version_id)
{
    CPUState *env = opaque;

    if (kvm_enabled()) {
        kvm_load_registers(env);
        kvm_load_mpstate(env);
    }
    return 0;
}
