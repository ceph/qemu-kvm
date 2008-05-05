#include "hw/hw.h"
#include "hw/boards.h"
#include "hw/ipf.h"

#include "exec-all.h"
#include "qemu-kvm.h"

void register_machines(void)
{
    qemu_register_machine(&ipf_machine);
}

void cpu_save(QEMUFile *f, void *opaque)
{
}

int cpu_load(QEMUFile *f, void *opaque, int version_id)
{
    return 0;
}
