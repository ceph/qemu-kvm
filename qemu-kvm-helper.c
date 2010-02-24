
#include "config.h"
#include "config-host.h"

#include "exec.h"

#include "qemu-kvm.h"

void qemu_kvm_call_with_env(void (*func)(void *), void *data, CPUState *newenv)
{
    host_reg_t saved_env_reg;
    CPUState *oldenv;

    oldenv = newenv;

    saved_env_reg = (host_reg_t) env;
    env = newenv;

    func(data);

    env = oldenv;
    asm("");
    env = (void *) saved_env_reg;
}

static void call_helper_cpuid(void *junk)
{
    helper_cpuid();
}

void qemu_kvm_cpuid_on_env(CPUState *env)
{
    qemu_kvm_call_with_env(call_helper_cpuid, NULL, env);
}

