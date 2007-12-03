
#include "config.h"
#include "config-host.h"

extern int kvm_allowed;
extern int kvm_irqchip;

#ifdef USE_KVM

#include <string.h>
#include "vl.h"

#include "qemu-kvm.h"
#include <libkvm.h>
#include <pthread.h>
#include <sys/utsname.h>

#endif
