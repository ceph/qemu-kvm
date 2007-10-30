#ifndef QEMU_KVM_H
#define QEMU_KVM_H

#include "cpu.h"
#include "libkvm.h"

int kvm_main_loop(void);
int kvm_qemu_init(void);
int kvm_qemu_create_context(void);
int kvm_init_ap(void);
void kvm_qemu_destroy(void);
void kvm_load_registers(CPUState *env);
void kvm_save_registers(CPUState *env);
int kvm_cpu_exec(CPUState *env);
int kvm_update_debugger(CPUState *env);
int kvm_qemu_init_env(CPUState *env);
void kvm_apic_init(CPUState *env);

int kvm_physical_memory_set_dirty_tracking(int enable);
int kvm_update_dirty_pages_log(void);
int kvm_get_phys_ram_page_bitmap(unsigned char *bitmap);

void qemu_kvm_call_with_env(void (*func)(void *), void *data, CPUState *env);
void qemu_kvm_cpuid_on_env(CPUState *env);
void kvm_update_after_sipi(CPUState *env);
void kvm_update_interrupt_request(CPUState *env);


#define ALIGN(x, y)  (((x)+(y)-1) & ~((y)-1))
#define BITMAP_SIZE(m) (ALIGN(((m)>>TARGET_PAGE_BITS), HOST_LONG_BITS) / 8)
#endif
