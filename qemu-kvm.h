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
int kvm_qemu_check_extension(int ext);
void kvm_apic_init(CPUState *env);

int kvm_physical_memory_set_dirty_tracking(int enable);
int kvm_update_dirty_pages_log(void);
int kvm_get_phys_ram_page_bitmap(unsigned char *bitmap);

void qemu_kvm_call_with_env(void (*func)(void *), void *data, CPUState *env);
void qemu_kvm_cpuid_on_env(CPUState *env);
void kvm_update_after_sipi(CPUState *env);
void kvm_update_interrupt_request(CPUState *env);
void kvm_cpu_register_physical_memory(target_phys_addr_t start_addr,
                                      unsigned long size,
                                      unsigned long phys_offset);
int kvm_arch_qemu_create_context(void);

void kvm_arch_save_regs(CPUState *env);
void kvm_arch_load_regs(CPUState *env);
int kvm_arch_qemu_init_env(CPUState *cenv);
int kvm_arch_halt(void *opaque, int vcpu);
void kvm_arch_pre_kvm_run(void *opaque, int vcpu);
void kvm_arch_post_kvm_run(void *opaque, int vcpu);
int kvm_arch_has_work(CPUState *env);
int kvm_arch_try_push_interrupts(void *opaque);
void kvm_arch_update_regs_for_sipi(CPUState *env);

CPUState *qemu_kvm_cpu_env(int index);

void qemu_kvm_aio_wait_start(void);
void qemu_kvm_aio_wait(void);
void qemu_kvm_aio_wait_end(void);

extern int kvm_allowed;
extern int kvm_irqchip;

void kvm_tpr_opt_setup(CPUState *env);
void kvm_tpr_access_report(CPUState *env, uint64_t rip, int is_write);
int handle_tpr_access(void *opaque, int vcpu,
			     uint64_t rip, int is_write);

#ifdef TARGET_PPC
int handle_powerpc_dcr_read(uint32_t dcrn, uint32_t *data);
int handle_powerpc_dcr_write(uint32_t dcrn, uint32_t data);
#endif

#define ALIGN(x, y)  (((x)+(y)-1) & ~((y)-1))
#define BITMAP_SIZE(m) (ALIGN(((m)>>TARGET_PAGE_BITS), HOST_LONG_BITS) / 8)


#endif
