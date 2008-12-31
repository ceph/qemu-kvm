/*
 * qemu/kvm integration
 *
 * Copyright (C) 2006-2008 Qumranet Technologies
 *
 * Licensed under the terms of the GNU GPL version 2 or higher.
 */
#ifndef THE_ORIGINAL_AND_TRUE_QEMU_KVM_H
#define THE_ORIGINAL_AND_TRUE_QEMU_KVM_H

#include "cpu.h"

#include <signal.h>

int kvm_main_loop(void);
int kvm_qemu_init(void);
int kvm_qemu_create_context(void);
int kvm_init_ap(void);
void kvm_qemu_destroy(void);
void kvm_load_registers(CPUState *env);
void kvm_save_registers(CPUState *env);
void kvm_load_mpstate(CPUState *env);
void kvm_save_mpstate(CPUState *env);
int kvm_cpu_exec(CPUState *env);
int kvm_insert_breakpoint(CPUState *current_env, target_ulong addr,
                          target_ulong len, int type);
int kvm_remove_breakpoint(CPUState *current_env, target_ulong addr,
                          target_ulong len, int type);
void kvm_remove_all_breakpoints(CPUState *current_env);
int kvm_update_guest_debug(CPUState *env, unsigned long reinject_trap);
int kvm_qemu_init_env(CPUState *env);
int kvm_qemu_check_extension(int ext);
void kvm_apic_init(CPUState *env);
int kvm_set_irq(int irq, int level);

int kvm_physical_memory_set_dirty_tracking(int enable);
int kvm_update_dirty_pages_log(void);
int kvm_get_phys_ram_page_bitmap(unsigned char *bitmap);

void qemu_kvm_call_with_env(void (*func)(void *), void *data, CPUState *env);
void qemu_kvm_cpuid_on_env(CPUState *env);
void kvm_inject_interrupt(CPUState *env, int mask);
void kvm_update_after_sipi(CPUState *env);
void kvm_update_interrupt_request(CPUState *env);
void kvm_cpu_register_physical_memory(target_phys_addr_t start_addr,
                                      unsigned long size,
                                      unsigned long phys_offset);
void kvm_cpu_unregister_physical_memory(target_phys_addr_t start_addr,
                                        target_phys_addr_t size,
                                        unsigned long phys_offset);
void *kvm_cpu_create_phys_mem(target_phys_addr_t start_addr,
			      unsigned long size, int log, int writable);

void kvm_cpu_destroy_phys_mem(target_phys_addr_t start_addr,
			      unsigned long size);
void kvm_qemu_log_memory(target_phys_addr_t start, target_phys_addr_t size,
                         int log);
int kvm_setup_guest_memory(void *area, unsigned long size);
int kvm_qemu_create_memory_alias(uint64_t phys_start,
                                 uint64_t len,
                                 uint64_t target_phys);
int kvm_qemu_destroy_memory_alias(uint64_t phys_start);

int kvm_arch_qemu_create_context(void);

void kvm_arch_save_regs(CPUState *env);
void kvm_arch_load_regs(CPUState *env);
int kvm_arch_qemu_init_env(CPUState *cenv);
int kvm_arch_halt(void *opaque, int vcpu);
void kvm_arch_pre_kvm_run(void *opaque, CPUState *env);
void kvm_arch_post_kvm_run(void *opaque, CPUState *env);
int kvm_arch_has_work(CPUState *env);
int kvm_arch_try_push_interrupts(void *opaque);
void kvm_arch_push_nmi(void *opaque);
void kvm_arch_update_regs_for_sipi(CPUState *env);
void kvm_arch_cpu_reset(CPUState *env);

struct kvm_guest_debug;
struct kvm_debug_exit_arch;

struct kvm_sw_breakpoint {
    target_ulong pc;
    target_ulong saved_insn;
    int use_count;
    TAILQ_ENTRY(kvm_sw_breakpoint) entry;
};
TAILQ_HEAD(kvm_sw_breakpoint_head, kvm_sw_breakpoint);

extern struct kvm_sw_breakpoint_head kvm_sw_breakpoints;

int kvm_arch_debug(struct kvm_debug_exit_arch *arch_info);
struct kvm_sw_breakpoint *kvm_find_sw_breakpoint(target_ulong pc);
int kvm_arch_insert_sw_breakpoint(CPUState *current_env,
                                  struct kvm_sw_breakpoint *bp);
int kvm_arch_remove_sw_breakpoint(CPUState *current_env,
                                  struct kvm_sw_breakpoint *bp);
int kvm_arch_insert_hw_breakpoint(target_ulong addr,
				  target_ulong len, int type);
int kvm_arch_remove_hw_breakpoint(target_ulong addr,
				  target_ulong len, int type);
void kvm_arch_remove_all_hw_breakpoints(void);
void kvm_arch_update_guest_debug(CPUState *env, struct kvm_guest_debug *dbg);

void qemu_kvm_aio_wait_start(void);
void qemu_kvm_aio_wait(void);
void qemu_kvm_aio_wait_end(void);

void qemu_kvm_notify_work(void);

void kvm_tpr_opt_setup();
void kvm_tpr_access_report(CPUState *env, uint64_t rip, int is_write);
int handle_tpr_access(void *opaque, int vcpu,
			     uint64_t rip, int is_write);
void kvm_tpr_vcpu_start(CPUState *env);

int qemu_kvm_get_dirty_pages(unsigned long phys_addr, void *buf);
int qemu_kvm_register_coalesced_mmio(target_phys_addr_t addr,
				     unsigned int size);
int qemu_kvm_unregister_coalesced_mmio(target_phys_addr_t addr,
				       unsigned int size);

void qemu_kvm_system_reset_request(void);

int kvm_coalesce_mmio_region(target_phys_addr_t start, ram_addr_t size);
int kvm_uncoalesce_mmio_region(target_phys_addr_t start, ram_addr_t size);

#ifdef USE_KVM_DEVICE_ASSIGNMENT
void kvm_ioperm(CPUState *env, void *data);
void kvm_arch_do_ioperm(void *_data);
#endif

#ifdef TARGET_PPC
int handle_powerpc_dcr_read(int vcpu, uint32_t dcrn, uint32_t *data);
int handle_powerpc_dcr_write(int vcpu,uint32_t dcrn, uint32_t data);
#endif

#define ALIGN(x, y)  (((x)+(y)-1) & ~((y)-1))
#define BITMAP_SIZE(m) (ALIGN(((m)>>TARGET_PAGE_BITS), HOST_LONG_BITS) / 8)

#ifdef USE_KVM
#include "libkvm.h"
#include "sys-queue.h"

extern int kvm_allowed;
extern int kvm_nested;
extern kvm_context_t kvm_context;

struct ioperm_data {
    unsigned long start_port;
    unsigned long num;
    int turn_on;
    LIST_ENTRY(ioperm_data) entries;
};

int qemu_kvm_has_sync_mmu(void);
void qemu_kvm_cpu_stop(CPUState *env);

#define kvm_enabled() (kvm_allowed)
#define qemu_kvm_irqchip_in_kernel() kvm_irqchip_in_kernel(kvm_context)
#define qemu_kvm_pit_in_kernel() kvm_pit_in_kernel(kvm_context)
#define kvm_has_sync_mmu() qemu_kvm_has_sync_mmu()
void kvm_init_vcpu(CPUState *env);
void kvm_load_tsc(CPUState *env);
#else
#define kvm_enabled() (0)
#define kvm_nested 0
#define qemu_kvm_irqchip_in_kernel() (0)
#define qemu_kvm_pit_in_kernel() (0)
#define kvm_has_sync_mmu() (0)
#define kvm_load_registers(env) do {} while(0)
#define kvm_save_registers(env) do {} while(0)
#define qemu_kvm_cpu_stop(env) do {} while(0)
static inline void kvm_init_vcpu(CPUState *env) { }
static inline void kvm_load_tsc(CPUState *env) {}
#endif

void kvm_mutex_unlock(void);
void kvm_mutex_lock(void);

static inline void kvm_sleep_begin(void)
{
    if (kvm_enabled())
	kvm_mutex_unlock();
}

static inline void kvm_sleep_end(void)
{
    if (kvm_enabled())
	kvm_mutex_lock();
}

static inline void kvm_set_phys_mem(target_phys_addr_t start_addr,
                      ram_addr_t size,
                      ram_addr_t phys_offset)
{
    kvm_cpu_register_physical_memory(start_addr, size, phys_offset);
}


void kvm_physical_sync_dirty_bitmap(target_phys_addr_t start_addr, target_phys_addr_t end_addr);

int kvm_log_start(target_phys_addr_t phys_addr, target_phys_addr_t len);
int kvm_log_stop(target_phys_addr_t phys_addr, target_phys_addr_t len);


static inline int kvm_sync_vcpus(void) { return 0; }

#endif
