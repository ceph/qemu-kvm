/** \file libkvm.h
 * libkvm API
 */

#ifndef LIBKVM_H
#define LIBKVM_H

#ifdef USE_KVM

#if defined(__s390__)
#include <asm/ptrace.h>
#endif

#include <stdint.h>

#ifndef __user
#define __user /* temporary, until installed via make headers_install */
#endif

#include <linux/kvm.h>

#include <signal.h>

/* FIXME: share this number with kvm */
/* FIXME: or dynamically alloc/realloc regions */
#ifdef __s390__
#define KVM_MAX_NUM_MEM_REGIONS 1u
#define MAX_VCPUS 64
#define LIBKVM_S390_ORIGIN (0UL)
#elif defined(__ia64__)
#define KVM_MAX_NUM_MEM_REGIONS 32u
#define MAX_VCPUS 256
#else
#define KVM_MAX_NUM_MEM_REGIONS 32u
#define MAX_VCPUS 16
#endif

/* kvm abi verison variable */
extern int kvm_abi;

/**
 * \brief The KVM context
 *
 * The verbose KVM context
 */

struct kvm_context {
	/// Filedescriptor to /dev/kvm
	int fd;
	int vm_fd;
	/// Callbacks that KVM uses to emulate various unvirtualizable functionality
	struct kvm_callbacks *callbacks;
	void *opaque;
	/// is dirty pages logging enabled for all regions or not
	int dirty_pages_log_all;
	/// do not create in-kernel irqchip if set
	int no_irqchip_creation;
	/// in-kernel irqchip status
	int irqchip_in_kernel;
	/// ioctl to use to inject interrupts
	int irqchip_inject_ioctl;
	/// do not create in-kernel pit if set
	int no_pit_creation;
	/// in-kernel pit status
	int pit_in_kernel;
	/// in-kernel coalesced mmio
	int coalesced_mmio;
#ifdef KVM_CAP_IRQ_ROUTING
	struct kvm_irq_routing *irq_routes;
	int nr_allocated_irq_routes;
#endif
	void *used_gsi_bitmap;
	int max_gsi;
};

struct kvm_vcpu_context
{
	int fd;
	struct kvm_run *run;
	struct kvm_context *kvm;
	uint32_t id;
};

typedef struct kvm_context *kvm_context_t;
typedef struct kvm_vcpu_context *kvm_vcpu_context_t;

#include "kvm.h"
int kvm_alloc_kernel_memory(kvm_context_t kvm, unsigned long memory,
								void **vm_mem);
int kvm_alloc_userspace_memory(kvm_context_t kvm, unsigned long memory,
								void **vm_mem);

int kvm_arch_create(kvm_context_t kvm, unsigned long phys_mem_bytes,
                        void **vm_mem);
int kvm_arch_run(kvm_vcpu_context_t vcpu);


void kvm_show_code(kvm_vcpu_context_t vcpu);

int handle_halt(kvm_vcpu_context_t vcpu);
int handle_shutdown(kvm_context_t kvm, CPUState *env);
void post_kvm_run(kvm_context_t kvm, CPUState *env);
int pre_kvm_run(kvm_context_t kvm, CPUState *env);
int handle_io_window(kvm_context_t kvm);
int handle_debug(kvm_vcpu_context_t vcpu, void *env);
int try_push_interrupts(kvm_context_t kvm);

#if defined(__x86_64__) || defined(__i386__)
struct kvm_msr_list *kvm_get_msr_list(kvm_context_t);
int kvm_get_msrs(kvm_vcpu_context_t, struct kvm_msr_entry *msrs, int n);
int kvm_set_msrs(kvm_vcpu_context_t, struct kvm_msr_entry *msrs, int n);
#endif

/*!
 * \brief Create new KVM context
 *
 * This creates a new kvm_context. A KVM context is a small area of data that
 * holds information about the KVM instance that gets created by this call.\n
 * This should always be your first call to KVM.
 *
 * \param opaque Not used
 * \return NULL on failure
 */
kvm_context_t kvm_init(void *opaque);

/*!
 * \brief Cleanup the KVM context
 *
 * Should always be called when closing down KVM.\n
 * Exception: If kvm_init() fails, this function should not be called, as the
 * context would be invalid
 *
 * \param kvm Pointer to the kvm_context that is to be freed
 */
void kvm_finalize(kvm_context_t kvm);

/*!
 * \brief Disable the in-kernel IRQCHIP creation
 *
 * In-kernel irqchip is enabled by default. If userspace irqchip is to be used,
 * this should be called prior to kvm_create().
 *
 * \param kvm Pointer to the kvm_context
 */
void kvm_disable_irqchip_creation(kvm_context_t kvm);

/*!
 * \brief Disable the in-kernel PIT creation
 *
 * In-kernel pit is enabled by default. If userspace pit is to be used,
 * this should be called prior to kvm_create().
 *
 *  \param kvm Pointer to the kvm_context
 */
void kvm_disable_pit_creation(kvm_context_t kvm);

/*!
 * \brief Create new virtual machine
 *
 * This creates a new virtual machine, maps physical RAM to it, and creates a
 * virtual CPU for it.\n
 * \n
 * Memory gets mapped for addresses 0->0xA0000, 0xC0000->phys_mem_bytes
 *
 * \param kvm Pointer to the current kvm_context
 * \param phys_mem_bytes The amount of physical ram you want the VM to have
 * \param phys_mem This pointer will be set to point to the memory that
 * kvm_create allocates for physical RAM
 * \return 0 on success
 */
int kvm_create(kvm_context_t kvm,
	       unsigned long phys_mem_bytes,
	       void **phys_mem);
int kvm_create_vm(kvm_context_t kvm);
int kvm_check_extension(kvm_context_t kvm, int ext);
void kvm_create_irqchip(kvm_context_t kvm);

/*!
 * \brief Create a new virtual cpu
 *
 * This creates a new virtual cpu (the first vcpu is created by kvm_create()).
 * Should be called from a thread dedicated to the vcpu.
 *
 * \param kvm kvm context
 * \param slot vcpu number (> 0)
 * \return 0 on success, -errno on failure
 */
kvm_vcpu_context_t kvm_create_vcpu(kvm_context_t kvm, int id);

/*!
 * \brief Start the VCPU
 *
 * This starts the VCPU and virtualization is started.\n
 * \n
 * This function will not return until any of these conditions are met:
 * - An IO/MMIO handler does not return "0"
 * - An exception that neither the guest OS, nor KVM can handle occurs
 *
 * \note This function will call the callbacks registered in kvm_init()
 * to emulate those functions
 * \note If you at any point want to interrupt the VCPU, kvm_run() will
 * listen to the EINTR signal. This allows you to simulate external interrupts
 * and asyncronous IO.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should be started
 * \return 0 on success, but you really shouldn't expect this function to
 * return except for when an error has occured, or when you have sent it
 * an EINTR signal.
 */
int kvm_run(kvm_vcpu_context_t vcpu, void *env);

/*!
 * \brief Get interrupt flag from on last exit to userspace
 *
 * This gets the CPU interrupt flag as it was on the last exit to userspace.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \return interrupt flag value (0 or 1)
 */
int kvm_get_interrupt_flag(kvm_vcpu_context_t vcpu);

/*!
 * \brief Get the value of the APIC_BASE msr as of last exit to userspace
 *
 * This gets the APIC_BASE msr as it was on the last exit to userspace.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \return APIC_BASE msr contents
 */
uint64_t kvm_get_apic_base(kvm_vcpu_context_t vcpu);

/*!
 * \brief Check if a vcpu is ready for interrupt injection
 *
 * This checks if vcpu interrupts are not masked by mov ss or sti.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \return boolean indicating interrupt injection readiness
 */
int kvm_is_ready_for_interrupt_injection(kvm_vcpu_context_t vcpu);

/*!
 * \brief Read VCPU registers
 *
 * This gets the GP registers from the VCPU and outputs them
 * into a kvm_regs structure
 *
 * \note This function returns a \b copy of the VCPUs registers.\n
 * If you wish to modify the VCPUs GP registers, you should call kvm_set_regs()
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \param regs Pointer to a kvm_regs which will be populated with the VCPUs
 * registers values
 * \return 0 on success
 */
int kvm_get_regs(kvm_vcpu_context_t vcpu, struct kvm_regs *regs);

/*!
 * \brief Write VCPU registers
 *
 * This sets the GP registers on the VCPU from a kvm_regs structure
 *
 * \note When this function returns, the regs pointer and the data it points to
 * can be discarded
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \param regs Pointer to a kvm_regs which will be populated with the VCPUs
 * registers values
 * \return 0 on success
 */
int kvm_set_regs(kvm_vcpu_context_t vcpu, struct kvm_regs *regs);
/*!
 * \brief Read VCPU fpu registers
 *
 * This gets the FPU registers from the VCPU and outputs them
 * into a kvm_fpu structure
 *
 * \note This function returns a \b copy of the VCPUs registers.\n
 * If you wish to modify the VCPU FPU registers, you should call kvm_set_fpu()
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \param fpu Pointer to a kvm_fpu which will be populated with the VCPUs
 * fpu registers values
 * \return 0 on success
 */
int kvm_get_fpu(kvm_vcpu_context_t vcpu, struct kvm_fpu *fpu);

/*!
 * \brief Write VCPU fpu registers
 *
 * This sets the FPU registers on the VCPU from a kvm_fpu structure
 *
 * \note When this function returns, the fpu pointer and the data it points to
 * can be discarded
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \param fpu Pointer to a kvm_fpu which holds the new vcpu fpu state
 * \return 0 on success
 */
int kvm_set_fpu(kvm_vcpu_context_t vcpu, struct kvm_fpu *fpu);

/*!
 * \brief Read VCPU system registers
 *
 * This gets the non-GP registers from the VCPU and outputs them
 * into a kvm_sregs structure
 *
 * \note This function returns a \b copy of the VCPUs registers.\n
 * If you wish to modify the VCPUs non-GP registers, you should call
 * kvm_set_sregs()
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \param regs Pointer to a kvm_sregs which will be populated with the VCPUs
 * registers values
 * \return 0 on success
 */
int kvm_get_sregs(kvm_vcpu_context_t vcpu, struct kvm_sregs *regs);

/*!
 * \brief Write VCPU system registers
 *
 * This sets the non-GP registers on the VCPU from a kvm_sregs structure
 *
 * \note When this function returns, the regs pointer and the data it points to
 * can be discarded
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \param regs Pointer to a kvm_sregs which will be populated with the VCPUs
 * registers values
 * \return 0 on success
 */
int kvm_set_sregs(kvm_vcpu_context_t vcpu, struct kvm_sregs *regs);

#ifdef KVM_CAP_MP_STATE
/*!
 *  * \brief Read VCPU MP state
 *
 */
int kvm_get_mpstate(kvm_vcpu_context_t vcpu, struct kvm_mp_state *mp_state);

/*!
 *  * \brief Write VCPU MP state
 *
 */
int kvm_set_mpstate(kvm_vcpu_context_t vcpu, struct kvm_mp_state *mp_state);
/*!
 *  * \brief Reset VCPU MP state
 *
 */
static inline int kvm_reset_mpstate(kvm_vcpu_context_t vcpu)
{
    struct kvm_mp_state mp_state = {.mp_state = KVM_MP_STATE_UNINITIALIZED};
    return kvm_set_mpstate(vcpu, &mp_state);
}
#endif

/*!
 * \brief Simulate an external vectored interrupt
 *
 * This allows you to simulate an external vectored interrupt.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \param irq Vector number
 * \return 0 on success
 */
int kvm_inject_irq(kvm_vcpu_context_t vcpu, unsigned irq);

#ifdef KVM_CAP_SET_GUEST_DEBUG
int kvm_set_guest_debug(kvm_vcpu_context_t, struct kvm_guest_debug *dbg);
#endif

#if defined(__i386__) || defined(__x86_64__)
/*!
 * \brief Setup a vcpu's cpuid instruction emulation
 *
 * Set up a table of cpuid function to cpuid outputs.\n
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should be initialized
 * \param nent number of entries to be installed
 * \param entries cpuid function entries table
 * \return 0 on success, or -errno on error
 */
int kvm_setup_cpuid(kvm_vcpu_context_t vcpu, int nent,
		    struct kvm_cpuid_entry *entries);

/*!
 * \brief Setup a vcpu's cpuid instruction emulation
 *
 * Set up a table of cpuid function to cpuid outputs.
 * This call replaces the older kvm_setup_cpuid interface by adding a few
 * parameters to support cpuid functions that have sub-leaf values.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should be initialized
 * \param nent number of entries to be installed
 * \param entries cpuid function entries table
 * \return 0 on success, or -errno on error
 */
int kvm_setup_cpuid2(kvm_vcpu_context_t vcpu, int nent,
		     struct kvm_cpuid_entry2 *entries);

/*!
 * \brief Setting the number of shadow pages to be allocated to the vm
 *
 * \param kvm pointer to kvm_context
 * \param nrshadow_pages number of pages to be allocated
 */
int kvm_set_shadow_pages(kvm_context_t kvm, unsigned int nrshadow_pages);

/*!
 * \brief Getting the number of shadow pages that are allocated to the vm
 *
 * \param kvm pointer to kvm_context
 * \param nrshadow_pages number of pages to be allocated
 */
int kvm_get_shadow_pages(kvm_context_t kvm , unsigned int *nrshadow_pages);

/*!
 * \brief Set up cr8 for next time the vcpu is executed
 *
 * This is a fast setter for cr8, which will be applied when the
 * vcpu next enters guest mode.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \param cr8 next cr8 value
 */
void kvm_set_cr8(kvm_vcpu_context_t vcpu, uint64_t cr8);

/*!
 * \brief Get cr8 for sync tpr in qemu apic emulation
 *
 * This is a getter for cr8, which used to sync with the tpr in qemu
 * apic emualtion.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 */
__u64 kvm_get_cr8(kvm_vcpu_context_t vcpu);
#endif

/*!
 * \brief Set a vcpu's signal mask for guest mode
 *
 * A vcpu can have different signals blocked in guest mode and user mode.
 * This allows guest execution to be interrupted on a signal, without requiring
 * that the signal be delivered to a signal handler (the signal can be
 * dequeued using sigwait(2).
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should be initialized
 * \param sigset signal mask for guest mode
 * \return 0 on success, or -errno on error
 */
int kvm_set_signal_mask(kvm_vcpu_context_t vcpu, const sigset_t *sigset);

/*!
 * \brief Dump VCPU registers
 *
 * This dumps some of the information that KVM has about a virtual CPU, namely:
 * - GP Registers
 *
 * A much more verbose version of this is available as kvm_dump_vcpu()
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \return 0 on success
 */
void kvm_show_regs(kvm_vcpu_context_t vcpu);


void *kvm_create_phys_mem(kvm_context_t, unsigned long phys_start, 
			  unsigned long len, int log, int writable);
void kvm_destroy_phys_mem(kvm_context_t, unsigned long phys_start, 
			  unsigned long len);
void kvm_unregister_memory_area(kvm_context_t, uint64_t phys_start,
                                unsigned long len);

int kvm_is_containing_region(kvm_context_t kvm, unsigned long phys_start, unsigned long size);
int kvm_register_phys_mem(kvm_context_t kvm,
			unsigned long phys_start, void *userspace_addr,
			unsigned long len, int log);
int kvm_get_dirty_pages(kvm_context_t, unsigned long phys_addr, void *buf);
int kvm_get_dirty_pages_range(kvm_context_t kvm, unsigned long phys_addr,
			      unsigned long end_addr, void*opaque,
			      int (*cb)(unsigned long start, unsigned long len,
					void*bitmap, void *opaque));
int kvm_register_coalesced_mmio(kvm_context_t kvm,
				uint64_t addr, uint32_t size);
int kvm_unregister_coalesced_mmio(kvm_context_t kvm,
				  uint64_t addr, uint32_t size);

/*!
 * \brief Create a memory alias
 *
 * Aliases a portion of physical memory to another portion.  If the guest
 * accesses the alias region, it will behave exactly as if it accessed
 * the target memory.
 */
int kvm_create_memory_alias(kvm_context_t,
			    uint64_t phys_start, uint64_t len,
			    uint64_t target_phys);

/*!
 * \brief Destroy a memory alias
 *
 * Removes an alias created with kvm_create_memory_alias().
 */
int kvm_destroy_memory_alias(kvm_context_t, uint64_t phys_start);

/*!
 * \brief Get a bitmap of guest ram pages which are allocated to the guest.
 *
 * \param kvm Pointer to the current kvm_context
 * \param phys_addr Memory slot phys addr
 * \param bitmap Long aligned address of a big enough bitmap (one bit per page)
 */
int kvm_get_mem_map(kvm_context_t kvm, unsigned long phys_addr, void *bitmap);
int kvm_get_mem_map_range(kvm_context_t kvm, unsigned long phys_addr,
			   unsigned long len, void *buf, void *opaque,
			   int (*cb)(unsigned long start,unsigned long len,
				     void* bitmap, void* opaque));
int kvm_set_irq_level(kvm_context_t kvm, int irq, int level, int *status);

int kvm_dirty_pages_log_enable_slot(kvm_context_t kvm,
				    uint64_t phys_start,
				    uint64_t len);
int kvm_dirty_pages_log_disable_slot(kvm_context_t kvm,
				     uint64_t phys_start,
				     uint64_t len);
/*!
 * \brief Enable dirty-pages-logging for all memory regions
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_dirty_pages_log_enable_all(kvm_context_t kvm);

/*!
 * \brief Disable dirty-page-logging for some memory regions
 *
 * Disable dirty-pages-logging for those memory regions that were
 * created with dirty-page-logging disabled.
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_dirty_pages_log_reset(kvm_context_t kvm);

/*!
 * \brief Query whether in kernel irqchip is used
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_irqchip_in_kernel(kvm_context_t kvm);

#ifdef KVM_CAP_IRQCHIP
/*!
 * \brief Dump in kernel IRQCHIP contents
 *
 * Dump one of the in kernel irq chip devices, including PIC (master/slave)
 * and IOAPIC into a kvm_irqchip structure
 *
 * \param kvm Pointer to the current kvm_context
 * \param chip The irq chip device to be dumped
 */
int kvm_get_irqchip(kvm_context_t kvm, struct kvm_irqchip *chip);

/*!
 * \brief Set in kernel IRQCHIP contents
 *
 * Write one of the in kernel irq chip devices, including PIC (master/slave)
 * and IOAPIC
 *
 *
 * \param kvm Pointer to the current kvm_context
 * \param chip THe irq chip device to be written
 */
int kvm_set_irqchip(kvm_context_t kvm, struct kvm_irqchip *chip);

#if defined(__i386__) || defined(__x86_64__)
/*!
 * \brief Get in kernel local APIC for vcpu
 *
 * Save the local apic state including the timer of a virtual CPU
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should be accessed
 * \param s Local apic state of the specific virtual CPU
 */
int kvm_get_lapic(kvm_vcpu_context_t vcpu, struct kvm_lapic_state *s);

/*!
 * \brief Set in kernel local APIC for vcpu
 *
 * Restore the local apic state including the timer of a virtual CPU
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should be accessed
 * \param s Local apic state of the specific virtual CPU
 */
int kvm_set_lapic(kvm_vcpu_context_t vcpu, struct kvm_lapic_state *s);

#endif

/*!
 * \brief Simulate an NMI
 *
 * This allows you to simulate a non-maskable interrupt.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \return 0 on success
 */
int kvm_inject_nmi(kvm_vcpu_context_t vcpu);

#endif

/*!
 * \brief Query wheather in kernel pit is used
 *
 *  \param kvm Pointer to the current kvm_context
 */
int kvm_pit_in_kernel(kvm_context_t kvm);

/*!
 * \brief Initialize coalesced MMIO
 *
 * Check for coalesced MMIO capability and store in context
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_init_coalesced_mmio(kvm_context_t kvm);

#ifdef KVM_CAP_PIT

#if defined(__i386__) || defined(__x86_64__)
/*!
 * \brief Get in kernel PIT of the virtual domain
 *
 * Save the PIT state.
 *
 * \param kvm Pointer to the current kvm_context
 * \param s PIT state of the virtual domain
 */
int kvm_get_pit(kvm_context_t kvm, struct kvm_pit_state *s);

/*!
 * \brief Set in kernel PIT of the virtual domain
 *
 * Restore the PIT state.
 * Timer would be retriggerred after restored.
 *
 * \param kvm Pointer to the current kvm_context
 * \param s PIT state of the virtual domain
 */
int kvm_set_pit(kvm_context_t kvm, struct kvm_pit_state *s);

int kvm_reinject_control(kvm_context_t kvm, int pit_reinject);

#ifdef KVM_CAP_PIT_STATE2
/*!
 * \brief Check for kvm support of kvm_pit_state2
 *
 * \param kvm Pointer to the current kvm_context
 * \return 0 on success
 */
int kvm_has_pit_state2(kvm_context_t kvm);

/*!
 * \brief Set in kernel PIT state2 of the virtual domain
 *
 *
 * \param kvm Pointer to the current kvm_context
 * \param ps2 PIT state2 of the virtual domain
 * \return 0 on success
 */
int kvm_set_pit2(kvm_context_t kvm, struct kvm_pit_state2 *ps2);

/*!
 * \brief Get in kernel PIT state2 of the virtual domain
 *
 *
 * \param kvm Pointer to the current kvm_context
 * \param ps2 PIT state2 of the virtual domain
 * \return 0 on success
 */
int kvm_get_pit2(kvm_context_t kvm, struct kvm_pit_state2 *ps2);

#endif
#endif
#endif

#ifdef KVM_CAP_VAPIC

/*!
 * \brief Enable kernel tpr access reporting
 *
 * When tpr access reporting is enabled, the kernel will call the
 * ->tpr_access() callback every time the guest vcpu accesses the tpr.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu vcpu to enable tpr access reporting on
 */
int kvm_enable_tpr_access_reporting(kvm_vcpu_context_t vcpu);

/*!
 * \brief Disable kernel tpr access reporting
 *
 * Undoes the effect of kvm_enable_tpr_access_reporting().
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu vcpu to disable tpr access reporting on
 */
int kvm_disable_tpr_access_reporting(kvm_vcpu_context_t vcpu);

int kvm_enable_vapic(kvm_vcpu_context_t vcpu, uint64_t vapic);

#endif

#if defined(__s390__)
int kvm_s390_initial_reset(kvm_context_t kvm, int slot);
int kvm_s390_interrupt(kvm_context_t kvm, int slot,
	struct kvm_s390_interrupt *kvmint);
int kvm_s390_set_initial_psw(kvm_context_t kvm, int slot, psw_t psw);
int kvm_s390_store_status(kvm_context_t kvm, int slot, unsigned long addr);
#endif

#ifdef KVM_CAP_DEVICE_ASSIGNMENT
/*!
 * \brief Notifies host kernel about a PCI device to be assigned to a guest
 *
 * Used for PCI device assignment, this function notifies the host
 * kernel about the assigning of the physical PCI device to a guest.
 *
 * \param kvm Pointer to the current kvm_context
 * \param assigned_dev Parameters, like bus, devfn number, etc
 */
int kvm_assign_pci_device(kvm_context_t kvm,
			  struct kvm_assigned_pci_dev *assigned_dev);

/*!
 * \brief Assign IRQ for an assigned device
 *
 * Used for PCI device assignment, this function assigns IRQ numbers for
 * an physical device and guest IRQ handling.
 *
 * \param kvm Pointer to the current kvm_context
 * \param assigned_irq Parameters, like dev id, host irq, guest irq, etc
 */
int kvm_assign_irq(kvm_context_t kvm,
		   struct kvm_assigned_irq *assigned_irq);

#ifdef KVM_CAP_ASSIGN_DEV_IRQ
/*!
 * \brief Deassign IRQ for an assigned device
 *
 * Used for PCI device assignment, this function deassigns IRQ numbers
 * for an assigned device.
 *
 * \param kvm Pointer to the current kvm_context
 * \param assigned_irq Parameters, like dev id, host irq, guest irq, etc
 */
int kvm_deassign_irq(kvm_context_t kvm,
                   struct kvm_assigned_irq *assigned_irq);
#endif
#endif

/*!
 * \brief Determines whether destroying memory regions is allowed
 *
 * KVM before 2.6.29 had a bug when destroying memory regions.
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_destroy_memory_region_works(kvm_context_t kvm);

#ifdef KVM_CAP_DEVICE_DEASSIGNMENT
/*!
 * \brief Notifies host kernel about a PCI device to be deassigned from a guest
 *
 * Used for hot remove PCI device, this function notifies the host
 * kernel about the deassigning of the physical PCI device from a guest.
 *
 * \param kvm Pointer to the current kvm_context
 * \param assigned_dev Parameters, like bus, devfn number, etc
 */
int kvm_deassign_pci_device(kvm_context_t kvm,
			    struct kvm_assigned_pci_dev *assigned_dev);
#endif

/*!
 * \brief Checks whether the generic irq routing capability is present
 *
 * Checks whether kvm can reroute interrupts among the various interrupt
 * controllers.
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_has_gsi_routing(kvm_context_t kvm);

/*!
 * \brief Determines the number of gsis that can be routed
 *
 * Returns the number of distinct gsis that can be routed by kvm.  This is
 * also the number of distinct routes (if a gsi has two routes, than another
 * gsi cannot be used...)
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_get_gsi_count(kvm_context_t kvm);

/*!
 * \brief Clears the temporary irq routing table
 *
 * Clears the temporary irq routing table.  Nothing is committed to the
 * running VM.
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_clear_gsi_routes(kvm_context_t kvm);

/*!
 * \brief Adds an irq route to the temporary irq routing table
 *
 * Adds an irq route to the temporary irq routing table.  Nothing is
 * committed to the running VM.
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_add_irq_route(kvm_context_t kvm, int gsi, int irqchip, int pin);

/*!
 * \brief Removes an irq route from the temporary irq routing table
 *
 * Adds an irq route to the temporary irq routing table.  Nothing is
 * committed to the running VM.
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_del_irq_route(kvm_context_t kvm, int gsi, int irqchip, int pin);

struct kvm_irq_routing_entry;
/*!
 * \brief Adds a routing entry to the temporary irq routing table
 *
 * Adds a filled routing entry to the temporary irq routing table. Nothing is
 * committed to the running VM.
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_add_routing_entry(kvm_context_t kvm,
                          struct kvm_irq_routing_entry* entry);

/*!
 * \brief Removes a routing from the temporary irq routing table
 *
 * Remove a routing to the temporary irq routing table.  Nothing is
 * committed to the running VM.
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_del_routing_entry(kvm_context_t kvm,
		          struct kvm_irq_routing_entry* entry);

/*!
 * \brief Updates a routing in the temporary irq routing table
 *
 * Update a routing in the temporary irq routing table
 * with a new value. entry type and GSI can not be changed.
 * Nothing is committed to the running VM.
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_update_routing_entry(kvm_context_t kvm,
                             struct kvm_irq_routing_entry* entry,
                             struct kvm_irq_routing_entry* newentry
);

/*!
 * \brief Commit the temporary irq routing table
 *
 * Commit the temporary irq routing table to the running VM.
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_commit_irq_routes(kvm_context_t kvm);

/*!
 * \brief Get unused GSI number for irq routing table
 *
 * Get unused GSI number for irq routing table
 *
 * \param kvm Pointer to the current kvm_context
 */
int kvm_get_irq_route_gsi(kvm_context_t kvm);

/*!
 * \brief Create a file descriptor for injecting interrupts
 *
 * Creates an eventfd based file-descriptor that maps to a specific GSI
 * in the guest.  eventfd compliant signaling (write() from userspace, or
 * eventfd_signal() from kernelspace) will cause the GSI to inject
 * itself into the guest at the next available window.
 *
 * \param kvm Pointer to the current kvm_context
 * \param gsi GSI to assign to this fd
 * \param flags reserved, must be zero
 */
int kvm_irqfd(kvm_context_t kvm, int gsi, int flags);

#ifdef KVM_CAP_DEVICE_MSIX
int kvm_assign_set_msix_nr(kvm_context_t kvm,
			   struct kvm_assigned_msix_nr *msix_nr);
int kvm_assign_set_msix_entry(kvm_context_t kvm,
                              struct kvm_assigned_msix_entry *entry);
#endif

uint32_t kvm_get_supported_cpuid(kvm_context_t kvm, uint32_t function, int reg);

#else /* !USE_KVM */

struct kvm_pit_state { };

#endif /* !USE_KVM */

#endif
