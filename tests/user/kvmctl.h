/** \file kvmctl.h
 * libkvm API
 */

#ifndef KVMCTL_H
#define KVMCTL_H

#ifndef __user
#define __user /* temporary, until installed via make headers_install */
#endif

#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <stdint.h>
#include <signal.h>

struct kvm_context;

typedef struct kvm_context *kvm_context_t;

/*!
 * \brief KVM callbacks structure
 *
 * This structure holds pointers to various functions that KVM will call
 * when it encounters something that cannot be virtualized, such as
 * accessing hardware devices via MMIO or regular IO.
 */
struct kvm_callbacks {
	/// For 8bit IO reads from the guest (Usually when executing 'inb')
    int (*inb)(void *opaque, uint16_t addr, uint8_t *data);
	/// For 16bit IO reads from the guest (Usually when executing 'inw')
    int (*inw)(void *opaque, uint16_t addr, uint16_t *data);
	/// For 32bit IO reads from the guest (Usually when executing 'inl')
    int (*inl)(void *opaque, uint16_t addr, uint32_t *data);
	/// For 8bit IO writes from the guest (Usually when executing 'outb')
    int (*outb)(void *opaque, uint16_t addr, uint8_t data);
	/// For 16bit IO writes from the guest (Usually when executing 'outw')
    int (*outw)(void *opaque, uint16_t addr, uint16_t data);
	/// For 32bit IO writes from the guest (Usually when executing 'outl')
    int (*outl)(void *opaque, uint16_t addr, uint32_t data);
	/// For 8bit memory reads from unmapped memory (For MMIO devices)
    int (*readb)(void *opaque, uint64_t addr, uint8_t *data);
	/// For 16bit memory reads from unmapped memory (For MMIO devices)
    int (*readw)(void *opaque, uint64_t addr, uint16_t *data);
	/// For 32bit memory reads from unmapped memory (For MMIO devices)
    int (*readl)(void *opaque, uint64_t addr, uint32_t *data);
	/// For 64bit memory reads from unmapped memory (For MMIO devices)
    int (*readq)(void *opaque, uint64_t addr, uint64_t *data);
	/// For 8bit memory writes to unmapped memory (For MMIO devices)
    int (*writeb)(void *opaque, uint64_t addr, uint8_t data);
	/// For 16bit memory writes to unmapped memory (For MMIO devices)
    int (*writew)(void *opaque, uint64_t addr, uint16_t data);
	/// For 32bit memory writes to unmapped memory (For MMIO devices)
    int (*writel)(void *opaque, uint64_t addr, uint32_t data);
	/// For 64bit memory writes to unmapped memory (For MMIO devices)
    int (*writeq)(void *opaque, uint64_t addr, uint64_t data);
    int (*debug)(void *opaque, int vcpu);
	/*!
	 * \brief Called when the VCPU issues an 'hlt' instruction.
	 *
	 * Typically, you should yeild here to prevent 100% CPU utilization
	 * on the host CPU.
	 */
    int (*halt)(void *opaque, int vcpu);
    int (*shutdown)(void *opaque, int vcpu);
    int (*io_window)(void *opaque);
    int (*try_push_interrupts)(void *opaque);
    void (*post_kvm_run)(void *opaque, int vcpu);
    int (*pre_kvm_run)(void *opaque, int vcpu);
};

/*!
 * \brief Create new KVM context
 *
 * This creates a new kvm_context. A KVM context is a small area of data that
 * holds information about the KVM instance that gets created by this call.\n
 * This should always be your first call to KVM.
 *
 * \param callbacks Pointer to a valid kvm_callbacks structure
 * \param opaque Not used
 * \return NULL on failure
 */
kvm_context_t kvm_init(struct kvm_callbacks *callbacks,
		       void *opaque);

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
int kvm_create_vcpu(kvm_context_t kvm, int slot);

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
int kvm_run(kvm_context_t kvm, int vcpu);

/*!
 * \brief Get interrupt flag from on last exit to userspace
 *
 * This gets the CPU interrupt flag as it was on the last exit to userspace.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \return interrupt flag value (0 or 1)
 */
int kvm_get_interrupt_flag(kvm_context_t kvm, int vcpu);

/*!
 * \brief Get the value of the APIC_BASE msr as of last exit to userspace
 *
 * This gets the APIC_BASE msr as it was on the last exit to userspace.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \return APIC_BASE msr contents
 */
uint64_t kvm_get_apic_base(kvm_context_t kvm, int vcpu);

/*!
 * \brief Check if a vcpu is ready for interrupt injection
 *
 * This checks if vcpu interrupts are not masked by mov ss or sti.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \return boolean indicating interrupt injection readiness
 */
int kvm_is_ready_for_interrupt_injection(kvm_context_t kvm, int vcpu);

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
void kvm_set_cr8(kvm_context_t kvm, int vcpu, uint64_t cr8);

/*!
 * \brief Get cr8 for sync tpr in qemu apic emulation
 *
 * This is a getter for cr8, which used to sync with the tpr in qemu
 * apic emualtion.
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 */
__u64 kvm_get_cr8(kvm_context_t kvm, int vcpu);

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
int kvm_get_regs(kvm_context_t kvm, int vcpu, struct kvm_regs *regs);

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
int kvm_set_regs(kvm_context_t kvm, int vcpu, struct kvm_regs *regs);
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
int kvm_get_fpu(kvm_context_t kvm, int vcpu, struct kvm_fpu *fpu);

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
int kvm_set_fpu(kvm_context_t kvm, int vcpu, struct kvm_fpu *fpu);

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
int kvm_get_sregs(kvm_context_t kvm, int vcpu, struct kvm_sregs *regs);

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
int kvm_set_sregs(kvm_context_t kvm, int vcpu, struct kvm_sregs *regs);

struct kvm_msr_list *kvm_get_msr_list(kvm_context_t);
int kvm_get_msrs(kvm_context_t, int vcpu, struct kvm_msr_entry *msrs, int n);
int kvm_set_msrs(kvm_context_t, int vcpu, struct kvm_msr_entry *msrs, int n);

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
int kvm_inject_irq(kvm_context_t kvm, int vcpu, unsigned irq);

int kvm_guest_debug(kvm_context_t, int vcpu, struct kvm_debug_guest *dbg);

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
int kvm_setup_cpuid(kvm_context_t kvm, int vcpu, int nent,
		    struct kvm_cpuid_entry *entries);

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
int kvm_set_signal_mask(kvm_context_t kvm, int vcpu, const sigset_t *sigset);

/*!
 * \brief Dump all VCPU information
 *
 * This dumps \b all the information that KVM has about a virtual CPU, namely:
 * - GP Registers
 * - System registers (selectors, descriptors, etc)
 * - VMCS Data
 * - MSRS
 * - Pending interrupts
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should get dumped
 * \return 0 on success
 */
int kvm_dump_vcpu(kvm_context_t kvm, int vcpu);

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
void kvm_show_regs(kvm_context_t kvm, int vcpu);

void *kvm_create_phys_mem(kvm_context_t, unsigned long phys_start, 
			  unsigned long len, int slot, int log, int writable);
void kvm_destroy_phys_mem(kvm_context_t, unsigned long phys_start, 
			  unsigned long len, int slot);
int kvm_get_dirty_pages(kvm_context_t, int slot, void *buf);


/*!
 * \brief Create a memory alias
 *
 * Aliases a portion of physical memory to another portion.  If the guest
 * accesses the alias region, it will behave exactly as if it accessed
 * the target memory.
 */
int kvm_create_memory_alias(kvm_context_t, int slot,
			    uint64_t phys_start, uint64_t len,
			    uint64_t target_phys);

/*!
 * \brief Destroy a memory alias
 *
 * Removes an alias created with kvm_create_memory_alias().
 */
int kvm_destroy_memory_alias(kvm_context_t, int slot);

/*!
 * \brief Get a bitmap of guest ram pages which are allocated to the guest.
 *
 * \param kvm Pointer to the current kvm_context
 * \param slot Memory slot number
 * \param bitmap Long aligned address of a big enough bitmap (one bit per page)
 */
int kvm_get_mem_map(kvm_context_t kvm, int slot, void *bitmap);
int kvm_set_irq_level(kvm_context_t kvm, int irq, int level);

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

/*!
 * \brief Get in kernel local APIC for vcpu
 *
 * Save the local apic state including the timer of a virtual CPU
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should be accessed
 * \param s Local apic state of the specific virtual CPU
 */
int kvm_get_lapic(kvm_context_t kvm, int vcpu, struct kvm_lapic_state *s);

/*!
 * \brief Set in kernel local APIC for vcpu
 *
 * Restore the local apic state including the timer of a virtual CPU
 *
 * \param kvm Pointer to the current kvm_context
 * \param vcpu Which virtual CPU should be accessed
 * \param s Local apic state of the specific virtual CPU
 */
int kvm_set_lapic(kvm_context_t kvm, int vcpu, struct kvm_lapic_state *s);

#endif
