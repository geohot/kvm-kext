// parts taken from arch/x86/kvm/vmx.c

#define __KERNEL__
#define CONFIG_X86_64

//#include <asm/msr-index.h>

// needed for hacks
unsigned long __force_order;

#include <asm/asm.h>
//#include <asm/processor-flags.h>
//#include <asm/special_insns.h>

#include "kvm_host.h"

//#include <linux/kvm_host.h>

void vmx_vcpu_run(struct kvm_vcpu *vcpu) {
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long debugctlmsr;

	/* Record the guest's net vcpu time for enforced NMI injections. */
	/*if (unlikely(!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked))
		vmx->entry_time = ktime_get();*/

	/* Don't enter VMX if guest state is invalid, let the exit handler
	   start emulation until we arrive back to a valid state */
	if (vmx->emulation_required)
		return;

	if (test_bit(VCPU_REGS_RSP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);

	if (test_bit(VCPU_REGS_RIP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RIP, vcpu->arch.regs[VCPU_REGS_RIP]);

	/* When single-stepping over STI and MOV SS, we must clear the
	 * corresponding interruptibility bits in the guest state. Otherwise
	 * vmentry fails as it then expects bit 14 (BS) in pending debug
	 * exceptions being set, but that's not correct for the guest debugging
	 * case. */
	/*if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		vmx_set_interrupt_shadow(vcpu, 0);*/

	//atomic_switch_perf_msrs(vmx);
	//debugctlmsr = get_debugctlmsr();

	vmx->__launched = vmx->loaded_vmcs->launched;
	asm(
		/* Store host registers */
		"push %%" _ASM_DX "; push %%" _ASM_BP ";"
		"push %%" _ASM_CX " \n\t" /* placeholder for guest rcx */
		"push %%" _ASM_CX " \n\t"
		"cmp %%" _ASM_SP ", %c[host_rsp](%0) \n\t"
		"je 1f \n\t"
		"mov %%" _ASM_SP ", %c[host_rsp](%0) \n\t"
		__ex(ASM_VMX_VMWRITE_RSP_RDX) "\n\t"
		"1: \n\t"
		/* Reload cr2 if changed */
		"mov %c[cr2](%0), %%" _ASM_AX " \n\t"
		"mov %%cr2, %%" _ASM_DX " \n\t"
		"cmp %%" _ASM_AX ", %%" _ASM_DX " \n\t"
		"je 2f \n\t"
		"mov %%" _ASM_AX", %%cr2 \n\t"
		"2: \n\t"
		/* Check if vmlaunch of vmresume is needed */
		"cmpl $0, %c[launched](%0) \n\t"
		/* Load guest registers.  Don't clobber flags. */
		"mov %c[rax](%0), %%" _ASM_AX " \n\t"
		"mov %c[rbx](%0), %%" _ASM_BX " \n\t"
		"mov %c[rdx](%0), %%" _ASM_DX " \n\t"
		"mov %c[rsi](%0), %%" _ASM_SI " \n\t"
		"mov %c[rdi](%0), %%" _ASM_DI " \n\t"
		"mov %c[rbp](%0), %%" _ASM_BP " \n\t"
#ifdef CONFIG_X86_64
		"mov %c[r8](%0),  %%r8  \n\t"
		"mov %c[r9](%0),  %%r9  \n\t"
		"mov %c[r10](%0), %%r10 \n\t"
		"mov %c[r11](%0), %%r11 \n\t"
		"mov %c[r12](%0), %%r12 \n\t"
		"mov %c[r13](%0), %%r13 \n\t"
		"mov %c[r14](%0), %%r14 \n\t"
		"mov %c[r15](%0), %%r15 \n\t"
#endif
		"mov %c[rcx](%0), %%" _ASM_CX " \n\t" /* kills %0 (ecx) */

		/* Enter guest mode */
		"jne 1f \n\t"
		__ex(ASM_VMX_VMLAUNCH) "\n\t"
		"jmp 2f \n\t"
		"1: " __ex(ASM_VMX_VMRESUME) "\n\t"
		"2: "
		/* Save guest registers, load host registers, keep flags */
		"mov %0, %c[wordsize](%%" _ASM_SP ") \n\t"
		"pop %0 \n\t"
		"mov %%" _ASM_AX ", %c[rax](%0) \n\t"
		"mov %%" _ASM_BX ", %c[rbx](%0) \n\t"
		__ASM_SIZE(pop) " %c[rcx](%0) \n\t"
		"mov %%" _ASM_DX ", %c[rdx](%0) \n\t"
		"mov %%" _ASM_SI ", %c[rsi](%0) \n\t"
		"mov %%" _ASM_DI ", %c[rdi](%0) \n\t"
		"mov %%" _ASM_BP ", %c[rbp](%0) \n\t"
#ifdef CONFIG_X86_64
		"mov %%r8,  %c[r8](%0) \n\t"
		"mov %%r9,  %c[r9](%0) \n\t"
		"mov %%r10, %c[r10](%0) \n\t"
		"mov %%r11, %c[r11](%0) \n\t"
		"mov %%r12, %c[r12](%0) \n\t"
		"mov %%r13, %c[r13](%0) \n\t"
		"mov %%r14, %c[r14](%0) \n\t"
		"mov %%r15, %c[r15](%0) \n\t"
#endif
		"mov %%cr2, %%" _ASM_AX "   \n\t"
		"mov %%" _ASM_AX ", %c[cr2](%0) \n\t"

		"pop  %%" _ASM_BP "; pop  %%" _ASM_DX " \n\t"
		"setbe %c[fail](%0) \n\t"
		//".pushsection .rodata \n\t"
		".global vmx_return \n\t"
		"vmx_return: " _ASM_PTR " 2b \n\t"
		//".popsection"
	      : : "c"(vmx), "d"((unsigned long)HOST_RSP),
		[launched]"i"(offsetof(struct vcpu_vmx, __launched)),
		[fail]"i"(offsetof(struct vcpu_vmx, fail)),
		[host_rsp]"i"(offsetof(struct vcpu_vmx, host_rsp)),
		[rax]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RAX])),
		[rbx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBP])),
#ifdef CONFIG_X86_64
		[r8]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R9])),
		[r10]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R15])),
#endif
		[cr2]"i"(offsetof(struct vcpu_vmx, vcpu.arch.cr2)),
		[wordsize]"i"(sizeof(ulong))
	      : "cc", "memory"
#ifdef CONFIG_X86_64
		, "rax", "rbx", "rdi", "rsi"
		, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
#else
		, "eax", "ebx", "edi", "esi"
#endif
	      );

	/* MSR_IA32_DEBUGCTLMSR is zeroed on vmexit. Restore it if needed */
	/*if (debugctlmsr)
		update_debugctlmsr(debugctlmsr);*/

#ifndef CONFIG_X86_64
	/*
	 * The sysexit path does not restore ds/es, so we must set them to
	 * a reasonable value ourselves.
	 *
	 * We can't defer this to vmx_load_host_state() since that function
	 * may be executed in interrupt context, which saves and restore segments
	 * around it, nullifying its effect.
	 */
	loadsegment(ds, __USER_DS);
	loadsegment(es, __USER_DS);
#endif

	vcpu->arch.regs_avail = ~((1 << VCPU_REGS_RIP) | (1 << VCPU_REGS_RSP)
				  | (1 << VCPU_EXREG_RFLAGS)
				  | (1 << VCPU_EXREG_PDPTR)
				  | (1 << VCPU_EXREG_SEGMENTS)
				  | (1 << VCPU_EXREG_CR3));
	vcpu->arch.regs_dirty = 0;

	vmx->idt_vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);

	vmx->loaded_vmcs->launched = 1;

	vmx->exit_reason = vmcs_read32(VM_EXIT_REASON);
	//trace_kvm_exit(vmx->exit_reason, vcpu, KVM_ISA_VMX);

	/*
	 * the KVM_REQ_EVENT optimization bit is only on for one entry, and if
	 * we did not inject a still-pending event to L1 now because of
	 * nested_run_pending, we need to re-enable this bit.
	 */
	/*if (vmx->nested.nested_run_pending)
		kvm_make_request(KVM_REQ_EVENT, vcpu);

	vmx->nested.nested_run_pending = 0;*/

	/*vmx_complete_atomic_exit(vmx);
	vmx_recover_nmi_blocking(vmx);
	vmx_complete_interrupts(vmx);*/
}

