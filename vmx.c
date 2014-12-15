// parts taken from arch/x86/kvm/vmx.c

#define __KERNEL__

// needed for hacks
unsigned long __force_order;

unsigned char vmcs[4096] __attribute__ ((aligned (4096)));

#include <asm/vmx.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>

static void kvm_cpu_vmxon(u64 addr) {
	asm volatile (ASM_VMX_VMXON_RAX
			: : "a"(&addr), "m"(addr)
			: "memory", "cc");
}

static void kvm_cpu_vmxoff(void) {
	asm volatile (ASM_VMX_VMXOFF : : : "cc");
}

void hardware_enable() {
  write_cr4(read_cr4() | X86_CR4_VMXE);
  // should be per cpu?
  kvm_cpu_vmxon((u64)vmcs);
}

void hardware_disable() {
  kvm_cpu_vmxoff();
	write_cr4(read_cr4() & ~X86_CR4_VMXE);
}

