// parts taken from arch/x86/kvm/vmx.c

#define __KERNEL__

// needed for hacks
unsigned long __force_order;

struct vmcs {
  u32 revision_id;
  u32 abort;
  char data[0];
};

unsigned char vmcs[4096] __attribute__ ((aligned (4096)));
struct vmcs *this_vmcs = (struct vmcs *)vmcs;

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

static inline int cpu_vmx_enabled(void) {
  return read_cr4() & X86_CR4_VMXE;
}

#include <vm/pmap.h>

typedef struct pmap *pmap_t;
extern pmap_t kernel_pmap;
extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);

#define rdmsr(msr, low, high)                                   \
  do {                                                            \
    u64 __val = native_read_msr((msr));                     \
    (void)((low) = (u32)__val);                             \
    (void)((high) = (u32)(__val >> 32));                    \
  } while (0)

void hardware_enable() {
  u32 vmx_msr_low, vmx_msr_high;
  rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

  this_vmcs->revision_id = vmx_msr_low;
  u64 phys = pmap_find_phys(kernel_pmap, vmcs);
  printf("vmcs @ %p @ %p\n", vmcs, phys);

  write_cr4(read_cr4() | X86_CR4_VMXE);
  // should be per cpu?
  kvm_cpu_vmxon(phys << 12);
}

void hardware_disable() {
  if (cpu_vmx_enabled()) {
    kvm_cpu_vmxoff();
    write_cr4(read_cr4() & ~X86_CR4_VMXE);
  }
}

