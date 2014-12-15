// parts taken from arch/x86/kvm/vmx.c

#define __KERNEL__

//#include <asm/msr-index.h>

// needed for hacks
unsigned long __force_order;

//#include <asm/vmx.h>
//#include <asm/processor-flags.h>
//#include <asm/special_insns.h>

#include "vmx_shims.h"
#include "vmx.h"


vmcs *allocate_vmcs() {
  u64 vmx_msr = rdmsr64(MSR_IA32_VMX_BASIC);
  printf("msr %llx\n", vmx_msr);

  vmcs *ret;
  ret = vmx_pcalloc();
  ret->revision_id = vmx_msr & 0xFFFFFFFF;

  return ret;
}

