#include <sys/proc.h>
#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <kern/task.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <i386/vmx.h>

static lck_grp_t  *mp_lock_grp;
static lck_attr_t *mp_lock_attr;
static lck_grp_attr_t *mp_lock_grp_attr;

#define LOAD_VMCS(vcpu) { lck_spin_lock(vcpu->ioctl_lock); vmcs_load(vcpu->vmcs); vcpu->vmcs_loaded = 1; }
#define RELEASE_VMCS(vcpu) { vmcs_clear(vcpu->vmcs); lck_spin_unlock(vcpu->ioctl_lock); vcpu->vmcs_loaded = 0; }

#define __ex(x) x
#define __pa vmx_paddr

#include <asm/uapi_vmx.h>
#include <linux/kvm.h>
#include "kvm_host.h"
#include "vmx_shims.h"       // vmcs allocation functions
#include "vmcs.h"            // vmcs read and write
#include "seg_base.h"        // functions for getting segment base
#include "vmx_segments.h"

// where is this include file?
extern "C" {
extern int cpu_number(void);
}

#define VCPU_SIZE (PAGE_SIZE*2)
#define KVM_PIO_PAGE_OFFSET 1

#define DEBUG printf

// return point from vmexit
extern const void* vmexit_handler;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

//#include "vmx.h"
//#include <linux/kvm_host.h>

#include <sys/kernel.h>
#include <kern/locks.h>
#include <signal.h>

#define IRQ_MAX 16

/* aggressively uniprocessor, one CREATE_VM = one processor */
struct vcpu {
  vmcs *vmcs;
  struct kvm_run *kvm_vcpu;

  unsigned long regs[NR_VCPU_REGS];
  unsigned long rflags;
  unsigned long cr2;
  struct dtr host_gdtr, host_idtr;
  unsigned short int host_ldtr;
  void *pio_data;

  unsigned long __launched;
  unsigned long fail;
  unsigned long host_rsp;
  int pending_io;

  unsigned long exit_qualification;
  int exit_instruction_len;
  unsigned long phys;

  int irq_level[IRQ_MAX];
  int pending_irq;

  struct kvm_cpuid_entry2 *cpuids;
  struct kvm_msr_entry *msrs;
  int cpuid_count;
  int msr_count;

  void *virtual_apic_page, *apic_access;

// using a spinlock here seems to fix the problem of the thread
//  being migrated to a different CPU while i'm working
  lck_spin_t *ioctl_lock;
  int vmcs_loaded;

  // store the physical addresses on the first page, and the virtual addresses on the second page
  unsigned long *pml4;
};

// TODO: shouldn't be global
struct vcpu *global_vcpu;

/* *********************** */
/* handle functions for different exit conditions */
/* *********************** */

static void skip_emulated_instruction(struct vcpu *vcpu) {
  vcpu->regs[VCPU_REGS_RIP] += vcpu->exit_instruction_len;
}

static int handle_io(struct vcpu *vcpu) {
  unsigned long exit_qualification = vcpu->exit_qualification;
  int in = (exit_qualification & 8) != 0;

  vcpu->kvm_vcpu->io.direction = in ? KVM_EXIT_IO_IN : KVM_EXIT_IO_OUT;
  vcpu->kvm_vcpu->io.size = (exit_qualification & 7) + 1;
  vcpu->kvm_vcpu->io.port = exit_qualification >> 16;
  vcpu->kvm_vcpu->io.count = 1;
  vcpu->kvm_vcpu->io.data_offset = KVM_PIO_PAGE_OFFSET * PAGE_SIZE;

  unsigned long val = 0;
  if (!in) {
    val = vcpu->regs[VCPU_REGS_RAX];
    unsigned int size = vcpu->kvm_vcpu->io.size * vcpu->kvm_vcpu->io.count;
    memcpy(vcpu->pio_data, &val, min(size, 8));
  } else {
    vcpu->pending_io = 1;
  }

  //printf("io 0x%X %d inter %x %x debug %lx %lx gla %lx\n", vcpu->kvm_vcpu->io.port, vcpu->kvm_vcpu->io.direction, inter, activity, debug, pending_debug, gla);
  //printf("io 0x%X %d data %lx\n", vcpu->kvm_vcpu->io.port, vcpu->kvm_vcpu->io.direction, val);

  vcpu->kvm_vcpu->exit_reason = KVM_EXIT_IO;
  //vcpu->kvm_vcpu->hw.hardware_exit_reason
  skip_emulated_instruction(vcpu);
  return 0;
}

static int handle_cpuid(struct vcpu *vcpu) {
  int i;
	u32 function, eax, ebx, ecx, edx;

	function = eax = vcpu->regs[VCPU_REGS_RAX];
	ecx = vcpu->regs[VCPU_REGS_RCX];

  int found = 0;

  for (i = 0; i < vcpu->cpuid_count; i++) {
    if (vcpu->cpuids[i].function == function) {
      eax = vcpu->cpuids[i].eax;
      ebx = vcpu->cpuids[i].ebx;
      ecx = vcpu->cpuids[i].ecx;
      edx = vcpu->cpuids[i].edx;
      found = 1;
      break;
    }
  }

  if (found == 0) {
    //printf("MISS cpuid function 0x%x index 0x%x\n", function, ecx);
    // lol emulate
    asm(
        "push %%rbx       \n"
        "cpuid             \n"
        "mov  %%rbx, %%rsi\n"
        "pop  %%rbx       \n"
      : "=a"   (eax),
        "=S"   (ebx),
        "=c"   (ecx),
        "=d"   (edx)
      : "a"    (eax),
        "S"    (ebx),
        "c"    (ecx),
        "d"    (edx));
  }

  // TODO: hack for FPU
  if (function == 1) edx |= 1;

	vcpu->regs[VCPU_REGS_RAX] = eax;
	vcpu->regs[VCPU_REGS_RBX] = ebx;
	vcpu->regs[VCPU_REGS_RCX] = ecx;
	vcpu->regs[VCPU_REGS_RDX] = edx;

  skip_emulated_instruction(vcpu);
  return 1;
}

static int handle_rdmsr(struct vcpu *vcpu) {
  printf("rdmsr 0x%lX\n", vcpu->regs[VCPU_REGS_RCX]);
  /*vcpu->regs[VCPU_REGS_RAX] = 0;
  vcpu->regs[VCPU_REGS_RDX] = 0;*/

  /*asm("rdmsr\n"
    : "=a"   (vcpu->regs[VCPU_REGS_RAX]),
      "=d"   (vcpu->regs[VCPU_REGS_RDX])
    : "c"    (vcpu->regs[VCPU_REGS_RCX]));*/

  //skip_emulated_instruction(vcpu);
  return 0;
}

static int handle_wrmsr(struct vcpu *vcpu) {
  printf("wrmsr 0x%lX\n", vcpu->regs[VCPU_REGS_RCX]);
  //skip_emulated_instruction(vcpu);
  return 0;
}

static int handle_ept_violation(struct vcpu *vcpu) {
  //u64 phys = vmcs_readl(GUEST_PHYSICAL_ADDRESS);
  printf("!!ept violation at %lx\n", vcpu->phys);
  //return 0;
  skip_emulated_instruction(vcpu);
  return 1;
}

static int handle_preemption_timer(struct vcpu *vcpu) {
  return 1;
  //return 0;
}

static int handle_external_interrupt(struct vcpu *vcpu) {
  // check for signal to process
  sigset_t tmp;
  sigfillset(&tmp);
  if (proc_issignal(proc_selfpid(), tmp)) {
    printf("got signal\n");
    return 0;
  }

  // should really handle it, this was the bugfix?
  return 1;
}

static int handle_apic_access(struct vcpu *vcpu) {
  printf("apic access: %lx\n", vcpu->exit_qualification);
  //return 0;
  // TODO: maybe actually do something here?
  skip_emulated_instruction(vcpu);
  return 1;
}

static int handle_interrupt_window(struct vcpu *vcpu) {
  return 1;
}

// 0xfed00000 = HPET
// 0xfee00000 = APIC

static int (*const kvm_vmx_exit_handlers[])(struct vcpu *vcpu) = {
  [EXIT_REASON_EXTERNAL_INTERRUPT]      = handle_external_interrupt,
	[EXIT_REASON_CPUID]                   = handle_cpuid,
  [EXIT_REASON_IO_INSTRUCTION]          = handle_io,
  [EXIT_REASON_MSR_READ]                = handle_rdmsr,
  [EXIT_REASON_MSR_WRITE]               = handle_wrmsr,
  [EXIT_REASON_EPT_VIOLATION]           = handle_ept_violation,
  [EXIT_REASON_PREEMPTION_TIMER]        = handle_preemption_timer,
  [EXIT_REASON_APIC_ACCESS]             = handle_apic_access,
  [EXIT_REASON_PENDING_INTERRUPT]       = handle_interrupt_window,
};

static const int kvm_vmx_max_exit_handlers = ARRAY_SIZE(kvm_vmx_exit_handlers);


/* *********************** */
/* ept functions */
/* *********************** */

static void ept_init(struct vcpu *vcpu) {
  // EPT allocation
	vcpu->pml4 = (unsigned long *)IOMallocAligned(PAGE_SIZE*2, PAGE_SIZE);
	bzero(vcpu->pml4, PAGE_SIZE*2);
}

#define PAGE_OFFSET 512
#define EPT_DEFAULTS (VMX_EPT_EXECUTABLE_MASK | VMX_EPT_WRITABLE_MASK | VMX_EPT_READABLE_MASK)

// could probably be managed by http://fxr.watson.org/fxr/source/osfmk/i386/pmap.h
static void ept_add_page(struct vcpu *vcpu, unsigned long virtual_address, unsigned long physical_address) {
  int pml4_idx = (virtual_address >> 39) & 0x1FF;
  int pdpt_idx = (virtual_address >> 30) & 0x1FF;
  int pd_idx = (virtual_address >> 21) & 0x1FF;
  int pt_idx = (virtual_address >> 12) & 0x1FF;
  unsigned long *pdpt, *pd, *pt;
  //printf("%p @ %d %d %d %d\n", virtual_address, pml4_idx, pdpt_idx, pd_idx, pt_idx);

  // allocate the pdpt in the pml4 if NULL
  pdpt = (unsigned long*)vcpu->pml4[PAGE_OFFSET + pml4_idx];
  if (pdpt == NULL) {
    pdpt = (unsigned long*)IOMallocAligned(PAGE_SIZE*2, PAGE_SIZE);
    bzero(pdpt, PAGE_SIZE*2);
    vcpu->pml4[PAGE_OFFSET + pml4_idx] = (unsigned long)pdpt;
    vcpu->pml4[pml4_idx] = __pa(pdpt) | EPT_DEFAULTS;
  }

  // allocate the pd in the pdpt
  pd = (unsigned long*)pdpt[PAGE_OFFSET + pdpt_idx];
  if (pd == NULL) {
    pd = (unsigned long*)IOMallocAligned(PAGE_SIZE*2, PAGE_SIZE);
    bzero(pd, PAGE_SIZE*2);
    pdpt[PAGE_OFFSET + pdpt_idx] = (unsigned long)pd;
    pdpt[pdpt_idx] = __pa(pd) | EPT_DEFAULTS;
  }

  // allocate the pt in the pd
  pt = (unsigned long*)pd[PAGE_OFFSET + pd_idx];
  if (pt == NULL) {
    pt = (unsigned long*)IOMallocAligned(PAGE_SIZE, PAGE_SIZE);
    bzero(pt, PAGE_SIZE);
    pd[PAGE_OFFSET + pd_idx] = (unsigned long)pt;
    pd[pd_idx] = __pa(pt) | EPT_DEFAULTS;
  }

  // set the entry in the page table
  pt[pt_idx] = physical_address | EPT_DEFAULTS;
}


/* *********************** */
/* init functions, require VMCS lock */
/* *********************** */

void init_host_values() {
  u16 selector;
  struct dtr gdtb, idtb;

  vmcs_writel(HOST_CR0, get_cr0()); 
  vmcs_writel(HOST_CR3, get_cr3_raw()); 
  vmcs_writel(HOST_CR4, get_cr4());

  asm ("movw %%cs, %%ax\n" : "=a"(selector));
  vmcs_write16(HOST_CS_SELECTOR, selector);
  vmcs_write16(HOST_SS_SELECTOR, get_ss());
  vmcs_write16(HOST_DS_SELECTOR, get_ds());
  vmcs_write16(HOST_ES_SELECTOR, get_es());
  vmcs_write16(HOST_FS_SELECTOR, get_fs());
  vmcs_write16(HOST_GS_SELECTOR, get_gs());
  vmcs_write16(HOST_TR_SELECTOR, get_tr()); 

  vmcs_writel(HOST_FS_BASE, rdmsr64(MSR_IA32_FS_BASE)); 
  vmcs_writel(HOST_GS_BASE, rdmsr64(MSR_IA32_GS_BASE));  // KERNEL_GS_BASE or GS_BASE?

  // HOST_TR_BASE?
  //printf("get_tr: %X %llx\n", get_tr(), segment_base(get_tr()));
  vmcs_writel(HOST_TR_BASE, segment_base(get_tr()));

  asm("sgdt %0\n" : :"m"(gdtb));
  vmcs_writel(HOST_GDTR_BASE, gdtb.base);

  asm("sidt %0\n" : :"m"(idtb));
  vmcs_writel(HOST_IDTR_BASE, idtb.base);

  vmcs_writel(HOST_IA32_SYSENTER_CS, rdmsr64(MSR_IA32_SYSENTER_CS));
  vmcs_writel(HOST_IA32_SYSENTER_ESP, rdmsr64(MSR_IA32_SYSENTER_ESP));
  vmcs_writel(HOST_IA32_SYSENTER_EIP, rdmsr64(MSR_IA32_SYSENTER_EIP));

  // PERF_GLOBAL_CTRL, PAT, and EFER are all disabled

  vmcs_writel(HOST_RIP, (unsigned long)&vmexit_handler);
  // HOST_RSP is set in run
}

static void vcpu_init(struct vcpu *vcpu) {
  vmcs_write32(EXCEPTION_BITMAP, 0);

  vmcs_writel(EPT_POINTER, __pa(vcpu->pml4) | (0x03 << 3));

  vcpu->virtual_apic_page = IOMallocAligned(PAGE_SIZE, PAGE_SIZE);
	bzero(vcpu->virtual_apic_page, PAGE_SIZE);
  vmcs_writel(VIRTUAL_APIC_PAGE_ADDR, __pa(vcpu->virtual_apic_page));

  vcpu->apic_access = IOMallocAligned(PAGE_SIZE, PAGE_SIZE);
	bzero(vcpu->apic_access, PAGE_SIZE);
  vmcs_writel(APIC_ACCESS_ADDR, __pa(vcpu->apic_access));

  // right?
  ept_add_page(vcpu, 0xfee00000, __pa(vcpu->apic_access));

  vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR | PIN_BASED_NMI_EXITING | PIN_BASED_EXT_INTR_MASK);
  vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, (CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR & ~(CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING)) |
    CPU_BASED_TPR_SHADOW | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_UNCOND_IO_EXITING | CPU_BASED_MOV_DR_EXITING);
  vmcs_write32(SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_UNRESTRICTED_GUEST | SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES);

  // better not include PAT, EFER, or PERF_GLOBAL
  vmcs_write32(VM_EXIT_CONTROLS, VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR | VM_EXIT_HOST_ADDR_SPACE_SIZE);
  vmcs_write32(VM_ENTRY_CONTROLS, VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR);

  vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
  vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);
  vmcs_write32(CR3_TARGET_COUNT, 0);  // 0 is less than 4
  
  // because these are 0 we don't need addresses
  vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
  vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
  vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);

  // VMCS shadowing isn't set, from 24.4
  vmcs_write64(VMCS_LINK_POINTER, ~0LL);
  vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

  vmcs_write64(VM_EXIT_MSR_STORE_ADDR, ~0LL);
  vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, ~0LL);
  vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, ~0LL);
  //vmcs_write64(EPT_POINTER, ~0LL);

  vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
  vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 0);
  vmcs_write32(TPR_THRESHOLD, 0);

  vmcs_write64(CR0_GUEST_HOST_MASK, 0);
  vmcs_write64(CR4_GUEST_HOST_MASK, 0);

  vmcs_write64(CR0_READ_SHADOW, 0);
  vmcs_write64(CR4_READ_SHADOW, 0);

  vmcs_write64(CR3_TARGET_VALUE0, 0);
  vmcs_write64(CR3_TARGET_VALUE1, 0);
  vmcs_write64(CR3_TARGET_VALUE2, 0);
  vmcs_write64(CR3_TARGET_VALUE3, 0);

  vmcs_write64(GUEST_PENDING_DBG_EXCEPTIONS, 0);

  vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0); 
  vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE); 

  vmcs_writel(VMX_PREEMPTION_TIMER_VALUE, 0);

  vmcs_writel(GUEST_SYSENTER_CS, rdmsr64(MSR_IA32_SYSENTER_CS));
  vmcs_writel(GUEST_SYSENTER_ESP, rdmsr64(MSR_IA32_SYSENTER_ESP));
  vmcs_writel(GUEST_SYSENTER_EIP, rdmsr64(MSR_IA32_SYSENTER_EIP));
}


/* *********************** */
/* device functions */
/* *********************** */

static int kvm_dev_open(dev_t Dev, int fFlags, int fDevType, struct proc *pProcess) {
  return 0;
}

static int kvm_dev_close(dev_t Dev, int fFlags, int fDevType, struct proc *pProcess) {
  return 0;
}

void kvm_show_regs(struct vcpu *vcpu) {
  printf("%8x: eax %08lx ebx %08lx ecx %08lx edx %08lx esi %016lx edi %08lx esp %08lx ebp %08lx eip %08lx rflags %08lx cr0: %lx cr3: %lx cr4: %lx\n",
    vcpu->kvm_vcpu->exit_reason,
    vcpu->regs[VCPU_REGS_RAX], vcpu->regs[VCPU_REGS_RBX], vcpu->regs[VCPU_REGS_RCX], vcpu->regs[VCPU_REGS_RDX],
    vcpu->regs[VCPU_REGS_RSI], vcpu->regs[VCPU_REGS_RDI], vcpu->regs[VCPU_REGS_RSP], vcpu->regs[VCPU_REGS_RBP],
    vcpu->regs[VCPU_REGS_RIP], vcpu->rflags,
    vmcs_readl(GUEST_CR0),vmcs_readl(GUEST_CR3),vmcs_readl(GUEST_CR4));
}

int kvm_get_regs(struct vcpu *vcpu, struct kvm_regs* kvm_regs) {
  kvm_regs->rax = vcpu->regs[VCPU_REGS_RAX]; kvm_regs->rcx = vcpu->regs[VCPU_REGS_RCX];
  kvm_regs->rdx = vcpu->regs[VCPU_REGS_RDX]; kvm_regs->rbx = vcpu->regs[VCPU_REGS_RBX];
  kvm_regs->rsp = vcpu->regs[VCPU_REGS_RSP]; kvm_regs->rbp = vcpu->regs[VCPU_REGS_RBP];
  kvm_regs->rsi = vcpu->regs[VCPU_REGS_RSI]; kvm_regs->rdi = vcpu->regs[VCPU_REGS_RDI];

  kvm_regs->r8 = vcpu->regs[VCPU_REGS_R8]; kvm_regs->r9 = vcpu->regs[VCPU_REGS_R9];
  kvm_regs->r10 = vcpu->regs[VCPU_REGS_R10]; kvm_regs->r11 = vcpu->regs[VCPU_REGS_R11];
  kvm_regs->r12 = vcpu->regs[VCPU_REGS_R12]; kvm_regs->r13 = vcpu->regs[VCPU_REGS_R13];
  kvm_regs->r14 = vcpu->regs[VCPU_REGS_R14]; kvm_regs->r15 = vcpu->regs[VCPU_REGS_R15];

  kvm_regs->rip = vcpu->regs[VCPU_REGS_RIP];

  kvm_regs->rflags = vcpu->rflags;

  return 0;
}

int kvm_set_regs(struct vcpu *vcpu, struct kvm_regs* kvm_regs) {
  vcpu->regs[VCPU_REGS_RAX] = kvm_regs->rax; vcpu->regs[VCPU_REGS_RCX] = kvm_regs->rcx;
  vcpu->regs[VCPU_REGS_RDX] = kvm_regs->rdx; vcpu->regs[VCPU_REGS_RBX] = kvm_regs->rbx;
  vcpu->regs[VCPU_REGS_RSP] = kvm_regs->rsp; vcpu->regs[VCPU_REGS_RBP] = kvm_regs->rbp;
  vcpu->regs[VCPU_REGS_RSI] = kvm_regs->rsi; vcpu->regs[VCPU_REGS_RDI] = kvm_regs->rdi;

  vcpu->regs[VCPU_REGS_R8] = kvm_regs->r8; vcpu->regs[VCPU_REGS_R9] = kvm_regs->r9;
  vcpu->regs[VCPU_REGS_R10] = kvm_regs->r10; vcpu->regs[VCPU_REGS_R11] = kvm_regs->r11;
  vcpu->regs[VCPU_REGS_R12] = kvm_regs->r12; vcpu->regs[VCPU_REGS_R13] = kvm_regs->r13;
  vcpu->regs[VCPU_REGS_R14] = kvm_regs->r14; vcpu->regs[VCPU_REGS_R15] = kvm_regs->r15;

  vcpu->regs[VCPU_REGS_RIP] = kvm_regs->rip;
  printf("setting rip: %llx\n", kvm_regs->rip);

  vcpu->rflags = kvm_regs->rflags;
  return 0;
}

int kvm_get_sregs(struct vcpu *vcpu, struct kvm_sregs *sregs) {
  LOAD_VMCS(vcpu);

  sregs->cr0 = vmcs_readl(GUEST_CR0);
  sregs->cr3 = vmcs_readl(GUEST_CR3);
  sregs->cr4 = vmcs_readl(GUEST_CR4);

  // guest segment registers
	kvm_get_segment(vcpu, &sregs->cs, VCPU_SREG_CS);
	kvm_get_segment(vcpu, &sregs->ss, VCPU_SREG_SS);
	kvm_get_segment(vcpu, &sregs->ds, VCPU_SREG_DS);
	kvm_get_segment(vcpu, &sregs->es, VCPU_SREG_ES);
	kvm_get_segment(vcpu, &sregs->fs, VCPU_SREG_FS);
	kvm_get_segment(vcpu, &sregs->gs, VCPU_SREG_GS);
	kvm_get_segment(vcpu, &sregs->tr, VCPU_SREG_TR);
	kvm_get_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

  // idtr and gdtr
  sregs->idt.limit = vmcs_read32(GUEST_IDTR_LIMIT);
  sregs->idt.base = vmcs_readl(GUEST_IDTR_BASE);
  sregs->gdt.limit = vmcs_read32(GUEST_GDTR_LIMIT);
  sregs->gdt.base = vmcs_readl(GUEST_GDTR_BASE);

  sregs->efer = vmcs_readl(GUEST_IA32_EFER);
  //sregs->apic_base = vmcs_readl(VIRTUAL_APIC_PAGE_ADDR);

  RELEASE_VMCS(vcpu);

  return 0;
}

int kvm_set_sregs(struct vcpu *vcpu, struct kvm_sregs *sregs) {
  LOAD_VMCS(vcpu);
  //return 0;

  // should check this values?
  /*printf("cr0 %lx %lx\n", sregs->cr0, vmcs_readl(GUEST_CR0));
  printf("cr3 %lx %lx\n", sregs->cr3, vmcs_readl(GUEST_CR3));
  printf("cr4 %lx %lx\n", sregs->cr4, vmcs_readl(GUEST_CR4));*/

  vmcs_writel(GUEST_CR0, sregs->cr0 | 0x20);
  vmcs_writel(GUEST_CR3, sregs->cr3);
  vmcs_writel(GUEST_CR4, sregs->cr4 | (1<<13));

  // sysenter msrs?

  // guest segment registers
	kvm_set_segment(vcpu, &sregs->cs, VCPU_SREG_CS);
	kvm_set_segment(vcpu, &sregs->ss, VCPU_SREG_SS);
	kvm_set_segment(vcpu, &sregs->ds, VCPU_SREG_DS);
	kvm_set_segment(vcpu, &sregs->es, VCPU_SREG_ES);
	kvm_set_segment(vcpu, &sregs->fs, VCPU_SREG_FS);
	kvm_set_segment(vcpu, &sregs->gs, VCPU_SREG_GS);
	kvm_set_segment(vcpu, &sregs->tr, VCPU_SREG_TR);
	kvm_set_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

  // idtr and gdtr
  vmcs_write32(GUEST_IDTR_LIMIT, sregs->idt.limit);
  vmcs_writel(GUEST_IDTR_BASE, sregs->idt.base);
  vmcs_write32(GUEST_GDTR_LIMIT, sregs->gdt.limit);
  vmcs_writel(GUEST_GDTR_BASE, sregs->gdt.base);

  vmcs_writel(GUEST_IA32_EFER, sregs->efer);
  RELEASE_VMCS(vcpu);

  printf("apic base: %llx\n", sregs->apic_base);
  //vmcs_writel(VIRTUAL_APIC_PAGE_ADDR, sregs->apic_base);
	return 0;
}

void kvm_run(struct vcpu *vcpu) {
  // all the pages go bye bye?
  __invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);

  // load the backing store
  vmcs_writel(GUEST_RFLAGS, vcpu->rflags);
  vmcs_writel(GUEST_RSP, vcpu->regs[VCPU_REGS_RSP]);
  vmcs_writel(GUEST_RIP, vcpu->regs[VCPU_REGS_RIP]);

  // TODO: i made this value up
  //vmcs_writel(VMX_PREEMPTION_TIMER_VALUE, 0x10000);

  asm volatile ("cli\n\t");
  init_host_values();

	asm(
    //"call _init_host_values\n\t"

		/* Store host registers */
		"push %%rdx\n\tpush %%rbp\n\t"
		"push %%rcx \n\t" /* placeholder for guest rcx */
		"push %%rcx \n\t"

    "sgdt %c[gdtr](%0)\n\t"
    "sidt %c[idtr](%0)\n\t"
    "sldt %c[ldtr](%0)\n\t"

		"mov %%rsp, %c[host_rsp](%0) \n\t"
		__ex(ASM_VMX_VMWRITE_RSP_RDX) "\n\t"
		"1: \n\t"
		/* Reload cr2 if changed */
		"mov %c[cr2](%0), %%rax \n\t"
		"mov %%cr2, %%rdx \n\t"
		"cmp %%rax, %%rdx \n\t"
		"je 2f \n\t"
		"mov %%rax, %%cr2 \n\t"
		"2: \n\t"
		/* Check if vmlaunch of vmresume is needed */
		"cmpl $0, %c[launched](%0) \n\t"
		/* Load guest registers.  Don't clobber flags. */
		"mov %c[rax](%0), %%rax \n\t"
		"mov %c[rbx](%0), %%rbx \n\t"
		"mov %c[rdx](%0), %%rdx \n\t"
		"mov %c[rsi](%0), %%rsi \n\t"
		"mov %c[rdi](%0), %%rdi \n\t"
		"mov %c[rbp](%0), %%rbp \n\t"
		"mov %c[r8](%0),  %%r8  \n\t"
		"mov %c[r9](%0),  %%r9  \n\t"
		"mov %c[r10](%0), %%r10 \n\t"
		"mov %c[r11](%0), %%r11 \n\t"
		"mov %c[r12](%0), %%r12 \n\t"
		"mov %c[r13](%0), %%r13 \n\t"
		"mov %c[r14](%0), %%r14 \n\t"
		"mov %c[r15](%0), %%r15 \n\t"
		"mov %c[rcx](%0), %%rcx \n\t" /* kills %0 (ecx) */

		/* Enter guest mode */
		"jne 1f \n\t"
		__ex(ASM_VMX_VMLAUNCH) "\n\t"
		"jmp 2f \n\t"
		"1:\n"
    __ex(ASM_VMX_VMRESUME) "\n\t"
		"2:\n"
		/* Save guest registers, load host registers, keep flags */
    ".global _vmexit_handler\n\t"
    "_vmexit_handler:\n\t"
    "nop\n\t"
    "nop\n\t"
		"mov %0, %c[wordsize](%%rsp) \n\t"
		"pop %0 \n\t"
		"mov %%rax, %c[rax](%0) \n\t"
		"mov %%rbx, %c[rbx](%0) \n\t"
		"pop %c[rcx](%0) \n\t"
		"mov %%rdx, %c[rdx](%0) \n\t"
		"mov %%rsi, %c[rsi](%0) \n\t"
		"mov %%rdi, %c[rdi](%0) \n\t"
		"mov %%rbp, %c[rbp](%0) \n\t"
		"mov %%r8,  %c[r8](%0) \n\t"
		"mov %%r9,  %c[r9](%0) \n\t"
		"mov %%r10, %c[r10](%0) \n\t"
		"mov %%r11, %c[r11](%0) \n\t"
		"mov %%r12, %c[r12](%0) \n\t"
		"mov %%r13, %c[r13](%0) \n\t"
		"mov %%r14, %c[r14](%0) \n\t"
		"mov %%r15, %c[r15](%0) \n\t"
		"mov %%cr2, %%rax   \n\t"
		"mov %%rax, %c[cr2](%0) \n\t"

		"pop  %%rbp\n\t pop  %%rdx \n\t"
		"setbe %c[fail](%0) \n\t"
    /* my turn */

    "lldt %c[ldtr](%0)\n\t"
    "lidt %c[idtr](%0)\n\t"
    "lgdt %c[gdtr](%0)\n\t"


	      : : "c"(vcpu), "d"((unsigned long)HOST_RSP),
		[launched]"i"(offsetof(struct vcpu, __launched)),
		[fail]"i"(offsetof(struct vcpu, fail)),
		[host_rsp]"i"(offsetof(struct vcpu, host_rsp)),
		[rax]"i"(offsetof(struct vcpu, regs[VCPU_REGS_RAX])),
		[rbx]"i"(offsetof(struct vcpu, regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct vcpu, regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct vcpu, regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct vcpu, regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct vcpu, regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct vcpu, regs[VCPU_REGS_RBP])),
		[r8]"i"(offsetof(struct vcpu, regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct vcpu, regs[VCPU_REGS_R9])),
		[r10]"i"(offsetof(struct vcpu, regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct vcpu, regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct vcpu, regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct vcpu, regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct vcpu, regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct vcpu, regs[VCPU_REGS_R15])),
		[cr2]"i"(offsetof(struct vcpu, cr2)),
		[idtr]"i"(offsetof(struct vcpu, host_idtr)),
		[gdtr]"i"(offsetof(struct vcpu, host_gdtr)),
    [ldtr]"i"(offsetof(struct vcpu, host_ldtr)),
		[wordsize]"i"(sizeof(ulong))
	      : "cc", "memory"
		, "rax", "rbx", "rdi", "rsi"
    // "rsp", "rbp", "rcx", "rdx"
		, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
  );
  //vcpu->__launched = 1;
  //vcpu->__launched = 0;

  // read them?
  vcpu->rflags = vmcs_readl(GUEST_RFLAGS);
  vcpu->regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
  vcpu->regs[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
}





static int kvm_set_user_memory_region(struct vcpu *vcpu, struct kvm_userspace_memory_region *mr) {
  // check alignment
  unsigned long off;
  IOMemoryDescriptor *md = IOMemoryDescriptor::withAddressRange(mr->userspace_addr, mr->memory_size, kIODirectionInOut, current_task());
  DEBUG("MAPPING 0x%llx WITH FLAGS %x SLOT %d IN GUEST AT 0x%llx-0x%llx\n", mr->userspace_addr, mr->flags, mr->slot, mr->guest_phys_addr, mr->guest_phys_addr + mr->memory_size);
  // wire in the memory
  IOReturn ret = md->prepare(kIODirectionInOut);
  if (ret != 0) {
    printf("wire pages failed :(\n");
    return EINVAL;
  }

  // TODO: support KVM_MEM_READONLY
  for (off = 0; off < mr->memory_size; off += PAGE_SIZE) {
    unsigned long va = mr->userspace_addr + off;
    addr64_t pa = md->getPhysicalSegment(off, NULL, kIOMemoryMapperNone);
    if (pa != 0) {
      ept_add_page(vcpu, mr->guest_phys_addr + off, pa);
    } else {
      printf("couldn't find vpage %lx\n", va);
      return EINVAL;
    }
  }

  return 0;
}

static int kvm_get_supported_cpuid(struct kvm_cpuid2 *cpuid) {
  // how do I copy the rest from user space if I only have a kernel space address?
  cpuid->nent = 0;
  return 0;
}

static int kvm_run_wrapper(struct vcpu *vcpu) {
  int cpun = cpu_number();
  int maxcont = 0;
  int cont = 1;
  unsigned int i;
  unsigned long val = 0;

  if (vcpu->pending_io) {
    unsigned int size = vcpu->kvm_vcpu->io.size * vcpu->kvm_vcpu->io.count;
    memcpy(&val, vcpu->pio_data, min(size, 8));
    vcpu->regs[VCPU_REGS_RAX] = val;
    vcpu->pending_io = 0;
  }


  unsigned long exit_reason = 0;
  unsigned long error, entry_error;
  vcpu->kvm_vcpu->exit_reason = 0;
  while (cont && (maxcont++) < 1000) {
    unsigned long intr_info = 0;

    if (exit_reason == EXIT_REASON_PENDING_INTERRUPT) {
    //if (vcpu->rflags & (1 << 9)) {
      // interrupt injection?
      for (i = 0; i < IRQ_MAX; i++) {
        if (vcpu->pending_irq & (1<<i)) {
          //printf("delivering IRQ %d rflags %lx\n", i, vcpu->rflags);
          // vm exits clear the valid bit, no need to do by hand
          intr_info = INTR_INFO_VALID_MASK | INTR_TYPE_EXT_INTR | (i+8);
          vcpu->pending_irq &= ~(1<<i);
          break;
        }
      }
    }

    LOAD_VMCS(vcpu);

    if (intr_info != 0) {
      vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info);
    }
    
    if (vcpu->pending_irq) {
      // set interrupt pending
      vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) | CPU_BASED_VIRTUAL_INTR_PENDING);
    } else {
      // clear interrupt pending
      vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) & ~CPU_BASED_VIRTUAL_INTR_PENDING);
    }

    //kvm_show_regs();
    // DISABLES INTERRUPTS!!!
    kvm_run(vcpu);

    //printf("%lx %lx\n", vcpu->idtr.base, vcpu->gdtr.base);
    //printf("vmcs: %lx\n", vcpu->vmcs);

    vcpu->exit_instruction_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
    vcpu->exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
    vcpu->phys = vmcs_readl(GUEST_PHYSICAL_ADDRESS);

    error = vmcs_read32(VM_INSTRUCTION_ERROR);
    entry_error = vmcs_read32(VM_ENTRY_EXCEPTION_ERROR_CODE);

    exit_reason = vmcs_read32(VM_EXIT_REASON);

    RELEASE_VMCS(vcpu);

    // interrupt gets delivered here
    asm volatile ("sti");

    if (exit_reason < kvm_vmx_max_exit_handlers && kvm_vmx_exit_handlers[exit_reason] != NULL) {
      cont = kvm_vmx_exit_handlers[exit_reason](vcpu);
    } else {
      cont = 0;
    }

    if (exit_reason != EXIT_REASON_IO_INSTRUCTION &&
        exit_reason != EXIT_REASON_PREEMPTION_TIMER &&
        exit_reason != EXIT_REASON_EXTERNAL_INTERRUPT &&
        exit_reason != EXIT_REASON_PENDING_INTERRUPT &&
        exit_reason != EXIT_REASON_CPUID) {
      printf("%3d -(%d,%d)- entry %ld exit %ld(0x%lx) error %ld phys 0x%lx    rip %lx  rsp %lx\n",
        maxcont, cpun, cpu_number(),
        entry_error, exit_reason, exit_reason, error, vcpu->phys, vcpu->regs[VCPU_REGS_RIP], vcpu->regs[VCPU_REGS_RSP]);
    }

    if (error != 0) break;
  }
  if (cont == 1) {
    printf("EXIT FROM TIMEOUT %lx\n", exit_reason);
  }
  //kvm_show_regs();

  return 0;
}

static int kvm_set_msrs(struct vcpu *vcpu, struct kvm_msrs *msrs) {
  //int i;
  printf("got %d msrs at %p\n", msrs->nmsrs, msrs);
  vcpu->msr_count = msrs->nmsrs;
  vcpu->msrs = (struct kvm_msr_entry *)IOMalloc(vcpu->msr_count * sizeof(struct kvm_msr_entry));
  copyin(msrs->self + offsetof(struct kvm_msrs, entries), vcpu->msrs, vcpu->msr_count * sizeof(struct kvm_msr_entry));

  /*for (i = 0; i < vcpu->msr_count; i++) {
    printf("  got msr 0x%x = 0x%lx\n", vcpu->msrs[i].index, vcpu->msrs[i].data);
  }*/
  return 0;
}

static int kvm_set_cpuid2(struct vcpu *vcpu, struct kvm_cpuid2 *cpuid2) {
  //int i;
  printf("got %d cpuids at %p\n", cpuid2->nent, cpuid2);

  vcpu->cpuid_count = cpuid2->nent;
  vcpu->cpuids = (struct kvm_cpuid_entry2*)IOMalloc(vcpu->cpuid_count * sizeof(struct kvm_cpuid_entry2));
  copyin(cpuid2->self + offsetof(struct kvm_cpuid2, entries), vcpu->cpuids, vcpu->cpuid_count * sizeof(struct kvm_cpuid_entry2));

  /*for (i = 0; i < vcpu->cpuid_count; i++) {
    printf("  got cpuid 0x%x 0x%x\n", vcpu->cpuids[i].function, vcpu->cpuids[i].index);
  }*/
  return 0;
}

static int kvm_irq_line(struct vcpu *vcpu, struct kvm_irq_level *irq) {
  //if (irq->level != 0) printf("irq %d = %d\n", irq->irq, irq->level);
  if (irq->irq < IRQ_MAX) {
    if (vcpu->irq_level[irq->irq] == 0 && irq->level == 1) {
      // trigger on rising edge?
      vcpu->pending_irq |= 1 << irq->irq;
    }
    vcpu->irq_level[irq->irq] = irq->level;
  }
  return 0;
}

lck_mtx_t *big_ioctl_lock = NULL;

static int kvm_dev_ioctl(dev_t Dev, u_long iCmd, caddr_t pData, int fFlags, struct proc *pProcess) {
  int ret = EOPNOTSUPP;
  int test;
  struct vcpu *vcpu = global_vcpu;

  iCmd &= 0xFFFFFFFF;
  IOMemoryDescriptor *md;
  IOMemoryMap *mm;

  lck_mtx_lock(big_ioctl_lock);

  // saw 0x14 once?
  if (pData == NULL || (u64)pData < PAGE_SIZE) goto fail;

  /* kvm_ioctl */
  switch (iCmd) {
    case KVM_GET_API_VERSION:
      ret = KVM_API_VERSION;
      break;
    case KVM_CREATE_VM:
      DEBUG("create vm\n");
      vcpu = (struct vcpu *)IOMalloc(sizeof(struct vcpu));
      bzero(vcpu, sizeof(struct vcpu));

      // TODO: no global!
      global_vcpu = vcpu;

      // assign an fd, must be a system fd
      // can't do this
      ept_init(vcpu);

      // init the one CPU as well
      vcpu->vmcs = allocate_vmcs();
      vcpu->kvm_vcpu = (struct kvm_run *)IOMallocAligned(VCPU_SIZE, PAGE_SIZE);
      vcpu->pio_data = ((unsigned char *)vcpu->kvm_vcpu + KVM_PIO_PAGE_OFFSET * PAGE_SIZE);
      vcpu->pending_io = 0;
      vcpu->ioctl_lock = lck_spin_alloc_init(mp_lock_grp, mp_lock_attr);
      bzero(vcpu->kvm_vcpu, VCPU_SIZE);
      vmcs_clear(vcpu->vmcs);

      LOAD_VMCS(vcpu);
      vcpu_init(vcpu);
      RELEASE_VMCS(vcpu);

      ret = 0;
      break;
    case KVM_GET_VCPU_MMAP_SIZE:
      ret = VCPU_SIZE;
      break;
    case KVM_CHECK_EXTENSION:
      test = *(int*)pData;
      if (test == KVM_CAP_USER_MEMORY || test == KVM_CAP_DESTROY_MEMORY_REGION_WORKS) {
        ret = 1;
      } else if (test == KVM_CAP_SET_TSS_ADDR || test == KVM_CAP_EXT_CPUID || test == KVM_CAP_MP_STATE) {
        ret = 1;
      } else if (test == KVM_CAP_SYNC_MMU) {
        ret = 1;
      } else {
        // most extensions aren't available
        ret = 0;
      }
      break;
    // unimplemented
    case KVM_GET_MSR_INDEX_LIST:
      // struct kvm_msr_list
      ret = 0;
      break;
    case KVM_GET_SUPPORTED_CPUID:
      ret = kvm_get_supported_cpuid((struct kvm_cpuid2 *)pData);
      break;
    default:
      break;
  }

  if (vcpu == NULL) goto fail;

  /* kvm_vm_ioctl */
  switch (iCmd) {
    case KVM_CREATE_VCPU:
      DEBUG("create vcpu\n");
      // does nothing since we only support one CPU
      ret = 0;
      break;
    case KVM_SET_USER_MEMORY_REGION:
      ret = kvm_set_user_memory_region(vcpu, (struct kvm_userspace_memory_region*)pData);
      break;
    case KVM_SET_IDENTITY_MAP_ADDR:
      ret = 0;
      break;
    case KVM_SET_TSS_ADDR:
      ret = 0;
      break;
    /* interrupts! */
    case KVM_CREATE_IRQCHIP:
      ret = 0;
      break;
    case KVM_IRQ_LINE:
      ret = kvm_irq_line(vcpu, (struct kvm_irq_level *)pData);
      break;
    /* PIT */
    case KVM_CREATE_PIT:
      printf("KVM_CREATE_PIT\n");
      ret = 0;
      break;
    case KVM_GET_PIT:
      //printf("KVM_GET_PIT\n");
      ret = 0;
      break;
    case KVM_SET_PIT:
      //printf("KVM_SET_PIT\n");
      ret = 0;
      break;
    /* FPU */
    case KVM_SET_FPU:
      ret = 0;
      break;
    /* MMIO */
    /*case KVM_REGISTER_COALESCED_MMIO:
      printf("KVM_REGISTER_COALESCED_MMIO\n");
      break;*/
    default:
      break;
  }

  /* kvm_vcpu_ioctl */
  switch (iCmd) {
    case KVM_GET_REGS:
      ret = kvm_get_regs(vcpu, (struct kvm_regs *)pData);
      break;
    case KVM_SET_REGS:
      ret = kvm_set_regs(vcpu, (struct kvm_regs *)pData);
      break;
    case KVM_GET_SREGS:
      ret = kvm_get_sregs(vcpu, (struct kvm_sregs *)pData);
      break;
    case KVM_SET_SREGS:
      ret = kvm_set_sregs(vcpu, (struct kvm_sregs *)pData);
      break;
    case KVM_RUN:
      ret = kvm_run_wrapper(vcpu);
      break;
    case KVM_MMAP_VCPU:
      md = IOMemoryDescriptor::withAddressRange((mach_vm_address_t)vcpu->kvm_vcpu, VCPU_SIZE, kIODirectionInOut, kernel_task);
      mm = md->createMappingInTask(current_task(), NULL, kIOMapAnywhere);
      //DEBUG("mmaped at %p %p\n", *(mach_vm_address_t *)pData, mm->getAddress());
      *(mach_vm_address_t *)pData = mm->getAddress();
      ret = 0;
      break;
    case KVM_SET_SIGNAL_MASK:
      // signals on kvm run?
      ret = 0;
      break;
    case KVM_SET_MSRS:
      ret = kvm_set_msrs(vcpu, (struct kvm_msrs *)pData);
      break;
    case KVM_SET_CPUID2:
      ret = kvm_set_cpuid2(vcpu, (struct kvm_cpuid2 *)pData);
      break;
    default:
      break;
  }

fail:
  if (ret == EOPNOTSUPP) {
    /* 0xa3, 0x8d, 0x99, 0x63 */
    /* KVM_GET_TSC_KHZ, KVM_SET_FPU, KVM_SET_MP_STATE, KVM_SET_IRQCHIP */
    printf("%d %p get ioctl %lX with pData %p return %d\n", cpu_number(), pProcess, iCmd, pData, ret);
  }
  lck_mtx_unlock(big_ioctl_lock);
  return ret;
}



static struct cdevsw kvm_functions = {
  /*.d_open     = */kvm_dev_open,
  /*.d_close    = */kvm_dev_close,
  /*.d_read     = */eno_rdwrt,
  /*.d_write    = */eno_rdwrt,
  /*.d_ioctl    = */kvm_dev_ioctl,
  /*.d_stop     = */eno_stop,
  /*.d_reset    = */eno_reset,
  /*.d_ttys     = */NULL,
  /*.d_select   = */eno_select,
// OS X does not support memory-mapped devices through the mmap() function. Fuckers.
  /*.d_mmap     = */eno_mmap,
  /*.d_strategy = */eno_strat,
  /*.d_getc     = */eno_getc,
  /*.d_putc     = */eno_putc,
  /*.d_type     = */0
};

static int g_kvm_major;
static void *g_kvm_ctl;

 
kern_return_t MyKextStart(kmod_info_t *ki, void *d) {
  int ret;
  printf("MyKext has started.\n");


  big_ioctl_lock = (lck_mtx_t *)IOLockAlloc();

  mp_lock_grp_attr = lck_grp_attr_alloc_init();
  mp_lock_grp = lck_grp_alloc_init("vmx", mp_lock_grp_attr);
  mp_lock_attr = lck_attr_alloc_init();

  ret = host_vmxon(FALSE);
  printf("host_vmxon: %d\n", ret);

  if (ret != 0) {
    return KMOD_RETURN_FAILURE;
  }

  g_kvm_major = cdevsw_add(-1, &kvm_functions);
  if (g_kvm_major < 0) {
    return KMOD_RETURN_FAILURE;
  }

  // insecure for testing!
  g_kvm_ctl = devfs_make_node(makedev(g_kvm_major, 0), DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666, "kvm");

  return KMOD_RETURN_SUCCESS;
}
 
kern_return_t MyKextStop(kmod_info_t *ki, void *d) {
  printf("MyKext has stopped.\n");

  devfs_remove(g_kvm_ctl);
  cdevsw_remove(g_kvm_major, &kvm_functions);

  host_vmxoff();

  return KERN_SUCCESS;
}

extern "C" {
extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);
}

KMOD_EXPLICIT_DECL(com.geohot.virt.kvm, "1.0.0d1", _start, _stop)
kmod_start_func_t *_realmain = MyKextStart;
kmod_stop_func_t *_antimain = MyKextStop;
int _kext_apple_cc = __APPLE_CC__;

