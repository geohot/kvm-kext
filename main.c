#include <sys/proc.h>
#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <i386/vmx.h>

extern "C" {
extern int  cpu_number(void);
}

#include <asm/uapi_vmx.h>

#include <linux/kvm.h>
#include "kvm_host.h"
//#include "kvm_cache_regs.h"

#include "vmx_shims.h"
#include "vmcs.h"

#define DEBUG printf

#define __ex(x) x
#define __pa vmx_paddr

extern const void* vmexit_handler;
extern const void* guest_entry_point;

static void vcpu_init();

#include "seg_base.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
//struct vcpu only_cpu;

//#include "vmx.h"
//#include <linux/kvm_host.h>


struct vcpu_arch {
  unsigned long regs[NR_VCPU_REGS];
  unsigned long rflags;
  unsigned long cr2;
  struct dtr host_gdtr, host_idtr;
  unsigned short int host_ldtr;
};

//#define NR_AUTOLOAD_MSRS 8

struct vcpu {
  vmcs *vmcs;
  struct kvm_run *kvm_vcpu;
  struct vcpu_arch arch;
  unsigned long __launched;
  unsigned long fail;
  unsigned long host_rsp;
} __vcpu;

static void skip_emulated_instruction(struct vcpu *vcpu) {
  vcpu->arch.regs[VCPU_REGS_RIP] += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
}

// TODO: check for RIP and things
u64 kvm_register_read(struct vcpu *vcpu, int reg) { return vcpu->arch.regs[reg]; }
void kvm_register_write(struct vcpu *vcpu, int reg, u64 value) { vcpu->arch.regs[reg] = value; }

static int handle_cpuid(struct vcpu *vcpu) {
	u32 function, eax, ebx, ecx, edx;

	function = eax = kvm_register_read(vcpu, VCPU_REGS_RAX);
	ecx = kvm_register_read(vcpu, VCPU_REGS_RCX);

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

	kvm_register_write(vcpu, VCPU_REGS_RAX, eax);
	kvm_register_write(vcpu, VCPU_REGS_RBX, ebx);
	kvm_register_write(vcpu, VCPU_REGS_RCX, ecx);
	kvm_register_write(vcpu, VCPU_REGS_RDX, edx);

  skip_emulated_instruction(vcpu);
  return 1;
}

static int (*const kvm_vmx_exit_handlers[])(struct vcpu *vcpu) = {
	[EXIT_REASON_CPUID]                   = handle_cpuid,
};

static const int kvm_vmx_max_exit_handlers = ARRAY_SIZE(kvm_vmx_exit_handlers);

void init_guest_values_from_host() {
  u64 value;
  u16 selector;
  struct dtr gdtb, idtb;

  vmcs_writel(GUEST_CR0, get_cr0()); 
  vmcs_writel(GUEST_CR3, get_cr3_raw()); 
  vmcs_writel(GUEST_CR4, get_cr4());

  u16 sel_value;
  u32 unusable_ar = 0x10000;
  u32 usable_ar; 
  vmcs_write32(GUEST_ES_LIMIT,0xFFFFFFFF); 
  vmcs_write32(GUEST_DS_LIMIT,0xFFFFFFFF); 
  vmcs_write32(GUEST_FS_LIMIT,0xFFFFFFFF); 
  vmcs_write32(GUEST_GS_LIMIT,0xFFFFFFFF); 
  vmcs_write32(GUEST_LDTR_LIMIT,0); 
  vmcs_write32(GUEST_SS_LIMIT,0xFFFFFFFF); 
  vmcs_write32(GUEST_CS_LIMIT,0xFFFFFFFF); 

  vmcs_write32(GUEST_ES_AR_BYTES, unusable_ar);
  vmcs_write32(GUEST_DS_AR_BYTES, unusable_ar);
  vmcs_write32(GUEST_FS_AR_BYTES, unusable_ar);
  vmcs_write32(GUEST_GS_AR_BYTES, unusable_ar);
  vmcs_write32(GUEST_LDTR_AR_BYTES, unusable_ar);

  asm ("movw %%cs, %%ax\n" : "=a"(sel_value));
  asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value)); 
  usable_ar = usable_ar>>8;
  usable_ar &= 0xf0ff; //clear bits 11:8 
  vmcs_write32(GUEST_CS_AR_BYTES, usable_ar);

  asm ("movw %%ss, %%ax\n" : "=a"(sel_value));
  asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value)); 
  usable_ar = usable_ar>>8;
  usable_ar &= 0xf0ff; //clear bits 11:8 
  vmcs_write32(GUEST_SS_AR_BYTES, usable_ar);

  asm ("movw %%cs, %%ax\n" : "=a"(selector));
  vmcs_write16(GUEST_CS_SELECTOR, selector);
  vmcs_write16(GUEST_SS_SELECTOR, get_ss());
  vmcs_write16(GUEST_DS_SELECTOR, get_ds());
  vmcs_write16(GUEST_ES_SELECTOR, get_es());
  vmcs_write16(GUEST_FS_SELECTOR, get_fs());
  vmcs_write16(GUEST_GS_SELECTOR, get_gs());
  vmcs_write16(GUEST_TR_SELECTOR, get_tr()); 

  asm("mov $0x40, %rax\n");
  asm("lsl %%eax, %%eax\n" :"=a"(value));
  vmcs_write32(GUEST_TR_LIMIT,value); 

  asm("str %%ax\n" : "=a"(sel_value));
  asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value)); 
  usable_ar = usable_ar>>8;
  vmcs_write32(GUEST_TR_AR_BYTES, usable_ar);

  vmcs_writel(GUEST_FS_BASE, rdmsr64(MSR_IA32_FS_BASE)); 
  vmcs_writel(GUEST_GS_BASE, rdmsr64(MSR_IA32_GS_BASE));  // KERNEL_GS_BASE or GS_BASE?

  // HOST_TR_BASE?
  //printf("get_tr: %X %llx\n", get_tr(), segment_base(get_tr()));
  vmcs_writel(GUEST_TR_BASE, segment_base(get_tr()));

  asm("sgdt %0\n" : :"m"(gdtb));
  vmcs_writel(GUEST_GDTR_BASE, gdtb.base);
  vmcs_writel(GUEST_GDTR_LIMIT, gdtb.limit);

  asm("sidt %0\n" : :"m"(idtb));
  vmcs_writel(GUEST_IDTR_BASE, gdtb.base);
  vmcs_writel(GUEST_IDTR_LIMIT, gdtb.limit);

  vmcs_writel(GUEST_SYSENTER_CS, rdmsr64(MSR_IA32_SYSENTER_CS));
  vmcs_writel(GUEST_SYSENTER_ESP, rdmsr64(MSR_IA32_SYSENTER_ESP));
  vmcs_writel(GUEST_SYSENTER_EIP, rdmsr64(MSR_IA32_SYSENTER_EIP));

  // PERF_GLOBAL_CTRL, PAT, and EFER are all disabled

  vmcs_writel(GUEST_RIP, (unsigned long)&guest_entry_point);
  vmcs_writel(GUEST_RSP, 0);
}

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


static void vmcs_load(struct vmcs *vmcs) {
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMPTRLD_RAX) "; setna %0"
			: "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
			: "cc", "memory");
	if (error)
		printf("kvm: vmptrld %p/%llx failed\n",
		       vmcs, phys_addr);
}


static void vmcs_clear(struct vmcs *vmcs) {
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMCLEAR_RAX) "; setna %0"
		      : "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
		      : "cc", "memory");
	if (error)
		printf("kvm: vmclear fail: %p/%llx\n",
		       vmcs, phys_addr);
}


struct vcpu *vcpu = &__vcpu;

static int kvm_dev_open(dev_t Dev, int fFlags, int fDevType, struct proc *pProcess) {
  return 0;
}

static int kvm_dev_close(dev_t Dev, int fFlags, int fDevType, struct proc *pProcess) {
  return 0;
}

static u32 vmx_segment_access_rights(struct kvm_segment *var) {
	u32 ar;

	if (var->unusable || !var->present)
		ar = 1 << 16;
	else {
		ar = var->type & 15;
		ar |= (var->s & 1) << 4;
		ar |= (var->dpl & 3) << 5;
		ar |= (var->present & 1) << 7;
		ar |= (var->avl & 1) << 12;
		ar |= (var->l & 1) << 13;
		ar |= (var->db & 1) << 14;
		ar |= (var->g & 1) << 15;
	}

	return ar;
}

#define VMX_SEGMENT_FIELD(seg)					\
	[VCPU_SREG_##seg] = {                                   \
		.selector = GUEST_##seg##_SELECTOR,		\
		.base = GUEST_##seg##_BASE,		   	\
		.limit = GUEST_##seg##_LIMIT,		   	\
		.ar_bytes = GUEST_##seg##_AR_BYTES,	   	\
	}

static const struct kvm_vmx_segment_field {
	unsigned selector;
	unsigned base;
	unsigned limit;
	unsigned ar_bytes;
} kvm_vmx_segment_fields[] = {
	VMX_SEGMENT_FIELD(CS),
	VMX_SEGMENT_FIELD(DS),
	VMX_SEGMENT_FIELD(ES),
	VMX_SEGMENT_FIELD(FS),
	VMX_SEGMENT_FIELD(GS),
	VMX_SEGMENT_FIELD(SS),
	VMX_SEGMENT_FIELD(TR),
	VMX_SEGMENT_FIELD(LDTR),
};

static void kvm_set_segment(struct vcpu *vcpu, struct kvm_segment *var, int seg) {
	const struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	vmcs_writel(sf->base, var->base);
	vmcs_write32(sf->limit, var->limit);
	vmcs_write16(sf->selector, var->selector);
	vmcs_write32(sf->ar_bytes, vmx_segment_access_rights(var));
}

void kvm_show_regs() {
  printf("%8lx: eax %08lx ebx %08lx ecx %08lx edx %08lx esi %016lx edi %08lx esp %08lx ebp %08lx eip %08lx rflags %08lx cr0: %lx cr3: %lx cr4: %lx\n",
    vcpu->kvm_vcpu->exit_reason,
    vcpu->arch.regs[VCPU_REGS_RAX], vcpu->arch.regs[VCPU_REGS_RBX], vcpu->arch.regs[VCPU_REGS_RCX], vcpu->arch.regs[VCPU_REGS_RDX],
    vcpu->arch.regs[VCPU_REGS_RSI], vcpu->arch.regs[VCPU_REGS_RDI], vcpu->arch.regs[VCPU_REGS_RSP], vcpu->arch.regs[VCPU_REGS_RBP],
    vcpu->arch.regs[VCPU_REGS_RIP], vcpu->arch.rflags,
    vmcs_readl(GUEST_CR0),vmcs_readl(GUEST_CR3),vmcs_readl(GUEST_CR4));
}

int kvm_get_regs(struct vcpu *vcpu, struct kvm_regs* kvm_regs) {
  kvm_regs->rax = vcpu->arch.regs[VCPU_REGS_RAX]; kvm_regs->rcx = vcpu->arch.regs[VCPU_REGS_RCX];
  kvm_regs->rdx = vcpu->arch.regs[VCPU_REGS_RDX]; kvm_regs->rbx = vcpu->arch.regs[VCPU_REGS_RBX];
  kvm_regs->rsp = vcpu->arch.regs[VCPU_REGS_RSP]; kvm_regs->rbp = vcpu->arch.regs[VCPU_REGS_RBP];
  kvm_regs->rsi = vcpu->arch.regs[VCPU_REGS_RSI]; kvm_regs->rdi = vcpu->arch.regs[VCPU_REGS_RDI];

  kvm_regs->r8 = vcpu->arch.regs[VCPU_REGS_R8]; kvm_regs->r9 = vcpu->arch.regs[VCPU_REGS_R9];
  kvm_regs->r10 = vcpu->arch.regs[VCPU_REGS_R10]; kvm_regs->r11 = vcpu->arch.regs[VCPU_REGS_R11];
  kvm_regs->r12 = vcpu->arch.regs[VCPU_REGS_R12]; kvm_regs->r13 = vcpu->arch.regs[VCPU_REGS_R13];
  kvm_regs->r14 = vcpu->arch.regs[VCPU_REGS_R14]; kvm_regs->r15 = vcpu->arch.regs[VCPU_REGS_R15];

  kvm_regs->rip = vcpu->arch.regs[VCPU_REGS_RIP];

  kvm_regs->rflags = vcpu->arch.rflags;

  return 0;
}

int kvm_set_regs(struct vcpu *vcpu, struct kvm_regs* kvm_regs) {
  vcpu->arch.regs[VCPU_REGS_RAX] = kvm_regs->rax; vcpu->arch.regs[VCPU_REGS_RCX] = kvm_regs->rcx;
  vcpu->arch.regs[VCPU_REGS_RDX] = kvm_regs->rdx; vcpu->arch.regs[VCPU_REGS_RBX] = kvm_regs->rbx;
  vcpu->arch.regs[VCPU_REGS_RSP] = kvm_regs->rsp; vcpu->arch.regs[VCPU_REGS_RBP] = kvm_regs->rbp;
  vcpu->arch.regs[VCPU_REGS_RSI] = kvm_regs->rsi; vcpu->arch.regs[VCPU_REGS_RDI] = kvm_regs->rdi;

  vcpu->arch.regs[VCPU_REGS_R8] = kvm_regs->r8; vcpu->arch.regs[VCPU_REGS_R9] = kvm_regs->r9;
  vcpu->arch.regs[VCPU_REGS_R10] = kvm_regs->r10; vcpu->arch.regs[VCPU_REGS_R11] = kvm_regs->r11;
  vcpu->arch.regs[VCPU_REGS_R12] = kvm_regs->r12; vcpu->arch.regs[VCPU_REGS_R13] = kvm_regs->r13;
  vcpu->arch.regs[VCPU_REGS_R14] = kvm_regs->r14; vcpu->arch.regs[VCPU_REGS_R15] = kvm_regs->r15;

  vcpu->arch.regs[VCPU_REGS_RIP] = kvm_regs->rip;
  printf("setting rip: %llx\n", kvm_regs->rip);

  vcpu->arch.rflags = kvm_regs->rflags;
  return 0;
}

int kvm_get_sregs(struct vcpu *vcpu, struct kvm_sregs *sregs) {
  sregs->cr0 = vmcs_readl(GUEST_CR0);
  sregs->cr3 = vmcs_readl(GUEST_CR3);
  sregs->cr4 = vmcs_readl(GUEST_CR4);

  // TODO: read the segments

  // idtr and gdtr
  sregs->idt.limit = vmcs_read32(GUEST_IDTR_LIMIT);
  sregs->idt.base = vmcs_readl(GUEST_IDTR_BASE);
  sregs->gdt.limit = vmcs_read32(GUEST_GDTR_LIMIT);
  sregs->gdt.base = vmcs_readl(GUEST_GDTR_BASE);

  sregs->efer = vmcs_readl(GUEST_IA32_EFER);

  return 0;
}

int kvm_set_sregs(struct vcpu *vcpu, struct kvm_sregs *sregs) {
  //return 0;

  // should check this values?
  printf("cr0 %lx %lx\n", sregs->cr0, vmcs_readl(GUEST_CR0));
  printf("cr3 %lx %lx\n", sregs->cr3, vmcs_readl(GUEST_CR3));
  printf("cr4 %lx %lx\n", sregs->cr4, vmcs_readl(GUEST_CR4));

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

	return 0;
}

void kvm_run(struct vcpu *vcpu) {
  //vmcs_writel(GUEST_RSP, &stackk[0x20]);
  //vmcs_writel(GUEST_RIP, &guest_entry_point);

  //vmcs_clear(vcpu->vmcs);
  //vmcs_load(vcpu->vmcs);
  //initialize_64bit_control();

  // should restore this
  //unsigned long debugctlmsr = rdmsr64(MSR_IA32_DEBUGCTLMSR);
  //printf("debugctl: %x\n", debugctlmsr);

  //vmcs_writel(GUEST_RSP, 0);
  //vmcs_writel(GUEST_RIP, 0xAAAAAAAA);

  /*u64 value;
  asm ("call tmp\n\t"
    "tmp:\n\t"
    "pop %%rax\n" :"=a"(value));
  printf("rip: %lx\n", value);*/

  // load the backing store
  vmcs_writel(GUEST_RFLAGS, vcpu->arch.rflags);
  vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
  vmcs_writel(GUEST_RIP, vcpu->arch.regs[VCPU_REGS_RIP]);

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
    "jmp _vmexit_handler\n\t"
    ".global _guest_entry_point\n\t"
    "_guest_entry_point:\n\t"
    "hlt\n\t"
		/* Save guest registers, load host registers, keep flags */
    "nop\n\t"
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

    "sti\n\t"

	      : : "c"(vcpu), "d"((unsigned long)HOST_RSP),
		[launched]"i"(offsetof(struct vcpu, __launched)),
		[fail]"i"(offsetof(struct vcpu, fail)),
		[host_rsp]"i"(offsetof(struct vcpu, host_rsp)),
		[rax]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_RAX])),
		[rbx]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_RBP])),
		[r8]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_R9])),
		[r10]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct vcpu, arch.regs[VCPU_REGS_R15])),
		[cr2]"i"(offsetof(struct vcpu, arch.cr2)),
		[idtr]"i"(offsetof(struct vcpu, arch.host_idtr)),
		[gdtr]"i"(offsetof(struct vcpu, arch.host_gdtr)),
    [ldtr]"i"(offsetof(struct vcpu, arch.host_ldtr)),
		[wordsize]"i"(sizeof(ulong))
	      : "cc", "memory"
		, "rax", "rbx", "rdi", "rsi"
    // "rsp", "rbp", "rcx", "rdx"
		, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
  );
  vcpu->__launched = 1;

  // read them?
  vcpu->arch.rflags = vmcs_readl(GUEST_RFLAGS);
  vcpu->arch.regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
  vcpu->arch.regs[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);

  //vmcs_clear(vcpu->vmcs);

  /*asm (
    "mov 0xAAAAAAAA, %%rax\n\t"
    "mov 0(%%rax), %%rax\n\t"
    : : "c"(entry_error), "d"(exit_reason), "b"(intr)
  );*/

  // crash controlled
  //printf("tmp %lx\n", rdmsr64(MSR_IA32_EFER));
}



/*#include <asm/msr-index.h>
static const u32 vmx_msr_index[] = {
	MSR_SYSCALL_MASK, MSR_LSTAR, MSR_CSTAR,
	MSR_EFER, MSR_TSC_AUX, MSR_STAR,
};*/


// store the physical addresses on the first page, and the virtual addresses on the second page
unsigned long *pml4 = NULL;

static void ept_init() {
  // EPT allocation
	pml4 = (unsigned long *)IOMallocAligned(PAGE_SIZE*2, PAGE_SIZE);
	bzero(pml4, PAGE_SIZE*2);
}


#define PAGE_OFFSET 512
#define EPT_DEFAULTS (VMX_EPT_EXECUTABLE_MASK | VMX_EPT_WRITABLE_MASK | VMX_EPT_READABLE_MASK)

// could probably be managed by http://fxr.watson.org/fxr/source/osfmk/i386/pmap.h
static void ept_add_page(unsigned long virtual_address, unsigned long physical_address) {
  int pml4_idx = (virtual_address >> 39) & 0x1FF;
  int pdpt_idx = (virtual_address >> 30) & 0x1FF;
  int pd_idx = (virtual_address >> 21) & 0x1FF;
  int pt_idx = (virtual_address >> 12) & 0x1FF;
  unsigned long *pdpt, *pd, *pt;
  //printf("%d %d %d %d\n", pml4_idx, pdpt_idx, pd_idx, pt_idx);

  // allocate the pdpt in the pml4 if NULL
  pdpt = (unsigned long*)pml4[PAGE_OFFSET + pml4_idx];
  if (pdpt == NULL) {
    pdpt = (unsigned long*)IOMallocAligned(PAGE_SIZE*2, PAGE_SIZE);
    bzero(pdpt, PAGE_SIZE*2);
    pml4[PAGE_OFFSET + pml4_idx] = (unsigned long)pdpt;
    pml4[pml4_idx] = __pa(pdpt) | EPT_DEFAULTS;
  }

  // allocate the pd in the pdpt
  pd = (unsigned long*)pdpt[PAGE_OFFSET + pdpt_idx];
  if (pd == NULL) {
    pd = (unsigned long*)IOMallocAligned(PAGE_SIZE*2, PAGE_SIZE);
    bzero(pd, PAGE_SIZE*2);
    pdpt[PAGE_OFFSET + pd_idx] = (unsigned long)pd;
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

static void vcpu_init() {
  //int i;

  //vmcs_writel(CR0_GUEST_HOST_MASK, ~0UL);

  // copied from vtx.c written

  //vmcs_writel(PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_POSTED_INTR | PIN_BASED_VMX_PREEMPTION_TIMER | PIN_BASED_VIRTUAL_NMIS | PIN_BASED_NMI_EXITING | PIN_BASED_EXT_INTR_MASK);  // all enabled, 24.6.1

  //vmcs_writel(CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_HLT_EXITING | CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_UNCOND_IO_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
  //vmcs_writel(SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_UNRESTRICTED_GUEST | SECONDARY_EXEC_ENABLE_EPT);
  vmcs_write32(EXCEPTION_BITMAP, 0xffffffff);

  vmcs_writel(EPT_POINTER, __pa(pml4) | (0x03 << 3));

  vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR);
  vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR | CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
  vmcs_write32(SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_UNRESTRICTED_GUEST | SECONDARY_EXEC_ENABLE_EPT);

  //vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR | CPU_BASED_HLT_EXITING);
  //vmcs_write32(SECONDARY_VM_EXEC_CONTROL, 0);

  // better not include PAT, EFER, or PERF_GLOBAL
  vmcs_write32(VM_EXIT_CONTROLS, VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR | VM_EXIT_HOST_ADDR_SPACE_SIZE);
  vmcs_write32(VM_ENTRY_CONTROLS, VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR);
  //vmcs_write32(VM_ENTRY_CONTROLS, VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR | VM_ENTRY_IA32E_MODE);

  //vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR);
  //vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR);
  //vmcs_write32(VM_EXIT_CONTROLS, VM_EXIT_HOST_ADDR_SPACE_SIZE);
  //vmcs_write32(VM_ENTRY_CONTROLS, VM_ENTRY_IA32E_MODE);

  /*printf("%lx %lx\n", rdmsr64(MSR_IA32_VMX_TRUE_PINBASED_CTLS), rdmsr64(MSR_IA32_VMX_PINBASED_CTLS));
  printf("%lx %lx\n", rdmsr64(MSR_IA32_VMX_TRUE_PROCBASED_CTLS), rdmsr64(MSR_IA32_VMX_PROCBASED_CTLS));
  printf("%lx %lx\n", rdmsr64(MSR_IA32_VMX_TRUE_VMEXIT_CTLS), rdmsr64(MSR_IA32_VMX_EXIT_CTLS));
  printf("%lx %lx\n", rdmsr64(MSR_IA32_VMX_TRUE_VMENTRY_CTLS), rdmsr64(MSR_IA32_VMX_ENTRY_CTLS));

  vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, rdmsr64(MSR_IA32_VMX_TRUE_PINBASED_CTLS));
  vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, rdmsr64(MSR_IA32_VMX_TRUE_PROCBASED_CTLS));
  vmcs_write32(VM_EXIT_CONTROLS, rdmsr64(MSR_IA32_VMX_TRUE_VMEXIT_CTLS) | VM_EXIT_HOST_ADDR_SPACE_SIZE);
  //vmcs_write32(VM_EXIT_CONTROLS, rdmsr64(MSR_IA32_VMX_TRUE_VMEXIT_CTLS));
  vmcs_write32(VM_ENTRY_CONTROLS, rdmsr64(MSR_IA32_VMX_TRUE_VMENTRY_CTLS) | VM_ENTRY_IA32E_MODE);*/

  /*vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR);
  vmcs_write32(VM_EXIT_CONTROLS, VM_EXIT_HOST_ADDR_SPACE_SIZE);
  vmcs_write32(VM_ENTRY_CONTROLS, VM_ENTRY_IA32E_MODE);*/

  /*vmcs_write32(VM_EXIT_CONTROLS, VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR | VM_EXIT_HOST_ADDR_SPACE_SIZE);
  vmcs_write32(VM_ENTRY_CONTROLS, VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR);*/

  /*vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, 0x1f);
  vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, 0x0401e172);
  vmcs_write32(VM_EXIT_CONTROLS, 0x36fff);
  vmcs_write32(VM_ENTRY_CONTROLS, 0x13ff);*/

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
  vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, ~0LL);
  vmcs_write64(APIC_ACCESS_ADDR, ~0LL);
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

  vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0); 
  vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE); 

  vmcs_writel(VMX_PREEMPTION_TIMER_VALUE, 0);

  vmcs_writel(GUEST_SYSENTER_CS, rdmsr64(MSR_IA32_SYSENTER_CS));
  vmcs_writel(GUEST_SYSENTER_ESP, rdmsr64(MSR_IA32_SYSENTER_ESP));
  vmcs_writel(GUEST_SYSENTER_EIP, rdmsr64(MSR_IA32_SYSENTER_EIP));


  // required to set the reserved bit
  //vmcs_writel(GUEST_RFLAGS, 2 | (1 << 15) | (1 << 3));

  //printf("vmexit: %lx\n", vmexit_handler);

  /*initialize_16bit_host_guest_state();
  initialize_64bit_control();
  // initialize_64bit_host_guest_state
  initialize_naturalwidth_control();
  initialize_32bit_host_guest_state();
  initialize_naturalwidth_host_guest_state();*/


  /*vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, __pa(vcpu->msr_autoload.host));
  vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, __pa(vcpu->msr_autoload.guest));*/

	/*for (i = 0; i < ARRAY_SIZE(vmx_msr_index); ++i) {
		u32 index = vmx_msr_index[i];
		u32 data_low, data_high;
		int j = vcpu->nmsrs;

		if (rdmsr_safe(index, &data_low, &data_high) < 0)
			continue;
		if (wrmsr_safe(index, data_low, data_high) < 0)
			continue;
		vcpu->guest_msrs[j].index = i;
		vcpu->guest_msrs[j].data = 0;
		vcpu->guest_msrs[j].mask = -1ull;
		++vcpu->nmsrs;
	}*/

  /*rdmsrl(MSR_FS_BASE, a);
  vmcs_writel(HOST_FS_BASE, a);
  rdmsrl(MSR_GS_BASE, a);
  vmcs_writel(HOST_GS_BASE, a);*/

}

#include <kern/task.h>

static int kvm_set_user_memory_region(struct kvm_userspace_memory_region *mr) {
  // check alignment
  unsigned long off;
  IOMemoryDescriptor *md = IOMemoryDescriptor::withAddressRange(mr->userspace_addr, mr->memory_size, kIODirectionInOut, current_task());
  DEBUG("MAPPING %p WITH FLAGS %x SLOT %d IN GUEST AT %p-%p\n", mr->userspace_addr, mr->flags, mr->slot, mr->guest_phys_addr, mr->guest_phys_addr + mr->memory_size);

  // wire in the memory
  IOReturn ret = md->prepare(kIODirectionInOut);

  //printf("%llx\n", md->getLength());

  //return 0;

  //printf("ret %d\n", ret);

  //printf("md is %p %lx\n", md, pa);
  //IOByteCount tmp;
  /*IOByteCount rpc, dpc;
  md->getPageCounts(&rpc, &dpc);
  printf("0x%x 0x%x\n", rpc, dpc);*/

  /*printf("current_task is %p\n", ct);
  printf("current_map is %d %p\n", sizeof(vm_map_t), (uintptr_t)get_task_map(ct));
  //printf("current_pmap is %p\n", get_task_pmap(ct));
  printf("kernel_pmap is %p\n", kernel_pmap);*/

  for (off = 0; off < mr->memory_size; off += PAGE_SIZE) {
    unsigned long va = mr->userspace_addr + off;
    addr64_t pa = md->getPhysicalSegment(off, NULL, kIOMemoryMapperNone);
    if (pa != 0) {
      ept_add_page(mr->guest_phys_addr + off, pa);
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
  int maxcont = 0;
  int cont = 1;
  unsigned long exit_reason;
  while (cont && (maxcont++) < 1000) {
    //kvm_show_regs();
    kvm_run(vcpu);

    exit_reason = vmcs_read32(VM_EXIT_REASON);

    //printf("%lx %lx\n", vcpu->arch.idtr.base, vcpu->arch.gdtr.base);
    //printf("vmcs: %lx\n", vcpu->vmcs);

    if (exit_reason < kvm_vmx_max_exit_handlers && kvm_vmx_exit_handlers[exit_reason] != NULL) {
      cont = kvm_vmx_exit_handlers[exit_reason](vcpu);
    } else {
      cont = 0;
    }
  }
  printf("looped %d times\n", maxcont);
  kvm_show_regs();

  unsigned long entry_error = vmcs_read32(VM_ENTRY_EXCEPTION_ERROR_CODE);
  unsigned int qual = vmcs_read32(EXIT_QUALIFICATION);
  unsigned long error = vmcs_read32(VM_INSTRUCTION_ERROR);
  //unsigned long intr = vmcs_read32(VM_EXIT_INTR_INFO);
  u64 phys = vmcs_readl(GUEST_PHYSICAL_ADDRESS);

  printf("entry %ld exit %d(0x%x) qual %X error %ld phys 0x%llx\n",
    entry_error, exit_reason, exit_reason, qual, error, phys);
  return 0;
}

static int kvm_set_cpuid2(struct vcpu *vcpu, struct kvm_cpuid2 *cpuid2) {
  printf("got %d cpuids at %p\n", cpuid2->nent, cpuid2);

  return 0;
}

static int kvm_dev_ioctl(dev_t Dev, u_long iCmd, caddr_t pData, int fFlags, struct proc *pProcess) {
  int ret = EOPNOTSUPP;
  int test;
  iCmd &= 0xFFFFFFFF;
  IOMemoryDescriptor *md;
  IOMemoryMap *mm;

  if (pData == NULL) goto fail;

  /* kvm_ioctl */
  switch (iCmd) {
    case KVM_GET_API_VERSION:
      ret = KVM_API_VERSION;
      break;
    case KVM_CREATE_VM:
      DEBUG("create vm\n");
      // assign an fd, must be a system fd
      // can't do this
      ept_init();
      ret = 0;
      break;
    case KVM_GET_VCPU_MMAP_SIZE:
      ret = PAGE_SIZE;
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
    case KVM_SET_IDENTITY_MAP_ADDR:
      ret = 0;
      break;
    case KVM_SET_TSS_ADDR:
      ret = 0;
      break;
    case KVM_CREATE_IRQCHIP:
      ret = 0;
      break;
    default:
      break;
  }

  if (pml4 != NULL) {
    /* kvm_vm_ioctl */
    switch (iCmd) {
      case KVM_CREATE_VCPU:
        DEBUG("create vcpu\n");
        vcpu->vmcs = allocate_vmcs();
        vcpu->kvm_vcpu = (struct kvm_run *)IOMallocAligned(PAGE_SIZE, PAGE_SIZE);
        bzero(vcpu->kvm_vcpu, PAGE_SIZE);
        vmcs_clear(vcpu->vmcs);
        vmcs_load(vcpu->vmcs);
        vcpu_init();
        //init_guest_values_from_host();
        ret = 0;
        break;
      case KVM_SET_USER_MEMORY_REGION:
        ret = kvm_set_user_memory_region((struct kvm_userspace_memory_region*)pData);
        break;
      default:
        break;
    }
  }

  if (vcpu->vmcs != NULL) {
    // processor issue?
    vmcs_load(vcpu->vmcs);

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
        md = IOMemoryDescriptor::withAddressRange((mach_vm_address_t)vcpu->kvm_vcpu, PAGE_SIZE, kIODirectionInOut, kernel_task);
        mm = md->createMappingInTask(current_task(), NULL, kIOMapAnywhere);
        DEBUG("mmaped at %p %p\n", *(mach_vm_address_t *)pData, mm->getAddress());
        *(mach_vm_address_t *)pData = mm->getAddress();
        ret = 0;
        break;
      case KVM_SET_SIGNAL_MASK:
        // signals on kvm run?
        ret = 0;
        break;
      case KVM_SET_CPUID2:
        ret = kvm_set_cpuid2(vcpu, (struct kvm_cpuid2 *)pData);
        break;
      default:
        break;
    }

    vmcs_clear(vcpu->vmcs);
  }

fail:
  printf("%d %p get ioctl %lX with pData %p return %d\n", cpu_number(), pProcess, iCmd, pData, ret);
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
  //printf("host rip is %lx\n", &vmexit_handler);

  ret = host_vmxon(FALSE);
  IOLog("host_vmxon: %d\n", ret);

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

  //hardware_disable();

  devfs_remove(g_kvm_ctl);
  cdevsw_remove(g_kvm_major, &kvm_functions);

  host_vmxoff();

  //if (only_vmcs != NULL) vmx_pfree(only_vmcs);

  return KERN_SUCCESS;
}

extern "C" {
extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);
}

KMOD_EXPLICIT_DECL(com.geohot.virt.kvm, "1.0.0d1", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = MyKextStart;
__private_extern__ kmod_stop_func_t *_antimain = MyKextStop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;

