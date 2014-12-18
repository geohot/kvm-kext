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
#include <i386/vmx.h>

#include <linux/kvm.h>
#include "kvm_host.h"
//#include "kvm_cache_regs.h"

#include "vmx_shims.h"
#include "vmcs.h"

#define __ex(x) x
#define __pa vmx_paddr

static void vcpu_init();

void initialize_naturalwidth_control(void){
  vmcs_write64(CR0_GUEST_HOST_MASK, 0);
  vmcs_write64(CR4_GUEST_HOST_MASK, 0);

  vmcs_write64(CR0_READ_SHADOW, 0);
  vmcs_write64(CR4_READ_SHADOW, 0);

  vmcs_write64(CR3_TARGET_VALUE0, 0);
  vmcs_write64(CR3_TARGET_VALUE1, 0);
  vmcs_write64(CR3_TARGET_VALUE2, 0);
  vmcs_write64(CR3_TARGET_VALUE3, 0);
}
  

// copies all host selectors, 0xc00 - 0xc0c
static void initialize_16bit_host_guest_state(void) {
  u16 	    value;
  asm ("movw %%es, %%ax\n" :"=a"(value));
  vmcs_write16(HOST_ES_SELECTOR,value); 
  vmcs_write16(GUEST_ES_SELECTOR,value); 

  asm ("movw %%cs, %%ax\n" : "=a"(value));
  vmcs_write16(HOST_CS_SELECTOR,value); 
  vmcs_write16(GUEST_CS_SELECTOR,value); 

  asm ("movw %%ss, %%ax\n" : "=a"(value));
  vmcs_write16(HOST_SS_SELECTOR,value); 
  vmcs_write16(GUEST_SS_SELECTOR,value); 

  asm ("movw %%ds, %%ax\n" : "=a"(value));
  vmcs_write16(HOST_DS_SELECTOR,value); 
  vmcs_write16(GUEST_DS_SELECTOR,value); 

  asm ("movw %%fs, %%ax\n" : "=a"(value));
  vmcs_write16(HOST_FS_SELECTOR,value); 
  vmcs_write16(GUEST_FS_SELECTOR,value); 

  asm ("movw %%gs, %%ax\n" : "=a"(value));
  vmcs_write16(HOST_GS_SELECTOR,value); 
  vmcs_write16(GUEST_GS_SELECTOR,value); 

  asm("str %%ax\n" : "=a"(value));
  vmcs_write16(HOST_TR_SELECTOR,value); 
  vmcs_write16(GUEST_TR_SELECTOR,value); 

  asm("sldt %%ax\n" : "=a"(value));
  vmcs_write16(GUEST_LDTR_SELECTOR,value); 
}

// host gdtr, idtr, tr, sysenter_cs
static void initialize_32bit_host_guest_state(void) {
   unsigned long field;
   u32 	    value;
   u64      gdtb = 0;
   u64      idtb = 0;
   u64      trbase;
   u64      trbase_lo;
   u64      trbase_hi;
   u64 	    realtrbase;
   u32      unusable_ar = 0x10000;
   u32      usable_ar; 
   u16      sel_value; 

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

  // other tr things
   asm("mov $0x40, %rax\n");
   asm("lsl %%eax, %%eax\n" :"=a"(value));
   vmcs_write32(GUEST_TR_LIMIT,value); 

   asm("str %%ax\n" : "=a"(sel_value));
   asm("lar %%eax,%%eax\n" :"=a"(usable_ar) :"a"(sel_value)); 
   usable_ar = usable_ar>>8;
   vmcs_write32(GUEST_TR_AR_BYTES, usable_ar);

  // gdt things
   asm("sgdt %0\n" : :"m"(gdtb));
   value = gdtb&0x0ffff;
   gdtb = gdtb>>16; //base

   if(((gdtb>>47)&0x1)){ gdtb |= 0xffff000000000000ull; }
   vmcs_write32(GUEST_GDTR_LIMIT,value); 
   vmcs_writel(GUEST_GDTR_BASE, gdtb);
   vmcs_writel(HOST_GDTR_BASE, gdtb);

  // tr things
   trbase = gdtb + 0x40;
   if(((trbase>>47)&0x1)){ trbase |= 0xffff000000000000ull; }

   // SS segment override
   asm("mov %0,%%rax\n" 
       ".byte 0x36\n"
       "movq (%%rax),%%rax\n"
        :"=a"(trbase_lo) :"0"(trbase) 
       );

   realtrbase = ((trbase_lo>>16) & (0x0ffff)) | (((trbase_lo>>32)&0x000000ff) << 16) | (((trbase_lo>>56)&0xff) << 24);

   // SS segment override for upper32 bits of base in ia32e mode
   asm("mov %0,%%rax\n" 
       ".byte 0x36\n"
       "movq 8(%%rax),%%rax\n"
        :"=a"(trbase_hi) :"0"(trbase) 
       );

   realtrbase = realtrbase | (trbase_hi<<32) ;
   printf("realtrbase: %lx\n", realtrbase);
   vmcs_writel(GUEST_TR_BASE, realtrbase);
   vmcs_writel(HOST_TR_BASE, realtrbase);

   asm("sidt %0\n" : :"m"(idtb));
   value = idtb&0x0ffff;
   idtb = idtb>>16; //base

   if(((idtb>>47)&0x1)){ idtb |= 0xffff000000000000ull; }
   vmcs_write32(GUEST_IDTR_LIMIT, value); 
   vmcs_writel(GUEST_IDTR_BASE, idtb);
   vmcs_writel(HOST_IDTR_BASE, idtb);

   vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0); 
   vmcs_write32(GUEST_ACTIVITY_STATE, 0); 
}


// host cr0, cr3, cr4, fs_base, gs_base, sysenter esp, eip, cs
static void initialize_naturalwidth_host_guest_state(void) {
  unsigned long field,field1;
  u64 	    value;
  int      fs_low;
  int      gs_low;

  asm ("movq %%cr0, %%rax\n" :"=a"(value));
  vmcs_writel(HOST_CR0, value); 
  vmcs_writel(GUEST_CR0, value); 

  asm ("movq %%cr3, %%rax\n" :"=a"(value));
  printf("cr3 is %lx\n", value);
  vmcs_writel(HOST_CR3, value); 
  vmcs_writel(GUEST_CR3, value); 

  asm ("movq %%cr4, %%rax\n" :"=a"(value));
  vmcs_writel(HOST_CR4,value); 
  vmcs_writel(GUEST_CR4,value); 

  value = rdmsr64(0xc0000100);
  printf("fs_base %lx\n", value);
  vmcs_writel(HOST_FS_BASE,value); 
  vmcs_writel(GUEST_FS_BASE,value); 

  value = rdmsr64(0xc0000101);
  printf("gs_base %lx\n", value);
  vmcs_writel(HOST_GS_BASE,value); 
  vmcs_writel(GUEST_GS_BASE,value);

  value = rdmsr64(0x176);
  printf("sysenter_esp %lx\n", value);
  vmcs_writel(GUEST_SYSENTER_ESP, value);
  vmcs_writel(HOST_IA32_SYSENTER_ESP, value);

  value = rdmsr64(0x175);
  printf("sysenter_eip %lx\n", value);
  vmcs_writel(GUEST_SYSENTER_EIP, value);
  vmcs_writel(HOST_IA32_SYSENTER_EIP, value);

  value = rdmsr64(0x174);
  printf("sysenter_cs %lx\n", value);
  vmcs_write32(GUEST_SYSENTER_CS, value);
  vmcs_write32(HOST_IA32_SYSENTER_CS, value);
}

void *io_bitmap_a_region, *io_bitmap_b_region, *msr_bitmap_phy_region, *virtual_apic_page;

static void initialize_64bit_control(void) {
  io_bitmap_a_region = IOMallocAligned(PAGE_SIZE, PAGE_SIZE);
  io_bitmap_b_region = IOMallocAligned(PAGE_SIZE, PAGE_SIZE);
  msr_bitmap_phy_region = IOMallocAligned(PAGE_SIZE, PAGE_SIZE);
  virtual_apic_page = IOMallocAligned(PAGE_SIZE, PAGE_SIZE);

	bzero(io_bitmap_a_region, PAGE_SIZE);
	bzero(io_bitmap_b_region, PAGE_SIZE);
	bzero(msr_bitmap_phy_region, PAGE_SIZE);
	bzero(virtual_apic_page, PAGE_SIZE);

  vmcs_writel(IO_BITMAP_A, __pa(io_bitmap_a_region));
  vmcs_writel(IO_BITMAP_B, __pa(io_bitmap_b_region));
  vmcs_writel(MSR_BITMAP, __pa(msr_bitmap_phy_region));
  vmcs_writel(VIRTUAL_APIC_PAGE_ADDR, __pa(virtual_apic_page));
  vmcs_writel(0x200C, 0);
  vmcs_writel(TSC_OFFSET, 0);
}


#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
//struct vcpu only_cpu;

//#include "vmx.h"
//#include <linux/kvm_host.h>

struct vcpu_arch {
  unsigned long regs[NR_VCPU_REGS];
  unsigned long cr2;
};

//#define NR_AUTOLOAD_MSRS 8

struct vcpu {
  vmcs *vmcs;
  struct vcpu_arch arch;
  unsigned long __launched;
  unsigned long fail;
  unsigned long host_rsp;

	//int                   nmsrs;
	/*struct msr_autoload {
		unsigned nr;
		struct vmx_msr_entry guest[NR_AUTOLOAD_MSRS];
		struct vmx_msr_entry host[NR_AUTOLOAD_MSRS];
	} msr_autoload;*/
} __vcpu;


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

void kvm_get_regs(struct vcpu *vcpu, struct kvm_regs* kvm_regs) {
  kvm_regs->rax = vcpu->arch.regs[VCPU_REGS_RAX]; kvm_regs->rcx = vcpu->arch.regs[VCPU_REGS_RCX];
  kvm_regs->rdx = vcpu->arch.regs[VCPU_REGS_RDX]; kvm_regs->rbx = vcpu->arch.regs[VCPU_REGS_RBX];
  kvm_regs->rsp = vcpu->arch.regs[VCPU_REGS_RSP]; kvm_regs->rbp = vcpu->arch.regs[VCPU_REGS_RBP];
  kvm_regs->rsi = vcpu->arch.regs[VCPU_REGS_RSI]; kvm_regs->rdi = vcpu->arch.regs[VCPU_REGS_RDI];

  kvm_regs->r8 = vcpu->arch.regs[VCPU_REGS_R8]; kvm_regs->r9 = vcpu->arch.regs[VCPU_REGS_R9];
  kvm_regs->r10 = vcpu->arch.regs[VCPU_REGS_R10]; kvm_regs->r11 = vcpu->arch.regs[VCPU_REGS_R11];
  kvm_regs->r12 = vcpu->arch.regs[VCPU_REGS_R12]; kvm_regs->r13 = vcpu->arch.regs[VCPU_REGS_R13];
  kvm_regs->r14 = vcpu->arch.regs[VCPU_REGS_R14]; kvm_regs->r15 = vcpu->arch.regs[VCPU_REGS_R15];

  kvm_regs->rip = vcpu->arch.regs[VCPU_REGS_RIP];

  // rflags?
}

void kvm_set_regs(struct vcpu *vcpu, struct kvm_regs* kvm_regs) {
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
}

/*void kvm_get_sregs(user_addr_t kvm_sregs_user) {
  struct kvm_sregs kvm_sregs;
  copyout(&kvm_sregs, kvm_sregs_user, sizeof(kvm_sregs));
}*/

int kvm_set_sregs(struct vcpu *vcpu, struct kvm_sregs *sregs) {
  //return 0;

	kvm_set_segment(vcpu, &sregs->cs, VCPU_SREG_CS);
	kvm_set_segment(vcpu, &sregs->ds, VCPU_SREG_DS);
	kvm_set_segment(vcpu, &sregs->es, VCPU_SREG_ES);
	kvm_set_segment(vcpu, &sregs->fs, VCPU_SREG_FS);
	kvm_set_segment(vcpu, &sregs->gs, VCPU_SREG_GS);
	kvm_set_segment(vcpu, &sregs->ss, VCPU_SREG_SS);

	kvm_set_segment(vcpu, &sregs->tr, VCPU_SREG_TR);
	kvm_set_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

  vmcs_writel(GUEST_CR0, sregs->cr0);
  vmcs_writel(GUEST_CR3, sregs->cr3);
  vmcs_writel(GUEST_CR4, sregs->cr4);

  vmcs_write32(GUEST_IDTR_LIMIT, sregs->idt.limit);
  vmcs_writel(GUEST_IDTR_BASE, sregs->idt.base);
  vmcs_write32(GUEST_GDTR_LIMIT, sregs->gdt.limit);
  vmcs_writel(GUEST_GDTR_BASE, sregs->gdt.base);

  vmcs_writel(GUEST_IA32_EFER, sregs->efer);

	return 0;
}

extern const ulong vmexit_handler;
extern const ulong guest_entry_point;

void kvm_run(struct vcpu *vcpu) {
  vcpu_init();

  //vmcs_writel(GUEST_RSP, &stackk[20]);
  vmcs_writel(GUEST_RIP, guest_entry_point);

  //vmcs_writel(GUEST_RSP, 0);
  //vmcs_writel(GUEST_RIP, 0xAAAAAAAA);

  /*u64 value;
  asm ("call tmp\n\t"
    "tmp:\n\t"
    "pop %%rax\n" :"=a"(value));
  printf("rip: %lx\n", value);*/

	asm(
		/* Store host registers */
		"push %%rdx\n\tpush %%rbp\n\t"
		"push %%rcx \n\t" /* placeholder for guest rcx */
		"push %%rcx \n\t"
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
		//__ex(ASM_VMX_VMLAUNCH) "\n\t"
		"jmp 2f \n\t"
		"1:\n"
    __ex(ASM_VMX_VMRESUME) "\n\t"
		"2:\n"
    "jmp _vmexit_handler\n\t"
    ".global _guest_entry_point\n\t"
    "_guest_entry_point:\n\t"
    "vmcall\n\t"
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

    /*".pushsection .rodata \n\t"
    ".global vmx_return \n\t"
    "vmx_return: .quad 2b \n\t"
    ".popsection"*/
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
		[wordsize]"i"(sizeof(ulong))
	      : "cc", "memory"
		, "rax", "rbx", "rdi", "rsi"
		, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
	      );

  vcpu->__launched = 1;
  unsigned long entry_error = vmcs_read32(VM_ENTRY_EXCEPTION_ERROR_CODE);
  unsigned long exit_reason = vmcs_read32(VM_EXIT_REASON);
  unsigned long error = vmcs_read32(VM_INSTRUCTION_ERROR);
  unsigned long host_rsp = vmcs_readl(HOST_RSP);
  unsigned long host_rip = vmcs_readl(HOST_RIP);
  unsigned long host_cr3 = vmcs_readl(HOST_CR3);
  printf("entry %ld exit %lx error %ld rsp %lx %lx rip %lx %lx\n", entry_error, exit_reason, error, vcpu->host_rsp, host_rsp, host_rip, host_cr3);
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

/*#include <asm/msr-index.h>
static const u32 vmx_msr_index[] = {
	MSR_SYSCALL_MASK, MSR_LSTAR, MSR_CSTAR,
	MSR_EFER, MSR_TSC_AUX, MSR_STAR,
};*/

static void vcpu_init() {
  int i;

  //vmcs_writel(CR0_GUEST_HOST_MASK, ~0UL);

  // copied from vtx.c written

  //vmcs_writel(PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_POSTED_INTR | PIN_BASED_VMX_PREEMPTION_TIMER | PIN_BASED_VIRTUAL_NMIS | PIN_BASED_NMI_EXITING | PIN_BASED_EXT_INTR_MASK);  // all enabled, 24.6.1

  //vmcs_writel(CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_HLT_EXITING | CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_UNCOND_IO_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
  //vmcs_writel(SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_UNRESTRICTED_GUEST | SECONDARY_EXEC_ENABLE_EPT);
  vmcs_write32(EXCEPTION_BITMAP, 0xffffffff);

  //vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR | PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING);
  //vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR | CPU_BASED_HLT_EXITING);

  //vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_ALWAYSON_WITHOUT_TRUE_MSR);
  //vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR);
  //vmcs_write32(VM_EXIT_CONTROLS, VM_EXIT_HOST_ADDR_SPACE_SIZE);
  //vmcs_write32(VM_ENTRY_CONTROLS, VM_ENTRY_IA32E_MODE);

  printf("%lx %lx\n", rdmsr64(MSR_IA32_VMX_TRUE_PINBASED_CTLS), rdmsr64(MSR_IA32_VMX_PINBASED_CTLS));
  printf("%lx %lx\n", rdmsr64(MSR_IA32_VMX_TRUE_PROCBASED_CTLS), rdmsr64(MSR_IA32_VMX_PROCBASED_CTLS));
  printf("%lx %lx\n", rdmsr64(MSR_IA32_VMX_TRUE_VMEXIT_CTLS), rdmsr64(MSR_IA32_VMX_EXIT_CTLS));
  printf("%lx %lx\n", rdmsr64(MSR_IA32_VMX_TRUE_VMENTRY_CTLS), rdmsr64(MSR_IA32_VMX_ENTRY_CTLS));

  vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, rdmsr64(MSR_IA32_VMX_TRUE_PINBASED_CTLS));
  vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, rdmsr64(MSR_IA32_VMX_TRUE_PROCBASED_CTLS));
  vmcs_write32(VM_EXIT_CONTROLS, rdmsr64(MSR_IA32_VMX_TRUE_VMEXIT_CTLS) | VM_EXIT_HOST_ADDR_SPACE_SIZE);
  vmcs_write32(VM_ENTRY_CONTROLS, rdmsr64(MSR_IA32_VMX_TRUE_VMENTRY_CTLS) | VM_ENTRY_IA32E_MODE);

  /*vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_ALWAYSON_WITHOUT_TRUE_MSR);
  vmcs_write32(VM_EXIT_CONTROLS, VM_EXIT_HOST_ADDR_SPACE_SIZE);
  vmcs_write32(VM_ENTRY_CONTROLS, VM_ENTRY_IA32E_MODE);*/

  //vmcs_write32(VM_EXIT_CONTROLS, VM_EXIT_ALWAYSON_WITHOUT_TRUE_MSR | VM_EXIT_HOST_ADDR_SPACE_SIZE);
  //vmcs_write32(VM_ENTRY_CONTROLS, VM_ENTRY_ALWAYSON_WITHOUT_TRUE_MSR | VM_ENTRY_IA32E_MODE);

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

  vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
  vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 0);
  vmcs_write32(TPR_THRESHOLD, 0);

  // EPT allocation
	/*void *pptr = IOMallocAligned(PAGE_SIZE*8, PAGE_SIZE);
	bzero(pptr, PAGE_SIZE);
  vmcs_writel(EPT_POINTER, pptr);*/

  // required to set the reserved bit
  vmcs_writel(GUEST_RFLAGS, 2);

  //printf("vmexit: %lx\n", vmexit_handler);
  vmcs_writel(HOST_RIP, &vmexit_handler);

  initialize_16bit_host_guest_state();
  initialize_64bit_control();
  // initialize_64bit_host_guest_state
  initialize_naturalwidth_control();
  initialize_32bit_host_guest_state();
  initialize_naturalwidth_host_guest_state();


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

static int kvm_dev_ioctl(dev_t Dev, u_long iCmd, caddr_t pData, int fFlags, struct proc *pProcess) {
  // maybe these shouldn't be on the stack?
  iCmd &= 0xFFFFFFFF;
  //printf("get ioctl %lX with pData %p\n", iCmd, pData);
  /* kvm_ioctl */
  switch (iCmd) {
    case KVM_GET_API_VERSION:
      return KVM_API_VERSION;
    case KVM_GET_MSR_INDEX_LIST:
      return EOPNOTSUPP;
    case KVM_CREATE_VM:
      // assign an fd, must be a system fd
      // can't do this

      return 0;
    case KVM_GET_VCPU_MMAP_SIZE:
      return PAGE_SIZE;
    case KVM_CHECK_EXTENSION:
      // no extensions are available
      return 0;
    default:
      break;
  }

  /* kvm_vm_ioctl */
  switch (iCmd) {
    case KVM_CREATE_VCPU:
      vcpu->vmcs = allocate_vmcs();
      vmcs_clear(vcpu->vmcs);
      vmcs_load(vcpu->vmcs);
      return 0;
    case KVM_SET_USER_MEMORY_REGION:
      return 0;
    default:
      break;
  }

  if (vcpu->vmcs == NULL) return EINVAL;

  /* kvm_vcpu_ioctl */
  switch (iCmd) {
    case KVM_GET_REGS:
      if (pData == NULL) return EINVAL;
      kvm_get_regs(vcpu, (struct kvm_regs *)pData);
      return 0;
    case KVM_SET_REGS:
      if (pData == NULL) return EINVAL;
      //kvm_set_regs(vcpu, (struct kvm_regs *)pData);
      return 0;
    case KVM_GET_SREGS:
      //kvm_get_sregs((user_addr_t)pData);
      return 0;
    case KVM_SET_SREGS:
      if (pData == NULL) return EINVAL;
      //kvm_set_sregs(vcpu, (struct kvm_sregs *)pData);
      return 0;
    case KVM_RUN:
      kvm_run(vcpu);
      return 0;
    default:
      break;
  }

  return EOPNOTSUPP;
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
  printf("host rip is %lx\n", &vmexit_handler);

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

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

KMOD_EXPLICIT_DECL(com.geohot.virt.kvm, "1.0.0d1", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = MyKextStart;
__private_extern__ kmod_stop_func_t *_antimain = MyKextStop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;

