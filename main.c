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

//struct vcpu only_cpu;

//#include "vmx.h"
//#include <linux/kvm_host.h>

struct vcpu_arch {
  unsigned long regs[NR_VCPU_REGS];
  unsigned long cr2;
};

struct vcpu {
  vmcs *vmcs;
  struct vcpu_arch arch;
  unsigned long __launched;
  unsigned long fail;
  unsigned long host_rsp;
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
	/*struct msr_data apic_base_msr;
	int mmu_reset_needed = 0;
	int pending_vec, max_bits, idx;
	struct desc_ptr dt;

	if (!guest_cpuid_has_xsave(vcpu) && (sregs->cr4 & X86_CR4_OSXSAVE))
		return -EINVAL;

	dt.size = sregs->idt.limit;
	dt.address = sregs->idt.base;
	kvm_x86_ops->set_idt(vcpu, &dt);
	dt.size = sregs->gdt.limit;
	dt.address = sregs->gdt.base;
	kvm_x86_ops->set_gdt(vcpu, &dt);

	vcpu->arch.cr2 = sregs->cr2;
	mmu_reset_needed |= kvm_read_cr3(vcpu) != sregs->cr3;
	vcpu->arch.cr3 = sregs->cr3;
	__set_bit(VCPU_EXREG_CR3, (ulong *)&vcpu->arch.regs_avail);

	kvm_set_cr8(vcpu, sregs->cr8);

	mmu_reset_needed |= vcpu->arch.efer != sregs->efer;
	kvm_x86_ops->set_efer(vcpu, sregs->efer);
	apic_base_msr.data = sregs->apic_base;
	apic_base_msr.host_initiated = true;
	kvm_set_apic_base(vcpu, &apic_base_msr);

	mmu_reset_needed |= kvm_read_cr0(vcpu) != sregs->cr0;
	kvm_x86_ops->set_cr0(vcpu, sregs->cr0);
	vcpu->arch.cr0 = sregs->cr0;

	mmu_reset_needed |= kvm_read_cr4(vcpu) != sregs->cr4;
	kvm_x86_ops->set_cr4(vcpu, sregs->cr4);
	if (sregs->cr4 & X86_CR4_OSXSAVE)
		kvm_update_cpuid(vcpu);

	idx = srcu_read_lock(&vcpu->kvm->srcu);
	if (!is_long_mode(vcpu) && is_pae(vcpu)) {
		load_pdptrs(vcpu, vcpu->arch.walk_mmu, kvm_read_cr3(vcpu));
		mmu_reset_needed = 1;
	}
	srcu_read_unlock(&vcpu->kvm->srcu, idx);

	if (mmu_reset_needed)
		kvm_mmu_reset_context(vcpu);

	max_bits = KVM_NR_INTERRUPTS;
	pending_vec = find_first_bit(
		(const unsigned long *)sregs->interrupt_bitmap, max_bits);
	if (pending_vec < max_bits) {
		kvm_queue_interrupt(vcpu, pending_vec, false);
		pr_debug("Set back pending irq %d\n", pending_vec);
	}*/

	kvm_set_segment(vcpu, &sregs->cs, VCPU_SREG_CS);
	kvm_set_segment(vcpu, &sregs->ds, VCPU_SREG_DS);
	kvm_set_segment(vcpu, &sregs->es, VCPU_SREG_ES);
	kvm_set_segment(vcpu, &sregs->fs, VCPU_SREG_FS);
	kvm_set_segment(vcpu, &sregs->gs, VCPU_SREG_GS);
	kvm_set_segment(vcpu, &sregs->ss, VCPU_SREG_SS);

	kvm_set_segment(vcpu, &sregs->tr, VCPU_SREG_TR);
	kvm_set_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

	//update_cr8_intercept(vcpu);

	/* Older userspace won't unhalt the vcpu on reset. */
	/*if (kvm_vcpu_is_bsp(vcpu) && kvm_rip_read(vcpu) == 0xfff0 &&
	    sregs->cs.selector == 0xf000 && sregs->cs.base == 0xffff0000 &&
	    !is_protmode(vcpu))
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

	kvm_make_request(KVM_REQ_EVENT, vcpu);*/

	return 0;
}

void kvm_run(struct vcpu *vcpu) {
	asm(
		/* Store host registers */
		"push %%rdx; push %%rbp;"
		"push %%rcx \n\t" /* placeholder for guest rcx */
		"push %%rcx \n\t"
		"cmp %%rsp, %c[host_rsp](%0) \n\t"
		"je 1f \n\t"
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
		"1: " __ex(ASM_VMX_VMRESUME) "\n\t"
		"2: "
		/* Save guest registers, load host registers, keep flags */
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

		"pop  %%rbp; pop  %%rdx \n\t"
		"setbe %c[fail](%0) \n\t"
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
  unsigned long exit_reason = vmcs_read32(VM_EXIT_REASON);
  unsigned long host_rsp = vmcs_readl(HOST_RSP);
  printf("exit %llx rsp %llx\n", exit_reason, host_rsp);
}

#define __ex(x) x
#define __pa vmx_paddr

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

static int kvm_dev_ioctl(dev_t Dev, u_long iCmd, caddr_t pData, int fFlags, struct proc *pProcess) {
  // maybe these shouldn't be on the stack?
  iCmd &= 0xFFFFFFFF;
  printf("get ioctl %lX with pData %p\n", iCmd, pData);
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
      kvm_set_regs(vcpu, (struct kvm_regs *)pData);
      return 0;
    case KVM_GET_SREGS:
      //kvm_get_sregs((user_addr_t)pData);
      return 0;
    case KVM_SET_SREGS:
      if (pData == NULL) return EINVAL;
      kvm_set_sregs(vcpu, (struct kvm_sregs *)pData);
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

