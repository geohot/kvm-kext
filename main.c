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

//struct vcpu_vmx only_cpu;

//#include "vmx.h"
//#include <linux/kvm_host.h>

struct vcpu_arch {
  unsigned long regs[NR_VCPU_REGS];
};

struct vcpu {
  vmcs *vmcs;
  struct vcpu_arch arch;
} __vcpu;

struct vcpu *vcpu = &__vcpu;

static int kvm_dev_open(dev_t Dev, int fFlags, int fDevType, struct proc *pProcess) {
  return 0;
}

static int kvm_dev_close(dev_t Dev, int fFlags, int fDevType, struct proc *pProcess) {
  return 0;
}

//void kvm_get_regs(struct vcpu *vcpu, user_addr_t kvm_regs_user) {
void kvm_get_regs(struct vcpu *vcpu, struct kvm_regs* kvm_regs) {
  //struct kvm_regs kvm_regs;
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

  //copyout(&kvm_regs, kvm_regs_user, sizeof(kvm_regs));
}

void kvm_set_regs(struct vcpu *vcpu, struct kvm_regs* kvm_regs) {
  /*struct kvm_regs kvm_regs;
  int ret = copyin(kvm_regs_user, &kvm_regs, sizeof(kvm_regs));
  printf("copyin: %x\n", ret);*/

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

  // rflags?
}

/*void kvm_get_sregs(user_addr_t kvm_sregs_user) {
  struct kvm_sregs kvm_sregs;
  copyout(&kvm_sregs, kvm_sregs_user, sizeof(kvm_sregs));
}

void kvm_set_sregs(user_addr_t kvm_sregs_user) {
  struct kvm_sregs kvm_sregs;
  copyin(kvm_sregs_user, &kvm_sregs, sizeof(kvm_sregs));
}*/

void kvm_run() {

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

  //if (vcpu->vmcs == NULL) return -1;

  /* kvm_vcpu_ioctl */
  switch (iCmd) {
    case KVM_GET_REGS:
      if (pData == NULL) return -1;
      kvm_get_regs(vcpu, (struct kvm_regs *)pData);
      return 0;
    case KVM_SET_REGS:
      if (pData == NULL) return -1;
      kvm_set_regs(vcpu, (struct kvm_regs *)pData);
      return 0;
    case KVM_GET_SREGS:
      //kvm_get_sregs((user_addr_t)pData);
      return 0;
    case KVM_SET_SREGS:
      //kvm_set_sregs((user_addr_t)pData);
      return 0;
    case KVM_RUN:
      //kvm_run();
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

