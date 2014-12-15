#include <sys/proc.h>
#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/kvm.h>
//#include <linux/kvm_host.h>

static int kvm_dev_open(dev_t Dev, int fFlags, int fDevType, struct proc *pProcess) {
  return 0;
}

static int kvm_dev_close(dev_t Dev, int fFlags, int fDevType, struct proc *pProcess) {
  return 0;
}

static int kvm_dev_ioctl(dev_t Dev, u_long iCmd, caddr_t pData, int fFlags, struct proc *pProcess) {
  // maybe these shouldn't be on the stack?
  /*struct kvm_regs kvm_regs;
  struct kvm_sregs kvm_sregs;*/

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
      hardware_enable();
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
      return 0;
    case KVM_SET_USER_MEMORY_REGION:
      return 0;
    default:
      break;
  }

  /* kvm_vcpu_ioctl */
  switch (iCmd) {
    case KVM_GET_REGS:
      //kvm_arch_vcpu_ioctl_get_regs(vcpu, &kvm_regs);
      return 0;
    case KVM_SET_REGS:
      return 0;
    case KVM_GET_SREGS:
      return 0;
    case KVM_SET_SREGS:
      return 0;
    case KVM_RUN:
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
  printf("MyKext has started.\n");

  g_kvm_major = cdevsw_add(-1, &kvm_functions);
  if (g_kvm_major < 0) {
    return KMOD_RETURN_FAILURE;
  }

  // insecure for testing!
  g_kvm_ctl = devfs_make_node(makedev(g_kvm_major, 0), DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666, "kvm");

  hardware_enable();

  return KMOD_RETURN_SUCCESS;
}
 
kern_return_t MyKextStop(kmod_info_t *ki, void *d) {
  printf("MyKext has stopped.\n");

  hardware_disable();

  devfs_remove(g_kvm_ctl);
  cdevsw_remove(g_kvm_major, &kvm_functions);

  return KERN_SUCCESS;
}

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

KMOD_EXPLICIT_DECL(com.geohot.virt.kvm, "1.0.0d1", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = MyKextStart;
__private_extern__ kmod_stop_func_t *_antimain = MyKextStop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;

