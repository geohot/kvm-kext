#include <stdio.h>
#include <stdlib.h>
#include <linux/kvm.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>

int __ioctl(int fd, unsigned int type, void *arg) {
  if (type == KVM_SET_CPUID || type == KVM_SET_CPUID2 || type == KVM_SET_MSRS ||
      type == KVM_GET_MSRS || type == KVM_GET_MSR_INDEX_LIST ||
      type == KVM_GET_SUPPORTED_CPUID) {
    // need user pointer to copyin the rest of the data not in the ioctl sizeof
    *(__u64 *)arg = (__u64)arg;
  }

  int ret = syscall(54, fd, type, arg);
  if (ret == -1) ret = errno;

  // os x seems to have issues allocating an fd in the kernel
  if (type == KVM_CREATE_VCPU || type == KVM_CREATE_VM) ret = fd;

  //printf("  returning %d\n", ret);
  return ret;
}

int kvm_ioctl(int fd, int type, ...) {
  int ret;
  void *arg;
  va_list ap;

  va_start(ap, type);
  arg = va_arg(ap, void *);
  va_end(ap);

  return __ioctl(fd, type, arg);
}

