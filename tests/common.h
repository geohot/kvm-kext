#include <stdio.h>
#include <stdlib.h>
#include <linux/kvm.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>

int kvm_ioctl(int fd, int type, ...)
{
  int ret;
  void *arg;
  va_list ap;

  va_start(ap, type);
  arg = va_arg(ap, void *);
  va_end(ap);

  ret = ioctl(fd, type, arg);
#ifdef __linux__
  if (ret == -1) {
    ret = -errno;
    perror("ioctl");
  }
  return ret;
#else
  // os x seems to have issues allocating an fd in the kernel
  if (type == KVM_CREATE_VCPU || type == KVM_CREATE_VM) return fd;
  return errno;
#endif
}

