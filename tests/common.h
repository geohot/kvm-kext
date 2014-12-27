#include <stdio.h>
#include <stdlib.h>
#include <linux/kvm.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>

int kvm_ioctl(int fd, int type, ...) {
  int ret;
  void *arg;
  va_list ap;

  va_start(ap, type);
  arg = va_arg(ap, void *);
  va_end(ap);

  return __ioctl(fd, type, arg);
}

