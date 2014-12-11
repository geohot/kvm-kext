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
  }
  return ret;
#else
  // os x seems to have issues allocating an fd in the kernel
  if (type == KVM_CREATE_VCPU || type == KVM_CREATE_VM) return fd;
  return errno;
#endif
}

int main(int argc, char *argv[]) {
  int kvm_fd = open("/dev/kvm", O_RDWR);
  if (kvm_fd < 0) {
    perror("kvm_open");
    return -1;
  }
  printf("sending ioctl %X\n", KVM_GET_API_VERSION);
  int version = kvm_ioctl(kvm_fd, KVM_GET_API_VERSION, 0);
  printf("got version %d\n", version);
  if (version != KVM_API_VERSION) {
    perror("ioctl");
  }
  int vm_fd = kvm_ioctl(kvm_fd, KVM_CREATE_VM, 0);
  printf("got vm %d\n", vm_fd);
  return 0;
}

