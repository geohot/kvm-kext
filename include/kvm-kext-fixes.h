#include <linux/kvm.h>
#include <sys/types.h>
#include <sys/ioctl.h>

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
  return ret;
}

// TODO: we don't even try here to make this anything like mmap
void *__mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  void *ret = NULL;
  __ioctl(fd, KVM_MMAP_VCPU, &ret);
  return ret;
}

