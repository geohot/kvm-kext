#include "common.h"

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

