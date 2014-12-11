#include "common.h"

int main(int argc, char *argv[]) {
  int kvm_fd = open("/dev/kvm", O_RDWR);
  int vm_fd = kvm_ioctl(kvm_fd, KVM_CREATE_VM, 0);
  int vcpu_fd = kvm_ioctl(vm_fd, KVM_CREATE_VCPU, 0);
  printf("three fds %d %d %d\n", kvm_fd, vm_fd, vcpu_fd);
}

