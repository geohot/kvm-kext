#include <stdio.h>
#include <stdlib.h>
#include <linux/kvm.h>
#include <sys/types.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
  int kvm_fd = open("/dev/kvm", O_RDWR);
  if (kvm_fd < 0) {
    perror("kvm_open");
    return -1;
  }
  int version = ioctl(kvm_fd, KVM_GET_API_VERSION, 0);
  if (version == KVM_API_VERSION) {
    printf("got version %d\n", version);
  } else {
    perror("ioctl");
  }
  return 0;
}

