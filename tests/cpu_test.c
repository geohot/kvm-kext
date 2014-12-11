// inspired by https://kernel.googlesource.com/pub/scm/virt/kvm/mst/qemu/+/kvm-8/kvm/user/kvmctl.c

#include "common.h"
#include <sys/mman.h>
#include <string.h>

void loop() {
  while (1) {
    printf("real talk\n");
    sleep(1);
  }
}

void kvm_show_regs(int vcpu_fd, int vcpu) {
  struct kvm_regs regs;
  int r;
  r = kvm_ioctl(vcpu_fd, KVM_GET_REGS, &regs);
  fprintf(stderr,
    "rax %016llx rbx %016llx rcx %016llx rdx %016llx\n"
    "rsi %016llx rdi %016llx rsp %016llx rbp %016llx\n"
    "r8  %016llx r9  %016llx r10 %016llx r11 %016llx\n"
    "r12 %016llx r13 %016llx r14 %016llx r15 %016llx\n"
    "rip %016llx rflags %08llx\n",
    regs.rax, regs.rbx, regs.rcx, regs.rdx,
    regs.rsi, regs.rdi, regs.rsp, regs.rbp,
    regs.r8,  regs.r9,  regs.r10, regs.r11,
    regs.r12, regs.r13, regs.r14, regs.r15,
    regs.rip, regs.rflags);
}

#define RAM_SIZE 0xa0000

int main(int argc, char *argv[]) {
  int err;
  int kvm_fd = open("/dev/kvm", O_RDWR);
  int vm_fd = kvm_ioctl(kvm_fd, KVM_CREATE_VM, 0);

  __u8 *guest_ram = (__u8 *)mmap(NULL, RAM_SIZE, 7, MAP_ANON|MAP_SHARED, -1, 0);
  printf("guest ram @ %p\n", guest_ram);

  struct kvm_userspace_memory_region low_memory = {
    .slot = 3,
    .flags = 0,
    .memory_size = RAM_SIZE,
    .guest_phys_addr = 0,
    .userspace_addr = (__u64)guest_ram,
  };
  err = kvm_ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &low_memory);
  printf("memory set up: %d\n", err);

  // nops
  memset(guest_ram, 0x90, RAM_SIZE);
  guest_ram[0xFFF1] = 0xeb;
  guest_ram[0xFFF2] = 0xfe;

  int vcpu_fd = kvm_ioctl(vm_fd, KVM_CREATE_VCPU, 0);
  printf("three fds %d %d %d\n", kvm_fd, vm_fd, vcpu_fd);

  kvm_show_regs(vcpu_fd, 0);

  int size = kvm_ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
  printf("vcpu size: 0x%x\n", size);
  struct kvm_run *run = (struct kvm_run *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);

  err = kvm_ioctl(vcpu_fd, KVM_RUN, 0);
  printf("running...%d\n", err);
  usleep(1000*100);

  kvm_show_regs(vcpu_fd, 0);
  printf("exit code %d suberror %d\n", run->exit_reason, run->internal.suberror);
}

