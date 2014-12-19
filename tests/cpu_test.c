// inspired by https://kernel.googlesource.com/pub/scm/virt/kvm/mst/qemu/+/kvm-8/kvm/user/kvmctl.c

#include "common.h"
#include <sys/mman.h>
#include <string.h>

// 4MB
#define RAM_SIZE 0x400000
#define ENTRY_POINT 0x100000
#define MB 0x80000

void loop() {
  while (1) {
    printf("real talk\n");
    sleep(1);
  }
}

void enter_32(int vcpu_fd) {
  struct kvm_regs regs = {
    .rsp = 0x80000,  /* 512KB */
    .rip = ENTRY_POINT, /* 1MB */
    .rflags = 2,
  };
  struct kvm_sregs sregs = {
    .cs = { 0, -1u,  8, 11, 1, 0, 1, 1, 0, 1, 0, 0 },
    .ds = { 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 },
    .es = { 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 },
    .fs = { 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 },
    .gs = { 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 },
    .ss = { 0, -1u, 16,  3, 1, 0, 1, 1, 0, 1, 0, 0 },

    .tr = { 0, 10000, 24, 11, 1, 0, 0, 0, 0, 0, 0, 0 },
    .ldt = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    .gdt = { 0, 0 },
    .idt = { 0, 0 },
    .cr0 = 0x37,
    .cr3 = 0,
    .cr4 = 0x2000,  // VMXE bit is required?
    .efer = 0,
    .apic_base = 0,
    .interrupt_bitmap = { 0 },
  };

  kvm_ioctl(vcpu_fd, KVM_SET_REGS, &regs);
  kvm_ioctl(vcpu_fd, KVM_SET_SREGS, &sregs);
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

int main(int argc, char *argv[]) {
  int err;
  int kvm_fd = open("/dev/kvm", O_RDWR);
  int vm_fd = kvm_ioctl(kvm_fd, KVM_CREATE_VM, 0);

  __u8 *guest_ram = (__u8 *)mmap(NULL, RAM_SIZE, 7, MAP_ANON|MAP_SHARED, -1, 0);
  printf("guest ram @ %p\n", guest_ram);

  // nops
  memset(guest_ram, 0x90, RAM_SIZE);
  guest_ram[ENTRY_POINT + 0x10] = 0x40;  // inc eax
  guest_ram[ENTRY_POINT + 0x11] = 0xf4;  // inc eax

  struct kvm_userspace_memory_region low_memory = {
    .slot = 3,
    .flags = 0,
    .memory_size = RAM_SIZE,
    .guest_phys_addr = 0,
    .userspace_addr = (__u64)guest_ram,
  };
  err = kvm_ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &low_memory);
  printf("memory set up: %d\n", err);


  int vcpu_fd = kvm_ioctl(vm_fd, KVM_CREATE_VCPU, 0);
  printf("three fds %d %d %d\n", kvm_fd, vm_fd, vcpu_fd);
  enter_32(vcpu_fd);

  kvm_show_regs(vcpu_fd, 0);

  /*int size = kvm_ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
  printf("vcpu size: 0x%x\n", size);
  struct kvm_run *run = (struct kvm_run *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);*/

  printf("running in one second\n");
  //sleep(1);
  err = kvm_ioctl(vcpu_fd, KVM_RUN, 0);
  printf("running...%d\n", err);
  //sleep(1);
  //sleep(1);

  kvm_show_regs(vcpu_fd, 0);
  //printf("exit code %d suberror %d\n", run->exit_reason, run->internal.suberror);
}

