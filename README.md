kvm-kext
========

An implementation of the kvm interface on OS X. Exposes /dev/kvm in almost the same way Linux does.

Released under GPLv2. Helper functions borrowed from the Linux Kernel.

Description
-----------

kvm (for Kernel-based Virtual Machine) is an interface to run virtual machines with acceleration by the hardware.
kvm-kext implements enough of the kvm API to run Linux accelerated by Intel VMX on OS X.
* https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt

Differences from Linux API
--------------------------

* OS X's ioctl cannot return numbers other than 0 or -1, so we look in errno
* The FD functions do not create new FDs, so you have to set the return value to the current fd in userspace.
  Consequently, only one VM and CPU are allowed per open of /dev/kvm.
* The ioctl's with a 0 length array as the last parameter have to also pass in their user space address.
* KVM_SET_PIT and KVM_SET_IRQCHIP incorrectly used IOR in the Linux header, so the numbers don't match Linux.

See tests/common.h for an __ioctl that fixes these things

mmaping of drivers is not allowed in OS X, so we add an ioctl KVM_MMAP_VCPU to behave like mmaping the VCPU.

Known Issues
------------

* The timer interrupt is generated using a horrible hack, it's sent whenever the host gets an interrupt.
* There's still a bug causing a kernel panic sometimes, mitigated somewhat by a big mutex and disabling
  interrupts in kvm_irq_line. Don't know why this fixes it.
* All memory passed into KVM_SET_USER_MEMORY_REGION is wired in when that ioctl is run.
* The FPU is unimplemented, might leak state between host and guest?
* Currrently, only one VM is supported because vcpu is global. Should be an easy fix.
* APICs and DRs don't work at all.
* Much of the API is still unimplemented.


