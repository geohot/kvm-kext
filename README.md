kvm-kext
========

An implementation of the kvm interface on OS X.
Exposes /dev/kvm in almost the same way Linux does(see below for differences).

Project for 15-412 by George Hotz. Released under GPLv2. Helper functions borrowed from the Linux Kernel.
Currently capable of booting the virtual Linux system in bintest/bootfd.img.

Do not rely on this for any sort of secure virtualization. /dev/kvm is currently world owned.

Description
-----------

kvm (for Kernel-based Virtual Machine) is an interface to run virtual machines with acceleration by the hardware.
kvm-kext implements enough of the kvm API to run 32-bit Linux accelerated by Intel VMX on OS X and put a console on a serial port.
* https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt

Usage
-----

Installing KEXT

* ./build.sh should build and install the kext
* See https://github.com/Homebrew/homebrew/issues/31164 for cause of issues with 10.10 
* Use "nvram boot-args=kext-dev-mode=1" to fix. This is a dangerous command.
* Currently doesn't codesign since the above fix doesn't require it.

Building QEMU with kvm support

* ./get-qemu.sh should just work, doesn't install
* Based on qemu-2.2.0 and makes two minor patches

Booting Test Linux

* ./test.sh

Differences from Linux API
--------------------------

* OS X's ioctl cannot return numbers other than 0 or -1, so we look in errno
* The FD functions do not create new FDs, so you have to set the return value to the current fd in userspace.
  Consequently, only one VM and CPU are allowed per open of /dev/kvm.
* The ioctl's with a 0 length array as the last parameter have to also pass in their user space address.
* KVM_SET_PIT and KVM_SET_IRQCHIP incorrectly used IOR in the Linux header, so the numbers don't match Linux.

mmaping of drivers is not allowed in OS X, so we add an ioctl KVM_MMAP_VCPU to behave like mmaping the VCPU.

See include/kvm-kext-fixes.h for fixes to these issues

Known Issues
------------

* The timer interrupt is generated using the host timer. Is this correct behavior?
* There's still a bug causing a kernel panic sometimes, mitigated somewhat by a big mutex and disabling
  interrupts in kvm_irq_line. Don't know why this fixes it.
* All memory passed into KVM_SET_USER_MEMORY_REGION is wired in when that ioctl is run.
* The FPU is unimplemented, might leak state between host and guest?
* APICs and DRs don't work at all.
* Much of the API is still unimplemented.
* QEMU VGA doesn't seem to work, unsure why. MMIO?
* Nothing is freed ever.

