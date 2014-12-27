#!/bin/bash -e
./build.sh
./get-qemu.sh
qemu-2.2.0/i386-softmmu/qemu-system-i386 -m 32MB -fda bintest/bootfd.img -net none -nographic -enable-kvm
tail /var/log/system.log

