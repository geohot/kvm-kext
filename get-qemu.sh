#!/bin/sh

if [ ! -d qemu-2.2.0 ]; then
  wget http://wiki.qemu-project.org/download/qemu-2.2.0.tar.bz2
  tar xf qemu-2.2.0.tar.bz2
  rm qemu-2.2.0.tar.bz2
fi


pushd .
cd qemu-2.2.0
./configure --target-list=i386-softmmu --enable-kvm --enable-trace-backend=stderr

popd

