#!/bin/bash -e

if [ ! -d qemu-2.2.0 ]; then
  wget http://wiki.qemu-project.org/download/qemu-2.2.0.tar.bz2
  tar xf qemu-2.2.0.tar.bz2
  rm qemu-2.2.0.tar.bz2
fi


if [ ! -f qemu-2.2.0/i386-softmmu/qemu-system-i386 ]; then
  pushd .
  cd qemu-2.2.0
  patch -p1 < ../qemu.patch
  ./configure --target-list=i386-softmmu --enable-kvm --enable-trace-backend=stderr --extra-cflags="-I $(pwd)/../include"
  make -j8
  popd
fi

