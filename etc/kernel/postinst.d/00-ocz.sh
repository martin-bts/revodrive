#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh

export LANG=C

KERNEL_VERSION="$1"
KERNEL_IMAGE="$2"

echo "======Upgrading to $KERNEL_VERSION======" >> /var/log/oczpcie.log 2>&1
if [ ! -d  /lib/modules/$KERNEL_VERSION/extra/oczpcie/ ]; then
	mkdir -p /lib/modules/$KERNEL_VERSION/extra/oczpcie/
fi
cd /usr/src/oczpcie
make clean >> /var/log/oczpcie.log 2>&1
make KERNELDIR=/usr/src/kernels/$KERNEL_VERSION >> /var/log/oczpcie.log 2>&1
cp *.ko /lib/modules/$KERNEL_VERSION/extra/oczpcie/
cd ../oczvca
make clean >> /var/log/oczpcie.log 2>&1
make KERNELDIR=/usr/src/kernels/$KERNEL_VERSION >> /var/log/oczpcie.log 2>&1
cp *.ko /lib/modules/$KERNEL_VERSION/extra/oczpcie/
depmod -aeF "/boot/System.map-$KERNEL_VERSION" $KERNEL_VERSION
dracut --force --kver $KERNEL_VERSION
exit 0
