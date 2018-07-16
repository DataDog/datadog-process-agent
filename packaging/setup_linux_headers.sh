#!/bin/sh
set -xe

# Simplified setup of linux headers, based on build from:
# https://github.com/richfelker/musl-cross-make/blob/master/litecross/Makefile#L266

LINUX_SITE=https://cdn.kernel.org/pub/linux/kernel

LINUX_KERNEL_VER=linux-4.4.10
KERNEL_TAR="${LINUX_KERNEL_VER}.tar.xz"
ARCH=x86

HEADER_BASE_PATH=/kernel-headers

mkdir -p $HEADER_BASE_PATH

# Download and extract header files
wget -c "${LINUX_SITE}/v4.x/${KERNEL_TAR}"
tar -Jxvf $KERNEL_TAR --directory $HEADER_BASE_PATH && rm -rf $KERNEL_TAR

# Install the headers
cd "${HEADER_BASE_PATH}/${LINUX_KERNEL_VER}"
mkdir -p /obj_kernel_headers/staged

make ARCH=$ARCH O=$PWD/obj_kernel_headers INSTALL_HDR_PATH=$PWD/obj_kernel_headers/staged headers_install
find $PWD/obj_kernel_headers/staged/include '(' -name .install -o -name ..install.cmd ')' -exec rm {} +

# Final location for use in our apps
mkdir -p $HEADER_BASE_PATH/include
cp -R $PWD/obj_kernel_headers/staged/include/* $HEADER_BASE_PATH/include