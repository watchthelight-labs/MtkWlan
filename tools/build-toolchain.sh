#!/bin/bash
# <wtl> project: mtkwlan | file: tools/build-toolchain.sh | author: watchthelight </wtl>
# Sets up the cross toolchain on Ubuntu 24.04 (native or WSL), as root:
#   clang/llvm from apt, Apple's ld64 from cctools-port, libdispatch (ld64 needs it),
#   and MacKernelSDK cloned next to the Makefile. Every upstream is pinned to the commit
#   MtkWlan was built with. Installs to /opt/dispatch and /opt/cctools.
set -e
export DEBIAN_FRONTEND=noninteractive
HERE=$(cd "$(dirname "$0")/.." && pwd)
apt-get install -y -qq git clang lld llvm make cmake ninja-build autoconf automake libtool libblocksruntime-dev python3 >/dev/null
mkdir -p /root/build
cd /root/build

pin() {   # pin <url> <dir> <commit>
  [ -d "$2" ] || git clone -q "$1" "$2"
  git -C "$2" fetch -q origin "$3" 2>/dev/null || true
  git -C "$2" checkout -q "$3"
}

# MacKernelSDK (headers, libkmod)
pin https://github.com/acidanthera/MacKernelSDK "$HERE/MacKernelSDK" 3f750085caa17ec3a7880f11c11bf4f48cd6a164

# libdispatch + BlocksRuntime
if [ ! -f /opt/dispatch/lib/libdispatch.so ]; then
  pin https://github.com/swiftlang/swift-corelibs-libdispatch libdispatch ce1b4d3540427a8c8a17a3b5eb7c5749665d384e
  cmake -S libdispatch -B libdispatch/out -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/opt/dispatch >/dev/null
  ninja -C libdispatch/out >/dev/null
  ninja -C libdispatch/out install >/dev/null
fi

# ld64 (cctools-port)
if [ ! -x /opt/cctools/bin/x86_64-apple-darwin-ld ]; then
  pin https://github.com/tpoechtrager/cctools-port cctools-port 904de2a71d4da6a9b30d2efaf912a10ddc7d9ddb
  cd cctools-port/cctools
  ./autogen.sh >/dev/null 2>&1 || true
  CC=clang CXX=clang++ ./configure --prefix=/opt/cctools --target=x86_64-apple-darwin \
    --with-libdispatch=/opt/dispatch --with-libblocksruntime=/opt/dispatch >/dev/null
  make -j"$(nproc)" >/dev/null
  make install >/dev/null
fi

LD_LIBRARY_PATH=/opt/dispatch/lib /opt/cctools/bin/x86_64-apple-darwin-ld -v 2>&1 | head -1
echo "toolchain ready; run make in $HERE"
