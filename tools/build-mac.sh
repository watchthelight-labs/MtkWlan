#!/bin/bash
# <wtl> project: mtkwlan | file: tools/build-mac.sh | author: watchthelight </wtl>
# Native build on macOS with the Command Line Tools SDK (no MacKernelSDK clone, no Linux box).
# Output: out/MtkWlan.kext, plus out/undefined.txt (what the kernel must resolve) and
# out/libraries.txt (what kmutil says those symbols need, read-only check). Nothing is loaded or installed.
# The build is reproducible: the same sources with the same Apple clang give the same binary.
set -euo pipefail
cd "$(dirname "$0")/.."
NAME=MtkWlan
# one source list for both builds: the SRCS lines of the Makefile (out/gen/MtkFirmware.c is generated below)
SRCS=$(awk '/^SRCS *:=/{sub(/^SRCS *:= */,""); s=$0; while (s ~ /\\$/) {sub(/\\$/,"",s); getline; s=s $0}; print s}' Makefile)
PB=/usr/libexec/PlistBuddy
KEXT_ID=$($PB -c 'Print :CFBundleIdentifier' Info.plist)
KEXT_VERSION=$($PB -c 'Print :CFBundleVersion' Info.plist)
grep -q "KEXT_VERSION := $KEXT_VERSION\$" Makefile || { echo "FAIL: Makefile KEXT_VERSION differs from Info.plist $KEXT_VERSION"; exit 1; }

SDK=$(xcrun --sdk macosx --show-sdk-path)
K=$SDK/System/Library/Frameworks/Kernel.framework/Headers
RES=$(clang -print-resource-dir)
OUT=out/$NAME.kext/Contents
rm -rf out/$NAME.kext out/obj
mkdir -p "$OUT/MacOS" out/obj out/gen

# firmware blobs from firmware/, checked against firmware/SHA256SUMS
python3 tools/gen_firmware.py out/gen/MtkFirmware.c

# the SDK marks IOPCIDevice and IOEthernet* deprecated (DriverKit); MacKernelSDK in the Linux build does not
FLAGS="-arch x86_64 -mmacosx-version-min=10.15 -mkernel -nostdinc -fno-builtin -fno-common -fno-stack-protector
 -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -DAPPLE -DNeXT -isystem $RES/include -I$K -Isrc -O2 -g0 -Wall -Wno-unused-parameter
 -Wno-deprecated-declarations"
CXXFLAGS="$FLAGS -fapple-kext -std=gnu++17 -nostdinc++ -fno-exceptions -fno-rtti -fno-use-cxa-atexit
 -fno-register-global-dtors-with-atexit -Wno-inconsistent-missing-override"
OBJS=""
for s in $SRCS; do
  o=out/obj/$(basename "${s%.*}").o
  case "$s" in
    *.cpp) clang++ $CXXFLAGS -c "$s" -o "$o" ;;
    *.c)   clang $FLAGS -std=gnu11 -c "$s" -o "$o" ;;
  esac
  OBJS="$OBJS $o"
done
clang $FLAGS -std=gnu11 -DKEXT_ID=$KEXT_ID -DKEXT_VERSION="\"$KEXT_VERSION\"" \
  -c src/kmod_info.c -o out/obj/kmod_info.o
# the SDK's libkmod objects say macOS 15.5, which ld notes against the 10.15 minimum (harmless)
clang++ -arch x86_64 -mmacosx-version-min=10.15 -nostdlib -Xlinker -kext -Xlinker -export_dynamic \
  $OBJS out/obj/kmod_info.o -L"$SDK/usr/lib" -lkmodc++ -lkmod "$RES/lib/darwin/libclang_rt.cc_kext.a" \
  -o "$OUT/MacOS/$NAME" 2>&1 | grep -v 'was built for newer macOS version' >&2 || true
[ -f "$OUT/MacOS/$NAME" ] || { echo "FAIL: link"; exit 1; }
cp Info.plist "$OUT/Info.plist"

# offline checks: MH_KEXT_BUNDLE, kmod_info, what the kernel must resolve, no C++ runtime it lacks
BIN=$OUT/MacOS/$NAME
otool -hv "$BIN" | grep -q KEXTBUNDLE && echo "filetype: MH_KEXT_BUNDLE" || { echo "FAIL: not MH_KEXT_BUNDLE"; exit 1; }
nm "$BIN" | grep -q ' _kmod_info$' && echo "kmod_info: present" || { echo "FAIL: no kmod_info"; exit 1; }
nm -u "$BIN" | sort > out/undefined.txt
echo "undefined symbols: $(wc -l < out/undefined.txt | tr -d ' ') (out/undefined.txt)"
if grep -E '^_{2,3}(cxa_|Unwind|gxx_)|^__ZTV.*__cxxabiv|^__Znw|^__Zdl' out/undefined.txt; then
  echo "FAIL: C++ runtime symbols the kernel does not export"; exit 1
fi
# which OSBundleLibraries the undefined symbols need (kmutil reads the installed kernel collections, changes nothing)
if kmutil libraries -p out/$NAME.kext --xml > out/libraries.plist 2> out/libraries.err; then
  plutil -p out/libraries.plist > out/libraries.txt
  echo "kmutil libraries: out/libraries.txt"
else
  echo "kmutil libraries: failed (out/libraries.err)"
fi
echo "built $KEXT_ID $KEXT_VERSION: $BIN ($(stat -f %z "$BIN") bytes)"
echo "sha256: $(shasum -a 256 "$BIN" | cut -c1-64)"
