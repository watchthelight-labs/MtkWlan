// <wtl> project: mtkwlan | file: src/MtkDma.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC

#include "MtkDma.hpp"
#include <IOKit/IOLib.h>

int MtkDmaMem::alloc(uint32_t size, IOMapper *mapper, uint32_t align) {
    size = (size + align - 1) & ~(align - 1);
    // physically contiguous, below 4 GB physical as well, in case the mapper is off
    bmd = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task,
              kIODirectionInOut | kIOMemoryPhysicallyContiguous, size, 0x00000000FFFFF000ULL);
    if (!bmd)
        return 1;
    if (bmd->prepare() != kIOReturnSuccess) {
        OSSafeReleaseNULL(bmd);
        return 2;
    }
    cmd = IODMACommand::withSpecification(kIODMACommandOutputHost64, 32, 0,
                                          IODMACommand::kMapped, 0, align, mapper);
    if (!cmd) {
        free();
        return 3;
    }
    if (cmd->setMemoryDescriptor(bmd, true) != kIOReturnSuccess) {
        free();
        return 4;
    }
    IODMACommand::Segment64 seg = {};
    UInt64 offset = 0;
    UInt32 nseg = 1;
    if (cmd->gen64IOVMSegments(&offset, &seg, &nseg) != kIOReturnSuccess || nseg != 1 ||
        seg.fLength < size || (seg.fIOVMAddr + size) > 0x100000000ULL) {
        free();
        return 5;
    }
    va = (uint8_t *)bmd->getBytesNoCopy();
    iova = (uint32_t)seg.fIOVMAddr;
    phys = bmd->getPhysicalSegment(0, nullptr, kIOMemoryMapperNone);
    len = size;
    bzero(va, size);
    return 0;
}

void MtkDmaMem::free() {
    if (cmd) {
        cmd->clearMemoryDescriptor(true);
        OSSafeReleaseNULL(cmd);
    }
    if (bmd) {
        bmd->complete();
        OSSafeReleaseNULL(bmd);
    }
    va = nullptr;
    iova = 0;
    len = 0;
}
