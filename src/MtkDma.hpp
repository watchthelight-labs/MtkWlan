// <wtl> project: mtkwlan | file: src/MtkDma.hpp | author: watchthelight </wtl>
// DMA memory for the MT7925: one physically contiguous block, mapped for the device through
// IODMACommand (so AppleVTD/IOMapper translates it), with a device address below 4 GB because
// mt7925_pci_probe sets a 32-bit DMA mask.

#ifndef MTKDMA_HPP
#define MTKDMA_HPP

#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IODMACommand.h>
#include <IOKit/IOMapper.h>

struct MtkDmaMem {
    IOBufferMemoryDescriptor *bmd = nullptr;
    IODMACommand *cmd = nullptr;
    uint8_t *va = nullptr;
    uint32_t iova = 0;   // device-visible address
    uint32_t len = 0;

    // Returns 0 on success, or a step number (1..5) that failed, for logging
    // mapper: the device's own IOMapper (IOMapper::copyMapperForDevice), so VT-d maps the
    // buffer into the MT7925's translation context
    int alloc(uint32_t size, IOMapper *mapper, uint32_t align = 4096);
    void free();
    // x86 PCIe DMA is cache coherent, so these only order CPU accesses around the device
    void toDevice() { __asm__ volatile("mfence" ::: "memory"); }
    void fromDevice() { __asm__ volatile("mfence" ::: "memory"); }
};

#endif
