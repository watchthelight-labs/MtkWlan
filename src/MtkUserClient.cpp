// <wtl> project: mtkwlan | file: src/MtkUserClient.cpp | author: watchthelight </wtl>
// SPDX-License-Identifier: ISC
// See MtkUserClient.hpp. IOUserClientClass in the MtkWlan personality names this class; IOServiceOpen on the
// MtkWlan service creates one per process.

#include "MtkUserClient.hpp"
#include <IOKit/IOLib.h>

OSDefineMetaClassAndStructors(MtkWlanUserClient, IOUserClient)

namespace {
const IOExternalMethodDispatch kMethods[kMtkUcCount] = {
    {&MtkWlanUserClient::sScan, 0, 0, 0, 0},                                            // kMtkUcScan
    {&MtkWlanUserClient::sResults, 0, 0, 0, kIOUCVariableStructureSize},                // kMtkUcResults
    {&MtkWlanUserClient::sJoin, 0, sizeof(mtk_join_params), 0, 0},                      // kMtkUcJoin
    {&MtkWlanUserClient::sDisconnect, 0, 0, 0, 0},                                      // kMtkUcDisconnect
    {&MtkWlanUserClient::sStatus, 0, 0, 0, sizeof(mtk_status)},                         // kMtkUcStatus
    {&MtkWlanUserClient::sTune, 2, 0, 0, 0},                                            // kMtkUcTune
};
} // namespace

bool MtkWlanUserClient::initWithTask(task_t owningTask, void *securityID, UInt32 type, OSDictionary *properties) {
    if (!owningTask || !IOUserClient::initWithTask(owningTask, securityID, type, properties)) return false;
    task = owningTask;
    admin = clientHasPrivilege(securityID, kIOClientPrivilegeAdministrator) == kIOReturnSuccess;
    return true;
}

bool MtkWlanUserClient::start(IOService *provider) {
    core = OSDynamicCast(MtkWlan, provider);
    if (!core || !core->userClientAllowed()) return false;
    if (!IOUserClient::start(provider)) return false;
    setProperty("MtkUcAdmin", admin);
    return true;
}

void MtkWlanUserClient::stop(IOService *provider) {
    core = nullptr;
    IOUserClient::stop(provider);
}

IOReturn MtkWlanUserClient::clientClose() {
    if (!isInactive()) terminate();
    return kIOReturnSuccess;
}

IOReturn MtkWlanUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments *args, IOExternalMethodDispatch *dispatch,
                                           OSObject *target, void *reference) {
    if (selector >= kMtkUcCount) return kIOReturnUnsupported;
    dispatch = const_cast<IOExternalMethodDispatch *>(&kMethods[selector]);
    target = this;
    return IOUserClient::externalMethod(selector, args, dispatch, target, reference);
}

// Run one selector on the core's gate. Scan / join / disconnect change state and need an administrator.
IOReturn MtkWlanUserClient::call(uint32_t selector, const void *in, void *out, uint32_t *outSize) {
    if (!core || !core->userClientAllowed()) return kIOReturnNotReady;
    if ((selector == kMtkUcScan || selector == kMtkUcJoin || selector == kMtkUcDisconnect || selector == kMtkUcTune) && !admin) return kIOReturnNotPrivileged;
    IOWorkLoop *wl = core->getWorkLoop();
    if (!wl) return kIOReturnNotReady;
    return wl->runAction(&MtkWlan::gatedUserCall, core, (void *)(uintptr_t)selector, const_cast<void *>(in), out, outSize);
}

IOReturn MtkWlanUserClient::sScan(OSObject *target, void *, IOExternalMethodArguments *) {
    MtkWlanUserClient *uc = OSDynamicCast(MtkWlanUserClient, target);
    if (!uc) return kIOReturnBadArgument;
    return uc->call(kMtkUcScan, nullptr, nullptr, nullptr);
}

IOReturn MtkWlanUserClient::sResults(OSObject *target, void *, IOExternalMethodArguments *a) {
    MtkWlanUserClient *uc = OSDynamicCast(MtkWlanUserClient, target);
    if (!uc || !a || !a->structureOutput) return kIOReturnBadArgument;
    uint32_t sz = a->structureOutputSize;
    IOReturn r = uc->call(kMtkUcResults, nullptr, a->structureOutput, &sz);
    if (r == kIOReturnSuccess) a->structureOutputSize = sz;
    return r;
}

IOReturn MtkWlanUserClient::sJoin(OSObject *target, void *, IOExternalMethodArguments *a) {
    MtkWlanUserClient *uc = OSDynamicCast(MtkWlanUserClient, target);
    if (!uc || !a || !a->structureInput || a->structureInputSize != sizeof(mtk_join_params)) return kIOReturnBadArgument;
    return uc->call(kMtkUcJoin, a->structureInput, nullptr, nullptr);
}

IOReturn MtkWlanUserClient::sDisconnect(OSObject *target, void *, IOExternalMethodArguments *) {
    MtkWlanUserClient *uc = OSDynamicCast(MtkWlanUserClient, target);
    if (!uc) return kIOReturnBadArgument;
    return uc->call(kMtkUcDisconnect, nullptr, nullptr, nullptr);
}

IOReturn MtkWlanUserClient::sStatus(OSObject *target, void *, IOExternalMethodArguments *a) {
    MtkWlanUserClient *uc = OSDynamicCast(MtkWlanUserClient, target);
    if (!uc || !a || !a->structureOutput || a->structureOutputSize < sizeof(mtk_status)) return kIOReturnBadArgument;
    uint32_t sz = a->structureOutputSize;
    IOReturn r = uc->call(kMtkUcStatus, nullptr, a->structureOutput, &sz);
    if (r == kIOReturnSuccess) a->structureOutputSize = sz;
    return r;
}

IOReturn MtkWlanUserClient::sTune(OSObject *target, void *, IOExternalMethodArguments *a) {
    MtkWlanUserClient *uc = OSDynamicCast(MtkWlanUserClient, target);
    if (!uc || !a || a->scalarInputCount != 2) return kIOReturnBadArgument;
    uint32_t kv[2] = {(uint32_t)a->scalarInput[0], (uint32_t)a->scalarInput[1]};
    return uc->call(kMtkUcTune, kv, nullptr, nullptr);
}
