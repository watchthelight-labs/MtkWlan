// <wtl> project: mtkwlan | file: src/MtkUserClient.hpp | author: watchthelight </wtl>
// MtkWlanUserClient: the IOUserClient of the MtkWlan core for tools/mtkwifi (MtkUserApi.h selectors).
// Scan, join and disconnect need an administrator task; results and status do not. Every call runs on the core's
// work loop gate (MtkWlan::gatedUserCall) and only sets flags or copies snapshots, so it never sleeps in a
// firmware command; it may wait for the gate while a tick is inside one (3 s worst case).

#ifndef MTKUSERCLIENT_HPP
#define MTKUSERCLIENT_HPP

#include <IOKit/IOUserClient.h>
#include "MtkWlan.hpp"

class MtkWlanUserClient : public IOUserClient {
    OSDeclareDefaultStructors(MtkWlanUserClient)

public:
    bool initWithTask(task_t owningTask, void *securityID, UInt32 type, OSDictionary *properties) override;
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    IOReturn clientClose() override;
    IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *args, IOExternalMethodDispatch *dispatch,
                            OSObject *target, void *reference) override;

    // the dispatch table entries (one per MtkUserApi.h selector)
    static IOReturn sScan(OSObject *target, void *ref, IOExternalMethodArguments *args);
    static IOReturn sResults(OSObject *target, void *ref, IOExternalMethodArguments *args);
    static IOReturn sJoin(OSObject *target, void *ref, IOExternalMethodArguments *args);
    static IOReturn sDisconnect(OSObject *target, void *ref, IOExternalMethodArguments *args);
    static IOReturn sStatus(OSObject *target, void *ref, IOExternalMethodArguments *args);
    static IOReturn sTune(OSObject *target, void *ref, IOExternalMethodArguments *args);

private:
    IOReturn call(uint32_t selector, const void *in, void *out, uint32_t *outSize);

    MtkWlan *core = nullptr;
    task_t task = nullptr;
    bool admin = false;
};

#endif
