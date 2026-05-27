//
// --------------------------------------------------------------------------
// HIDPPListener.mm
// Created for Mac Mouse Fix (https://github.com/noah-nuebling/mac-mouse-fix)
// Created by Pradyumna Krishna in 2026
// Refactored with Logitech CID activation logic by Miguel Angelo in 2026
// Licensed under the MMF License (https://github.com/noah-nuebling/mac-mouse-fix/blob/master/License)
// --------------------------------------------------------------------------
//

#import "HIDPPListener.h"

#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/hid/IOHIDKeys.h>
#import <IOKit/hid/IOHIDLib.h>

#import <algorithm>
#import <set>
#import <vector>

#import "DeviceManager.h"

/// Logitech HID++ 2.0 REPROG_CONTROLS_V4 support.
///
/// This listener asks Logitech firmware to divert controls that are normally
/// consumed by the device, then forwards the resulting CID notifications
/// directly into Mac Mouse Fix's button pipeline.

static constexpr uint16_t kLogitechVendorID = 0x046D;
static constexpr uint8_t kHIDPPReportLong = 0x11;
static constexpr uint8_t kHIDPPDeviceIndex = 0xFF;
static constexpr uint16_t kHIDPPFeatureReprogControlsV4 = 0x1B04;
static constexpr uint8_t kHIDPPDivertFlags = 0x03; // divert + divert_valid
static constexpr uint8_t kHIDPPDivertOffFlags = 0x02; // !divert + divert_valid
static constexpr uint8_t kHIDPPGetFeature = 0x0E;
static constexpr uint8_t kHIDPPGetCount = 0x0E;
static constexpr uint8_t kHIDPPGetCidInfo = 0x1E;
static constexpr uint8_t kHIDPPSetCidReporting = 0x3E;
static constexpr int kFirstExtraButtonNumber = 6;
static constexpr int64_t kHIDPPEventTag = 0x4D4D4648; // "MMFH"
static constexpr int kHIDPPMaxActivationAttempts = 30;
static constexpr NSTimeInterval kHIDPPActivationRetryDelay = 1.0;

static constexpr uint16_t kTIDBack = 0x003C;
static constexpr uint16_t kTIDForward = 0x003E;

/// TIDs we should never divert because taking them over would break primary click input.
static constexpr uint16_t kPrimaryButtonTIDs[] = {
    0x0038, // left
    0x0039, // right
    0x003A, // middle
};

typedef struct {
    uint16_t cid;
    int buttonNumber;
    CGMouseButton cgButton;
} HIDPPCIDMapping;

static CFMachPortRef sDragTap = (CFMachPortRef)NULL;
static CFRunLoopSourceRef sDragTapSource = (CFRunLoopSourceRef)NULL;
static std::set<CGMouseButton> sHeldButtons;

static uint64_t registryIDForDevice(IOHIDDeviceRef device)
{
    io_service_t service = IOHIDDeviceGetService(device);
    uint64_t rid = 0;
    IORegistryEntryGetRegistryEntryID(service, &rid);
    return rid;
}

static uint64_t ioHIDDeviceUIntProperty(IOHIDDeviceRef device, CFStringRef key)
{
    if (!device || !key) return 0;
    CFTypeRef ref = IOHIDDeviceGetProperty(device, key);
    if (!ref || CFGetTypeID(ref) != CFNumberGetTypeID()) return 0;

    uint64_t value = 0;
    CFNumberGetValue((CFNumberRef)ref, kCFNumberSInt64Type, &value);
    return value;
}

static bool isPrimaryButtonTID(uint16_t tid)
{
    for (uint16_t primaryTID : kPrimaryButtonTIDs) {
        if (primaryTID == tid) return true;
    }
    return false;
}

static uint16_t readUInt16(const uint8_t *bytes)
{
    return ((uint16_t)bytes[0] << 8) | bytes[1];
}

static CGEventSourceRef sharedSource(void)
{
    static CGEventSourceRef source = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        source = CGEventSourceCreate(kCGEventSourceStateHIDSystemState);
    });
    return source;
}

static inline void tagEvent(CGEventRef event)
{
    if (!event) return;
    CGEventSetIntegerValueField(event, kCGEventSourceUserData, kHIDPPEventTag);
}

static inline bool isTaggedEvent(CGEventRef event)
{
    if (!event) return false;
    return CGEventGetIntegerValueField(event, kCGEventSourceUserData) == kHIDPPEventTag;
}

static CGPoint currentMouseLocation(void)
{
    CGEventRef event = CGEventCreate(sharedSource());
    CGPoint location = CGEventGetLocation(event);
    CFRelease(event);
    return location;
}

static void postButtonEvent(CGMouseButton button, bool down)
{
    CGEventRef event = CGEventCreateMouseEvent(sharedSource(),
                                               down ? kCGEventOtherMouseDown : kCGEventOtherMouseUp,
                                               currentMouseLocation(),
                                               button);
    if (!event) return;

    CGEventSetIntegerValueField(event, kCGMouseEventButtonNumber, button);
    CGEventSetIntegerValueField(event, kCGMouseEventPressure, down ? 1 : 0);
    tagEvent(event);
    CGEventPost(kCGHIDEventTap, event);
    CFRelease(event);
}

static CGEventRef dragTapCallback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *refcon)
{
    if (type == kCGEventTapDisabledByTimeout || type == kCGEventTapDisabledByUserInput) {
        if (sDragTap) CGEventTapEnable(sDragTap, true);
        return event;
    }

    if (isTaggedEvent(event)) return event;

    if (!sHeldButtons.empty()) {
        CGPoint location = CGEventGetLocation(event);
        for (CGMouseButton button : sHeldButtons) {
            CGEventRef drag = CGEventCreateMouseEvent(sharedSource(),
                                                      kCGEventOtherMouseDragged,
                                                      location,
                                                      button);
            if (!drag) continue;

            CGEventSetIntegerValueField(drag, kCGMouseEventButtonNumber, button);
            tagEvent(drag);
            CGEventPost(kCGSessionEventTap, drag);
            CFRelease(drag);
        }
    }

    return event;
}

static void ensureDragTap(void)
{
    if (sDragTap != NULL) {
        CGEventTapEnable(sDragTap, true);
        return;
    }

    CGEventMask mask = CGEventMaskBit(kCGEventMouseMoved) |
                       CGEventMaskBit(kCGEventLeftMouseDragged) |
                       CGEventMaskBit(kCGEventRightMouseDragged) |
                       CGEventMaskBit(kCGEventOtherMouseDragged);

    sDragTap = CGEventTapCreate(kCGHIDEventTap,
                                kCGHeadInsertEventTap,
                                kCGEventTapOptionListenOnly,
                                mask,
                                dragTapCallback,
                                NULL);
    if (!sDragTap) {
        NSLog(@"[HIDPP] Could not create drag event tap");
        return;
    }

    sDragTapSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, sDragTap, 0);
    CFRunLoopAddSource(CFRunLoopGetMain(), sDragTapSource, kCFRunLoopCommonModes);
}

@interface HIDPPListener () {
    IOHIDDeviceRef _iohid;
    uint64_t _registryID;
    uint8_t _reportBuffer[64];
    uint8_t _lastResponse[20];
    BOOL _gotResponse;
    BOOL _running;
    BOOL _scheduled;
    int _activationAttempts;
    uint8_t _featureIndex;
    std::vector<HIDPPCIDMapping> _cidMappings;
    std::set<uint16_t> _pressedCIDs;
    NSTimer *_activationRetryTimer;
    NSTimer *_reactivateTimer;
}

- (void)handleReport:(const uint8_t *)report length:(CFIndex)length;
- (void)handleReportError:(IOReturn)result;
- (void)reactivateWithRetryReset:(BOOL)reset;
- (void)attemptActivation;
- (void)scheduleActivationRetry;
- (void)handleActivationRetryTimer:(NSTimer *)timer;

@end

static void inputReportCallback(void *context,
                                IOReturn result,
                                void *sender,
                                IOHIDReportType type,
                                uint32_t reportID,
                                uint8_t *report,
                                CFIndex len)
{
    HIDPPListener *listener = (__bridge HIDPPListener *)context;
    if (result != kIOReturnSuccess) {
        [listener handleReportError:result];
        return;
    }
    if (len < 5 || report[0] != kHIDPPReportLong) return;

    [listener handleReport:report length:len];
}

@implementation HIDPPListener

- (instancetype)initWithDevice:(IOHIDDeviceRef)device
{
    self = [super init];
    if (self) {
        _iohid = device;
        CFRetain(_iohid);
        _registryID = registryIDForDevice(device);
        _featureIndex = 0;
    }
    return self;
}

- (void)dealloc
{
    [self stop];
    if (_iohid) CFRelease(_iohid);
}

- (uint64_t)registryID
{
    return _registryID;
}

- (BOOL)start:(NSError * _Nullable __autoreleasing *)error
{
    if (_running) return YES;

    uint16_t vendorID = (uint16_t)ioHIDDeviceUIntProperty(_iohid, CFSTR(kIOHIDVendorIDKey));
    if (vendorID != kLogitechVendorID) {
        if (error) {
            *error = [NSError errorWithDomain:@"HIDPP"
                                         code:11
                                     userInfo:@{NSLocalizedDescriptionKey: @"Non-Logitech device"}];
        }
        return NO;
    }

    IOHIDDeviceRegisterInputReportCallback(_iohid,
                                           _reportBuffer,
                                           sizeof(_reportBuffer),
                                           inputReportCallback,
                                           (__bridge void *)self);
    IOHIDDeviceScheduleWithRunLoop(_iohid, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
    _scheduled = YES;
    _running = YES;
    ensureDragTap();

    [[[NSWorkspace sharedWorkspace] notificationCenter] addObserver:self
                                                           selector:@selector(reactivate)
                                                               name:NSWorkspaceDidWakeNotification
                                                             object:nil];

    _reactivateTimer = [NSTimer scheduledTimerWithTimeInterval:60 * 30
                                                        target:self
                                                      selector:@selector(reactivate)
                                                      userInfo:nil
                                                       repeats:YES];

    [self reactivateWithRetryReset:YES];
    NSLog(@"[HIDPP] Started listener for registryID %llu", _registryID);
    return YES;
}

- (void)stop
{
    if (!_running && !_scheduled) return;

    [[[NSWorkspace sharedWorkspace] notificationCenter] removeObserver:self];
    [_activationRetryTimer invalidate];
    _activationRetryTimer = nil;
    [_reactivateTimer invalidate];
    _reactivateTimer = nil;

    for (uint16_t cid : _pressedCIDs) {
        [self postCID:cid down:false];
    }
    _pressedCIDs.clear();

    if (_featureIndex != 0) {
        for (HIDPPCIDMapping mapping : _cidMappings) {
            [self setCidReportingForCID:mapping.cid flags:kHIDPPDivertOffFlags];
        }
    }

    [self unschedule];
    _running = NO;
    _activationAttempts = 0;
    _featureIndex = 0;
    _cidMappings.clear();

    NSLog(@"[HIDPP] Stopped listener for registryID %llu", _registryID);
}

- (void)unschedule
{
    if (!_scheduled) return;
    IOHIDDeviceUnscheduleFromRunLoop(_iohid, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
    _scheduled = NO;
}

- (void)reactivate
{
    if (!_running) return;
    [self reactivateWithRetryReset:YES];
}

- (void)reactivateWithRetryReset:(BOOL)reset
{
    if (!_running) return;
    if (reset) {
        _activationAttempts = 0;
        [_activationRetryTimer invalidate];
        _activationRetryTimer = nil;
    }

    [self attemptActivation];
}

- (void)attemptActivation
{
    if (!_running) return;

    int divertedCount = [self activateDevice];
    if (divertedCount > 0) {
        _activationAttempts = 0;
        [_activationRetryTimer invalidate];
        _activationRetryTimer = nil;
        NSLog(@"[HIDPP] Activated %d Logitech CID(s) for registryID %llu", divertedCount, _registryID);
        return;
    }

    [self scheduleActivationRetry];
}

- (void)scheduleActivationRetry
{
    if (!_running || _activationRetryTimer != nil) return;
    if (_activationAttempts >= kHIDPPMaxActivationAttempts) {
        NSLog(@"[HIDPP] Activation timed out for registryID %llu", _registryID);
        return;
    }

    _activationAttempts++;
    _activationRetryTimer = [NSTimer scheduledTimerWithTimeInterval:kHIDPPActivationRetryDelay
                                                             target:self
                                                           selector:@selector(handleActivationRetryTimer:)
                                                           userInfo:nil
                                                            repeats:NO];
    NSLog(@"[HIDPP] Activation pending for registryID %llu (attempt %d/%d)",
          _registryID,
          _activationAttempts,
          kHIDPPMaxActivationAttempts);
}

- (void)handleActivationRetryTimer:(NSTimer *)timer
{
    _activationRetryTimer = nil;
    [self attemptActivation];
}

- (void)handleReport:(const uint8_t *)report length:(CFIndex)length
{
    if (length < 5) return;

    if (report[3] != 0x00) {
        size_t copyLength = std::min((size_t)length, sizeof(_lastResponse));
        memcpy(_lastResponse, report, copyLength);
        _gotResponse = YES;
        return;
    }

    std::set<uint16_t> newPressedCIDs;
    for (CFIndex offset = 4; offset + 1 < length; offset += 2) {
        uint16_t cid = readUInt16(&report[offset]);
        if (cid == 0) continue;
        if ([self mappingForCID:cid] == NULL) continue;
        newPressedCIDs.insert(cid);
    }

    for (uint16_t cid : newPressedCIDs) {
        if (_pressedCIDs.find(cid) == _pressedCIDs.end()) {
            [self postCID:cid down:true];
        }
    }
    for (uint16_t cid : _pressedCIDs) {
        if (newPressedCIDs.find(cid) == newPressedCIDs.end()) {
            [self postCID:cid down:false];
        }
    }
    _pressedCIDs = newPressedCIDs;
}

- (void)handleReportError:(IOReturn)result
{
    if (!_running) return;

    for (uint16_t cid : _pressedCIDs) {
        [self postCID:cid down:false];
    }
    _pressedCIDs.clear();

    NSLog(@"[HIDPP] Input report error %x for registryID %llu; retrying activation", result, _registryID);
    [self reactivateWithRetryReset:NO];
}

- (IOReturn)sendAndWait:(const uint8_t *)packet
{
    _gotResponse = NO;
    memset(_lastResponse, 0, sizeof(_lastResponse));

    IOReturn result = IOHIDDeviceSetReport(_iohid,
                                           kIOHIDReportTypeOutput,
                                           packet[0],
                                           (uint8_t *)packet,
                                           20);
    if (result != kIOReturnSuccess) return result;

    for (int i = 0; i < 100 && !_gotResponse; i++) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.01, false);
    }

    if (!_gotResponse) return kIOReturnTimeout;
    if (_lastResponse[2] == 0xFF) return kIOReturnError;
    return kIOReturnSuccess;
}

- (int)activateDevice
{
    uint8_t packet[20] = {0};

    packet[0] = kHIDPPReportLong;
    packet[1] = kHIDPPDeviceIndex;
    packet[2] = 0x00;
    packet[3] = kHIDPPGetFeature;
    packet[4] = (uint8_t)(kHIDPPFeatureReprogControlsV4 >> 8);
    packet[5] = (uint8_t)(kHIDPPFeatureReprogControlsV4 & 0xFF);
    if ([self sendAndWait:packet] != kIOReturnSuccess || _lastResponse[4] == 0) return 0;
    _featureIndex = _lastResponse[4];

    memset(packet, 0, sizeof(packet));
    packet[0] = kHIDPPReportLong;
    packet[1] = kHIDPPDeviceIndex;
    packet[2] = _featureIndex;
    packet[3] = kHIDPPGetCount;
    if ([self sendAndWait:packet] != kIOReturnSuccess) return 0;

    int count = _lastResponse[4];
    std::vector<HIDPPCIDMapping> mappingsToDivert;

    int nextExtraButtonNumber = [self nextExtraButtonNumber];
    for (int i = 0; i < count && mappingsToDivert.size() < 32; i++) {
        memset(packet, 0, sizeof(packet));
        packet[0] = kHIDPPReportLong;
        packet[1] = kHIDPPDeviceIndex;
        packet[2] = _featureIndex;
        packet[3] = kHIDPPGetCidInfo;
        packet[4] = (uint8_t)i;

        if ([self sendAndWait:packet] != kIOReturnSuccess) continue;

        uint16_t cid = readUInt16(&_lastResponse[4]);
        uint16_t tid = readUInt16(&_lastResponse[6]);
        uint8_t flags = _lastResponse[8];
        bool canDivert = (flags & (1 << 4)) != 0;
        int buttonNumber = [self existingOrNewButtonNumberForTID:tid
                                                             cid:cid
                                           nextExtraButtonNumber:&nextExtraButtonNumber];

        if (cid != 0 && canDivert && buttonNumber != 0 && !isPrimaryButtonTID(tid)) {
            mappingsToDivert.push_back({
                cid,
                buttonNumber,
                (CGMouseButton)(buttonNumber - 1),
            });
        }
    }

    int divertedCount = 0;
    for (HIDPPCIDMapping mapping : mappingsToDivert) {
        if ([self setCidReportingForCID:mapping.cid flags:kHIDPPDivertFlags] == kIOReturnSuccess) {
            divertedCount++;
            if ([self mappingForCID:mapping.cid] == NULL) {
                _cidMappings.push_back(mapping);
            }
        }
    }

    return divertedCount;
}

- (IOReturn)setCidReportingForCID:(uint16_t)cid flags:(uint8_t)flags
{
    if (_featureIndex == 0) return kIOReturnNotReady;

    uint8_t packet[20] = {0};
    packet[0] = kHIDPPReportLong;
    packet[1] = kHIDPPDeviceIndex;
    packet[2] = _featureIndex;
    packet[3] = kHIDPPSetCidReporting;
    packet[4] = (uint8_t)(cid >> 8);
    packet[5] = (uint8_t)(cid & 0xFF);
    packet[6] = flags;

    return [self sendAndWait:packet];
}

- (int)existingOrNewButtonNumberForTID:(uint16_t)tid
                                    cid:(uint16_t)cid
                  nextExtraButtonNumber:(int *)nextExtraButtonNumber
{
    if (tid == kTIDBack) return 4;
    if (tid == kTIDForward) return 5;
    if (isPrimaryButtonTID(tid)) return 0;

    HIDPPCIDMapping *existingMapping = [self mappingForCID:cid];
    if (existingMapping != NULL) return existingMapping->buttonNumber;

    return (*nextExtraButtonNumber)++;
}

- (int)nextExtraButtonNumber
{
    int nextExtraButtonNumber = kFirstExtraButtonNumber;
    for (HIDPPCIDMapping mapping : _cidMappings) {
        if (mapping.buttonNumber >= nextExtraButtonNumber) {
            nextExtraButtonNumber = mapping.buttonNumber + 1;
        }
    }
    return nextExtraButtonNumber;
}

- (HIDPPCIDMapping *)mappingForCID:(uint16_t)cid
{
    for (HIDPPCIDMapping &mapping : _cidMappings) {
        if (mapping.cid == cid) return &mapping;
    }
    return NULL;
}

- (void)postCID:(uint16_t)cid down:(bool)down
{
    HIDPPCIDMapping *mapping = [self mappingForCID:cid];
    if (mapping == NULL) return;

    postButtonEvent(mapping->cgButton, down);
    if (down) {
        sHeldButtons.insert(mapping->cgButton);
    } else {
        sHeldButtons.erase(mapping->cgButton);
    }
}

@end
