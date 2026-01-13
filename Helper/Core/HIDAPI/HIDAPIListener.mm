//  HIDAPIListener.mm
//  Mac Mouse Fix Helper

#import "HIDAPIListener.h"

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <IOKit/hid/IOHIDKeys.h>
#import <IOKit/IOKitLib.h>
#import <thread>
#import <mutex>
#import <set>
#import <vector>
#import <algorithm>
#import <string>
#include <cstring>
#include <cwchar>

// Use lightweight NSLog-based logging
#define REPLACE_COCOALUMBERJACK 1
#import "Logging.h"

// Vendored hidapi
#include "hidapi.h"

#ifdef __APPLE__
extern "C" void hid_darwin_set_open_exclusive(int open_exclusive);
#endif

/// Forward declarations
static CGEventSourceRef sharedSource(void);
static CGEventRef dragTapCallback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *refcon);

/// Shared drag-tap to emit kCGEventOtherMouseDragged events while a button is held.
static CFMachPortRef sDragTap = (CFMachPortRef)NULL;
static CFRunLoopSourceRef sDragTapSource = (CFRunLoopSourceRef)NULL;
static std::mutex sHeldButtonsMutex;
static std::set<CGMouseButton> sHeldButtons;
static constexpr int64_t kHIDPPEventTag = 0x4D4D4648; // "MMFH"

struct HIDPPReprogTarget {
    uint8_t device_index;
    uint8_t feature_index;
    std::set<uint16_t> last_cids;
};

static NSString *stringFromWChar(const wchar_t *value)
{
    if (!value) return @"(null)";
    size_t len = std::wcslen(value);
    if (len == 0) return @"";
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    NSStringEncoding encoding = (sizeof(wchar_t) == 4) ? NSUTF32LittleEndianStringEncoding : NSUTF16LittleEndianStringEncoding;
#else
    NSStringEncoding encoding = (sizeof(wchar_t) == 4) ? NSUTF32BigEndianStringEncoding : NSUTF16BigEndianStringEncoding;
#endif
    NSString *str = [[NSString alloc] initWithBytes:value length:len * sizeof(wchar_t) encoding:encoding];
    return str ?: @"(unreadable)";
}

static void logHidDeviceInfo(const struct hid_device_info *cur)
{
    if (!cur) return;
    NSString *product = stringFromWChar(cur->product_string);
    NSString *manufacturer = stringFromWChar(cur->manufacturer_string);
    NSString *serial = stringFromWChar(cur->serial_number);
    DDLogInfo(@"[HIDAPI] dev path=%s vid=%04x pid=%04x usage_page=%04x usage=%04x iface=%d product=%@ manufacturer=%@ serial=%@",
              cur->path ? cur->path : "(null)",
              cur->vendor_id,
              cur->product_id,
              cur->usage_page,
              cur->usage,
              cur->interface_number,
              product,
              manufacturer,
              serial);
}

@interface HIDAPIListener () {
    IOHIDDeviceRef _iohid;
    uint64_t _registryID;
    hid_device *_hidHandle;
    std::thread _thread;
    BOOL _running;
    std::vector<HIDPPReprogTarget> _reprogTargets;
    std::mutex _stateLock;
}
@end

static uint64_t registryIDForDevice(IOHIDDeviceRef device)
{
    io_service_t service = IOHIDDeviceGetService(device);
    uint64_t rid = 0;
    IORegistryEntryGetRegistryEntryID(service, &rid);
    return rid;
}

static CGEventSourceRef sharedSource(void) {
    static CGEventSourceRef src = (CGEventSourceRef)NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        src = CGEventSourceCreate(kCGEventSourceStateHIDSystemState);
    });
    return src;
}

static inline void tagEvent(CGEventRef event) {
    if (!event) return;
    CGEventSetIntegerValueField(event, kCGEventSourceUserData, kHIDPPEventTag);
}

static inline bool isTaggedEvent(CGEventRef event) {
    if (!event) return false;
    return (CGEventGetIntegerValueField(event, kCGEventSourceUserData) == kHIDPPEventTag);
}

static CGEventRef dragTapCallback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *refcon)
{
    if (isTaggedEvent(event)) return event;
    std::set<CGMouseButton> heldCopy;
    {
        std::lock_guard<std::mutex> guard(sHeldButtonsMutex);
        heldCopy = sHeldButtons;
    }
    if (!heldCopy.empty()) {
        CGPoint loc = CGEventGetLocation(event);
        for (CGMouseButton btn : heldCopy) {
            CGEventRef drag = CGEventCreateMouseEvent(sharedSource(),
                                                      kCGEventOtherMouseDragged,
                                                      loc,
                                                      btn);
            if (drag) {
                CGEventSetIntegerValueField(drag, kCGMouseEventButtonNumber, btn);
                tagEvent(drag);
                DDLogDebug(@"[HIDAPI] dragTap drag for btn %d at (%0.0f,%0.0f)", btn, loc.x, loc.y);
                CGEventPost(kCGSessionEventTap, drag);
                CFRelease(drag);
            }
        }
    }
    return event;
}

static CGPoint currentMouseLocation()
{
    CGEventRef evt = CGEventCreate(sharedSource());
    CGPoint loc = CGEventGetLocation(evt);
    CFRelease(evt);
    return loc;
}

static void postButton(CGMouseButton button, bool down)
{
    CGPoint loc = currentMouseLocation();
    CGEventType type = down ? kCGEventOtherMouseDown : kCGEventOtherMouseUp;
    CGEventRef e = CGEventCreateMouseEvent(sharedSource(), type, loc, button);
    if (e) {
        CGEventSetIntegerValueField(e, kCGMouseEventButtonNumber, button);
        CGEventSetIntegerValueField(e, kCGMouseEventPressure, down ? 1 : 0);
        tagEvent(e);
        DDLogDebug(@"[HIDAPI] posting %@ for CG button %d at (%0.0f,%0.0f)", down ? @"down" : @"up", button, loc.x, loc.y);
        CGEventPost(kCGHIDEventTap, e);
        CFRelease(e);
    }
}

static bool mapCidToButton(uint16_t cid, CGMouseButton &outButton);

static void ensureDragTap()
{
    if (sDragTap != (CFMachPortRef)NULL) return;
    CGEventMask mask = CGEventMaskBit(kCGEventMouseMoved) |
                       CGEventMaskBit(kCGEventLeftMouseDragged) |
                       CGEventMaskBit(kCGEventRightMouseDragged) |
                       CGEventMaskBit(kCGEventOtherMouseDragged);
    sDragTap = CGEventTapCreate(kCGHIDEventTap,
                                kCGHeadInsertEventTap,
                                kCGEventTapOptionListenOnly,
                                mask,
                                (CGEventTapCallBack)dragTapCallback,
                                NULL);
    if (sDragTap) {
        sDragTapSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, sDragTap, 0);
        CFRunLoopAddSource(CFRunLoopGetMain(), sDragTapSource, kCFRunLoopCommonModes);
    }
}

// MARK: - HID++ (HIDPP 2.0) helpers (minimal, adapted from Solaar/hidpp)

static constexpr uint8_t kHIDPPReportShort = 0x10;
static constexpr uint8_t kHIDPPReportLong = 0x11;
static constexpr uint8_t kHIDPPReportVeryLong = 0x12;
static constexpr size_t kHIDPPShortReportLength = 7;
static constexpr size_t kHIDPPLongReportLength = 20;
static constexpr size_t kHIDPPVeryLongReportLength = 64;
static constexpr uint8_t kHIDPP20RootIndex = 0x00;
static constexpr uint8_t kHIDPP20ErrorMessage = 0xFF;
static constexpr uint16_t kHIDPP20FeatureSet = 0x0001;
static constexpr uint16_t kHIDPP20FeatureReprogControlsV4 = 0x1B04;
static constexpr uint8_t kHIDPP20FunctionGetFeature = 0x00; // Root.GetFeature
static constexpr uint8_t kHIDPP20FunctionSetCidReporting = 0x03; // 0x30
static const bool kHIDPPVerboseLogs = false;
static bool sLastHidppSendFailed = false;
static constexpr uint16_t kHIDPPControlBackButton = 0x0053;
static constexpr uint16_t kHIDPPControlForwardButton = 0x0056;

static bool mapCidToButton(uint16_t cid, CGMouseButton &outButton)
{
    if (cid == kHIDPPControlBackButton) {
        outButton = (CGMouseButton)3; // button 4
        return true;
    }
    if (cid == kHIDPPControlForwardButton) {
        outButton = (CGMouseButton)4; // button 5
        return true;
    }
    return false;
}

static uint8_t hidppNextSoftwareId()
{
    static uint8_t swId = 0x0F;
    if (swId < 0x0F) {
        swId += 1;
    } else {
        swId = 0x02;
    }
    return swId;
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

static uint16_t ioHIDVendorID(IOHIDDeviceRef device)
{
    return (uint16_t)ioHIDDeviceUIntProperty(device, CFSTR(kIOHIDVendorIDKey));
}

static uint16_t ioHIDProductID(IOHIDDeviceRef device)
{
    return (uint16_t)ioHIDDeviceUIntProperty(device, CFSTR(kIOHIDProductIDKey));
}

static bool wideContains(const wchar_t *haystack, const wchar_t *needle)
{
    if (!haystack || !needle) return false;
    return std::wcsstr(haystack, needle) != nullptr;
}

static std::string pathForRegistryID(uint64_t registryID)
{
    return std::string("DevSrvsID:") + std::to_string(registryID);
}

struct HIDPPCandidatePath {
    int score;
    std::string path;
    uint16_t usage_page;
    uint16_t usage;
};

static std::vector<HIDPPCandidatePath> hidppCandidatePaths(IOHIDDeviceRef device, uint64_t registryID)
{
    std::vector<HIDPPCandidatePath> candidates;
    if (kHIDPPVerboseLogs && registryID != 0) {
        candidates.push_back({0, pathForRegistryID(registryID), 0, 0});
    }

    uint16_t productID = ioHIDProductID(device);

    struct hid_device_info *devs = hid_enumerate(0x046d, 0);
    for (struct hid_device_info *cur = devs; cur; cur = cur->next) {
        if (!cur->path) continue;
        if (productID != 0 && cur->product_id != productID) continue;
        if ((cur->usage_page & 0xFF00) != 0xFF00) continue; // avoid grabbing the HID mouse interface
        int score = 1;
        if ((cur->usage_page & 0xFF00) == 0xFF00) score += 100;
        if (cur->usage_page == 0xFF00) score += 20;
        if (cur->usage_page == 0xFF43) score += 30;
        if (wideContains(cur->product_string, L"Receiver")) score += 10;
        if (wideContains(cur->product_string, L"Unifying")) score += 10;
        if (wideContains(cur->product_string, L"Bolt")) score += 10;
        if (wideContains(cur->product_string, L"LIGHTSPEED")) score += 5;
        if (productID && cur->product_id == productID) score += 5;
        candidates.push_back({score, cur->path, cur->usage_page, cur->usage});
    }
    hid_free_enumeration(devs);

    std::sort(candidates.begin(), candidates.end(), [](const HIDPPCandidatePath &a, const HIDPPCandidatePath &b) {
        return a.score > b.score;
    });

    return candidates;
}

static bool hidppSendReport(hid_device *handle,
                            uint8_t reportId,
                            size_t reportLength,
                            uint8_t deviceIndex,
                            uint8_t featureIndex,
                            uint8_t functionNibble,
                            uint8_t swId,
                            const uint8_t *params,
                            size_t paramsLen)
{
    if (!handle) return false;
    if (reportLength < 5 || reportLength > kHIDPPVeryLongReportLength) return false;
    uint8_t report[kHIDPPVeryLongReportLength] = {0};
    report[0] = reportId;
    report[1] = deviceIndex;
    report[2] = featureIndex;
    report[3] = (uint8_t)((functionNibble & 0x0F) << 4) | (swId & 0x0F);
    size_t copyLen = std::min(paramsLen, reportLength - 4);
    if (params && copyLen > 0) {
        std::memcpy(&report[4], params, copyLen);
    }

    int written = hid_write(handle, report, reportLength);
    if (written < 0) {
        if (kHIDPPVerboseLogs) {
            DDLogInfo(@"[HIDAPI] hid_write failed (reportId=0x%02x len=%zu): %ls", reportId, reportLength, hid_error(handle));
        }
        written = hid_send_feature_report(handle, report, reportLength);
        if (written < 0 && kHIDPPVerboseLogs) {
            DDLogInfo(@"[HIDAPI] hid_send_feature_report failed (reportId=0x%02x len=%zu): %ls", reportId, reportLength, hid_error(handle));
        }
    }
    return written >= 0;
}

static bool hidppSendWithFallback(hid_device *handle,
                                  uint8_t deviceIndex,
                                  uint8_t featureIndex,
                                  uint8_t functionNibble,
                                  uint8_t swId,
                                  const uint8_t *params,
                                  size_t paramsLen)
{
    struct Variant { uint8_t reportId; size_t length; const char *name; };
    static const Variant variants[] = {
        {kHIDPPReportShort, kHIDPPShortReportLength, "short"},
        {kHIDPPReportLong, kHIDPPLongReportLength, "long"},
        {kHIDPPReportVeryLong, kHIDPPVeryLongReportLength, "verylong"},
        {0x00, kHIDPPShortReportLength, "unnumbered-short"},
    };
    for (const Variant &v : variants) {
        if (hidppSendReport(handle, v.reportId, v.length, deviceIndex, featureIndex, functionNibble, swId, params, paramsLen)) {
            if (kHIDPPVerboseLogs) {
                DDLogInfo(@"[HIDAPI] send ok (%s, reportId=0x%02x, len=%zu)", v.name, v.reportId, v.length);
            }
            return true;
        }
    }
    return false;
}

static bool hidppReadReport(hid_device *handle,
                            uint8_t *outReport,
                            size_t outReportLen,
                            int timeoutMs,
                            int *outLen)
{
    if (!handle || !outReport || outReportLen == 0) return false;
    int len = hid_read_timeout(handle, outReport, outReportLen, timeoutMs);
    if (outLen) *outLen = len;
    return len > 0;
}

static bool hidpp20Request(hid_device *handle,
                           uint8_t deviceIndex,
                           uint8_t featureIndex,
                           uint8_t functionNibble,
                           const uint8_t *params,
                           size_t paramsLen,
                           uint8_t *outParams,
                           size_t outParamsMax,
                           size_t *outParamsLen,
                           int timeoutMs)
{
    if (outParamsLen) *outParamsLen = 0;
    sLastHidppSendFailed = false;
    uint8_t swId = hidppNextSoftwareId();
    if (!hidppSendWithFallback(handle, deviceIndex, featureIndex, functionNibble, swId, params, paramsLen)) {
        sLastHidppSendFailed = true;
        return false;
    }

    const int maxLoops = 3; // bounded retries within timeout
    for (int i = 0; i < maxLoops; ++i) {
        uint8_t buf[64] = {0};
        int len = 0;
        if (!hidppReadReport(handle, buf, sizeof(buf), timeoutMs, &len)) {
            continue;
        }
        if (len < 6) continue;

        bool hasReportId = (buf[0] == kHIDPPReportShort || buf[0] == kHIDPPReportLong || buf[0] == kHIDPPReportVeryLong);
        size_t offset = hasReportId ? 1 : 0;
        size_t headerLen = offset + 3;
        if ((size_t)len < headerLen) continue;

        uint8_t dev = buf[offset + 0];
        if (!(dev == deviceIndex || dev == (uint8_t)(deviceIndex ^ 0xFF))) continue;

        uint8_t subId = buf[offset + 1];
        if (subId == kHIDPP20ErrorMessage) {
            uint8_t errFeature = (size_t)len >= (offset + 2) ? buf[offset + 1] : 0;
            uint8_t errAddr = (size_t)len >= (offset + 3) ? buf[offset + 2] : 0;
            DDLogWarn(@"[HIDAPI] HID++ error message for dev %d (feature %02x, fn %x)", dev, errFeature, errAddr >> 4);
            return false;
        }
        if (subId != featureIndex) continue;

        uint8_t addr = buf[offset + 2];
        uint8_t fn = (addr & 0xF0) >> 4;
        uint8_t respSwId = (addr & 0x0F);
        if (fn != (functionNibble & 0x0F)) continue;
        if (respSwId != swId) continue;

        size_t paramLen = (size_t)len > headerLen ? (size_t)(len - headerLen) : 0;
        size_t copyLen = std::min(paramLen, outParamsMax);
        if (outParams && copyLen > 0) {
            std::memcpy(outParams, &buf[headerLen], copyLen);
        }
        if (outParamsLen) *outParamsLen = copyLen;
        return true;
    }
    return false;
}

static bool hidpp20GetFeatureIndex(hid_device *handle,
                                   uint8_t deviceIndex,
                                   uint16_t featureId,
                                   uint8_t *outIndex)
{
    uint8_t params[2] = { (uint8_t)(featureId >> 8), (uint8_t)(featureId & 0xFF) };
    uint8_t response[16] = {0};
    size_t responseLen = 0;
    if (!hidpp20Request(handle,
                        deviceIndex,
                        kHIDPP20RootIndex,
                        kHIDPP20FunctionGetFeature,
                        params,
                        sizeof(params),
                        response,
                        sizeof(response),
                        &responseLen,
                        150)) {
        return false;
    }
    if (responseLen < 1) return false;
    uint8_t index = response[0];
    if (index == 0x00) return false;
    if (outIndex) *outIndex = index;
    return true;
}

static void hidpp20LogFeatureSet(hid_device *handle, uint8_t deviceIndex)
{
    if (!kHIDPPVerboseLogs) return;
    uint8_t featureSetIndex = 0;
    if (!hidpp20GetFeatureIndex(handle, deviceIndex, kHIDPP20FeatureSet, &featureSetIndex)) {
        DDLogInfo(@"[HIDAPI] dev %d: FEATURE_SET not available (not HID++2 or feature missing)", deviceIndex);
        return;
    }

    uint8_t countResp[8] = {0};
    size_t countLen = 0;
    if (!hidpp20Request(handle,
                        deviceIndex,
                        featureSetIndex,
                        0x00,
                        nullptr,
                        0,
                        countResp,
                        sizeof(countResp),
                        &countLen,
                        150)) {
        DDLogInfo(@"[HIDAPI] dev %d: FEATURE_SET getCount failed (index=%02x)", deviceIndex, featureSetIndex);
        return;
    }

    if (countLen < 1) {
        DDLogInfo(@"[HIDAPI] dev %d: FEATURE_SET getCount returned no data (index=%02x)", deviceIndex, featureSetIndex);
        return;
    }

    uint8_t count = countResp[0];
    DDLogInfo(@"[HIDAPI] dev %d: FEATURE_SET index=%02x count=%u (excludes ROOT)", deviceIndex, featureSetIndex, count);

    for (uint8_t idx = 0; idx <= count; ++idx) { // include ROOT at 0
        uint8_t params[1] = { idx };
        uint8_t resp[16] = {0};
        size_t respLen = 0;
        if (!hidpp20Request(handle,
                            deviceIndex,
                            featureSetIndex,
                            0x01,
                            params,
                            sizeof(params),
                            resp,
                            sizeof(resp),
                            &respLen,
                            150)) {
            DDLogInfo(@"[HIDAPI] dev %d: feature[%u] read failed", deviceIndex, idx);
            continue;
        }
        if (respLen < 2) {
            DDLogInfo(@"[HIDAPI] dev %d: feature[%u] short response", deviceIndex, idx);
            continue;
        }
        uint16_t featureId = (uint16_t)((resp[0] << 8) | resp[1]);
        uint8_t flags = (respLen >= 3) ? resp[2] : 0;
        uint8_t version = (respLen >= 4) ? resp[3] : 0;
        DDLogInfo(@"[HIDAPI] dev %d: feature[%u] id=0x%04x flags=0x%02x ver=%u",
                  deviceIndex, idx, featureId, flags, version);
    }
}

static bool hidpp20SetCidReporting(hid_device *handle,
                                   uint8_t deviceIndex,
                                   uint8_t featureIndex,
                                   uint16_t cid,
                                   uint8_t flags,
                                   uint16_t remap)
{
    uint8_t params[5] = {
        (uint8_t)(cid >> 8),
        (uint8_t)(cid & 0xFF),
        flags,
        (uint8_t)(remap >> 8),
        (uint8_t)(remap & 0xFF),
    };
    uint8_t response[8] = {0};
    size_t responseLen = 0;
    return hidpp20Request(handle,
                          deviceIndex,
                          featureIndex,
                          kHIDPP20FunctionSetCidReporting,
                          params,
                          sizeof(params),
                          response,
                          sizeof(response),
                          &responseLen,
                          150);
}

@implementation HIDAPIListener

- (instancetype)initWithDevice:(IOHIDDeviceRef)device
{
    self = [super init];
    if (self) {
        _iohid = device;
        CFRetain(_iohid);
        _registryID = registryIDForDevice(device);
        _hidHandle = nullptr;
        _running = NO;
        _reprogTargets.clear();
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

    uint16_t vid = ioHIDVendorID(_iohid);
    uint16_t pid = ioHIDProductID(_iohid);
    DDLogInfo(@"[HIDAPI] Starting listener for registryID %llu", _registryID);
    DDLogInfo(@"[HIDAPI] IOHID vid=%04x pid=%04x", vid, pid);

    if (vid != 0x046d) {
        if (error) {
            *error = [NSError errorWithDomain:@"HIDAPI"
                                         code:11
                                     userInfo:@{NSLocalizedDescriptionKey:@"Non-Logitech device"}];
        }
        return NO;
    }

    hid_init();
#ifdef __APPLE__
    hid_darwin_set_open_exclusive(0);
#endif

        _reprogTargets.clear();

    if (kHIDPPVerboseLogs) {
        struct hid_device_info *allDevs = hid_enumerate(0x046d, 0);
        for (struct hid_device_info *cur = allDevs; cur; cur = cur->next) {
            logHidDeviceInfo(cur);
        }
        hid_free_enumeration(allDevs);
    }

    std::vector<HIDPPCandidatePath> candidatePaths = hidppCandidatePaths(_iohid, _registryID);
    std::string chosenPath;

    DDLogInfo(@"[HIDAPI] Candidate paths: %lu", (unsigned long)candidatePaths.size());
    for (const HIDPPCandidatePath &candidate : candidatePaths) {
        DDLogInfo(@"[HIDAPI] candidate path: %s score=%d usage_page=%04x usage=%04x",
                  candidate.path.c_str(),
                  candidate.score,
                  candidate.usage_page,
                  candidate.usage);
    }

    for (const HIDPPCandidatePath &candidate : candidatePaths) {
        const std::string &path = candidate.path;
        DDLogInfo(@"[HIDAPI] probing path: %s usage_page=%04x usage=%04x", path.c_str(), candidate.usage_page, candidate.usage);
        hid_device *handle = hid_open_path(path.c_str());
        if (!handle) {
            DDLogInfo(@"[HIDAPI] open failed for path %s", path.c_str());
            continue;
        }

        hid_set_nonblocking(handle, 0);

        std::vector<HIDPPReprogTarget> targets;
        uint8_t featureIndex = 0;

        bool foundAny = false;
        bool sendFailed = false;
        auto tryEnableReprog = [&](uint8_t devIdx) -> bool {
            hidpp20LogFeatureSet(handle, devIdx);
            if (!hidpp20GetFeatureIndex(handle, devIdx, kHIDPP20FeatureReprogControlsV4, &featureIndex)) {
                if (sLastHidppSendFailed) sendFailed = true;
                return false;
            }
            DDLogInfo(@"[HIDAPI] dev %d: REPROG_CONTROLS_V4 index=%02x", devIdx, featureIndex);
            // DIVERTED flag + valid bit (DIVERTED << 1)
            const uint8_t divertFlags = 0x03;
            bool backOk = hidpp20SetCidReporting(handle, devIdx, featureIndex, kHIDPPControlBackButton, divertFlags, 0);
            bool fwdOk = hidpp20SetCidReporting(handle, devIdx, featureIndex, kHIDPPControlForwardButton, divertFlags, 0);
            if (!backOk) {
                DDLogInfo(@"[HIDAPI] dev %d: setCidReporting failed for Back Button", devIdx);
            }
            if (!fwdOk) {
                DDLogInfo(@"[HIDAPI] dev %d: setCidReporting failed for Forward Button", devIdx);
            }
            if (backOk || fwdOk) {
                targets.push_back({devIdx, featureIndex, {}});
                return true;
            }
            return false;
        };

        // Try direct HID++ 2.0 device index first (0xFF).
        if (tryEnableReprog(0xFF)) {
            foundAny = true;
        } else if (sendFailed) {
            // keep sendFailed
        } else {
            // Try receiver slots (1..6) for paired devices.
            for (uint8_t devIdx = 1; devIdx <= 6; ++devIdx) {
                if (tryEnableReprog(devIdx)) {
                    foundAny = true;
                } else if (sendFailed) {
                    break;
                }
            }
        }
        if (sendFailed) {
            DDLogInfo(@"[HIDAPI] HID++ send failed for path %s", path.c_str());
        } else if (!foundAny) {
            DDLogInfo(@"[HIDAPI] REPROG_CONTROLS_V4 not supported on path %s", path.c_str());
        }

        if (!targets.empty()) {
            _hidHandle = handle;
            _reprogTargets = targets;
            chosenPath = path;
            break;
        }

        hid_close(handle);
    }

    if (!_hidHandle) {
        DDLogError(@"[HIDAPI] No Logitech HID++ interface with REPROG_CONTROLS_V4 found");
        if (error) {
            *error = [NSError errorWithDomain:@"HIDAPI" code:10 userInfo:@{NSLocalizedDescriptionKey:@"No Logitech HID++ interface with REPROG_CONTROLS_V4 found"}];
        }
        return NO;
    }

    DDLogInfo(@"[HIDAPI] Opened HID++ path %s with %lu target(s)", chosenPath.c_str(), (unsigned long)_reprogTargets.size());

    for (HIDPPReprogTarget &target : _reprogTargets) {
        DDLogInfo(@"[HIDAPI] REPROG diversion active dev %d feat %02x", target.device_index, target.feature_index);
    }

    _running = YES;
    ensureDragTap();

    HIDAPIListener *listenerSelf = self;
    _thread = std::thread([listenerSelf]{
        uint8_t buf[64];
        while (listenerSelf->_running) {
            int len = hid_read_timeout(listenerSelf->_hidHandle, buf, sizeof(buf), 500);
            if (len <= 0) continue;
            if (len < 6) continue;
            bool hasReportId = (buf[0] == kHIDPPReportShort || buf[0] == kHIDPPReportLong || buf[0] == kHIDPPReportVeryLong);
            size_t offset = hasReportId ? 1 : 0;
            size_t headerLen = offset + 3;
            if ((size_t)len < headerLen + 8) continue;

            uint8_t devIdx = buf[offset + 0];
            uint8_t featureIdx = buf[offset + 1];
            uint8_t addr = buf[offset + 2];
            uint8_t functionNibble = (addr & 0xF0) >> 4;
            uint8_t swId = (addr & 0x0F);
            if (swId != 0x00) continue; // notifications should have SW ID 0
            if (functionNibble != 0x00) continue; // diverted controls notification

            HIDPPReprogTarget *target = nullptr;
            for (HIDPPReprogTarget &t : listenerSelf->_reprogTargets) {
                uint8_t altDev = (uint8_t)(t.device_index ^ 0xFF);
                if ((t.device_index == devIdx || altDev == devIdx) && t.feature_index == featureIdx) {
                    target = &t;
                    break;
                }
            }
            if (!target) continue;

            std::set<uint16_t> newCids;
            for (int i = 0; i < 4; ++i) {
                uint16_t cid = (uint16_t)((buf[headerLen + i * 2] << 8) | buf[headerLen + i * 2 + 1]);
                if (cid != 0) newCids.insert(cid);
            }
            DDLogDebug(@"[HIDAPI] reprog notify dev=%d feat=%02x count=%lu len=%d", devIdx, featureIdx, (unsigned long)newCids.size(), len);

            std::lock_guard<std::mutex> guard(listenerSelf->_stateLock);
            if (newCids != target->last_cids) {
                for (const uint16_t &cid : newCids) {
                    if (target->last_cids.find(cid) == target->last_cids.end()) {
                        CGMouseButton cgBtn;
                        if (mapCidToButton(cid, cgBtn)) {
                            DDLogDebug(@"[HIDAPI] CID 0x%04x down -> CG %d", cid, cgBtn);
                            postButton(cgBtn, true);
                            std::lock_guard<std::mutex> heldGuard(sHeldButtonsMutex);
                            sHeldButtons.insert(cgBtn);
                        }
                    }
                }
                for (const uint16_t &cid : target->last_cids) {
                    if (newCids.find(cid) == newCids.end()) {
                        CGMouseButton cgBtn;
                        if (mapCidToButton(cid, cgBtn)) {
                            DDLogDebug(@"[HIDAPI] CID 0x%04x up -> CG %d", cid, cgBtn);
                            postButton(cgBtn, false);
                            std::lock_guard<std::mutex> heldGuard(sHeldButtonsMutex);
                            sHeldButtons.erase(cgBtn);
                        }
                    }
                }
                target->last_cids = newCids;
            }
        }
    });

    return YES;
}

- (void)stop
{
    if (!_running) return;

    _running = NO;
    if (_thread.joinable()) {
        _thread.join();
    }
    if (_hidHandle) {
        for (HIDPPReprogTarget &target : _reprogTargets) {
            const uint8_t divertOff = 0x02; // valid bit for DIVERTED, cleared value
            hidpp20SetCidReporting(_hidHandle, target.device_index, target.feature_index, kHIDPPControlBackButton, divertOff, 0);
            hidpp20SetCidReporting(_hidHandle, target.device_index, target.feature_index, kHIDPPControlForwardButton, divertOff, 0);
        }
        hid_close(_hidHandle);
        _hidHandle = nullptr;
    }
    _reprogTargets.clear();
    hid_exit();

    // Clear held buttons
    {
        std::lock_guard<std::mutex> guard(sHeldButtonsMutex);
        sHeldButtons.clear();
    }

    DDLogInfo(@"[HIDAPI] Stopped listener for device %llu", _registryID);
}

@end
