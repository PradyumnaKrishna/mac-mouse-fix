//
// --------------------------------------------------------------------------
// HIDPPListener.h
// Created for Mac Mouse Fix (https://github.com/noah-nuebling/mac-mouse-fix)
// Created by Pradyumna Krishna in 2026
// Licensed under the MMF License (https://github.com/noah-nuebling/mac-mouse-fix/blob/master/License)
// --------------------------------------------------------------------------
//

#import <Foundation/Foundation.h>
#import <IOKit/hid/IOHIDDevice.h>

/// Listens for Logitech HID++ notifications and synthesizes mouse button events.
/// Best-effort: Logitech devices are retried after reconnect/wake because firmware can be late to expose HID++.
@interface HIDPPListener : NSObject

- (instancetype)initWithDevice:(IOHIDDeviceRef)device;
- (uint64_t)registryID;
- (BOOL)start:(NSError * _Nullable __autoreleasing *)error;
- (void)stop;

@end
