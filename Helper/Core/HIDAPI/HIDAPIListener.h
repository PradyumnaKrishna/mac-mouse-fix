//  HIDAPIListener.h
//  Mac Mouse Fix Helper

#import <Foundation/Foundation.h>
#import <IOKit/hid/IOHIDDevice.h>

@interface HIDAPIListener : NSObject

- (instancetype)initWithDevice:(IOHIDDeviceRef)device;
- (uint64_t)registryID;
- (BOOL)start:(NSError * _Nullable __autoreleasing *)error;
- (void)stop;

@end

