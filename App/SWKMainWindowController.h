//
//  SWKMainWindowController.h
//

#import <Cocoa/Cocoa.h>

@class SWKEngine;

NS_ASSUME_NONNULL_BEGIN

@interface SWKMainWindowController : NSWindowController

- (instancetype)initWithEngine:(SWKEngine *)engine NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithWindow:(nullable NSWindow *)window NS_UNAVAILABLE;
- (nullable instancetype)initWithCoder:(NSCoder *)coder NS_UNAVAILABLE;

- (void)focusAddressField;
- (void)reload;

@end

NS_ASSUME_NONNULL_END
