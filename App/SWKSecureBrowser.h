//
//  SWKSecureBrowser.h
//  A WKWebView host that applies the filtering engine and a strict navigation policy.
//

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

@class SWKEngine;
@class SWKSecureBrowser;

NS_ASSUME_NONNULL_BEGIN

@protocol SWKSecureBrowserDelegate <NSObject>
/// A human-readable security event (blocked, upgraded, cleaned, TLS result...).
- (void)secureBrowser:(SWKSecureBrowser *)browser didLogEvent:(NSString *)event;
- (void)secureBrowserDidChangeLocation:(SWKSecureBrowser *)browser;
@end

@interface SWKSecureBrowser : NSObject <WKNavigationDelegate, WKUIDelegate>

@property (nonatomic, readonly) WKWebView *webView;
@property (nonatomic, weak, nullable) id<SWKSecureBrowserDelegate> delegate;

/// Session counters (the lifetime totals live in SWKStatsStore).
@property (nonatomic, readonly) NSUInteger blockedCount;
@property (nonatomic, readonly) NSUInteger upgradedCount;
@property (nonatomic, readonly) NSUInteger paramsRemovedCount;

- (instancetype)initWithEngine:(SWKEngine *)engine NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

/// Accepts "example.com", "http://example.com" or "https://...". Anything that
/// is not http(s) after normalisation is refused.
- (void)loadAddress:(NSString *)address;

@end

NS_ASSUME_NONNULL_END
