//
//  SWKSecureBrowser.m
//

#import "SWKSecureBrowser.h"

#import <Security/Security.h>

#import "SWKEngine.h"
#import "SWKStatsStore.h"

static NSString * const kRuleListIdentifier = @"com.rohithkumarballem.SecureWebKit.trackers";
static const NSUInteger kMaxConsecutiveUpgrades = 3;

@implementation SWKSecureBrowser {
    SWKEngine *_engine;
    WKWebView *_webView;
    BOOL _rulesReady;
    NSString *_pendingAddress;
    NSUInteger _consecutiveUpgrades;
}

- (instancetype)initWithEngine:(SWKEngine *)engine
{
    if ((self = [super init])) {
        _engine = engine;

        WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
        // Nothing the page stores (cookies, localStorage, caches) outlives the app.
        config.websiteDataStore = [WKWebsiteDataStore nonPersistentDataStore];
        config.preferences.javaScriptCanOpenWindowsAutomatically = NO;
        config.preferences.fraudulentWebsiteWarningEnabled = YES;
        if (@available(macOS 14.0, *))
            config.upgradeKnownHostsToHTTPS = YES;

        _webView = [[WKWebView alloc] initWithFrame:NSZeroRect configuration:config];
        _webView.navigationDelegate = self;
        _webView.UIDelegate = self;
        _webView.allowsBackForwardNavigationGestures = YES;
        _webView.translatesAutoresizingMaskIntoConstraints = NO;

        [self installContentRules];
    }
    return self;
}

- (WKWebView *)webView { return _webView; }

#pragma mark - Content rule list

- (void)installContentRules
{
    NSURL *url = [NSBundle.mainBundle URLForResource:@"webkit-rules" withExtension:@"json"];
    NSString *json = url ? [NSString stringWithContentsOfURL:url encoding:NSUTF8StringEncoding error:nil] : nil;
    if (!json) {
        [self markRulesReadyWithMessage:@"Content rules missing; relying on native policy only."];
        return;
    }
    __weak typeof(self) weakSelf = self;
    [WKContentRuleListStore.defaultStore compileContentRuleListForIdentifier:kRuleListIdentifier
                                                       encodedContentRuleList:json
                                                            completionHandler:^(WKContentRuleList *list, NSError *error) {
        SWKSecureBrowser *strongSelf = weakSelf;
        if (!strongSelf)
            return;
        if (list) {
            [strongSelf->_webView.configuration.userContentController addContentRuleList:list];
            [strongSelf markRulesReadyWithMessage:[NSString stringWithFormat:@"Content rules active (%lu tracker domains).",
                                                   (unsigned long)strongSelf->_engine.trackerCount]];
        } else {
            [strongSelf markRulesReadyWithMessage:[NSString stringWithFormat:@"Content rules failed: %@", error.localizedDescription]];
        }
    }];
}

- (void)markRulesReadyWithMessage:(NSString *)message
{
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_rulesReady = YES;
        [self log:message];
        if (self->_pendingAddress) {
            NSString *address = self->_pendingAddress;
            self->_pendingAddress = nil;
            [self loadAddress:address];
        }
    });
}

#pragma mark - Loading

- (void)loadAddress:(NSString *)address
{
    NSString *trimmed = [address stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (trimmed.length == 0)
        return;
    if (!_rulesReady) {
        _pendingAddress = trimmed;  // never load before the rule list is attached
        return;
    }

    if (![trimmed containsString:@"://"])
        trimmed = [@"https://" stringByAppendingString:trimmed];
    NSURL *url = [NSURL URLWithString:trimmed];
    NSString *scheme = url.scheme.lowercaseString;
    if (!url.host.length || !([scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"])) {
        [self log:[NSString stringWithFormat:@"Refused address: %@", trimmed]];
        return;
    }
    _consecutiveUpgrades = 0;
    [_webView loadRequest:[NSURLRequest requestWithURL:url]];
}

- (void)log:(NSString *)event
{
    [self.delegate secureBrowser:self didLogEvent:event];
}

static BOOL IsLoopbackHost(NSString *host)
{
    NSString *h = host.lowercaseString;
    return [h isEqualToString:@"localhost"] || [h isEqualToString:@"127.0.0.1"] || [h isEqualToString:@"::1"] ||
           [h isEqualToString:@"[::1]"] || [h hasSuffix:@".localhost"];
}

#pragma mark - WKNavigationDelegate

- (void)webView:(WKWebView *)webView
decidePolicyForNavigationAction:(WKNavigationAction *)action
        decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler
{
    NSURL *url = action.request.URL;
    NSString *scheme = url.scheme.lowercaseString;
    BOOL mainFrame = action.targetFrame.isMainFrame;
    BOOL isGET = action.request.HTTPMethod.length == 0 || [action.request.HTTPMethod isEqualToString:@"GET"];

    // Embedded documents may use these; they never reach the network by themselves.
    if ([scheme isEqualToString:@"about"] || (!mainFrame && ([scheme isEqualToString:@"blob"] || [scheme isEqualToString:@"data"]))) {
        decisionHandler(WKNavigationActionPolicyAllow);
        return;
    }

    BOOL isHTTP = [scheme isEqualToString:@"http"];
    if (!isHTTP && ![scheme isEqualToString:@"https"]) {
        [self log:[NSString stringWithFormat:@"Blocked %@: link", scheme ?: @"unknown"]];
        decisionHandler(WKNavigationActionPolicyCancel);
        return;
    }

    // HTTPS only. Loopback is exempt so local development still works.
    if (isHTTP && !IsLoopbackHost(url.host ?: @"")) {
        if (!mainFrame) {
            _blockedCount++;
            [self log:[NSString stringWithFormat:@"Blocked insecure frame: %@", url.host]];
            decisionHandler(WKNavigationActionPolicyCancel);
            return;
        }
        if (++_consecutiveUpgrades > kMaxConsecutiveUpgrades) {
            [self log:[NSString stringWithFormat:@"%@ keeps redirecting to HTTP; stopped.", url.host]];
            decisionHandler(WKNavigationActionPolicyCancel);
            return;
        }
        NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
        components.scheme = @"https";
        if (components.port.integerValue == 80)
            components.port = nil;
        if (components.URL) {
            _upgradedCount++;
            [self log:[NSString stringWithFormat:@"Upgraded %@ to HTTPS", url.host]];
            decisionHandler(WKNavigationActionPolicyCancel);
            [webView loadRequest:[NSURLRequest requestWithURL:components.URL]];
            return;
        }
    }

    NSString *pageHost = webView.URL.host;
    SWKDecision *decision = [_engine evaluateURL:url
                                  firstPartyHost:mainFrame ? nil : pageHost
                                            type:mainFrame ? SWKResourceTypeMainFrame : SWKResourceTypeSubFrame];

    if (decision.action == SWKActionBlock) {
        _blockedCount++;
        [SWKStatsStore.sharedStore addTrackersDetected:1 paramsRemoved:0];
        [self log:[NSString stringWithFormat:@"Blocked tracker frame: %@", decision.matchedDomain]];
        decisionHandler(WKNavigationActionPolicyCancel);
        return;
    }

    // Only rewrite plain GET navigations: a POST body would be lost on reload.
    if (decision.action == SWKActionRewrite && decision.rewrittenURL && mainFrame && isGET) {
        _paramsRemovedCount += decision.removedParameters;
        [SWKStatsStore.sharedStore addTrackersDetected:0 paramsRemoved:decision.removedParameters];
        [self log:[NSString stringWithFormat:@"Removed %lu tracking parameter%@ from link",
                   (unsigned long)decision.removedParameters, decision.removedParameters == 1 ? @"" : @"s"]];
        decisionHandler(WKNavigationActionPolicyCancel);
        [webView loadRequest:[NSURLRequest requestWithURL:decision.rewrittenURL]];
        return;
    }

    decisionHandler(WKNavigationActionPolicyAllow);
}

- (void)webView:(WKWebView *)webView
decidePolicyForNavigationResponse:(WKNavigationResponse *)response
        decisionHandler:(void (^)(WKNavigationResponsePolicy))decisionHandler
{
    // This host has no download UI, so anything WebKit cannot render is refused
    // rather than silently written to disk.
    if (response.isForMainFrame && !response.canShowMIMEType) {
        [self log:[NSString stringWithFormat:@"Blocked download (%@)", response.response.MIMEType ?: @"unknown type"]];
        decisionHandler(WKNavigationResponsePolicyCancel);
        return;
    }
    decisionHandler(WKNavigationResponsePolicyAllow);
}

- (void)webView:(WKWebView *)webView
didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
        completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler
{
    NSURLProtectionSpace *space = challenge.protectionSpace;
    if (![space.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust] || !space.serverTrust) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }

    // Evaluate against a hostname-bound SSL policy plus best-effort revocation,
    // and refuse the connection on any failure. There is no click-through.
    SecTrustRef trust = space.serverTrust;
    SecPolicyRef ssl = SecPolicyCreateSSL(true, (__bridge CFStringRef)space.host);
    SecPolicyRef revocation = SecPolicyCreateRevocation(kSecRevocationUseAnyAvailableMethod);
    CFMutableArrayRef policies = CFArrayCreateMutable(kCFAllocatorDefault, 2, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(policies, ssl);
    if (revocation)
        CFArrayAppendValue(policies, revocation);
    SecTrustSetPolicies(trust, policies);
    CFRelease(policies);
    CFRelease(ssl);
    if (revocation)
        CFRelease(revocation);

    CFErrorRef error = NULL;
    if (SecTrustEvaluateWithError(trust, &error)) {
        NSString *subject = @"unknown subject";
        CFArrayRef chain = SecTrustCopyCertificateChain(trust);
        if (chain && CFArrayGetCount(chain) > 0) {
            NSString *summary = CFBridgingRelease(SecCertificateCopySubjectSummary((SecCertificateRef)CFArrayGetValueAtIndex(chain, 0)));
            if (summary.length)
                subject = summary;
        }
        if (chain)
            CFRelease(chain);
        [self log:[NSString stringWithFormat:@"TLS verified for %@ (%@)", space.host, subject]];
        completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:trust]);
    } else {
        NSString *reason = error ? CFBridgingRelease(CFErrorCopyDescription(error)) : @"unknown error";
        if (error)
            CFRelease(error);
        [self log:[NSString stringWithFormat:@"Refused %@: certificate not trusted (%@)", space.host, reason]];
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    }
}

- (void)webView:(WKWebView *)webView didCommitNavigation:(WKNavigation *)navigation
{
    [self.delegate secureBrowserDidChangeLocation:self];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation
{
    _consecutiveUpgrades = 0;
    [self.delegate secureBrowserDidChangeLocation:self];
}

- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error
{
    if ([error.domain isEqualToString:NSURLErrorDomain] && error.code == NSURLErrorCancelled)
        return;  // our own cancel-and-reload paths
    [self log:[NSString stringWithFormat:@"Load failed: %@", error.localizedDescription]];
}

#pragma mark - WKUIDelegate

- (WKWebView *)webView:(WKWebView *)webView
createWebViewWithConfiguration:(WKWebViewConfiguration *)configuration
   forNavigationAction:(WKNavigationAction *)action
        windowFeatures:(WKWindowFeatures *)windowFeatures
{
    // Pop-ups are refused; a plain link click that wanted a new window is
    // loaded in place instead.
    if (action.navigationType == WKNavigationTypeLinkActivated && action.request.URL)
        [webView loadRequest:action.request];
    else
        [self log:@"Blocked pop-up window"];
    return nil;
}

- (void)webView:(WKWebView *)webView
requestMediaCapturePermissionForOrigin:(WKSecurityOrigin *)origin
               initiatedByFrame:(WKFrameInfo *)frame
                           type:(WKMediaCaptureType)type
                decisionHandler:(void (^)(WKPermissionDecision))decisionHandler
API_AVAILABLE(macos(12.0))
{
    [self log:[NSString stringWithFormat:@"Denied camera/microphone request from %@", origin.host]];
    decisionHandler(WKPermissionDecisionDeny);
}

@end
