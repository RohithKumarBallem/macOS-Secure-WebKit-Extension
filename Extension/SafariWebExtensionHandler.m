//
//  SafariWebExtensionHandler.m
//
//  Native side of browser.runtime.sendNativeMessage. Commands:
//    ping                              -> engine info
//    classify {firstParty, hosts[]}    -> {trackers[]}   (hosts the engine blocks)
//    report   {detected, sanitized}    -> add to lifetime counters
//    stats                             -> lifetime counters
//
//  Messages come from the extension's own scripts, but are validated as
//  untrusted input anyway: bounded sizes, strict types, a fixed command set.
//  Message contents (hostnames, URLs) are never logged or persisted.
//

#import "SafariWebExtensionHandler.h"

#import <SafariServices/SafariServices.h>
#import <os/log.h>

#import "SWKEngine.h"
#import "SWKStatsStore.h"

static const NSUInteger kMaxHosts = 200;
static const NSUInteger kMaxHostLength = 253;
static const NSUInteger kMaxCount = 100000;

static os_log_t Log(void)
{
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("com.rohithkumarballem.SecureWebKit", "extension"); });
    return log;
}

static SWKEngine *SharedEngine(void)
{
    static SWKEngine *engine;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSError *error = nil;
        engine = [[SWKEngine alloc] initWithBundle:NSBundle.mainBundle error:&error];
        if (!engine)
            os_log_error(Log(), "Engine failed to load: %{public}@", error.localizedDescription);
    });
    return engine;
}

static NSDictionary *Failure(NSString *reason)
{
    return @{ @"ok" : @NO, @"error" : reason };
}

static NSUInteger ClampedCount(id value)
{
    if (![value isKindOfClass:NSNumber.class])
        return 0;
    long long n = [value longLongValue];
    return n < 0 ? 0 : (NSUInteger)MIN(n, (long long)kMaxCount);
}

static NSDictionary *ReplyForMessage(id message)
{
    if (![message isKindOfClass:NSDictionary.class])
        return Failure(@"bad request");

    NSString *command = message[@"cmd"];
    if (![command isKindOfClass:NSString.class])
        return Failure(@"bad request");

    SWKEngine *engine = SharedEngine();
    if (!engine)
        return Failure(@"engine unavailable");

    if ([command isEqualToString:@"ping"]) {
        return @{ @"ok" : @YES, @"trackerDomains" : @(engine.trackerCount), @"params" : @(engine.parameterCount) };
    }

    if ([command isEqualToString:@"classify"]) {
        NSString *firstParty = message[@"firstParty"];
        NSArray *hosts = message[@"hosts"];
        if (![hosts isKindOfClass:NSArray.class] || hosts.count > kMaxHosts)
            return Failure(@"bad hosts");
        if ([firstParty isKindOfClass:NSString.class] ? firstParty.length > kMaxHostLength : firstParty != nil)
            return Failure(@"bad firstParty");
        for (id host in hosts) {
            if (![host isKindOfClass:NSString.class])
                return Failure(@"bad hosts");
        }
        return @{ @"ok" : @YES, @"trackers" : [engine trackerHostsAmong:hosts firstParty:firstParty] };
    }

    if ([command isEqualToString:@"report"]) {
        [SWKStatsStore.sharedStore addTrackersDetected:ClampedCount(message[@"detected"])
                                         paramsRemoved:ClampedCount(message[@"sanitized"])];
        return @{ @"ok" : @YES };
    }

    if ([command isEqualToString:@"stats"]) {
        SWKStatsStore *store = SWKStatsStore.sharedStore;
        return @{ @"ok" : @YES,
                  @"trackersDetected" : @(store.trackersDetected),
                  @"paramsRemoved" : @(store.paramsRemoved) };
    }

    return Failure(@"unknown command");
}

@implementation SafariWebExtensionHandler

- (void)beginRequestWithExtensionContext:(NSExtensionContext *)context
{
    NSExtensionItem *request = context.inputItems.firstObject;

    id message;
    if (@available(macOS 11.0, *))
        message = request.userInfo[SFExtensionMessageKey];
    else
        message = request.userInfo[@"message"];

    NSDictionary *reply = ReplyForMessage(message);

    NSExtensionItem *response = [[NSExtensionItem alloc] init];
    if (@available(macOS 11.0, *))
        response.userInfo = @{ SFExtensionMessageKey : reply };
    else
        response.userInfo = @{ @"message" : reply };

    [context completeRequestReturningItems:@[ response ] completionHandler:nil];
}

@end
