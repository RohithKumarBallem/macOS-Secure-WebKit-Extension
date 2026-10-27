//
//  SWKEngine.m
//

#import "SWKEngine.h"

#include "swk.h"

NSErrorDomain const SWKErrorDomain = @"com.rohithkumarballem.SecureWebKit";

@implementation SWKDecision

- (instancetype)initWithAction:(SWKAction)action
                        reason:(NSString *)reason
                       matched:(NSString *)matched
                     rewritten:(NSURL *)rewritten
                       removed:(NSUInteger)removed
{
    if ((self = [super init])) {
        _action = action;
        _reason = [reason copy];
        _matchedDomain = [matched copy];
        _rewrittenURL = [rewritten copy];
        _removedParameters = removed;
    }
    return self;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"<SWKDecision %ld %@ %@>", (long)_action, _reason, _matchedDomain ?: @"-"];
}

@end

@implementation SWKEngineStats

- (instancetype)initWithStats:(swk_stats)s
{
    if ((self = [super init])) {
        _evaluated = s.evaluated;
        _blocked = s.blocked;
        _rewritten = s.rewritten;
        _parametersRemoved = s.params_removed;
    }
    return self;
}

@end

@implementation SWKEngine {
    swk_engine *_engine;
}

static NSData *ReadResource(NSBundle *bundle, NSString *name, NSError **error)
{
    NSURL *url = [bundle URLForResource:name withExtension:@"txt"];
    if (!url) {
        if (error)
            *error = [NSError errorWithDomain:SWKErrorDomain code:1
                                     userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Missing resource %@.txt", name] }];
        return nil;
    }
    return [NSData dataWithContentsOfURL:url options:NSDataReadingMappedIfSafe error:error];
}

- (instancetype)initWithBundle:(NSBundle *)bundle error:(NSError **)error
{
    if ((self = [super init])) {
        NSData *trackers = ReadResource(bundle, @"trackers", error);
        NSData *params = trackers ? ReadResource(bundle, @"tracking-params", error) : nil;
        if (!trackers || !params)
            return nil;

        _engine = swk_engine_new();
        if (!_engine) {
            if (error)
                *error = [NSError errorWithDomain:SWKErrorDomain code:2
                                         userInfo:@{ NSLocalizedDescriptionKey : @"Out of memory creating filter engine" }];
            return nil;
        }
        swk_engine_load_trackers(_engine, trackers.bytes, trackers.length);
        swk_engine_load_params(_engine, params.bytes, params.length);
    }
    return self;
}

- (void)dealloc
{
    swk_engine_free(_engine);
}

- (NSUInteger)trackerCount { return swk_engine_tracker_count(_engine); }
- (NSUInteger)parameterCount { return swk_engine_param_count(_engine); }
- (SWKEngineStats *)stats { return [[SWKEngineStats alloc] initWithStats:swk_engine_stats(_engine)]; }

static const char *CStringOrNil(NSString *s)
{
    return s.length ? s.UTF8String : NULL;
}

- (SWKDecision *)evaluateURL:(NSURL *)url firstPartyHost:(NSString *)firstPartyHost type:(SWKResourceType)type
{
    const char *raw = url.absoluteString.UTF8String;
    char out[SWK_MAX_URL + 1];
    swk_decision d = swk_engine_evaluate(_engine, raw, raw ? strlen(raw) : 0, CStringOrNil(firstPartyHost),
                                         (swk_resource_type)type, out, sizeof out);

    NSURL *rewritten = nil;
    if (d.action == SWK_REWRITE)
        rewritten = [NSURL URLWithString:[[NSString alloc] initWithBytes:out length:d.out_len encoding:NSUTF8StringEncoding]];

    return [[SWKDecision alloc] initWithAction:(SWKAction)d.action
                                        reason:@(swk_reason_name(d.reason))
                                       matched:d.matched[0] ? @(d.matched) : nil
                                     rewritten:rewritten
                                       removed:d.removed_params];
}

- (NSArray<NSString *> *)trackerHostsAmong:(NSArray<NSString *> *)hosts firstParty:(NSString *)firstPartyHost
{
    NSMutableArray<NSString *> *found = [NSMutableArray array];
    for (NSString *host in hosts) {
        // Bare hostnames only: anything that could change the URL's meaning is skipped.
        if (![host isKindOfClass:NSString.class] || host.length == 0 || host.length > SWK_MAX_HOST)
            continue;
        if ([host rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"/?#@:[] \t\r\n\\"]].location != NSNotFound)
            continue;
        NSString *probe = [NSString stringWithFormat:@"https://%@/", host];
        // A script request is the representative case for "would this host be blocked?".
        const char *raw = probe.UTF8String;
        swk_decision d = swk_engine_evaluate(_engine, raw, strlen(raw), CStringOrNil(firstPartyHost),
                                             SWK_RT_SCRIPT, NULL, 0);
        if (d.action == SWK_BLOCK)
            [found addObject:host];
    }
    return found;
}

@end
