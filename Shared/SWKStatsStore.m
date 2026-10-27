//
//  SWKStatsStore.m
//

#import "SWKStatsStore.h"

static NSString * const kTrackers = @"stats.trackersDetected";
static NSString * const kParams = @"stats.paramsRemoved";

@implementation SWKStatsStore {
    NSUserDefaults *_defaults;
    dispatch_queue_t _queue;
}

+ (instancetype)sharedStore
{
    static SWKStatsStore *store;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ store = [[SWKStatsStore alloc] init]; });
    return store;
}

- (instancetype)init
{
    if ((self = [super init])) {
        NSString *group = [NSBundle.mainBundle objectForInfoDictionaryKey:@"SWKAppGroup"];
        // An unexpanded "$(...)" means the build setting was never defined.
        BOOL valid = [group isKindOfClass:NSString.class] && group.length > 0 && ![group containsString:@"$("];
        NSUserDefaults *shared = valid ? [[NSUserDefaults alloc] initWithSuiteName:group] : nil;
        _usesAppGroup = shared != nil;
        _defaults = shared ?: [[NSUserDefaults alloc] init];
        _queue = dispatch_queue_create("com.rohithkumarballem.SecureWebKit.stats", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (NSUInteger)trackersDetected
{
    __block NSUInteger value;
    dispatch_sync(_queue, ^{ value = (NSUInteger)[self->_defaults integerForKey:kTrackers]; });
    return value;
}

- (NSUInteger)paramsRemoved
{
    __block NSUInteger value;
    dispatch_sync(_queue, ^{ value = (NSUInteger)[self->_defaults integerForKey:kParams]; });
    return value;
}

- (void)addTrackersDetected:(NSUInteger)trackers paramsRemoved:(NSUInteger)params
{
    dispatch_sync(_queue, ^{
        // Serialised within a process. The app and the extension are separate
        // processes, so a rare lost update between them is possible and accepted
        // for a display-only counter.
        [self->_defaults setInteger:[self->_defaults integerForKey:kTrackers] + (NSInteger)trackers forKey:kTrackers];
        [self->_defaults setInteger:[self->_defaults integerForKey:kParams] + (NSInteger)params forKey:kParams];
    });
}

@end
