//
//  SWKStatsStore.h
//  Lifetime counters shared between the container app and the extension.
//
//  Only aggregate counts are stored. No URLs, hostnames or page titles are
//  ever persisted.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SWKStatsStore : NSObject

/// Uses the app group named by the `SWKAppGroup` Info.plist key of the main
/// bundle, falling back to the process's own defaults when it is unavailable
/// (unsigned or unprovisioned builds).
+ (instancetype)sharedStore;

@property (nonatomic, readonly) NSUInteger trackersDetected;
@property (nonatomic, readonly) NSUInteger paramsRemoved;
@property (nonatomic, readonly) BOOL usesAppGroup;

- (void)addTrackersDetected:(NSUInteger)trackers paramsRemoved:(NSUInteger)params;

@end

NS_ASSUME_NONNULL_END
