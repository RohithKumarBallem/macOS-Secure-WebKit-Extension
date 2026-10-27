//
//  SWKEngine.h
//  Objective-C wrapper around the C filtering core (Core/include/swk.h).
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSErrorDomain const SWKErrorDomain;

typedef NS_ENUM(NSInteger, SWKAction) {
    SWKActionAllow = 0,
    SWKActionBlock = 1,
    SWKActionRewrite = 2,
};

typedef NS_ENUM(NSInteger, SWKResourceType) {
    SWKResourceTypeOther = 0,
    SWKResourceTypeMainFrame,
    SWKResourceTypeSubFrame,
    SWKResourceTypeScript,
    SWKResourceTypeImage,
    SWKResourceTypeStylesheet,
    SWKResourceTypeXHR,
    SWKResourceTypePing,
};

@interface SWKDecision : NSObject
@property (nonatomic, readonly) SWKAction action;
/// Stable machine-readable reason, e.g. "tracker-domain" or "tracking-params".
@property (nonatomic, readonly, copy) NSString *reason;
/// The blocklist/allowlist entry that matched, if any.
@property (nonatomic, readonly, copy, nullable) NSString *matchedDomain;
/// Set when action == SWKActionRewrite.
@property (nonatomic, readonly, copy, nullable) NSURL *rewrittenURL;
@property (nonatomic, readonly) NSUInteger removedParameters;
@end

@interface SWKEngineStats : NSObject
@property (nonatomic, readonly) uint64_t evaluated;
@property (nonatomic, readonly) uint64_t blocked;
@property (nonatomic, readonly) uint64_t rewritten;
@property (nonatomic, readonly) uint64_t parametersRemoved;
@end

/// Thread-safe once initialised: evaluate from any queue.
@interface SWKEngine : NSObject

/// Loads trackers.txt and tracking-params.txt from `bundle`'s resources.
- (nullable instancetype)initWithBundle:(NSBundle *)bundle error:(NSError **)error NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@property (nonatomic, readonly) NSUInteger trackerCount;
@property (nonatomic, readonly) NSUInteger parameterCount;
@property (nonatomic, readonly) SWKEngineStats *stats;

- (SWKDecision *)evaluateURL:(NSURL *)url
              firstPartyHost:(nullable NSString *)firstPartyHost
                        type:(SWKResourceType)type;

/// The subset of `hosts` (bare hostnames) the engine would block as third-party
/// trackers on a page served from `firstPartyHost`. Order is preserved.
- (NSArray<NSString *> *)trackerHostsAmong:(NSArray<NSString *> *)hosts
                                firstParty:(nullable NSString *)firstPartyHost;

@end

NS_ASSUME_NONNULL_END
