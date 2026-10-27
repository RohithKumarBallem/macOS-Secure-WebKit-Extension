//
//  SWKMainWindowController.m
//
//  One window: the Safari extension's status on top, a secure preview browser in
//  the middle, and the security event log and counters at the bottom.
//

#import "SWKMainWindowController.h"

#import <SafariServices/SafariServices.h>

#import "SWKEngine.h"
#import "SWKSecureBrowser.h"
#import "SWKStatsStore.h"

static NSString * const kWelcomeHTML =
    @"<!doctype html><meta charset=utf-8><meta name=color-scheme content='light dark'>"
    @"<style>body{font:15px -apple-system,sans-serif;max-width:560px;margin:48px auto;padding:0 20px;line-height:1.5}"
    @"code{background:rgba(127,127,127,.18);padding:1px 5px;border-radius:4px}li{margin:6px 0}</style>"
    @"<h1>Secure WebKit preview</h1>"
    @"<p>This browser pane runs the same filtering engine as the Safari extension. Try:</p><ul>"
    @"<li><a href='https://example.com/?utm_source=demo&amp;fbclid=abc123&amp;keep=1'>A link with tracking parameters</a> "
    @"&mdash; they are removed before the request is made.</li>"
    @"<li><a href='http://example.com/'>A plain-HTTP link</a> &mdash; upgraded to HTTPS.</li>"
    @"<li>Any page with ads or analytics &mdash; third-party tracker requests are blocked.</li></ul>"
    @"<p>Cookies and site data are discarded when you quit.</p>";

@interface SWKMainWindowController () <NSTextFieldDelegate, SWKSecureBrowserDelegate>
@end

@implementation SWKMainWindowController {
    SWKEngine *_engine;
    SWKSecureBrowser *_browser;
    NSTextField *_addressField;
    NSTextField *_eventLabel;
    NSTextField *_extensionLabel;
    NSTextField *_statsLabel;
    NSButton *_settingsButton;
}

- (instancetype)initWithEngine:(SWKEngine *)engine
{
    NSWindow *window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 980, 720)
                                                   styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                                             NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
                                                     backing:NSBackingStoreBuffered
                                                       defer:NO];
    window.title = @"Secure WebKit";
    window.minSize = NSMakeSize(640, 420);
    window.releasedWhenClosed = NO;

    if ((self = [super initWithWindow:window])) {
        _engine = engine;
        _browser = [[SWKSecureBrowser alloc] initWithEngine:engine];
        _browser.delegate = self;
        [self buildInterface];
        [window center];

        [NSNotificationCenter.defaultCenter addObserver:self
                                               selector:@selector(refreshExtensionState)
                                                   name:NSApplicationDidBecomeActiveNotification
                                                 object:nil];
        [self refreshExtensionState];
        [self refreshStats];
        [_browser.webView loadHTMLString:kWelcomeHTML baseURL:nil];
    }
    return self;
}

- (void)dealloc
{
    [NSNotificationCenter.defaultCenter removeObserver:self];
}

#pragma mark - UI

static NSTextField *Label(NSFont *font, NSColor *color)
{
    NSTextField *label = [NSTextField labelWithString:@""];
    label.font = font;
    label.textColor = color;
    label.lineBreakMode = NSLineBreakByTruncatingTail;
    [label setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationHorizontal];
    return label;
}

- (void)buildInterface
{
    NSView *content = self.window.contentView;

    _addressField = [NSTextField textFieldWithString:@""];
    _addressField.placeholderString = @"Enter an address (HTTPS only)";
    _addressField.delegate = self;
    _addressField.target = self;
    _addressField.action = @selector(goPressed:);

    NSButton *go = [NSButton buttonWithTitle:@"Go" target:self action:@selector(goPressed:)];
    go.keyEquivalent = @"";
    NSStackView *toolbar = [NSStackView stackViewWithViews:@[ _addressField, go ]];
    toolbar.spacing = 8;

    _extensionLabel = Label([NSFont systemFontOfSize:12 weight:NSFontWeightMedium], NSColor.labelColor);
    _settingsButton = [NSButton buttonWithTitle:@"Open Safari Extension Settings…" target:self action:@selector(openSafariSettings:)];
    _settingsButton.controlSize = NSControlSizeSmall;
    NSView *spacer = [[NSView alloc] init];
    [spacer setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationHorizontal];
    NSStackView *extensionRow = [NSStackView stackViewWithViews:@[ _extensionLabel, spacer, _settingsButton ]];
    extensionRow.spacing = 8;

    _eventLabel = Label([NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular], NSColor.secondaryLabelColor);
    _eventLabel.stringValue = @"Starting…";
    _statsLabel = Label([NSFont systemFontOfSize:11], NSColor.secondaryLabelColor);

    NSBox *rule = [[NSBox alloc] init];
    rule.boxType = NSBoxSeparator;

    NSStackView *stack = [NSStackView stackViewWithViews:@[ extensionRow, toolbar, _browser.webView, rule, _eventLabel, _statsLabel ]];
    stack.orientation = NSUserInterfaceLayoutOrientationVertical;
    stack.alignment = NSLayoutAttributeLeading;
    stack.spacing = 8;
    stack.edgeInsets = NSEdgeInsetsMake(12, 14, 10, 14);
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:content.leadingAnchor],
        [stack.trailingAnchor constraintEqualToAnchor:content.trailingAnchor],
        [stack.topAnchor constraintEqualToAnchor:content.topAnchor],
        [stack.bottomAnchor constraintEqualToAnchor:content.bottomAnchor],
        [toolbar.widthAnchor constraintEqualToAnchor:stack.widthAnchor constant:-28],
        [extensionRow.widthAnchor constraintEqualToAnchor:stack.widthAnchor constant:-28],
        [_browser.webView.widthAnchor constraintEqualToAnchor:stack.widthAnchor constant:-28],
        [rule.widthAnchor constraintEqualToAnchor:stack.widthAnchor constant:-28],
        [_eventLabel.widthAnchor constraintEqualToAnchor:stack.widthAnchor constant:-28],
        [_statsLabel.widthAnchor constraintEqualToAnchor:stack.widthAnchor constant:-28],
    ]];
    [_browser.webView setContentHuggingPriority:1 forOrientation:NSLayoutConstraintOrientationVertical];
    [_browser.webView setContentCompressionResistancePriority:1 forOrientation:NSLayoutConstraintOrientationVertical];
}

- (void)focusAddressField
{
    [self.window makeFirstResponder:_addressField];
}

- (void)reload
{
    [_browser.webView reload];
}

- (void)goPressed:(id)sender
{
    [_browser loadAddress:_addressField.stringValue];
}

#pragma mark - Extension state

static NSString *ExtensionBundleIdentifier(void)
{
    return [NSBundle.mainBundle.bundleIdentifier stringByAppendingString:@".Extension"];
}

- (void)refreshExtensionState
{
    [SFSafariExtensionManager getStateOfSafariExtensionWithIdentifier:ExtensionBundleIdentifier()
                                                    completionHandler:^(SFSafariExtensionState *state, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!state) {
                self->_extensionLabel.stringValue = @"Safari extension: not found (build and run the app from Xcode with signing enabled)";
                self->_extensionLabel.textColor = NSColor.systemOrangeColor;
            } else if (state.isEnabled) {
                self->_extensionLabel.stringValue = @"Safari extension: enabled";
                self->_extensionLabel.textColor = NSColor.systemGreenColor;
            } else {
                self->_extensionLabel.stringValue = @"Safari extension: installed but turned off in Safari";
                self->_extensionLabel.textColor = NSColor.systemOrangeColor;
            }
        });
    }];
}

- (void)openSafariSettings:(id)sender
{
    [SFSafariApplication showPreferencesForExtensionWithIdentifier:ExtensionBundleIdentifier() completionHandler:^(NSError *error) {
        if (error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self->_eventLabel.stringValue = [NSString stringWithFormat:@"Could not open Safari settings: %@", error.localizedDescription];
            });
        }
    }];
}

#pragma mark - SWKSecureBrowserDelegate

- (void)secureBrowser:(SWKSecureBrowser *)browser didLogEvent:(NSString *)event
{
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_eventLabel.stringValue = event;
        [self refreshStats];
    });
}

- (void)secureBrowserDidChangeLocation:(SWKSecureBrowser *)browser
{
    NSURL *url = browser.webView.URL;
    if (url && ![url.scheme isEqualToString:@"about"])
        _addressField.stringValue = url.absoluteString;
    [self refreshStats];
}

- (void)refreshStats
{
    SWKStatsStore *store = SWKStatsStore.sharedStore;
    _statsLabel.stringValue = [NSString stringWithFormat:
        @"This session: %lu blocked · %lu upgraded to HTTPS · %lu tracking parameters removed.   All time (app + extension): %lu trackers, %lu parameters.   Engine: %lu tracker domains.",
        (unsigned long)_browser.blockedCount, (unsigned long)_browser.upgradedCount, (unsigned long)_browser.paramsRemovedCount,
        (unsigned long)store.trackersDetected, (unsigned long)store.paramsRemoved, (unsigned long)_engine.trackerCount];
}

@end
