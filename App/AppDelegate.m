//
//  AppDelegate.m
//

#import "AppDelegate.h"

#import "SWKEngine.h"
#import "SWKMainWindowController.h"

@implementation AppDelegate {
    SWKMainWindowController *_windowController;
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
    [self buildMenu];

    NSError *error = nil;
    SWKEngine *engine = [[SWKEngine alloc] initWithBundle:NSBundle.mainBundle error:&error];
    if (!engine) {
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"Secure WebKit could not load its filter lists";
        alert.informativeText = error.localizedDescription ?: @"Unknown error.";
        [alert runModal];
        [NSApp terminate:nil];
        return;
    }

    _windowController = [[SWKMainWindowController alloc] initWithEngine:engine];
    [_windowController showWindow:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender
{
    return YES;
}

- (BOOL)applicationSupportsSecureRestorableState:(NSApplication *)app
{
    return YES;
}

- (void)focusAddress:(id)sender { [_windowController focusAddressField]; }
- (void)reloadPage:(id)sender { [_windowController reload]; }

#pragma mark - Menu

- (NSMenuItem *)item:(NSString *)title action:(SEL)action key:(NSString *)key target:(id)target
{
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:action keyEquivalent:key];
    item.target = target;
    return item;
}

- (void)buildMenu
{
    NSMenu *bar = [[NSMenu alloc] init];
    NSString *name = @"Secure WebKit";

    NSMenuItem *appItem = [[NSMenuItem alloc] init];
    NSMenu *app = [[NSMenu alloc] initWithTitle:name];
    [app addItem:[self item:[@"Hide " stringByAppendingString:name] action:@selector(hide:) key:@"h" target:NSApp]];
    [app addItem:NSMenuItem.separatorItem];
    [app addItem:[self item:[@"Quit " stringByAppendingString:name] action:@selector(terminate:) key:@"q" target:NSApp]];
    appItem.submenu = app;
    [bar addItem:appItem];

    NSMenuItem *editItem = [[NSMenuItem alloc] init];
    NSMenu *edit = [[NSMenu alloc] initWithTitle:@"Edit"];
    [edit addItem:[self item:@"Undo" action:NSSelectorFromString(@"undo:") key:@"z" target:nil]];
    [edit addItem:[self item:@"Redo" action:NSSelectorFromString(@"redo:") key:@"Z" target:nil]];
    [edit addItem:NSMenuItem.separatorItem];
    [edit addItem:[self item:@"Cut" action:@selector(cut:) key:@"x" target:nil]];
    [edit addItem:[self item:@"Copy" action:@selector(copy:) key:@"c" target:nil]];
    [edit addItem:[self item:@"Paste" action:@selector(paste:) key:@"v" target:nil]];
    [edit addItem:[self item:@"Select All" action:@selector(selectAll:) key:@"a" target:nil]];
    editItem.submenu = edit;
    [bar addItem:editItem];

    NSMenuItem *navItem = [[NSMenuItem alloc] init];
    NSMenu *nav = [[NSMenu alloc] initWithTitle:@"Navigate"];
    [nav addItem:[self item:@"Open Address…" action:@selector(focusAddress:) key:@"l" target:self]];
    [nav addItem:[self item:@"Reload" action:@selector(reloadPage:) key:@"r" target:self]];
    navItem.submenu = nav;
    [bar addItem:navItem];

    NSMenuItem *windowItem = [[NSMenuItem alloc] init];
    NSMenu *window = [[NSMenu alloc] initWithTitle:@"Window"];
    [window addItem:[self item:@"Minimize" action:@selector(performMiniaturize:) key:@"m" target:nil]];
    [window addItem:[self item:@"Close" action:@selector(performClose:) key:@"w" target:nil]];
    windowItem.submenu = window;
    [bar addItem:windowItem];

    NSApp.mainMenu = bar;
    NSApp.windowsMenu = window;
}

@end
