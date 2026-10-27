# macOS Secure WebKit Extension

A privacy-focused Safari Web Extension for macOS, written in **Objective-C and C**, plus a container app that hosts a hardened **WebKit** browser pane built on the macOS **Security** framework.

It blocks third-party trackers, strips tracking parameters from links, and runs entirely on-device: the extension has no network access, and the only thing persisted is aggregate counters. Per-tab tracker hostnames shown in the popup live in session storage and are cleared when the tab navigates or closes.

| | |
|---|---|
| Languages | C11 (filter engine), Objective-C (app, Safari extension handler, WebKit integration), JavaScript (extension UI/content script) |
| Frameworks | WebKit (`WKWebView`, `WKContentRuleList`, `WKNavigationDelegate`), SafariServices (`SFSafariWebExtensionHandler`, `SFSafariExtensionManager`), Security (`SecTrust`, `SecPolicy`), AppKit, os_log |
| Platform | macOS 13+ (built and tested on macOS 26.6.2, Xcode 16.4, Intel x86_64) |
| Size | ~2,800 lines of C/Objective-C (+ ~430 lines of tests), 141 tracker domains, 55 tracking-parameter rules |

## Aim

Third-party trackers add network requests, leak browsing activity across sites and slow pages down. This project cuts that traffic off **before a connection is made**, on-device, without sending anything to a server.

Design targets:

- **Privacy:** block at least 95% of third-party tracking requests on typical pages, strip tracking identifiers (`fbclid`, `gclid`, `utm_*`, ...) from URLs, and keep all filtering local.
- **Performance:** load pages faster by dropping tracker requests at the rule level (declarative blocking, no JavaScript on the request path) and keeping the native matcher in the sub-microsecond range. The working target is roughly 20% faster loads on tracker-heavy pages.
- **Security posture:** HTTPS-only navigation, explicit TLS trust evaluation, least-privilege sandboxing.

How these targets are measured is described under [Evaluation](#evaluation).

## How it works

```
                 Blocklists/trackers.txt, tracking-params.txt   (single source of truth)
                                   │
                         Tools/swk_tool.c  ── `make rules`
                                   │  (same C parser/engine used at runtime)
        ┌──────────────┬───────────┴───────────┬────────────────┐
  trackers.json    params.json           webkit-rules.json   config.json
  Safari DNR       Safari DNR            WKContentRuleList   params for the
  block rules      redirect rules        (preview browser)   content script
        │              │                       │
 ┌──────┴──────────────┴─────┐          ┌──────┴────────────────────────────┐
 │ Safari Web Extension       │          │ Container app (SecureWebKit.app)   │
 │  • declarative blocking    │          │  • WKWebView, ephemeral storage    │
 │    (no JS in request path) │          │  • navigation policy → C engine    │
 │  • content.js: clean URL,  │          │  • HTTPS-only upgrade              │
 │    clean clicked links     │          │  • SecTrust server-trust checks    │
 │  • native messaging ──────►│ C engine │  • blocks downloads/popups/camera  │
 └────────────────────────────┘          └────────────────────────────────────┘
```

### The C core (`Core/`)

Portable C11, no dependencies beyond libc, shared by every component.

- **`swk_set.c`**: case-insensitive open-addressing hash set over a string arena. Keys are hashed *right to left*, so every label-aligned suffix of a hostname is a prefix of the hash state. `a.b.tracker.com` is matched against the list by hashing once and probing at each label boundary: **O(hostname length), independent of list size**, with no per-lookup allocation.
- **`swk_url.c`**: zero-copy URL parser (userinfo, IPv6 literals, ports, trailing dots) that rejects control characters and malformed authorities, plus an approximate registrable-domain (eTLD+1) table for first- vs third-party decisions.
- **`swk_engine.c`**: list parser (plain domains, hosts-file lines, Adblock `||domain^` anchors, `@@` allowlist), query-parameter sanitiser that preserves the encoding of untouched parameters, and the decision engine. Order: allowlist → tracker domain (third-party, non-main-frame only) → parameter stripping. Statistics use C11 atomics; an engine is safe to share across threads once loaded.
- **`swk_export.c`**: emits Safari `declarativeNetRequest` rulesets and a `WKContentRuleList`, so the extension and the app are guaranteed to enforce the same list.

### Safari extension (`Extension/`)

- `rules/trackers.json`, `rules/params.json`: **declarative** rules; Safari enforces them, so no JavaScript runs on the request path.
- `content.js`: removes tracking parameters from the address bar (`history.replaceState`) and from links at click time; after load it reports the page's third-party *hostnames only* (never URLs) to the native engine.
- `SafariWebExtensionHandler.m`: native-messaging endpoint (`ping`, `classify`, `report`, `stats`). Every message is treated as untrusted: fixed command set, strict type checks, size caps, clamped counters, hostnames containing URL syntax are skipped, and message contents are never logged.
- Least privilege: the extension is sandboxed with **no network entitlement**; permissions are `declarativeNetRequest`, `nativeMessaging`, `storage`, `activeTab`.

### Container app (`App/`)

A `WKWebView` host that shows the same protections working natively:

- **Ephemeral storage**: `WKWebsiteDataStore nonPersistentDataStore`; nothing a page stores survives quitting.
- **`WKContentRuleList`** compiled from the generated rules, attached before the first load.
- **`WKNavigationDelegate` policy hook** runs every navigation through the C engine: tracker frames cancelled, tracking parameters removed from GET navigations, non-HTTP(S) schemes refused.
- **HTTPS-only**: plain-HTTP main-frame loads are upgraded (loopback exempt) with a redirect-loop guard; plain-HTTP subframes are blocked.
- **TLS**: `didReceiveAuthenticationChallenge` evaluates server trust explicitly with `SecPolicyCreateSSL` (hostname-bound) + `SecPolicyCreateRevocation` and `SecTrustEvaluateWithError`; failures cancel the connection, with no click-through.
- **Denied by default**: unrenderable-MIME downloads, pop-up windows, camera/microphone requests.
- Reports whether the Safari extension is enabled (`SFSafariExtensionManager`) and opens its settings pane.

## Build and run

Developed and tested with Xcode 16.4. The project file uses the Xcode 14 format but older versions were not tried.

```sh
# C core: tests, sanitizer, benchmark, regenerate rules (no Xcode needed)
make test
make ubsan
make bench
make rules          # after editing Blocklists/*.txt
make check-rules    # fails if committed rules are stale

# Full app + extension (unsigned compile check)
xcodebuild -project SecureWebKit.xcodeproj -scheme SecureWebKit \
  CODE_SIGNING_ALLOWED=NO build
```

**To actually run the extension in Safari** you need a signed build:

1. `cp Config/Signing.local.xcconfig.example Config/Signing.local.xcconfig` and set your `DEVELOPMENT_TEAM`.
2. Open `SecureWebKit.xcodeproj`, run the **SecureWebKit** scheme.
3. Safari → Settings → Extensions → enable **Secure WebKit** and allow it on all websites.

Try `swk-tool` directly:

```sh
$ build/swk-tool eval --trackers Blocklists/trackers.txt --params Blocklists/tracking-params.txt \
    --first-party news.example.com \
    https://www.google-analytics.com/analytics.js \
    'https://shop.example.com/p?id=7&utm_source=mail&fbclid=abc'
block    tracker-domain   https://www.google-analytics.com/analytics.js  [google-analytics.com]
rewrite  tracking-params  https://shop.example.com/p?id=7&utm_source=mail&fbclid=abc
         -> https://shop.example.com/p?id=7
```

## Testing

| Check | Result |
|---|---|
| C unit tests (`make test`) | 20,220 checks, 0 failures; built with `-Wall -Wextra -Wpedantic -Wconversion -Werror` |
| UBSan (`make ubsan`) | clean |
| Allocator guard/scribble + `leaks --atExit` | clean, 0 leaks |
| ObjC native handler, driven through a mock `NSExtensionContext` | 16/16 checks, including malformed, oversized and hostile messages |
| Generated `WKContentRuleList` compiled by WebKit | compiles; a deliberately invalid rule is rejected (control) |
| Generated JSON | valid; rule ids unique |
| `xcodebuild` (Debug, signing off, warnings-as-errors) | succeeds, zero warnings |
| Built app launched | stays running; no errors on stderr |

**Testing scope and known gaps:**

- The extension has **not been run inside Safari**; this machine has no code-signing identity. The Safari `declarativeNetRequest` rules (especially the `queryTransform` parameter-removal redirects) are generated to spec but untested in Safari.
- The app's UI was launched but **not inspected visually or interacted with** (no screen-capture permission here).
- AddressSanitizer could not be used: Xcode 16.4's ASan runtime traps inside `libsystem_pthread` at process start on macOS 26 (before any project code runs). UBSan and the allocator checks above were used instead.
- `registrable domain` handling uses a small built-in table, not the full Public Suffix List.
- Prefix parameter rules (`utm_*`) run in the native engine and content script only; Safari's DNR can remove exact names, so the common `utm_*` names are also listed individually.

## Evaluation

The two headline targets are evaluated as follows.

**Tracking-request reduction** = 1 − (tracker requests with the extension ÷ tracker requests without it), over a fixed set of sites.

1. For each site, export a HAR from Safari with the extension off, then on.
2. Classify requests against an *independent* list (for example EasyPrivacy) so the evaluation list is not the blocklist being tested.
3. Report per-site and aggregate reduction, plus any broken-page reports.

For offline scoring, label requests in the corpus format (`<tracker|params|clean> <first-party|-> <url>`) and run `swk-tool bench --corpus <file>`.

**Page-load time:** Web Inspector (Network / Timelines) `load` time, at least 10 cold loads per site per configuration, reporting the median and spread, on both tracker-heavy and tracker-light pages.

### Regression benchmark (`make bench`)

A small hand-labelled corpus (`Bench/sample-corpus.txt`: 119 requests, 68 tracker / 12 tracking-parameter / 39 clean) guards the engine against regressions in matching speed and false positives:

```
engine:   141 tracker domains, 0 allowlisted, 55 tracking params (loaded in 0.15 ms)
tracker requests blocked:       68/68 = 100.0%
tracking-param URLs rewritten:  12/12 = 100.0%
clean requests wrongly touched: 0/39 = 0.0%
throughput: 518 ns/request (1.93 M requests/s) over 200000 evaluations
```

(Intel i7-9750H, `-O2`, single thread.) The corpus is authored against the bundled blocklist, so it exercises the engine; it is not a substitute for the real-world evaluation above.

## Layout

```
Core/            C11 engine (swk.h public API)       Tests/   C unit tests
Tools/           swk-tool CLI, icon generator         Bench/   labelled sample corpus
Blocklists/      trackers.txt, tracking-params.txt    Config/  xcconfig (app group, signing)
Extension/       Safari extension: handler + Resources/ (manifest, scripts, popup, generated rules)
App/             Container app (AppKit, WKWebView host)
Shared/          ObjC wrapper over the C engine, shared stats store
SecureWebKit.xcodeproj
```

## Limitations and next steps

- Run the real-world evaluation above across a fixed site set and publish the results table here.
- Starter blocklist is small and curated. Append a larger list (EasyPrivacy, Peter Lowe's) and run `make rules`. Rule count must stay under Safari's limit.
- No per-site pause/allowlist UI yet (allowlist is build-time via `@@domain` lines).
- Lifetime counters are shared between app and extension through an app group (`SWK_APP_GROUP`); requires a signed build, and a lost update between the two processes is possible.
- No license file has been chosen; add one before accepting contributions.
