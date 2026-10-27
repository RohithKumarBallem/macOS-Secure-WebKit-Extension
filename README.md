# macOS Secure WebKit Extension

A privacy-focused Safari Web Extension for macOS, written in **Objective-C and C**, plus a container app that hosts a hardened **WebKit** browser pane built on the macOS **Security** framework.

It blocks third-party trackers, strips tracking parameters from links, and runs entirely on-device: no network access in the extension, no URLs or hostnames ever stored.

| | |
|---|---|
| Languages | C11 (filter engine), Objective-C (app, Safari extension handler, WebKit integration), JavaScript (extension UI/content script) |
| Frameworks | WebKit (`WKWebView`, `WKContentRuleList`, `WKNavigationDelegate`), SafariServices (`SFSafariWebExtensionHandler`, `SFSafariExtensionManager`), Security (`SecTrust`, `SecPolicy`), AppKit, os_log |
| Platform | macOS 13+ (built and tested on macOS 26.6.2, Xcode 16.4, Intel x86_64) |
| Size | ~2,800 lines of C/Objective-C (+ ~430 lines of tests), 141 tracker domains, 55 tracking-parameter rules |

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

## Verification: what was actually run

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

**Not verified (be upfront about this):**

- The extension has **not been run inside Safari**; this machine has no code-signing identity. The Safari `declarativeNetRequest` rules (especially the `queryTransform` parameter-removal redirects) are generated to spec but untested in Safari.
- The app's UI was launched but **not inspected visually or interacted with** (no screen-capture permission here).
- AddressSanitizer could not be used: Xcode 16.4's ASan runtime traps inside `libsystem_pthread` at process start on macOS 26 (before any project code runs). UBSan and the allocator checks above were used instead.
- `registrable domain` handling uses a small built-in table, not the full Public Suffix List.
- Prefix parameter rules (`utm_*`) run in the native engine and content script only; Safari's DNR can remove exact names, so the common `utm_*` names are also listed individually.

## Benchmark

`make bench` replays `Bench/sample-corpus.txt` (119 labelled requests: 68 tracker, 12 tracking-parameter, 39 clean):

```
engine:   141 tracker domains, 0 allowlisted, 55 tracking params (loaded in 0.15 ms)
tracker requests blocked:       68/68 = 100.0%
tracking-param URLs rewritten:  12/12 = 100.0%
clean requests wrongly touched: 0/39 = 0.0%
throughput: 518 ns/request (1.93 M requests/s) over 200000 evaluations
```

(Intel i7-9750H, `-O2`, single thread.)

> **Read this before quoting these numbers.** The corpus is hand-written by the author against the same blocklist, so the block rate describes *the corpus*, not real-world traffic. The **throughput** and **false-positive** figures are the meaningful ones. On the first run two tracker URLs were missed (Mixpanel's CDN, HubSpot's tracking host); I added those hostnames to the list, which is why it now reads 100%. A score you can raise by editing the list you are testing against says little about real-world effectiveness.

## Résumé guidance

**This repository does *not* measure "95% fewer tracking requests" or "20% faster page loads."** Those require data this project doesn't contain. Only claim them if you measured them elsewhere; otherwise use wording the repo supports. Safe, accurate claims:

- Built a Safari Web Extension and container app for macOS in **Objective-C and C**, integrating **WebKit** (`WKContentRuleList`, `WKNavigationDelegate`, ephemeral data stores) and **Security framework** APIs (`SecTrust`/`SecPolicy` server-trust evaluation) to enforce HTTPS-only browsing and block third-party trackers.
- Wrote a portable **C11 filtering engine**: right-to-left-hashed domain-suffix set giving O(hostname-length) matching independent of list size; ~0.5 µs per request (≈1.9 M requests/s single-threaded, measured on a labelled 119-request corpus); zero-copy URL parser; tracking-parameter sanitiser.
- Compiled one blocklist into Safari `declarativeNetRequest` rules and a `WKContentRuleList` with a C code generator, so blocking is enforced declaratively with no JavaScript in the request path.
- Hardened the native-messaging boundary (command allowlist, type/size validation, no logging of page data) and sandboxed the extension with no network entitlement; **20,220-check** unit-test suite, UBSan and leak checks clean.

Notes on wording: Safari extensions cannot hook sockets, so "intercept" is accurate for the app's `WKNavigationDelegate` policy hook and for declarative rules, not for system-wide traffic. If you want the percentage claims, measure them:

- **Tracking-request reduction**: export a HAR from Safari for ~20 real sites with the extension off and on, label requests against an independent list (e.g. EasyPrivacy), and compare counts. Add your labelled requests to the corpus format (`<tracker|params|clean> <first-party|-> <url>`) and run `swk-tool bench`.
- **Page load**: use Web Inspector's Timelines/Network `load` time, ≥10 cold loads per site per configuration, report median and spread.

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

- Starter blocklist is small and curated. Append a larger list (EasyPrivacy, Peter Lowe's) and run `make rules`. Rule count must stay under Safari's limit.
- No per-site pause/allowlist UI yet (allowlist is build-time via `@@domain` lines).
- Lifetime counters are shared between app and extension through an app group (`SWK_APP_GROUP`); requires a signed build, and a lost update between the two processes is possible.
- No license file has been chosen; add one before accepting contributions.
