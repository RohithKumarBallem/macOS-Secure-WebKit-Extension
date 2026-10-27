/*
 * swk.h - Secure WebKit filtering core.
 *
 * Portable C11, no dependencies beyond libc. The same code backs the Safari
 * extension handler, the container app's WKWebView and the swk-tool CLI.
 *
 * Threading: build an engine (swk_engine_load_*), then share it freely.
 * swk_engine_evaluate() and swk_engine_sanitize_url() are safe to call from
 * many threads once loading has finished; loading must not race with them.
 */
#ifndef SWK_H
#define SWK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SWK_CORE_VERSION "1.0.0"

#define SWK_MAX_HOST 253   /* RFC 1035 */
#define SWK_MAX_URL  8192  /* longer URLs are not evaluated (treated as allow) */

/* ------------------------------------------------------------------ */
/* String set: case-insensitive (ASCII), insertion-ordered, with an O(labels)
 * domain-suffix lookup. Keys are copied into an arena, so there is one
 * allocation per growth step rather than one per entry. */

typedef struct swk_set swk_set;

swk_set *swk_set_new(size_t expected);
void     swk_set_free(swk_set *s);

/* 1 = added, 0 = already present, -1 = invalid key or out of memory. */
int      swk_set_add(swk_set *s, const char *key, size_t len);
bool     swk_set_contains(const swk_set *s, const char *key, size_t len);
size_t   swk_set_count(const swk_set *s);
/* Entry `index` in insertion order (NOT NUL-terminated), or NULL. */
const char *swk_set_at(const swk_set *s, size_t index, size_t *len);

/* True if `host` or any parent domain of it (at least two labels) is in the
 * set. `*match_off`, if non-NULL, receives the offset of the matching suffix. */
bool     swk_set_match_domain(const swk_set *s, const char *host, size_t len,
                              size_t *match_off);

/* ------------------------------------------------------------------ */
/* URL parsing (zero-copy, hierarchical URLs only). */

typedef struct { const char *ptr; size_t len; } swk_slice;

typedef struct {
    swk_slice scheme;
    swk_slice host;      /* no userinfo/port, one trailing dot removed, case preserved */
    swk_slice path;
    swk_slice query;     /* without '?' */
    swk_slice fragment;  /* without '#' */
    uint16_t  port;      /* 0 when absent */
    bool      has_query;
    bool      has_fragment;
    bool      host_is_ip;
} swk_url;

/* False for anything that is not a well-formed scheme://host... URL
 * (data:, about:, javascript:, control characters, bad port, ...). */
bool swk_url_parse(const char *s, size_t len, swk_url *out);

bool   swk_host_is_ip(const char *host, size_t len);
/* Offset of the registrable domain (approximate eTLD+1) inside `host`. */
size_t swk_registrable_offset(const char *host, size_t len);
/* True when both hosts share a registrable domain (or are the same IP). */
bool   swk_same_site(const char *a, size_t alen, const char *b, size_t blen);

/* ------------------------------------------------------------------ */
/* Engine */

typedef struct swk_engine swk_engine;

typedef enum {
    SWK_ALLOW   = 0,
    SWK_BLOCK   = 1,
    SWK_REWRITE = 2   /* load decision.out_url instead */
} swk_action;

typedef enum {
    SWK_REASON_NONE = 0,
    SWK_REASON_NOT_NETWORK,       /* not an http(s)/ws(s) URL, or unparseable */
    SWK_REASON_ALLOWLIST,
    SWK_REASON_TRACKER_DOMAIN,
    SWK_REASON_FIRST_PARTY,       /* tracker domain, but it is the page's own site */
    SWK_REASON_USER_NAVIGATION,   /* tracker domain, but a top-level navigation */
    SWK_REASON_TRACKING_PARAMS,
    SWK_REASON_OUTPUT_TOO_SMALL   /* rewrite needed but out buffer was too small */
} swk_reason;

typedef enum {
    SWK_RT_OTHER = 0,
    SWK_RT_MAIN_FRAME,   /* user-initiated top-level navigation: never blocked */
    SWK_RT_SUB_FRAME,
    SWK_RT_SCRIPT,
    SWK_RT_IMAGE,
    SWK_RT_STYLESHEET,
    SWK_RT_XHR,
    SWK_RT_PING
} swk_resource_type;

typedef struct {
    swk_action action;
    swk_reason reason;
    size_t     removed_params;
    size_t     out_len;                  /* length written to `out` on SWK_REWRITE */
    char       matched[SWK_MAX_HOST + 1];/* matching list entry for BLOCK/ALLOW */
} swk_decision;

typedef struct {
    uint64_t evaluated;
    uint64_t blocked;
    uint64_t rewritten;
    uint64_t params_removed;
} swk_stats;

typedef struct {
    size_t accepted;
    size_t duplicates;
    size_t rejected;
} swk_load_report;

swk_engine *swk_engine_new(void);
void        swk_engine_free(swk_engine *e);

/* Tracker list. Accepted line formats (blank lines and # / ! comments ignored):
 *     example.com                plain domain
 *     0.0.0.0 example.com        hosts file
 *     ||example.com^             Adblock-style domain anchor (options ignored)
 *     @@example.com / @@||...    allowlist entry (wins over the blocklist)
 * A domain also covers its subdomains. */
swk_load_report swk_engine_load_trackers(swk_engine *e, const char *text, size_t len);

/* Tracking query parameters, one per line. `name` is an exact match,
 * `prefix*` matches any parameter starting with `prefix`. */
swk_load_report swk_engine_load_params(swk_engine *e, const char *text, size_t len);

size_t swk_engine_tracker_count(const swk_engine *e);
size_t swk_engine_allow_count(const swk_engine *e);
size_t swk_engine_param_count(const swk_engine *e);

/* Decide what to do with a request for `url`.
 *   first_party_host - hostname of the page making the request, or NULL.
 *   out/out_cap      - receives the sanitized URL for SWK_REWRITE (>= url_len+1
 *                      bytes is always enough). May be NULL if rewriting is
 *                      not wanted.
 * Order: allowlist > tracker domain (third-party, non-main-frame) > param strip. */
swk_decision swk_engine_evaluate(swk_engine *e, const char *url, size_t url_len,
                                 const char *first_party_host,
                                 swk_resource_type type,
                                 char *out, size_t out_cap);

#define SWK_OK          0
#define SWK_E_PARSE    (-1)
#define SWK_E_NOSPACE  (-2)

/* Strip tracking query parameters. If none are present nothing is written and
 * *out_len == url_len. Otherwise the result (NUL-terminated) goes to `out`. */
int swk_engine_sanitize_url(swk_engine *e, const char *url, size_t url_len,
                            char *out, size_t out_cap,
                            size_t *out_len, size_t *removed);

swk_stats swk_engine_stats(const swk_engine *e);

const char *swk_action_name(swk_action a);
const char *swk_reason_name(swk_reason r);

/* ------------------------------------------------------------------ */
/* Rule export. Returns a malloc'd NUL-terminated string (free() it) or NULL.
 * Output is deterministic: entries appear in list order. */

typedef enum {
    SWK_EXPORT_DNR_TRACKERS,   /* Safari declarativeNetRequest block + allow rules */
    SWK_EXPORT_DNR_PARAMS,     /* DNR redirect rules that strip tracking params */
    SWK_EXPORT_WEBKIT_RULES,   /* WKContentRuleList / Safari content blocker JSON */
    SWK_EXPORT_CONFIG          /* params + counts for the extension's content script */
} swk_export_format;

char *swk_engine_export(const swk_engine *e, swk_export_format fmt);

#ifdef __cplusplus
}
#endif

#endif /* SWK_H */
