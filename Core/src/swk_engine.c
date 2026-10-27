#include "swk_internal.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Lifecycle */

swk_engine *swk_engine_new(void)
{
    swk_engine *e = calloc(1, sizeof *e);
    if (!e)
        return NULL;
    e->trackers = swk_set_new(4096);
    e->allow = swk_set_new(64);
    e->params = swk_set_new(128);
    e->prefixes = swk_set_new(16);
    if (!e->trackers || !e->allow || !e->params || !e->prefixes) {
        swk_engine_free(e);
        return NULL;
    }
    return e;
}

void swk_engine_free(swk_engine *e)
{
    if (!e)
        return;
    swk_set_free(e->trackers);
    swk_set_free(e->allow);
    swk_set_free(e->params);
    swk_set_free(e->prefixes);
    free(e);
}

size_t swk_engine_tracker_count(const swk_engine *e) { return e ? swk_set_count(e->trackers) : 0; }
size_t swk_engine_allow_count(const swk_engine *e)   { return e ? swk_set_count(e->allow) : 0; }
size_t swk_engine_param_count(const swk_engine *e)
{
    return e ? swk_set_count(e->params) + swk_set_count(e->prefixes) : 0;
}

/* ------------------------------------------------------------------ */
/* List parsing */

static bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r'; }

static bool is_domain_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
}

/* Strict hostname check. Needs >= 2 labels and a non-numeric TLD, which also
 * rejects the "0.0.0.0" placeholder entries found in hosts files. */
static bool valid_domain(const char *s, size_t n)
{
    if (n < 4 || n > SWK_MAX_HOST)
        return false;
    size_t label = 0, labels = 1;
    bool tld_has_alpha = false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!is_domain_char(c))
            return false;
        if (c == '.') {
            if (label == 0 || s[i - 1] == '-')
                return false;
            labels++;
            label = 0;
            tld_has_alpha = false;
            continue;
        }
        if (c == '-' && label == 0)
            return false;
        if (++label > 63)
            return false;
        if (c >= 'a' && c <= 'z')
            tld_has_alpha = true;
    }
    return labels >= 2 && label > 0 && s[n - 1] != '-' && tld_has_alpha;
}

static bool valid_param(const char *s, size_t n)
{
    if (n == 0 || n > 64)
        return false;
    bool alnum = false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        bool is_alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        if (!is_alnum && c != '_' && c != '-' && c != '.')
            return false;
        alnum |= is_alnum;
    }
    return alnum;  /* "-" or "__" alone is a typo, not a parameter name */
}

static bool looks_like_ip_token(const char *s, size_t n)
{
    if (n == 0)
        return false;
    bool colon = false, dot = false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == ':') colon = true;
        else if (c == '.') dot = true;
        else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return colon || dot;
}

typedef struct {
    const char *ptr;
    size_t len;
} span;

static span trim(span s)
{
    while (s.len && is_space(s.ptr[0])) { s.ptr++; s.len--; }
    while (s.len && is_space(s.ptr[s.len - 1])) s.len--;
    return s;
}

/* Reduces one list line to a bare domain. Returns false for skippable lines. */
static bool extract_domain(span line, span *domain, bool *allow)
{
    *allow = false;

    /* Inline "# comment" (but a leading '#' is a full-line comment). */
    for (size_t i = 0; i < line.len; i++) {
        if (line.ptr[i] == '#' && (i == 0 || is_space(line.ptr[i - 1]))) {
            line.len = i;
            break;
        }
    }
    line = trim(line);
    if (line.len == 0 || line.ptr[0] == '!' || line.ptr[0] == '[')
        return false;

    if (line.len >= 2 && line.ptr[0] == '@' && line.ptr[1] == '@') {
        *allow = true;
        line.ptr += 2;
        line.len -= 2;
    }
    if (line.len >= 2 && line.ptr[0] == '|' && line.ptr[1] == '|') {
        line.ptr += 2;
        line.len -= 2;
    }

    /* First whitespace-separated token; hosts files put an address first. */
    size_t tok = 0;
    while (tok < line.len && !is_space(line.ptr[tok]))
        tok++;
    span first = { line.ptr, tok };
    span rest = trim((span){ line.ptr + tok, line.len - tok });
    if (rest.len && looks_like_ip_token(first.ptr, first.len)) {
        size_t t2 = 0;
        while (t2 < rest.len && !is_space(rest.ptr[t2]))
            t2++;
        first = (span){ rest.ptr, t2 };
    }

    /* Adblock-style options / separators end the domain. */
    for (size_t i = 0; i < first.len; i++) {
        char c = first.ptr[i];
        if (c == '^' || c == '$' || c == '/' || c == '|') {
            first.len = i;
            break;
        }
    }

    if (first.len >= 2 && first.ptr[0] == '*' && first.ptr[1] == '.') {
        first.ptr += 2;
        first.len -= 2;
    }
    while (first.len && first.ptr[0] == '.') { first.ptr++; first.len--; }
    while (first.len && first.ptr[first.len - 1] == '.') first.len--;

    *domain = first;
    return true;
}

static void count_add(swk_load_report *r, int rc)
{
    if (rc > 0) r->accepted++;
    else if (rc == 0) r->duplicates++;
    else r->rejected++;
}

swk_load_report swk_engine_load_trackers(swk_engine *e, const char *text, size_t len)
{
    swk_load_report r = { 0, 0, 0 };
    if (!e || !text)
        return r;

    const char *p = text, *end = text + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *line_end = nl ? nl : end;
        span domain;
        bool allow;
        if (extract_domain((span){ p, (size_t)(line_end - p) }, &domain, &allow)) {
            char buf[SWK_MAX_HOST + 1];
            if (domain.len > SWK_MAX_HOST) {
                r.rejected++;
            } else {
                for (size_t i = 0; i < domain.len; i++) {
                    char c = domain.ptr[i];
                    buf[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
                }
                if (valid_domain(buf, domain.len))
                    count_add(&r, swk_set_add(allow ? e->allow : e->trackers, buf, domain.len));
                else
                    r.rejected++;
            }
        }
        p = nl ? nl + 1 : end;
    }
    return r;
}

swk_load_report swk_engine_load_params(swk_engine *e, const char *text, size_t len)
{
    swk_load_report r = { 0, 0, 0 };
    if (!e || !text)
        return r;

    const char *p = text, *end = text + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        span line = { p, (size_t)((nl ? nl : end) - p) };
        for (size_t i = 0; i < line.len; i++) {
            if (line.ptr[i] == '#') {
                line.len = i;
                break;
            }
        }
        line = trim(line);
        if (line.len) {
            bool prefix = line.ptr[line.len - 1] == '*';
            size_t n = prefix ? line.len - 1 : line.len;
            if (!valid_param(line.ptr, n) || (prefix && n < 2))
                r.rejected++;
            else
                count_add(&r, swk_set_add(prefix ? e->prefixes : e->params, line.ptr, n));
        }
        p = nl ? nl + 1 : end;
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* Query sanitising */

static bool is_tracking_param(const swk_engine *e, const char *name, size_t n)
{
    if (n == 0)
        return false;
    if (n <= SWK_MAX_HOST && swk_set_contains(e->params, name, n))
        return true;

    size_t count = swk_set_count(e->prefixes);
    for (size_t i = 0; i < count; i++) {
        size_t plen;
        const char *pre = swk_set_at(e->prefixes, i, &plen);
        if (n < plen)
            continue;
        size_t k = 0;
        for (; k < plen; k++) {
            char c = name[k];
            if (c >= 'A' && c <= 'Z')
                c = (char)(c + 32);
            if (c != pre[k])
                break;
        }
        if (k == plen)
            return true;
    }
    return false;
}

static size_t put(char *out, size_t cap, size_t pos, const char *s, size_t n)
{
    if (out && pos + n <= cap)
        memcpy(out + pos, s, n);
    return pos + n;
}

/* Walks the query once. With out == NULL it only counts. Returns the length of
 * the rewritten URL; *removed is the number of parameters dropped. */
static size_t sanitize(const swk_engine *e, const swk_url *u, const char *url,
                       size_t url_len, char *out, size_t cap, size_t *removed)
{
    *removed = 0;
    if (!u->has_query)
        return url_len;

    const char *q = u->query.ptr, *q_end = q + u->query.len;

    for (const char *s = q; s < q_end;) {
        const char *amp = memchr(s, '&', (size_t)(q_end - s));
        const char *seg_end = amp ? amp : q_end;
        const char *eq = memchr(s, '=', (size_t)(seg_end - s));
        if (is_tracking_param(e, s, (size_t)((eq ? eq : seg_end) - s)))
            (*removed)++;
        s = amp ? amp + 1 : q_end;
    }
    if (*removed == 0)
        return url_len;

    size_t pos = put(out, cap, 0, url, (size_t)(q - 1 - url));  /* up to, not incl., '?' */
    char sep = '?';
    for (const char *s = q; s < q_end;) {
        const char *amp = memchr(s, '&', (size_t)(q_end - s));
        const char *seg_end = amp ? amp : q_end;
        const char *eq = memchr(s, '=', (size_t)(seg_end - s));
        if (seg_end > s && !is_tracking_param(e, s, (size_t)((eq ? eq : seg_end) - s))) {
            pos = put(out, cap, pos, &sep, 1);
            pos = put(out, cap, pos, s, (size_t)(seg_end - s));
            sep = '&';
        }
        s = amp ? amp + 1 : q_end;
    }
    if (u->has_fragment) {
        pos = put(out, cap, pos, "#", 1);
        pos = put(out, cap, pos, u->fragment.ptr, u->fragment.len);
    }
    return pos;
}

int swk_engine_sanitize_url(swk_engine *e, const char *url, size_t url_len,
                            char *out, size_t out_cap,
                            size_t *out_len, size_t *removed)
{
    size_t dummy_len, dummy_removed;
    if (!out_len) out_len = &dummy_len;
    if (!removed) removed = &dummy_removed;
    *out_len = 0;
    *removed = 0;

    swk_url u;
    if (!e || !url || url_len > SWK_MAX_URL || !swk_url_parse(url, url_len, &u))
        return SWK_E_PARSE;

    size_t n = sanitize(e, &u, url, url_len, NULL, 0, removed);
    if (*removed == 0) {
        *out_len = url_len;
        return SWK_OK;
    }
    if (!out || n + 1 > out_cap)
        return SWK_E_NOSPACE;

    sanitize(e, &u, url, url_len, out, out_cap, removed);
    out[n] = '\0';
    *out_len = n;
    atomic_fetch_add_explicit(&e->stats.params_removed, *removed, memory_order_relaxed);
    return SWK_OK;
}

/* ------------------------------------------------------------------ */
/* Decisions */

static bool scheme_is(const swk_slice *s, const char *lit)
{
    size_t n = strlen(lit);
    if (s->len != n)
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = s->ptr[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c + 32);
        if (c != lit[i])
            return false;
    }
    return true;
}

static void set_matched(swk_decision *d, const char *host, size_t off, size_t hlen)
{
    size_t n = hlen - off;
    memcpy(d->matched, host + off, n);
    d->matched[n] = '\0';
}

swk_decision swk_engine_evaluate(swk_engine *e, const char *url, size_t url_len,
                                 const char *first_party_host,
                                 swk_resource_type type,
                                 char *out, size_t out_cap)
{
    swk_decision d;
    memset(&d, 0, sizeof d);
    d.action = SWK_ALLOW;
    d.reason = SWK_REASON_NOT_NETWORK;
    if (!e)
        return d;

    atomic_fetch_add_explicit(&e->stats.evaluated, 1, memory_order_relaxed);

    swk_url u;
    if (!url || url_len > SWK_MAX_URL || !swk_url_parse(url, url_len, &u))
        return d;
    if (!scheme_is(&u.scheme, "http") && !scheme_is(&u.scheme, "https") &&
        !scheme_is(&u.scheme, "ws") && !scheme_is(&u.scheme, "wss"))
        return d;

    d.reason = SWK_REASON_NONE;

    char host[SWK_MAX_HOST + 1];
    size_t hlen = u.host.len;
    for (size_t i = 0; i < hlen; i++) {
        char c = u.host.ptr[i];
        host[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    host[hlen] = '\0';

    size_t off;
    if (!u.host_is_ip && swk_set_match_domain(e->allow, host, hlen, &off)) {
        d.reason = SWK_REASON_ALLOWLIST;
        set_matched(&d, host, off, hlen);
        return d;
    }

    if (!u.host_is_ip && swk_set_match_domain(e->trackers, host, hlen, &off)) {
        set_matched(&d, host, off, hlen);
        /* A top-level navigation is the user's choice; a same-site request is
         * the site talking to itself. Everything else is a third party. */
        if (type == SWK_RT_MAIN_FRAME) {
            d.reason = SWK_REASON_USER_NAVIGATION;
        } else if (first_party_host &&
                   swk_same_site(host, hlen, first_party_host, strlen(first_party_host))) {
            d.reason = SWK_REASON_FIRST_PARTY;
        } else {
            d.action = SWK_BLOCK;
            d.reason = SWK_REASON_TRACKER_DOMAIN;
            atomic_fetch_add_explicit(&e->stats.blocked, 1, memory_order_relaxed);
            return d;
        }
    }

    size_t removed = 0;
    size_t n = sanitize(e, &u, url, url_len, NULL, 0, &removed);
    if (removed) {
        d.removed_params = removed;
        if (!out || n + 1 > out_cap) {
            d.reason = SWK_REASON_OUTPUT_TOO_SMALL;
            return d;
        }
        sanitize(e, &u, url, url_len, out, out_cap, &removed);
        out[n] = '\0';
        d.out_len = n;
        d.action = SWK_REWRITE;
        d.reason = SWK_REASON_TRACKING_PARAMS;
        atomic_fetch_add_explicit(&e->stats.rewritten, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&e->stats.params_removed, removed, memory_order_relaxed);
    }
    return d;
}

swk_stats swk_engine_stats(const swk_engine *e)
{
    swk_stats s = { 0, 0, 0, 0 };
    if (!e)
        return s;
    s.evaluated = atomic_load_explicit(&e->stats.evaluated, memory_order_relaxed);
    s.blocked = atomic_load_explicit(&e->stats.blocked, memory_order_relaxed);
    s.rewritten = atomic_load_explicit(&e->stats.rewritten, memory_order_relaxed);
    s.params_removed = atomic_load_explicit(&e->stats.params_removed, memory_order_relaxed);
    return s;
}

const char *swk_action_name(swk_action a)
{
    switch (a) {
    case SWK_ALLOW:   return "allow";
    case SWK_BLOCK:   return "block";
    case SWK_REWRITE: return "rewrite";
    }
    return "unknown";
}

const char *swk_reason_name(swk_reason r)
{
    switch (r) {
    case SWK_REASON_NONE:             return "none";
    case SWK_REASON_NOT_NETWORK:      return "not-network";
    case SWK_REASON_ALLOWLIST:        return "allowlist";
    case SWK_REASON_TRACKER_DOMAIN:   return "tracker-domain";
    case SWK_REASON_FIRST_PARTY:      return "first-party";
    case SWK_REASON_USER_NAVIGATION:  return "user-navigation";
    case SWK_REASON_TRACKING_PARAMS:  return "tracking-params";
    case SWK_REASON_OUTPUT_TOO_SMALL: return "output-too-small";
    }
    return "unknown";
}
