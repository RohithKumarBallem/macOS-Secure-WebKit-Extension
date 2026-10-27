#include "swk_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Rule export. Every key that reaches this file was validated by the list
 * parser to [a-z0-9._-], so no JSON string escaping is needed beyond the
 * backslashes written deliberately for regular expressions.
 */

typedef struct {
    char  *data;
    size_t len, cap;
    bool   failed;
} buf;

static void buf_put(buf *b, const char *s, size_t n)
{
    if (b->failed)
        return;
    if (b->len + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + n + 1)
            cap *= 2;
        char *p = realloc(b->data, cap);
        if (!p) {
            b->failed = true;
            return;
        }
        b->data = p;
        b->cap = cap;
    }
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

static void buf_str(buf *b, const char *s) { buf_put(b, s, strlen(s)); }

static void buf_uint(buf *b, size_t v)
{
    char tmp[32];
    int n = snprintf(tmp, sizeof tmp, "%zu", v);
    buf_put(b, tmp, (size_t)n);
}

/* Domain as a WebKit url-filter regex fragment: dots escaped for JSON+regex. */
static void buf_regex_domain(buf *b, const char *d, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (d[i] == '.')
            buf_str(b, "\\\\.");
        else
            buf_put(b, d + i, 1);
    }
}

static void begin_item(buf *b, size_t *count)
{
    buf_str(b, (*count)++ ? ",\n" : "\n");
}

static char *finish(buf *b)
{
    if (b->failed) {
        free(b->data);
        return NULL;
    }
    return b->data;
}

/* Rule ids must be unique within a ruleset; priorities make allow beat block. */
static char *export_dnr_trackers(const swk_engine *e)
{
    buf b = { 0 };
    size_t items = 0, id = 1;
    buf_str(&b, "[");

    size_t n = swk_set_count(e->trackers);
    for (size_t i = 0; i < n; i++) {
        size_t len;
        const char *d = swk_set_at(e->trackers, i, &len);
        begin_item(&b, &items);
        buf_str(&b, "{\"id\":");
        buf_uint(&b, id++);
        buf_str(&b, ",\"priority\":1,\"action\":{\"type\":\"block\"},"
                    "\"condition\":{\"urlFilter\":\"||");
        buf_put(&b, d, len);
        buf_str(&b, "^\",\"domainType\":\"thirdParty\"}}");
    }

    n = swk_set_count(e->allow);
    for (size_t i = 0; i < n; i++) {
        size_t len;
        const char *d = swk_set_at(e->allow, i, &len);
        begin_item(&b, &items);
        buf_str(&b, "{\"id\":");
        buf_uint(&b, id++);
        buf_str(&b, ",\"priority\":2,\"action\":{\"type\":\"allow\"},"
                    "\"condition\":{\"urlFilter\":\"||");
        buf_put(&b, d, len);
        buf_str(&b, "^\"}}");
    }

    buf_str(&b, items ? "\n]\n" : "]\n");
    return finish(&b);
}

/* One rule per parameter and anchor ("?p=" / "&p="), main frame only. Anchoring
 * on the separator keeps the rule from matching a parameter name that merely
 * appears inside a path or another value, which would redirect to itself. */
static char *export_dnr_params(const swk_engine *e)
{
    buf b = { 0 };
    size_t items = 0, id = 1;
    buf_str(&b, "[");

    size_t n = swk_set_count(e->params);
    for (size_t i = 0; i < n; i++) {
        size_t len;
        const char *p = swk_set_at(e->params, i, &len);
        for (int anchor = 0; anchor < 2; anchor++) {
            begin_item(&b, &items);
            buf_str(&b, "{\"id\":");
            buf_uint(&b, id++);
            buf_str(&b, ",\"priority\":1,\"action\":{\"type\":\"redirect\",\"redirect\":"
                        "{\"transform\":{\"queryTransform\":{\"removeParams\":[\"");
            buf_put(&b, p, len);
            buf_str(&b, "\"]}}}},\"condition\":{\"urlFilter\":\"");
            buf_str(&b, anchor ? "&" : "?");
            buf_put(&b, p, len);
            buf_str(&b, "=\",\"resourceTypes\":[\"main_frame\"]}}");
        }
    }

    buf_str(&b, items ? "\n]\n" : "]\n");
    return finish(&b);
}

/* WKContentRuleList / Safari content blocker format. The regex mirrors what
 * content-blocker converters emit: scheme, optional subdomains, the domain,
 * then a port or path boundary. */
static char *export_webkit(const swk_engine *e)
{
    buf b = { 0 };
    size_t items = 0;
    buf_str(&b, "[");

    size_t n = swk_set_count(e->trackers);
    for (size_t i = 0; i < n; i++) {
        size_t len;
        const char *d = swk_set_at(e->trackers, i, &len);
        begin_item(&b, &items);
        buf_str(&b, "{\"trigger\":{\"url-filter\":\"^[^:]+://+([^:/]+\\\\.)?");
        buf_regex_domain(&b, d, len);
        buf_str(&b, "[:/]\",\"load-type\":[\"third-party\"]},\"action\":{\"type\":\"block\"}}");
    }

    n = swk_set_count(e->allow);
    for (size_t i = 0; i < n; i++) {
        size_t len;
        const char *d = swk_set_at(e->allow, i, &len);
        begin_item(&b, &items);
        buf_str(&b, "{\"trigger\":{\"url-filter\":\"^[^:]+://+([^:/]+\\\\.)?");
        buf_regex_domain(&b, d, len);
        buf_str(&b, "[:/]\"},\"action\":{\"type\":\"ignore-previous-rules\"}}");
    }

    buf_str(&b, items ? "\n]\n" : "]\n");
    return finish(&b);
}

static void put_string_array(buf *b, const swk_set *s)
{
    buf_str(b, "[");
    size_t n = swk_set_count(s);
    for (size_t i = 0; i < n; i++) {
        size_t len;
        const char *p = swk_set_at(s, i, &len);
        if (i)
            buf_str(b, ",");
        buf_str(b, "\"");
        buf_put(b, p, len);
        buf_str(b, "\"");
    }
    buf_str(b, "]");
}

static char *export_config(const swk_engine *e)
{
    buf b = { 0 };
    buf_str(&b, "{\n  \"version\": \"" SWK_CORE_VERSION "\",\n  \"trackerDomains\": ");
    buf_uint(&b, swk_set_count(e->trackers));
    buf_str(&b, ",\n  \"allowDomains\": ");
    buf_uint(&b, swk_set_count(e->allow));
    buf_str(&b, ",\n  \"params\": ");
    put_string_array(&b, e->params);
    buf_str(&b, ",\n  \"paramPrefixes\": ");
    put_string_array(&b, e->prefixes);
    buf_str(&b, "\n}\n");
    return finish(&b);
}

char *swk_engine_export(const swk_engine *e, swk_export_format fmt)
{
    if (!e)
        return NULL;
    switch (fmt) {
    case SWK_EXPORT_DNR_TRACKERS: return export_dnr_trackers(e);
    case SWK_EXPORT_DNR_PARAMS:   return export_dnr_params(e);
    case SWK_EXPORT_WEBKIT_RULES: return export_webkit(e);
    case SWK_EXPORT_CONFIG:       return export_config(e);
    }
    return NULL;
}
