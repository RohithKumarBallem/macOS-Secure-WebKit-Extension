#include "swk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks, g_failures;

#define CHECK(cond)                                                              \
    do {                                                                         \
        g_checks++;                                                              \
        if (!(cond)) {                                                           \
            g_failures++;                                                        \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
        }                                                                        \
    } while (0)

#define CHECK_STR(actual, expected)                                              \
    do {                                                                         \
        g_checks++;                                                              \
        if (strcmp((actual), (expected)) != 0) {                                 \
            g_failures++;                                                        \
            fprintf(stderr, "  FAIL %s:%d:\n    got:      %s\n    expected: %s\n", \
                    __FILE__, __LINE__, (actual), (expected));                   \
        }                                                                        \
    } while (0)

#define RUN(fn)                                                                  \
    do {                                                                         \
        int before = g_failures;                                                 \
        fn();                                                                    \
        printf("%s %s\n", g_failures == before ? "ok  " : "FAIL", #fn);          \
    } while (0)

static bool has_suffix(const swk_set *s, const char *host)
{
    return swk_set_match_domain(s, host, strlen(host), NULL);
}

/* ---- set ---- */

static void test_set_basic(void)
{
    swk_set *s = swk_set_new(0);
    CHECK(swk_set_add(s, "Example.COM", 11) == 1);
    CHECK(swk_set_add(s, "example.com", 11) == 0);  /* case-insensitive duplicate */
    CHECK(swk_set_add(s, "", 0) == -1);
    CHECK(swk_set_count(s) == 1);
    CHECK(swk_set_contains(s, "EXAMPLE.com", 11));
    CHECK(!swk_set_contains(s, "example.org", 11));

    size_t len;
    const char *k = swk_set_at(s, 0, &len);
    CHECK(len == 11 && memcmp(k, "example.com", 11) == 0);  /* stored lowercase */
    CHECK(swk_set_at(s, 1, &len) == NULL);
    swk_set_free(s);
}

static void test_set_growth_and_order(void)
{
    swk_set *s = swk_set_new(1);
    char key[64];
    for (int i = 0; i < 20000; i++) {
        int n = snprintf(key, sizeof key, "host%d.example.net", i);
        CHECK(swk_set_add(s, key, (size_t)n) == 1);
    }
    CHECK(swk_set_count(s) == 20000);
    for (int i = 0; i < 20000; i += 997) {
        int n = snprintf(key, sizeof key, "host%d.example.net", i);
        CHECK(swk_set_contains(s, key, (size_t)n));
        size_t len;
        const char *k = swk_set_at(s, (size_t)i, &len);
        CHECK(len == (size_t)n && memcmp(k, key, len) == 0);
    }
    CHECK(!swk_set_contains(s, "host20000.example.net", 21));
    swk_set_free(s);
}

static void test_set_domain_suffix(void)
{
    swk_set *s = swk_set_new(0);
    swk_set_add(s, "tracker.com", 11);
    swk_set_add(s, "ads.example.org", 15);

    CHECK(has_suffix(s, "tracker.com"));
    CHECK(has_suffix(s, "a.b.c.tracker.com"));
    CHECK(has_suffix(s, "WWW.Tracker.COM"));
    CHECK(has_suffix(s, "ads.example.org"));
    CHECK(has_suffix(s, "x.ads.example.org"));

    CHECK(!has_suffix(s, "example.org"));            /* parent of an entry is not blocked */
    CHECK(!has_suffix(s, "nottracker.com"));         /* label boundary respected */
    CHECK(!has_suffix(s, "tracker.com.evil.io"));    /* only the suffix counts */
    CHECK(!has_suffix(s, "com"));
    CHECK(!has_suffix(s, ""));

    size_t off = 99;
    CHECK(swk_set_match_domain(s, "cdn.eu.tracker.com", 18, &off) && off == 7);
    swk_set_free(s);
}

/* ---- URL ---- */

static swk_url parse_ok(const char *s)
{
    swk_url u;
    CHECK(swk_url_parse(s, strlen(s), &u));
    return u;
}

static void test_url_parse(void)
{
    swk_url u = parse_ok("https://user:pw@Sub.Example.com:8443/a/b?x=1&y=2#frag");
    CHECK(u.scheme.len == 5 && memcmp(u.scheme.ptr, "https", 5) == 0);
    CHECK(u.host.len == 15 && memcmp(u.host.ptr, "Sub.Example.com", 15) == 0);
    CHECK(u.port == 8443);
    CHECK(u.path.len == 4 && memcmp(u.path.ptr, "/a/b", 4) == 0);
    CHECK(u.has_query && u.query.len == 7 && memcmp(u.query.ptr, "x=1&y=2", 7) == 0);
    CHECK(u.has_fragment && u.fragment.len == 4);
    CHECK(!u.host_is_ip);

    u = parse_ok("http://example.com");
    CHECK(u.path.len == 0 && !u.has_query && !u.has_fragment);

    u = parse_ok("http://example.com?x=1");
    CHECK(u.has_query && u.path.len == 0);

    u = parse_ok("https://example.com./x");
    CHECK(u.host.len == 11);  /* trailing dot dropped */

    u = parse_ok("http://[::1]:8080/x");
    CHECK(u.host_is_ip && u.port == 8080 && u.host.len == 5);

    u = parse_ok("http://192.168.0.1/x");
    CHECK(u.host_is_ip);

    u = parse_ok("https://evil.com@good.com/");
    CHECK(u.host.len == 8 && memcmp(u.host.ptr, "good.com", 8) == 0);  /* userinfo is not the host */
}

static void test_url_rejects(void)
{
    swk_url u;
    const char *bad[] = {
        "", "about:blank", "javascript:alert(1)", "data:text/html,hi", "example.com/x",
        "http://", "http:///path", "https://exa mple.com/", "https://example.com/\r\nX: y",
        "http://example.com:99999/", "http://example.com:ab/", "http://[::1/", "1http://x.com/",
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
        CHECK(!swk_url_parse(bad[i], strlen(bad[i]), &u));
}

static void test_same_site(void)
{
    CHECK(swk_same_site("www.example.com", 15, "cdn.example.com", 15));
    CHECK(swk_same_site("EXAMPLE.com", 11, "a.b.example.COM", 15));
    CHECK(!swk_same_site("example.com", 11, "example.org", 11));
    CHECK(!swk_same_site("a.co.uk", 7, "b.co.uk", 7));                /* co.uk is a suffix */
    CHECK(swk_same_site("x.a.co.uk", 9, "y.a.co.uk", 9));
    CHECK(swk_same_site("10.0.0.1", 8, "10.0.0.1", 8));
    CHECK(!swk_same_site("10.0.0.1", 8, "10.0.0.2", 8));
    CHECK(swk_same_site("localhost", 9, "localhost", 9));
    CHECK(!swk_same_site("", 0, "example.com", 11));
}

/* ---- list parsing ---- */

static swk_engine *engine_with(const char *trackers, const char *params)
{
    swk_engine *e = swk_engine_new();
    if (trackers) swk_engine_load_trackers(e, trackers, strlen(trackers));
    if (params) swk_engine_load_params(e, params, strlen(params));
    return e;
}

static void test_tracker_list_formats(void)
{
    const char *list =
        "# comment\n"
        "! adblock comment\n"
        "[Adblock Plus 2.0]\n"
        "\n"
        "plain.com\n"
        "0.0.0.0 hosts-style.net\n"
        "127.0.0.1\tTabbed.Org   # trailing note\r\n"
        "||abp-style.io^\n"
        "||abp-options.io^$third-party,script\n"
        "*.wildcard.com\n"
        ".dotted.com.\n"
        "plain.com\n"            /* duplicate */
        "0.0.0.0 0.0.0.0\n"      /* hosts placeholder */
        "localhost\n"            /* single label */
        "bad_chars!.com\n"
        "-leading.com\n"
        "double..dot.com\n"
        "@@||allowed.com^\n"
        "::1 ip6-localhost\n";

    swk_engine *e = swk_engine_new();
    swk_load_report r = swk_engine_load_trackers(e, list, strlen(list));
    CHECK(swk_engine_tracker_count(e) == 7);
    CHECK(swk_engine_allow_count(e) == 1);
    CHECK(r.accepted == 8);
    CHECK(r.duplicates == 1);
    CHECK(r.rejected == 6);

    char out[256];
    const char *urls[] = {
        "https://plain.com/x", "https://hosts-style.net/x", "https://tabbed.org/x",
        "https://abp-style.io/x", "https://abp-options.io/x", "https://a.wildcard.com/x",
        "https://dotted.com/x",
    };
    for (size_t i = 0; i < sizeof urls / sizeof *urls; i++) {
        swk_decision d = swk_engine_evaluate(e, urls[i], strlen(urls[i]), "site.example",
                                             SWK_RT_SCRIPT, out, sizeof out);
        CHECK(d.action == SWK_BLOCK);
    }
    swk_engine_free(e);
}

/* ---- decisions ---- */

static void test_evaluate_decisions(void)
{
    swk_engine *e = engine_with(
        "tracker.com\nfacebook.com\nanalytics.example.net\n@@||tracker.com^\n", NULL);
    /* tracker.com is both listed and allowlisted: allowlist must win. */
    swk_engine_load_trackers(e, "metrics.io\n", 11);

    char out[512];
    #define EVAL(url, fp, type) swk_engine_evaluate(e, url, strlen(url), fp, type, out, sizeof out)

    swk_decision d = EVAL("https://cdn.metrics.io/a.js", "news.example", SWK_RT_SCRIPT);
    CHECK(d.action == SWK_BLOCK && d.reason == SWK_REASON_TRACKER_DOMAIN);
    CHECK_STR(d.matched, "metrics.io");

    d = EVAL("https://sub.tracker.com/a.js", "news.example", SWK_RT_SCRIPT);
    CHECK(d.action == SWK_ALLOW && d.reason == SWK_REASON_ALLOWLIST);

    d = EVAL("https://metrics.io/a.js", "www.metrics.io", SWK_RT_SCRIPT);
    CHECK(d.action == SWK_ALLOW && d.reason == SWK_REASON_FIRST_PARTY);

    d = EVAL("https://metrics.io/", NULL, SWK_RT_MAIN_FRAME);
    CHECK(d.action == SWK_ALLOW && d.reason == SWK_REASON_USER_NAVIGATION);

    d = EVAL("https://metrics.io/", NULL, SWK_RT_SUB_FRAME);  /* unknown page => third party */
    CHECK(d.action == SWK_BLOCK);

    d = EVAL("https://notmetrics.io/a.js", "news.example", SWK_RT_SCRIPT);
    CHECK(d.action == SWK_ALLOW && d.reason == SWK_REASON_NONE);

    d = EVAL("wss://ws.metrics.io/socket", "news.example", SWK_RT_OTHER);
    CHECK(d.action == SWK_BLOCK);

    d = EVAL("data:text/plain,hello", "news.example", SWK_RT_OTHER);
    CHECK(d.action == SWK_ALLOW && d.reason == SWK_REASON_NOT_NETWORK);

    d = EVAL("ftp://metrics.io/x", "news.example", SWK_RT_OTHER);
    CHECK(d.reason == SWK_REASON_NOT_NETWORK);

    d = EVAL("http://127.0.0.1/metrics.io", "news.example", SWK_RT_SCRIPT);
    CHECK(d.action == SWK_ALLOW);

    swk_stats st = swk_engine_stats(e);
    CHECK(st.evaluated == 10);
    CHECK(st.blocked == 3);
    swk_engine_free(e);
}

static void test_evaluate_edge_inputs(void)
{
    swk_engine *e = engine_with("metrics.io\n", "fbclid\n");
    char out[64];

    swk_decision d = swk_engine_evaluate(e, NULL, 0, NULL, SWK_RT_OTHER, out, sizeof out);
    CHECK(d.action == SWK_ALLOW);
    d = swk_engine_evaluate(NULL, "https://metrics.io/", 19, NULL, SWK_RT_OTHER, out, sizeof out);
    CHECK(d.action == SWK_ALLOW);

    char *huge = malloc(SWK_MAX_URL + 100);
    memset(huge, 'a', SWK_MAX_URL + 99);
    memcpy(huge, "https://metrics.io/", 19);
    huge[SWK_MAX_URL + 99] = '\0';
    d = swk_engine_evaluate(e, huge, strlen(huge), NULL, SWK_RT_SCRIPT, out, sizeof out);
    CHECK(d.action == SWK_ALLOW);  /* over the cap: not evaluated */
    free(huge);

    /* Rewrite needed but output buffer too small must not overflow it. */
    d = swk_engine_evaluate(e, "https://a.example/p?fbclid=1&k=v", 32, NULL, SWK_RT_SCRIPT, out, 8);
    CHECK(d.action == SWK_ALLOW && d.reason == SWK_REASON_OUTPUT_TOO_SMALL);
    d = swk_engine_evaluate(e, "https://a.example/p?fbclid=1&k=v", 32, NULL, SWK_RT_SCRIPT, NULL, 0);
    CHECK(d.reason == SWK_REASON_OUTPUT_TOO_SMALL);
    swk_engine_free(e);
}

/* ---- sanitising ---- */

static void sanitize_case(swk_engine *e, const char *in, const char *expected, size_t removed)
{
    char out[1024];
    size_t out_len = 0, got_removed = 99;
    int rc = swk_engine_sanitize_url(e, in, strlen(in), out, sizeof out, &out_len, &got_removed);
    CHECK(rc == SWK_OK);
    CHECK(got_removed == removed);
    if (removed == 0) {
        CHECK(out_len == strlen(in));
    } else {
        CHECK_STR(out, expected);
        CHECK(out_len == strlen(expected));
    }
}

static void test_sanitize(void)
{
    swk_engine *e = engine_with(NULL,
        "fbclid\ngclid\nmc_eid\nutm_*\n_hsenc\n# comment\nbad param\n-\n*\nx*\n");
    CHECK(swk_engine_param_count(e) == 5);  /* fbclid gclid mc_eid _hsenc + utm_ ("x*" is too short) */

    sanitize_case(e, "https://a.com/p?utm_source=x&id=7&utm_medium=y", "https://a.com/p?id=7", 2);
    sanitize_case(e, "https://a.com/p?id=7&fbclid=abc", "https://a.com/p?id=7", 1);
    sanitize_case(e, "https://a.com/p?fbclid=abc&id=7&gclid=1&z=2", "https://a.com/p?id=7&z=2", 2);
    sanitize_case(e, "https://a.com/p?fbclid=abc", "https://a.com/p", 1);
    sanitize_case(e, "https://a.com/p?fbclid=abc#section", "https://a.com/p#section", 1);
    sanitize_case(e, "https://a.com/p?id=1&fbclid#frag", "https://a.com/p?id=1#frag", 1);
    sanitize_case(e, "https://a.com/p?UTM_Source=x&FBCLID=1&Id=3", "https://a.com/p?Id=3", 2);
    sanitize_case(e, "https://a.com?utm_source=x", "https://a.com", 1);
    sanitize_case(e, "https://a.com/p?a=1&&fbclid=1&&b=2", "https://a.com/p?a=1&b=2", 1);
    sanitize_case(e, "https://a.com/p?q=fbclid", NULL, 0);                 /* value, not name */
    sanitize_case(e, "https://a.com/p?xfbclid=1", NULL, 0);                /* substring is not a match */
    sanitize_case(e, "https://a.com/p/fbclid=1", NULL, 0);                 /* path is untouched */
    sanitize_case(e, "https://a.com/p?next=https://b.com/?fbclid=1", NULL, 0);  /* nested URL value */
    sanitize_case(e, "https://a.com/p", NULL, 0);
    sanitize_case(e, "https://a.com/p?", NULL, 0);
    sanitize_case(e, "https://a.com/p?id=1", NULL, 0);

    char out[64];
    size_t out_len, removed;
    CHECK(swk_engine_sanitize_url(e, "https://a.com/p?fbclid=1&id=2", 29, out, 8, &out_len, &removed) == SWK_E_NOSPACE);
    CHECK(swk_engine_sanitize_url(e, "https://a.com/p?fbclid=1&id=2", 29, out, sizeof out, &out_len, &removed) == SWK_OK);
    CHECK(swk_engine_sanitize_url(e, "not a url", 9, out, sizeof out, &out_len, &removed) == SWK_E_PARSE);

    /* The result must be exactly as long as promised, with the NUL right after. */
    char exact[32];
    const char *in = "https://a.com/p?fbclid=1&id=2";
    CHECK(swk_engine_sanitize_url(e, in, strlen(in), exact, strlen("https://a.com/p?id=2") + 1, &out_len, &removed) == SWK_OK);
    CHECK_STR(exact, "https://a.com/p?id=2");
    swk_engine_free(e);
}

static void test_evaluate_rewrite(void)
{
    swk_engine *e = engine_with("metrics.io\n", "utm_*\ngclid\n");
    char out[256];
    const char *url = "https://shop.example/item?id=3&utm_campaign=spring&gclid=Cj0K";
    swk_decision d = swk_engine_evaluate(e, url, strlen(url), "shop.example", SWK_RT_MAIN_FRAME, out, sizeof out);
    CHECK(d.action == SWK_REWRITE && d.reason == SWK_REASON_TRACKING_PARAMS);
    CHECK(d.removed_params == 2);
    CHECK_STR(out, "https://shop.example/item?id=3");
    CHECK(d.out_len == strlen(out));

    /* Allowlisted sites are left completely alone. */
    swk_engine_load_trackers(e, "@@shop.example\n", 15);
    d = swk_engine_evaluate(e, url, strlen(url), "shop.example", SWK_RT_MAIN_FRAME, out, sizeof out);
    CHECK(d.action == SWK_ALLOW && d.reason == SWK_REASON_ALLOWLIST);

    swk_stats st = swk_engine_stats(e);
    CHECK(st.rewritten == 1 && st.params_removed == 2);
    swk_engine_free(e);
}

/* ---- export ---- */

static void test_export(void)
{
    swk_engine *e = engine_with("tracker.com\nads.example.org\n@@||ok.tracker.com^\n", "fbclid\nutm_*\n");

    char *trackers = swk_engine_export(e, SWK_EXPORT_DNR_TRACKERS);
    CHECK(trackers != NULL);
    CHECK(strstr(trackers, "{\"id\":1,\"priority\":1,\"action\":{\"type\":\"block\"},"
                           "\"condition\":{\"urlFilter\":\"||tracker.com^\",\"domainType\":\"thirdParty\"}}"));
    CHECK(strstr(trackers, "\"urlFilter\":\"||ads.example.org^\""));
    CHECK(strstr(trackers, "{\"id\":3,\"priority\":2,\"action\":{\"type\":\"allow\"}"));
    CHECK(!strstr(trackers, "main_frame"));
    free(trackers);

    char *params = swk_engine_export(e, SWK_EXPORT_DNR_PARAMS);
    CHECK(strstr(params, "\"removeParams\":[\"fbclid\"]"));
    CHECK(strstr(params, "\"urlFilter\":\"?fbclid=\""));
    CHECK(strstr(params, "\"urlFilter\":\"&fbclid=\""));
    CHECK(!strstr(params, "utm_"));  /* DNR cannot express prefixes */
    free(params);

    char *webkit = swk_engine_export(e, SWK_EXPORT_WEBKIT_RULES);
    CHECK(strstr(webkit, "\"url-filter\":\"^[^:]+://+([^:/]+\\\\.)?tracker\\\\.com[:/]\""));
    CHECK(strstr(webkit, "\"load-type\":[\"third-party\"]"));
    CHECK(strstr(webkit, "\"type\":\"ignore-previous-rules\""));
    free(webkit);

    char *config = swk_engine_export(e, SWK_EXPORT_CONFIG);
    CHECK(strstr(config, "\"trackerDomains\": 2"));
    CHECK(strstr(config, "\"params\": [\"fbclid\"]"));
    CHECK(strstr(config, "\"paramPrefixes\": [\"utm_\"]"));
    free(config);

    swk_engine *empty = swk_engine_new();
    char *none = swk_engine_export(empty, SWK_EXPORT_DNR_TRACKERS);
    CHECK_STR(none, "[]\n");
    free(none);
    swk_engine_free(empty);
    swk_engine_free(e);
}

int main(void)
{
    RUN(test_set_basic);
    RUN(test_set_growth_and_order);
    RUN(test_set_domain_suffix);
    RUN(test_url_parse);
    RUN(test_url_rejects);
    RUN(test_same_site);
    RUN(test_tracker_list_formats);
    RUN(test_evaluate_decisions);
    RUN(test_evaluate_edge_inputs);
    RUN(test_sanitize);
    RUN(test_evaluate_rewrite);
    RUN(test_export);

    printf("\n%d checks, %d failed\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
