#include "swk.h"

#include <string.h>

static bool is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
static bool is_digit(char c) { return c >= '0' && c <= '9'; }

static bool is_scheme_char(char c)
{
    return is_alpha(c) || is_digit(c) || c == '+' || c == '-' || c == '.';
}

/* Parses `s[0..n)` as a decimal port. Empty is allowed (host:). */
static bool parse_port(const char *s, size_t n, uint16_t *out)
{
    if (n > 5)
        return false;
    unsigned v = 0;
    for (size_t i = 0; i < n; i++) {
        if (!is_digit(s[i]))
            return false;
        v = v * 10 + (unsigned)(s[i] - '0');
    }
    if (v > 65535)
        return false;
    *out = (uint16_t)v;
    return true;
}

bool swk_host_is_ip(const char *host, size_t len)
{
    if (len == 0)
        return false;
    if (host[0] == '[')
        return true;
    size_t dots = 0;
    for (size_t i = 0; i < len; i++) {
        if (host[i] == '.')
            dots++;
        else if (!is_digit(host[i]))
            return false;
    }
    return dots == 3;
}

bool swk_url_parse(const char *s, size_t n, swk_url *u)
{
    memset(u, 0, sizeof *u);
    if (!s || n < 8 || !is_alpha(s[0]))
        return false;

    /* A URL with whitespace or control characters is never one a browser
     * would send as-is; refusing it also rules out header-splitting tricks. */
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] <= 0x20 || (unsigned char)s[i] == 0x7f)
            return false;

    size_t i = 0;
    while (i < n && is_scheme_char(s[i]))
        i++;
    if (i + 3 > n || s[i] != ':' || s[i + 1] != '/' || s[i + 2] != '/')
        return false;
    u->scheme = (swk_slice){ s, i };

    size_t auth = i + 3;
    size_t auth_end = auth;
    while (auth_end < n && s[auth_end] != '/' && s[auth_end] != '?' && s[auth_end] != '#')
        auth_end++;

    size_t host_start = auth;
    for (size_t k = auth_end; k > auth; k--) {
        if (s[k - 1] == '@') {
            host_start = k;
            break;
        }
    }

    size_t host_end;
    if (host_start < auth_end && s[host_start] == '[') {
        size_t close = host_start;
        while (close < auth_end && s[close] != ']')
            close++;
        if (close >= auth_end)
            return false;
        host_end = close + 1;
        u->host_is_ip = true;
        if (host_end < auth_end) {
            if (s[host_end] != ':' || !parse_port(s + host_end + 1, auth_end - host_end - 1, &u->port))
                return false;
        }
    } else {
        host_end = auth_end;
        for (size_t k = host_start; k < auth_end; k++) {
            if (s[k] == ':') {
                host_end = k;
                break;
            }
        }
        if (host_end < auth_end && !parse_port(s + host_end + 1, auth_end - host_end - 1, &u->port))
            return false;
    }

    /* "example.com." and "example.com" are the same host. */
    if (host_end > host_start + 1 && s[host_end - 1] == '.' && !u->host_is_ip)
        host_end--;
    size_t host_len = host_end - host_start;
    if (host_len == 0 || host_len > SWK_MAX_HOST)
        return false;
    u->host = (swk_slice){ s + host_start, host_len };
    if (!u->host_is_ip)
        u->host_is_ip = swk_host_is_ip(u->host.ptr, host_len);

    size_t p = auth_end;
    size_t path_end = p;
    while (path_end < n && s[path_end] != '?' && s[path_end] != '#')
        path_end++;
    u->path = (swk_slice){ s + p, path_end - p };

    size_t pos = path_end;
    if (pos < n && s[pos] == '?') {
        size_t q_end = pos + 1;
        while (q_end < n && s[q_end] != '#')
            q_end++;
        u->query = (swk_slice){ s + pos + 1, q_end - pos - 1 };
        u->has_query = true;
        pos = q_end;
    }
    if (pos < n && s[pos] == '#') {
        u->fragment = (swk_slice){ s + pos + 1, n - pos - 1 };
        u->has_fragment = true;
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Registrable domain. A real implementation needs the Public Suffix List; this
 * covers the multi-part suffixes that matter for first/third-party decisions on
 * common sites. Unknown suffixes fall back to "last two labels". */

static const char *const k_two_level_suffixes[] = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp",
    "co.kr", "or.kr", "ac.kr", "go.kr", "ne.kr",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "gov.in",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.mx", "org.mx", "gob.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.uy",
    "com.tr", "org.tr", "com.sg", "com.hk", "org.hk", "com.tw", "org.tw",
    "co.za", "org.za", "co.il", "org.il", "co.id", "co.th", "in.th",
    "com.my", "com.ph", "com.vn", "com.pk", "com.ng", "com.eg", "com.sa", "com.ua",
    "com.pl", "net.pl", "org.pl",
};

static bool is_two_level_suffix(const char *s, size_t n)
{
    for (size_t i = 0; i < sizeof k_two_level_suffixes / sizeof *k_two_level_suffixes; i++) {
        const char *suf = k_two_level_suffixes[i];
        if (strlen(suf) != n)
            continue;
        size_t k = 0;
        for (; k < n; k++) {
            char c = s[k];
            if (c >= 'A' && c <= 'Z')
                c = (char)(c + 32);
            if (c != suf[k])
                break;
        }
        if (k == n)
            return true;
    }
    return false;
}

size_t swk_registrable_offset(const char *host, size_t len)
{
    if (!host || len == 0 || swk_host_is_ip(host, len))
        return 0;

    size_t dots[3];
    size_t found = 0;
    for (size_t i = len; i-- > 0 && found < 3;)
        if (host[i] == '.')
            dots[found++] = i;

    if (found < 2)
        return 0;  /* "example.com", "localhost" */

    size_t last_two = dots[1] + 1;
    if (is_two_level_suffix(host + last_two, len - last_two))
        return found == 3 ? dots[2] + 1 : 0;
    return last_two;
}

bool swk_same_site(const char *a, size_t alen, const char *b, size_t blen)
{
    if (!a || !b || alen == 0 || blen == 0)
        return false;
    size_t ao = swk_registrable_offset(a, alen);
    size_t bo = swk_registrable_offset(b, blen);
    size_t an = alen - ao, bn = blen - bo;
    if (an != bn)
        return false;
    for (size_t i = 0; i < an; i++) {
        char x = a[ao + i], y = b[bo + i];
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y)
            return false;
    }
    return true;
}
