#include "swk.h"

#include <stdlib.h>
#include <string.h>

/*
 * Open-addressing hash set over an arena of lowercase keys.
 *
 * The hash runs over the key *from the last byte to the first*. That makes
 * every label-aligned suffix of a hostname a prefix of the reversed key, so
 * swk_set_match_domain() hashes the host once and probes the table at each
 * label boundary - O(host length), independent of the list size.
 */

#define FNV_OFFSET 0xcbf29ce484222325ULL
#define FNV_PRIME  0x100000001b3ULL

typedef struct {
    uint64_t hash;
    uint32_t off;
    uint32_t len;
} swk_entry;

struct swk_set {
    char      *arena;
    size_t     arena_len, arena_cap;
    swk_entry *entries;
    size_t     count, entries_cap;
    uint32_t  *slots;     /* entry index + 1; 0 = empty */
    size_t     slot_cap;  /* power of two */
};

static inline unsigned char fold(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

static inline uint64_t mix(uint64_t h, unsigned char c)
{
    return (h ^ fold(c)) * FNV_PRIME;
}

static inline size_t slot_of(uint64_t h, size_t mask)
{
    return (size_t)((h ^ (h >> 32)) & mask);
}

static bool eq_ci(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (fold((unsigned char)a[i]) != fold((unsigned char)b[i]))
            return false;
    return true;
}

static bool probe(const swk_set *s, uint64_t h, const char *key, size_t len)
{
    size_t mask = s->slot_cap - 1;
    for (size_t i = slot_of(h, mask);; i = (i + 1) & mask) {
        uint32_t slot = s->slots[i];
        if (slot == 0)
            return false;
        const swk_entry *e = &s->entries[slot - 1];
        if (e->hash == h && e->len == len && eq_ci(s->arena + e->off, key, len))
            return true;
    }
}

static bool rehash(swk_set *s, size_t new_cap)
{
    uint32_t *slots = calloc(new_cap, sizeof *slots);
    if (!slots)
        return false;
    size_t mask = new_cap - 1;
    for (size_t n = 0; n < s->count; n++) {
        size_t i = slot_of(s->entries[n].hash, mask);
        while (slots[i])
            i = (i + 1) & mask;
        slots[i] = (uint32_t)(n + 1);
    }
    free(s->slots);
    s->slots = slots;
    s->slot_cap = new_cap;
    return true;
}

swk_set *swk_set_new(size_t expected)
{
    if (expected > ((size_t)1 << 24))
        expected = (size_t)1 << 24;
    size_t cap = 16;
    while (cap < expected * 2)
        cap <<= 1;

    swk_set *s = calloc(1, sizeof *s);
    if (!s)
        return NULL;
    s->slots = calloc(cap, sizeof *s->slots);
    if (!s->slots) {
        free(s);
        return NULL;
    }
    s->slot_cap = cap;
    return s;
}

void swk_set_free(swk_set *s)
{
    if (!s)
        return;
    free(s->arena);
    free(s->entries);
    free(s->slots);
    free(s);
}

int swk_set_add(swk_set *s, const char *key, size_t len)
{
    if (!s || !key || len == 0 || len > SWK_MAX_HOST)
        return -1;

    uint64_t h = FNV_OFFSET;
    for (size_t i = len; i-- > 0;)
        h = mix(h, (unsigned char)key[i]);
    if (probe(s, h, key, len))
        return 0;

    if ((s->count + 1) * 2 > s->slot_cap && !rehash(s, s->slot_cap * 2))
        return -1;

    if (s->count == s->entries_cap) {
        size_t cap = s->entries_cap ? s->entries_cap * 2 : 64;
        swk_entry *p = realloc(s->entries, cap * sizeof *p);
        if (!p)
            return -1;
        s->entries = p;
        s->entries_cap = cap;
    }
    if (s->arena_len + len > UINT32_MAX)
        return -1;
    if (s->arena_len + len > s->arena_cap) {
        size_t cap = s->arena_cap ? s->arena_cap * 2 : 4096;
        while (cap < s->arena_len + len)
            cap *= 2;
        char *p = realloc(s->arena, cap);
        if (!p)
            return -1;
        s->arena = p;
        s->arena_cap = cap;
    }

    char *dst = s->arena + s->arena_len;
    for (size_t i = 0; i < len; i++)
        dst[i] = (char)fold((unsigned char)key[i]);
    s->entries[s->count] = (swk_entry){ h, (uint32_t)s->arena_len, (uint32_t)len };
    s->arena_len += len;
    s->count++;

    size_t mask = s->slot_cap - 1;
    size_t i = slot_of(h, mask);
    while (s->slots[i])
        i = (i + 1) & mask;
    s->slots[i] = (uint32_t)s->count;
    return 1;
}

bool swk_set_contains(const swk_set *s, const char *key, size_t len)
{
    if (!s || !s->count || !key || len == 0 || len > SWK_MAX_HOST)
        return false;
    uint64_t h = FNV_OFFSET;
    for (size_t i = len; i-- > 0;)
        h = mix(h, (unsigned char)key[i]);
    return probe(s, h, key, len);
}

size_t swk_set_count(const swk_set *s)
{
    return s ? s->count : 0;
}

const char *swk_set_at(const swk_set *s, size_t index, size_t *len)
{
    if (!s || index >= s->count)
        return NULL;
    if (len)
        *len = s->entries[index].len;
    return s->arena + s->entries[index].off;
}

bool swk_set_match_domain(const swk_set *s, const char *host, size_t len,
                          size_t *match_off)
{
    if (!s || !s->count || !host || len == 0 || len > SWK_MAX_HOST)
        return false;

    uint64_t h = FNV_OFFSET;
    bool seen_dot = false;

    /* Walk right to left. Before folding host[i], `h` covers host[i+1..len),
     * which is label-aligned exactly when host[i] is a dot. A candidate needs
     * at least one dot so a bare TLD never matches. */
    for (size_t i = len; i-- > 0;) {
        unsigned char c = (unsigned char)host[i];
        if (c == '.' && seen_dot && probe(s, h, host + i + 1, len - i - 1)) {
            if (match_off)
                *match_off = i + 1;
            return true;
        }
        if (c == '.')
            seen_dot = true;
        h = mix(h, c);
    }
    if (seen_dot && probe(s, h, host, len)) {
        if (match_off)
            *match_off = 0;
        return true;
    }
    return false;
}
