/*
 * swk-tool - build-time and diagnostic CLI around the filtering core.
 *
 *   swk-tool compile --trackers F --params F --out DIR
 *       Writes the rule files the Safari extension and WKWebView consume:
 *       trackers.json (DNR), params.json (DNR), webkit-rules.json, config.json
 *
 *   swk-tool eval --trackers F --params F [--first-party HOST] URL...
 *       Prints the engine's decision for each URL.
 *
 *   swk-tool bench --trackers F --params F --corpus F [--iterations N]
 *       Replays a labelled corpus and reports block rate, false positives and
 *       throughput. Corpus lines: "<tracker|params|clean> <first-party|-> <url>".
 */
#define _POSIX_C_SOURCE 200809L

#include "swk.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "swk-tool: cannot open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    char *data = malloc((size_t)size + 1);
    if (!data || fread(data, 1, (size_t)size, f) != (size_t)size) {
        fprintf(stderr, "swk-tool: cannot read %s\n", path);
        free(data);
        fclose(f);
        return NULL;
    }
    fclose(f);
    data[size] = '\0';
    *len = (size_t)size;
    return data;
}

static int write_file(const char *dir, const char *name, const char *data)
{
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "swk-tool: cannot write %s: %s\n", path, strerror(errno));
        return -1;
    }
    size_t n = strlen(data);
    int rc = fwrite(data, 1, n, f) == n ? 0 : -1;
    if (fclose(f) != 0)
        rc = -1;
    return rc;
}

typedef struct {
    const char *trackers;
    const char *params;
    const char *out;
    const char *corpus;
    const char *first_party;
    long        iterations;
} options;

static const char *opt_value(int argc, char **argv, int *i)
{
    if (*i + 1 >= argc) {
        fprintf(stderr, "swk-tool: %s needs a value\n", argv[*i]);
        exit(2);
    }
    return argv[++*i];
}

static swk_engine *load_engine(const options *o)
{
    swk_engine *e = swk_engine_new();
    if (!e) {
        fprintf(stderr, "swk-tool: out of memory\n");
        return NULL;
    }
    if (o->trackers) {
        size_t n;
        char *text = read_file(o->trackers, &n);
        if (!text) { swk_engine_free(e); return NULL; }
        swk_load_report r = swk_engine_load_trackers(e, text, n);
        fprintf(stderr, "trackers: %zu accepted, %zu duplicate, %zu rejected\n",
                r.accepted, r.duplicates, r.rejected);
        free(text);
    }
    if (o->params) {
        size_t n;
        char *text = read_file(o->params, &n);
        if (!text) { swk_engine_free(e); return NULL; }
        swk_load_report r = swk_engine_load_params(e, text, n);
        fprintf(stderr, "params:   %zu accepted, %zu duplicate, %zu rejected\n",
                r.accepted, r.duplicates, r.rejected);
        free(text);
    }
    return e;
}

static int cmd_compile(const options *o)
{
    if (!o->out || (!o->trackers && !o->params)) {
        fprintf(stderr, "usage: swk-tool compile --trackers F --params F --out DIR\n");
        return 2;
    }
    swk_engine *e = load_engine(o);
    if (!e)
        return 1;

    static const struct {
        swk_export_format fmt;
        const char *name;
    } outputs[] = {
        { SWK_EXPORT_DNR_TRACKERS, "trackers.json" },
        { SWK_EXPORT_DNR_PARAMS,   "params.json" },
        { SWK_EXPORT_WEBKIT_RULES, "webkit-rules.json" },
        { SWK_EXPORT_CONFIG,       "config.json" },
    };
    int rc = 0;
    for (size_t i = 0; i < sizeof outputs / sizeof *outputs && rc == 0; i++) {
        char *json = swk_engine_export(e, outputs[i].fmt);
        if (!json || write_file(o->out, outputs[i].name, json) != 0)
            rc = 1;
        else
            printf("wrote %s/%s (%zu bytes)\n", o->out, outputs[i].name, strlen(json));
        free(json);
    }
    swk_engine_free(e);
    return rc;
}

static int cmd_eval(const options *o, int argc, char **argv)
{
    swk_engine *e = load_engine(o);
    if (!e)
        return 1;
    if (argc == 0)
        fprintf(stderr, "swk-tool: no URLs given\n");

    for (int i = 0; i < argc; i++) {
        char out[SWK_MAX_URL + 1];
        swk_decision d = swk_engine_evaluate(e, argv[i], strlen(argv[i]), o->first_party,
                                             SWK_RT_SCRIPT, out, sizeof out);
        printf("%-8s %-16s %s", swk_action_name(d.action), swk_reason_name(d.reason), argv[i]);
        if (d.action == SWK_REWRITE)
            printf("\n         -> %s", out);
        else if (d.matched[0])
            printf("  [%s]", d.matched);
        putchar('\n');
    }
    swk_engine_free(e);
    return 0;
}

typedef enum { LABEL_TRACKER, LABEL_PARAMS, LABEL_CLEAN } label;

typedef struct {
    label  label;
    char  *first_party;  /* NULL when "-" */
    char  *url;
} sample;

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static int load_corpus(const char *path, sample **out, size_t *count)
{
    size_t n;
    char *text = read_file(path, &n);
    if (!text)
        return -1;

    size_t cap = 256, used = 0;
    sample *s = malloc(cap * sizeof *s);
    if (!s) { free(text); return -1; }

    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        while (*line == ' ' || *line == '\t') line++;
        if (*line == '#' || *line == '\0' || *line == '\r')
            continue;
        char *save = NULL;
        char *lab = strtok_r(line, " \t\r", &save);
        char *fp = strtok_r(NULL, " \t\r", &save);
        char *url = strtok_r(NULL, " \t\r", &save);
        if (!lab || !fp || !url) {
            fprintf(stderr, "swk-tool: malformed corpus line: %s\n", line);
            continue;
        }
        label l;
        if (!strcmp(lab, "tracker")) l = LABEL_TRACKER;
        else if (!strcmp(lab, "params")) l = LABEL_PARAMS;
        else if (!strcmp(lab, "clean")) l = LABEL_CLEAN;
        else {
            fprintf(stderr, "swk-tool: unknown label '%s'\n", lab);
            continue;
        }
        if (used == cap) {
            cap *= 2;
            sample *p = realloc(s, cap * sizeof *s);
            if (!p) { free(s); free(text); return -1; }
            s = p;
        }
        s[used].label = l;
        s[used].first_party = strcmp(fp, "-") ? strdup(fp) : NULL;
        s[used].url = strdup(url);
        used++;
    }
    free(text);
    *out = s;
    *count = used;
    return 0;
}

static int cmd_bench(const options *o)
{
    if (!o->corpus) {
        fprintf(stderr, "usage: swk-tool bench --trackers F --params F --corpus F [--iterations N]\n");
        return 2;
    }

    double t0 = now_ns();
    swk_engine *e = load_engine(o);
    double load_ms = (now_ns() - t0) / 1e6;
    if (!e)
        return 1;

    sample *corpus = NULL;
    size_t count = 0;
    if (load_corpus(o->corpus, &corpus, &count) != 0 || count == 0) {
        fprintf(stderr, "swk-tool: empty or unreadable corpus\n");
        swk_engine_free(e);
        return 1;
    }

    size_t total[3] = { 0 }, handled[3] = { 0 }, wrong_clean = 0;
    char out[SWK_MAX_URL + 1];
    for (size_t i = 0; i < count; i++) {
        const sample *s = &corpus[i];
        swk_decision d = swk_engine_evaluate(e, s->url, strlen(s->url), s->first_party,
                                             SWK_RT_SCRIPT, out, sizeof out);
        total[s->label]++;
        switch (s->label) {
        case LABEL_TRACKER: if (d.action == SWK_BLOCK) handled[s->label]++; break;
        case LABEL_PARAMS:  if (d.action == SWK_REWRITE) handled[s->label]++; break;
        case LABEL_CLEAN:   if (d.action != SWK_ALLOW) wrong_clean++; else handled[s->label]++; break;
        }
    }

    long iters = o->iterations > 0 ? o->iterations : 200000;
    volatile size_t sink = 0;
    double start = now_ns();
    for (long it = 0; it < iters; it++) {
        const sample *s = &corpus[(size_t)it % count];
        swk_decision d = swk_engine_evaluate(e, s->url, strlen(s->url), s->first_party,
                                             SWK_RT_SCRIPT, out, sizeof out);
        sink += (size_t)d.action;
    }
    double per_op = (now_ns() - start) / (double)iters;
    (void)sink;

    printf("engine:   %zu tracker domains, %zu allowlisted, %zu tracking params (loaded in %.2f ms)\n",
           swk_engine_tracker_count(e), swk_engine_allow_count(e), swk_engine_param_count(e), load_ms);
    printf("corpus:   %zu requests (%zu tracker, %zu params, %zu clean)\n",
           count, total[LABEL_TRACKER], total[LABEL_PARAMS], total[LABEL_CLEAN]);
    if (total[LABEL_TRACKER])
        printf("tracker requests blocked:       %zu/%zu = %.1f%%\n", handled[LABEL_TRACKER],
               total[LABEL_TRACKER], 100.0 * (double)handled[LABEL_TRACKER] / (double)total[LABEL_TRACKER]);
    if (total[LABEL_PARAMS])
        printf("tracking-param URLs rewritten:  %zu/%zu = %.1f%%\n", handled[LABEL_PARAMS],
               total[LABEL_PARAMS], 100.0 * (double)handled[LABEL_PARAMS] / (double)total[LABEL_PARAMS]);
    if (total[LABEL_CLEAN])
        printf("clean requests wrongly touched: %zu/%zu = %.1f%%\n", wrong_clean,
               total[LABEL_CLEAN], 100.0 * (double)wrong_clean / (double)total[LABEL_CLEAN]);
    printf("throughput: %.0f ns/request (%.2f M requests/s) over %ld evaluations\n",
           per_op, 1e3 / per_op, iters);

    for (size_t i = 0; i < count; i++) {
        free(corpus[i].first_party);
        free(corpus[i].url);
    }
    free(corpus);
    swk_engine_free(e);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: swk-tool <compile|eval|bench> [options]\n");
        return 2;
    }
    const char *cmd = argv[1];
    options o = { 0 };
    int rest_start = argc;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--trackers")) o.trackers = opt_value(argc, argv, &i);
        else if (!strcmp(argv[i], "--params")) o.params = opt_value(argc, argv, &i);
        else if (!strcmp(argv[i], "--out")) o.out = opt_value(argc, argv, &i);
        else if (!strcmp(argv[i], "--corpus")) o.corpus = opt_value(argc, argv, &i);
        else if (!strcmp(argv[i], "--first-party")) o.first_party = opt_value(argc, argv, &i);
        else if (!strcmp(argv[i], "--iterations")) o.iterations = strtol(opt_value(argc, argv, &i), NULL, 10);
        else { rest_start = i; break; }
    }

    if (!strcmp(cmd, "compile")) return cmd_compile(&o);
    if (!strcmp(cmd, "eval"))    return cmd_eval(&o, argc - rest_start, argv + rest_start);
    if (!strcmp(cmd, "bench"))   return cmd_bench(&o);
    fprintf(stderr, "swk-tool: unknown command '%s'\n", cmd);
    return 2;
}
