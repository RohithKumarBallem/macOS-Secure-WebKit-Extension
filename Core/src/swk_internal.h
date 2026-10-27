#ifndef SWK_INTERNAL_H
#define SWK_INTERNAL_H

#include "swk.h"

#include <stdatomic.h>

struct swk_engine {
    swk_set *trackers;   /* domains to block */
    swk_set *allow;      /* domains exempt from everything */
    swk_set *params;     /* exact tracking parameter names */
    swk_set *prefixes;   /* tracking parameter name prefixes (utm_, ...) */

    struct {
        _Atomic uint64_t evaluated;
        _Atomic uint64_t blocked;
        _Atomic uint64_t rewritten;
        _Atomic uint64_t params_removed;
    } stats;
};

#endif
