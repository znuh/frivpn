#ifndef TIMER_H
#define TIMER_H
#include "linux-list.h"
#include <stdint.h>
#include "chains.h"

time64_t chains_gettime(chains_t *chains, int precision);

ctimer_t *ctimer_create(chains_t *chains, int thread_id, int (*work) (chains_t *chains, ctimer_t *ct, void *priv), void *priv, time64_t interval);
void ctimer_start(chains_t *chains, ctimer_t *ct);
void ctimer_stop(chains_t *chains, ctimer_t *ct);

#endif /* TIMER_H */
