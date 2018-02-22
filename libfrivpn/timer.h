/*
 * Copyright (C) 2017-2018 Benedikt Heinz <Zn000h AT gmail.com>
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this code.  If not, see <http://www.gnu.org/licenses/>.
 */

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
