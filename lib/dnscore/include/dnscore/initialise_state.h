/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
 * The YADIFA TM software product is provided under the BSD 3-clause license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *        * Redistributions of source code must retain the above copyright
 *          notice, this list of conditions and the following disclaimer.
 *        * Redistributions in binary form must reproduce the above copyright
 *          notice, this list of conditions and the following disclaimer in the
 *          documentation and/or other materials provided with the distribution.
 *        * Neither the name of EURid nor the names of its contributors may be
 *          used to endorse or promote products derived from this software
 *          without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnscore/mutex.h>

struct initialiser_state_s
{
    mutex_t           mtx;
    cond_t            cond;
    volatile uint32_t value; // don't want it optimised in a loop
};

typedef struct initialiser_state_s initialiser_state_t;

#define INITIALISE_STATE_INIT {MUTEX_INITIALIZER, COND_INITIALIZER, 0}

/*
 * usage:
 *
 * if(initialise_state_begin(...))
 * {
 *   ...
 *
 *   if(failed)
 *   {
 *     initialise_state_cancel(...);
 *     return error;
 *   }
 *
 *   initialise_state_end(...);
 * }
 *
 * ...
 */

bool initialise_state_begin(initialiser_state_t *initstate);
void initialise_state_ready(initialiser_state_t *initstate);
void initialise_state_cancel(initialiser_state_t *initstate); // to cancel a failed initialisation

/*
 * usage:
 *
 * if(initialise_state_unready(...))
 * {
 *   ...
 *
 *   initialise_state_end(...);
 * }
 *
 * ...
 *
 * NOTE: there is no cancellation available as this is not expected to fail
 */

bool initialise_state_unready(initialiser_state_t *initstate);
void initialise_state_end(initialiser_state_t *initstate);

/*
 * usage:
 *
 * if(initialise_state_initialised(...))
 * {
 *   initialise_state_clear(...);
 * }
 */

bool initialise_state_initialised(initialiser_state_t *initstate);
bool initialise_state_initialised_or_uninitialising(initialiser_state_t *initstate);

/** @} */
