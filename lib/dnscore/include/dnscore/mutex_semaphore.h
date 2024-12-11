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

#include <dnscore/mutex_defines.h>

#define DNSCORE_SEMAPHORE_SUPPORT 0

#if DNSCORE_SEMAPHORE_SUPPORT
#include <semaphore.h>
#endif

#if DNSCORE_SEMAPHORE_SUPPORT

typedef sem_t     semaphore_t;

static inline int semaphone_init(semaphore_t *sem)
{
    int ret = sem_init(sem, 0, 0);
    return ret;
}

static inline int semaphone_init_process_shared(semaphore_t *sem)
{
    int ret = sem_init(sem, 1, 1);
    return ret;
}

static inline void semaphore_finalize(semaphore_t *sem) { sem_destroy(sem); }

static inline void semaphore_lock(semaphore_t *sem)
{
    for(;;)
    {
        if(sem_wait(sem) == 0)
        {
            return;
        }

        int err = errno;
        if(err != EINTR)
        {
            abort();
        }
    }
}

static inline bool semaphore_trylock(semaphore_t *sem)
{
    int ret = sem_trywait(sem); // fails if
    return ret == 0;
}

static inline void semaphore_unlock(semaphore_t *sem) { sem_post(sem); }

#endif // SEMAPHORE_SUPPORT

/** @} */
