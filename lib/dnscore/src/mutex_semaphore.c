/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
 * @defgroup threading mutexes, ...
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#define __MUTEX_SEMAPHORE_C__ 1

#if __linux__ || __APPLE__ || __FreeBSD__
#define MUTEX_SEMAPHORE_SUPPORTED 1
#endif

#if MUTEX_SEMAPHORE_SUPPORTED
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#endif

#include "dnscore/mutex_semaphore.h"

#if MUTEX_SEMAPHORE_SUPPORTED
struct mutex_semaphore_s
{
    sem_t *sem;
    char name[64-sizeof(void*)];
};

typedef struct mutex_semaphore_s mutex_semaphore_t;

/**
 * Initialises an inter-process mutex implemented with a semaphore.
 *
 * @param ms
 * @param semaphore_name the name of the semaphore
 * @return
 */

ya_result mutex_semaphore_init_ex(mutex_semaphore_t *ms, const char *semaphore_name)
{
    if(strlen(semaphore_name) > sizeof(ms->name))
    {
        return INVALID_STATE_ERROR;
    }

    for(int attempt = 2; attempt > 0; attempt--)
    {
        sem_t *sem = sem_open(semaphore_name, O_CREAT | O_EXCL, S_IRUSR, 1);
        if(sem != SEM_FAILED)
        {
            ms->sem = sem;
            return SUCCESS;
        }
        else
        {
            int err = errno;
            if(err == EEXIST)
            {
                if(sem_unlink(semaphore_name) >= 0)
                {
                    continue;
                }
                else
                {
                    err = errno;
                }
            }

            return MAKE_ERRNO_ERROR(err);
        }
    }

    return ERROR;
}

/**
 * Initialises an inter-process mutex implemented with a semaphore.
 *
 * @param ms
 * @return
 */

ya_result mutex_semaphore_init(mutex_semaphore_t *ms)
{
    char semaphore_name[64];
    snprintf(semaphore_name, sizeof(semaphore_name), "mutex_semaphore-%08x-%p", getpid(), ms);
    return mutex_semaphore_init_ex(ms, semaphore_name);
}

/**
 * Destroys the semaphore
 *
 * @param ms
 */

void mutex_semaphore_finalise(mutex_semaphore_t *ms)
{
    if(ms->sem != NULL)
    {
        sem_close(ms->sem);
        sem_unlink(ms->name);
        ms->sem = NULL;
    }
}

/**
 * Locks the semaphore
 *
 * @param ms
 */

void mutex_semaphore_lock(mutex_semaphore_t *ms)
{
    sem_wait(ms->sem);
}

/**
 * Unlocks the semaphore
 *
 * @param ms
 */
void mutex_semaphore_unlock(mutex_semaphore_t *ms)
{
    sem_post(ms->sem);
}
#else
struct mutex_semaphore_s
{
    sem_t *sem;
    char name[64-sizeof(void*)];
};

typedef struct mutex_semaphore_s mutex_semaphore_t;

ya_result mutex_semaphore_init_ex(mutex_semaphore_t *ms, const char *semaphore_name)
{
    return FEATURE_NOT_IMPLEMENTED_ERROR;
}

ya_result mutex_semaphore_init(mutex_semaphore_t *ms)
{
    return FEATURE_NOT_IMPLEMENTED_ERROR;
}

void mutex_semaphore_finalise(mutex_semaphore_t *ms)
{
    abort();
}

void mutex_semaphore_lock(mutex_semaphore_t *ms)
{
    abort();
}

void mutex_semaphore_unlock(mutex_semaphore_t *ms)
{
    abort();
}
#endif

/** @} */
