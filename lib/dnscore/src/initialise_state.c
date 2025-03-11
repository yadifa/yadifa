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

#include "dnscore/mutex.h"

#define INITIALISE_STATE_UNINITIALISED  0
#define INITIALISE_STATE_INITIALISING   1
#define INITIALISE_STATE_INITIALISED    2
#define INITIALISE_STATE_UNINITIALISING 3

bool initialise_state_begin(initialiser_state_t *initstate)
{
    mutex_lock(&initstate->mtx);
    bool     again;
    uint32_t ret;
    do
    {
        ret = initstate->value;
        again = false;

        switch(initstate->value)
        {
            case INITIALISE_STATE_UNINITIALISED: // not initialised
            {
                initstate->value = INITIALISE_STATE_INITIALISING;
                cond_notify(&initstate->cond);
                break;
            }
            case INITIALISE_STATE_INITIALISING: // initializing
            {
                while(initstate->value == INITIALISE_STATE_INITIALISING)
                {
                    cond_wait(&initstate->cond, &initstate->mtx);
                }
                break;
            }
            case INITIALISE_STATE_INITIALISED: //  already initialised
            {
                break;
            }
            case INITIALISE_STATE_UNINITIALISING:
            {
                while(initstate->value == INITIALISE_STATE_UNINITIALISING)
                {
                    cond_wait(&initstate->cond, &initstate->mtx);
                }
                // should be uninitialised now
                again = true;
                break;
            }
            default: // bogus
            {
                break;
            }
        }
    } while(again);

    cond_notify(&initstate->cond);
    mutex_unlock(&initstate->mtx);

    return ret == INITIALISE_STATE_UNINITIALISED;
}

/**
 * Can only be called in the block where initialise_state_begin returned true
 */

void initialise_state_ready(initialiser_state_t *initstate)
{
    mutex_lock(&initstate->mtx);
    if(initstate->value == INITIALISE_STATE_INITIALISING)
    {
        initstate->value = INITIALISE_STATE_INITIALISED;
        cond_notify(&initstate->cond);
    }
    else
    {
        abort(); // bogus use of this tool
    }
    mutex_unlock(&initstate->mtx);
}

/**
 * Can only be called in the block where initialise_state_begin returned true
 */

void initialise_state_cancel(initialiser_state_t *initstate)
{
    mutex_lock(&initstate->mtx);
    if(initstate->value == INITIALISE_STATE_INITIALISING)
    {
        initstate->value = INITIALISE_STATE_UNINITIALISED;
        cond_notify(&initstate->cond);
    }
    else
    {
        abort(); // bogus use of this tool
    }
    mutex_unlock(&initstate->mtx);
}

bool initialise_state_unready(initialiser_state_t *initstate)
{
    ya_result ret;
    bool      again;

    mutex_lock(&initstate->mtx);

    do
    {
        ret = initstate->value;
        again = false;

        switch(initstate->value)
        {
            case INITIALISE_STATE_UNINITIALISED:
            {
                // nothing to do
                break;
            }
            case INITIALISE_STATE_INITIALISING:
            {
                // wait for it to be done or to fail
                while(initstate->value == INITIALISE_STATE_UNINITIALISING)
                {
                    cond_wait(&initstate->cond, &initstate->mtx);
                }
                again = true;
                break;
            }
            case INITIALISE_STATE_INITIALISED:
            {
                // can uninitialise
                initstate->value = INITIALISE_STATE_UNINITIALISING;
                cond_notify(&initstate->cond);
                break;
            }
            case INITIALISE_STATE_UNINITIALISING:
            {
                // wait for it to be done
                while(initstate->value == INITIALISE_STATE_UNINITIALISING)
                {
                    cond_wait(&initstate->cond, &initstate->mtx);
                }
                again = true;
                break;
            }
            default:
            {
                abort(); // broken
            }
        }
    } while(again);

    mutex_unlock(&initstate->mtx);
    return ret == INITIALISE_STATE_INITIALISED;
}

/**
 * Can only be called in the block where initialise_state_unready returned true
 */

void initialise_state_end(initialiser_state_t *initstate)
{
    mutex_lock(&initstate->mtx);
    if(initstate->value == INITIALISE_STATE_UNINITIALISING)
    {
        initstate->value = INITIALISE_STATE_UNINITIALISED;
        cond_notify(&initstate->cond);
    }
    else
    {
        abort(); // bogus use of this tool
    }
    mutex_unlock(&initstate->mtx);
}

bool initialise_state_initialised(initialiser_state_t *initstate)
{
    bool ret;
    mutex_lock(&initstate->mtx);
    ret = initstate->value == INITIALISE_STATE_INITIALISED;
    mutex_unlock(&initstate->mtx);
    return ret;
}

bool initialise_state_initialised_or_uninitialising(initialiser_state_t *initstate)
{
    bool ret;
    mutex_lock(&initstate->mtx);
    ret = (initstate->value == INITIALISE_STATE_INITIALISED) || (initstate->value == INITIALISE_STATE_UNINITIALISING);
    mutex_unlock(&initstate->mtx);
    return ret;
}

/** @} */
