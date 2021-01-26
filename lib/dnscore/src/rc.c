/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
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
 *------------------------------------------------------------------------------
 *
 */

/** @defgroup threading mutexes, ...
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore-config.h"
#include <sys/types.h>
#include <unistd.h>
#include "dnscore/logger.h"

#include "dnscore/rc.h"

#define MODULE_MSG_HANDLE		g_system_logger

void
rc_init_vtbl(rc_vtbl *vtbl, rc_free_method *free_callback, mutex_t *mtx)
{
    vtbl->free_callback = free_callback;
    vtbl->mtx = mtx;
}

void
rc_finalize_vtbl(rc_vtbl *vtbl)
{
    vtbl->free_callback = NULL;
    vtbl->mtx = NULL;
}

void
rc_set_internal(rc_s *rc, rc_vtbl *vtbl)
{
    rc->vtbl = vtbl;
    rc->count = 0;
}

void
rc_aquire_internal(rc_s *rc)
{
    mutex_lock(rc->vtbl->mtx);
    ++rc->count;
    mutex_unlock(rc->vtbl->mtx);
}

void
rc_release_internal(rc_s *rc, void *data)
{
    mutex_lock(rc->vtbl->mtx);
    if(--rc->count > 0)
    {
        mutex_unlock(rc->vtbl->mtx);
    }
    else
    {
        if(rc->count < 0)
        {
            // oopsie
            log_err("negative RC count: %i rc=%p data=%p", rc->count, rc, data);
            logger_flush(); // then abort()
            abort();
        }
        
        mutex_unlock(rc->vtbl->mtx);
        rc->vtbl->free_callback(data);
    }
}
