/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2023, EURid vzw. All rights reserved.
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

#include "dnscore/error_state.h"
#include "dnscore/logger.h"

bool
error_state_log(error_state_t *es, ya_result err)
{
    bool log_message = FALSE;

    if(es->error != err)
    {
        s64 now = timeus();
        es->error = err;
        es->count = 1;
        es->first_epoch = now;
        es->last_epoch = now;

        log_message = TRUE;
    }
    else
    {
        ++es->count;

        s64 now = timeus();
        if(now - es->last_epoch >= ERROR_STATE_FAILURE_LOG_PERIOD)
        {
            log_message = TRUE;
            es->last_epoch = now;
        }
    }

    return log_message;
}

void
error_state_clear(error_state_t *es, logger_handle *log_handle, int level, const char *notice_message)
{
    if(es->error != 0)
    {
        s64 now = timeus();
        if(now - es->last_epoch >= ERROR_STATE_FAILURE_LOG_PERIOD)
        {
            if((log_handle != NULL) && (notice_message != NULL))
            {
                if(log_handle->active[level] != 0)
                {
                    logger_handle_msg_nocull(log_handle, level,
                                             "%s recovered from a stream of %lli issues having occurred between %llT and %llT",
                                             notice_message, es->count, es->first_epoch, es->last_epoch);
                }
            }

            es->first_epoch = 0;
            es->last_epoch = 0;
            es->error = 0;
            es->count = 0;
        }
    }
}

bool
error_state_log_locked(error_state_t *es, ya_result err)
{
    mutex_lock(&es->mtx);
    bool ret = error_state_log(es, err);
    mutex_unlock(&es->mtx);
    return ret;
}

void
error_state_clear_locked(error_state_t *es, logger_handle *log_handle, int level, const char *notice_message)
{
    mutex_lock(&es->mtx);
    error_state_clear(es, log_handle, level, notice_message);
    mutex_unlock(&es->mtx);
}
