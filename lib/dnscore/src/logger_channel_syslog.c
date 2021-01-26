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

/** @defgroup logger Logging functions
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#define LOGGER_CHANNEL_SYSLOG_MULTITHREADED 0
#define SYSLOG_IS_THREADSAFE 0

#if !LOGGER_CHANNEL_SYSLOG_MULTITHREADED
#undef SYSLOG_IS_THREADSAFE
#define SYSLOG_IS_THREADSAFE 1
#endif

#if !SYSLOG_IS_THREADSAFE
#include <dnscore/thread.h>
#endif

#include "dnscore/logger_channel_syslog.h"
#include "dnscore/sys_types.h"
#include "dnscore/format.h"

#define SYSLOG_MAX_LINE_SIZE 1024
#define SYSLOG_FORMATTING_ERROR_TEXT "internal syslog formatting error"
#define SYSLOG_FORMATTING_ERROR_TEXT_LENGTH 33

struct logger_syslog_data
{
    char* ident;
    int options;
    int facility;
};

typedef struct logger_syslog_data logger_syslog_data;

static ya_result
logger_channel_syslog_constmsg(logger_channel* chan, int level, char* text, u32 text_len, u32 date_offset)
{
    (void)chan;
    (void)text_len;
    if(level > LOG_DEBUG)
    {
        level = LOG_DEBUG;
    }
    syslog(level, "%s", &text[date_offset]); /* don't worry about not being a string literal */
    
    return SUCCESS;
}

static ya_result
logger_channel_syslog_msg(logger_channel* chan, int level, char* text, ...)
{
    (void)chan;

    char tmp[SYSLOG_MAX_LINE_SIZE];

    va_list args;
    va_start(args, text);

    ya_result return_code = vsnformat(tmp, sizeof(tmp), text, args);

    if(FAIL(return_code))
    {
        memcpy(tmp, SYSLOG_FORMATTING_ERROR_TEXT, SYSLOG_FORMATTING_ERROR_TEXT_LENGTH);
        return_code = SYSLOG_FORMATTING_ERROR_TEXT_LENGTH;
    }

    syslog(level, "%s", tmp);

    va_end(args);

    return return_code;
}

static ya_result
logger_channel_syslog_vmsg(logger_channel* chan, int level, char* text, va_list args)
{
    (void)chan;
    char tmp[SYSLOG_MAX_LINE_SIZE];

    ya_result return_code = vsnformat(tmp, sizeof(tmp), text, args);

    if(FAIL(return_code))
    {
        memcpy(tmp, SYSLOG_FORMATTING_ERROR_TEXT, SYSLOG_FORMATTING_ERROR_TEXT_LENGTH);
        return_code = SYSLOG_FORMATTING_ERROR_TEXT_LENGTH;
    }
    /*
     * NOTE: LOG_DEBUG is the last supported level
     */
    
    syslog(level & LOG_PRIMASK, "%s", tmp);

    return return_code;
}

static void
logger_channel_syslog_flush(logger_channel* chan)
{
    /* NOP */

    (void)chan;
}

static void
logger_channel_syslog_close(logger_channel* chan)
{
    logger_syslog_data *sd = (logger_syslog_data*)chan->data;

    free(sd->ident);
    free(sd);

    closelog();

    chan->data = NULL;
    chan->vtbl = NULL;
}

static ya_result
logger_channel_syslog_reopen(logger_channel* chan)
{
    logger_syslog_data *sd = (logger_syslog_data*)chan->data;
    closelog();

    openlog(sd->ident, sd->options, sd->facility);

    return SUCCESS;
}

static void
logger_channel_syslog_sync(logger_channel* chan)
{
    (void)chan;
}

static const logger_channel_vtbl syslog_vtbl = {
    logger_channel_syslog_constmsg,
    logger_channel_syslog_msg,
    logger_channel_syslog_vmsg,
    logger_channel_syslog_flush,
    logger_channel_syslog_close,
    logger_channel_syslog_reopen,
    logger_channel_syslog_sync,
    "syslog_channel"
};

void
logger_channel_syslog_open(const char* ident, int options, int facility, logger_channel* chan)
{
    if(chan == NULL)
    {
        osformatln(termerr, "tried to open syslog (%s) on uninitialised channel", ident);
        return;
    }
    
    logger_syslog_data *sd;
    MALLOC_OBJECT_OR_DIE(sd, logger_syslog_data, 0x4d5254534e414843); /* CHANSTRM */
    sd->ident = strdup(ident);
    sd->options = options;
    sd->facility = facility;

    chan->data = sd;

    chan->vtbl = &syslog_vtbl;
    
    openlog(sd->ident, options, facility);
}
/** @} */

/*----------------------------------------------------------------------------*/
