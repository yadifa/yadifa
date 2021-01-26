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
#include <dnscore/thread.h>

#include "dnscore/logger_channel_stream.h"
#include "dnscore/logger_handle.h"
#include "dnscore/output_stream.h"
#include "dnscore/format.h"

/*
 * The new logger model does not requires MT protection on the channels
 */

typedef struct stream_data stream_data;

struct stream_data
{
    output_stream os;
    bool force_flush;
};

static ya_result
logger_channel_stream_constmsg(logger_channel* chan, int level, char* text, u32 text_len, u32 date_offset)
{
    (void)level;
    (void)date_offset;

    stream_data* sd = (stream_data*)chan->data;

    output_stream_write(&sd->os, (const u8*)text, text_len);

    ya_result ret = output_stream_write(&sd->os, (const u8*)"\n", 1);

    if(sd->force_flush)
    {
        output_stream_flush(&sd->os);
    }

    return ret;
}

static ya_result
logger_channel_stream_vmsg(logger_channel* chan, int level, char* text, va_list args)
{
    (void)level;

    stream_data* sd = (stream_data*)chan->data;

    vosformat(&sd->os, text, args);

    ya_result ret = output_stream_write(&sd->os, (const u8*)"\n", 1);

    if(sd->force_flush)
    {
        output_stream_flush(&sd->os);
    }

    return ret;
}

static ya_result
logger_channel_stream_msg(logger_channel* chan, int level, char* text, ...)
{
    va_list args;
    va_start(args, text);

    ya_result ret = logger_channel_stream_vmsg(chan, level, text, args);

    va_end(args);

    return ret;
}

static void
logger_channel_stream_flush(logger_channel* chan)
{
    stream_data* sd = (stream_data*)chan->data;

    output_stream_flush(&sd->os);
}

static void
logger_channel_stream_close(logger_channel* chan)
{
    stream_data* sd = (stream_data*)chan->data;

    output_stream_flush(&sd->os);
    output_stream_close(&sd->os);

    chan->vtbl = NULL;
    sd->os.data = NULL;
    sd->os.vtbl = NULL;

    free(chan->data);
    chan->data = NULL;
}

static ya_result
logger_channel_stream_reopen(logger_channel* chan)
{
    stream_data* sd = (stream_data*)chan->data;
    
    // there is no way to reopen a steam, simply flush its current contents

    output_stream_flush(&sd->os);

    return SUCCESS;
}

static void
logger_channel_steam_sync(logger_channel* chan)
{
    (void)chan;
}

static const logger_channel_vtbl stream_vtbl =
{
    logger_channel_stream_constmsg,
    logger_channel_stream_msg,    
    logger_channel_stream_vmsg,
    logger_channel_stream_flush,
    logger_channel_stream_close,
    logger_channel_stream_reopen,
    logger_channel_steam_sync,
    "stream_channel"
};

/*
 * Takes ownership of the stream.
 * The stream will be unusable by the caller at the return of this function
 */

void
logger_channel_stream_open(output_stream* os, bool forceflush, logger_channel* chan)
{
    if(chan == NULL)
    {
        osformatln(termerr, "tried to open stream on uninitialised channel");
        return;
    }
    
    stream_data* sd;
    MALLOC_OBJECT_OR_DIE(sd, stream_data, 0x4d5254534e414843); /* CHANSTRM */

    sd->os.data = os->data;
    sd->os.vtbl = os->vtbl;
    sd->force_flush = forceflush;

    /* NOTE:	Do NOT use a black hole.
     *		Let the application crashes if it tries to use a stream it does not own anymore
     */
    os->data = NULL;
    os->vtbl = NULL;

    chan->data = sd;
    chan->vtbl = &stream_vtbl;
}

/** @} */
