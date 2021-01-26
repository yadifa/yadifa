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

/** @defgroup streaming Streams
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

#include <arpa/inet.h>  /* or netinet/in.h */

#include "dnscore/input_stream.h"
#include "dnscore/rfc.h"
#include "dnscore/logger.h"

#include "dnscore/dnscore.h"

#define MODULE_MSG_HANDLE g_system_logger

ya_result
input_stream_read_fully(input_stream *stream, void* buffer_start, u32 len_start)
{
    input_stream_read_method* readfunc = stream->vtbl->read;
    u32 len = len_start;
    u8* buffer = (u8*)buffer_start;
    ya_result ret;
    
    while(len > 0)
    {
        if(FAIL(ret = readfunc(stream, buffer, len)))
        {
            return ret;
        }

        if(ret == 0) /* eof */
        {
            break;
        }

        buffer += ret;
        len -= ret; // cppcheck: false positive
    }

    /* If we only read a partial it's wrong.
     * If we were aked to read nothing it's ok.
     * If we read nothing at all we were on EOF and its still ok
     */

    if(len > 0)
    {
        return UNABLE_TO_COMPLETE_FULL_READ;
    }

    return (ya_result)(buffer - (u8*)buffer_start);
}

ya_result
input_stream_skip_fully(input_stream *stream, u32 len_start)
{
    input_stream_skip_method* skipfunc = stream->vtbl->skip;
    u32 len = len_start;
    ya_result ret;

    while(len > 0)
    {
        if(FAIL(ret = skipfunc(stream, len)))
        {
            return ret;
        }

        if(ret == 0) /* eof */
        {
            break;
        }

        len -= ret; // cppcheck: false positive
    }

    /* If we only read a partial it's wrong.
     * If we were aked to read nothing it's ok.
     * If we read nothing at all we were on EOF and its still ok
     */

    if(len > 0)
    {
        return UNABLE_TO_COMPLETE_FULL_READ;
    }

    return len_start;
}

ya_result
input_stream_read_nu32(input_stream *stream, u32 *output)
{
    u32 data;
    ya_result err;

    if(ISOK(err = input_stream_read_fully(stream, &data, 4)))
    {
        *output = ntohl(data);
    }

    return err;
}

ya_result
input_stream_read_nu16(input_stream *stream, u16 *output)
{
    u16 data;
    ya_result err;

    if(ISOK(err = input_stream_read_fully(stream, &data, 2)))
    {
        *output = ntohs(data);
    }

    return err;
}

ya_result
input_stream_read_u32(input_stream *stream, u32 *output)
{
    u32 data;
    ya_result err;

    if(ISOK(err = input_stream_read_fully(stream, &data, 4)))
    {
        *output = data;
    }

    return err;
}

ya_result
input_stream_read_s32(input_stream *stream, s32 *output)
{
    u32 data;
    ya_result err;

    if(ISOK(err = input_stream_read_fully(stream, &data, 4)))
    {
        *output = data;
    }

    return err;
}

ya_result
input_stream_read_u16(input_stream *stream, u16 *output)
{
    u16 data;
    ya_result err;

    if(ISOK(err = input_stream_read_fully(stream, &data, 2)))
    {
        *output = data;
    }

    return err;
}

union t32
{
    u8 bytes[4];
    u32 value; 
};

ya_result
input_stream_read_pu32(input_stream* is, u32 *output)
{
    ya_result ret;
    u32 value = 0;
    union t32 buffer;
    buffer.value = 0;
    ya_result n = 0;
    u8 s = 0;
       
    for(;;)
    {
#if WORDS_BIGENDIAN
        if(FAIL(ret = input_stream_read(is, &buffer.bytes[3], 1)))
        {
            return ret;
        }
#else
        if(FAIL(ret = input_stream_read(is, &buffer.bytes[0], 1)))
        {
            return ret;
        }
#endif
        
        value |= (buffer.value & 127) << s;
        
        ++n;
        
        if(buffer.value < 128)
        {
            *output = value;
            return n;
        }
        
        s += 7;
    }
}

union t64
{
    u8 bytes[8];
    u64 value; 
};

ya_result
input_stream_read_pu64(input_stream* is, u64 *output)
{
    ya_result ret;
    u64 value = 0;
    union t64 buffer;
    buffer.value = 0;
    ya_result n = 0;
    u8 s = 0;
       
    for(;;)
    {
#if WORDS_BIGENDIAN
        if(FAIL(ret = input_stream_read(is, &buffer.bytes[7], 1)))
        {
            return ret;
        }
#else
        if(FAIL(ret = input_stream_read(is, &buffer.bytes[0], 1)))
        {
            return ret;
        }
#endif
        
        value |= (buffer.value & 127) << s;
        
        ++n;
        
        if(buffer.value < 128)
        {
            *output = value;
            return n;
        }
        
        s += 7;
    }
}

ya_result
input_stream_read_dnsname(input_stream *stream, u8 *output_buffer)
{
    u8 *output = output_buffer;
    const u8 * const limit = &output_buffer[MAX_DOMAIN_LENGTH - 1];  /* -1 because the limit is computed after the terminator */

    for(;;)
    {
        int n;

        if(FAIL(n = input_stream_read_fully(stream, output, 1)))
        {
            return (output == output_buffer) ? 0 /* eof*/ : n;
        }

        if((n = *output++) == 0)
        {
            break;
        }

        if(n > MAX_LABEL_LENGTH)
        {
            return LABEL_TOO_LONG;
        }

        u8* tmp = output;

        output += n;

        if(output >= limit)
        {
            return DOMAIN_TOO_LONG;
        }

        if(FAIL(n = input_stream_read_fully(stream, tmp, n)))
        {
            return n;
        }
        
        /* 0x012a = 01 '*' = wildcard */
        
        /*if(GET_U16_AT(tmp[-1]) != NU16(0x012a))*/
        {
            if(!dnslabel_locase_verify_charspace(&tmp[-1]))
            {
                return INVALID_CHARSET;
            }
        }
    }

    return (ya_result)(output - output_buffer);
}

ya_result
input_stream_read_rname(input_stream *stream, u8 *output_buffer)
{
    u8 *output = output_buffer;
    const u8 * const limit = &output_buffer[MAX_DOMAIN_LENGTH - 1];  /* -1 because the limit is computed after the terminator */

    for(;;)
    {
        int n;

        if(FAIL(n = input_stream_read_fully(stream, output, 1)))
        {
            return (output == output_buffer) ? 0 /* eof*/ : n;
        }

        if((n = *output++) == 0)
        {
            break;
        }

        if(n > MAX_LABEL_LENGTH)
        {
            return LABEL_TOO_LONG;
        }

        u8* tmp = output;

        output += n;

        if(output >= limit)
        {
            return DOMAIN_TOO_LONG;
        }

        if(FAIL(n = input_stream_read_fully(stream, tmp, n)))
        {
            return n;
        }
    }

    return (ya_result)(output - output_buffer);
}

ya_result
input_stream_read_line(input_stream *stream, char *output_, int max_len)
{
    const char * const limit = &output_[max_len];
    char *output = output_;
    
    /*
     * Cache the method
     */
    
    input_stream_read_method *read_method = stream->vtbl->read;
    
    while(output < limit)
    {
        ya_result n = read_method(stream, (u8*)output, 1);
        
        if(n <= 0)
        {
            if(n == 0)
            {
                n = ((ya_result)(output - output_));
            }
            
            return n;
        }
        
        if(*output++ == '\n')
        {
            return ((ya_result)(output - output_));
        }
    }
    
    return max_len;
}

static ya_result input_stream_void_read(input_stream *stream, void* in_buffer,u32 in_len)
{
    (void)stream;
    (void)in_buffer;
    (void)in_len;

    log_err("tried to read a closed stream");
    return INVALID_STATE_ERROR;
}

static ya_result input_stream_void_skip(input_stream *stream, u32 byte_count)
{
    (void)stream;
    (void)byte_count;

    log_err("tried to skip a closed stream");
    return INVALID_STATE_ERROR;
}

static void input_stream_void_close(input_stream *stream)
{
    (void)stream;

    log_err("tried to close a closed stream");
#if DEBUG
    logger_flush();
    abort();
#endif
}

static const input_stream_vtbl void_input_stream_vtbl ={
    input_stream_void_read,
    input_stream_void_skip,
    input_stream_void_close,
    "void_input_stream",
};

/**
 * This tools allows a safer misuse (and detection) of closed streams
 * It sets the stream to a sink that warns abouts its usage and for which every call that can fail fails.
 */

void input_stream_set_void(input_stream* is)
{
    yassert(is != NULL);
    is->data = NULL;
    is->vtbl = &void_input_stream_vtbl;
}

static ya_result input_stream_sink_read(input_stream *stream, void* in_buffer,u32 in_len)
{
    (void)stream;
    (void)in_buffer;
    (void)in_len;
    return -1;
}

static ya_result input_stream_sink_skip(input_stream *stream, u32 byte_count)
{
    (void)stream;
    return byte_count;
}

static void input_stream_sink_close(input_stream *stream)
{
    (void)stream;
}

static const input_stream_vtbl sink_input_stream_vtbl ={
    input_stream_sink_read,
    input_stream_sink_skip,
    input_stream_sink_close,
    "sink_input_stream",
};

/**
 * Used to temporarily initialise a stream with a sink that can be closed safely.
 * Typically used as pre-init so the stream can be closed even if the function
 * setup failed before reaching stream initialisation.
 * 
 * @param is
 */

void input_stream_set_sink(input_stream* is)
{
    yassert(is != NULL);
    is->data = NULL;
    is->vtbl = &sink_input_stream_vtbl;
}

/** @} */
