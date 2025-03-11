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
 * @defgroup streaming Streams
 * @ingroup dnscore
 * @brief
 *
 *  Implementation of routines for the resource_record struct
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "dnscore/dnscore.h"
#include "dnscore/logger.h"
#include "dnscore/dnsname.h"
#include "dnscore/output_stream.h"
#include "dnscore/base64.h"
#include "dnscore/base32.h"
#include "dnscore/base32hex.h"
#include "dnscore/base16.h"
#include "dnscore/zalloc.h"

#define MODULE_MSG_HANDLE g_system_logger

#define OSTREAM_TAG       0x4d41455254534f

static const char ESCAPE_CHARS[] = {'@', '$', '\\', ';', '.'};

ya_result         output_stream_write_nu32(output_stream_t *os, uint32_t value)
{
    uint8_t buffer[4];

    /*    ------------------------------------------------------------    */

    buffer[0] = value >> 24;
    buffer[1] = value >> 16;
    buffer[2] = value >> 8;
    buffer[3] = value;

    return output_stream_write(os, buffer, 4);
}

ya_result output_stream_write_nu16(output_stream_t *os, uint16_t value)
{
    uint8_t buffer[2];

    /*    ------------------------------------------------------------    */

    buffer[0] = value >> 8;
    buffer[1] = value;

    return output_stream_write(os, buffer, 2);
}

ya_result output_stream_decode_base64(output_stream_t *os, const char *string, uint32_t length)
{
    const char *string_start = string;
    char        buffer[64];
    uint8_t     buffer_bin[48];

    uint32_t    needle = 0;

    ya_result   return_code = OK;

    /*    ------------------------------------------------------------    */

    while(length-- > 0)
    {
        char c = *string++;

        if(isspace(c))
        {
            continue;
        }

        buffer[needle++] = c;
        if(needle == 64)
        {
            if(FAIL(return_code = base64_decode(buffer, needle, buffer_bin)))
            {
                return return_code;
            }

            if(FAIL(return_code = output_stream_write(os, buffer_bin, return_code)))
            {
                return return_code;
            }

            needle = 0;
        }
    }

    if(needle > 0)
    {
        if((needle & 3) != 0)
        {
            return PARSEB64_ERROR;
        }

        if(FAIL(return_code = base64_decode(buffer, needle, buffer_bin)))
        {
            return return_code;
        }

        if(FAIL(return_code = output_stream_write(os, buffer_bin, return_code)))
        {
            return return_code;
        }
    }

    /* return the number of bytes read, instead of the last write size
     * this way something can be done about the input.
     *
     * alternatively we could just return "success"
     */

    return (ya_result)(string - string_start);
}

ya_result output_stream_decode_base32(output_stream_t *os, const char *string, uint32_t length)
{
    const char *string_start = string;
    char        buffer[64];
    uint8_t     buffer_bin[40];

    uint32_t    needle = 0;

    ya_result   return_code = OK;

    /*    ------------------------------------------------------------    */

    while(length-- > 0)
    {
        char c = *string++;

        if(isspace(c))
        {
            continue;
        }

        buffer[needle++] = c;
        if(needle == sizeof(buffer))
        {
            if(FAIL(return_code = base32_decode(buffer, needle, buffer_bin)))
            {
                return return_code;
            }

            if(FAIL(return_code = output_stream_write(os, buffer_bin, return_code)))
            {
                return return_code;
            }

            needle = 0;
        }
    }

    if(needle > 0)
    {
        if((needle & 7) != 0)
        {
            return PARSEB32_ERROR;
        }

        if(FAIL(return_code = base32_decode(buffer, needle, buffer_bin)))
        {
            return return_code;
        }

        if(FAIL(return_code = output_stream_write(os, buffer_bin, return_code)))
        {
            return return_code;
        }
    }

    /* return the number of bytes read, instead of the last write size
     * this way something can be done about the input.
     *
     * alternatively we could just return "success"
     */

    return (ya_result)(string - string_start);
}

ya_result output_stream_decode_base32hex(output_stream_t *os, const char *string, uint32_t length)
{
    const char *string_start = string;
    char        buffer[64];
    uint8_t     buffer_bin[40];

    uint32_t    needle = 0;

    ya_result   return_code = OK;

    /*    ------------------------------------------------------------    */

    while(length-- > 0)
    {
        char c = *string++;

        if(isspace(c))
        {
            continue;
        }

        buffer[needle++] = c;

        if(needle == sizeof(buffer))
        {
            if(FAIL(return_code = base32hex_decode(buffer, needle, buffer_bin)))
            {
                return return_code;
            }

            if(FAIL(return_code = output_stream_write(os, buffer_bin, return_code)))
            {
                return return_code;
            }

            needle = 0;
        }
    }

    if(needle > 0)
    {
        if((needle & 7) != 0)
        {
            return PARSEB32H_ERROR;
        }

        if(FAIL(return_code = base32hex_decode(buffer, needle, buffer_bin)))
        {
            return return_code;
        }

        if(FAIL(return_code = output_stream_write(os, buffer_bin, return_code)))
        {
            return return_code;
        }
    }

    /* return the number of bytes read, instead of the last write size
     * this way something can be done about the input.
     *
     * alternatively we could just return "success"
     */

    return (ya_result)(string - string_start);
}

ya_result output_stream_decode_base16(output_stream_t *os, const char *string, uint32_t length)
{
    const char *string_start = string;
    uint32_t    needle = 0;
    ya_result   return_code = OK;
    char        buffer[64];
    uint8_t     buffer_bin[32];

    /*    ------------------------------------------------------------    */

    while(length-- > 0)
    {
        char c = *string++;

        if(isspace(c))
        {
            continue;
        }

        buffer[needle++] = c;
        if(needle == sizeof(buffer))
        {
            if(FAIL(return_code = base16_decode(buffer, needle, buffer_bin)))
            {
                return return_code;
            }
            if(FAIL(return_code = output_stream_write(os, buffer_bin, return_code)))
            {
                return return_code;
            }

            needle = 0;
        }
    }

    if(needle > 0)
    {
        if((needle & 1) != 0)
        {
            return PARSEB16_ERROR;
        }

        if(FAIL(return_code = base16_decode(buffer, needle, buffer_bin)))
        {
            return return_code;
        }

        if(FAIL(return_code = output_stream_write(os, buffer_bin, return_code)))
        {
            return return_code;
        }
    }

    /* return the number of bytes read, instead of the last write size
     * this way something can be done about the input.
     *
     * alternatively we could just return "success"
     */

    return (ya_result)(string - string_start);
}

ya_result output_stream_write_pu16(output_stream_t *os, uint16_t value)
{
    uint8_t v;

    if(value > 127)
    {
        v = (uint8_t)value;
        value >>= 7;
        v |= 0x80;

        /* I'll only check the error for the last byte */

        output_stream_write(os, &v, 1);
    }

    v = (uint8_t)value;

    return output_stream_write(os, &v, 1);
}

ya_result output_stream_write_pu32(output_stream_t *os, uint32_t value)
{
    uint8_t v;

    while(value > 127)
    {
        v = (uint8_t)value;
        value >>= 7;
        v |= 0x80;

        /* I'll only check the error for the last byte */

        output_stream_write(os, &v, 1);
    }

    v = (uint8_t)value;

    return output_stream_write(os, &v, 1);
}

ya_result output_stream_write_pu64(output_stream_t *os, uint64_t value)
{
    uint8_t v;

    while(value > 127)
    {
        v = (uint8_t)value;
        value >>= 7;
        v |= 0x80;

        /* I'll only check the error for the last byte */

        output_stream_write(os, &v, 1);
    }

    v = (uint8_t)value;

    return output_stream_write(os, &v, 1);
}

/**
 * Writes a C-string to a stream
 *
 * @param os    the stream
 * @param text  the text
 *
 * return an error code
 */

ya_result output_stream_write_text(output_stream_t *os, const char *text) { return output_stream_write(os, text, strlen(text)); }

ya_result output_stream_write_dnsname(output_stream_t *os, const uint8_t *name)
{
    uint32_t len = dnsname_len(name);
    return output_stream_write(os, name, len);
}

ya_result output_stream_write_dnsname_text(output_stream_t *os, const uint8_t *name)
{
    static char    dot[1] = {'.'};

    const uint8_t *base = name;

    uint8_t        label_len;
    label_len = *name;

    if(label_len > 0)
    {
        do
        {
            output_stream_write(os, ++name, label_len);
            output_stream_write(os, &dot, 1);
            name += label_len;
            label_len = *name;
        } while(label_len > 0);
    }
    else
    {
        output_stream_write(os, &dot, 1);
    }

    return (ya_result)(name - base + 1);
}

ya_result output_stream_write_dnslabel_text_escaped(output_stream_t *os, const uint8_t *label)
{
    static const char escape[1] = {'\\'};

    int               len = *label++;

    uint32_t          additional_len = 0;
    for(int_fast32_t i = 0; i < len; ++i)
    {
        switch(label[i])
        {
            case '@':
            case '$':
            case ';':
            case '\\':
            case '.':
                ++additional_len;
                output_stream_write(os, escape, 1);
                FALLTHROUGH // fall through
                    default : output_stream_write(os, &label[i], 1);
        }
    }

    return len + additional_len;
}

static bool output_stream_write_should_escape(const uint8_t *name, size_t name_len)
{
    for(size_t i = 0; i < name_len; ++i)
    {
        const char c = name[i];

        for(uint_fast32_t j = 0; j < sizeof(ESCAPE_CHARS); ++j)
        {
            if(c == ESCAPE_CHARS[j])
            {
                return true;
            }
        }
    }

    return false;
}

ya_result output_stream_write_dnsname_text_escaped(output_stream_t *os, const uint8_t *name)
{
    static const char dot[1] = {'.'};

    uint8_t           label_len;
    label_len = *name;

    if(label_len > 0)
    {
        const uint8_t *name_base = name++;
        do
        {
            if(!output_stream_write_should_escape(name, label_len))
            {
                output_stream_write(os, name, label_len);
            }
            else
            {
                // write escaped
                output_stream_write_dnslabel_text_escaped(os, name - 1);
            }

            output_stream_write(os, dot, 1);

            name += label_len;
            label_len = *name++;
        } while(label_len > 0);
        return name - name_base;
    }
    else
    {
        output_stream_write(os, dot, 1);
        return 1;
    }
}

ya_result output_stream_write_dnslabel_vector(output_stream_t *os, dnslabel_vector_reference_t labels, int32_t top)
{
    ya_result n = 0;
    int32_t   i;

    for(i = 0; i <= top; i++)
    {
        ya_result err;
        uint8_t   len = labels[i][0] + 1;

        if(FAIL(err = output_stream_write(os, labels[i], len)))
        {
            return err;
        }

        n += err;
    }

    output_stream_write_u8(os, 0);

    return n;
}

ya_result output_stream_write_dnslabel_stack(output_stream_t *os, dnslabel_stack_reference_t labels, int32_t top)
{
    ya_result n = 0;
    int32_t   i;

    for(i = top; i >= 0; i--)
    {
        ya_result err;
        uint8_t   len = labels[i][0] + 1;

        if(FAIL(err = output_stream_write(os, labels[i], len)))
        {
            return err;
        }

        n += err;
    }

    output_stream_write_u8(os, 0);

    return n;
}

output_stream_t *output_stream_new_instance()
{
    output_stream_t *os;
    ZALLOC_OBJECT_OR_DIE(os, output_stream_t, OSTREAM_TAG); /* OSTREAM */
    os->data = NULL;
    os->vtbl = NULL;
    return os;
}

static ya_result void_output_stream_write(output_stream_t *stream, const uint8_t *buffer, uint32_t len)
{
    (void)stream;
    (void)buffer;
    (void)len;
    log_err("tried to write a closed stream");
    return INVALID_STATE_ERROR;
}

static ya_result void_output_stream_flush(output_stream_t *stream)
{
    (void)stream;
    log_err("tried to flush a closed stream");
    return INVALID_STATE_ERROR;
}

static void void_output_stream_close(output_stream_t *stream)
{
    (void)stream;
    /*
     * WARNING
     */
    log_err("tried to close a closed stream");
}

static const output_stream_vtbl void_output_stream_vtbl = {
    void_output_stream_write,
    void_output_stream_flush,
    void_output_stream_close,
    "void_output_stream",
};

/**
 * This tools allows a safer misuse (and detection) of closed streams
 * It sets the stream to a sink that warns abouts its usage and for which every call that can fail fails.
 */

void output_stream_set_void(output_stream_t *stream)
{
    stream->data = NULL;
    stream->vtbl = &void_output_stream_vtbl;
}

static ya_result sink_output_stream_write(output_stream_t *stream, const uint8_t *buffer, uint32_t len)
{
    (void)stream;
    (void)buffer;
    return len;
}

static ya_result sink_output_stream_flush(output_stream_t *stream)
{
    (void)stream;
    return SUCCESS;
}

static void                     sink_output_stream_close(output_stream_t *stream) { (void)stream; }

static const output_stream_vtbl sink_output_stream_vtbl = {
    sink_output_stream_write,
    sink_output_stream_flush,
    sink_output_stream_close,
    "sink_output_stream",
};

/**
 * Used to temporarily initialise a stream with a sink that can be closed safely.
 * Typically used as pre-init so the stream can be closed even if the function
 * setup failed before reaching stream initialisation.
 *
 * @param os
 */

void output_stream_set_sink(output_stream_t *os)
{
    os->data = NULL;
    os->vtbl = &sink_output_stream_vtbl;
}

ya_result output_stream_write_fully(output_stream_t *stream, const void *buffer_start, uint32_t len_start)
{
    output_stream_write_method *writefunc = stream->vtbl->write;
    uint32_t                    len = len_start;
    uint8_t                    *buffer = (uint8_t *)buffer_start;
    ya_result                   ret;

    while(len > 0)
    {
        if(FAIL(ret = writefunc(stream, buffer, len)))
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
     * If we were asked to read nothing it's ok.
     * If we read nothing at all we were on EOF and its still ok
     */

    if(len > 0)
    {
        return UNABLE_TO_COMPLETE_FULL_WRITE;
    }

    return (ya_result)(buffer - (uint8_t *)buffer_start);
}

/** @} */
