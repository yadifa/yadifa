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

#include <dnscore/rfc.h>
#include <dnscore/dnsname.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnscore/format.h>
#include "input.h"

#define RECORD_SIZE_MAX (256 + 10 + 65535)

static ya_result input_stream_input_read(input_stream *stream,void *in_buffer,u32 count)
{
    input_stream_input_data_t *data = (input_stream_input_data_t*)stream->data;

    u8 *buffer = (u8*)in_buffer;

    // this is an abomination cpu-wise

    while(count > 0)
    {
        if(data->avail == 0)
        {
            data->feed(data);

            if(data->avail == 0)
            {
                break;
            }
        }

        *buffer++ = data->data[data->base & INPUT_STREAM_INPUT_BUFFER_MASK];
        ++data->base;
        --data->avail;
        --count;
    }

    return buffer - (u8*)in_buffer;
}

static ya_result input_stream_input_skip(input_stream *stream,u32 count)
{
    input_stream_input_data_t *data = (input_stream_input_data_t*)stream->data;

    s32 from = data->base;

    // this is an abomination cpu-wise

    while(count > 0)
    {
        if(data->avail == 0)
        {
            data->feed(data);

            if(data->avail == 0)
            {
                break;
            }
        }

        data->base++;
        --data->avail;
        --count;
    }

    return data->base - from;
}

static void input_stream_input_close(input_stream *stream)
{
    input_stream_input_data_t *data = (input_stream_input_data_t*)stream->data;
    free(data);
    input_stream_set_sink(stream);
}

static const input_stream_vtbl input_stream_input_vtbl =
{
    input_stream_input_read,
    input_stream_input_skip,
    input_stream_input_close,
    "input_stream_input_stream",
};

ya_result
input_stream_input_init(input_stream *is, input_t *input, input_stream_input_data_feed_method *feed_callback)
{
    input_stream_input_data_t *data;
    MALLOC_OBJECT_OR_DIE(data, input_stream_input_data_t, GENERIC_TAG);
    ZEROMEMORY(data, sizeof(input_stream_input_data_t));
    data->input = input;
    data->feed = feed_callback;
    is->data = data;
    is->vtbl = &input_stream_input_vtbl;
    return SUCCESS;
}

struct input_data_s
{
    const u8 *domain;
};

ya_result
input_stream_data_write(struct input_stream_input_data_s *input_data, const u8 *buffer, size_t buffer_size)
{
    // this is an abomination cpu-wise

    size_t room = sizeof(input_data->data) - input_data->avail;

    if(room < buffer_size)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    int buffer_size_org = buffer_size;

    while(buffer_size > 0)
    {
        input_data->data[(input_data->base + input_data->avail) & INPUT_STREAM_INPUT_BUFFER_MASK] = *buffer++;
        ++input_data->avail;
        --buffer_size;
    }

    return buffer_size_org;
}

static u32 g_record_input_data_feed_serial = 0;

void
record_input_data_feed_serial_set(u32 serial)
{
    g_record_input_data_feed_serial = serial;
}

ya_result
record_input_data_feed(struct input_stream_input_data_s *input_data, const u16 *script, size_t script_count, const u8 *fqdn, size_t *index)
{
    if(*index >= script_count)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    const u8 *domain = input_domain_get(input_data->input);
    bool is_subdomain = dnsname_is_subdomain(fqdn, domain);

    if(is_subdomain)
    {
    }
    else // APEX
    {
    }

    output_stream baos;
    bytearray_output_stream_init(&baos, NULL, 0x20000);
    s32 rdata_offset;
    s32 rdata_size;

    output_stream_write_dnsname(&baos, fqdn);
    output_stream_write_u16(&baos, script[*index]); // NE
    output_stream_write_u16(&baos, CLASS_IN); // NE
    output_stream_write_u32(&baos, htonl(86400));
    rdata_offset = bytearray_output_stream_size(&baos);
    output_stream_write_u16(&baos, 0);

    switch(script[*index])
    {
        case TYPE_SOA:
        {
            output_stream_write(&baos, "\003ns1", 4);
            output_stream_write_dnsname(&baos, fqdn);
            output_stream_write(&baos, "\004mail", 5);
            output_stream_write_dnsname(&baos, fqdn);
            output_stream_write_u32(&baos, htonl(g_record_input_data_feed_serial));
            output_stream_write_u32(&baos, htonl(3600));
            output_stream_write_u32(&baos, htonl(1800));
            output_stream_write_u32(&baos, htonl(360000));
            output_stream_write_u32(&baos, htonl(600));
            break;
        }
        case TYPE_NS:
        {
            int ns_count = 1;
            for(size_t i = 0; i < *index; ++i)
            {
                if(script[i] == TYPE_NS)
                {
                    ++ns_count;
                }
            }

            char name[256];
            u8 wire[256];
            snformat(name, sizeof(name), "ns%i.%{dnsname}", ns_count, fqdn);
            cstr_to_dnsname(wire, name);
            output_stream_write_dnsname(&baos, wire);
            break;
        }
        case TYPE_MX:
        {
            int mx_count = 1;
            for(size_t i = 0; i < *index; ++i)
            {
                if(script[*index] == TYPE_MX)
                {
                    ++mx_count;
                }
            }

            char name[256];
            u8 wire[256];
            snformat(name, sizeof(name), "mail%i.%{dnsname}", mx_count, fqdn);
            cstr_to_dnsname(wire, name);
            output_stream_write_u16(&baos, htons(mx_count * 10));
            output_stream_write_dnsname(&baos, wire);
            break;
        }
    }

    s32 record_size = bytearray_output_stream_size(&baos);
    rdata_size = record_size - rdata_offset - 2;

    u8 *record_wire = bytearray_output_stream_buffer(&baos);
    SET_U16_AT(record_wire[rdata_offset], ntohs(rdata_size));

    ya_result ret;

    if(ISOK(ret = input_stream_data_write(input_data, record_wire, record_size)))
    {
        (*index)++;
    }

    output_stream_close(&baos);

    return ret;
}
