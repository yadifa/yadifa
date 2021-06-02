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

#pragma once

#include <dnscore/input_stream.h>
#include <dnscore/rfc.h>

#define INPUT_STREAM_INPUT_BUFFER_SIZE 0x40000 // it needs to be bigger than twice the maximum record size AND a 2^n
#define INPUT_STREAM_INPUT_BUFFER_MASK (INPUT_STREAM_INPUT_BUFFER_SIZE - 1)

struct input_s;

typedef const u8* input_domain_get_method(struct input_s *input);
typedef ya_result input_axfr_input_stream_init_method(struct input_s *input, input_stream *is);
typedef ya_result input_ixfr_input_stream_init_method(struct input_s *input, u32 serial_value, input_stream *is);
typedef ya_result input_finalise_method(struct input_s *input);

struct input_vtbl_s
{
    input_domain_get_method *domain_get;
    input_axfr_input_stream_init_method *axfr_input_stream_init;
    input_ixfr_input_stream_init_method *ixfr_input_stream_init;
    input_finalise_method *finalise;
};

typedef struct input_vtbl_s input_vtbl_t;

struct input_s
{
    void *data;
    input_vtbl_t *vtbl;
};

typedef struct input_s input_t;

struct input_stream_input_data_s;

typedef ya_result input_stream_input_data_feed_method(struct input_stream_input_data_s *input_data);

struct input_stream_input_data_s
{
    input_t *input;
    input_stream_input_data_feed_method *feed;
    s64 mode;
    u32 avail;
    s32 base;

    s64 indexes[16]; // space reserved for the feed callback, it will mostly need indexes and pointers
    uint8_t *pointers[16];

    u8 data[INPUT_STREAM_INPUT_BUFFER_SIZE];
};

typedef struct input_stream_input_data_s input_stream_input_data_t;

static inline const u8* input_domain_get(input_t *input)
{
    return input->vtbl->domain_get(input);
}

static inline ya_result input_axfr_input_stream_init(input_t *input, input_stream *is)
{
    return input->vtbl->axfr_input_stream_init(input, is);
}

static inline ya_result input_ixfr_input_stream_init(input_t *input, u32 serial_value, input_stream *is)
{
    return input->vtbl->ixfr_input_stream_init(input, serial_value, is);
}

static inline ya_result input_finalise(input_t *input)
{
    return input->vtbl->finalise(input);
}

ya_result input_stream_input_init(input_stream *is, input_t *input, input_stream_input_data_feed_method *feed_callback);

static inline input_stream_input_data_t* input_stream_input_data(input_stream *is)
{
    return (input_stream_input_data_t*)is->data;
}

ya_result input_stream_data_write(struct input_stream_input_data_s *input_data, const u8 *buffer, size_t buffer_size);

void record_input_data_feed_serial_set(u32 serial);
/*
 * SOA
 * NS
 * MX
 *
 */
/*
u16 record_input_data_feed_script[] =
{
    TYPE_SOA, TYPE_NS, TYPE_NS, TYPE_MX
}
*/
ya_result record_input_data_feed(struct input_stream_input_data_s *input_data, const u16 *script, size_t script_count, const u8 *fqdn, size_t *index);
