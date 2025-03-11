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

/*------------------------------------------------------------------------------
 *
 * @ingroup dnscore
 *
 *----------------------------------------------------------------------------*/
#ifndef _OUTPUT_STREAM_H
#define _OUTPUT_STREAM_H

#include <dnscore/sys_types.h>
#include <dnscore/dnsname.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct output_stream_s;
typedef struct output_stream_s    output_stream_t;

typedef ya_result                 output_stream_write_method(output_stream_t *stream, const uint8_t *buffer, uint32_t len);
typedef ya_result                 output_stream_flush_method(output_stream_t *stream);

typedef void                      output_stream_close_method(output_stream_t *stream);

typedef ya_result                 output_stream_skip_method(output_stream_t *stream, uint32_t byte_count);

typedef struct output_stream_vtbl output_stream_vtbl;

struct output_stream_vtbl
{
    output_stream_write_method *write;
    output_stream_flush_method *flush;
    output_stream_close_method *close;

    const char                 *__class__; /* MUST BE A UNIQUE POINTER, ie: One defined in the class's .c file
                                              The name should be unique in order to avoid compiler tricks
                                            */

    /* Add your inheritable methods here */
};

struct output_stream_s
{
    void                     *data;
    const output_stream_vtbl *vtbl;
};

#define output_stream_class(os__)                  ((os__)->vtbl)
#define output_stream_class_name(os__)             ((os__)->vtbl->__class__)
#define output_stream_write(os__, buffer__, len__) (os__)->vtbl->write((os__), (const uint8_t *)(buffer__), (len__))
#define output_stream_flush(os__)                  (os__)->vtbl->flush(os__)
#define output_stream_close(os__)                  (os__)->vtbl->close(os__)
#define output_stream_valid(os__)                  ((os__)->vtbl != NULL)

ya_result output_stream_write_nu32(output_stream_t *os, uint32_t value);
ya_result output_stream_write_nu16(output_stream_t *os, uint16_t value);

/*
 * ya_result output_stream_write_u8(output_stream_t *os, uint8_t value);
 */

static inline ya_result output_stream_write_u8(output_stream_t *os, uint8_t value) { return output_stream_write(os, &value, 1); }

static inline ya_result output_stream_write_u16(output_stream_t *os, uint16_t value) { return output_stream_write(os, (uint8_t *)&value, 2); }

static inline ya_result output_stream_write_u32(output_stream_t *os, uint32_t value) { return output_stream_write(os, (uint8_t *)&value, 4); }

/*
 * PACKED unsigned 32 bits
 *
 * The integer is divided into 7 bits packets (lsb -> msb)
 * The 8th bit is set until the end is reached
 *
 * [  0..  127] => [     0x00 ..      0x7f]
 * [128..16384] => [0x80 0x01 .. 0xff 0x7f]
 *
 */

ya_result output_stream_write_pu16(output_stream_t *os, uint16_t value);

ya_result output_stream_write_pu32(output_stream_t *os, uint32_t value);

ya_result output_stream_write_pu64(output_stream_t *os, uint64_t value);

/**
 * Writes a C-string to a stream
 *
 * @param os    the stream
 * @param text  the text
 *
 * return an error code
 */

ya_result output_stream_write_text(output_stream_t *os, const char *text);

// wire
ya_result output_stream_write_dnsname(output_stream_t *os, const uint8_t *name);

// ascii
ya_result output_stream_write_dnsname_text(output_stream_t *os, const uint8_t *name);

ya_result output_stream_write_dnslabel_text_escaped(output_stream_t *os, const uint8_t *label);
ya_result output_stream_write_dnsname_text_escaped(output_stream_t *os, const uint8_t *name);

ya_result output_stream_write_dnslabel_vector(output_stream_t *os, dnslabel_vector_reference_t labels, int32_t top);

ya_result output_stream_write_dnslabel_stack(output_stream_t *os, dnslabel_stack_reference_t labels, int32_t top);

ya_result output_stream_decode_base64(output_stream_t *os, const char *string, uint32_t length);
ya_result output_stream_decode_base32(output_stream_t *os, const char *string, uint32_t length);
ya_result output_stream_decode_base32hex(output_stream_t *os, const char *string, uint32_t length);
ya_result output_stream_decode_base16(output_stream_t *os, const char *string, uint32_t length);

/**
 * Note: the typebitmap.h file declares a type_bit_maps_output_stream_write function
 */

output_stream_t *output_stream_new_instance();

/**
 * This tools allows a safer misuse (and detection) of closed streams
 * It sets the stream to a sink that warns abouts its usage and for which every call that can fail fails.
 */

void output_stream_set_void(output_stream_t *stream);

/**
 * Used to temporarily initialise a stream with a sink that can be closed safely.
 * Typically used as pre-init so the stream can be closed even if the function
 * setup failed before reaching stream initialisation.
 *
 * @param os
 */

void      output_stream_set_sink(output_stream_t *os);

ya_result output_stream_write_fully(output_stream_t *stream, const void *buffer_start, uint32_t len_start);

#ifdef __cplusplus
}
#endif

#endif /* _OUTPUT_STREAM_H */
