/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
 * @defgroup format C-string formatting
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <math.h>

#include "dnscore/timeformat.h"
#include "dnscore/ctrl_rfc.h"
#include "dnscore/hash.h"
#include "dnscore/mutex.h"

// Enables or disables the feature
#define HAS_DLADDR_SUPPORT 0

#ifdef __linux__
#ifdef __GNUC__
// linux + gnu: Enabling enhanced function address translation
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef __USE_GNU
#define __USE_GNU 1
#endif
#include <dlfcn.h>
#undef HAS_DLADDR_SUPPORT
#define HAS_DLADDR_SUPPORT 0 // keep it disabled for the rest of the binary
#endif
#endif

/* Added this for FreeBSD */
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#elif defined __OpenBSD__
#include <sys/socket.h>
#endif
/**/

#include <arpa/inet.h>
#include <time.h>

#include "dnscore/format.h"
#include "dnscore/bytearray_output_stream.h"
#include "dnscore/counter_output_stream.h"
#include "dnscore/ptr_vector.h"
#include "dnscore/base64.h"
#include "dnscore/base16.h"
#include "dnscore/base32hex.h"
#include "dnscore/sys_error.h"
#include "dnscore/dnscore_extension.h"

#define FMTHDESC_TAG               0x4353454448544d46

#define SENTINEL                   '%'
#define NULL_STRING_SUBSTITUTE     "(NULL)"
#define NULL_STRING_SUBSTITUTE_LEN (sizeof(NULL_STRING_SUBSTITUTE) - 1)

#define CHR0                       '\0'

static const uint8_t *STREOL = (const uint8_t *)"\n";
// static const uint8_t* STRCHR0 = (const uint8_t*)"\0";
static const uint8_t *STRMINUS = (const uint8_t *)"-";
static const uint8_t *STRESCAPE = (const uint8_t *)"\\";
static const uint8_t *STRQUOTE = (const uint8_t *)"\"";
static const uint8_t  STRSPACE[] = {' '};
static const uint8_t  STRSEPARATOR[] = {' ', '|', ' '};
// static const uint8_t QUOTE_SPACE_QUOTE[3] = {'"', ' ', '"'};

#if 0
static const char ESCAPE_CHARS[] = {'@', '$', '\\', ';', ' ', '\t'};
#endif

#define TXT_ESCAPE_TYPE_NONE 0
#define TXT_ESCAPE_TYPE_CHAR 1
#define TXT_ESCAPE_TYPE_OCTL 2

static const uint8_t TXT_ESCAPE_TYPE[256] = {
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,

    TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_CHAR, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, // 0x20
    TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, // 0x28
    TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, // 0x30
    TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, // 0x38
    TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, // 0x40
    TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, // 0x48
    TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, // 0x50
    TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_CHAR, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, // 0x58
    TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, // 0x60
    TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, // 0x68
    TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, // 0x70
    TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, TXT_ESCAPE_TYPE_NONE, // 0x78

    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
    TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL, TXT_ESCAPE_TYPE_OCTL,
};

/*
 * Linear access to the format handlers.  Accessed through a dichotomy.
 */

static ptr_vector_t                        format_handler_descriptor_table = {{NULL}, -1, -1};
static const format_handler_descriptor_t **format_handler_descriptor_hash_table = NULL;
static int                                 format_handler_descriptor_hash_table_size = 0;
static mutex_t                             debug_osformat_mtx = MUTEX_INITIALIZER;

// static bool g_format_usable = false;

static int format_handler_compare(const char *str1, int32_t str1_len, const char *str2, int32_t str2_len)
{

    int32_t len = MIN(str1_len, str2_len);

    int     ret = memcmp(str1, str2, len);

    if(ret == 0)
    {
        ret = str1_len - str2_len;
    }

    return ret;
}

static int format_handler_qsort_compare(const void *a_, const void *b_)
{
    format_handler_descriptor_t *a = (format_handler_descriptor_t *)a_;
    format_handler_descriptor_t *b = (format_handler_descriptor_t *)b_;

    return format_handler_compare(a->name, a->name_len, b->name, b->name_len);
}

static const format_handler_descriptor_t *format_get_format_handler(const char *name, uint32_t name_len)
{
    if(format_handler_descriptor_table.data == NULL)
    {
        return NULL; /* Not initialized */
    }

    format_handler_descriptor_t *fh = NULL;

    uint32_t                     low = 0;
    uint32_t                     high = format_handler_descriptor_table.offset + 1;

    while(high - low > 3)
    {
        uint32_t mid = (high + low) / 2;

        fh = format_handler_descriptor_table.data[mid];

        int cmp = format_handler_compare(name, name_len, fh->name, fh->name_len);

        if(cmp == 0)
        {
            return fh;
        }

        if(cmp > 0)
        {
            low = mid + 1;
        }
        else
        {
            high = mid;
        }
    }

    for(; low < high; low++)
    {
        fh = format_handler_descriptor_table.data[low];

        int cmp = format_handler_compare(fh->name, fh->name_len, name, name_len);

        if(cmp == 0)
        {
            return fh;
        }
    }

    return NULL;
}

/* Example of custom format handler -> */

/*
 * The dummy format handler simply prints the pointer in hexadecimal / lo-case
 */

static void dummy_format_handler_method(const void *val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *reserved_for_method_parameters)
{
    (void)reserved_for_method_parameters;

    intptr_t ival = (intptr_t)val;
    format_hex_u64_lo(ival, stream, padding, pad_char, left_justified);
}

static format_handler_descriptor_t dummy_format_handler_descriptor = {"Unsupported", 11, dummy_format_handler_method};

/* <- Example of custom format handler */

static void format_grow_hash_table();

void        format_class_init()
{
    if(format_handler_descriptor_table.data != NULL)
    {
        return;
    }

    ptr_vector_init(&format_handler_descriptor_table);

    format_grow_hash_table();
}

void format_class_finalize()
{
    ptr_vector_finalise(&format_handler_descriptor_table);
    free((void *)format_handler_descriptor_hash_table);
    format_handler_descriptor_hash_table = NULL;
}

#if UNUSED
bool format_available() { return format_handler_descriptor_table.data != NULL; }
#endif

uint32_t isqrt(uint32_t);

#define FORMAT_GROW_HASH_TABLE_COUNT 19
static int  format_grow_hash_table_sizes_index = 0;
static int  format_grow_hash_table_sizes[FORMAT_GROW_HASH_TABLE_COUNT] = {1117, 2237, 4481, 8963, 17929, 35863, 71741, 143483, 286973, 573953, 1147921, 2295859, 4591721, 9183457, 18366923, 36733847, 73467739, 146935499, 293871013};

static void format_grow_hash_table()
{
    bool retry;

    do
    {
        if(format_grow_hash_table_sizes_index < FORMAT_GROW_HASH_TABLE_COUNT)
        {
            format_handler_descriptor_hash_table_size = format_grow_hash_table_sizes[format_grow_hash_table_sizes_index++]; // prime
        }
        else
        {
            fprintf(stderr, "can't register these formats with the current implementation");
            exit(1);
        }

        if(format_handler_descriptor_hash_table != NULL)
        {
            free((void *)format_handler_descriptor_hash_table);
        }

        retry = false;

        MALLOC_OBJECT_ARRAY_OR_DIE(format_handler_descriptor_hash_table, const format_handler_descriptor_t *, format_handler_descriptor_hash_table_size, FMTHDESC_TAG);
        ZEROMEMORY((void *)format_handler_descriptor_hash_table, format_handler_descriptor_hash_table_size * sizeof(format_handler_descriptor_t *));

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&format_handler_descriptor_table); ++i)
        {
            const format_handler_descriptor_t *fhd = (format_handler_descriptor_t *)ptr_vector_get(&format_handler_descriptor_table, i);
            hashcode                           code = hash_chararray(fhd->name, fhd->name_len);

            int                                slot = code % format_handler_descriptor_hash_table_size;

            if(format_handler_descriptor_hash_table[slot] != NULL)
            {
                retry = true;
                break;
            }

            format_handler_descriptor_hash_table[slot] = fhd; // VS false positive: slot is unsigned and limited by the modulo of the size of the table
        }
    } while(retry);
}

ya_result format_registerclass(const format_handler_descriptor_t *fhd)
{
    if(format_get_format_handler(fhd->name, fhd->name_len) != NULL)
    {
        return FORMAT_ALREADY_REGISTERED; /* Already registered */
    }

    ptr_vector_append(&format_handler_descriptor_table, (format_handler_descriptor_t *)fhd);

    ptr_vector_qsort(&format_handler_descriptor_table, format_handler_qsort_compare);

    hashcode code = hash_chararray(fhd->name, fhd->name_len);
    int      slot = code % format_handler_descriptor_hash_table_size;

    if(format_handler_descriptor_hash_table[slot] == NULL)
    {
        format_handler_descriptor_hash_table[slot] = fhd;
    }
    else
    {
        format_grow_hash_table();
    }

    return SUCCESS;
}

/*typedef size_t formatter(char* output, size_t max_chars, bool left-aligned, void* value_to_convert,int
 * arg_count,va_list args);*/

typedef void      u64_formatter_function(uint64_t, output_stream_t *, int32_t, char, bool);

static const char __HEXA__[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
static const char __hexa__[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static void       do_padding(output_stream_t *stream, int32_t padding, char pad_char)
{
    output_stream_write_method *os_write = stream->vtbl->write;

    while(padding-- > 0)
    {
        os_write(stream, (uint8_t *)&pad_char, 1);
    }
}

static void format_unsigned(const char *input, size_t size, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified)
{
    padding -= size;

    if(left_justified)
    {
        output_stream_write(stream, (const uint8_t *)input, size);
        do_padding(stream, padding, pad_char);
    }
    else
    {
        do_padding(stream, padding, pad_char);
        output_stream_write(stream, (const uint8_t *)input, size);
    }

    /* Done */
}

static void format_signed(const char *input, size_t size, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, bool sign)
{
    padding -= size;

    if(left_justified)
    {
        if(sign)
        {
            output_stream_write(stream, STRMINUS, 1);
        }

        output_stream_write(stream, (const uint8_t *)input, size);
        do_padding(stream, padding, pad_char);
    }
    else
    {
        if(sign && pad_char == '0')
        {
            output_stream_write(stream, STRMINUS, 1);
        }

        do_padding(stream, padding, pad_char);

        if(sign && pad_char != '0')
        {
            output_stream_write(stream, STRMINUS, 1);
        }

        output_stream_write(stream, (const uint8_t *)input, size);
    }

    /* Done */
}

static void format_hex_u64_common(const char *hexa_table, uint64_t val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified)
{
    char  tmp[__SIZEOF_POINTER__ * 2];
    char *next = &tmp[sizeof(tmp)];

    do
    {
        *--next = hexa_table[val & 0x0f];
        val >>= 4;
    } while(val != 0);

    format_unsigned(next, &tmp[sizeof(tmp)] - next, stream, padding, pad_char, left_justified);
}

void format_oct_u64(uint64_t val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified)
{
    char  tmp[24];
    char *next = &tmp[sizeof(tmp)];

    do
    {
        *--next = '0' + (val & 7);
        val >>= 3;
    } while(val != 0);

    /* next points at the first char of the 10-based representation of the integer */

    format_unsigned(next, &tmp[sizeof(tmp)] - next, stream, padding, pad_char, left_justified);
}

void format_dec_u64(uint64_t val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified)
{
    char  tmp[20];
    char *next = &tmp[sizeof(tmp)];

    do
    {
        *--next = '0' + (val % 10);
        val /= 10;
    } while(val != 0);

    /* next points at the first char of the 10-based representation of the integer */

    format_unsigned(next, &tmp[sizeof(tmp)] - next, stream, padding, pad_char, left_justified);
}

void format_dec_s64(int64_t val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified)
{
    char  tmp[20];
    char *next = &tmp[sizeof(tmp)];

    bool  sign;

    if((sign = (val < 0)))
    {
        val = -val;
    }

    uint64_t uval = (uint64_t)val;

    do
    {
        *--next = '0' + (uval % 10);
        uval /= 10;
    } while(uval != 0);

    format_signed(next, &tmp[sizeof(tmp)] - next, stream, padding, pad_char, left_justified, sign);
}

void        format_hex_u64_lo(uint64_t val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified) { format_hex_u64_common(__hexa__, val, stream, padding, pad_char, left_justified); }

void        format_hex_u64_hi(uint64_t val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified) { format_hex_u64_common(__HEXA__, val, stream, padding, pad_char, left_justified); }

static void format_double_make_format(char *p, int32_t padding, int32_t float_padding, char pad_char, bool left_justified, bool long_double)
{
    *p++ = '%';

    if(!left_justified)
    {
        *p++ = '-';
    }
    if(pad_char != ' ')
    {
        *p++ = pad_char;
    }
    if(padding >= 0)
    {
        p += sprintf(p, "%i", padding);
    }
    if(float_padding >= 0)
    {
        *p++ = '.';
        p += sprintf(p, "%i", float_padding);
    }
    if(long_double)
    {
        *p++ = 'L';
    }
    *p++ = 'f';
    *p++ = CHR0;
}

static void format_longdouble(long double val, output_stream_t *stream, int32_t padding, int32_t float_padding, char pad_char, bool left_justified)
{
    char fmt[32];
    char tmp[64];

    format_double_make_format(fmt, padding, float_padding, pad_char, left_justified, true);
    int len = snprintf(tmp, sizeof(tmp), fmt, val);
    output_stream_write(stream, (const uint8_t *)tmp, len);
}

static void format_double(double val, output_stream_t *stream, int32_t padding, int32_t float_padding, char pad_char, bool left_justified)
{
    char fmt[32];
    char tmp[64];

    format_double_make_format(fmt, padding, float_padding, pad_char, left_justified, false);
    int len = snprintf(tmp, sizeof(tmp), fmt, val);
    output_stream_write(stream, (const uint8_t *)tmp, len);
}

void format_asciiz(const char *val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified)
{
    if(val == NULL)
    {
        val = NULL_STRING_SUBSTITUTE;
    }

    size_t val_len = strlen(val);

    padding -= val_len;

    if(left_justified)
    {
        output_stream_write(stream, (const uint8_t *)val, val_len);
        do_padding(stream, padding, pad_char);
    }
    else
    {
        do_padding(stream, padding, pad_char);
        output_stream_write(stream, (const uint8_t *)val, val_len);
    }
}

ya_result vosformat(output_stream_t *os_, const char *fmt, va_list args)
{
    counter_output_stream_context_t cosd;
    output_stream_t                 os;
    counter_output_stream_init(&os, os_, &cosd);

    const char *next = fmt;

    int32_t     padding = -1;
    int32_t     float_padding = -1;
    uint8_t     type_size = sizeof(int);
    uint8_t     size_modifier_count = 0;
    char        pad_char = ' ';
    bool        left_justified = true;

    char        c;

    for(;;)
    {
        c = *next;

        if(c == 0)
        {
            /* copy the rest, return */
            size_t size = next - fmt;

            output_stream_write(&os, (const uint8_t *)fmt, size);

            ya_result ret;

            if(ISOK(cosd.result))
            {
                ret = cosd.write_count;
            }
            else
            {
                ret = cosd.result;
            }

            /**
             *	NOTE: counter_output_stream_t has changed a bit since its first version.
             *
             *
             *	      It does not closes the fitlered stream on "close"
             *        It does not flushes the filtered stream on "close" either.
             *        It only flushes the filtered stream when explicitly asked with "flush"
             *
             *        It is thus useless to call close here (we just loose the time for the call)
             *
             */

            /* output_stream_close(&os); */

            return ret;
        }

        if(c == SENTINEL)
        {
            size_modifier_count = 0;

            /* copy the rest, format */

            size_t size = next - fmt;

            output_stream_write(&os, (const uint8_t *)fmt, size);

            next++;

            fmt += size;

            /* format */

            c = *next++;

            if(c == '%')
            {
                /*
                 * warning: ‘char’ is promoted to ‘int’ when passed through ‘...’
                 *	    (so you should pass ‘int’ not ‘char’ to ‘va_arg’)
                 *	    if this code is reached, the program will abort
                 *
                 * => int
                 */

                format_asciiz("%", &os, padding, pad_char, left_justified);

                fmt = next;

                padding = 0;
                type_size = sizeof(int);
                pad_char = ' ';
                left_justified = true;

                continue;
            }

            /* Justify */

            if(c == '-')
            {
                left_justified = false;
                c = *next++;
            }

            /* Padding */

            if(c == '0')
            {
                pad_char = c;

                left_justified = false;

                c = *next++;
            }

            /* Padding */

            if(isdigit(c))
            {
                char  padding_string[10];

                char *p = padding_string;
                int   n = 9;

                do
                {
                    *p++ = c;
                    c = *next++;
                } while(isdigit(c) && (n > 0));

                *p = CHR0;

                padding = atoi(padding_string);
            }

            if(c == '.')
            {
                char  padding_string[10];

                char *p = padding_string;
                int   n = 9;
                c = *next++;
                do
                {
                    *p++ = c;
                    c = *next++;
                } while(isdigit(c) && (n > 0));

                *p = CHR0;

                float_padding = atoi(padding_string);
            }

            /* Type size */

            if(c == 'h')
            {
                c = *next++;

                type_size = sizeof(uint16_t);

                if(c == 'h')
                {
                    c = *next++;

                    type_size = sizeof(uint8_t);
                }
            }
            else if(c == 'l')
            {
                c = *next++;

                type_size = sizeof(uint32_t);
                size_modifier_count = 1;

                if(c == 'l')
                {
                    c = *next++;

                    type_size = sizeof(uint64_t);
                    size_modifier_count = 2;
                }
            }
            else if(c == 'L')
            {
                c = *next++;

                type_size = sizeof(long double);
            }

            /* Type */

            switch(c)
            {
                case 'i':
                {
                    int64_t val;

                    switch(type_size)
                    {
                        case sizeof(int8_t):
                        {
                            /*
                             * warning: ‘uint8_t’ is promoted to ‘int’ when passed through ‘...’
                             *	    (so you should pass ‘int’ not ‘uint8_t’ to ‘va_arg’)
                             *	    if this code is reached, the program will abort
                             *
                             * => int
                             */
                            val = (int8_t)va_arg(args, int);
                            break;
                        }

                        case sizeof(int16_t):
                        {
                            /*
                             * warning: ‘u16’ is promoted to ‘int’ when passed through ‘...’
                             *	    (so you should pass ‘int’ not ‘u16’ to ‘va_arg’)
                             *	    if this code is reached, the program will abort
                             *
                             * => int
                             */

                            val = (int16_t)va_arg(args, int);
                            break;
                        }

                        case sizeof(int32_t):
                        {
                            val = (int32_t)va_arg(args, int32_t);
                            break;
                        }

                        case sizeof(int64_t):
                        {
                            val = va_arg(args, int64_t);
                            break;
                        }
                        default:
                        {
                            /* Invalid formatting : FULL STOP */

                            flushout();
                            flusherr();

                            fprintf(stderr, "Invalid type size '%i' in string '%s'", type_size, fmt); /* Keep native */
                            fflush(stderr);

                            abort();
                        }
                    }

                    format_dec_s64(val, &os, padding, pad_char, left_justified);

                    break;
                }

                case 'r':
                {
                    ya_result val = va_arg(args, ya_result);

                    error_writetext(&os, val);

                    break;
                }

                case 'x':
                case 'X':
                case 'u':
                case 'd':
                case 'o':
                {
                    u64_formatter_function *formatter;

                    uint64_t                val;

                    if(c == 'u' || c == 'd')
                    {
                        formatter = format_dec_u64;
                    }
                    else if(c == 'X')
                    {
                        formatter = format_hex_u64_hi;
                    }
                    else if(c == 'x')
                    {
                        formatter = format_hex_u64_lo;
                    }
                    else
                    {
                        formatter = format_oct_u64;
                    }

                    switch(type_size)
                    {

                        case sizeof(uint8_t):
                        {
                            /*
                             * warning: ‘uint8_t’ is promoted to ‘int’ when passed through ‘...’
                             *	    (so you should pass ‘int’ not ‘uint8_t’ to ‘va_arg’)
                             *	    if this code is reached, the program will abort
                             *
                             * => int
                             */
                            val = va_arg(args, int);
                            break;
                        }

                        case sizeof(uint16_t):
                        {
                            /*
                             * warning: ‘u16’ is promoted to ‘int’ when passed through ‘...’
                             *	    (so you should pass ‘int’ not ‘u16’ to ‘va_arg’)
                             *	    if this code is reached, the program will abort
                             *
                             * => int
                             */

                            val = va_arg(args, int);
                            break;
                        }

                        case sizeof(uint32_t):
                        {
                            val = va_arg(args, uint32_t);
                            break;
                        }

                        case sizeof(uint64_t):
                        {
                            val = va_arg(args, u64);
                            break;
                        }
                        default:
                        {
                            /* Invalid formatting : FULL STOP */

                            flushout();
                            flusherr();

                            fprintf(stderr, "Invalid type size '%i' in string '%s'", type_size, fmt); /* Keep native */
                            fflush(stderr);

                            abort();
                        }
                    }

                    formatter(val, &os, padding, pad_char, left_justified);
                    break;
                }
                case 'P':
                {

                    intptr_t val = va_arg(args, intptr_t);

#if HAS_DLADDR_SUPPORT
                    Dl_info info;

                    if(val != 0)
                    {
                        if(dladdr((void *)val, &info) != 0)
                        {
                            if(info.dli_sname != NULL)
                            {
                                format_asciiz(info.dli_sname, &os, padding, pad_char, left_justified);
                                break;
                            }
                            else if(info.dli_fname != NULL)
                            {
                                format_asciiz(info.dli_fname, &os, padding, pad_char, left_justified);
                                val -= (intptr_t)info.dli_fbase;
                                output_stream_write_u8(&os, (uint8_t)':');
                            }
                        }
                    }
#endif

                    format_hex_u64_hi(val, &os, __SIZEOF_POINTER__ * 2, '0', false);
                    break;
                }
                case 'p':
                {
                    intptr_t val = va_arg(args, intptr_t);

                    format_hex_u64_hi(val, &os, __SIZEOF_POINTER__ * 2, '0', false);
                    break;
                }
                case 'f':
                {
                    if(type_size == sizeof(long double))
                    {
                        long double val = va_arg(args, long double);

                        format_longdouble(val, &os, padding, float_padding, pad_char, left_justified);
                    }
                    else
                    {
                        double val = va_arg(args, double);

                        format_double(val, &os, padding, float_padding, pad_char, left_justified);
                    }

                    break;
                }
                case 's':
                {
                    const char *val;

                    val = va_arg(args, const char *);

                    format_asciiz(val, &os, padding, pad_char, left_justified);

                    break;
                }
                case 'c':
                {
                    /* I'm using the string formatter.  It's slower than it could but ... */
                    char tmp[2];
                    tmp[1] = CHR0;

                    /*
                     * warning: ‘char’ is promoted to ‘int’ when passed through ‘...’
                     *	    (so you should pass ‘int’ not ‘char’ to ‘va_arg’)
                     *	    if this code is reached, the program will abort
                     *
                     * => int
                     */

                    tmp[0] = va_arg(args, int);

                    format_asciiz(tmp, &os, padding, pad_char, left_justified);

                    break;
                }

                case '{':
                {
                    const char *type_name = next;
                    do
                    {
                        c = *next++;

                        if(c == 0)
                        {
                            flushout();
                            flusherr();

                            fprintf(stderr, "PANIC: Invalid format type in string '%s' : '}' expected.", fmt); /* Keep native */
                            fflush(stderr);
                            abort();
                        }
                    } while(c != '}');

                    /* type_name -> next contains the type name and arguments
                     * arguments can be integers
                     */

                    size_t                             type_name_len = next - 1 - type_name;

                    const format_handler_descriptor_t *desc = format_get_format_handler(type_name, type_name_len);

                    if(desc == NULL)
                    {
                        /* Uses the "dummy" handler */

                        desc = &dummy_format_handler_descriptor;
                    }

                    void *ptr = va_arg(args, void *);
                    desc->format_handler(ptr, &os, padding, pad_char, left_justified, NULL);

                    break;
                }

                case 'w':
                {
                    void            *ptr = va_arg(args, void *);
                    format_writer_t *fw = (format_writer_t *)ptr;
                    fw->callback(fw->value, &os, padding, pad_char, left_justified, NULL);
                    break;
                }

                case 't':
                {
                    int val = (int)va_arg(args, int);
                    do_padding(&os, val, '\t');
                    break;
                }

                case 'S':
                {
                    int val = (int)va_arg(args, int);
                    do_padding(&os, val, ' ');
                    break;
                }

                case 'T':
                {
                    switch(size_modifier_count)
                    {
                        case 0:
                        {
                            int64_t val = (int64_t)va_arg(args, uint32_t);
                            localepoch_format_handler_method((void *)(intptr_t)val, &os, 0, 0, false, NULL);
                            break;
                        }

                        case 1:
                        {
                            int64_t val = (int64_t)va_arg(args, int64_t);
                            localdatetime_format_handler_method((void *)(intptr_t)val, &os, 0, 0, false, NULL);
                            break;
                        }

                        case 2:
                        {

                            int64_t val = (int64_t)va_arg(args, int64_t);
                            localdatetimeus_format_handler_method((void *)(intptr_t)val, &os, 0, 0, false, NULL);
                            break;
                        }
                        default:
                        {
                            abort();
                        }
                    }

                    break;
                }

                case 'U':
                {
                    switch(size_modifier_count)
                    {
                        case 0:
                        {
                            int64_t val = (int64_t)va_arg(args, uint32_t);
                            epoch_format_handler_method((void *)(intptr_t)val, &os, 0, 0, false, NULL);
                            break;
                        }

                        case 1:
                        {
                            int64_t val = (int64_t)va_arg(args, int64_t);
                            datetime_format_handler_method((void *)(intptr_t)val, &os, 0, 0, false, NULL);
                            break;
                        }

                        case 2:
                        {

                            int64_t val = (int64_t)va_arg(args, int64_t);
                            datetimeus_format_handler_method((void *)(intptr_t)val, &os, 0, 0, false, NULL);
                            break;
                        }
                        default:
                        {
                            abort();
                        }
                    }

                    break;
                }
            }

            fmt = next;

            padding = -1;
            float_padding = -1;
            type_size = sizeof(int);
            pad_char = ' ';
            left_justified = true;

            continue;
        }

        next++;

        /* look for the sentinel */
    }
}

ya_result osprint(output_stream_t *stream, const char *text) { return output_stream_write(stream, (const uint8_t *)text, strlen(text)); }

/**
 * Prints a text, wrapped.
 *
 * @param stream the stream to print to
 * @param text the text to print
 * @param column_current the current column in the console
 * @param column_count the number of columns in the screen (0: attempt to detect using IOCTLs)
 * @param column_wrap when wrapping, the column to wrap to
 */

ya_result osprint_wrapped(output_stream_t *stream, const char *text, int column_current, int column_count, int column_wrap)
{
    const char *next_word = text;
    bool        just_wrapped = true;
    for(;;)
    {
        int word_size;
        switch(*next_word)
        {
            case ' ':
            {
                word_size = 1;
                if(column_current + word_size >= column_count)
                {
                    if(!just_wrapped)
                    {
                        just_wrapped = true;
                        output_stream_write_u8(stream, '\n');
                        for(int_fast32_t i = 0; i < column_wrap; ++i)
                        {
                            output_stream_write_u8(stream, ' ');
                        }
                        column_current = column_wrap;
                    }
                }
                else
                {
                    output_stream_write_u8(stream, ' ');
                    column_current += word_size;
                }
                ++next_word;
                continue;
            }
            case '\t':
            {
                word_size = 8 - (column_current & 7);
                if(column_current + word_size >= column_count)
                {
                    if(!just_wrapped)
                    {
                        just_wrapped = true;
                        output_stream_write_u8(stream, '\n');
                        for(int_fast32_t i = 0; i < column_wrap; ++i)
                        {
                            output_stream_write_u8(stream, ' ');
                        }
                        column_current = column_wrap;
                    }
                }
                else
                {
                    for(int_fast32_t i = 0; i < word_size; ++i)
                    {
                        output_stream_write_u8(stream, ' ');
                    }
                    column_current += word_size;
                }
                ++next_word;
                continue;
            }
            case '\r':
            {
                ++next_word;
                continue;
            }
            case '\n':
            {
                if(!just_wrapped)
                {
                    just_wrapped = true;
                    output_stream_write_u8(stream, '\n');
                    for(int_fast32_t i = 0; i < column_wrap; ++i)
                    {
                        output_stream_write_u8(stream, ' ');
                    }
                    column_current = column_wrap;
                }
                ++next_word;
                continue;
            }
            case '\0':
            {
                return SUCCESS;
            }
            default:
            {
                word_size = 1;
                while(next_word[word_size] > ' ')
                {
                    ++word_size;
                }
                if(column_current + word_size >= column_count)
                {
                    if(!just_wrapped)
                    {
                        // just_wrapped = true;
                        output_stream_write_u8(stream, '\n');
                        for(int_fast32_t i = 0; i < column_wrap; ++i)
                        {
                            output_stream_write_u8(stream, ' ');
                        }
                        column_current = column_wrap;
                    }
                }

                output_stream_write(stream, next_word, word_size);
                next_word += word_size;
                column_current += word_size;
                just_wrapped = false;
                continue;
            }
        } // switch
    } // for

    return output_stream_write(stream, (const uint8_t *)text, strlen(text));
}

ya_result osprintln(output_stream_t *stream, const char *text)
{
    ya_result n = strlen(text);

    output_stream_write(stream, (const uint8_t *)text, n);
    output_stream_write(stream, STREOL, 1);

    return n + 1;
}

ya_result osformat(output_stream_t *stream, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    ya_result err = vosformat(stream, fmt, args);
    va_end(args);
    return err;
}

ya_result osformatln(output_stream_t *stream, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    ya_result err1 = vosformat(stream, fmt, args);
    va_end(args);

    if(ISOK(err1))
    {
        ya_result err2 = output_stream_write(stream, STREOL, 1);

        if(ISOK(err2))
        {
            return err1 + err2;
        }

        return err2;
    }

    return err1;
}

ya_result debug_osformatln(output_stream_t *stream, const char *fmt, ...)
{
    int64_t now = timeus();
    mutex_lock(&debug_osformat_mtx);
    localdatetimeus_format_handler_method((void *)(intptr_t)now, stream, 0, 0, false, NULL);
    output_stream_write(stream, STRSEPARATOR, sizeof(STRSEPARATOR));
    format_dec_u64(getpid(), stream, 0, 0, false);
    output_stream_write(stream, STRSEPARATOR, sizeof(STRSEPARATOR));
    format_hex_u64_lo((uint64_t)(intptr_t)pthread_self(), stream, 0, 0, false);
    output_stream_write(stream, STRSEPARATOR, sizeof(STRSEPARATOR));
    va_list args;
    va_start(args, fmt);
    ya_result err1 = vosformat(stream, fmt, args);
    va_end(args);
    output_stream_write(stream, STREOL, 1);
    mutex_unlock(&debug_osformat_mtx);
    return err1;
}

ya_result debug_println(const char *text)
{
    int64_t now = timeus();
    mutex_lock(&debug_osformat_mtx);
    localdatetimeus_format_handler_method((void *)(intptr_t)now, termout, 0, 0, false, NULL);
    output_stream_write(termout, STRSEPARATOR, sizeof(STRSEPARATOR));
    format_dec_u64(getpid(), termout, 0, 0, false);
    output_stream_write(termout, STRSEPARATOR, sizeof(STRSEPARATOR));
    format_hex_u64_lo((uint64_t)(intptr_t)pthread_self(), termout, 0, 0, false);
    output_stream_write(termout, STRSEPARATOR, sizeof(STRSEPARATOR));
    ya_result n = strlen(text);
    output_stream_write(termout, (const uint8_t *)text, n);
    output_stream_write(termout, STREOL, 1);
    mutex_unlock(&debug_osformat_mtx);
    return n + 1;
}

ya_result print(const char *text) { return output_stream_write(termout, (const uint8_t *)text, strlen(text)); }

ya_result println(const char *text)
{
    ya_result n = strlen(text);
    output_stream_write(termout, (const uint8_t *)text, n);
    output_stream_write(termout, STREOL, 1);

    return n + 1;
}

int format(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    ya_result err = vosformat(termout, fmt, args);
    va_end(args);
    return err;
}

ya_result formatln(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    ya_result err1 = vosformat(termout, fmt, args);
    va_end(args);

    if(ISOK(err1))
    {
        ya_result err2 = output_stream_write(termout, STREOL, 1);

        if(ISOK(err2))
        {
            return err1 + err2;
        }

        return err2;
    }

    return err1;
}

int vsnformat(char *out, size_t out_size, const char *fmt, va_list args)
{
    if(out_size == 0)
    {
        return 0;
    }

    output_stream_t                 baos;
    bytearray_output_stream_context baos_context;

    bytearray_output_stream_init_ex_static(&baos, (uint8_t *)out, out_size - 1, 0, &baos_context);

    int ret = vosformat(&baos, fmt, args);

    if(ret < (int)out_size)
    {
        out[ret] = CHR0;
    }
    else
    {
        out[out_size - 1] = CHR0;
    }

    output_stream_close(&baos);

    return ret;
}

/**
 * This formatter will return an allocated (malloc) string as a result of the format
 *
 * @param outp
 * @param out_size
 * @param fmt
 * @param args
 * @return
 */

int vasnformat(char **outp, size_t out_size, const char *fmt, va_list args)
{
    output_stream_t                 baos;
    bytearray_output_stream_context baos_context;

    bytearray_output_stream_init_ex_static(&baos, NULL, out_size, 0, &baos_context);

    int ret = vosformat(&baos, fmt, args);

    if(ISOK(ret) && ((out_size == 0) || (ret < (int)out_size)))
    {
        output_stream_write_u8(&baos, 0);
        *outp = (char *)bytearray_output_stream_dup(&baos);
    }
    else
    {
        *outp = NULL;
    }

    output_stream_close(&baos);

    return ret;
}

/**
 * This formatter will return an allocated (malloc) string as a result of the format
 *
 * @param outp
 * @param out_size
 * @param fmt
 * @param ...
 * @return
 */

int asnformat(char **outp, size_t out_size, const char *fmt, ...)
{
    int     ret;
    va_list args;
    va_start(args, fmt);
    ret = vasnformat(outp, out_size, fmt, args);
    va_end(args);

    return ret;
}

/**
 * This formatter will return an allocated (malloc) string as a result of the format
 *
 * @param outp

 * @param fmt
 * @param ...
 * @return
 */

int asformat(char **outp, const char *fmt, ...)
{
    int     ret;
    va_list args;
    va_start(args, fmt);
    ret = vasnformat(outp, 0, fmt, args);
    va_end(args);

    return ret;
}

int snformat(char *out, size_t out_size, const char *fmt, ...)
{
    int     ret;
    va_list args;
    va_start(args, fmt);
    ret = vsnformat(out, out_size, fmt, args);
    va_end(args);

    return ret;
}

int osprint_base64(output_stream_t *os, const uint8_t *rdata_pointer, uint32_t rdata_size)
{
    char     buffer[65];
    int      total = 0;
    uint32_t n;

    while(rdata_size > 48)
    {
        n = base64_encode(rdata_pointer, 48, buffer);
        buffer[n++] = ' ';
        output_stream_write(os, (uint8_t *)buffer, n);
        total += n;
        rdata_pointer += 48;
        rdata_size -= 48;
    }

    n = base64_encode(rdata_pointer, rdata_size, buffer);
    output_stream_write(os, (uint8_t *)buffer, n);

    total += n;

    return total;
}

int osprint_base16(output_stream_t *os, const uint8_t *rdata_pointer, uint32_t rdata_size)
{
    char     buffer[65];
    int      total = 0;
    uint32_t n;

    while(rdata_size > 32)
    {
        n = base16_encode(rdata_pointer, 32, buffer);
        buffer[n++] = ' ';
        output_stream_write(os, (uint8_t *)buffer, n);
        total += n;
        rdata_pointer += 32;
        rdata_size -= 32;
    }

    n = base16_encode(rdata_pointer, rdata_size, buffer);
    output_stream_write(os, (uint8_t *)buffer, n);

    total += n;

    return total;
}

int fformat(FILE *out, const char *fmt, ...)
{
    char tmp[4096];

#if DEBUG
    memset(tmp, '!', sizeof(tmp));
#endif

    int     ret;
    va_list args;
    va_start(args, fmt);
    ret = vsnformat(tmp, sizeof(tmp), fmt, args);
    fputs(tmp, out);
    va_end(args);

    return ret;
}

/*------------------------------------------------------------------------------
 * FUNCTIONS */

void osprint_u32(output_stream_t *os, uint32_t value) { format_dec_u64(value, os, 9, ' ', false); }

void osprint_u16(output_stream_t *os, uint16_t value) { format_dec_u64(value, os, 5, ' ', false); }

void osprint_u32_hex(output_stream_t *os, uint32_t value) { format_hex_u64_common(__hexa__, value, os, 8, '0', false); }

void print_char(char value)
{
    char tmp[1];
    tmp[0] = value;
    output_stream_write(&__termout__, (uint8_t *)tmp, 1);
}

void osprint_char(output_stream_t *os, char value)
{
    char tmp[1];
    tmp[0] = value;
    output_stream_write(os, (uint8_t *)tmp, 1);
}

void osprint_char_times(output_stream_t *os, char value, int times)
{
    char tmp[32];

    if(times < 0)
    {
        return;
    }

    if(times > 32)
    {
        memset(tmp, value, 32);

        do
        {
            output_stream_write(os, tmp, 32);
            times -= 32;
        } while(times >= 32);

        output_stream_write(os, tmp, times);
    }
    else
    {
        memset(tmp, value, times);
        output_stream_write(os, tmp, times);
    }
}

ya_result osprint_type_bitmap(output_stream_t *os, const uint8_t *rdata_pointer, uint16_t rdata_size)
{
    /*
     * WindowIndex + WindowSize + bits => a minimum of 3 bytes
     */
    while(rdata_size >= 3)
    {
        uint16_t type_hi = *rdata_pointer++;
        uint8_t  count = *rdata_pointer++;

        rdata_size -= 2;

        if(rdata_size < count)
        {
            return INCORRECT_RDATA;
        }

        rdata_size -= count;

        /*type_hi <<= 8;*/

        uint16_t type_lo = 0;

        while(count-- > 0)
        {
            uint8_t  bitmap = *rdata_pointer++;
            uint32_t b;

            for(b = 8; b > 0; b--)
            {
                if((bitmap & 0x80) != 0)
                {
                    /* Enabled */

                    uint16_t type = type_hi + type_lo;

                    osformat(os, " %{dnstype}", &type);
                }

                bitmap <<= 1;

                type_lo += 0x100;
            }
        }
    }

    return SUCCESS;
}

static const uint32_t loc_pow10[10] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000};
static const char     loc_ns[2] = {'N', 'S'};
static const char     loc_ew[2] = {'E', 'W'};

static bool           loc_float(uint8_t v, uint32_t *out_value)
{
    uint32_t m = v >> 4;
    uint32_t e = v & 0x0f;
    // m in [0;9] e in [0;9]
    // if m == 0 then e != 0
    if(!((m > 9) || (e > 9) || ((m == 0) && (e != 0))))
    {
        *out_value = m * loc_pow10[e];
        return true;
    }
    else
    {
        return false;
    }
}

struct loc_coordinate_s
{
    int32_t secfrac;
    int32_t sec;
    int32_t min;
    int32_t deg;
    int32_t cardinal_index; // N S // E W
};

static void loc_coordinate_init(struct loc_coordinate_s *c, int32_t val)
{
    uint32_t uval = (uint32_t)val; // this avoid the need of -fwrapv
    uval -= INT32_MIN;             //
    val = (int32_t)uval;           //

    if(val < 0)
    {
        val = -val;
        c->cardinal_index = 1;
    }
    else
    {
        c->cardinal_index = 0;
    }

    c->secfrac = val % 1000;
    val /= 1000;
    c->sec = val % 60;
    val /= 60;
    c->min = val % 60;
    val /= 60;
    c->deg = val;
}

/**
 * Print a text (char*, len) between quotes, escaping when required.
 *
 * @param os the output stream
 * @param text a pointer to the text
 * @param text_len the lenght of the text
 * @return an error code
 */

ya_result osprint_quoted_text_escaped(output_stream_t *os, const uint8_t *text, int text_len)
{
    output_stream_write(os, STRQUOTE, 1);

    for(int i = 0; i < text_len; ++i)
    {
        uint8_t escape_type = TXT_ESCAPE_TYPE[text[i]];

        switch(escape_type)
        {
            case TXT_ESCAPE_TYPE_NONE:
            {
                output_stream_write(os, &text[i], 1);
                break;
            }
            case TXT_ESCAPE_TYPE_CHAR:
            {
                output_stream_write(os, STRESCAPE, 1);
                output_stream_write(os, &text[i], 1);
                break;
            }
            case TXT_ESCAPE_TYPE_OCTL:
            {
                uint8_t decimal[4];
                decimal[0] = '\\';
                decimal[1] = ((text[i] / 100) % 10) + '0';
                decimal[2] = ((text[i] / 10) % 10) + '0';
                decimal[3] = (text[i] % 10) + '0';
                output_stream_write(os, decimal, 4);
                break;
            }
        }
    }

    int ret = output_stream_write(os, STRQUOTE, 1);
    return ret;
}

/**
 * Prints the TEXT representation of the rdata of a record of a given type.
 *
 * @param os the output stream
 * @param type the record type
 * @param rdata_pointer a pointer to the rdata
 * @param rdata_size the size of the rdata
 * @return an error code
 */

ya_result osprint_rdata(output_stream_t *os, uint16_t type, const uint8_t *rdata_pointer, uint16_t rdata_size)
{
    char tmp[16];

    switch(type)
    {
        case TYPE_A:
        {
            if(rdata_size == 4)
            {
                osformat(os, "%d.%d.%d.%d", rdata_pointer[0], rdata_pointer[1], rdata_pointer[2], rdata_pointer[3]);
                return SUCCESS;
            }
            return INCORRECT_RDATA;
        }

        case TYPE_AAAA:
        {
            uint16_t *rdata_u16 = (uint16_t *)rdata_pointer;
            if(rdata_size == 16)
            {
                char ip6txt[INET6_ADDRSTRLEN];

                inet_ntop(AF_INET6, rdata_u16, ip6txt, sizeof(ip6txt));

                osprint(os, ip6txt);

                return SUCCESS;
            }
            return INCORRECT_RDATA;
        }
        case TYPE_MX:
        case TYPE_KX:
        case TYPE_LP:
        case TYPE_AFSDB:
            osformat(os, "%hd ", ntohs(GET_U16_AT(*rdata_pointer)));
            rdata_pointer += 2;
            rdata_size -= 2;
        FALLTHROUGH // fall through
            case TYPE_NS:
        case TYPE_CNAME:
        case TYPE_DNAME:
        case TYPE_PTR:
        case TYPE_MB:
        case TYPE_MD:
        case TYPE_MF:
        case TYPE_MG:
        case TYPE_MR:
        {
            /* ONE NAME record */
            if(rdata_size > 0)
            {
                output_stream_write_dnsname_text(os, rdata_pointer);
                return SUCCESS;
            }
            return INCORRECT_RDATA;
        }
        case TYPE_RP:
        {
            if(rdata_size > 0)
            {
                rdata_pointer += output_stream_write_dnsname_text(os, rdata_pointer);
                output_stream_write(os, STRSPACE, sizeof(STRSPACE));
                output_stream_write_dnsname_text(os, rdata_pointer);
                return SUCCESS;
            }
            return INCORRECT_RDATA;
        }
        case TYPE_PX:
        {
            if(rdata_size >= 4)
            {
                osformat(os, "%hd ", ntohs(GET_U16_AT(*rdata_pointer)));
                rdata_pointer += 2;
                rdata_size -= 2;
            }
            else
            {
                return INCORRECT_RDATA;
            }
        }
        FALLTHROUGH // fall through
            case TYPE_TALINK:
        {
            if(rdata_size >= 2)
            {
                uint32_t len = output_stream_write_dnsname_text(os, rdata_pointer);
                rdata_size -= len;

                if(rdata_size > 0)
                {
                    rdata_pointer += len;
                    output_stream_write(os, STRSPACE, 1);
                    len = output_stream_write_dnsname_text(os, rdata_pointer);
                    rdata_size -= len;

                    if(rdata_size == 0)
                    {
                        return SUCCESS;
                    }
                }
            }

            return INCORRECT_RDATA;
        }

        case TYPE_WKS:
        {
            if(rdata_size >= 6)
            {
                osformat(os, "%d.%d.%d.%d", rdata_pointer[0], rdata_pointer[1], rdata_pointer[2], rdata_pointer[3]);

                rdata_pointer += 4;
                rdata_size -= 4;

                ya_result len = protocol_id_to_name(rdata_pointer[0], tmp + 1, sizeof(tmp) - 1);

                if(len < 0)
                {
                    return len;
                }

                tmp[0] = ' ';
                output_stream_write(os, tmp, len + 1);

                rdata_pointer++;
                rdata_size--;

                for(int_fast32_t index = 0; index < rdata_size; ++index)
                {
                    uint8_t m;
                    if((m = rdata_pointer[index]) != 0)
                    {
                        for(int_fast32_t i = 7; i >= 0; --i)
                        {
                            if((m & (1 << i)) != 0)
                            {
                                uint16_t port = (uint16_t)((index << 3) + 7 - i);

                                len = server_port_to_name(port, tmp + 1, sizeof(tmp) - 1);

                                if(len < 0)
                                {
                                    return len;
                                }

                                output_stream_write(os, tmp, len + 1);
                            }
                        }
                    }
                }

                return SUCCESS;
            }
            return INCORRECT_RDATA;
        }

        case TYPE_GPOS:
        {
            const uint8_t *limit = &rdata_pointer[rdata_size];
            int            sep_len = 0;
            for(int_fast32_t i = 0; i < 3; ++i)
            {
                uint8_t len = *rdata_pointer++;

                if(len == 0)
                {
                    return INCORRECT_RDATA;
                }

                if(&rdata_pointer[len] > limit)
                {
                    return INCORRECT_RDATA;
                }

                output_stream_write(os, STRSPACE, sep_len);
                output_stream_write(os, rdata_pointer, len);
                rdata_pointer += len;
                sep_len = 1;
            }

            return SUCCESS;
        }

        case TYPE_LOC:
        {
            /*
             * RDATA_SIZE: must be 16
             *
             * VERSION:  This must be zero.
             * Implementations are required to check this field and make
             * no assumptions about the format of unrecognized versions.
             */

            if(rdata_size != 16 || rdata_pointer[0] != 0)
            {
                return INCORRECT_RDATA;
            }

            /*
             * SIZE: The diameter of a sphere enclosing the described entity, in centimeters
             * format is a pair of four-bit unsigned integers, each ranging from zero to nine
             * This allows sizes from 0e0 (<1cm) to 9e9 (90,000km) to be expressed.
             * Four-bit values greater than 9 are undefined, as are values with a base of zero and a non-zero exponent
             */

            uint32_t size;
            uint32_t horizp;
            uint32_t vertp;

            if(!loc_float(rdata_pointer[1], &size) || !loc_float(rdata_pointer[2], &horizp) || !loc_float(rdata_pointer[3], &vertp))
            {
                return INCORRECT_RDATA;
            }

            /*
             * LATITUDE
             */
            struct loc_coordinate_s loc_latitude;
            loc_coordinate_init(&loc_latitude, ntohl(GET_U32_AT(rdata_pointer[4])));

            /*
             * LONGITUDE
             */

            struct loc_coordinate_s loc_longitude;
            loc_coordinate_init(&loc_longitude, ntohl(GET_U32_AT(rdata_pointer[8])));

            /*
             * ALTITUDE
             */

            const int32_t wgs84_reference = 10000000; // cm

            int32_t       altitude = ntohl(GET_U32_AT(rdata_pointer[12]));
            int32_t       altfrac;
            // int32_t altsign;

            if(altitude >= wgs84_reference)
            {
                altitude -= wgs84_reference;
                altfrac = altitude % 100;
                altitude /= 100;
                // altsign = 1;
            }
            else
            {
                altitude = wgs84_reference - altitude;
                altfrac = altitude % 100;
                altitude /= -100;
                // altsign = -1;
            }

            osformat(os,
                     "%u %02u %02u.%03u %c %u %02u %02u.%03u %c %d.%02um %dm %dm %dm",
                     loc_latitude.deg,                    // degrees latitude [0 .. 90]
                     loc_latitude.min,                    // minutes latitude [0 .. 59]
                     loc_latitude.sec,                    // seconds latitude [0 .. 59]
                     loc_latitude.secfrac,                // fractions of seconds of latitude]
                     loc_ns[loc_latitude.cardinal_index], // ['N' / 'S']

                     loc_longitude.deg,                    // degrees longitude [0 .. 90]
                     loc_longitude.min,                    // minutes longitude [0 .. 59]
                     loc_longitude.sec,                    // seconds longitude [0 .. 59]
                     loc_longitude.secfrac,                // fractions of seconds of longitude]
                     loc_ew[loc_longitude.cardinal_index], // ['E' / 'W']

                     altitude, // altitude in meters [-100000.00 .. 42849672.95]
                     altfrac,

                     size,
                     horizp,
                     vertp);

            return SUCCESS;
        }
        case TYPE_CSYNC:
        {
            if(rdata_size >= 6)
            {
                format_dec_u64(ntohl(GET_U32_AT(rdata_pointer[0])), os, 0, 0, false);
                output_stream_write_u8(os, ' ');
                format_dec_u64(ntohs(GET_U16_AT(rdata_pointer[4])), os, 0, 0, false);
                // output_stream_write_u8(os, ' '); // osprint_type_bitmap starts with a space
                rdata_pointer += 6;
                rdata_size -= 6;

                return osprint_type_bitmap(os, rdata_pointer, rdata_size);
            }

            return INCORRECT_RDATA;
        }
        case TYPE_OPENPGPKEY:
        {
            if(rdata_size > 0)
            {
                return osprint_base64(os, rdata_pointer, rdata_size);
            }

            return INCORRECT_RDATA;
        }
        case TYPE_HINFO:
        case TYPE_MINFO:
        {
            /* Two Pascal String records */

            /*
             * <character-string> is a single length octet followed by that number
             * of characters.  <character-string> is treated as binary information,
             * and can be up to 256 characters in length (including the length octet).
             *
             */

            uint32_t len;
            len = *rdata_pointer;
            --rdata_size;
            if(len > rdata_size)
            {
                return INCORRECT_RDATA;
            }
            ++rdata_pointer;
            osprint_quoted_text_escaped(os, rdata_pointer, len);
            output_stream_write(os, STRSPACE, sizeof(STRSPACE));
            rdata_pointer += len;
            rdata_size -= len;
            len = *rdata_pointer;
            --rdata_size;
            if(len > rdata_size)
            {
                return INCORRECT_RDATA;
            }
            ++rdata_pointer;
            osprint_quoted_text_escaped(os, rdata_pointer, len);
            // rdata_size -= len;
            // rdata_pointer += len;

            return SUCCESS;
        }

        case TYPE_SOA:
        {
            static uint8_t dot = (uint8_t)'.';
            static uint8_t space = (uint8_t)' ';
            static uint8_t escape = (uint8_t)'\\';

            output_stream_write_dnsname_text(os, rdata_pointer);

            output_stream_write(os, &space, 1);

            uint32_t len = dnsname_len(rdata_pointer);

            rdata_size -= len;

            if(rdata_size > 0)
            {
                rdata_pointer += len;

                const uint8_t *label = rdata_pointer;
                uint8_t        label_len = *label;

                if(label_len > 0)
                {
                    label++;

                    do
                    {
                        do
                        {
                            if(!dnsname_is_charspace(*label))
                            {
                                output_stream_write(os, &escape, 1);
                            }

                            output_stream_write(os, label++, 1);
                        } while(--label_len > 0);

                        output_stream_write(os, &dot, 1);

                        label_len = *label++;
                    } while(label_len > 0);

                    len = label - rdata_pointer;
                }
                else
                {
                    output_stream_write(os, &dot, 1);

                    len = 1;
                }

                rdata_size -= len;

                if(rdata_size == 20)
                {
                    rdata_pointer += len;

                    osformat(os, " %u %u %u %u %u", ntohl(GET_U32_AT(rdata_pointer[0])), ntohl(GET_U32_AT(rdata_pointer[4])), ntohl(GET_U32_AT(rdata_pointer[8])), ntohl(GET_U32_AT(rdata_pointer[12])), ntohl(GET_U32_AT(rdata_pointer[16])));

                    return SUCCESS;
                }
            }

            return INCORRECT_RDATA;
        }
        case TYPE_RRSIG:
        {
            struct tm exp;
            struct tm inc;

            time_t    t = (time_t)ntohl(GET_U32_AT(rdata_pointer[8]));
            gmtime_r(&t, &exp);
            t = (time_t)ntohl(GET_U32_AT(rdata_pointer[12]));
            gmtime_r(&t, &inc);

            uint16_t covered_type = (GET_U16_AT(rdata_pointer[0])); /** @note NATIVETYPE */

            osformat(os,
                     "%{dnstype} %u %u %u %04u%02u%02u%02u%02u%02u %04u%02u%02u%02u%02u%02u %u ",
                     &covered_type,
                     U8_AT(rdata_pointer[2]),
                     U8_AT(rdata_pointer[3]),
                     ntohl(GET_U32_AT(rdata_pointer[4])),
                     exp.tm_year + 1900,
                     exp.tm_mon + 1,
                     exp.tm_mday,
                     exp.tm_hour,
                     exp.tm_min,
                     exp.tm_sec,
                     inc.tm_year + 1900,
                     inc.tm_mon + 1,
                     inc.tm_mday,
                     inc.tm_hour,
                     inc.tm_min,
                     inc.tm_sec,
                     ntohs(GET_U16_AT(rdata_pointer[16])));

            rdata_pointer += RRSIG_RDATA_HEADER_LEN;
            rdata_size -= RRSIG_RDATA_HEADER_LEN;

            output_stream_write_dnsname_text(os, rdata_pointer);
            uint32_t len = dnsname_len(rdata_pointer);
            output_stream_write_u8(os, ' ');

            rdata_pointer += len;
            rdata_size -= len;

            if(rdata_size > 0)
            {
                osprint_base64(os, rdata_pointer, rdata_size);
            }

            return SUCCESS;
        }
        case TYPE_DNSKEY:
        case TYPE_KEY:
        case TYPE_CDNSKEY:
        {
            osformat(os, "%u %u %u ", ntohs(GET_U16_AT(rdata_pointer[0])), U8_AT(rdata_pointer[2]), U8_AT(rdata_pointer[3]));

            rdata_pointer += 4;
            rdata_size -= 4;

            osprint_base64(os, rdata_pointer, rdata_size);

            return SUCCESS;
        }
        case TYPE_DS:
        case TYPE_CDS:
        case TYPE_DLV:
        {
            osformat(os, "%u %u %u ", ntohs(GET_U16_AT(rdata_pointer[0])), U8_AT(rdata_pointer[2]), U8_AT(rdata_pointer[3]));

            rdata_pointer += 4;
            rdata_size -= 4;

            while(rdata_size-- > 0)
            {
                osformat(os, "%02X", *rdata_pointer++);
            }

            return SUCCESS;
        }
        case TYPE_NSEC:
        {
            output_stream_write_dnsname_text(os, rdata_pointer);
            uint32_t len = dnsname_len(rdata_pointer);
            // output_stream_write_u8(os, ' '); osprint_type_bitmap starts with a space

            rdata_pointer += len;
            rdata_size -= len;

            ya_result ret;

            if(ISOK(ret = osprint_type_bitmap(os, rdata_pointer, rdata_size)))
            {
                return SUCCESS;
            }

            return ret;
        }
        case TYPE_NSEC3:
        case TYPE_NSEC3PARAM:
        {
            osformat(os, "%hhd %hhd %hd ", rdata_pointer[0], (type != TYPE_NSEC3PARAM) ? rdata_pointer[1] : 0, ntohs(GET_U16_AT(rdata_pointer[2])));
            uint8_t len = rdata_pointer[4];

            rdata_pointer += 5;
            rdata_size -= 5;

            if(len == 0)
            {
                osprint(os, "-");
            }
            else
            {
                rdata_size -= len;

                while(len-- > 0)
                {
                    osformat(os, "%02x", *rdata_pointer++);
                }
            }

            if(type == TYPE_NSEC3)
            {
                output_stream_write_u8(os, ' ');

                len = *rdata_pointer++;

                rdata_size -= 1 + len;

                ya_result return_code;

                if(FAIL(return_code = output_stream_write_base32hex(os, rdata_pointer, len)))
                {
                    return return_code;
                }

                rdata_pointer += len;

                return_code = osprint_type_bitmap(os, rdata_pointer, rdata_size);

                return return_code;
            }

            return SUCCESS;
        }
        case TYPE_TLSA:
        {
            osformat(os, "%hhd %hhd %hhd ", rdata_pointer[0], rdata_pointer[1], rdata_pointer[2]);

            return osprint_base16(os, &rdata_pointer[3], rdata_size - 3);
        }
        case TYPE_SSHFP:
        {
            osformat(os, "%hhd %hhd ", rdata_pointer[0], rdata_pointer[1]);

            return osprint_base16(os, &rdata_pointer[2], rdata_size - 2);
        }
        case TYPE_NID:
        case TYPE_L64:
        {
            if(rdata_size == 10)
            {
                osformat(
                    os, "%hu %04x:%04x:%04x:%04x", ntohs(GET_U16_AT(rdata_pointer[0])), ntohs(GET_U16_AT(rdata_pointer[2])), ntohs(GET_U16_AT(rdata_pointer[4])), ntohs(GET_U16_AT(rdata_pointer[6])), ntohs(GET_U16_AT(rdata_pointer[8])));

                return SUCCESS;
            }

            return INCORRECT_RDATA;
        }

        case TYPE_L32:
        {
            if(rdata_size == 6)
            {
                osformat(os, "%hu %hhu.%hhu.%hhu.%hhu", ntohs(GET_U16_AT(rdata_pointer[0])), rdata_pointer[2], rdata_pointer[3], rdata_pointer[4], rdata_pointer[5]);

                return SUCCESS;
            }

            return INCORRECT_RDATA;
        }

        case TYPE_EUI48:
        {
            if(rdata_size == 6)
            {
                osformat(os, "%02x-%02x-%02x-%02x-%02x-%02x", rdata_pointer[0], rdata_pointer[1], rdata_pointer[2], rdata_pointer[3], rdata_pointer[4], rdata_pointer[5]);

                return SUCCESS;
            }

            return INCORRECT_RDATA;
        }

        case TYPE_EUI64:
        {
            if(rdata_size == 8)
            {
                osformat(os, "%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x", rdata_pointer[0], rdata_pointer[1], rdata_pointer[2], rdata_pointer[3], rdata_pointer[4], rdata_pointer[5], rdata_pointer[6], rdata_pointer[7]);

                return SUCCESS;
            }

            return INCORRECT_RDATA;
        }

        case TYPE_SRV:
        {
            uint16_t       priority = GET_U16_AT(rdata_pointer[0]);
            uint16_t       weight = GET_U16_AT(rdata_pointer[2]);
            uint16_t       port = GET_U16_AT(rdata_pointer[4]);
            const uint8_t *fqdn = (const uint8_t *)&rdata_pointer[6];

            return osformat(os, "%hd %hd %hd %{dnsname}", priority, weight, port, fqdn);
        }
        case TYPE_ZONE_TYPE:
        {
            uint8_t zone_type = rdata_pointer[0];

            char   *txt;

            switch(zone_type)
            {
                case ZT_HINT:
                {
                    txt = ZT_HINT_STRING;
                    break;
                }
                case ZT_PRIMARY:
                {
                    txt = ZT_PRIMARY_STRING;
                    break;
                }
                case ZT_SECONDARY:
                {
                    txt = ZT_SECONDARY_STRING;
                    break;
                }
                case ZT_STUB:
                {
                    txt = ZT_STUB_STRING;
                    break;
                }
                default:
                {
                    txt = "undefined";
                    break;
                }
            }

            return osprint(os, txt);
        }
        case TYPE_ZONE_PRIMARY:
        case TYPE_ZONE_SECONDARIES:
        case TYPE_ZONE_NOTIFY:
        {
            uint8_t        flags = rdata_pointer[0];
            const uint8_t *src = &rdata_pointer[1];

            ya_result      total = 0;

            switch(flags & 0x0f)
            {
                case 4:
                {
                    // 4 bytes

                    total += osformat(os, "%d.%d.%d.%d", src[0], src[1], src[2], src[3]);

                    src += 4;

                    break;
                }
                case 6:
                {
                    // 16 bytes

                    char ip6txt[INET6_ADDRSTRLEN];

                    inet_ntop(AF_INET6, src, ip6txt, sizeof(ip6txt));

                    total += osprint(os, ip6txt);

                    src += 16;

                    break;
                }
            }

            if((flags & REMOTE_SERVER_FLAGS_PORT_MASK) != 0)
            {
                uint16_t port = ntohs(GET_U16_AT(*src));

                total += osformat(os, " %hd", port);

                src += 2;
            }

            if((flags & REMOTE_SERVER_FLAGS_KEY_MASK) != 0)
            {

                total += osformat(os, " %{dnsname}", src);
            }

            return total;
        }

        case TYPE_TXT:
        case TYPE_SPF:
        {
            uint8_t pascal_string_size;
            int     space_len = 0;

            while(rdata_size > 0)
            {
                pascal_string_size = *rdata_pointer++;

                if(pascal_string_size > 0)
                {
                    if(pascal_string_size < rdata_size)
                    {
                        output_stream_write(os, STRSPACE, space_len); // 0 at first, then 1
                        pascal_string_size = MIN(pascal_string_size, rdata_size);
                        osprint_quoted_text_escaped(os, rdata_pointer, pascal_string_size);
                    }
                    else
                    {
                        return INCORRECT_RDATA;
                    }
                }
                else
                {
                    output_stream_write(os, "\"\"", 2);
                }

                space_len = 1;

                rdata_size--;
                rdata_pointer += pascal_string_size;
                rdata_size -= pascal_string_size;
            }

            return SUCCESS;
        }
        case TYPE_CAA:
        {
            if(rdata_size > 3)
            {
                uint8_t flags = *rdata_pointer++;
                --rdata_size;
                format_dec_u64(flags, os, 0, 0, false);
                output_stream_write_u8(os, ' ');

                uint8_t tag_size = *rdata_pointer++;
                --rdata_size;
                if(rdata_size >= tag_size)
                {
                    output_stream_write(os, rdata_pointer, tag_size);
                    rdata_pointer += tag_size;
                    rdata_size -= tag_size;
                    static char space_doublequote[2] = {' ', '"'};
                    output_stream_write(os, space_doublequote, sizeof(space_doublequote));
                    output_stream_write(os, rdata_pointer, rdata_size);
                    output_stream_write_u8(os, '"');
                    return SUCCESS;
                }
            }
            return INCORRECT_RDATA;
        }
        case TYPE_CERT:
        {
            if(rdata_size < 6)
            {
                return INCORRECT_RDATA;
            }

            uint16_t type_id = ntohs(GET_U16_AT_P(rdata_pointer));
            rdata_pointer += 2;
            const char *mnemonic = dns_cert_type_name_from_id(type_id);
            if(mnemonic != NULL)
            {
                output_stream_write(os, mnemonic, strlen(mnemonic));
            }
            else
            {
                format_dec_u64(type_id, os, 0, ' ', false);
            }

            output_stream_write_u8(os, ' ');
            uint16_t tag = ntohs(GET_U16_AT_P(rdata_pointer));
            rdata_pointer += 2;
            format_dec_u64(tag, os, 0, 0, false);
            output_stream_write_u8(os, ' ');
            uint8_t     algorithm = *rdata_pointer++;
            const char *algorithm_name = dns_encryption_algorithm_get_name(algorithm);
            if(algorithm_name != NULL)
            {
                osprint(os, algorithm_name);
            }
            else
            {
                format_dec_u64(algorithm, os, 0, 0, false);
            }
            output_stream_write_u8(os, ' ');
            rdata_size -= 5;
            osprint_base64(os, rdata_pointer, rdata_size);
            return SUCCESS;
        }
        case TYPE_DHCID:
        {
            osprint_base64(os, rdata_pointer, rdata_size);
            return SUCCESS;
        }
        case TYPE_CTRL_ZONEFREEZE:
        case TYPE_CTRL_ZONEUNFREEZE:
        case TYPE_CTRL_ZONENOTIFY:
        case TYPE_CTRL_ZONERELOAD:
        case TYPE_CTRL_ZONECFGRELOAD:
        {
            /* ONE NAME record */
            if(rdata_size > 0)
            {
                ya_result ret = output_stream_write_dnsname_text(os, rdata_pointer);
                return ret;
            }
            return SUCCESS;
        }
        case TYPE_CTRL_SRVLOGLEVEL:
        case TYPE_CTRL_SRVQUERYLOG:
        {
            if(rdata_size == 1)
            {
                format_hex_u64_lo(rdata_pointer[0], os, 2, '0', false);
                return SUCCESS;
            }
            return INCORRECT_RDATA;
        }
        case TYPE_CTRL_ZONESYNC:
        {
            /* ONE NAME record */
            if(rdata_size > 0)
            {
                format_hex_u64_lo(rdata_pointer[0], os, 2, '0', false);

                if(rdata_size > 1)
                {
                    output_stream_write_u8(os, (uint8_t)' ');
                    ya_result ret = output_stream_write_dnsname_text(os, rdata_pointer + 1);

                    if(ISOK(ret))
                    {
                        return ret + 3;
                    }
                    else
                    {
                        return ret;
                    }
                }
            }
            return SUCCESS;
        }
        case TYPE_TSIG:
        {
            const uint8_t *limit = &rdata_pointer[rdata_size];

            ya_result      ret = output_stream_write_dnsname_text(os, rdata_pointer);

            if(FAIL(ret))
            {
                return ret;
            }

            rdata_pointer += ret;

            if(limit - rdata_pointer < 16)
            {
                return INCORRECT_RDATA;
            }

            uint16_t time_hi = ntohs(GET_U16_AT(rdata_pointer[0]));
            uint32_t time_lo = ntohl(GET_U32_AT(rdata_pointer[2]));
            uint16_t fudge = ntohs(GET_U16_AT(rdata_pointer[6]));
            uint16_t mac_size = ntohs(GET_U16_AT(rdata_pointer[8]));

            rdata_pointer += 10;

            if(limit - rdata_pointer < mac_size + 6)
            {
                return INCORRECT_RDATA;
            }

            uint64_t epoch = time_hi;
            epoch <<= 32;
            epoch |= time_lo;

            osformat(os, " %u %hu %hu", epoch, fudge, mac_size);

            if(mac_size > 0)
            {
                osprint_char(os, ' ');
                osprint_base64(os, rdata_pointer, mac_size);
                rdata_pointer += mac_size;
            }

            uint16_t oid = ntohs(GET_U16_AT(rdata_pointer[0]));
            uint16_t error = ntohs(GET_U16_AT(rdata_pointer[2]));
            uint16_t olen = ntohs(GET_U16_AT(rdata_pointer[4]));

            rdata_pointer += 6;

            if(limit - rdata_pointer != olen)
            {
                return INCORRECT_RDATA;
            }

            osformat(os, " %i %s %i", ntohs(oid), dns_message_rcode_get_name(error), olen);

            if(rdata_pointer < limit)
            {
                do
                {
                    osformat(os, " %02x", rdata_pointer[0]);
                } while(++rdata_pointer < limit);
            }

            return SUCCESS;
        }

        case TYPE_A6:
        case TYPE_IXFR:
        case TYPE_AXFR:
        case TYPE_SIG:
        case TYPE_ANY:
        default:
        {
            if(!dnscore_dns_extension_osprint_data(os, type, rdata_pointer, rdata_size))
            {
                osformat(os, "\\# %u ", rdata_size); /* rfc 3597 */
                osprint_base16(os, rdata_pointer, rdata_size);
            }

            return SUCCESS;
        }
    }

    return INCORRECT_RDATA;
}

/**
 * Prints the TEXT representation of the rdata of a record of a given type.
 * FQDN containing '@', '$', '\\' and ';' are escaped.
 *
 * Uses osprint_rdata for types not requiring escapes.
 *
 * @param os the output stream
 * @param type the record type
 * @param rdata_pointer a pointer to the rdata
 * @param rdata_size the size of the rdata
 *
 * returns an error code.
 */

ya_result osprint_rdata_escaped(output_stream_t *os, uint16_t type, const uint8_t *rdata_pointer, uint16_t rdata_size)
{
    switch(type)
    {
        case TYPE_MX:
        case TYPE_KX:
        case TYPE_LP:
        case TYPE_AFSDB:
            osformat(os, "%hd ", ntohs(GET_U16_AT(*rdata_pointer)));
            rdata_pointer += 2;
            rdata_size -= 2;
        FALLTHROUGH // fall through
            case TYPE_NS:
        case TYPE_CNAME:
        case TYPE_DNAME:
        case TYPE_PTR:
        case TYPE_MB:
        case TYPE_MD:
        case TYPE_MF:
        case TYPE_MG:
        case TYPE_MR:
        {
            /* ONE NAME record */
            if(rdata_size > 0)
            {
                output_stream_write_dnsname_text_escaped(os, rdata_pointer);
                return SUCCESS;
            }
            return INCORRECT_RDATA;
        }

        case TYPE_TALINK:
        {
            if(rdata_size >= 2)
            {
                uint32_t len = output_stream_write_dnsname_text_escaped(os, rdata_pointer);
                rdata_size -= len;

                if(rdata_size > 0)
                {
                    rdata_pointer += len;
                    output_stream_write(os, STRSPACE, 1);
                    len = output_stream_write_dnsname_text_escaped(os, rdata_pointer);
                    rdata_size -= len;

                    if(rdata_size == 0)
                    {
                        return SUCCESS;
                    }
                }
            }

            return INCORRECT_RDATA;
        }
        case TYPE_SOA:
        {
            output_stream_write_dnsname_text_escaped(os, rdata_pointer);
            output_stream_write_u8(os, ' ');

            uint32_t len = dnsname_len(rdata_pointer);
            rdata_size -= len;

            if(rdata_size > 0)
            {
                rdata_pointer += len;

                output_stream_write_dnsname_text_escaped(os, rdata_pointer);
                output_stream_write_u8(os, ' ');

                len = dnsname_len(rdata_pointer);
                rdata_size -= len;

                if(rdata_size == 20)
                {
                    rdata_pointer += len;

                    osformat(os, "%u %u %u %u %u", ntohl(GET_U32_AT(rdata_pointer[0])), ntohl(GET_U32_AT(rdata_pointer[4])), ntohl(GET_U32_AT(rdata_pointer[8])), ntohl(GET_U32_AT(rdata_pointer[12])), ntohl(GET_U32_AT(rdata_pointer[16])));

                    return SUCCESS;
                }
            }

            return INCORRECT_RDATA;
        }
        case TYPE_RRSIG:
        {
            struct tm exp;
            struct tm inc;

            time_t    t = (time_t)ntohl(GET_U32_AT(rdata_pointer[8]));
            gmtime_r(&t, &exp);
            t = (time_t)ntohl(GET_U32_AT(rdata_pointer[12]));
            gmtime_r(&t, &inc);

            uint16_t covered_type = (GET_U16_AT(rdata_pointer[0])); /** @note NATIVETYPE */

            osformat(os,
                     "%{dnstype} %u %u %u %04u%02u%02u%02u%02u%02u %04u%02u%02u%02u%02u%02u %u ",
                     &covered_type,
                     U8_AT(rdata_pointer[2]),
                     U8_AT(rdata_pointer[3]),
                     ntohl(GET_U32_AT(rdata_pointer[4])),
                     exp.tm_year + 1900,
                     exp.tm_mon + 1,
                     exp.tm_mday,
                     exp.tm_hour,
                     exp.tm_min,
                     exp.tm_sec,
                     inc.tm_year + 1900,
                     inc.tm_mon + 1,
                     inc.tm_mday,
                     inc.tm_hour,
                     inc.tm_min,
                     inc.tm_sec,
                     ntohs(GET_U16_AT(rdata_pointer[16])));

            rdata_pointer += RRSIG_RDATA_HEADER_LEN;
            rdata_size -= RRSIG_RDATA_HEADER_LEN;

            output_stream_write_dnsname_text_escaped(os, rdata_pointer);
            uint32_t len = dnsname_len(rdata_pointer);
            output_stream_write_u8(os, ' ');

            rdata_pointer += len;
            rdata_size -= len;

            if(rdata_size > 0)
            {
                osprint_base64(os, rdata_pointer, rdata_size);
            }

            return SUCCESS;
        }

        case TYPE_NSEC:
        {
            output_stream_write_dnsname_text_escaped(os, rdata_pointer);
            uint32_t len = dnsname_len(rdata_pointer);
            // output_stream_write_u8(os, ' '); // osprint_type_bitmap starts with a ' '

            rdata_pointer += len;
            rdata_size -= len;

            ya_result ret;

            if(ISOK(ret = osprint_type_bitmap(os, rdata_pointer, rdata_size)))
            {
                return SUCCESS;
            }

            return ret;
        }

        case TYPE_SRV:
        {
            uint16_t       priority = GET_U16_AT(rdata_pointer[0]);
            uint16_t       weight = GET_U16_AT(rdata_pointer[2]);
            uint16_t       port = GET_U16_AT(rdata_pointer[4]);
            const uint8_t *fqdn = (const uint8_t *)&rdata_pointer[6];

            osformat(os, "%hd %hd %hd ", priority, weight, port);

            ya_result ret = output_stream_write_dnsname_text_escaped(os, fqdn);

            return ret;
        }

        default:
        {
            ya_result ret = osprint_rdata(os, type, rdata_pointer, rdata_size);

            return ret;
        }
    }

    return INCORRECT_RDATA;
}

ya_result print_rdata(uint16_t type, const uint8_t *rdata_pointer, uint16_t rdata_size) { return osprint_rdata(termout, type, rdata_pointer, rdata_size); }

void      osprint_dump_with_base(output_stream_t *os, const void *data_pointer_, size_t size_, size_t line_size, uint32_t flags, const void *base_pointer_)
{
    const uint8_t *data_pointer = (const uint8_t *)data_pointer_;
    size_t         size = size_;

    bool           offset = (flags & OSPRINT_DUMP_OFFSET) != 0;
    bool           address = (flags & OSPRINT_DUMP_ADDRESS) != 0;
    bool           hex = (flags & OSPRINT_DUMP_HEX) != 0;
    bool           text = (flags & OSPRINT_DUMP_TEXT) != 0;
    bool           squeeze_zeroes = (flags & OSPRINT_DUMP_SQUEEZE_ZEROES) != 0;

    size_t         group = flags & OSPRINT_DUMP_LAYOUT_GROUP_MASK;
    group >>= OSPRINT_DUMP_LAYOUT_GROUP_SHIFT;
    size_t separator = flags & OSPRINT_DUMP_LAYOUT_SEPARATOR_MASK;
    separator >>= OSPRINT_DUMP_LAYOUT_SEPARATOR_SHIFT;

    int32_t offset_width = 2 * 2;

    if(offset)
    {
        if(size_ > U16_MAX)
        {
            if(size_ <= U32_MAX)
            {
                offset_width = 4 * 2;
            }
            else
            {
                offset_width = 8 * 2;
            }
        }
    }

    size_t  dump_size;
    size_t  i;
    int64_t zeroes_count = 0;

    char    hexbyte[2];

    do
    {
        if(line_size != 0)
        {
            dump_size = MIN(line_size, size);
        }
        else
        {
            dump_size = size;
        }

        const uint8_t *data;

        if(squeeze_zeroes && (dump_size == line_size))
        {
            if(base_pointer_ < (const void *)data_pointer)
            {
                bool zeroes = true;
                for(int_fast32_t i = 0; i < (int)line_size; ++i)
                {
                    if(data_pointer[i] != 0)
                    {
                        zeroes = false;
                        break;
                    }
                }

                if(zeroes)
                {
                    zeroes_count += line_size;
                    data_pointer += dump_size;
                    size -= dump_size;
                    continue;
                }
                else if(zeroes_count > 0)
                {
                    osformatln(os, "\t\t... %lli zeroes ...", zeroes_count);
                    zeroes_count = 0;
                }
            }
        }

        if(address)
        {
            format_hex_u64_hi((intptr_t)data_pointer, os, __SIZEOF_POINTER__ * 2, '0', false);
            output_stream_write(os, (const uint8_t *)" | ", 3);
        }

        if(offset)
        {
            format_hex_u64_hi((intptr_t)data_pointer - (intptr_t)base_pointer_, os, offset_width, '0', false);
            output_stream_write(os, (const uint8_t *)" | ", 3);
        }

        if(hex)
        {
            data = data_pointer;

            for(i = 0; i < dump_size; i++)
            {
                uint8_t val = *data++;

                hexbyte[0] = __hexa__[val >> 4];
                hexbyte[1] = __hexa__[val & 0x0f];

                output_stream_write(os, (uint8_t *)hexbyte, 2);

                if((i & group) == group)
                {
                    output_stream_write_u8(os, (uint8_t)' ');
                }
                if((i & separator) == separator)
                {
                    output_stream_write_u8(os, (uint8_t)' ');
                }
            }

            for(; i < line_size; i++)
            {
                output_stream_write(os, (const uint8_t *)"  ", 2); // these are two spaces
                if((i & group) == group)
                {
                    output_stream_write_u8(os, (uint8_t)' ');
                }
                if((i & separator) == separator)
                {
                    output_stream_write_u8(os, (uint8_t)' ');
                }
            }
        }

        if(text)
        {
            if(hex)
            {
                output_stream_write(os, (const uint8_t *)" |  ", 4);
            }

            data = data_pointer;

            for(i = 0; i < dump_size; i++)
            {
                char c = *data++;

                // c < ' ' && c > 126 => c + 1 < ' ' + 1
                if((char)(c + 1) < (char)(' ' + 1))
                {
                    c = '.';
                }

                output_stream_write_u8(os, (uint8_t)c);
            }
        }

        data_pointer += dump_size;
        size -= dump_size;

        if(size != 0)
        {
            output_stream_write_u8(os, (uint8_t)'\n');
        }
    } while(size > 0);
}

void osprint_dump(output_stream_t *os, const void *data_pointer_, size_t size_, size_t line_size, uint32_t flags) { osprint_dump_with_base(os, data_pointer_, size_, line_size, flags, data_pointer_); }

void osprint_question(output_stream_t *os, const uint8_t *qname, uint16_t qclass, uint16_t qtype) { osformat(os, ";; QUESTION SECTION:\n%{dnsname} %{dnsclass} %{dnstype}\n\n", qname, &qclass, &qtype); }

void print_question(const uint8_t *qname, uint16_t qclass, uint16_t qtype) { osprint_question(termout, qname, qclass, qtype); }

/** @} */
