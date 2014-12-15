/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
/** @defgroup format C-string formatting
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#include "dnscore/ctrl-rfc.h"

// Enables or disables the feature
#define HAS_DLADDR_SUPPORT 0

#ifdef __linux__
#ifdef __GNUC__
#pragma message "linux + gnu: Enabling enhanced function address translation"
#define __USE_GNU
#define _GNU_SOURCE
#include <dlfcn.h>
#undef HAS_DLADDR_SUPPORT
#define HAS_DLADDR_SUPPORT 0    // keep it disabled for the rest of the binary
#endif
#endif

/* Added this for FreeBSD */
#ifdef __FreeBSD__
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
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

#define SENTINEL '%'
#define NULL_STRING_SUBSTITUTE "(NULL)"
#define NULL_STRING_SUBSTITUTE_LEN (sizeof(NULL_STRING_SUBSTITUTE)-1)

#define CHR0 '\0'

static const u8* STREOL = (const u8*)"\n";
//static const u8* STRCHR0 = (const u8*)"\0";
static const u8* STRMINUS = (const u8*)"-";

/*
 * Linear access to the format handlers.  Accessed through a dichotomy.
 */

static ptr_vector format_handler_descriptor_table = {NULL, -1, -1};

//static bool g_format_usable = FALSE;

static int
format_handler_compare(const char* str1, s32 str1_len, const char* str2, s32 str2_len)
{

    s32 len = MIN(str1_len, str2_len);

    int ret = memcmp(str1, str2, len);

    if(ret == 0)
    {
        ret = str1_len - str2_len;
    }

    return ret;
}

static int
format_handler_qsort_compare(const void* a_, const void* b_)
{
    format_handler_descriptor* a = *(format_handler_descriptor**)a_;
    format_handler_descriptor* b = *(format_handler_descriptor**)b_;

    return format_handler_compare(a->name, a->name_len, b->name, b->name_len);
}

static format_handler_descriptor*
format_get_format_handler(const char* name, u32 name_len)
{
    if(format_handler_descriptor_table.data == NULL)
    {
        return NULL; /* Not initialized */
    }

    format_handler_descriptor* fh = NULL;

    u32 low = 0;
    u32 high = format_handler_descriptor_table.offset + 1;

    while(high - low > 3)
    {
        u32 mid = (high + low) / 2;

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

static void
dummy_format_handler_method(const void* val, output_stream* stream, s32 padding, char pad_char, bool left_justified, void* reserved_for_method_parameters)
{
    intptr ival = (intptr)val;
    format_hex_u64_lo(ival, stream, padding, pad_char, left_justified);
}

static format_handler_descriptor dummy_format_handler_descriptor ={
    "Unsupported",
    11,
    dummy_format_handler_method
};

/* <- Example of custom format handler */

void
format_class_init()
{
    if(format_handler_descriptor_table.data != NULL)
    {
        return;
    }

    ptr_vector_init(&format_handler_descriptor_table);
}

void
format_class_finalize()
{
    ptr_vector_destroy(&format_handler_descriptor_table);
}

bool
format_available()
{
    return format_handler_descriptor_table.data != NULL;
}

ya_result
format_registerclass(const format_handler_descriptor* fhd)
{
    if(format_get_format_handler(fhd->name, fhd->name_len) != NULL)
    {
        return FORMAT_ALREADY_REGISTERED; /* Already registered */
    }

    ptr_vector_append(&format_handler_descriptor_table, (format_handler_descriptor*)fhd);

    ptr_vector_qsort(&format_handler_descriptor_table, format_handler_qsort_compare);
    
    return SUCCESS;
}

/*typedef size_t formatter(char* output, size_t max_chars, bool left-aligned, void* value_to_convert,int arg_count,va_list args);*/

typedef void
u64_formatter_function(u64, output_stream*, s32, char, bool);

static const char __HEXA__[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
static const char __hexa__[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static void
do_padding(output_stream* stream, s32 padding, char pad_char)
{
    output_stream_write_method* os_write = stream->vtbl->write;

    while(padding-- > 0)
    {
        os_write(stream, (u8*) & pad_char, 1);
    }
}

static void
format_unsigned(const char* input, size_t size, output_stream* stream, s32 padding, char pad_char, bool left_justified)
{
    padding -= size;

    if(left_justified)
    {
        output_stream_write(stream, (const u8*)input, size);
        do_padding(stream, padding, pad_char);
    }
    else
    {
        do_padding(stream, padding, pad_char);
        output_stream_write(stream, (const u8*)input, size);
    }

    /* Done */
}

static void
format_signed(const char* input, size_t size, output_stream* stream, s32 padding, char pad_char, bool left_justified, bool sign)
{
    padding -= size;

    if(left_justified)
    {
        if(sign)
        {
            output_stream_write(stream, STRMINUS, 1);
        }

        output_stream_write(stream, (const u8*)input, size);
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

        output_stream_write(stream, (const u8*)input, size);
    }

    /* Done */
}

static void
format_hex_u64_common(const char* hexa_table, u64 val, output_stream* stream, s32 padding, char pad_char, bool left_justified)
{
    char tmp[__SIZEOF_POINTER__ * 2];
    char* next = &tmp[sizeof (tmp)];

    do
    {
        *--next = hexa_table[val & 0x0f];
        val >>= 4;
    }
    while(val != 0);

    format_unsigned(next, &tmp[sizeof (tmp)] - next, stream, padding, pad_char, left_justified);
}

void
format_oct_u64(u64 val, output_stream* stream, s32 padding, char pad_char, bool left_justified)
{
    char tmp[20];
    char* next = &tmp[sizeof (tmp)];

    do
    {
        *--next = '0' + (val & 7);
        val >>= 3;
    }
    while(val != 0);

    /* next points at the first char of the 10-based representation of the integer */

    format_unsigned(next, &tmp[sizeof (tmp)] - next, stream, padding, pad_char, left_justified);
}

void
format_dec_u64(u64 val, output_stream* stream, s32 padding, char pad_char, bool left_justified)
{
    char tmp[20];
    char* next = &tmp[sizeof (tmp)];

    do
    {
        *--next = '0' + (val % 10);
        val /= 10;
    }
    while(val != 0);

    /* next points at the first char of the 10-based representation of the integer */

    format_unsigned(next, &tmp[sizeof (tmp)] - next, stream, padding, pad_char, left_justified);
}

void
format_dec_s64(s64 val, output_stream* stream, s32 padding, char pad_char, bool left_justified)
{
    char tmp[20];
    char* next = &tmp[sizeof (tmp)];

    bool sign;

    if((sign = (val < 0)))
    {
        val = -val;
    }

    u64 uval = (u64)val;

    do
    {
        *--next = '0' + (uval % 10);
        uval /= 10;
    }
    while(uval != 0);

    format_signed(next, &tmp[sizeof (tmp)] - next, stream, padding, pad_char, left_justified, sign);
}

void
format_hex_u64_lo(u64 val, output_stream* stream, s32 padding, char pad_char, bool left_justified)
{
    format_hex_u64_common(__hexa__, val, stream, padding, pad_char, left_justified);
}

void
format_hex_u64_hi(u64 val, output_stream* stream, s32 padding, char pad_char, bool left_justified)
{
    format_hex_u64_common(__HEXA__, val, stream, padding, pad_char, left_justified);
}

static void
format_double_make_format(char* p, s32 padding, s32 float_padding, char pad_char, bool left_justified, bool long_double)
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

static void
format_longdouble(long double val, output_stream* stream, s32 padding, s32 float_padding, char pad_char, bool left_justified)
{
    char fmt[32];
    char tmp[64];

    format_double_make_format(fmt, padding, float_padding, pad_char, left_justified, TRUE);

    int len = snprintf(tmp, sizeof (tmp), fmt, val);

    output_stream_write(stream, (const u8*)tmp, len);
}

static void
format_double(double val, output_stream* stream, s32 padding, s32 float_padding, char pad_char, bool left_justified)
{
    char fmt[32];
    char tmp[64];

    format_double_make_format(fmt, padding, float_padding, pad_char, left_justified, FALSE);

    int len = snprintf(tmp, sizeof (tmp), fmt, val);

    output_stream_write(stream, (const u8*)tmp, len);
}

void
format_asciiz(const char* val, output_stream* stream, s32 padding, char pad_char, bool left_justified)
{
    if(val == NULL)
    {
        val = NULL_STRING_SUBSTITUTE;
    }

    size_t val_len = strlen(val);

    padding -= val_len;

    if(left_justified)
    {
        output_stream_write(stream, (const u8*)val, val_len);
        do_padding(stream, padding, pad_char);
    }
    else
    {
        do_padding(stream, padding, pad_char);
        output_stream_write(stream, (const u8*)val, val_len);
    }
}

ya_result
vosformat(output_stream* os_, const char* fmt, va_list args)
{
    counter_output_stream_data cosd;
    output_stream os;

    counter_output_stream_init(os_, &os, &cosd);

    const char* next = fmt;

    s32 padding = -1;
    s32 float_padding = -1;
    u8 type_size = sizeof (int);
    char pad_char = ' ';
    bool left_justified = TRUE;

    char c;

    for(;;)
    {
        c = *next;

        if(c == 0)
        {
            /* copy the rest, return */
            size_t size = next - fmt;

            output_stream_write(&os, (const u8*)fmt, size);

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
             *	NOTE: counter_output_stream has changed a bit since its first version.
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
            /* copy the rest, format */

            size_t size = next - fmt;

            output_stream_write(&os, (const u8*)fmt, size);

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
                type_size = sizeof (int);
                pad_char = ' ';
                left_justified = TRUE;

                continue;
            }

            /* Justify */

            if(c == '-')
            {
                left_justified = FALSE;
                c = *next++;
            }

            /* Padding */

            if(c == '0')
            {
                pad_char = c;

                left_justified = FALSE;

                c = *next++;
            }

            /* Padding */

            if(isdigit(c))
            {
                char padding_string[10];

                char* p = padding_string;
                int n = 9;

                do
                {
                    *p++ = c;
                    c = *next++;
                }
                while(isdigit(c) && (n > 0));

                *p = CHR0;

                padding = atoi(padding_string);
            }

            if(c == '.')
            {
                char padding_string[10];

                char* p = padding_string;
                int n = 9;
                c = *next++;
                do
                {
                    *p++ = c;
                    c = *next++;
                }
                while(isdigit(c) && (n > 0));

                *p = CHR0;

                float_padding = atoi(padding_string);
            }

            /* Type size */

            if(c == 'h')
            {
                c = *next++;

                type_size = sizeof (u16);

                if(c == 'h')
                {
                    c = *next++;

                    type_size = sizeof (u8);
                }
            }
            else if(c == 'l')
            {
                c = *next++;

                type_size = sizeof (u32);

                if(c == 'l')
                {
                    c = *next++;

                    type_size = sizeof (u64);
                }
            }
            else if(c == 'L')
            {
                c = *next++;

                type_size = sizeof (long double);
            }

            /* Type */

            switch(c)
            {
                case 't':
                {
                    int val = (int)va_arg(args, int);
                    do_padding(&os, val, '\t');
                    break;
                }
                case 'T':
                {
                    int val = (int)va_arg(args, int);
                    do_padding(&os, val, ' ');
                    break;
                }
                case 'i':
                {
                    s64 val;

                    switch(type_size)
                    {

                        case sizeof (s8):
                        {
                            /*
                             * warning: ‘u8’ is promoted to ‘int’ when passed through ‘...’
                             *	    (so you should pass ‘int’ not ‘u8’ to ‘va_arg’)
                             *	    if this code is reached, the program will abort
                             *
                             * => int
                             */
                            val = (s8)va_arg(args, int);
                            break;
                        }

                        case sizeof (s16):
                        {
                            /*
                             * warning: ‘u16’ is promoted to ‘int’ when passed through ‘...’
                             *	    (so you should pass ‘int’ not ‘u16’ to ‘va_arg’)
                             *	    if this code is reached, the program will abort
                             *
                             * => int
                             */

                            val = (s16)va_arg(args, int);
                            break;
                        }

                        case sizeof (s32):
                        {
                            val = (s32)va_arg(args, s32);
                            break;
                        }

                        case sizeof (s64):
                        {
                            val = va_arg(args, s64);
                            break;
                        }
                        default:
                        {
                            /* Invalid formatting : FULL STOP */

                            flushout();
                            flusherr();

                            fprintf(stderr, "Invalid type size '%i' in string '%s'", type_size, fmt); /* Keep native */
                            fflush(stderr);

                            exit(EXIT_CODE_FORMAT_ERROR);
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
                    u64_formatter_function* formatter;

                    u64 val;

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

                        case sizeof (u8):
                        {
                            /*
                             * warning: ‘u8’ is promoted to ‘int’ when passed through ‘...’
                             *	    (so you should pass ‘int’ not ‘u8’ to ‘va_arg’)
                             *	    if this code is reached, the program will abort
                             *
                             * => int
                             */
                            val = va_arg(args, int);
                            break;
                        }

                        case sizeof (u16):
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

                        case sizeof (u32):
                        {
                            val = va_arg(args, u32);
                            break;
                        }

                        case sizeof (u64):
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

                            exit(EXIT_CODE_FORMAT_ERROR);
                        }
                    }

                    formatter(val, &os, padding, pad_char, left_justified);
                    break;
                }
                case 'P':
                {

                    intptr val = va_arg(args, intptr);

#if HAS_DLADDR_SUPPORT != 0
                    Dl_info info;

                    if(val != 0)
                    {
                        if(dladdr((void*)val, &info) != 0)
                        {
                            if(info.dli_sname != NULL)
                            {
                                format_asciiz(info.dli_sname, &os, padding, pad_char, left_justified);
                                break;
                            }
                            else if(info.dli_fname != NULL)
                            {
                                format_asciiz(info.dli_fname, &os, padding, pad_char, left_justified);
                                val -= (intptr)info.dli_fbase;
                                output_stream_write_u8(&os, (u8)':');
                            }
                        }
                    }
#endif
                    
                    format_hex_u64_hi(val, &os, __SIZEOF_POINTER__ * 2, '0', FALSE);
                    break;
                }
                case 'p':
                {
                    intptr val = va_arg(args, intptr);

                    format_hex_u64_hi(val, &os, __SIZEOF_POINTER__ * 2, '0', FALSE);
                    break;
                }
                case 'f':
                {
                    if(type_size == sizeof (long double))
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
                    const char* val;

                    val = va_arg(args, const char*);

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
                    const char* type_name = next;
                    do
                    {
                        c = *next++;

                        if(c == 0)
                        {
                            flushout();
                            flusherr();

                            fprintf(stderr, "PANIC: Invalid format type in string '%s' : '}' expected.", fmt); /* Keep native */
                            fflush(stderr);
                            exit(EXIT_CODE_FORMAT_ERROR);
                        }
                    }
                    while(c != '}');

                    /* type_name -> next contains the type name and arguments
                     * arguments can be integers
                     */

                    size_t type_name_len = next - 1 - type_name;

                    format_handler_descriptor* desc = format_get_format_handler(type_name, type_name_len);

                    if(desc == NULL)
                    {
                        /* Uses the "dummy" handler */

                        desc = &dummy_format_handler_descriptor;
                    }

                    void* ptr = va_arg(args, void*);
                    desc->format_handler(ptr, &os, padding, pad_char, left_justified, NULL);

                    break;
                }
                
                case 'w':
                {
                    void* ptr = va_arg(args, void*);
                    format_writer *fw = (format_writer*)ptr;
                    fw->callback(fw->value, &os, padding, pad_char, left_justified, NULL);
                    break;
                }
            }

            fmt = next;

            padding = -1;
            float_padding = -1;
            type_size = sizeof (int);
            pad_char = ' ';
            left_justified = TRUE;

            continue;
        }

        next++;

        /* look for the sentinel */
    }
}

ya_result
osprint(output_stream* stream, const char* text)
{
    return output_stream_write(stream, (const u8*)text, strlen(text));
}

ya_result
osprintln(output_stream* stream, const char* text)
{
    ya_result n = strlen(text);
    
    output_stream_write(stream, (const u8*)text, n);
    output_stream_write(stream, STREOL, 1);
    
    return n + 1;
}

ya_result
osformat(output_stream* stream, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    ya_result err = vosformat(stream, fmt, args);
    va_end(args);
    return err;
}

ya_result
osformatln(output_stream* stream, const char* fmt, ...)
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

ya_result
print(const char* text)
{
    return output_stream_write(termout, (const u8*)text, strlen(text));
}

ya_result
println(const char* text)
{
    ya_result n = strlen(text);
    
    output_stream_write(termout, (const u8*)text, n);
    output_stream_write(termout, STREOL, 1);
    
    return n + 1;
}

int
format(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    ya_result err = vosformat(termout, fmt, args);
    va_end(args);
    return err;
}

ya_result
formatln(const char* fmt, ...)
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

int
vsnformat(char* out, size_t out_size, const char* fmt, va_list args)
{
    if(out_size == 0)
    {
        return 0;
    }

    output_stream baos;
    bytearray_output_stream_context baos_context;

    bytearray_output_stream_init_ex_static(&baos, (u8*)out, out_size - 1, 0, &baos_context);

    int ret = vosformat(&baos, fmt, args);

    if(ret < out_size)
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

int
snformat(char* out, size_t out_size, const char* fmt, ...)
{
    int ret;
    va_list args;
    va_start(args, fmt);
    ret = vsnformat(out, out_size, fmt, args);
    va_end(args);

    return ret;
}

int
osprint_base64(output_stream* os, const u8* rdata_pointer, u32 rdata_size)
{
    char buffer[65];
    int total = 0;
    u32 n;

    while(rdata_size > 48)
    {
        n = base64_encode(rdata_pointer, 48, buffer);
        buffer[n++] = ' ';
        output_stream_write(os, (u8*)buffer, n);
        total += n;
        rdata_pointer += 48;
        rdata_size -= 48;
    }

    n = base64_encode(rdata_pointer, rdata_size, buffer);
    output_stream_write(os, (u8*)buffer, n);

    total += n;

    return total;
}

int
osprint_base16(output_stream* os, const u8* rdata_pointer, u32 rdata_size)
{
    char buffer[65];
    int total = 0;
    u32 n;

    while(rdata_size > 32)
    {
        n = base16_encode(rdata_pointer, 32, buffer);
        buffer[n++] = ' ';
        output_stream_write(os, (u8*)buffer, n);
        total += n;
        rdata_pointer += 32;
        rdata_size -= 32;
    }

    n = base16_encode(rdata_pointer, rdata_size, buffer);
    output_stream_write(os, (u8*)buffer, n);

    total += n;

    return total;
}

int
fformat(FILE* out, const char* fmt, ...)
{
    char tmp[4096];

#ifdef DEBUG
    memset(tmp, '!', sizeof (tmp));
#endif

    int ret;
    va_list args;
    va_start(args, fmt);
    ret = vsnformat(tmp, sizeof (tmp), fmt, args);
    fputs(tmp, out);
    va_end(args);

    return ret;
}

/*------------------------------------------------------------------------------
 * FUNCTIONS */

void
osprint_u32(output_stream* os, u32 value)
{
    format_dec_u64(value, os, 9, ' ', FALSE);
}

void
osprint_u16(output_stream* os, u16 value)
{
    format_dec_u64(value, os, 5, ' ', FALSE);
}

void
osprint_u32_hex(output_stream* os, u32 value)
{
    format_hex_u64_common(__hexa__, value, os, 8, '0', FALSE);
}

void
print_char(char value)
{
    char tmp[1];
    tmp[0] = value;
    output_stream_write(&__termout__, (u8*)tmp, 1);
}

void
osprint_char(output_stream* os, char value)
{
    char tmp[1];
    tmp[0] = value;
    output_stream_write(os, (u8*)tmp, 1);
}


ya_result
osprint_type_bitmap(output_stream* os, const u8* rdata_pointer, u16 rdata_size)
{
    /*
     * WindowIndex + WindowSize + bits => a minimum of 3 bytes
     */
    while(rdata_size >= 3)
    {
        u16 type_hi = *rdata_pointer++;
        u8 count = *rdata_pointer++;

        rdata_size -= 2;

        if(rdata_size < count)
        {
            return INCORRECT_RDATA;
        }

        rdata_size -= count;

        /*type_hi <<= 8;*/

        u16 type_lo = 0;

        while(count-- > 0)
        {
            u8 bitmap = *rdata_pointer++;
            u32 b;

            for(b = 8; b > 0; b--)
            {
                if((bitmap & 0x80) != 0)
                {
                    /* Enabled */

                    u16 type = type_hi + type_lo;

                    osformat(os, " %{dnstype}", &type);
                }

                bitmap <<= 1;

                type_lo+=0x100;
            }
        }
    }

    return SUCCESS;
}

ya_result
osprint_rdata(output_stream* os, u16 type, const u8* rdata_pointer, u16 rdata_size)
{
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
            u16* rdata_u16 = (u16*)rdata_pointer;
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
            osformat(os, "%hd ", ntohs(GET_U16_AT(*rdata_pointer)));
            rdata_pointer += 2;
            rdata_size -= 2;
            /* NO BREAK HERE, I WANT TO FALLTROUGH */;
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
                osformat(os, "%{dnsname}", rdata_pointer);
                return SUCCESS;
            }
            return INCORRECT_RDATA;
        }
        case TYPE_HINFO:
        case TYPE_MINFO:
        {
            /* TWO Pascal String records */

            /*
             * <character-string> is a single length octet followed by that number
             * of characters.  <character-string> is treated as binary information,
             * and can be up to 256 characters in length (including the length octet).
             *
             */

            int i;

            for(i = 0; i < 2; i++)
            {
                u32 len = (*rdata_pointer) + 1;

                if(len > rdata_size)
                {
                    return INCORRECT_RDATA;
                }

                osformat(os, "%{dnslabel}", rdata_pointer);

                rdata_size -= len;
                rdata_pointer += len;
            }

            return SUCCESS;
        }
        case TYPE_SOA:
        {
            osformat(os, "%{dnsname} ", rdata_pointer);
            u32 len = dnsname_len(rdata_pointer);

            rdata_size -= len;

            if(rdata_size > 0)
            {
                rdata_pointer += len;
                
                const u8 *label = rdata_pointer;
                u8 label_len = *label;
                
                static u8 dot = (u8)'.';
                static u8 escape = (u8)'\\';

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
                        }
                        while(--label_len > 0);
                        
                        output_stream_write(os, &dot, 1);

                        label_len = *label++;
                    }
                    while(label_len > 0);
                    
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

                    osformat(os, " %u %u %u %u %u",
                             ntohl(GET_U32_AT(rdata_pointer[ 0])),
                             ntohl(GET_U32_AT(rdata_pointer[ 4])),
                             ntohl(GET_U32_AT(rdata_pointer[ 8])),
                             ntohl(GET_U32_AT(rdata_pointer[12])),
                             ntohl(GET_U32_AT(rdata_pointer[16])));

                    return SUCCESS;
                }
            }

            return INCORRECT_RDATA;
        }
        case TYPE_RRSIG:
        {
            struct tm exp;
            struct tm inc;

            time_t t = (time_t)ntohl(GET_U32_AT(rdata_pointer[8]));
            gmtime_r(&t, &exp);
            t = (time_t)ntohl(GET_U32_AT(rdata_pointer[12]));
            gmtime_r(&t, &inc);

            u16 covered_type = (GET_U16_AT(rdata_pointer[0])); /** @note NATIVETYPE */

            osformat(os, "%{dnstype} %u %u %u %04u%02u%02u%02u%02u%02u %04u%02u%02u%02u%02u%02u %u ",
                     &covered_type,
                     U8_AT(rdata_pointer[2]),
                     U8_AT(rdata_pointer[3]),
                     ntohl(GET_U32_AT(rdata_pointer[4])),
                     exp.tm_year + 1900, exp.tm_mon + 1, exp.tm_mday, exp.tm_hour, exp.tm_min, exp.tm_sec,
                     inc.tm_year + 1900, inc.tm_mon + 1, inc.tm_mday, inc.tm_hour, inc.tm_min, inc.tm_sec,
                     ntohs(GET_U16_AT(rdata_pointer[16])));

            rdata_pointer += RRSIG_RDATA_HEADER_LEN;
            rdata_size -= RRSIG_RDATA_HEADER_LEN;

            osformat(os, "%{dnsname} ", rdata_pointer);
            u32 len = dnsname_len(rdata_pointer);

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
        {
            osformat(os, "%u %u %u ",
                     ntohs(GET_U16_AT(rdata_pointer[0])),
                     U8_AT(rdata_pointer[2]),
                     U8_AT(rdata_pointer[3]));

            rdata_pointer += 4;
            rdata_size -= 4;

            osprint_base64(os, rdata_pointer, rdata_size);

            return SUCCESS;
        }
        case TYPE_DS:
        {
            osformat(os, "%u %u %u ",
                     ntohs(GET_U16_AT(rdata_pointer[0])),
                     U8_AT(rdata_pointer[2]),
                     U8_AT(rdata_pointer[3]));

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
            osformat(os, "%{dnsname} ", rdata_pointer);

            u32 len = dnsname_len(rdata_pointer);

            rdata_pointer += len;
            rdata_size -= len;

            ya_result return_code;
            
            if(ISOK(return_code = osprint_type_bitmap(os, rdata_pointer, rdata_size)))
            {
                return SUCCESS;
            }

            return return_code;
        }
        case TYPE_NSEC3:
        case TYPE_NSEC3PARAM:
        {
            osformat(os, "%hhd %hhd %hd ",
                     rdata_pointer[0],
                     (type != TYPE_NSEC3PARAM) ? rdata_pointer[1] : 0,
                     ntohs(GET_U16_AT(rdata_pointer[2])));
            u8 len = rdata_pointer[4];

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
                osprint(os, " ");

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
        case TYPE_SRV:
        {
            u16 priority = GET_U16_AT(rdata_pointer[0]);
            u16 weight = GET_U16_AT(rdata_pointer[2]);
            u16 port = GET_U16_AT(rdata_pointer[4]);
            const u8 *fqdn = (const u8*)&rdata_pointer[6];
            
            return osformat(os, "%hd %hd %hd %{dnsname}", priority, weight, port, fqdn);
        }
        case TYPE_ZONE_TYPE:
        {
            u8 zone_type = rdata_pointer[0];
            
            char *txt;
            
            switch(zone_type)
            {
                case ZT_HINT:
                {
                    txt = "hint";
                    break;
                }
                case ZT_MASTER:
                {
                    txt = "master";
                    break;
                }
                case ZT_SLAVE:
                {
                    txt = "slave";
                    break;
                }
                case ZT_STUB:
                {
                    txt = "stub";
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
        case TYPE_ZONE_MASTER:
        case TYPE_ZONE_SLAVES:
        case TYPE_ZONE_NOTIFY:
        {
            u8 flags = rdata_pointer[0];
            const u8 *src = &rdata_pointer[1];
            
            ya_result total = 0;
            
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

                    inet_ntop(AF_INET6, &src, ip6txt, sizeof(ip6txt));

                    total += osprint(os, ip6txt);
                    
                    src += 16;
                    
                    break;
                }
            }
            
            if((flags & REMOTE_SERVER_FLAGS_PORT_MASK) != 0)
            {
                u16 port = GET_U16_AT(*src);
                
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
        {
            u8 c;

            while(rdata_size > 0)
            {
                c = *rdata_pointer++;

                if(c > 0)
                {
                    c = MIN(c, rdata_size);

                    output_stream_write(os, rdata_pointer, c);
                    output_stream_write(os, (u8*)" ", 1);
                }

                rdata_size--;
                rdata_pointer += c;
                rdata_size -= c;
            }

            return SUCCESS;
        }
        case TYPE_A6:
        case TYPE_ASFDB:
        case TYPE_TSIG:
        case TYPE_IXFR:
        case TYPE_AXFR:
        case TYPE_SIG:
        case TYPE_ANY:
        default:

            osformat(os, "\\# %u ", rdata_size); /* rfc 3597 */
            osprint_base16(os, rdata_pointer, rdata_size);

            return SUCCESS;
    }
    
    return INCORRECT_RDATA;
}

ya_result
print_rdata(u16 type, u8* rdata_pointer, u16 rdata_size)
{
    return osprint_rdata(termout, type, rdata_pointer, rdata_size);
}

void
osprint_dump(output_stream *os, const void* data_pointer_, size_t size_, size_t line_size, u32 flags)
{
    const u8* data_pointer = (const u8*)data_pointer_;
    s32 size = size_;
    
    bool address = (flags & OSPRINT_DUMP_ADDRESS) != 0;
    bool hex = (flags & OSPRINT_DUMP_HEX) != 0;
    bool text = (flags & OSPRINT_DUMP_TEXT) != 0;
    
    int group = flags & OSPRINT_DUMP_LAYOUT_GROUP_MASK;
    group >>= OSPRINT_DUMP_LAYOUT_GROUP_SHIFT;
    int separator = flags & OSPRINT_DUMP_LAYOUT_SEPARATOR_MASK;
    separator >>= OSPRINT_DUMP_LAYOUT_SEPARATOR_SHIFT;

    int dump_size;
    int i;
    
    char hexbyte[2];

    do
    {
        dump_size = MIN(line_size, size);

        const u8* data;

        if(address)
        {
            format_hex_u64_hi((intptr)data_pointer, os, __SIZEOF_POINTER__ * 2, '0', FALSE);
            output_stream_write(os, (const u8*)" | ", 3);
        }

        if(hex)
        {
            data = data_pointer;
            
            for(i = 0; i < dump_size; i++)
            {
                u8 val = *data++;
                
                hexbyte[0] = __hexa__[val >> 4];
                hexbyte[1] = __hexa__[val & 0x0f];
                
                output_stream_write(os, (u8*)hexbyte, 2);
                
                if((i & group) == group)
                {
                    output_stream_write_u8(os, (u8)' ');
                }
                if((i & separator) == separator)
                {
                    output_stream_write_u8(os, (u8)' ');
                }
            }

            for(; i < line_size; i++)
            {
                output_stream_write(os, (const u8*)"  ", 2);                             // these are two spaces
                if((i & group) == group)
                {
                    output_stream_write_u8(os, (u8)' ');
                }
                if((i & separator) == separator)
                {
                    output_stream_write_u8(os, (u8)' ');
                }
            }
        }

        if(text)
        {
            if(hex)
            {
                output_stream_write(os, (const u8*)" |  ", 4);
            }
            
            data = data_pointer;
            
            for(i = 0; i < dump_size; i++)
            {
                char c = *data++;
                
                if(c < ' ')
                {
                    c = '.';
                }

                output_stream_write_u8(os, (u8)c);
            }
        }

        data_pointer += dump_size;
        size -= dump_size;

        if(size != 0)
        {
            output_stream_write_u8(os, (u8)'\n');
        }
    }
    while(size > 0);
}

void
osprint_question(output_stream* os, u8* qname, u16 qclass, u16 qtype)
{
    osformat(os, ";; QUESTION SECTION:\n%{dnsname} %{dnsclass} %{dnstype}\n\n", qname, &qclass, &qtype);
}

void
print_question(u8* qname, u16 qclass, u16 qtype)
{
    osprint_question(termout, qname, qclass, qtype);
}

/** @} */

/*----------------------------------------------------------------------------*/

