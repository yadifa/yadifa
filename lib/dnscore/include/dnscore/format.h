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

/** @defgroup format C-string formatting
 *  @ingroup dnscore
 *  @brief 
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#pragma once

#include <stdio.h>
#include <stdarg.h>

#include <dnscore/sys_types.h>
#include <dnscore/output_stream.h>
#include <dnscore/dnscore.h>

#define OSPRINT_DUMP_LAYOUT_GROUP_MASK      0x0000ff00U
#define OSPRINT_DUMP_LAYOUT_GROUP_SHIFT     8U
#define OSPRINT_DUMP_LAYOUT_SEPARATOR_MASK  0x000000ffU
#define OSPRINT_DUMP_LAYOUT_SEPARATOR_SHIFT 0U
#define OSPRINT_DUMP_ADDRESS                0x40000000U
#define OSPRINT_DUMP_HEX                    0x20000000U
#define OSPRINT_DUMP_TEXT                   0x10000000U
    
// predefined layouts
#define OSPRINT_DUMP_LAYOUT_DENSE           0x0000ffffU
#define OSPRINT_DUMP_LAYOUT_ERIC            0x000003ffU
#define OSPRINT_DUMP_LAYOUT_GERY            0x00000003U
    
#define OSPRINT_DUMP_ALL                    (OSPRINT_DUMP_ADDRESS|OSPRINT_DUMP_HEX|OSPRINT_DUMP_TEXT)
#define OSPRINT_DUMP_HEXTEXT                (OSPRINT_DUMP_HEX|OSPRINT_DUMP_TEXT)
#define OSPRINT_DUMP_BASE16                 (OSPRINT_DUMP_LAYOUT_DENSE|OSPRINT_DUMP_HEX)

/**
 *
 * Formats:
 * 
 *   modifier   : restrict :
 *              :    to    :
 * -            :          : change justification
 * 123456789    :          : padding space
 * 0            :          : use '0' char for padding
 * .12345789    : f        : for float types, precision to use
 * hh           : iudXxo   : half half : 8 bits
 * h            : iudXxo   : half : 16 bits
 * l            : iudXxo   : long : 32 bits
 * ll           : iudXxo   : long long : 64 bits
 * L            : f        : long double
 * 
 *    formats   :
 *              :
 * %t           : integer, prints the number of tabs on the output
 * %S           : integer, prints the number of spaces on the output
 * %T           : integer, prints the 32/64 bits UTC time on the output
 *                %T   : 32 bits = YYYY-MM-DD HH:mm:SS
 *                %lT  : 64 bits = YYYY-MM-DD HH:mm:SS
 *                %llT : 64 bits = YYYY-MM-DD HH:mm:SS.NNNNNN
 * %i           : integer, prints the signed 8/16/32/64 bits integer in base 10 on the output
 * %r           : integer, prints the ya_result registered message on the output or the hexadecimal code
 * %u           : integer, prints the unsigned 8/16/32/64 bits integer in base 10 on the output
 * %d           : integer, prints the unsigned 8/16/32/64 bits integer in base 10 on the output
 * %X           : integer, prints the unsigned 8/16/32/64 bits integer in base 16 uppercase on the output
 * %x           : integer, prints the unsigned 8/16/32/64 bits integer in base 16 lowercase on the output
 * %o           : integer, prints the unsigned 8/16/32/64 bits integer in base 8 on the output
 * %p           : void*  , prints the pointer in hexadecimal on the output
 * %P           : void*  , prints the name of the pointer if possible, else the hexadecimal on the output
 * %f           : double , prints the long double/double/float on the output
 * %s           : char*  , prints the ASCIIZ string on the output
 * %c           : char   , prints the 8-bits char on the output
 * %w           : format_writer, calls the format_writer callback to print on the output
 * 
 * Format extension mechanism:
 * 
 * "%{registeredformatname}" : void*, prints the pointed value on the output
 *                           : use ya_result format_registerclass(format_handler_descriptor* fhd) for registration
 */

/* void* value, output_stream*, s32 padding, char pad_char, bool left_justified, void* reserved */
    
typedef void format_handler_method(const void*, output_stream*, s32, char, bool, void* reserved_for_method_parameters);

typedef struct format_handler_descriptor format_handler_descriptor;

// About the %w format:
// 
// a pointer to this can be given as a 'w' parameter ie: "%w"
// the writer callback get's called with
// void* value as first parameter, what to print
// output_stream *os as second parameter, where to write the chars to
// s32 padding the number of chars it's supposed to take on the output (minimum)
// char padchar the character to use for padding
// bool left_justified where to justify the text
// void* don't use that one
//
// ex:
//
// format_writer temp_fw_0 = {my_complex_or_rare_type_printer_callback, &my_complex_or_rare_type};
//
// format("So the value is : '%w'\n", &temp_fw_0);
//

struct format_writer
{
    format_handler_method *callback;
    const void * value;
};

typedef struct format_writer format_writer;

struct format_handler_descriptor
{
    const char* name;
    int name_len;	    /* Needed in order to quicken the matching */
    format_handler_method* format_handler;
};

void format_class_init();

ya_result format_registerclass(const format_handler_descriptor* fhd);

/**
 * %% -> %
 * %-09lli right-justified 0-padded "long long integer" (s64)
 * %-9llu right-justified "long long unsigned integer" (u64)
 * %-20{class} right-justified "class" (class has to be registered)
 * %-20{class(a,b,c,d)} right-justified "class" called with 4 arguments (class has to be registered)
 *
 * %[-][0| ]([hh|h|l|ll]u|i|x)|([L]f)|c|s|{}
 *
 * ---
 *
 * hh  8 bits
 * h  16 bits
 * l  32 bits (The default if no length is given is 32 bits)
 * ll 64 bits
 *
 * i signed integer
 * u unsigned integer
 * d unsigned integer
 * x hexadecimal lo
 * X hexadecimal hi
 * b binary (not in yet)
 *
 * ---
 *
 * L long
 *
 * f double
 *
 * ---
 *
 * c char
 *
 * ---
 *
 * s asciiz string
 *
 * ---
 *
 * {class name} pointer to something that will be interpreted by the handler
 *
 */

ya_result vosformat(output_stream* os_, const char* fmt, va_list args);
ya_result osprint(output_stream* stream,const char* text);
ya_result osprintln(output_stream* stream,const char* text);
ya_result osformat(output_stream* stream,const char* fmt,...);
ya_result osformatln(output_stream* stream,const char* fmt,...);
ya_result print(const char* text);
ya_result println(const char* text);
ya_result format(const char* fmt,...);
ya_result formatln(const char* fmt,...);

// prefixes time | pid | pthread_self
ya_result debug_osformatln(output_stream* stream, const char* fmt, ...);
ya_result debug_println(const char* text);

int vsnformat(char* out_, size_t out_size, const char* fmt, va_list args);
int snformat(char* out, size_t out_size, const char* fmt, ...);

/**
 * This formatter will return an allocated (malloc) string as a result of the format
 * 
 * @param outp
 * @param out_size
 * @param fmt
 * @param args
 * @return 
 */

int vasnformat(char** outp, size_t out_size, const char* fmt, va_list args);

/**
 * This formatter will return an allocated (malloc) string as a result of the format
 * 
 * @param outp
 * @param out_size
 * @param fmt
 * @param ...
 * @return 
 */

int asnformat(char** outp, size_t out_size, const char* fmt, ...);

/**
 * This formatter will return an allocated (malloc) string as a result of the format
 * 
 * @param outp
 * @param fmt
 * @param ...
 * @return 
 */

int asformat(char** outp, const char* fmt, ...);

/* Used by extensions */

void format_dec_u64(u64 val, output_stream* stream, s32 padding, char pad_char, bool left_justified);
void format_dec_s64(s64 val, output_stream* stream, s32 padding, char pad_char, bool left_justified);
void format_hex_u64_lo(u64 val, output_stream* stream, s32 padding, char pad_char, bool left_justified);
void format_hex_u64_hi(u64 val, output_stream* stream, s32 padding, char pad_char, bool left_justified);
void format_oct_u64(u64 val, output_stream* stream, s32 padding, char pad_char, bool left_justified);
void format_asciiz(const char* val, output_stream* stream, s32 padding, char pad_char, bool left_justified);

/**/

int osprint_base16(output_stream* os, const u8* rdata, u32 rdata_size);
int osprint_base64(output_stream* os, const u8* rdata, u32 rdata_size);

void osprint_u32(output_stream* os, u32 value);
void osprint_u16(output_stream* os, u16 value);
void osprint_u32_hex(output_stream* os, u32 value);

void print_char(char value);

void osprint_char(output_stream *os, char value);
void osprint_char_times(output_stream *os, char value, int times);
void osprint_dump(output_stream *os, const void* data_pointer_, size_t size_, size_t line_size, u32 flags);

ya_result osprint_type_bitmap(output_stream *os, const u8 *rdata_pointer, u16 rdata_size);
ya_result osprint_rdata(output_stream *os, u16 type, const u8 *rdata_pointer, u16 rdata_size);
ya_result osprint_rdata_escaped(output_stream *os, u16 type, const u8 *rdata_pointer, u16 rdata_size);
ya_result print_rdata(u16 type, u8 *rdata, u16 rdata_size);

void osprint_question(output_stream *os, u8 *qname, u16 qclass, u16 qtype);
void print_question(u8 *qname, u16 qclass, u16 qtype);

#if 0 /* fix */
#else
#define FORMAT_BREAK_ON_INVALID(address__, len__)
#endif

/*
 * This is just a tool function used to test vsnformat.
 * It is not meant for the logger.
 * It has an output length limitation of 4096 bytes.
 *
 * Please use the other functions if possible.
 */

int fformat(FILE *out, const char *fmt, ...);

/**
 * This tool struct is used so the RDATA part of a record can be printed/formatted
 *
 * we would have:
 *
 * rdata_desc myrdata={TYPE_SOA, rdata_len, rdata};
 * format("bla bla bla %{rdatadesc}", &myrdata);
 *
 *
 */

struct rdata_desc_s
{
    u16         type;
    u16         len;
    const u8 *  rdata;
};

typedef struct rdata_desc_s rdata_desc;

