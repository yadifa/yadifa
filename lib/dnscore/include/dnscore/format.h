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
* DOCUMENTATION */
/** @defgroup format C-string formatting
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _FORMAT_H
#define	_FORMAT_H

#include <stdio.h>
#include <stdarg.h>

#include <dnscore/sys_types.h>
#include <dnscore/output_stream.h>
#include <dnscore/dnscore.h>

#ifdef	__cplusplus
extern "C" {
#endif

/**
 *
 * Format extention mechanism:
 *
 */

/* void* value, output_stream*, s32 padding, char pad_char, bool left_justified */
typedef void format_handler_method(void*, output_stream*, s32, char, bool, void* reserved_for_method_parameters);

typedef struct format_handler_descriptor format_handler_descriptor;


struct format_handler_descriptor
{
    const char* name;
    int name_len;	    /* Needed in order to quicken the matching */
    format_handler_method* format_handler;
};

void format_class_init();

ya_result format_registerclass(format_handler_descriptor* fhd);

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

int vsnformat(char* out_, size_t out_size, const char* fmt, va_list args);
int snformat(char* out, size_t out_size, const char* fmt, ...);

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

void osprint_char(output_stream* os, char value);

void print_payload(output_stream* os, const u_char *, int);

void osprint_u32(output_stream* os, u32 value);
void osprint_u16(output_stream* os, u16 value);
void osprint_u32_hex(output_stream* os, u32 value);


ya_result osprint_type_bitmap(output_stream* os, const u8* rdata_pointer, u16 rdata_size);
ya_result osprint_rdata(output_stream* os, u16 type, const u8* rdata_pointer, u16 rdata_size);
ya_result print_rdata(u16 type, u8* rdata, u16 rdata_size);
void osprint_question(output_stream* os, u8* qname, u16 qclass, u16 qtype);
void print_question(u8* qname, u16 qclass, u16 qtype);

#if defined(DEBUG_VALID_ADDRESS)
#define FORMAT_BREAK_ON_INVALID(address__, len__) if(!debug_is_valid_address(address__, len__)){ output_stream_write(stream, (const u8*)"INVALID_ADDRESS", 15);return;}
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


#ifdef	__cplusplus
}
#endif

#endif	/* _FORMAT_H */
/** @} */

/*----------------------------------------------------------------------------*/

