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
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _TIMEFORMAT_H
#define	_TIMEFORMAT_H

/*
 * Format extensions related to dns
 *
 * dnsname  : u8* dns name
 * dnslabel : u8* dns label (pascal string)
 * class    : u16* zone class
 * type     : u16* record type
 */

#include <dnscore/output_stream.h>
#ifdef	__cplusplus
extern "C" {
#endif

/**
 * writers of formats
 * 
 * 
 */

// dtus 0000-00-00 00:00:00.000000U
void datetimeus_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters);
// 0000-00-00 00:00:00.000000 
void localdatetimeus_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters);
// dtms 0000-00-00 00:00:00.000
void datetimems_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters);
// dts 0000-00-00 00:00:00
void datetime_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters);
// ldts 0000-00-00 00:00:00
void localdatetime_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters);
// date 0000-00-00
void date_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters);
// time 00:00:00
void time_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters);
// epoch 0000-00-00 00:00:00U
void epoch_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters);
// epoch 0000-00-00 00:00:00
void localepoch_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters);
// epoch 0000-00-00 00:00:00 or ""
void epochz_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters);
// epoch 00000000000000
void packedepoch_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters);

/**
 * Macros for use with the %w format
 * 
 */

#define DATETIMEUS_DEF2(variable,realvariable) format_writer variable##_format_writer = {datetimeus_format_handler_method, (void*)(intptr)realvariable}
#define DATETIMEUS_DEF(variable) format_writer variable##_format_writer = {datetimeus_format_handler_method, (void*)(intptr)variable}
#define DATETIMEUS_REF(variable) &variable##_format_writer

#define DATETIMEMS_DEF2(variable,realvariable) format_writer variable##_format_writer = {datetimems_format_handler_method, (void*)(intptr)realvariable}
#define DATETIMEMS_DEF(variable) format_writer variable##_format_writer = {datetimems_format_handler_method, (void*)(intptr)variable}
#define DATETIMEMS_REF(variable) &variable##_format_writer

#define DATETIME_DEF2(variable,realvariable) format_writer variable##_format_writer = {datetime_format_handler_method, (void*)(intptr)realvariable}
#define DATETIME_DEF(variable) format_writer variable##_format_writer = {datetime_format_handler_method, (void*)(intptr)variable}
#define DATETIME_REF(variable) &variable##_format_writer

#define DATE_DEF2(variable,realvariable) format_writer variable##_format_writer = {date_format_handler_method, (void*)(intptr)realvariable}
#define DATE_DEF(variable) format_writer variable##_format_writer = {date_format_handler_method, (void*)(intptr)variable}
#define DATE_REF(variable) &variable##_format_writer

#define TIME_DEF2(variable,realvariable) format_writer variable##_format_writer = {time_format_handler_method, (void*)(intptr)realvariable}
#define TIME_DEF(variable) format_writer variable##_format_writer = {time_format_handler_method, (void*)(intptr)variable}
#define TIME_REF(variable) &variable##_format_writer

#define EPOCH_DEF2(variable,realvariable) format_writer variable##_format_writer = {epoch_format_handler_method, (void*)(intptr)realvariable}
#define EPOCH_DEF(variable) format_writer variable##_format_writer = {epoch_format_handler_method, (void*)(intptr)variable}
#define EPOCH_REF(variable) &variable##_format_writer

#define EPOCHZ_DEF2(variable,realvariable) format_writer variable##_format_writer = {epochz_format_handler_method, (void*)(intptr)realvariable}
#define EPOCHZ_DEF(variable) format_writer variable##_format_writer = {epochz_format_handler_method, (void*)(intptr)variable}
#define EPOCHZ_REF(variable) &variable##_format_writer

void timeformat_class_init();

#ifdef	__cplusplus
}
#endif

#endif	/* _DNSFORMAT_H */
/** @} */

/*----------------------------------------------------------------------------*/

