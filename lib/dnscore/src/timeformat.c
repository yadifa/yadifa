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
#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>	/* Required for BSD */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

//#include "dnscore/dnscore-config.h"
#include "dnscore/rfc.h"
#include "dnscore/ctrl-rfc.h"
#include "dnscore/format.h"
#include "dnscore/dnsname.h"
#include "dnscore/base32hex.h"
#include "dnscore/dnsformat.h"
#include "dnscore/host_address.h"

#define NULL_STRING_SUBSTITUTE (u8*)"(NULL)"
#define NULL_STRING_SUBSTITUTE_LEN 6 /*(sizeof(NULL_STRING_SUBSTITUTE)-1)*/
#define PORT_SEPARATOR '#'
#define PORT_SEPARATOR_V4 PORT_SEPARATOR
#define PORT_SEPARATOR_V6 PORT_SEPARATOR

static const char dateseparator[1] = {'-'};
static const char timeseparator[1] = {':'};
static const char fracseparator[1] = {'.'};
static const char datetimeseparator[1] = {' '};
static const char utcsuffix[1] = {'Z'};

/** 
 *  dtus
 *
 *  @note 64 bits epoch written up to the us
 */

void
datetimeus_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    u64 epoch_us = (u64)(intptr)val;
    time_t epoch = (time_t)(epoch_us / 1000000);
    u32 us = (u32)(epoch_us % 1000000);
    
    struct tm t;    
    gmtime_r(&epoch, &t);
    
    format_dec_u64(t.tm_year + 1900, stream, 4, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1    , stream, 2, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday       , stream, 2, '0', FALSE);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour       , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min        , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec        , stream, 2, '0', FALSE);
    output_stream_write(stream, fracseparator, 1);
    format_dec_u64(us              , stream, 6, '0', FALSE);
    output_stream_write(stream, utcsuffix, 1);
}

void
localdatetimeus_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    u64 epoch_us = (u64)(intptr)val;
    time_t epoch = (time_t)(epoch_us / 1000000);
    u32 us = (u32)(epoch_us % 1000000);
    
    struct tm t;    
    localtime_r(&epoch, &t);
    
    format_dec_u64(t.tm_year + 1900, stream, 4, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1    , stream, 2, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday       , stream, 2, '0', FALSE);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour       , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min        , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec        , stream, 2, '0', FALSE);
    output_stream_write(stream, fracseparator, 1);
    format_dec_u64(us              , stream, 6, '0', FALSE);
}

static format_handler_descriptor datetimeus_format_handler_descriptor =
{
    "dtus",
    4,
    datetimeus_format_handler_method
};

/** 
 *  dtms
 *
 *  @note 64 bits epoch written up to the ms
 */

void
datetimems_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    u64 epoch_us = (u64)(intptr)val;
    time_t epoch = (time_t)(epoch_us / 1000000);
    u32 ms = (u32)(epoch_us % 1000000);
    ms /= 1000;
    
    struct tm t;
    
    gmtime_r(&epoch, &t);
    
    format_dec_u64(t.tm_year + 1900, stream, 4, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1    , stream, 2, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday       , stream, 2, '0', FALSE);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour       , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min        , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec        , stream, 2, '0', FALSE);
    output_stream_write(stream, fracseparator, 1);
    format_dec_u64(ms              , stream, 3, '0', FALSE);
}

static format_handler_descriptor datetimems_format_handler_descriptor =
{
    "dtms",
    4,
    datetimems_format_handler_method
};

/** 
 *  dts
 *
 *  @note 64 bits epoch written up to the s
 */

void
datetime_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    u64 epoch_us = (u64)(intptr)val;
    time_t epoch = (time_t)(epoch_us / 1000000);
    
    struct tm t;
    
    gmtime_r(&epoch, &t);
    
    format_dec_u64(t.tm_year + 1900, stream, 4, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1    , stream, 2, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday       , stream, 2, '0', FALSE);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour       , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min        , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec        , stream, 2, '0', FALSE);
}

static format_handler_descriptor datetime_format_handler_descriptor =
{
    "dts",
    3,
    datetime_format_handler_method
};

/**
 *  dts
 *
 *  @note 64 bits epoch written up to the s
 */

void
localdatetime_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    u64 epoch_us = (u64)(intptr)val;
    time_t epoch = (time_t)(epoch_us / 1000000);

    struct tm t;

    gmtime_r(&epoch, &t);

    format_dec_u64(t.tm_year + 1900, stream, 4, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1    , stream, 2, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday       , stream, 2, '0', FALSE);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour       , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min        , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec        , stream, 2, '0', FALSE);
}

static format_handler_descriptor localdatetime_format_handler_descriptor =
{
    "ldts",
    4,
    localdatetime_format_handler_method
};

/** 
 *  date
 *
 *  @note 64 bits epoch written up to the day
 */

void
date_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    u64 epoch_us = (u64)(intptr)val;
    time_t epoch = (time_t)(epoch_us / 1000000);
    
    struct tm t;
    
    gmtime_r(&epoch, &t);
    
    format_dec_u64(t.tm_year + 1900, stream, 4, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1    , stream, 2, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday       , stream, 2, '0', FALSE);
}

static format_handler_descriptor date_format_handler_descriptor =
{
    "date",
    4,
    date_format_handler_method
};

/** 
 *  time
 *
 *  @note 64 bits with only HH:MM:SS
 */

void
time_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    u64 epoch_us = (u64)(intptr)val;
    time_t epoch = (time_t)(epoch_us / 1000000);
    
    struct tm t;
    
    gmtime_r(&epoch, &t);
    
    format_dec_u64(t.tm_hour       , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min        , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec        , stream, 2, '0', FALSE);
}

static format_handler_descriptor time_format_handler_descriptor =
{
    "time",
    4,
    time_format_handler_method
};

/** 
 *  epoch
 *
 *  @note 32 bits epoch written up to the s
 */

void
epoch_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    time_t epoch = (time_t)(intptr)val;
    struct tm t;
    gmtime_r(&epoch, &t);
    
    format_dec_u64(t.tm_year + 1900, stream, 4, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1    , stream, 2, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday       , stream, 2, '0', FALSE);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour       , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min        , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec        , stream, 2, '0', FALSE);
    output_stream_write(stream, utcsuffix, 1);
}

void
localepoch_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    time_t epoch = (time_t)(intptr)val;
    struct tm t;
    localtime_r(&epoch, &t);
    
    format_dec_u64(t.tm_year + 1900, stream, 4, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1    , stream, 2, '0', FALSE);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday       , stream, 2, '0', FALSE);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour       , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min        , stream, 2, '0', FALSE);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec        , stream, 2, '0', FALSE);
}

static format_handler_descriptor epoch_format_handler_descriptor =
{
    "epoch",
    5,
    epoch_format_handler_method
};

/** 
 *  epoch where value 0 prints nothing
 *
 *  @note 32 bits epoch written up to the s
 */

void
epochz_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    time_t epoch = (time_t)(intptr)val;
    
    if(epoch != 0)
    {
        struct tm t;

        gmtime_r(&epoch, &t);

        format_dec_u64(t.tm_year + 1900, stream, 4, '0', FALSE);
        output_stream_write(stream, dateseparator, 1);
        format_dec_u64(t.tm_mon + 1    , stream, 2, '0', FALSE);
        output_stream_write(stream, dateseparator, 1);
        format_dec_u64(t.tm_mday       , stream, 2, '0', FALSE);
        output_stream_write(stream, datetimeseparator, 1);
        format_dec_u64(t.tm_hour       , stream, 2, '0', FALSE);
        output_stream_write(stream, timeseparator, 1);
        format_dec_u64(t.tm_min        , stream, 2, '0', FALSE);
        output_stream_write(stream, timeseparator, 1);
        format_dec_u64(t.tm_sec        , stream, 2, '0', FALSE);
    }
    else
    {
        while(padding > 0)
        {
            output_stream_write(stream, "-", 1);
            --padding;
        }
    }
}

static format_handler_descriptor epochz_format_handler_descriptor =
{
    "epochz",
    6,
    epochz_format_handler_method
};

/** 
 *  epoch
 *
 *  @note 32 bits epoch written up to the s
 */

void
packedepoch_format_handler_method(const void *restrict val, output_stream *stream, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    time_t epoch = (time_t)(intptr)val;
    struct tm t;
    
    gmtime_r(&epoch, &t);
    
    format_dec_u64(t.tm_year + 1900, stream, 4, '0', FALSE);
    format_dec_u64(t.tm_mon + 1    , stream, 2, '0', FALSE);
    format_dec_u64(t.tm_mday       , stream, 2, '0', FALSE);
    format_dec_u64(t.tm_hour       , stream, 2, '0', FALSE);
    format_dec_u64(t.tm_min        , stream, 2, '0', FALSE);
    format_dec_u64(t.tm_sec        , stream, 2, '0', FALSE);
    // DO NOT ADD A SUFFIX HERE
}

static format_handler_descriptor packedepoch_format_handler_descriptor =
{
    "packedepoch",
    11,
    packedepoch_format_handler_method
};

static bool timeformat_class_init_done = FALSE;

void
timeformat_class_init()
{
    if(timeformat_class_init_done)
    {
        return;
    }

    timeformat_class_init_done = TRUE;

    format_class_init();

    // 64 bits
    
    format_registerclass(&datetimeus_format_handler_descriptor);
    format_registerclass(&datetimems_format_handler_descriptor);
    format_registerclass(&datetime_format_handler_descriptor);
    format_registerclass(&date_format_handler_descriptor);
    format_registerclass(&time_format_handler_descriptor);
    format_registerclass(&localdatetime_format_handler_descriptor);

    // 32 bits
    
    format_registerclass(&epoch_format_handler_descriptor);
    format_registerclass(&epochz_format_handler_descriptor);
    format_registerclass(&packedepoch_format_handler_descriptor);
}

/** @} */
