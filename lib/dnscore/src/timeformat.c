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
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h> /* Required for BSD */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "dnscore/rfc.h"
#include "dnscore/ctrl_rfc.h"
#include "dnscore/format.h"
#include "dnscore/dnsname.h"
#include "dnscore/base32hex.h"
#include "dnscore/dnsformat.h"
#include "dnscore/host_address.h"
#include "dnscore/mutex.h"

#define NULL_STRING_SUBSTITUTE     (uint8_t *)"(NULL)"
#define NULL_STRING_SUBSTITUTE_LEN 6 /*(sizeof(NULL_STRING_SUBSTITUTE)-1)*/
#define PORT_SEPARATOR             '#'
#define PORT_SEPARATOR_V4          PORT_SEPARATOR
#define PORT_SEPARATOR_V6          PORT_SEPARATOR

static const char dateseparator[1] = {'-'};
static const char timeseparator[1] = {':'};
static const char fracseparator[1] = {'.'};
static const char datetimeseparator[1] = {' '};
static const char tseparator[1] = {'T'};
static const char utcsuffix[1] = {'Z'};
static const char zeromssuffix[4] = {'.', '0', '0', '0'};

/**
 *  dtus
 *
 *  @note 64 bits epoch written up to the us
 */

void datetimeus_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    uint64_t  epoch_us = (uint64_t)(intptr_t)val;
    time_t    epoch = (time_t)(epoch_us / 1000000);
    uint32_t  us = (uint32_t)(epoch_us % 1000000);

    struct tm t;
    gmtime_r(&epoch, &t);

    format_dec_u64(t.tm_year + 1900, stream, 4, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1, stream, 2, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday, stream, 2, '0', false);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec, stream, 2, '0', false);
    output_stream_write(stream, fracseparator, 1);
    format_dec_u64(us, stream, 6, '0', false);
    output_stream_write(stream, utcsuffix, 1);
}

static format_handler_descriptor_t datetimeus_format_handler_descriptor = {"dtus", 4, datetimeus_format_handler_method};

/**
 *  dtus
 *
 *  @note 64 bits epoch written up to the us
 */

void datetimeustms_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    uint64_t  epoch_us = (uint64_t)(intptr_t)val;
    time_t    epoch = (time_t)(epoch_us / 1000000);
    uint32_t  ms = (uint32_t)(epoch_us % 1000000) / 1000;

    struct tm t;
    gmtime_r(&epoch, &t);

    format_dec_u64(t.tm_year + 1900, stream, 4, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1, stream, 2, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday, stream, 2, '0', false);
    output_stream_write(stream, tseparator, 1);
    format_dec_u64(t.tm_hour, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec, stream, 2, '0', false);
    output_stream_write(stream, fracseparator, 1);
    format_dec_u64(ms, stream, 3, '0', false);
    output_stream_write(stream, utcsuffix, 1);
}

static format_handler_descriptor_t datetimeustms_format_handler_descriptor = {"dtustms", 7, datetimeustms_format_handler_method};

void                               localdatetimeus_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    uint64_t  epoch_us = (uint64_t)(intptr_t)val;
    time_t    epoch = (time_t)(epoch_us / 1000000);
    uint32_t  us = (uint32_t)(epoch_us % 1000000);

    struct tm t;
    localtime_r(&epoch, &t);

    format_dec_u64(t.tm_year + 1900, stream, 4, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1, stream, 2, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday, stream, 2, '0', false);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec, stream, 2, '0', false);
    output_stream_write(stream, fracseparator, 1);
    format_dec_u64(us, stream, 6, '0', false);
}

static format_handler_descriptor_t localdatetimeus_format_handler_descriptor = {"ldtus", 5, localdatetimeus_format_handler_method};

/**
 *  dtms
 *
 *  @note 64 bits epoch written up to the ms
 */

void datetimems_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    uint64_t epoch_us = (uint64_t)(intptr_t)val;
    time_t   epoch = (time_t)(epoch_us / 1000000);
    uint32_t ms = (uint32_t)(epoch_us % 1000000);
    ms /= 1000;

    struct tm t;

    gmtime_r(&epoch, &t);

    format_dec_u64(t.tm_year + 1900, stream, 4, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1, stream, 2, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday, stream, 2, '0', false);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec, stream, 2, '0', false);
    output_stream_write(stream, fracseparator, 1);
    format_dec_u64(ms, stream, 3, '0', false);
}

static format_handler_descriptor_t datetimems_format_handler_descriptor = {"dtms", 4, datetimems_format_handler_method};

/**
 *  dts
 *
 *  @note 64 bits epoch written up to the s
 */

void datetime_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    uint64_t  epoch_us = (uint64_t)(intptr_t)val;
    time_t    epoch = (time_t)(epoch_us / 1000000LL);

    struct tm t;

    gmtime_r(&epoch, &t);

    format_dec_u64(t.tm_year + 1900, stream, 4, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1, stream, 2, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday, stream, 2, '0', false);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec, stream, 2, '0', false);
}

static format_handler_descriptor_t datetime_format_handler_descriptor = {"dts", 3, datetime_format_handler_method};

/**
 *  dts
 *
 *  @note 64 bits epoch written up to the s
 */

void localdatetime_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    uint64_t  epoch_us = (uint64_t)(intptr_t)val;
    time_t    epoch = (time_t)(epoch_us / 1000000);

    struct tm t;

    localtime_r(&epoch, &t);

    format_dec_u64(t.tm_year + 1900, stream, 4, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1, stream, 2, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday, stream, 2, '0', false);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec, stream, 2, '0', false);
}

static format_handler_descriptor_t localdatetime_format_handler_descriptor = {"ldts", 4, localdatetime_format_handler_method};

/**
 *  date
 *
 *  @note 64 bits epoch written up to the day
 */

void date_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    uint64_t  epoch_us = (uint64_t)(intptr_t)val;
    time_t    epoch = (time_t)(epoch_us / 1000000);

    struct tm t;

    gmtime_r(&epoch, &t);

    format_dec_u64(t.tm_year + 1900, stream, 4, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1, stream, 2, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday, stream, 2, '0', false);
}

static format_handler_descriptor_t date_format_handler_descriptor = {"date", 4, date_format_handler_method};

/**
 *  time
 *
 *  @note 64 bits with only HH:MM:SS
 */

void time_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    uint64_t  epoch_us = (uint64_t)(intptr_t)val;
    time_t    epoch = (time_t)(epoch_us / 1000000);

    struct tm t;

    gmtime_r(&epoch, &t);

    format_dec_u64(t.tm_hour, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec, stream, 2, '0', false);
}

static format_handler_descriptor_t time_format_handler_descriptor = {"time", 4, time_format_handler_method};

/**
 *  epoch
 *
 *  @note 32 bits epoch written up to the s
 */

void epoch_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    time_t    epoch = (time_t)(intptr_t)val;
    struct tm t;
    gmtime_r(&epoch, &t);

    format_dec_u64(t.tm_year + 1900, stream, 4, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1, stream, 2, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday, stream, 2, '0', false);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec, stream, 2, '0', false);
    output_stream_write(stream, utcsuffix, 1);
}

static format_handler_descriptor_t epoch_format_handler_descriptor = {"epoch", 5, epoch_format_handler_method};

void                               epochtms_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    time_t    epoch = (time_t)(intptr_t)val;
    struct tm t;
    gmtime_r(&epoch, &t);

    format_dec_u64(t.tm_year + 1900, stream, 4, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1, stream, 2, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday, stream, 2, '0', false);
    output_stream_write(stream, tseparator, 1);
    format_dec_u64(t.tm_hour, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec, stream, 2, '0', false);
    output_stream_write(stream, zeromssuffix, sizeof(zeromssuffix));
    output_stream_write(stream, utcsuffix, 1);
}

static format_handler_descriptor_t epochtms_format_handler_descriptor = {"epochtms", 8, epochtms_format_handler_method};

void                               localepoch_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    time_t    epoch = (time_t)(intptr_t)val;
    struct tm t;
    localtime_r(&epoch, &t);

    format_dec_u64(t.tm_year + 1900, stream, 4, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mon + 1, stream, 2, '0', false);
    output_stream_write(stream, dateseparator, 1);
    format_dec_u64(t.tm_mday, stream, 2, '0', false);
    output_stream_write(stream, datetimeseparator, 1);
    format_dec_u64(t.tm_hour, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_min, stream, 2, '0', false);
    output_stream_write(stream, timeseparator, 1);
    format_dec_u64(t.tm_sec, stream, 2, '0', false);
}

static format_handler_descriptor_t localepoch_format_handler_descriptor = {"lepoch", 6, localepoch_format_handler_method};

/**
 *  epoch where value 0 prints nothing
 *
 *  @note 32 bits epoch written up to the s
 */

void epochz_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    time_t epoch = (time_t)(intptr_t)val;

    if(epoch != 0)
    {
        struct tm t;

        gmtime_r(&epoch, &t);

        format_dec_u64(t.tm_year + 1900, stream, 4, '0', false);
        output_stream_write(stream, dateseparator, 1);
        format_dec_u64(t.tm_mon + 1, stream, 2, '0', false);
        output_stream_write(stream, dateseparator, 1);
        format_dec_u64(t.tm_mday, stream, 2, '0', false);
        output_stream_write(stream, datetimeseparator, 1);
        format_dec_u64(t.tm_hour, stream, 2, '0', false);
        output_stream_write(stream, timeseparator, 1);
        format_dec_u64(t.tm_min, stream, 2, '0', false);
        output_stream_write(stream, timeseparator, 1);
        format_dec_u64(t.tm_sec, stream, 2, '0', false);
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

static format_handler_descriptor_t epochz_format_handler_descriptor = {"epochz", 6, epochz_format_handler_method};

/**
 *  epoch
 *
 *  @note 32 bits epoch written up to the s
 */

void packedepoch_format_handler_method(const void *restrict val, output_stream_t *stream, int32_t padding, char pad_char, bool left_justified, void *restrict reserved_for_method_parameters)
{
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    time_t    epoch = (time_t)(intptr_t)val;
    struct tm t;

    gmtime_r(&epoch, &t);

    format_dec_u64(t.tm_year + 1900, stream, 4, '0', false);
    format_dec_u64(t.tm_mon + 1, stream, 2, '0', false);
    format_dec_u64(t.tm_mday, stream, 2, '0', false);
    format_dec_u64(t.tm_hour, stream, 2, '0', false);
    format_dec_u64(t.tm_min, stream, 2, '0', false);
    format_dec_u64(t.tm_sec, stream, 2, '0', false);
    // DO NOT ADD A SUFFIX HERE
}

static format_handler_descriptor_t packedepoch_format_handler_descriptor = {"packedepoch", 11, packedepoch_format_handler_method};

static initialiser_state_t         timeformat_class_init_state = INITIALISE_STATE_INIT;

void                               timeformat_class_init()
{
    if(initialise_state_begin(&timeformat_class_init_state))
    {
        format_class_init();

        // 64 bits

        format_registerclass(&datetimeus_format_handler_descriptor);
        format_registerclass(&localdatetimeus_format_handler_descriptor);
        format_registerclass(&datetimems_format_handler_descriptor);
        format_registerclass(&datetime_format_handler_descriptor);
        format_registerclass(&date_format_handler_descriptor);
        format_registerclass(&time_format_handler_descriptor);
        format_registerclass(&localdatetime_format_handler_descriptor);
        format_registerclass(&datetimeustms_format_handler_descriptor);

        // 32 bits

        format_registerclass(&epoch_format_handler_descriptor);
        format_registerclass(&localepoch_format_handler_descriptor);
        format_registerclass(&epochz_format_handler_descriptor);
        format_registerclass(&packedepoch_format_handler_descriptor);
        format_registerclass(&epochtms_format_handler_descriptor);

        initialise_state_ready(&timeformat_class_init_state);
    }
}

/** @} */
