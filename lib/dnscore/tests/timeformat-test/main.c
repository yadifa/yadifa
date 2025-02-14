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

#include "yatest.h"
#include <time.h>
#include "dnscore/timems.h"
#include <dnscore/dnscore.h>
#include <dnscore/timeformat.h>
#include <dnscore/bytearray_output_stream.h>

static output_stream_t os;
static const int64_t         epoch_us = 1719393018LL * ONE_SECOND_US + 314159;
static const time_t          epoch_time = 1719393018;

static void            init()
{
    dnscore_init();
    timeformat_class_init();
    bytearray_output_stream_init(&os, NULL, 65536);
    setenv("TZ", "GMT+1", 1);
    tzset();
#if !__FreeBSD__
    formatln("%s/%s %li %i", tzname[0], tzname[1], timezone, daylight);
#else
    formatln("%s/%s %li", tzname[0], tzname[1], timezone);
#endif
    flushout();
}

static void finalise() { dnscore_finalize(); }

static int datetimeus_test()
{
    init();
    yatest_log("sizeof(time_t)=%i sizeof(epoch_us)=%i, epoch_us=%" PRIi64, (int)sizeof(time_t), (int)sizeof(epoch_us), epoch_us);
    osformat(&os, "%{dtus}", &epoch_us);
    output_stream_write_u8(&os, 0);
    const char *expected = "2024-06-26 09:10:18.314159Z";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

static int datetimeustms_test()
{
    init();
    osformat(&os, "%{dtustms}", &epoch_us);
    output_stream_write_u8(&os, 0);
    const char *expected = "2024-06-26T09:10:18.314Z";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

static int localdatetimeus_test()
{
    init();
    osformat(&os, "%{ldtus}", &epoch_us);
    output_stream_write_u8(&os, 0);
    const char *expected = "2024-06-26 08:10:18.314159";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

static int datetimems_test()
{
    init();
    osformat(&os, "%{dtms}", &epoch_us);
    output_stream_write_u8(&os, 0);
    const char *expected = "2024-06-26 09:10:18.314";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

static int datetime_test()
{
    init();
    osformat(&os, "%{dts}", &epoch_us);
    output_stream_write_u8(&os, 0);
    const char *expected = "2024-06-26 09:10:18";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

static int localdatetime_test()
{
    init();
    osformat(&os, "%{ldts}", &epoch_us);
    output_stream_write_u8(&os, 0);
    const char *expected = "2024-06-26 08:10:18";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

static int date_test()
{
    init();
    osformat(&os, "%{date}", &epoch_us);
    output_stream_write_u8(&os, 0);
    const char *expected = "2024-06-26";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

static int time_test()
{
    init();
    osformat(&os, "%{time}", &epoch_us);
    output_stream_write_u8(&os, 0);
    const char *expected = "09:10:18";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

static int epoch_test()
{
    init();
    osformat(&os, "%{epoch}", &epoch_time);
    output_stream_write_u8(&os, 0);
    const char *expected = "2024-06-26 09:10:18Z";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

static int epochtms_test()
{
    init();
    osformat(&os, "%{epochtms}", &epoch_time);
    output_stream_write_u8(&os, 0);
    const char *expected = "2024-06-26T09:10:18.000Z";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

static int localepoch_test()
{
    init();
    osformat(&os, "%{lepoch}", &epoch_time);
    output_stream_write_u8(&os, 0);
    const char *expected = "2024-06-26 08:10:18";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

static int epochz_test()
{
    init();
    osformat(&os, "%{epochz}", &epoch_time);
    output_stream_write_u8(&os, 0);
    const char *expected = "2024-06-26 09:10:18";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

static int packedepoch_test()
{
    init();
    osformat(&os, "%{packedepoch}", &epoch_time);
    output_stream_write_u8(&os, 0);
    const char *expected = "20240626091018";
    yatest_log("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
    if(strcmp((const char *)bytearray_output_stream_buffer(&os), expected) != 0)
    {
        yatest_err("Expected '%s' got '%s'", expected, bytearray_output_stream_buffer(&os));
        return 1;
    }
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(datetimeus_test)
YATEST(localdatetimeus_test)
YATEST(datetimems_test)
YATEST(datetimeustms_test)
YATEST(datetime_test)
YATEST(localdatetime_test)
YATEST(date_test)
YATEST(time_test)
YATEST(epoch_test)
YATEST(epochtms_test)
YATEST(localepoch_test)
YATEST(epochz_test)
YATEST(packedepoch_test)
YATEST_TABLE_END
