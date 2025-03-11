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

#include "yatest.h"
#include <dnscore/dnscore.h>
#include <dnscore/timems.h>

static time_t    test_epoch = 1719393018;
static int64_t   test_epochus = 1719393018000000LL;
static struct tm test_tm;

static void      init()
{
    dnscore_init();
    gmtime_r(&test_epoch, &test_tm);
}

static void finalise() { dnscore_finalize(); }

static int  time_epoch_as_rfc5322_test()
{
    int  ret;
    char text[1024];
    init();
    ret = time_epoch_as_rfc5322(test_epoch, text, sizeof(text));
    if(ret < 0)
    {
        yatest_err("time_epoch_as_rfc5322 failed with %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    text[ret] = '\0';
    const char *expected = "Jun, 26 2024 09:10:18 GMT";
    yatest_log("Expected '%s', got '%s'", expected, text);
    if(strcmp(text, expected) != 0)
    {
        yatest_err("Expected '%s', got '%s'", expected, text);
        return 1;
    }
    finalise();
    return 0;
}

static int time_gm_internal_test()
{
    init();
    time_t epoch = timegm_internal(&test_tm);
    yatest_log("Got %i, expected %i", epoch, test_epoch);
    if(epoch != test_epoch)
    {
        yatest_err("Got %i, expected %i", epoch, test_epoch);
        return 1;
    }
    finalise();
    return 0;
}

static int timeus_test()
{
    init();
    time_t  now = time(NULL);
    int64_t nowus = timeus();
    nowus /= ONE_SECOND_US;
    if(llabs(nowus - now) > 1)
    {
        yatest_err("timeus difference %lli > 1", llabs(nowus - now));
        return 1;
    }
    finalise();
    return 0;
}

static int timeus_and_s_test()
{
    init();
    int32_t s;
    time_t  now = time(NULL);
    int64_t nowus = timeus_and_s(&s);
    nowus /= ONE_SECOND_US;
    if(llabs(nowus - now) > 1)
    {
        yatest_err("timeus_and_s difference %lli > 1", llabs(nowus - now));
        return 1;
    }
    if(llabs(s - now) > 1)
    {
        yatest_err("timeus_and_s difference %lli > 1 (s)", llabs(nowus - now));
        return 1;
    }
    finalise();
    return 0;
}

static int timems_test()
{
    init();
    time_t  now = time(NULL);
    int64_t nowms = timems();
    nowms /= 1000;
    if(nowms - now > 1)
    {
        yatest_err("timems difference %lli > 1", nowms - now);
        return 1;
    }
    finalise();
    return 0;
}

static int timems_new_test()
{
    init();
    time_t  now = time(NULL);
    int64_t nowms = timems_new();
    nowms /= 1000;
    if(nowms - now > 1)
    {
        yatest_err("timems difference %lli > 1", nowms - now);
        return 1;
    }
    finalise();
    return 0;
}

static int usleep_ex_test()
{
    init();
    int64_t t;
    yatest_timer_start(&t);
    usleep_ex(2 * ONE_SECOND_US);
    yatest_timer_stop(&t);
    if(llabs(t - 2 * ONE_SECOND_US) > 100000)
    {
        yatest_err("inaccurate");
        return 1;
    }
    finalise();
    return 0;
}

static int usleep_until_test()
{
    init();
    int64_t now = timeus();
    usleep_until(now + ONE_SECOND_US);
    int64_t t = timeus();
    int64_t d = llabs(ONE_SECOND_US - (t - now));
    if(d > 100000)
    {
        yatest_err("inaccurate");
        return 1;
    }
    finalise();
    return 0;
}

static int mkgmtime_test()
{
    init();
    time_t epoch = mkgmtime(&test_tm);
    yatest_log("Got %i, expected %i", epoch, test_epoch);
    if(epoch != test_epoch)
    {
        yatest_err("Got %i, expected %i", epoch, test_epoch);
        return 1;
    }
    finalise();
    return 0;
}

static int time_days_in_month_test()
{
    static const int dim_2000_2005[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 28, 31, 30, 31, 30,
                                        31, 31, 30, 31, 30, 31, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    init();
    int dim_index = 0;
    for(int y = 2000; y < 2005; ++y)
    {
        for(int m = 0; m < 12; ++m)
        {
            int n = time_days_in_month(y, m);
            if(n != dim_2000_2005[dim_index])
            {
                yatest_err("error for %i/%i: expected %i, got %i", y, m, dim_2000_2005[dim_index], n);
                return 1;
            }
            ++dim_index;
        }
    }
    finalise();
    return 0;
}

static int time_first_day_of_month_test()
{
    static const int dom_2000_2005[] = {6, 2, 3, 6, 1, 4, 6, 2, 5, 0, 3, 5, 1, 4, 4, 0, 2, 5, 0, 3, 6, 1, 4, 6, 2, 5, 5, 1, 3, 6, 1, 4, 0, 2, 5, 0, 3, 6, 6, 2, 4, 0, 2, 5, 1, 3, 6, 1, 4, 0, 1, 4, 6, 2, 4, 0, 3, 5, 1, 3};
    init();
    int dim_index = 0;
    for(int y = 2000; y < 2005; ++y)
    {
        for(int m = 0; m < 12; ++m)
        {
            int n = time_first_day_of_month(y, m);
            if(n != dom_2000_2005[dim_index])
            {
                yatest_err("error for %i/%i: expected %i, got %i", y, m, dom_2000_2005[dim_index], n);
                return 1;
            }
            ++dim_index;
        }
    }
    finalise();
    return 0;
}

static int timeus_from_smarttime_ex_test()
{
    init();
    int64_t ret;
    int64_t expected;

    ret = timeus_from_smarttime_ex("yesterday", test_epochus);
    if(ret < 0)
    {
        yatest_err("yesterday: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    expected = test_epochus - 86400000000LL;
    if(ret != expected)
    {
        yatest_err("yesterday: time doesn't match: got %lli, expected %lli", ret, expected);
        return 1;
    }

    //

    ret = timeus_from_smarttime_ex("now", test_epochus);
    if(ret < 0)
    {
        yatest_err("now: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    expected = test_epochus;
    if(ret != expected)
    {
        yatest_err("now: time doesn't match: got %lli, expected %lli", ret, expected);
        return 1;
    }

    ret = timeus_from_smarttime_ex("tomorrow", test_epochus);
    if(ret < 0)
    {
        yatest_err("tomorrow: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    expected = test_epochus + 86400000000LL;
    if(ret != expected)
    {
        yatest_err("tomorrow: time doesn't match: got %lli, expected %lli", ret, expected);
        return 1;
    }

    //

    ret = timeus_from_smarttime_ex("-1year", test_epochus);
    if(ret < 0)
    {
        yatest_err("-1year: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    expected = test_epochus - 366LL * 86400000000LL;
    if(ret != expected)
    {
        yatest_err("-1year: time doesn't match: got %lli, expected %lli", ret, expected);
        return 1;
    }

    //

    ret = timeus_from_smarttime_ex("+1year", test_epochus);
    if(ret < 0)
    {
        yatest_err("+1year: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    expected = test_epochus + 366LL * 86400000000LL;
    if(ret != expected)
    {
        yatest_err("+1year: time doesn't match: got %lli, expected %lli", ret, expected);
        return 1;
    }

    //

    ret = timeus_from_smarttime_ex("+1month", test_epochus);
    if(ret < 0)
    {
        yatest_err("+1month: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    expected = test_epochus + 31LL * 86400000000LL;
    if(ret != expected)
    {
        yatest_err("+1month: time doesn't match: got %lli, expected %lli", ret, expected);
        return 1;
    }

    //

    ret = timeus_from_smarttime_ex("+1week", test_epochus);
    if(ret < 0)
    {
        yatest_err("+1week: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    expected = test_epochus + 7LL * 86400000000LL;
    if(ret != expected)
    {
        yatest_err("+1week: time doesn't match: got %lli, expected %lli", ret, expected);
        return 1;
    }

    //

    ret = timeus_from_smarttime_ex("+1day", test_epochus);
    if(ret < 0)
    {
        yatest_err("+1week: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    expected = test_epochus + 86400000000LL;
    if(ret != expected)
    {
        yatest_err("+1week: time doesn't match: got %lli, expected %lli", ret, expected);
        return 1;
    }

    //

    ret = timeus_from_smarttime_ex("+1hour", test_epochus);
    if(ret < 0)
    {
        yatest_err("+1hour: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    expected = test_epochus + 3600000000LL;
    if(ret != expected)
    {
        yatest_err("+1hour: time doesn't match: got %lli, expected %lli", ret, expected);
        return 1;
    }

    //

    ret = timeus_from_smarttime_ex("+1minute", test_epochus);
    if(ret < 0)
    {
        yatest_err("+1minute: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    expected = test_epochus + 60000000LL;
    if(ret != expected)
    {
        yatest_err("+1minute: time doesn't match: got %lli, expected %lli", ret, expected);
        return 1;
    }

    //

    ret = timeus_from_smarttime_ex("+1second", test_epochus);
    if(ret < 0)
    {
        yatest_err("+1second: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    expected = test_epochus + 1000000LL;
    if(ret != expected)
    {
        yatest_err("+1second: time doesn't match: got %lli, expected %lli", ret, expected);
        return 1;
    }

    //

    ret = timeus_from_smarttime_ex("20240626091018", test_epochus);
    if(ret < 0)
    {
        yatest_err("20240626091018: %08x = %s", ret, error_gettext(ret));
        return 1;
    }
    expected = test_epochus;
    if(ret != expected)
    {
        yatest_err("20240626091018: time doesn't match: got %lli, expected %lli", ret, expected);
        return 1;
    }

    finalise();
    return 0;
}

static int timeus_with_offset_test()
{
    init();
    timeus_set_offset(3600000000LL);
    time_t  now = time(NULL);
    int64_t nowus = timeus_with_offset();
    nowus /= ONE_SECOND_US;
    if(llabs(nowus - 3600LL - now) > 1)
    {
        yatest_err("timeus difference %lli > 1", llabs(nowus - now));
        return 1;
    }
    finalise();
    return 0;
}

YATEST_TABLE_BEGIN
YATEST(time_epoch_as_rfc5322_test)
YATEST(time_gm_internal_test)
YATEST(timeus_test)
YATEST(timeus_and_s_test)
YATEST(timems_test)
YATEST(timems_new_test)
YATEST(usleep_ex_test)
YATEST(usleep_until_test)
YATEST(mkgmtime_test)
YATEST(time_days_in_month_test)
YATEST(time_first_day_of_month_test)
YATEST(timeus_from_smarttime_ex_test)
YATEST(timeus_with_offset_test)
YATEST_TABLE_END
