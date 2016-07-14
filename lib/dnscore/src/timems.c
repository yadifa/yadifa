/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2016, EURid. All rights reserved.
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
/** @defgroup dnscoretools Generic Tools
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore-config.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#include "dnscore/timems.h"

static int DAYS_IN_MONTH_NORM[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
static int DAYS_IN_MONTH_LEAP[12] = {31,29,31,30,31,30,31,31,30,31,30,31};

/// @note 20150326 edf -- timegm is not portable (Solaris) in the end, implementing one seemed the only choice

/**
 * This implementation is based on the formula found in:
 * 
 * http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap04.html#tag_04_15
 * 4.15 Seconds Since the Epoch
 * 
 * It only cares on the Year, Month, Day, Hour, Minute and Second fields of struct tm (the one we are really caring about)
 * It's a constant-time implementation.
 * 
 * I don't see an obvious way to make it faster expect having the year values pre-calculated for the next 30+ years
 * (This would spare a few divs and a mult.)
 * 
 * If I improve it further, it may be a replacement on the timegm() dependency.
 * 
 */

    // J   F   M    A    M    J    J    A    S    O    N    D
    // 31  28  31   30   31   30   31   31   30   31   30   31

#define MDAY_FIX(d_) ((d_)-1)

static int timegm_mdays_norm[12] = {MDAY_FIX(0),MDAY_FIX( 31),MDAY_FIX( 59),MDAY_FIX( 90),MDAY_FIX( 120),MDAY_FIX( 151),MDAY_FIX( 181),MDAY_FIX( 212),MDAY_FIX( 243),MDAY_FIX( 273),MDAY_FIX( 304),MDAY_FIX( 334)}; // MDAY_FIX(365)

static int timegm_mdays_leap[12] = {MDAY_FIX(0),MDAY_FIX( 31),MDAY_FIX( 60),MDAY_FIX( 91),MDAY_FIX( 121),MDAY_FIX( 152),MDAY_FIX( 182),MDAY_FIX( 213),MDAY_FIX( 244),MDAY_FIX( 274),MDAY_FIX( 305),MDAY_FIX( 335)}; // MDAY_FIX(366)

time_t timegm_internal(struct tm *tv)
{
    time_t ret;
    
    if( (tv->tm_year < 0)                   ||
        (((u32)tv->tm_mon) > 11)            ||
        (((u32)tv->tm_mday - 1) > 31 - 1)   ||
        (((u32)tv->tm_hour) > 60)           ||
        (((u32)tv->tm_min) > 59)            ||
        (((u32)tv->tm_sec) > 60) )
    {
        return -1;
    }

    int yyyy = (tv->tm_year + 1900);

    int yday;
    if(((yyyy & 3) == 0) && (((yyyy % 100) != 0) || ((yyyy % 400) == 0)))
    {
        yday = timegm_mdays_leap[tv->tm_mon];
    }
    else
    {
        yday = timegm_mdays_norm[tv->tm_mon];
    }

    yday += tv->tm_mday;

    ret =   tv->tm_sec                       +
            tv->tm_min               *    60 +
            tv->tm_hour              *  3600 +
            (
                yday                     +
                ((tv->tm_year-69)/4)     -
                ((tv->tm_year-1)/100)    +
                ((tv->tm_year+299)/400)
            ) * 86400                        +
            (tv->tm_year-70)         * 31536000;

    return ret;
}

/*
 * Return the time in ms
 */

u64
timeus()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    u64 r = tv.tv_sec;
    r *= 1000000LL;
    r += tv.tv_usec;

    return r;
}

u64
timems()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    u64 r = tv.tv_sec;
    r *= 1000;
    r += tv.tv_usec / 1000;

    return r;
}

/*
 * Wait until the ms is incremented, then return the time in ms
 */

u64
timems_new()
{
    u64 t;
    u64 tms;
    u64 ttr;
    
    t = timeus();
    tms = t/1000;
    
    do
    {
        usleep(MIN(1000 - (tms % 1000), 1));
        ttr = timeus() / 1000;
    }
    while(ttr == tms);

    return ttr;
}

#define USLEEP_LIMIT 0xffffffff
//#define USLEEP_LIMIT 1000000

/**
 * usleep only support a limited range of time (sometimes 2^32 us, sometimes < 1 s)
 * This wrapper ensures time supported is up to 4294967295.000000 seconds
 * 
 * @param us the number of microseconds to wait for, can range from 0 to 4294967295000000 micro seconds
 */

void
usleep_ex(u64 us_)
{
    s64 us = (s64)us_;
    s64 now = timeus();
    s64 limit = now + us;
    
    if(us >= USLEEP_LIMIT)
    {   
        do
        {
            sleep(us / 1000000);
            now = timeus();
            us = limit - now;
        }
        while(us >= USLEEP_LIMIT);
    }
    
    // us is the remaining us to wait for
    
    while(us > 0)
    {
        usleep(us);
        now = timeus();
        us = limit - now;
    }
}

time_t
mkgmtime(const struct tm *tm_)
{
#if defined __FreeBSD__ || defined __OpenBSD__ || _BSD_SOURCE || _SVID_SOURCE
    time_t ret = timegm(tm_);
#else
    struct tm tm;
    memcpy(&tm, tm_, sizeof(struct tm));
    tm.tm_zone = NULL;
    tm.tm_gmtoff = 0;
    time_t ret = mktime(&tm);
    ret -= timezone;
#endif // __FREEBSD__

    return ret;
}

bool
time_is_leap_year(int y)
{
    return (((y & 3) == 0) && (((y % 100) != 0) || ((y % 400) == 0)));
}

int
time_days_in_month(int y, int m)
{
    yassert((m >= 0) &&( m < 12) && (y > 1900));
    
    if(!time_is_leap_year(y))
    {
        return DAYS_IN_MONTH_NORM[m];
    }
    else
    {
        return DAYS_IN_MONTH_LEAP[m];
    }
}

/**
 * Retrieves the first day of the month.
 * 
 * 0 is Sunday
 * 
 * @param year 0-based
 * @param month 0-based
 * @return the number of the day of the month or an error code
 */

int
time_first_day_of_month(int year, int month)
{
    yassert((month >= 0) &&( month < 12) && (year > 1900));
    
    struct tm tm;
    ZEROMEMORY(&tm, sizeof(struct tm));
    tm.tm_mday = 1;
    tm.tm_mon = month;
    tm.tm_year = year - 1900;
    time_t epoch = mkgmtime(&tm);
    gmtime_r(&epoch, &tm);
    return tm.tm_wday;
}

/** @} */

/*----------------------------------------------------------------------------*/

