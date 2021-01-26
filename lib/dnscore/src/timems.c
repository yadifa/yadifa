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
#include <dnscore/parsing.h>
#include <dnscore/config_settings.h>

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

static char time_day_of_week[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri","Sat"};
static char time_month_of_year[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

/**
 * Sun to Sat
 * 
 * @param day
 * @return A 3 letters name followed by a zero
 */

const char * time_get_day_of_week_name(int day)
{
    if(day >= 0 && day < 7)
    {
        return time_day_of_week[day];
    }
    else
    {
        return NULL;
    }
}

/**
 * Jan to Dec
 * 
 * @param month
 * @return A 3 letters name followed by a zero
 */

const char * time_get_month_of_year_name(int month)
{
    if(month >= 0 && month < 12)
    {
        return time_month_of_year[month];
    }
    else
    {
        return NULL;
    }
}

static char*
time_write_day_time_number(char *buffer, int value)
{
    yassert(value >= 0 && value <= 99);
    
    if(value >= 10)
    {
        *buffer++ = '0' + (value / 10);
        value %= 10;
    }
    
    *buffer++ = '0' + value;
    
    return buffer;
}

static char*
time_write_year_time_number(char *buffer, int value)
{
    yassert(value >= 0 && value <= 9999);
    
    if(value >= 1000)
    {
        *buffer++ = '0' + (value / 1000);
        value %= 1000;
    }
    
    if(value >= 100)
    {
        *buffer++ = '0' + (value / 100);
        value %= 100;
    }
    
    if(value >= 10)
    {
        *buffer++ = '0' + (value / 10);
        value %= 10;
    }
    
    *buffer++ = '0' + value;
    
    return buffer;
}

static char*
time_write_zero_padded_time_number(char *buffer, int value)
{
    yassert(value >= 0 && value <= 99);
    
    if(value >= 10)
    {
        *buffer++ = '0' + (value / 10);
        value %= 10;
    }
    else
    {
        *buffer++ = '0';
    }
    
    *buffer++ = '0' + value;
    
    return buffer;
}

/**
 * Convert time structure into the text format defined by RFC5322 (GMT)
 * Does put a '\0' at the end of the buffer.
 * Requires a buffer of at least 29 bytes.
 * 
 * @param epoch
 * @param buffer
 * @param buffer_size
 * 
 * @return the number of chars written or an error
 */

ya_result
time_tm_as_rfc5322(const struct tm *t, char *buffer, size_t buffer_size)
{
    if(buffer_size >= 29)
    {
        const char * const day = time_get_day_of_week_name(t->tm_wday);

        if(day == NULL)
        {
            return INVALID_ARGUMENT_ERROR;
        }

        const char * const month = time_get_month_of_year_name(t->tm_mon);

        if(month == NULL)
        {
            return INVALID_ARGUMENT_ERROR;
        }

        memcpy(buffer, day, 3);
        memcpy(&buffer[3], ", ", 2);
        char *p = time_write_day_time_number(&buffer[5], t->tm_mday);
        *p++ = ' ';
        memcpy(buffer, month, 3);
        *p++ = ' ';
        p = time_write_year_time_number(p, t->tm_year + 1900);
        *p++ = ' ';
        p = time_write_zero_padded_time_number(p, t->tm_hour);
        *p++ = ':';
        p = time_write_zero_padded_time_number(p, t->tm_min);
        *p++ = ':';
        p = time_write_zero_padded_time_number(p, t->tm_sec);
        memcpy(p, " GMT" , 4);

        p += 4;

        return p - buffer;
    }
    else
    {
        return BUFFER_WOULD_OVERFLOW;
    }
}

/**
 * Convert epoch into the text format defined by RFC5322 (GMT)
 * Does put a '\0' at the end of the buffer.
 * Requires a buffer of at least 29 bytes.
 * 
 * @param epoch
 * @param buffer
 * @param buffer_size
 * 
 * @return the number of chars written or an error
 */

ya_result
time_epoch_as_rfc5322(time_t epoch, char *buffer, size_t buffer_size)
{
    struct tm t;
    gmtime_r(&epoch, &t);
    ya_result ret = time_tm_as_rfc5322(&t, buffer, buffer_size);
    return ret;
}

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

s64
timeus()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    s64 r = tv.tv_sec;
    r *= 1000000LL;
    r += tv.tv_usec;

    return r;
}

s64
timeus_and_s(s32 *seconds_ptr)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    *seconds_ptr = tv.tv_sec;

    s64 r = tv.tv_sec;
    r *= 1000000LL;
    r += tv.tv_usec;

    return r;
}
s64
timems()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    s64 r = tv.tv_sec;
    r *= 1000;
    r += tv.tv_usec / 1000;

    return r;
}

/*
 * Wait until the ms is incremented, then return the time in ms
 */

s64
timems_new()
{
    s64 t;
    s64 tms;
    s64 ttr;
    
    t = timeus();
    tms = t / 1000;

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

void
usleep_until(s64 epoch_us)
{
    s64 now = timeus();
    while(now < epoch_us)
    {
        usleep_ex(epoch_us - now);
        now = timeus();
    }
}

#ifndef WIN32
time_t
mkgmtime(const struct tm *tm_)
{
#if defined __FreeBSD__ || defined __OpenBSD__ || _BSD_SOURCE || _SVID_SOURCE
    struct tm tm_copy = *tm_;
    time_t ret = timegm(&tm_copy);
#else
    struct tm tm;
    memcpy(&tm, tm_, sizeof(struct tm));
#ifndef WIN32
    tm.tm_zone = NULL;
    tm.tm_gmtoff = 0;
#endif
    time_t ret = mktime(&tm);
    ret -= timezone;
#endif // __FREEBSD__

    return ret;
}
#else
time_t
mkgmtime(const struct tm* tm_)
{
    return _mkgmtime(tm_);
}

#endif

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

static s64 timeus_offset = 0;

/**
 * Returns timeus() - offset
 * Used to fake the current time.
 */

s64 timeus_with_offset()
{
    return timeus() + timeus_offset;
}

/**
 * Sets the offset of the time returned by timeus_with_offset()
 */

void timeus_set_offset(s64 us)
{
    timeus_offset = us;
}

/**
 * Internal tool function for timeus_from_smarttime
 * Tells if a name starts by another.
 *
 * @param singular the name to match
 * @param name the matching name
 * @param name_limit points after the last letter of the matching name
 *
 * @return SUCCESS if it's a match, else PARSEDATE_ERROR
 *
 * e.g.: "seconds", "sec", ... => SUCCESS
 * e.g.: "seconds", "msec", ... => PARSEDATE_ERROR
 */

static ya_result
timeus_tools_unit_name_check(const char* singular, const char* name, const char* name_limit)
{
    int n = name_limit - name;
    for(int i = 1; i < n; ++i)
    {
        if(singular[i] != name[i])
        {
            if(name[i] == '\0')
            {
                return SUCCESS;
            }
            else
            {
                return PARSEDATE_ERROR;
            }
        }
    }

    return SUCCESS;
}

/**
 * Parses a text as a date/time and converts it to an epoch in microseconds.
 *
 * yesterday
 * now
 * tomorrow
 * +1y +1year +1years (months,weeks,days,seconds)
 * -1y -1year -1years (months,weeks,days,seconds)
 * 2019-04-16
 * 2019-04-16_12:00:00.123456
 * 20190416
 * 20190416120000123456
 *
 */

s64
timeus_from_smarttime_ex(const char *text, s64 now)
{
    s64 epoch = 0;
    s64 relative = 0;
    ya_result ret;

    text = parse_skip_spaces(text);
    if(*text == '+')
    {
        relative = 1;
        ++text;
    }
    else if(*text == '-')
    {
        relative = -1;
        ++text;
    }

    if(isalpha(*text))
    {
        // keyword
        if(memcmp(text, "now", 3) == 0)
        {
            //relative = 0;
            epoch = now;
            return epoch;
        }
        else if(memcmp(text, "tomorrow", 8) == 0)
        {
            //relative = 0;
            epoch = now + ONE_SECOND_US * 86400;
            return epoch;
        }
        else if(memcmp(text, "yesterday", 9) == 0)
        {
            //relative = 0;
            epoch = now - ONE_SECOND_US * 86400;
            return epoch;
        }
        else
        {
            return CONFIG_PARSE_UNKNOWN_KEYWORD;
        }
    }

    if(isdigit(*text))
    {
        if(relative)
        {
            // integer
            const char *limit = parse_skip_digits(text);
            size_t size = limit - text;
            s64 value;
            if(FAIL(ret = parse_u64_check_range_len_base10(text, size, (u64*)&value, 0, 504921600)))    // 0 to 16 years expressed in seconds
            {
                return ret;
            }

            epoch = value * relative;

            // multiplier
            text = limit;
            if(*text != '\0')
            {
                limit += strlen(limit);

                switch(*text)
                {
                    case 's':
                    {
                        if(FAIL(ret = timeus_tools_unit_name_check("seconds", text, limit)))
                        {
                            return ret;
                        }
                        epoch *= ONE_SECOND_US;
                        break;
                    }
                    case 'h':
                    {
                        if(FAIL(ret = timeus_tools_unit_name_check("hours", text, limit)))
                        {
                            return ret;
                        }
                        epoch *= ONE_SECOND_US;
                        break;
                    }
                    case 'd': // days
                    {
                        if(FAIL(ret = timeus_tools_unit_name_check("days", text, limit)))
                        {
                            return ret;
                        }
                        epoch *= 86400LL * ONE_SECOND_US;
                        break;
                    }
                    case 'w': // weeks
                    {
                        if(FAIL(ret = timeus_tools_unit_name_check("weeks", text, limit)))
                        {
                            return ret;
                        }
                        epoch *= 7LL * 86400LL * ONE_SECOND_US;
                        break;
                    }
                    case 'm': // months
                    {
                        if(FAIL(ret = timeus_tools_unit_name_check("months", text, limit)))
                        {
                            if(FAIL(ret = timeus_tools_unit_name_check("minutes", text, limit)))
                            {
                                return ret;
                            }
                            else
                            {
                                epoch *= 60LL * ONE_SECOND_US;
                            }
                        }
                        else
                        {
                            epoch *= 31LL * 86400LL * ONE_SECOND_US;
                        }
                        break;
                    }
                    case 'y': // years
                    {
                        if(FAIL(ret = timeus_tools_unit_name_check("years", text, limit)))
                        {
                            return ret;
                        }
                        epoch *= 366LL * 86400LL * ONE_SECOND_US;
                        break;
                    }
                    default:
                    {
                        return PARSEDATE_ERROR;
                    }
                }
            }
            else
            {
                epoch *= ONE_SECOND_US;
            }

            epoch += now;

            return epoch;
        }
        else
        {
            // read 4 digits, skip non digits
            // read 2 digits, skip non digits
            // read 2 digits, skip non digits
            // this is an acceptable value, but if there is more
            // read 2 digits, skip non digits
            // read 2 digits, skip non digits
            // read 2 digits, skip non digits
            // this is an acceptable value, but if there is more
            // read up to 6 digits
            u32 year = 0, month = 0, day = 0;
            u32 hours = 0, minutes = 0, seconds = 0;
            u32 microseconds = 0;

            // parse year, month and day

            if(FAIL(ret = parse_u32_check_range_len_base10(text, 4, &year, 1970, 2034)))
            {
                return ret;
            }
            text += 4;
            text = parse_skip_nondigits(text);

            if(FAIL(ret = parse_u32_check_range_len_base10(text, 2, &month, 1, 12)))
            {
                return ret;
            }
            text += 2;
            text = parse_skip_nondigits(text);

            if(FAIL(ret = parse_u32_check_range_len_base10(text, 2, &day, 1, 31)))
            {
                return ret;
            }
            text += 2;

            // skip blanks
            // if the end of the text hasn't been reached then start parsing hours, minutes and seconds

            text = parse_skip_spaces(text);

            if(*text != 0)
            {
                text = parse_skip_nondigits(text);

                if(FAIL(ret = parse_u32_check_range_len_base10(text, 2, &hours, 0, 23)))
                {
                    return ret;
                }
                text += 2;
                text = parse_skip_nondigits(text);

                if(FAIL(ret = parse_u32_check_range_len_base10(text, 2, &minutes, 0, 59)))
                {
                    return ret;
                }
                text += 2;
                text = parse_skip_nondigits(text);

                if(FAIL(ret = parse_u32_check_range_len_base10(text, 2, &seconds, 0, 59)))
                {
                    return ret;
                }
                text += 2;

                // skip blanks
                // if the end of the text hasn't been reached then start parsing fractional time

                text = parse_skip_spaces(text);

                if(*text != 0)
                {
                    text = parse_skip_nondigits(text);

                    int digits = 6;

                    while((digits > 0) && isdigit(*text))
                    {
                        microseconds *= 10;
                        microseconds += *text - '0';
                        ++text;
                        --digits;
                    }

                    while(digits > 0)
                    {
                        microseconds *= 10;
                        --digits;
                    }
                }
            }

            struct tm tm;
            memset(&tm, 0, sizeof(struct tm));
            tm.tm_year = year - 1900;
            tm.tm_mon = month - 1;
            tm.tm_mday = day - 1;
            tm.tm_hour = hours;
            tm.tm_min = minutes;
            tm.tm_sec = seconds;
            time_t t = timegm(&tm);
            epoch = t;
            epoch *= ONE_SECOND_US;
            epoch += microseconds;

            return epoch;
        }
    }

    return PARSEDATE_ERROR;
}

/**
 * Parses a text as a date/time and converts it to an epoch in microseconds.
 *
 * yesterday
 * now
 * tomorrow
 * +1y +1year +1years (months,weeks,days,seconds)
 * -1y -1year -1years (months,weeks,days,seconds)
 * 2019-04-16
 * 2019-04-16_12:00:00.123456
 * 20190416
 * 20190416120000123456
 *
 */

s64
timeus_from_smarttime(const char *text)
{
    s64 ret;
    ret = timeus_from_smarttime_ex(text, timeus());
    return ret;
}

/** @} */
