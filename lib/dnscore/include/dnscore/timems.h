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
#ifndef _TIMEMS_H
#define	_TIMEMS_H

#include <unistd.h>
#include <time.h>
#include <dnscore/sys_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif

#define ONE_SECOND_US 1000000LL
#define ONE_SECOND_US_F 1000000.0

/**
 * A local implementation of struct tm *t
 * 
 * @param tv
 * @return 
 */
    
time_t timegm_internal(struct tm *tv);

/*
 * Returns the time in us
 */

s64 timeus();

/*
 * Returns the time in us and sets the pointed s32 to the time in s
 */

s64 timeus_and_s(s32 *seconds_ptr);



/*
 * Returns the time in ms
 */

s64 timems();

/*
 * Waits until the ms is incremented, then returns the time in ms
 */

s64 timems_new();

/**
 * usleep only support a limited range of time (sometimes 2^32 us, sometimes < 1 s)
 * This wrapper ensures time supported is up to 4294967295.000000 seconds
 * 
 * @param us the number of microseconds to wait for, can range from 0 to 4294967295000000 micro seconds
 */

void usleep_ex(u64 us_);

void usleep_until(s64 epoch_us);

time_t mkgmtime(const struct tm *tm);

bool time_is_leap_year(int y);

int time_days_in_month(int y, int m);

/**
 * Retrieves the first day of the month.
 * 
 * 0 is Sunday
 * 
 * @param year 0-based
 * @param month 0-based
 * @return the number of the day of the month or an error code
 */

int time_first_day_of_month(int year, int month);

/**
 * Sun to Sat
 * 
 * @param day
 * 
 * @return A 3 letters name followed by a zero
 */

const char * time_get_day_of_week_name(int day);

/**
 * Jan to Dec
 * 
 * @param month
 * @return A 3 letters name followed by a zero
 */

const char * time_get_month_of_year_name(int month);

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
time_tm_as_rfc5322(const struct tm *t, char *buffer, size_t buffer_size);

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

ya_result time_epoch_as_rfc5322(time_t epoch, char *buffer, size_t buffer_size);

/**
 * Returns timeus() - offset
 * Used to fake the current time.
 */

s64 timeus_with_offset();

/**
 * Sets the offset of the time returned by timeus_with_offset()
 */

void timeus_set_offset(s64 us);

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

s64 timeus_from_smarttime_ex(const char *text, s64 now);

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

s64 timeus_from_smarttime(const char *text);

static inline double timeus_diff_seconds_double(s64 from, s64 to)
{
    double ret = (double)(to - from);
    ret /= ONE_SECOND_US_F;
    return ret;
}

static inline double timeus_diff_ms_double(s64 from, s64 to)
{
    double ret = (double)(to - from);
    ret /= 1000.0;
    return ret;
}

static inline s64 timeus_diff_ms(s64 from, s64 to)
{
    s64 ret = (to - from);
    ret /= 1000LL;
    return ret;
}

static inline s64 time_to_timeus(time_t t)
{
    return (ONE_SECOND_US * t);
}

#ifdef	__cplusplus
}
#endif

#endif	/* _TIMEMS_H */
/** @} */
