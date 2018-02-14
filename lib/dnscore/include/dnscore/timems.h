/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2018, EURid vzw. All rights reserved.
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
    
/**
 * A local implementation of struct tm *t
 * 
 * @param tv
 * @return 
 */
    
time_t timegm_internal(struct tm *tv);

/*
 * Return the time in us
 */

u64 timeus();

/*
 * Return the time in ms
 */

u64 timems();

/*
 * Wait until the ms is incremented, then return the time in ms
 */

u64 timems_new();

/**
 * usleep only support a limited range of time (sometimes 2^32 us, sometimes < 1 s)
 * This wrapper ensures time supported is up to 4294967295.000000 seconds
 * 
 * @param us the number of microseconds to wait for, can range from 0 to 4294967295000000 micro seconds
 */

void usleep_ex(u64 us_);

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

#ifdef	__cplusplus
}
#endif

#endif	/* _TIMEMS_H */
/** @} */

/*----------------------------------------------------------------------------*/

