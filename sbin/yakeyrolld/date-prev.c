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

/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */

#include "dnssec-policy.h"

#include <dnscore/logger.h>
#include <dnscore/timems.h>

#include <dnscore/timeformat.h>

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

static bool dnssec_policy_date_prev_day(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def);
static void dnssec_policy_date_prev_day_move(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def);

/**
 * Returns the first index matching the rule in the mask, starting from the first value,
 * going down to the lsb then looping from the msb.
 *
 * @param from the first index to test
 * @param mask the bitmask to test (64 bits max)
 * @param limit the number of bits in the mask
 *
 * @return the first matching index
 *
 */

static int
dnssec_policy_date_prev_mask(int from, u64 mask, int limit)
{
    assert(from >= 0);
    assert(limit >= 0);
    for(int ret = from; ret >= 0; --ret)
    {    
        if((mask & (1ULL << ret)) != 0)
        {
            return ret;
        }
    }
    for(int ret = limit - 1; ret > from; --ret)
    {
        if((mask & (1ULL << ret)) != 0)
        {
            return ret;
        }
    }
    
    return -1; // no match
}

static bool
dnssec_policy_date_prev_month(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    bool ret = TRUE;
    for(;;)
    {
        int month = dnssec_policy_date_prev_mask(date->absolute.month, def->month, 12);

        yassert(month >= 0);

        if(month != date->absolute.month)
        {
            ret = FALSE;

            date->absolute.day = time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, month) - 1;
            date->absolute.hour = 23;
            date->absolute.minute = 59;

            if(month > date->absolute.month)
            {
                if(date->absolute.year == 0)
                {
                    log_err("previous month outside of supported time range");
                    logger_flush();
                }

                date->absolute.month = 11;
                --date->absolute.year;
                continue;
            }
            else
            {
                date->absolute.month = month;
                return FALSE;
            }

            // the caller is supposed to proceed on day (then hour, then minute) correction
        }
        else
        {
            return ret; // no change
        }
    }
}

// the "move" version of the function guarantees the value will be changed

static void
dnssec_policy_date_prev_month_move(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    // month could loop back into the previous year too
    date->absolute.hour = 23;
    date->absolute.minute = 59;

    if(date->absolute.month > 0)
    {
        --date->absolute.month;

        date->absolute.day = time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month) - 1;
    }
    else
    {
        if(date->absolute.year == 0)
        {
            log_err("previous month outside of supported time range");
            logger_flush();
        }

        --date->absolute.year;

        date->absolute.month = 11;
        date->absolute.day = time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month) - 1;
    }

    dnssec_policy_date_prev_month(date, def);
}

static bool
dnssec_policy_date_prev_week(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    bool ret = TRUE;

    if((def->week == ZONE_POLICY_RULE_ANYWEEK) && (def->weekday == ZONE_POLICY_RULE_ANYWEEKDAY))
    {
        return ret;
    }

    for(;;)
    {
        int fdom = time_first_day_of_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month);

        if(def->week != ZONE_POLICY_RULE_ANYWEEK)
        {
            // from the first day of the Month, the base of the week can be found
            // sunday = 0, but we want to start a Monday
            int week_base = 7 - (fdom + 6) % 7; // if we want to start a Sunday we add 0 instead

            // need to find the base of the month

            int week = (date->absolute.day - week_base);
            int newweek;
            if(week >= 0) // don't divide directly
            {
                week /= 7;
                newweek = dnssec_policy_date_prev_mask(week, def->week, 4); // matching week
            }
            else
            {
                week = -1;
                newweek = dnssec_policy_date_prev_mask(5, def->week, 4); // matching week
            }

            if(newweek != week)
            {
                ret = FALSE;

                // the week changed earlier in this month
                if(newweek > week)
                {
                    // month changed
                    dnssec_policy_date_prev_month_move(date, def);
                    continue;
                }
                else // newweek > week : the week changed to the prev month
                {
                    // move the day to the prev week
                    date->absolute.day = week_base + newweek * 7 + 6; // + 6 because we want the last day of that week
                    date->absolute.hour = 23;
                    date->absolute.minute = 59;
                }
            } // else nothing changed
        } // endif (def->week != ZONE_POLICY_RULE_ANYWEEK)

        // no change made for the week, what about the week-day ?

        if(def->weekday != ZONE_POLICY_RULE_ANYWEEKDAY)
        {
            int wday = (date->absolute.day + fdom) % 7;

            int newwday = dnssec_policy_date_prev_mask(wday, def->weekday, 7); // matching week day

            if(newwday != wday)
            {
                ret = FALSE;

                int dday = wday - newwday;

                if(dday < 0) // verify this
                {
                    dday += 7;
                }

                int day = date->absolute.day - dday;

                if(day < 0)
                {
                    // month changed

                    dnssec_policy_date_prev_month_move(date, def);
                }
                else
                {
                    date->absolute.day = day;
                    date->absolute.hour = 23;
                    date->absolute.minute = 59;
                }

                continue;
            }
        } // endif (def->weekday != ZONE_POLICY_RULE_ANYWEEKDAY)

        break;
    }

    return ret;
}

static bool
dnssec_policy_date_prev_day(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    bool ret = TRUE;

    for(;;)
    {
        int day = dnssec_policy_date_prev_mask(date->absolute.day, def->day, time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month) - 1);

        yassert(day >= 0);

        if(day != date->absolute.day) // the current day didn't match (so it changed)
        {
            ret = FALSE;

            date->absolute.hour = 23;
            date->absolute.minute = 59;

            if(day > date->absolute.day) // the day has looped up, the month must decrement
            {
                // the day has looped to the prev month
                
                dnssec_policy_date_prev_month_move(date, def); // _move functions enforce a change then call their non-_move version to check a match
                
                continue;
            }
            else // the day has changed, we will match time down from the top of the day (23:59)
            {
                date->absolute.day = day;
            }
        }
        
        // we have a day that may or may not match the week and the week-day, we check that here

        if(dnssec_policy_date_prev_week(date, def)) // if true, it's a match
        {
            // week is good
            
            return ret;
        }

        ret = FALSE;
    }
}

static void
dnssec_policy_date_prev_day_move(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    date->absolute.hour = 23;
    date->absolute.minute = 59;

    if(date->absolute.day > 0)
    {
        --date->absolute.day;
    }
    else
    {
        dnssec_policy_date_prev_month_move(date, def);
    }
    
    dnssec_policy_date_prev_day(date, def);
}

static bool
dnssec_policy_date_prev_hour(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    bool ret = TRUE;

    for(;;)
    {
        int hour = dnssec_policy_date_prev_mask(date->absolute.hour, def->hour, 24);

        if(hour != date->absolute.hour)
        {
            ret = FALSE;

            date->absolute.minute = 59;

            if(hour > date->absolute.hour)
            {
                dnssec_policy_date_prev_day_move(date, def);
            }
            else
            {
                date->absolute.hour = hour;
            }
        }
        else
        {
            return ret;
        }
    }
}

static void
dnssec_policy_date_prev_hour_move(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    // hour could loop back into the previous year too

    date->absolute.minute = 59;

    if(date->absolute.hour > 0)
    {
        --date->absolute.hour;
    }
    else
    {
        dnssec_policy_date_prev_day_move(date, def);
    }

    dnssec_policy_date_prev_hour(date, def);
}

static bool
dnssec_policy_date_prev_minute(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    bool ret = TRUE;
    for(;;)
    {
        int minute = dnssec_policy_date_prev_mask(date->absolute.minute, def->minute, 60);

        if(minute != date->absolute.minute)
        {
            ret = FALSE;

            if(minute > date->absolute.minute)
            {
                dnssec_policy_date_prev_hour_move(date, def);
            }
            else
            {
                date->absolute.minute = minute;
            }
        }
        else
        {
            return ret;
        }
    }
}

ya_result
dnssec_policy_date_init_at_prev_rule(dnssec_policy_date *date, const dnssec_policy_date *from, const dnssec_policy_date *rule)
{
    yassert(from->type.type == ZONE_POLICY_ABSOLUTE);
    if(rule->type.type == ZONE_POLICY_RULE)
    {
        const dnssec_policy_rule_definition_s *def = dnssec_policy_rule_definition_get_from_rule(rule);

        time_t epoch;
        dnssec_policy_date_get_epoch(from, &epoch);
        if(rule->type.type == ZONE_POLICY_RULE)
        {
            epoch -= 60; // force a move back in time
        }

        dnssec_policy_date_init_from_epoch(date, epoch);   

        dnssec_policy_date_prev_month(date, def);
        dnssec_policy_date_prev_day(date, def);
        dnssec_policy_date_prev_hour(date, def);
        dnssec_policy_date_prev_minute(date, def);

        return SUCCESS;
    }
    else if(rule->type.type == ZONE_POLICY_RELATIVE)
    {
        time_t epoch;
        dnssec_policy_date_get_epoch(from, &epoch);
        epoch -= rule->relative.seconds;
        dnssec_policy_date_init_from_epoch(date, epoch);

        return SUCCESS;
    }
    else
    {
        return POLICY_ILLEGAL_DATE_TYPE;
    }
}

/**
 * @}
 */
