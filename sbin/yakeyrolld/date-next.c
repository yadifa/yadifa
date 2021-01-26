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



/**
 * Returns the first index matching the rule in the mask, starting from the first value,
 * going up to the msb then looping from the lsb.
 *
 * @param from the first index to test
 * @param mask the bitmask to test (64 bits max)
 * @param limit the number of bits in the mask
 *
 * @return the first matching index
 *
 */

static int
dnssec_policy_date_next_mask(int from, u64 mask, int limit)
{
    assert(from >= 0);
    assert(limit >= 0);

    for(int ret = from; ret < limit; ++ret)
    {    
        if((mask & (1ULL << ret)) != 0)
        {
            return ret;
        }
    }
    for(int ret = 0; ret < from; ++ret)
    {
        if((mask & (1ULL << ret)) != 0)
        {
            return ret;
        }
    }
    
    return -1; // no match
}

static bool
dnssec_policy_date_next_month(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    bool ret = TRUE;

    for(;;)
    {
        int month = dnssec_policy_date_next_mask(date->absolute.month, def->month, 12);

        yassert(month >= 0);

        if(month != date->absolute.month)
        {
            ret = FALSE;

            date->absolute.day = 0;
            date->absolute.hour = 0;
            date->absolute.minute = 0;

            if(month < date->absolute.month)
            {
                date->absolute.month = month;
                ++date->absolute.year;
                continue;
            }
            else
            {
                date->absolute.month = month;
                return FALSE;
            }
        }
        else
        {
            return ret;
        }
    }
}

static void
dnssec_policy_date_next_month_move(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    date->absolute.day = 0;
    date->absolute.hour = 0;
    date->absolute.minute = 0;

    if(date->absolute.month < 11)
    {
        ++date->absolute.month;
    }
    else
    {
        ++date->absolute.year;
        date->absolute.month = 0;
    }

    dnssec_policy_date_next_month(date, def);
}

static bool
dnssec_policy_date_next_week(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    bool ret = TRUE;

    if((def->week == ZONE_POLICY_RULE_ANYWEEK) && (def->weekday == ZONE_POLICY_RULE_ANYWEEKDAY))
    {
        return ret;
    }

    for(;;)
    {
        int fdom = time_first_day_of_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month);

        // no change made by the week, what about the week-day ?

        if(def->weekday != ZONE_POLICY_RULE_ANYWEEKDAY)
        {
            int wday = (date->absolute.day + fdom) % 7; // obtain the day name from the absolute day number (0 = sunday)

            int newwday = dnssec_policy_date_next_mask(wday, def->weekday, 7); // matching week day

            if(newwday != wday)
            {
                ret = FALSE;

                int dday = newwday - wday;

                if(dday < 0)
                {
                    dday += 7;
                }

                int day = date->absolute.day + dday;

                if(day >= time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month)) // no -1 here
                {
                    // month changed
                    //date->absolute.day = dnssec_policy_date_next_earliest_day_from_week(def);
                    //date->absolute.hour = 0;
                    //date->absolute.minute = 0;

                    dnssec_policy_date_next_month_move(date, def);
                }
                else
                {
                    date->absolute.day = day;
                    date->absolute.hour = 0;
                    date->absolute.minute = 0;
                }

                continue;
            }
        } // endif (def->weekday != ZONE_POLICY_RULE_ANYWEEKDAY)

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
                newweek = dnssec_policy_date_next_mask(week, def->week, 4); // matching week
            }
            else
            {
                week = -1;
                newweek = dnssec_policy_date_next_mask(0, def->week, 4); // matching week
            }

            if(newweek != week)
            {
                ret = FALSE;

                // the week changed later in this month
                if(newweek < week) // newweek < week : the week changed to the next month
                {
                    // month changed
                    dnssec_policy_date_next_month_move(date, def);
                    continue;
                }
                else
                {
                    // move the day to the next week
                    date->absolute.day = week_base + newweek * 7;
                    date->absolute.hour = 0;
                    date->absolute.minute = 0;
                }
            } // else nothing changed
        } // endif (def->week != ZONE_POLICY_RULE_ANYWEEK)

        break;
    }

    return ret;
}

static bool
dnssec_policy_date_next_day(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    bool ret = TRUE;

    for(;;)
    {
        int day = dnssec_policy_date_next_mask(date->absolute.day, def->day, time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month));

        yassert(day >= 0);

        if(day != date->absolute.day)
        {
            ret = FALSE;

            date->absolute.hour = 0;
            date->absolute.minute = 0;

            if(day < date->absolute.day)
            {
                // the day has looped to the next month
                
                dnssec_policy_date_next_month_move(date, def);
                
                continue;
            }
            else // the day has changed
            {
                date->absolute.day = day;
            }
        }
        
        // we have a day that may or may not match the week and the week-day

        if(dnssec_policy_date_next_week(date, def))
        {
            // week is good
            
            return ret;
        }

        ret = FALSE;
    }
}

static void
dnssec_policy_date_next_day_move(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    date->absolute.hour = 0;
    date->absolute.minute = 0;

    // [0;n]                   [1;n+1]
    if(date->absolute.day < time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month) - 1)
    {
        ++date->absolute.day;
    }
    else
    {
        dnssec_policy_date_next_month_move(date, def);
    }
    
    dnssec_policy_date_next_day(date, def);
}

static bool
dnssec_policy_date_next_hour(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    bool ret = TRUE;

    for(;;)
    {
        int hour = dnssec_policy_date_next_mask(date->absolute.hour, def->hour, 24);

        if(hour != date->absolute.hour)
        {
            ret = FALSE;

            date->absolute.minute = 0;

            if(hour < date->absolute.hour)
            {
                dnssec_policy_date_next_day_move(date, def);
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
dnssec_policy_date_next_hour_move(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    // hour could loop back into the nextious year too

    date->absolute.minute = 0;

    if(date->absolute.hour < 23)
    {
        ++date->absolute.hour;
    }
    else
    {
        dnssec_policy_date_next_day_move(date, def);
    }

    dnssec_policy_date_next_hour(date, def);
}

static bool
dnssec_policy_date_next_minute(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    bool ret = TRUE;
    for(;;)
    {
        int minute = dnssec_policy_date_next_mask(date->absolute.minute, def->minute, 60);

        if(date->absolute.minute != minute)
        {
            ret = FALSE;

            if(minute < date->absolute.minute)
            {
                dnssec_policy_date_next_hour_move(date, def);
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
dnssec_policy_date_init_at_next_rule(dnssec_policy_date *date, const dnssec_policy_date *from, const dnssec_policy_date *rule)
{
    yassert(from->type.type == ZONE_POLICY_ABSOLUTE);
    
    if(rule->type.type == ZONE_POLICY_RULE)
    {    
        const dnssec_policy_rule_definition_s *def = dnssec_policy_rule_definition_get_from_rule(rule);

        time_t epoch;
        dnssec_policy_date_get_epoch(from, &epoch);

        if(rule->type.type == ZONE_POLICY_RULE)
        {
            epoch += 60;
        }

        dnssec_policy_date_init_from_epoch(date, epoch);

        dnssec_policy_date_next_month(date, def);
        dnssec_policy_date_next_day(date, def);
        dnssec_policy_date_next_hour(date, def);
        dnssec_policy_date_next_minute(date, def);

        return SUCCESS;
    }
    else if(rule->type.type == ZONE_POLICY_RELATIVE)
    {
        time_t epoch;
        dnssec_policy_date_get_epoch(from, &epoch);
        epoch += rule->relative.seconds;
        dnssec_policy_date_init_from_epoch(date, epoch);

        return SUCCESS;
    }
    else
    {
        return POLICY_ILLEGAL_DATE_TYPE;
    }
}

ya_result
dnssec_policy_date_init_from_rule(dnssec_policy_date *date, const dnssec_policy_date *from, const dnssec_policy_date *rule)
{
    yassert(from->type.type == ZONE_POLICY_ABSOLUTE);

    if(rule->type.type == ZONE_POLICY_RULE)
    {
        const dnssec_policy_rule_definition_s *def = dnssec_policy_rule_definition_get_from_rule(rule);

        time_t epoch;
        dnssec_policy_date_get_epoch(from, &epoch);

        dnssec_policy_date_init_from_epoch(date, epoch);

        dnssec_policy_date_next_month(date, def);
        dnssec_policy_date_next_day(date, def);
        dnssec_policy_date_next_hour(date, def);
        dnssec_policy_date_next_minute(date, def);

        return SUCCESS;
    }
    else if(rule->type.type == ZONE_POLICY_RELATIVE)
    {
        time_t epoch;
        dnssec_policy_date_get_epoch(from, &epoch);
        epoch += rule->relative.seconds;
        dnssec_policy_date_init_from_epoch(date, epoch);

        return SUCCESS;
    }
    else
    {
        return POLICY_ILLEGAL_DATE_TYPE;
    }
}


bool
dnssec_policy_date_matches(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *def)
{
    int month = dnssec_policy_date_next_mask(date->absolute.month, def->month, 12);
    if(month != date->absolute.month)
    {
        return FALSE;
    }


    int fdom = time_first_day_of_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month);

    if(def->week == ZONE_POLICY_RULE_ANYWEEK)
    {
        // from the first day of the Month, the base of the week can be found
        // sunday = 0, but we want to start a Monday
        int week_base = (fdom + 6 % 7); // if we want to start a Sunday we add 0 instead

        // need to find the base of the month

        int week = (date->absolute.day - week_base);
        if(week >= 0) // don't divide directly
        {
            week /= 7;
            int newweek = dnssec_policy_date_next_mask(week, def->week, 4); // matching week

            if(newweek != week)
            {
                return FALSE;
            }
        }
        else
        {
            return FALSE;
        }
    }

    if(def->weekday != ZONE_POLICY_RULE_ANYWEEKDAY)
    {
        int fdom = time_first_day_of_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month);

        int wday = (date->absolute.day + fdom) % 7; // obtain the day name from the absolute day number (0 = sunday)

        int newwday = dnssec_policy_date_next_mask(wday, def->weekday, 7); // matching week day

        if(newwday != wday)
        {
            return FALSE;
        }
    }

    int day = dnssec_policy_date_next_mask(date->absolute.day, def->day, time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month));

    if(day != date->absolute.day)
    {
        return FALSE;
    }

    int hour = dnssec_policy_date_next_mask(date->absolute.hour, def->hour, 24);

    if(hour != date->absolute.hour)
    {
        return FALSE;
    }

    int minute = dnssec_policy_date_next_mask(date->absolute.minute, def->minute, 60);

    if(minute != date->absolute.minute)
    {
        return FALSE;
    }

    return TRUE;
}

/**
 * @}
 */
