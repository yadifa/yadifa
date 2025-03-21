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

/**-----------------------------------------------------------------------------
 * @defgroup ### #######
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include <dnscore/logger.h>
#include <dnscore/timems.h>

#include "dnssec_policy.h"

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle_t *g_dnssec_logger;

#include "server_error.h"

#if DNSCORE_HAS_PRIMARY_SUPPORT && DNSCORE_HAS_DNSSEC_SUPPORT

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

static int zone_policy_date_next_mask(int from, uint64_t mask, int limit)
{
    assert(from >= 0);
    assert(limit >= 0);

    for(int_fast32_t ret = from; ret < limit; ++ret)
    {
        if((mask & (1ULL << ret)) != 0)
        {
            return ret;
        }
    }
    for(int_fast32_t ret = 0; ret < from; ++ret)
    {
        if((mask & (1ULL << ret)) != 0)
        {
            return ret;
        }
    }

    return -1; // no match
}

static bool zone_policy_date_next_month(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    bool ret = true;

    for(;;)
    {
        int month = zone_policy_date_next_mask(date->absolute.month, def->month, 12);

        yassert(month >= 0);

        if(month != date->absolute.month)
        {
            ret = false;

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
                return false;
            }
        }
        else
        {
            return ret;
        }
    }
}

static void zone_policy_date_next_month_move(zone_policy_date *date, const zone_policy_rule_definition_s *def)
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

    zone_policy_date_next_month(date, def);
}

static bool zone_policy_date_next_week(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    bool ret = true;

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

            int newwday = zone_policy_date_next_mask(wday, def->weekday, 7); // matching week day

            if(newwday != wday)
            {
                ret = false;

                int dday = newwday - wday;

                if(dday < 0)
                {
                    dday += 7;
                }

                int day = date->absolute.day + dday;

                if(day >= time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE,
                                             date->absolute.month)) // no -1 here
                {
                    // month changed
                    // date->absolute.day = zone_policy_date_next_earliest_day_from_week(def);
                    // date->absolute.hour = 0;
                    // date->absolute.minute = 0;

                    zone_policy_date_next_month_move(date, def);
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
                newweek = zone_policy_date_next_mask(week, def->week, 4); // matching week
            }
            else
            {
                week = -1;
                newweek = zone_policy_date_next_mask(0, def->week, 4); // matching week
            }

            if(newweek != week)
            {
                ret = false;

                // the week changed later in this month
                if(newweek < week) // newweek < week : the week changed to the next month
                {
                    // month changed
                    zone_policy_date_next_month_move(date, def);
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

static bool zone_policy_date_next_day(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    bool ret = true;

    for(;;)
    {
        int day = zone_policy_date_next_mask(date->absolute.day, def->day, time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month));

        yassert(day >= 0);

        if(day != date->absolute.day)
        {
            ret = false;

            date->absolute.hour = 0;
            date->absolute.minute = 0;

            if(day < date->absolute.day)
            {
                // the day has looped to the next month

                zone_policy_date_next_month_move(date, def);

                continue;
            }
            else // the day has changed
            {
                date->absolute.day = day;
            }
        }

        // we have a day that may or may not match the week and the week-day

        if(zone_policy_date_next_week(date, def))
        {
            // week is good

            return ret;
        }

        ret = false;
    }
}

static void zone_policy_date_next_day_move(zone_policy_date *date, const zone_policy_rule_definition_s *def)
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
        zone_policy_date_next_month_move(date, def);
    }

    zone_policy_date_next_day(date, def);
}

static bool zone_policy_date_next_hour(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    bool ret = true;

    for(;;)
    {
        int hour = zone_policy_date_next_mask(date->absolute.hour, def->hour, 24);

        if(hour != date->absolute.hour)
        {
            ret = false;

            date->absolute.minute = 0;

            if(hour < date->absolute.hour)
            {
                zone_policy_date_next_day_move(date, def);
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

static void zone_policy_date_next_hour_move(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    // hour could loop back into the nextious year too

    date->absolute.minute = 0;

    if(date->absolute.hour < 23)
    {
        ++date->absolute.hour;
    }
    else
    {
        zone_policy_date_next_day_move(date, def);
    }

    zone_policy_date_next_hour(date, def);
}

static bool zone_policy_date_next_minute(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    bool ret = true;
    for(;;)
    {
        int minute = zone_policy_date_next_mask(date->absolute.minute, def->minute, 60);

        if(date->absolute.minute != minute)
        {
            ret = false;

            if(minute < date->absolute.minute)
            {
                zone_policy_date_next_hour_move(date, def);
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

ya_result zone_policy_date_init_at_next_rule(zone_policy_date *date, const zone_policy_date *from, const zone_policy_date *rule)
{
    yassert(from->type.type == ZONE_POLICY_ABSOLUTE);

    if(rule->type.type == ZONE_POLICY_RULE)
    {
        const zone_policy_rule_definition_s *def = zone_policy_rule_definition_get_from_rule(rule);

        time_t                               epoch;
        zone_policy_date_get_epoch(from, &epoch);

        if(rule->type.type == ZONE_POLICY_RULE)
        {
            epoch += 60;
        }

        zone_policy_date_init_from_epoch(date, epoch);

        zone_policy_date_next_month(date, def);
        zone_policy_date_next_day(date, def);
        zone_policy_date_next_hour(date, def);
        zone_policy_date_next_minute(date, def);

        return SUCCESS;
    }
    else if(rule->type.type == ZONE_POLICY_RELATIVE)
    {
        time_t epoch;
        zone_policy_date_get_epoch(from, &epoch);
        epoch += rule->relative.seconds;
        zone_policy_date_init_from_epoch(date, epoch);

        return SUCCESS;
    }
    else
    {
        return POLICY_ILLEGAL_DATE_TYPE;
    }
}

ya_result zone_policy_date_init_from_rule(zone_policy_date *date, const zone_policy_date *from, const zone_policy_date *rule)
{
    yassert(from->type.type == ZONE_POLICY_ABSOLUTE);

    if(rule->type.type == ZONE_POLICY_RULE)
    {
        const zone_policy_rule_definition_s *def = zone_policy_rule_definition_get_from_rule(rule);

        time_t                               epoch;
        zone_policy_date_get_epoch(from, &epoch);

        zone_policy_date_init_from_epoch(date, epoch);

        zone_policy_date_next_month(date, def);
        zone_policy_date_next_day(date, def);
        zone_policy_date_next_hour(date, def);
        zone_policy_date_next_minute(date, def);

        return SUCCESS;
    }
    else if(rule->type.type == ZONE_POLICY_RELATIVE)
    {
        time_t epoch;
        zone_policy_date_get_epoch(from, &epoch);
        epoch += rule->relative.seconds;
        zone_policy_date_init_from_epoch(date, epoch);

        return SUCCESS;
    }
    else
    {
        return POLICY_ILLEGAL_DATE_TYPE;
    }
}

bool zone_policy_date_matches(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    int month = zone_policy_date_next_mask(date->absolute.month, def->month, 12);
    if(month != date->absolute.month)
    {
        return false;
    }

    int fdom = time_first_day_of_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month);

    if(def->week == ZONE_POLICY_RULE_ANYWEEK)
    {
        // from the first day of the Month, the base of the week can be found
        // sunday = 0, but we want to start a Monday
        int week_base = (fdom + 6 % 7); // if we want to start a Sunday we add 0 instead

        // need to find the base of the month

        int week = (date->absolute.day - week_base);
        int newweek;

        if(week >= 0) // don't divide directly
        {
            week /= 7;
            newweek = zone_policy_date_next_mask(week, def->week, 4); // matching week
        }
        else
        {
            week = -1;
            newweek = zone_policy_date_next_mask(0, def->week, 4); // matching week
        }

        if(newweek != week)
        {
            return false;
        }
    }

    if(def->weekday != ZONE_POLICY_RULE_ANYWEEKDAY)
    {
        int fdom = time_first_day_of_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month);

        int wday = (date->absolute.day + fdom) % 7; // obtain the day name from the absolute day number (0 = sunday)

        int newwday = zone_policy_date_next_mask(wday, def->weekday, 7); // matching week day

        if(newwday != wday)
        {
            return false;
        }
    }

    int day = zone_policy_date_next_mask(date->absolute.day, def->day, time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month));

    if(day != date->absolute.day)
    {
        return false;
    }

    int hour = zone_policy_date_next_mask(date->absolute.hour, def->hour, 24);

    if(hour != date->absolute.hour)
    {
        return false;
    }

    int minute = zone_policy_date_next_mask(date->absolute.minute, def->minute, 60);

    if(minute != date->absolute.minute)
    {
        return false;
    }

    return true;
}

#endif

/**
 * @}
 */
