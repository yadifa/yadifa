/*------------------------------------------------------------------------------
*
* Copyright (c) 2011-2017, EURid. All rights reserved.
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

#include "server-config.h"

#include "zone-signature-policy.h"
#include "zone_desc.h"
#include "confs.h"

#include <dnscore/logger.h>
#include <dnscore/timems.h>

#include <dnscore/timeformat.h>

#include "database-service-zone-resignature.h"

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

// cron to date
// maximum returned value: 28 + 6 = 34 => this call has to be MAX(dim,ret) by the caller
static int
zone_policy_date_prev_latest_day_from_week(const zone_policy_rule_definition_s *def)
{
    yassert(def->week != 0);
    int m = def->week;
    int ret = 3 * 7 + 6;            // latest day of latest week
    while((m & 0x8) == 0)
    {
        ret -= 7;
        m <<= 1;
    }
    
    return ret;
}

static int
zone_policy_date_prev_mask(int from, u64 mask, int limit)
{
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
zone_policy_date_prev_month(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    int month = zone_policy_date_prev_mask(date->absolute.month, def->month, 12);
    yassert(month >= 0);
    if(month != date->absolute.month)
    {
        if(month > date->absolute.month)
        {
            --date->absolute.year;
        }
        date->absolute.month = month;
        date->absolute.day = zone_policy_date_prev_latest_day_from_week(def);
        if(date->absolute.day > 27) // may need correction ?
        {
            date->absolute.day = MAX(date->absolute.day, time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month) - 1);
        }
        date->absolute.hour = 23;
        date->absolute.minute = 59;
        
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

static void
zone_policy_date_prev_month_move(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    --date->absolute.month;

    date->absolute.day = zone_policy_date_prev_latest_day_from_week(def);
    if(date->absolute.day > 27) // may need correction ?
    {
        date->absolute.day = MAX(date->absolute.day, time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month) - 1);
    }
    date->absolute.hour = 23;
    date->absolute.minute = 59;

    zone_policy_date_prev_month(date, def);
}

static bool
zone_policy_date_prev_week(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    if(def->week != ZONE_POLICY_RULE_ANYWEEK)
    {
        int week = date->absolute.day / 7; // current week

        int newweek = zone_policy_date_prev_mask(week, def->week, 4); // matching week

        if(newweek != week)
        {
            // the week changed earlier in this month
            if(newweek < week)
            {
                // move the day to the prev week
                int day = newweek * 7 + 6;

                if(day > date->absolute.day)
                {
                    // month changed
                    date->absolute.day = zone_policy_date_prev_latest_day_from_week(def);
                    if(date->absolute.day > 27) // may need correction ?
                    {
                        date->absolute.day = MAX(date->absolute.day, time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month) - 1);
                    }
                    date->absolute.hour = 23;
                    date->absolute.minute = 59;
                    zone_policy_date_prev_month_move(date, def);
                }
                else
                {
                    date->absolute.day = day; // time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month) - 1;
                    date->absolute.hour = 23;
                    date->absolute.minute = 59;
                }
            }
            else // newweek > week : the week changed to the prev month
            {
                // month changed

                date->absolute.day = zone_policy_date_prev_latest_day_from_week(def); // earliest week
                if(date->absolute.day > 27) // may need correction ?
                {
                    date->absolute.day = MAX(date->absolute.day, time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month) - 1);
                }
                date->absolute.hour = 23;
                date->absolute.minute = 59;
                zone_policy_date_prev_month_move(date, def);
            }

            return FALSE;

        } // else nothing changed
    }

    // no change made by the week, what about the week-day ?
    
    if(def->weekday != ZONE_POLICY_RULE_ANYWEEKDAY)
    {
        int fdom = time_first_day_of_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month);
        
        int wday = (date->absolute.day + fdom) % 7;
        
        int newwday = zone_policy_date_prev_mask(wday, def->weekday, 7); // matching week day
        
        if(newwday != wday)
        {
            int dday = wday - newwday;
            
            if(dday < 0) // verify this
            {
                dday += 7;
            }
            
            int day = date->absolute.day - dday;

            if(day < 0)
            {
                // month changed
                date->absolute.day = time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month) - 1;
                date->absolute.hour = 23;
                date->absolute.minute = 59;
                
                zone_policy_date_prev_month_move(date, def);
            }
            else
            {
                date->absolute.day = day;
                date->absolute.hour = 23;
                date->absolute.minute = 59;
            }
            
            return FALSE;
        }
    }
    
    return TRUE;
}

static void
zone_policy_date_prev_day(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    //struct tm tm;
    //tm = date->absolute.year;

    for(;;)
    {
        int day = zone_policy_date_prev_mask(date->absolute.day, def->day, time_days_in_month(date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month));
        yassert(day >= 0);
        if(day != date->absolute.day)
        {
            if(day > date->absolute.day)
            {
                // the day has looped to the prev month
                
                zone_policy_date_prev_month_move(date, def);
                
                continue;
            }
            else // the day has changed
            {
                date->absolute.day = day;
                date->absolute.hour = 23;
                date->absolute.minute = 59;
            }
        }
        
        // we have a day that may or may not match the week and the week-day

        if(zone_policy_date_prev_week(date, def))
        {
            // week is good
            
            break;
        }
    }
}

static void
zone_policy_date_prev_day_move(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    if(date->absolute.day > 0)
    {   --date->absolute.day;
        date->absolute.hour = 23;
        date->absolute.minute = 59;
    }
    else
    {    
        zone_policy_date_prev_month_move(date, def);
    }
    
    zone_policy_date_prev_day(date, def);
}

static void
zone_policy_date_prev_hour(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    for(;;)
    {
        int hour = zone_policy_date_prev_mask(date->absolute.hour, def->hour, 24);
        int o = date->absolute.hour;
        date->absolute.hour = hour;
        
        if(hour <= o)
        {
            break;
        }
        
        date->absolute.minute = 59;

        if(hour > o)
        {
            zone_policy_date_prev_day_move(date, def);
        }
    }
}

static void
zone_policy_date_prev_minute(zone_policy_date *date, const zone_policy_rule_definition_s *def)
{
    for(;;)
    {
        int minute = zone_policy_date_prev_mask(date->absolute.minute, def->minute, 60);
        int o = date->absolute.minute;
        date->absolute.minute = minute;
        
        if(minute <= o)
        {
            break;
        }

        if(minute > o)
        {
            date->absolute.minute = minute;
            
            if(date->absolute.hour > 0)
            {
                --date->absolute.hour;
                zone_policy_date_prev_hour(date, def);
            }
            else
            {
                date->absolute.hour = 0;
                zone_policy_date_prev_day_move(date, def);
            }
        }
    }
}

void
zone_policy_date_init_at_prev_rule(zone_policy_date *date, const zone_policy_date *from, const zone_policy_date *rule)
{
    yassert(from->type.type == ZONE_POLICY_ABSOLUTE);
    if(rule->type.type == ZONE_POLICY_RULE)
    {
        const zone_policy_rule_definition_s *def = zone_policy_rule_definition_get_from_rule(rule);

        time_t epoch;
        zone_policy_date_get_epoch(from, &epoch);
        if(rule->type.type == ZONE_POLICY_RULE)
        {
            epoch -= 60;
        }
        zone_policy_date_init_from_epoch(date, epoch);   

        zone_policy_date_prev_month(date, def);
        zone_policy_date_prev_day(date, def);
        zone_policy_date_prev_hour(date, def);
        zone_policy_date_prev_minute(date, def);
    }
    else if(rule->type.type == ZONE_POLICY_RELATIVE)
    {
        time_t epoch;
        zone_policy_date_get_epoch(from, &epoch);
        epoch -= rule->relative.seconds;
        zone_policy_date_init_from_epoch(date, epoch);
    }
    else
    {
        abort();
    }
}

/**
 * @}
 */
