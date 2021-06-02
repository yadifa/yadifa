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

#include <dnscore/mutex.h>
#include <dnscore/ptr_set.h>
#include <dnscore/u32_set.h>
#include <dnscore/dnskey.h>
#include <dnscore/timems.h>
#include <dnscore/random.h>
#include <dnscore/packet_reader.h>
#include <dnscore/timeformat.h>
#include <dnscore/threaded_dll_cw.h>
#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/timeformat.h>

#include <dnsdb/dnssec-keystore.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/nsec.h>
#include <dnsdb/nsec3.h>

#if HAS_EVENT_DYNAMIC_MODULE
#include "dynamic-module-handler.h"
#endif

#ifndef HAS_DYNUPDATE_DIFF_ENABLED
#error "HAS_DYNUPDATE_DIFF_ENABLED not defined"
#endif

#define MODULE_MSG_HANDLE g_dnssec_logger

logger_handle *g_dnssec_logger = LOGGER_HANDLE_SINK;

#define DNSECPOL_TAG 0x4c4f504345534e44
#define DPOLKYST_TAG 0x5453594b4c4f5044
#define DPOLKEY_TAG  0x0059454b4c4f5044
#define DPOLDNIL_TAG 0x4c494e444c4f5044
#define DPOLSALT_TAG 0x544c41534c4f5044
#define DPOLROLL_TAG 0x4c4c4f524c4f5044
#define DPOLRULE_TAG 0x454c55524c4f5044
#define DPOLQUEU_TAG 0x554555514c4f5044

#define DNSSEC_POLICY_EPOCH_DOOMSDAY 0x3ac7d61800 // ~ 1st January 3970

#define KEY_POLICY_EPOCH_MATCH_MARGIN 180 // how close two epochs have to be to be considered a match

#define DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS 0
#if DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS
#pragma message("WARNING: DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS enabled !")
#endif


static u32_set dnssec_policy_rule_definition_set = U32_SET_EMPTY;
static group_mutex_t dnssec_policy_rule_definition_set_mtx = GROUP_MUTEX_INITIALIZER;
static volatile u32 dnssec_policy_rule_definition_next_index = 0;

// local functions definitions

ya_result dnssec_policy_date_init_at_next_rule(dnssec_policy_date *date, const dnssec_policy_date *from, const dnssec_policy_date *rule);
ya_result dnssec_policy_date_init_at_prev_rule(dnssec_policy_date *date, const dnssec_policy_date *from, const dnssec_policy_date *rule);

ya_result dnssec_policy_date_init_from_rule(dnssec_policy_date *date, const dnssec_policy_date *from, const dnssec_policy_date *rule);

//

static ptr_set dnssec_policy_roll_set = PTR_SET_ASCIIZ_EMPTY;
static group_mutex_t dnssec_policy_roll_set_mtx = GROUP_MUTEX_INITIALIZER;
static group_mutex_t dnssec_policy_roll_mtx = GROUP_MUTEX_INITIALIZER;

//

static ptr_set dnssec_policy_set = PTR_SET_ASCIIZ_EMPTY;
static group_mutex_t dnssec_policy_set_mtx = GROUP_MUTEX_INITIALIZER;
static group_mutex_t dnssec_policy_mtx = GROUP_MUTEX_INITIALIZER;

//
#if 0
static ptr_set dnssec_denial_set = PTR_SET_ASCIIZ_EMPTY;
static group_mutex_t dnssec_denial_set_mtx = GROUP_MUTEX_INITIALIZER;
static group_mutex_t dnssec_denial_mtx = GROUP_MUTEX_INITIALIZER;
#endif
//

static ptr_set dnssec_policy_key_set = PTR_SET_ASCIIZ_EMPTY;
static group_mutex_t dnssec_policy_key_set_mtx = GROUP_MUTEX_INITIALIZER;
static group_mutex_t dnssec_policy_key_mtx = GROUP_MUTEX_INITIALIZER;

//

static ptr_set dnssec_policy_key_suite_set = PTR_SET_ASCIIZ_EMPTY;
static group_mutex_t dnssec_policy_key_suite_set_mtx = GROUP_MUTEX_INITIALIZER;
static group_mutex_t dnssec_policy_key_suite_mtx = GROUP_MUTEX_INITIALIZER;

//

#if DEBUG
static void
dnssec_policy_date_format_handler_method(const void *restrict val, output_stream *os, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    dnssec_policy_date *date = (dnssec_policy_date*)val;
    (void)padding;
    (void)pad_char;
    (void)left_justified;
    (void)reserved_for_method_parameters;
    
    switch(date->type.type)
    {
        case ZONE_POLICY_ABSOLUTE:
        {
            osformat(os, "%4u-%02u-%02u %02u:%02u:00U", date->absolute.year + ZONE_POLICY_DATE_YEAR_BASE, date->absolute.month + 1, date->absolute.day + 1, date->absolute.hour, date->absolute.minute);
            break;
        }
        case ZONE_POLICY_RELATIVE:
        {
            osformat(os, "(%u)+%us", date->relative.seconds, date->relative.relativeto);
            break;
        }
        case ZONE_POLICY_RULE:
        {
            dnssec_policy_rule_definition_s *def = dnssec_policy_rule_definition_get_from_rule(date);
            osformat(os, "[%016x %06x %08x %02x %x %x]", def->minute, def->hour, def->day, def->month, def->weekday, def->week);
            break;
        }
        default:
        {
            output_stream_write(os, "?", 1);
            break;
        }
    }
}
#endif

ya_result
dnssec_policy_add_generate_key_create_at(keyroll_t *keyroll, struct dnssec_policy_key_suite *kr, time_t epoch, dnssec_key **out_keyp)
{
    dnssec_policy_table_s tbl;
    dnssec_policy_date now_date;
    ya_result ret;

    ret = dnssec_policy_date_init_from_epoch(&now_date, epoch);

    if(FAIL(ret))
    {
        log_err("dnssec_policy_add_generate_key_create_at: dnssec_policy_table_init_from_date returned an error: %r", ret);
        return ret;
    }

    ret = dnssec_policy_table_init_from_date(&tbl, &kr->roll->time_table, &now_date);

    if(FAIL(ret))
    {
        log_err("dnssec_policy_add_generate_key_create_at: dnssec_policy_table_init_from_date returned an error: %r", ret);
        return ret;
    }

#if DEBUG
    format_writer n_fw = {dnssec_policy_date_format_handler_method, &now_date};
    format_writer c_fw = {dnssec_policy_date_format_handler_method, &tbl.created};
    format_writer p_fw = {dnssec_policy_date_format_handler_method, &tbl.publish};
    format_writer a_fw = {dnssec_policy_date_format_handler_method, &tbl.activate};
    format_writer d_fw = {dnssec_policy_date_format_handler_method, &tbl.inactive};
    format_writer r_fw = {dnssec_policy_date_format_handler_method, &tbl.delete};

    log_debug("dnssec-policy: %{dnsname}: %s: at %U = %U = %w: queued key: create=%w, publish=%w, activate=%w, deactivate=%w, remove=%w",
              keyroll->domain, kr->name, epoch, epoch, &n_fw,
            &c_fw, &p_fw, &a_fw, &d_fw, &r_fw);
#endif

    time_t created_epoch;
    time_t publish_epoch;
    time_t activate_epoch;
    time_t deactivate_epoch;
    time_t unpublish_epoch;

    if(FAIL(ret = dnssec_policy_date_get_epoch(&tbl.created, &created_epoch))) // note: created should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_add_generate_key_create_at: dnssec_policy_date_get_epoch (created_epoch) returned an error: %r", ret);
        return ret;
    }

    if(FAIL(ret = dnssec_policy_date_get_epoch(&tbl.publish, &publish_epoch))) // note: publish should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_add_generate_key_create_at: dnssec_policy_date_get_epoch (publish_epoch) returned an error: %r", ret);
        return ret;
    }

    if(FAIL(ret = dnssec_policy_date_get_epoch(&tbl.activate, &activate_epoch))) // note: activate should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_add_generate_key_create_at: dnssec_policy_date_get_epoch (activate_epoch) returned an error: %r", ret);
        return ret;
    }

    if(FAIL(ret = dnssec_policy_date_get_epoch(&tbl.inactive, &deactivate_epoch))) // note: deactivate should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_add_generate_key_create_at: dnssec_policy_date_get_epoch (deactivate_epoch) returned an error: %r", ret);
        return ret;
    }

    if(FAIL(ret = dnssec_policy_date_get_epoch(&tbl.delete, &unpublish_epoch))) // note: unpublish should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_add_generate_key_create_at: dnssec_policy_date_get_epoch (unpublish_epoch) returned an error: %r", ret);
        return ret;
    }

    if(FAIL(ret = keyroll_generate_dnskey_ex(keyroll, kr->key->size, kr->key->algorithm, ONE_SECOND_US * created_epoch, ONE_SECOND_US * publish_epoch, ONE_SECOND_US * activate_epoch,
                               ONE_SECOND_US * deactivate_epoch, ONE_SECOND_US * unpublish_epoch, (kr->key->flags == DNSKEY_FLAGS_KSK), out_keyp)))
    {
        log_err("dnssec_policy_add_generate_key_create_at: dnssec_policy_date_get_epoch (unpublish_epoch) returned an error: %r", ret);
        return ret;
    }

    yassert(tbl.created.type.type == ZONE_POLICY_ABSOLUTE);

    time_t alarm_epoch;

    if(FAIL(ret = dnssec_policy_date_get_epoch(&tbl.created, &alarm_epoch))) // note: created should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_add_generate_key_create_at: dnssec_policy_date_get_epoch returned an error: %r", ret);
        return ret;
    }

#if DEBUG
    log_debug("dnssec-policy: %{dnsname}: %s: key created set at %U", keyroll->domain, kr->name, alarm_epoch);
#endif

    return SUCCESS;
}

/**
 * Works only with RULEs (cron) key suites
 * 
 * @param zone_desc
 * @param kr
 * @param active_at
 */

ya_result
dnssec_policy_add_generate_key_active_at(keyroll_t *keyroll, struct dnssec_policy_key_suite *kr, time_t active_at)
{
    dnssec_policy_date creation_date;
    dnssec_policy_date publish_date;
    dnssec_policy_date activate_date;
    dnssec_policy_date inactive_date;
    dnssec_policy_date unpublish_date;
    dnssec_policy_date now_date;

    ya_result ret;

    // set now_date to active epoch

    if(FAIL(ret = dnssec_policy_date_init_from_epoch(&now_date, active_at)))
    {
        return ret;
    }

    // find the previous match for active date

    if(FAIL(ret = dnssec_policy_date_init_at_prev_rule(&activate_date, &now_date, &kr->roll->time_table.activate)))
    {
        return ret;
    }

    // find the previous match for publish date

    if(FAIL(ret = dnssec_policy_date_init_at_prev_rule(&publish_date, &activate_date, &kr->roll->time_table.publish)))
    {
        return ret;
    }

    // find the previous match for create date

    if(FAIL(ret = dnssec_policy_date_init_at_prev_rule(&creation_date, &publish_date, &kr->roll->time_table.created)))
    {
        return ret;
    }

    time_t creation_epoch = 60;
    time_t activate_epoch = 60;

    // get the computed create epoch

    if(FAIL(ret = dnssec_policy_date_get_epoch(&creation_date, &creation_epoch)))
    {
        return ret;
    }

    // get the computed active epoch

    if(FAIL(ret = dnssec_policy_date_get_epoch(&activate_date, &activate_epoch)))
    {
        return ret;
    }

    //creation_epoch -= 60;

#if DEBUG
    format_writer c_fw = {dnssec_policy_date_format_handler_method, &creation_date};

    {
        format_writer a_fw0 = {dnssec_policy_date_format_handler_method, &activate_date};
        format_writer p_fw0 = {dnssec_policy_date_format_handler_method, &publish_date};
        format_writer n_fw0 = {dnssec_policy_date_format_handler_method, &now_date};

        log_debug1("dnssec-policy: %{dnsname}: %s: base create: %w <= public: %w <= activate: %w : %U (%w)", keyroll->domain, kr->name, &c_fw, &p_fw0, &a_fw0, creation_epoch, &n_fw0);
    }
#endif

    // compute the forward publish date from the creation date

    if(FAIL(ret = dnssec_policy_date_init_at_next_rule(&publish_date, &creation_date, &kr->roll->time_table.publish)))
    {
        return ret;
    }

    // compute the forward activate date from the publish date

    if(FAIL(ret = dnssec_policy_date_init_at_next_rule(&activate_date, &publish_date, &kr->roll->time_table.activate)))
    {
        return ret;
    }

#if DEBUG
    format_writer p_fw = {dnssec_policy_date_format_handler_method, &publish_date};
    format_writer a_fw = {dnssec_policy_date_format_handler_method, &activate_date};
    {
        log_debug1("dnssec-policy: %{dnsname}: %s: base create: %w => publish: %w => activate: %w : %U (after forward correction)", keyroll->domain, kr->name, &c_fw, &p_fw, &a_fw, creation_epoch);
    }
#endif

    // compute the future key timings to ensure there will be no period without a signature

    dnssec_policy_date next_creation_date;
    dnssec_policy_date next_publish_date;
    dnssec_policy_date next_activate_date;

    if(FAIL(ret = dnssec_policy_date_init_at_next_rule(&next_creation_date, &activate_date, &kr->roll->time_table.created)))
    {
        return ret;
    }

    if(FAIL(ret = dnssec_policy_date_init_at_next_rule(&next_publish_date, &next_creation_date, &kr->roll->time_table.publish)))
    {
        return ret;
    }

    if(FAIL(ret = dnssec_policy_date_init_at_next_rule(&next_activate_date, &next_publish_date, &kr->roll->time_table.activate)))
    {
        return ret;
    }

#if DEBUG
    {
        format_writer na_fw = {dnssec_policy_date_format_handler_method, &next_activate_date};
        format_writer np_fw = {dnssec_policy_date_format_handler_method, &next_publish_date};
        format_writer nc_fw = {dnssec_policy_date_format_handler_method, &next_creation_date};

        log_debug1("dnssec-policy: %{dnsname}: %s: next activate: %w => publish: %w => activate: %w", keyroll->domain, kr->name, &nc_fw, &np_fw, &na_fw);
    }
#endif

    // and use this next_activate as a base for the current deactivate

    if(FAIL(ret = dnssec_policy_date_init_at_next_rule(&inactive_date, &next_activate_date, &kr->roll->time_table.inactive)))
    {
        return ret;
    }

    if(FAIL(ret = dnssec_policy_date_init_at_next_rule(&unpublish_date, &inactive_date, &kr->roll->time_table.delete)))
    {
        return ret;
    }

    time_t inactive_epoch = 0;

    if(FAIL(ret = dnssec_policy_date_get_epoch(&inactive_date, &inactive_epoch)))
    {
        return ret;
    }

    if(inactive_epoch - activate_epoch < DNSSEC_POLICY_MINIMUM_ACTIVATED_TIME_SUGGESTION_SECONDS)
    {
        double d = inactive_epoch - activate_epoch;
        d /= 86400.0;
        double c = DNSSEC_POLICY_MINIMUM_ACTIVATED_TIME_SUGGESTION_SECONDS;
        c /= 86400.0;
        log_warn("dnssec-policy: %{dnsname}: %s: the key will only be activated for %.3f days, consider increasing this value to at least %.3f days", keyroll->domain, kr->name, d, c);
    }

    if(inactive_epoch < active_at)
    {
        log_err("dnssec-policy: %{dnsname}: %s: computing timings to be in the current activated time window produces an already expired key", keyroll->domain, kr->name );

        return INVALID_STATE_ERROR;
    }

#if DEBUG
    format_writer d_fw = {dnssec_policy_date_format_handler_method, &inactive_date};
    dnssec_policy_date remove_date;
    ret = dnssec_policy_date_init_at_next_rule(&remove_date, &inactive_date, &kr->roll->time_table.delete);
    (void)ret;
    format_writer r_fw = {dnssec_policy_date_format_handler_method, &unpublish_date};

    log_debug("dnssec-policy: %{dnsname}: %s: rule key: create=%w, publish=%w, activate=%w, deactivate=%w, remove=%w",
              keyroll->domain, kr->name,
            &c_fw, &p_fw, &a_fw, &d_fw, &r_fw);
#endif

    log_debug("dnssec-policy: %{dnsname}: %s: will generate a key at %U (rule new) to be active at %U (%lli)", keyroll->domain, kr->name, creation_epoch, active_at, active_at);

    ////
    {
        dnssec_policy_table_s tbl;
        dnssec_policy_date now_date;
        ya_result ret;

        ret = dnssec_policy_date_init_from_epoch(&now_date, creation_epoch);

        if(FAIL(ret))
        {
            return ret;
        }

        ret = dnssec_policy_table_init_from_date(&tbl, &kr->roll->time_table, &now_date);

        if(FAIL(ret))
        {
            return ret;
        }

        time_t active_epoch;

        ret = dnssec_policy_date_get_epoch(&tbl.activate, &active_epoch);

        if(FAIL(ret))
        {
            return ret;
        }

        time_t inactive_epoch;

        ret = dnssec_policy_date_get_epoch(&tbl.inactive, &inactive_epoch);

        if(FAIL(ret))
        {
            return ret;
        }

        if((active_epoch > active_at) || (inactive_epoch < active_at))
        {
            flushout();
            return ERROR;
        }
    }

    ////

#if DEBUG
    logger_flush();
#endif

    // add the command

    dnssec_key *key = NULL;

    ret = dnssec_policy_add_generate_key_create_at(keyroll, kr, creation_epoch, &key);

    if(key != NULL)
    {
        if(ISOK(ret))
        {
            if(!dnskey_is_activated(key, active_at))
            {
                s32 key_active_at = dnskey_get_activate_epoch(key);
                s32 key_inactive_at = dnskey_get_inactive_epoch(key);
                log_err("key expected to be active at %u but is active from %u to %u (%U [%U; %U])", active_at, key_active_at, key_inactive_at, active_at, key_active_at, key_inactive_at);
                logger_flush();
                ret = ERROR;
            }
        }

        dnskey_release(key);
    }

    return ret;
}

/**
 * Compare two dates together.
 * Absolute with Absolute
 * Relative with Relative
 * 
 * Any other combination will return -1
 * 
 * @param d1 first date
 * @param d2 second date
 * @return <0,0,>0 if d1 is less than, equal to, or greater than d2
 */

int
dnssec_policy_date_compare(const dnssec_policy_date *d1, const dnssec_policy_date *d2)
{
    int ret;
    
    if(d1->type.type == ZONE_POLICY_ABSOLUTE && d2->type.type == ZONE_POLICY_ABSOLUTE)
    {
        ret = d1->absolute.year;
        ret -= d2->absolute.year;
        
        if(ret == 0)
        {
            ret = d1->absolute.month;
            ret -= d2->absolute.month;
            
            if(ret == 0)
            {
                ret = d1->absolute.day;
                ret -= d2->absolute.day;
                
                if(ret == 0)
                {
                    ret = d1->absolute.hour;
                    ret -= d2->absolute.hour;

                    if(ret == 0)
                    {
                        ret = d1->absolute.minute;
                        ret -= d2->absolute.minute;
                    }
                }
            }
        }
        
        return ret;
    }
    else if(d1->type.type == ZONE_POLICY_RELATIVE && d2->type.type == ZONE_POLICY_RELATIVE)
    {
        ret = d1->relative.seconds;
        ret -= d2->relative.seconds;
        return ret;
    }
    
    return POLICY_ILLEGAL_DATE_COMPARE;
}

/**
 * Retrieves the first day of the month.
 * 
 * 0 is Sunday
 * 
 * @param year 0-based
 * @param month 0-based
 * @param week 0 to 4, week of the day
 * @param wday 0 to 6, day of the week, 0 for Sunday
 * @return the number of the day of the month or an error code
 */

ya_result
dnssec_policy_get_mday_from_year_month_week_wday(int year, int month, int week, int wday)
{
    int mday1 = time_first_day_of_month(year, month);
    
    if(mday1 >= 0)
    {
        /**
         * @note this can obviously  be simplified (++week) but I think it's clearer this way (for now)
         */
        
        if(wday < mday1)
        {   
            // 0 1 2 3 4 5 6
            //
            // X Y Z 1 2 3 4
            // 4[6]7 8 9 ...
            
            return wday - mday1 + 7 * (week + 1);
        }
        else
        {
            // 0 1 2 3 4 5 6
            //
            // X Y Z 1 2 3 4
            // 4 6 7 8[9]...
            
            return wday - mday1 + 7 * week;
        }
    }
    else
    {
        return POLICY_ILLEGAL_DATE;
    }
}

/**
 * Initialises an absolute date from a year, month, week and week-day
 * 
 * ie: 2nd Wednesday of January 2001
 * 
 * 0 is Sunday
 * 
 * @param date the date to initialise
 * @param year 0-based
 * @param month 0-based
 * @param week 0 to 4, week of the day
 * @param wday 0 to 6, day of the week, 0 for Sunday
 * @return an error code
 */

ya_result
dnssec_policy_date_init_from_year_month_week_wday(dnssec_policy_date *date, int year, int month, int week, int wday)
{    
    struct tm tm;
    ZEROMEMORY(&tm, sizeof(struct tm));
    tm.tm_mday = 1;
    tm.tm_mon = month;
    tm.tm_year = year - 1900;
    time_t t = mkgmtime(&tm);
    if(t >= 0)
    {
        if(tm.tm_wday >= 0)
        {
            /**
             * @note this can obviously  be simplified (++week) but I think it's clearer this way (for now)
             * 
             * tm_wday is the first week-day of the month
             */

            if(wday < tm.tm_wday) // [0 .. 7] < [1 .. 31] ?
            {
                // 0 1 2 3 4 5 6
                //
                // X Y Z 1 2 3 4
                // 4[6]7 8 9 ...

                tm.tm_mday = wday - tm.tm_wday + 7 * (week + 1) + 1;
            }
            else
            {
                // 0 1 2 3 4 5 6
                //
                // X Y Z 1 2 3 4
                // 4 6 7 8[9]...

                tm.tm_mday = wday - tm.tm_wday + 7 * week + 1;
            }
            
            t = mkgmtime(&tm);
            
            if(t >= 0)
            {
                if(tm.tm_year < 228)
                {
                    date->type.type = ZONE_POLICY_ABSOLUTE;
                    date->absolute.year = tm.tm_year - (ZONE_POLICY_DATE_YEAR_BASE - 1900); // 1900 based to 2000 based
                    date->absolute.month = tm.tm_mon;
                    date->absolute.day = tm.tm_mday - 1; // 1 based to 0 based
                    date->absolute.hour = tm.tm_hour;
                    date->absolute.minute = tm.tm_min;
                    
                    return SUCCESS;
                 }
            }
        }
    }
    
    return POLICY_ILLEGAL_DATE_PARAMETERS;
}

/**
 * Initialises an absolute date from a UNIX epoch
 * 
 * @param date
 * @param epoch
 * @return an error code
 */

ya_result
dnssec_policy_date_init_from_epoch(dnssec_policy_date *date, time_t epoch)
{
    time_t t = epoch;
    struct tm d;
    
    // if it worked and there was no overflow ...
    
    if((gmtime_r(&t, &d) != NULL) && (d.tm_year < 228))
    {
        date->type.type = ZONE_POLICY_ABSOLUTE;
        date->absolute.year = d.tm_year - (ZONE_POLICY_DATE_YEAR_BASE - 1900); // 1900 based to 2000 based
        date->absolute.month = d.tm_mon;
        date->absolute.day = d.tm_mday - 1; // 1 based to 0 based
        date->absolute.hour = d.tm_hour;
        date->absolute.minute = d.tm_min;
        
        return SUCCESS;
    }
    
    return POLICY_ILLEGAL_DATE_PARAMETERS;
}

/**
 * Gets the UNIX epoch from an absolute date
 * 
 * @param date
 * @param epoch a pointer to hold the result
 * @return an error code
 */

ya_result
dnssec_policy_date_get_epoch(const dnssec_policy_date *date, time_t *epoch)
{
    time_t t;
    struct tm d;
    
    yassert(epoch != NULL);
    
    if(date->type.type != ZONE_POLICY_ABSOLUTE) // only works with absolute dates
    {
        return POLICY_ILLEGAL_DATE_TYPE;
    }
    
    ZEROMEMORY(&d, sizeof(struct tm));
    
    d.tm_year = date->absolute.year + (ZONE_POLICY_DATE_YEAR_BASE - 1900);  // 2000 based to 1900 based
    d.tm_mon = date->absolute.month;
    d.tm_mday = date->absolute.day + 1;     // 0 based to 1 based
    d.tm_hour = date->absolute.hour;
    d.tm_min = date->absolute.minute;
    d.tm_sec = 0;
    
    t = mkgmtime(&d);
    
    if(t != -1)
    {
        *epoch = t;
        return SUCCESS;
    }
    else
    {
        return MAKE_ERRNO_ERROR(EOVERFLOW);
    }
}

/**
 * Initialises the absolute date with an epoch plus time in seconds.
 * 
 * @param date
 * @param epoch an epoch to add the seconds to
 * @param seconds
 * @return an error code
 */

ya_result
dnssec_policy_date_init_after_epoch(dnssec_policy_date *date, time_t epoch, u32 seconds)
{
    ya_result ret = dnssec_policy_date_init_from_epoch(date, epoch + seconds);
    return ret;
}

/**
 * Initialises the absolute date with an absolute date plus time in seconds.
 * 
 * @param date
 * @param from an absolute date to add the seconds to
 * @param seconds
 * @return an error code
 */

ya_result
dnssec_policy_date_init_after_date(dnssec_policy_date *date, const dnssec_policy_date *from, u32 seconds)
{
    ya_result ret;
    time_t epoch;
    if(ISOK(ret = dnssec_policy_date_get_epoch(from, &epoch)))
    {
        ret = dnssec_policy_date_init_from_epoch(date, epoch + seconds);
    }
    return ret;
}





dnssec_policy_rule_definition_s*
dnssec_policy_rule_definition_get_from_index(u32 index)
{
    dnssec_policy_rule_definition_s *ret = NULL;
    group_mutex_read_lock(&dnssec_policy_rule_definition_set_mtx);
    u32_node *node = u32_set_find(&dnssec_policy_rule_definition_set, index);
    if(node != NULL)
    {
        ret = (dnssec_policy_rule_definition_s*)node->value;
    }
    group_mutex_read_unlock(&dnssec_policy_rule_definition_set_mtx);
    return ret;
}

dnssec_policy_rule_definition_s*
dnssec_policy_rule_definition_get_from_rule(const dnssec_policy_date *rule)
{
    dnssec_policy_rule_definition_s *ret = NULL;
    if(rule->type.type == ZONE_POLICY_RULE)
    {
        ret = dnssec_policy_rule_definition_get_from_index(rule->rule.index);
    }
    return ret;
}

void
dnssec_policy_rule_init(dnssec_policy_rule_s *rule, const dnssec_policy_rule_definition_s *rule_definition)
{   
    group_mutex_write_lock(&dnssec_policy_rule_definition_set_mtx);
    yassert(dnssec_policy_rule_definition_next_index < 0x40000000);
    
    for(;;)
    {
        ++dnssec_policy_rule_definition_next_index;
        if(dnssec_policy_rule_definition_next_index == 0x40000000)
        {
            dnssec_policy_rule_definition_next_index = 0;
        }

        u32_node *node = u32_set_insert(&dnssec_policy_rule_definition_set, dnssec_policy_rule_definition_next_index);
        
        if(node->value == NULL)
        {
            rule->index = dnssec_policy_rule_definition_next_index;
            rule->type = ZONE_POLICY_RULE;

            dnssec_policy_rule_definition_s *new_rule_definition;
            ZALLOC_OBJECT_OR_DIE( new_rule_definition, dnssec_policy_rule_definition_s, DPOLRULE_TAG);
            memcpy(new_rule_definition, rule_definition, sizeof(dnssec_policy_rule_definition_s));
            node->value = new_rule_definition;
            break;
        }
    }
    
    group_mutex_write_unlock(&dnssec_policy_rule_definition_set_mtx);
}

void
dnssec_policy_rule_finalize(dnssec_policy_rule_s *rule)
{
    group_mutex_write_lock(&dnssec_policy_rule_definition_set_mtx);
    u32_node *node = u32_set_find(&dnssec_policy_rule_definition_set, rule->index);
    if(node != NULL)
    {
        if(node->value != NULL)
        {
            ZFREE(node->value, dnssec_policy_rule_definition_s);
        }
        
        u32_set_delete(&dnssec_policy_rule_definition_set, rule->index);
    }
    group_mutex_write_unlock(&dnssec_policy_rule_definition_set_mtx);
}

void
dnssec_policy_date_init_from_rule_definition(dnssec_policy_date *date, const dnssec_policy_rule_definition_s *rule_definition)
{
    
    date->type.type = ZONE_POLICY_RULE;
    dnssec_policy_rule_init(&date->rule, rule_definition);
}

/**
 * This complicated functions initialises a date with the earliest matching of the rule starting from 'from'
 *
 * @param date
 * @param from
 * @param rule
 *
 * @return an error code
 */
ya_result
dnssec_policy_date_init_from_date(dnssec_policy_date *date, const dnssec_policy_date *from, const dnssec_policy_date *rule)
{
    ya_result ret;

#if DEBUG
    format_writer from_fw = {dnssec_policy_date_format_handler_method, from};
    format_writer rule_fw = {dnssec_policy_date_format_handler_method, rule};
    format_writer date_fw = {dnssec_policy_date_format_handler_method, date};
#endif

    if(from->type.type != ZONE_POLICY_ABSOLUTE)
    {
#if DEBUG
        log_debug1("dnssec_policy_date_init_from_date(%p, %w, %w): can only work from an absolute time", date, &from_fw, &rule_fw);
#endif
        return POLICY_ILLEGAL_DATE_TYPE;
    }

    switch(rule->type.type)
    {
        case ZONE_POLICY_RELATIVE:
        {
            memcpy(date, from, sizeof(dnssec_policy_date));
#if DEBUG
            log_debug1("dnssec_policy_date_init_from_date(%p, %w, %w): initialising relative time", date, &from_fw, &rule_fw);
#endif
            ret = dnssec_policy_date_init_after_date(date, from, rule->relative.seconds); // +60 because it must be after and because of minute granularity
#if DEBUG
            log_debug1("dnssec_policy_date_init_from_date: %w = %w + %w", &date_fw, &from_fw, &rule_fw);
#endif
            return ret;
        }
        case ZONE_POLICY_RULE:
        {
#if DEBUG
            log_debug1("dnssec_policy_date_init_from_date(%p, %w, %w): initialising rule-based time", date, &from_fw, &rule_fw);
#endif
            ret = dnssec_policy_date_init_from_rule(date, from, rule);
#if DEBUG
            log_debug1("dnssec_policy_date_init_from_date: %w = %w + %w", &date_fw, &from_fw, &rule_fw);
#endif
            return ret;
        }
        default:
        {
#if DEBUG
            log_debug1("dnssec_policy_date_init_from_date(%p, %w, %w): unexpected type", date, &from_fw, &rule_fw);
#endif
            return POLICY_ILLEGAL_DATE_TYPE;
        }
    }
}

/**
 * This complicated functions initialises a date with the earliest matching of the rule starting after 'from'
 * 
 * @param date
 * @param from
 * @param rule
 * 
 * @return an error code
 */
ya_result
dnssec_policy_date_init_at_next_date(dnssec_policy_date *date, const dnssec_policy_date *from, const dnssec_policy_date *rule)
{
    ya_result ret;

#if DEBUG
    format_writer from_fw = {dnssec_policy_date_format_handler_method, from};
    format_writer rule_fw = {dnssec_policy_date_format_handler_method, rule};
    format_writer date_fw = {dnssec_policy_date_format_handler_method, date};
#endif
    
    if(from->type.type != ZONE_POLICY_ABSOLUTE)
    {
#if DEBUG
        log_debug1("dnssec_policy_date_init_at_next_date(%p, %w, %w): can only work from an absolute time", date, &from_fw, &rule_fw);
#endif
        return POLICY_ILLEGAL_DATE_TYPE;
    }
    
    switch(rule->type.type)
    {
        case ZONE_POLICY_RELATIVE:
        {
            memcpy(date, from, sizeof(dnssec_policy_date));
#if DEBUG
            log_debug1("dnssec_policy_date_init_at_next_date(%p, %w, %w): initialising relative time", date, &from_fw, &rule_fw);
#endif
            ret = dnssec_policy_date_init_from_date(date, from + 60, rule); // +60 because it must be after and because of minute granularity
#if DEBUG
            log_debug1("dnssec_policy_date_init_at_next_date: %w = %w + %w", &date_fw, &from_fw, &rule_fw);
#endif
            return ret;
        }
        case ZONE_POLICY_RULE:            
        {
#if DEBUG
            log_debug1("dnssec_policy_date_init_at_next_date(%p, %w, %w): initialising rule-based time", date, &from_fw, &rule_fw);
#endif
            ret = dnssec_policy_date_init_at_next_rule(date, from, rule);
#if DEBUG
            log_debug1("dnssec_policy_date_init_at_next_date: %w = %w + %w", &date_fw, &from_fw, &rule_fw);
#endif
            return ret;
        }
        default:
        {
#if DEBUG
            log_debug1("dnssec_policy_date_init_at_next_date(%p, %w, %w): unexpected type", date, &from_fw, &rule_fw);
#endif
            return POLICY_ILLEGAL_DATE_TYPE;
        }
    }
}

static dnssec_policy_date*
dnssec_policy_table_get_date_by_index(dnssec_policy_table_s *tbl, int index)
{
    switch(index)
    {
        case ZONE_POLICY_RELATIVE_TO_GENERATE:
            return &tbl->created;
        case ZONE_POLICY_RELATIVE_TO_PUBLISH:
            return &tbl->publish;
        case ZONE_POLICY_RELATIVE_TO_ACTIVATE:
            return &tbl->activate;
        case ZONE_POLICY_RELATIVE_TO_INACTIVE:
            return &tbl->inactive;
        case ZONE_POLICY_RELATIVE_TO_REMOVE:
            return &tbl->delete;
#if HAS_DS_PUBLICATION_SUPPORT
        case ZONE_POLICY_RELATIVE_TO_DS_PUBLISH:
            return &tbl->ds_publish;
        case ZONE_POLICY_RELATIVE_TO_DS_REMOVE:
            return &tbl->ds_remove;
#endif
        default:
            return NULL;
    }
}

ya_result
dnssec_policy_table_init_from_date(dnssec_policy_table_s *tbl, dnssec_policy_table_s *with, dnssec_policy_date *from)
{
    ya_result ret;
    
    if(with->created.type.type == ZONE_POLICY_RULE)
    {
        if(ISOK(ret = dnssec_policy_date_init_from_date(&tbl->created, from, &with->created)))
        {
            if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->publish, &tbl->created, &with->publish)))
            {
                if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->activate, &tbl->publish, &with->activate)))
                {
#if DEBUG
                    format_writer c_fw = {dnssec_policy_date_format_handler_method, &tbl->created};
                    format_writer p_fw = {dnssec_policy_date_format_handler_method, &tbl->publish};
                    format_writer a_fw = {dnssec_policy_date_format_handler_method, &tbl->activate};

                    log_debug("dnssec_policy_table_init: base c:%w => p:%w => a:%w", &c_fw, &p_fw, &a_fw);
#endif
                    // compute the future key timings to ensure there will be no period without a signature
                
                    dnssec_policy_date next_creation_date;
                    dnssec_policy_date next_publish_date;
                    dnssec_policy_date next_activate_date;

                    if(ISOK(ret = dnssec_policy_date_init_at_next_date(&next_creation_date, &tbl->activate, &with->created)))
                    {
                        if(ISOK(ret = dnssec_policy_date_init_at_next_date(&next_publish_date, &next_creation_date, &with->publish)))
                        {
                            if(ISOK(ret = dnssec_policy_date_init_at_next_date(&next_activate_date, &next_publish_date, &with->activate)))
                            {
#if DEBUG
                                format_writer na_fw = {dnssec_policy_date_format_handler_method, &next_activate_date};
                                format_writer np_fw = {dnssec_policy_date_format_handler_method, &next_publish_date};
                                format_writer nc_fw = {dnssec_policy_date_format_handler_method, &next_creation_date};

                                log_debug("dnssec_policy_table_init: next c:%w => p:%w => a:%w", &nc_fw, &np_fw, &na_fw);
#endif
                                if(ISOK(ret = dnssec_policy_date_init_from_date(&tbl->inactive, &next_activate_date, &with->inactive)))
                                {
#if HAS_DS_PUBLICATION_SUPPORT
                                    if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->delete, &tbl->inactive, &with->delete)))
                                    {
                                        if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->ds_add, &tbl->created, &with->ds_add)))
                                        {
                                            ret = dnssec_policy_date_init_at_next_date(&tbl->ds_del, &tbl->ds_add, &with->ds_del);
                                        }
                                    }
#else
                                    ret = dnssec_policy_date_init_at_next_date(&tbl->delete, &tbl->inactive, &with->delete);
#if DEBUG
                                    format_writer i_fw = {dnssec_policy_date_format_handler_method, &tbl->inactive};
                                    format_writer d_fw = {dnssec_policy_date_format_handler_method, &tbl->delete};

                                    log_debug("dnssec_policy_table_init: base i:%w => d:%w", &i_fw, &d_fw);
#endif
#endif
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else if(with->created.type.type == ZONE_POLICY_RELATIVE)
    {
        if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->created, from, &with->created))) // here !
        {
            if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->publish, &tbl->created, &with->publish)))
            {
                if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->activate, dnssec_policy_table_get_date_by_index(tbl, with->activate.relative.relativeto), &with->activate)))
                {
                    if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->inactive, dnssec_policy_table_get_date_by_index(tbl, with->inactive.relative.relativeto), &with->inactive)))
                    {
                        if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->delete, dnssec_policy_table_get_date_by_index(tbl, with->delete.relative.relativeto), &with->delete)))
                        {
                        }
                    }
                }
            }
        }
    }
    else
    {
        ret = POLICY_ILLEGAL_DATE_TYPE;
    }
    
    return ret;
}

ya_result
dnssec_policy_table_init_from_created_epoch(dnssec_policy_table_s *tbl, dnssec_policy_table_s *with, time_t created_epoch)
{
    ya_result ret;
    
    if(FAIL(ret = dnssec_policy_date_init_from_epoch(&tbl->created, created_epoch)))
    {
        return ret;
    }
    
    if(with->created.type.type == ZONE_POLICY_RULE)
    {
        if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->publish, &tbl->created, &with->publish)))
        {
            if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->activate, &tbl->publish, &with->activate)))
            {
#if DEBUG
                format_writer c_fw = {dnssec_policy_date_format_handler_method, &tbl->created};
                format_writer p_fw = {dnssec_policy_date_format_handler_method, &tbl->publish};
                format_writer a_fw = {dnssec_policy_date_format_handler_method, &tbl->activate};

                log_debug("dnssec_policy_table_init: base %w => %w => %w", &c_fw, &p_fw, &a_fw);
#endif
                // compute the future key timings to ensure there will be no period without a signature

                dnssec_policy_date next_creation_date;
                dnssec_policy_date next_publish_date;
                dnssec_policy_date next_activate_date;

                if(ISOK(ret = dnssec_policy_date_init_at_next_date(&next_creation_date, &tbl->activate, &with->created)))
                {
                    if(ISOK(ret = dnssec_policy_date_init_at_next_date(&next_publish_date, &next_creation_date, &with->publish)))
                    {
                        if(ISOK(ret = dnssec_policy_date_init_at_next_date(&next_activate_date, &next_publish_date, &with->activate)))
                        {
#if DEBUG
                            format_writer na_fw = {dnssec_policy_date_format_handler_method, &next_activate_date};
                            format_writer np_fw = {dnssec_policy_date_format_handler_method, &next_publish_date};
                            format_writer nc_fw = {dnssec_policy_date_format_handler_method, &next_creation_date};

                            log_debug("dnssec_policy_table_init: next %w => %w => %w", &nc_fw, &np_fw, &na_fw);
#endif
                            if(ISOK(ret = dnssec_policy_date_init_from_date(&tbl->inactive, &next_activate_date, &with->inactive)))
                            {
#if HAS_DS_PUBLICATION_SUPPORT
                                if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->delete, &tbl->inactive, &with->delete)))
                                {
                                    if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->ds_add, &tbl->created, &with->ds_add)))
                                    {
                                        ret = dnssec_policy_date_init_at_next_date(&tbl->ds_del, &tbl->ds_add, &with->ds_del);
                                    }
                                }
#else
                                ret = dnssec_policy_date_init_at_next_date(&tbl->delete, &tbl->inactive, &with->delete);
#endif
                            }
                        }
                    }
                }
            }
        }
    }
    else if(with->created.type.type == ZONE_POLICY_RELATIVE)
    {
        if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->publish, &tbl->created, &with->publish)))
        {
            if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->activate, dnssec_policy_table_get_date_by_index(tbl, with->activate.relative.relativeto), &with->activate)))
            {
                if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->inactive, dnssec_policy_table_get_date_by_index(tbl, with->inactive.relative.relativeto), &with->inactive)))
                {
                    if(ISOK(ret = dnssec_policy_date_init_at_next_date(&tbl->delete, dnssec_policy_table_get_date_by_index(tbl, with->delete.relative.relativeto), &with->delete)))
                    {
                    }
                }
            }
        }
    }
    else
    {
        ret = POLICY_ILLEGAL_DATE_TYPE;
    }
    
    return ret;
}

static bool
dnssec_policy_key_roll_matches(const struct dnssec_policy_key_suite *kr, const dnssec_key *key)
{
    yassert((kr->key->flags == DNSKEY_FLAGS_KSK) || (kr->key->flags == DNSKEY_FLAGS_ZSK));
    
    if(dnskey_get_algorithm(key) == kr->key->algorithm)
    {
        // matches flags

        if((dnskey_get_flags(key) & DNSKEY_FLAGS_KSK) == kr->key->flags)
        {
            int key_size = dnskey_get_size(key);
            
            if((key_size - kr->key->size) < 48)
            {
                // algorithm, flags and size are matching
                // now what about the times
                
                if((key->epoch_created != 0) &&
                   (key->epoch_publish != 0) &&
                   (key->epoch_activate != 0) &&
                   (key->epoch_inactive != 0) &&
                   (key->epoch_delete != 0))
                {
                    log_debug1("dnssec-policy: %s: %s: key %05d/%d timings: %U %U %U %U %U",
                            key->origin,
                            kr->name,
                            dnskey_get_tag_const(key), ntohs(key->flags),
                            key->epoch_created, key->epoch_publish, key->epoch_activate, key->epoch_inactive, key->epoch_delete);
                    
                    dnssec_policy_table_s key_tbl;
                    // kr->roll->time_table.created.type
                    //dnssec_policy_table_init_from_epoch(&key_tbl, &kr->roll->time_table, key->epoch_created); // .. 33900

                                 //dnssec_policy_table_init_from_date(dnssec_policy_table_s *tbl, dnssec_policy_table_s *with, dnssec_policy_date *from)
                    if(ISOK(dnssec_policy_table_init_from_created_epoch(&key_tbl, &kr->roll->time_table, key->epoch_created)))
                    {
                        time_t key_created = 0, key_publish = 0, key_activate = 0, key_inactive = 0, key_delete = 0;
                        dnssec_policy_date_get_epoch(&key_tbl.created, &key_created);
                        dnssec_policy_date_get_epoch(&key_tbl.publish, &key_publish);
                        dnssec_policy_date_get_epoch(&key_tbl.activate, &key_activate);
                        dnssec_policy_date_get_epoch(&key_tbl.inactive, &key_inactive);
                        dnssec_policy_date_get_epoch(&key_tbl.delete, &key_delete);

                        u32 margin = keyroll_deactivation_margin(key_activate, key_inactive, key_delete);

                        s64 pait = (key_inactive + margin) - key_activate;
                        s64 kait = key->epoch_inactive - key->epoch_activate;
                        s64 dait = labs(pait - kait);

                        s64 pidt = key_delete - (key_inactive + margin);
                        s64 kidt = key->epoch_delete - key->epoch_inactive;
                        s64 didt = labs(pidt - kidt);

                        s64 dc = labs(key_created - key->epoch_created);
                        s64 dp = labs(key_publish - key->epoch_publish);
                        s64 da = labs(key_activate - key->epoch_activate);
                        s64 di = labs((key_inactive + margin) - key->epoch_inactive);
                        s64 dd = labs(key_delete - key->epoch_delete);

                        //bool match = (/*dc < KEY_POLICY_EPOCH_MATCH_MARGIN &&*/ dp < KEY_POLICY_EPOCH_MATCH_MARGIN && da < KEY_POLICY_EPOCH_MATCH_MARGIN && di < KEY_POLICY_EPOCH_MATCH_MARGIN && dd < KEY_POLICY_EPOCH_MATCH_MARGIN);

                        // This checks if the key matches were it counts.  We already know flags & size are a match, now if it lives long enough and is deleted in time, then it is a match.
                        // The next key generation will have to align to these timings to find when will be the next one.

                        bool match = (dait < KEY_POLICY_EPOCH_MATCH_MARGIN) && (didt < KEY_POLICY_EPOCH_MATCH_MARGIN);

                        log_debug2("dnssec-policy: %s: %s: key %05d/%d pkd: ai=%lli id=%lli, with a margin of %lli",
                                   key->origin,
                                   kr->name,
                                   dnskey_get_tag_const(key), ntohs(key->flags), dait, didt, KEY_POLICY_EPOCH_MATCH_MARGIN);

                        log_debug2("dnssec-policy: %s: %s: key %05d/%d deltas: (%lli) %lli %lli %lli %lli, with a margin of %lli",
                                   key->origin,
                                   kr->name,
                                   dnskey_get_tag_const(key), ntohs(key->flags), dc, dp, da, di, dd, KEY_POLICY_EPOCH_MATCH_MARGIN);

                        log_debug1("dnssec-policy: %s: %s: key %05d/%d expects: %U %U %U %U %U : %s",
                                key->origin,
                                kr->name,
                                dnskey_get_tag_const(key), ntohs(key->flags),
                                key_created, key_publish, key_activate, key_inactive, key_delete,
                                ((match)?"MATCH":"DIFFERS"));

                        return match;
                    } // else dnssec_policy_table_init_from_created_epoch failed and something is wrong => false
                    else
                    {
                        log_err("dnssec-policy: %s: %s: key %05d/%d matching triggered an error in dnssec_policy_table_init_from_created_epoch",
                                   key->origin,
                                   kr->name,
                                   dnskey_get_tag_const(key), ntohs(key->flags));
                    }
                }
                else
                {
                    log_debug1("dnssec-policy: %s: %s: key %05d/%d is not a match as it has no time table (skipping)",
                            key->origin,
                            kr->name,
                            dnskey_get_tag_const(key), ntohs(key->flags));
                }
            }
            else
            {
                log_debug1("dnssec-policy: %s: %s: key %05d/%d of size %i is not a match as the expected size is %i (skipping for this key roll)",
                            key->origin,
                            kr->name,
                            dnskey_get_tag_const(key), ntohs(key->flags), key_size, kr->key->size);
            }
        }
        else
        {
            log_debug1("dnssec-policy: %s: %s: key %05d/%d is not a match as the expected flags is %i (skipping for this key roll)",
                            key->origin,
                            kr->name,
                            dnskey_get_tag_const(key), ntohs(key->flags), ntohs(kr->key->flags));
        }
    }
    else
    {
        log_debug1("dnssec-policy: %s: %s: key %05d/%d is not a match as the expected algorithm is %i (skipping for this key roll)",
                            key->origin,
                            kr->name,
                            dnskey_get_tag_const(key), ntohs(key->flags), kr->key->algorithm);
    }
    
    return FALSE;
}

/**
 * Compares keys by activation time, inactivation time and tag.
 * Handles 0 epoch as "never" (as expected)
 * 
 * @param a_
 * @param b_
 * @return 
 */

static int dnssec_policy_dnssec_key_ptr_vector_qsort_by_activation_time_callback(const void *a_, const void *b_)
{
    const dnssec_key *a = (const dnssec_key*)a_;
    const dnssec_key *b = (const dnssec_key*)b_;

    if(a == b)
    {
        return 0;
    }
    
    s64 a_a = a->epoch_activate;
    if(a_a == 0)
    {
        a_a = DNSSEC_POLICY_EPOCH_DOOMSDAY;
    }
    
    s64 b_a = b->epoch_activate;
    if(b_a == 0)
    {
        b_a = DNSSEC_POLICY_EPOCH_DOOMSDAY;
    }
    
    s64 r = a_a - b_a;
    
    if(r == 0)
    {
        s64 a_i = a->epoch_inactive;
        if(a_i == 0)
        {
            a_i = DNSSEC_POLICY_EPOCH_DOOMSDAY;
        }

        s64 b_i = b->epoch_inactive;
        if(b_i == 0)
        {
            b_i = DNSSEC_POLICY_EPOCH_DOOMSDAY;
        }
        
        r = a_i - b_i;
        
        if(r == 0)
        {
            r = dnskey_get_tag_const(a) - dnskey_get_tag_const(b);

            if(r == 0)
            {
                r = dnskey_get_algorithm(a) - dnskey_get_algorithm(b);

                if(r == 0)
                {
                    u8 a_bytes[1024];
                    u8 b_bytes[1024];
                    u32 a_size = a->vtbl->dnssec_key_writerdata(a, a_bytes, sizeof(a_bytes));
                    u32 b_size = b->vtbl->dnssec_key_writerdata(b, b_bytes, sizeof(b_bytes));

                    r = a_size - b_size;

                    if(r == 0)
                    {
                        r = memcmp(a_bytes, b_bytes, a_size);
                    }
                }
            }
        }
    }
    
    return r;
}

static void
dnssec_policy_log_debug_key(const char *prefix, const dnssec_key *key)
{
    EPOCHZ_DEF2(created, key->epoch_created);
    EPOCHZ_DEF2(publish, key->epoch_publish);
    EPOCHZ_DEF2(activate, key->epoch_activate);
    EPOCHZ_DEF2(inactive, key->epoch_inactive);
    EPOCHZ_DEF2(delete, key->epoch_delete);
#if 0 /* fix */
#else
    log_debug("%sK%{dnsname}+%03d+%05d/%d created=%1w publish=%1w activate=%1w inactive=%1w delete=%1w",
            prefix,
            key->owner_name,
            key->algorithm,
            dnskey_get_tag_const(key),
            ntohs(key->flags),
            EPOCHZ_REF(created),
            EPOCHZ_REF(publish),
            EPOCHZ_REF(activate),
            EPOCHZ_REF(inactive),
            EPOCHZ_REF(delete));
#endif
}

#if 0
static void
dnssec_policy_print_key(const char *prefix, const dnssec_key *key)
{
    EPOCHZ_DEF2(created, key->epoch_created);
    EPOCHZ_DEF2(publish, key->epoch_publish);
    EPOCHZ_DEF2(activate, key->epoch_activate);
    EPOCHZ_DEF2(inactive, key->epoch_inactive);
    EPOCHZ_DEF2(delete, key->epoch_delete);
#if 0 /* fix */
#else
    formatln("%sK%{dnsname}+%03d+%05d/%d created=%1w publish=%1w activate=%1w inactive=%1w delete=%1w",
              prefix,
              key->owner_name,
              key->algorithm,
              dnskey_get_tag_const(key),
              ntohs(key->flags),
              EPOCHZ_REF(created),
              EPOCHZ_REF(publish),
              EPOCHZ_REF(activate),
              EPOCHZ_REF(inactive),
              EPOCHZ_REF(delete));
#endif
}
#endif

ya_result
dnssec_policy_roll_create_from_rules(const char *id,
                                   const dnssec_policy_rule_definition_s *generate,
                                   const dnssec_policy_rule_definition_s *publish,
                                   const dnssec_policy_rule_definition_s *activate,
                                   const dnssec_policy_rule_definition_s *inactive,
                                   const dnssec_policy_rule_definition_s *remove,
                                   const dnssec_policy_rule_definition_s *ds_publish,
                                   const dnssec_policy_rule_definition_s *ds_remove)
{
    log_debug("dnssec-policy-roll: %s: (rules stuff)", id);
    
    dnssec_policy_roll *dpr;
    ZALLOC_OBJECT_OR_DIE( dpr, dnssec_policy_roll, DPOLROLL_TAG);
    dpr->name = strdup(id);
    
    group_mutex_write_lock(&dnssec_policy_roll_set_mtx);
    ptr_node *node = ptr_set_insert(&dnssec_policy_roll_set, dpr->name);
    
    if(node->value != NULL)
    {
        dnssec_policy_roll_release((dnssec_policy_roll*)node->value);
        node->key = dpr->name;
    }

    dnssec_policy_rule_init(&dpr->time_table.created.rule, generate);
    dnssec_policy_rule_init(&dpr->time_table.publish.rule, publish);
    dnssec_policy_rule_init(&dpr->time_table.activate.rule, activate);
    dnssec_policy_rule_init(&dpr->time_table.inactive.rule, inactive);
    dnssec_policy_rule_init(&dpr->time_table.delete.rule, remove);
#if HAS_DS_PUBLICATION_SUPPORT
    dnssec_policy_rule_init(&dpr->time_table.ds_add.rule, ds_publish);
    dnssec_policy_rule_init(&dpr->time_table.ds_del.rule, ds_remove);
#else
    (void)ds_publish;
    (void)ds_remove;
#endif
    dpr->rc = 1;
    node->value = dpr;
    
    group_mutex_write_unlock(&dnssec_policy_roll_set_mtx);
    return 0;
}

ya_result
dnssec_policy_roll_create_from_relatives(const char *id,
                                       const dnssec_policy_relative_s *generate,
                                       u8 generate_from,
                                       const dnssec_policy_relative_s *publish,
                                       u8 publish_from,
                                       const dnssec_policy_relative_s *activate,
                                       u8 activate_from,
                                       const dnssec_policy_relative_s *inactive,
                                       u8 inactive_from,
                                       const dnssec_policy_relative_s *remove,
                                       u8 remove_from
#if HAS_DS_PUBLICATION_SUPPORT
                                       ,
                                       const dnssec_policy_relative_s *ds_publish,
                                       u8 ds_publish_from,
                                       const dnssec_policy_relative_s *ds_remove,
                                       u8 ds_remove_from
#endif
                                       )
{
    log_debug("dnssec-policy-roll: %s: (relative stuff)", id);
    
    if(generate->seconds < 60)
    {
        log_err("dnssec-policy: %s: generate parameter cannot be less than one minute", id);
        return POLICY_ILLEGAL_DATE_PARAMETERS;
    }
    
    if(inactive->seconds - activate->seconds < 60)
    {
        log_err("dnssec-policy: %s: key appears to not be activated for even one minute", id);
        return POLICY_ILLEGAL_DATE_PARAMETERS;
    }
       
    if(generate->seconds < 3600)
    {
        log_warn("dnssec-policy: %s: key is generated every %i seconds.  Keys are expected to be generated every few weeks, months or years.", id, generate->seconds);
    }
    
    if(inactive->seconds - activate->seconds < generate->seconds)
    {
        log_warn("dnssec-policy: %s: key appears to not be activated for less time than the generation period", id);
    }
    
    dnssec_policy_roll *dpr;
    ZALLOC_OBJECT_OR_DIE( dpr, dnssec_policy_roll, DPOLROLL_TAG);
    dpr->name = strdup(id);
    
    group_mutex_write_lock(&dnssec_policy_roll_set_mtx);
    ptr_node *node = ptr_set_insert(&dnssec_policy_roll_set, dpr->name);
    
    if(node->value != NULL)
    {
        dnssec_policy_roll_release((dnssec_policy_roll*)node->value);
        node->value = NULL;
    }
        
    dpr->time_table.created.relative = *generate;
    dpr->time_table.publish.relative = *publish;
    dpr->time_table.activate.relative = *activate;
    dpr->time_table.inactive.relative = *inactive;
    dpr->time_table.delete.relative = *remove;
    
    dpr->time_table.created.relative.seconds += 59;
    dpr->time_table.created.relative.seconds -= (dpr->time_table.created.relative.seconds % 60);
    
    dpr->time_table.publish.relative.seconds += 59;
    dpr->time_table.publish.relative.seconds -= (dpr->time_table.publish.relative.seconds % 60);
    
    dpr->time_table.activate.relative.seconds += 59;
    dpr->time_table.activate.relative.seconds -= (dpr->time_table.activate.relative.seconds % 60);
    
    dpr->time_table.inactive.relative.seconds += 59;
    dpr->time_table.inactive.relative.seconds -= (dpr->time_table.inactive.relative.seconds % 60);
    
    dpr->time_table.delete.relative.seconds += 59;
    dpr->time_table.delete.relative.seconds -= (dpr->time_table.delete.relative.seconds % 60);
    
#if HAS_DS_PUBLICATION_SUPPORT
    dpr->time_table.ds_add.relative = *ds_publish;
    dpr->time_table.ds_del.relative = *ds_remove;
#endif
    
    yassert(publish_from <= ZONE_POLICY_RELATIVE_TO_GENERATE);
    yassert(activate_from <= ZONE_POLICY_RELATIVE_TO_PUBLISH);
    yassert(inactive_from <= ZONE_POLICY_RELATIVE_TO_INACTIVE);
    yassert(remove_from <= ZONE_POLICY_RELATIVE_TO_REMOVE);
#if HAS_DS_PUBLICATION_SUPPORT
    yassert(ds_publish_from <= ZONE_POLICY_RELATIVE_TO_DS_PUBLISH);
    yassert(ds_remove_from <= ZONE_POLICY_RELATIVE_TO_DS_REMOVE);
#endif
        
    dpr->time_table.created.relative.relativeto = generate_from;
    dpr->time_table.publish.relative.relativeto = publish_from;
    dpr->time_table.activate.relative.relativeto = activate_from;
    dpr->time_table.inactive.relative.relativeto = inactive_from;
    dpr->time_table.delete.relative.relativeto = remove_from;
#if HAS_DS_PUBLICATION_SUPPORT
    dpr->time_table.ds_add.relative.relativeto = ds_publish_from;
    dpr->time_table.ds_del.relative.relativeto = ds_remove_from;
#endif
    
    dpr->rc = 1;
    node->key = dpr->name;
    node->value = dpr;
    
    group_mutex_write_unlock(&dnssec_policy_roll_set_mtx);

    return 0;
}

dnssec_policy_roll *
dnssec_policy_roll_acquire_from_name(const char *id)
{
    dnssec_policy_roll *dpr = NULL;

    group_mutex_read_lock(&dnssec_policy_roll_set_mtx);
    
    ptr_node *node = ptr_set_find(&dnssec_policy_roll_set, id);
    if(node != NULL)
    {
        dpr = (dnssec_policy_roll*)node->value;
        group_mutex_write_lock(&dnssec_policy_roll_mtx);
        ++dpr->rc;
        group_mutex_write_unlock(&dnssec_policy_roll_mtx);
    }
    
    group_mutex_read_unlock(&dnssec_policy_roll_set_mtx);

    return dpr;
}

#if 0
ya_result
dnssec_policy_roll_test_all(time_t active_at, u32 duration_seconds, bool print_text, bool log_text)
{
    group_mutex_read_lock(&dnssec_policy_roll_set_mtx);

    ptr_set_iterator iter;
    ptr_set_iterator_init(&dnssec_policy_roll_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        if(index == 0)
        {
            if(node->value != NULL)
            {
                dnssec_policy_roll *dpr = (dnssec_policy_roll*)node->value;
                group_mutex_write_lock(&dnssec_policy_roll_mtx);
                ret = dnssec_policy_key_roll_test( dpr, active_at, duration_seconds, print_text, log_text);
                group_mutex_write_unlock(&dnssec_policy_roll_mtx);
            }
            break;
        }

        --index;
    }

    group_mutex_read_unlock(&dnssec_policy_roll_set_mtx);
}
#endif

dnssec_policy_roll *
dnssec_policy_roll_acquire_from_index(int index)
{
    dnssec_policy_roll *dpr = NULL;

    if(index >= 0)
    {
        group_mutex_read_lock(&dnssec_policy_roll_set_mtx);

        ptr_set_iterator iter;
        ptr_set_iterator_init(&dnssec_policy_roll_set, &iter);
        while(ptr_set_iterator_hasnext(&iter))
        {
            ptr_node *node = ptr_set_iterator_next_node(&iter);
            if(index == 0)
            {
                if(node->value != NULL)
                {
                    dpr = (dnssec_policy_roll*)node->value;
                    group_mutex_write_lock(&dnssec_policy_roll_mtx);
                    ++dpr->rc;
                    group_mutex_write_unlock(&dnssec_policy_roll_mtx);
                }

                break;
            }

            --index;
        }

        group_mutex_read_unlock(&dnssec_policy_roll_set_mtx);
    }

    return dpr;
}


void
dnssec_policy_roll_release(dnssec_policy_roll *dpr)
{
    group_mutex_write_lock(&dnssec_policy_roll_mtx);
    if(--dpr->rc == 0)
    {
        // destroy the table
        if(dpr->time_table.created.type.type == ZONE_POLICY_RULE)
        {
            dnssec_policy_rule_finalize(&dpr->time_table.created.rule);
        }
        if(dpr->time_table.publish.type.type == ZONE_POLICY_RULE)
        {
            dnssec_policy_rule_finalize(&dpr->time_table.publish.rule);
        }
        if(dpr->time_table.activate.type.type == ZONE_POLICY_RULE)
        {
            dnssec_policy_rule_finalize(&dpr->time_table.activate.rule);
        }
        if(dpr->time_table.inactive.type.type == ZONE_POLICY_RULE)
        {
            dnssec_policy_rule_finalize(&dpr->time_table.inactive.rule);
        }
        if(dpr->time_table.delete.type.type == ZONE_POLICY_RULE)
        {
            dnssec_policy_rule_finalize(&dpr->time_table.delete.rule);
        }
#if HAS_DS_PUBLICATION_SUPPORT
        if(dpr->time_table.ds_add.type.type == ZONE_POLICY_RULE)
        {
            dnssec_policy_rule_finalize(&dpr->time_table.ds_add.rule);
        }
        if(dpr->time_table.ds_del.type.type == ZONE_POLICY_RULE)
        {
            dnssec_policy_rule_finalize(&dpr->time_table.ds_del.rule);
        }
#endif
        free(dpr->name);
        ZFREE_OBJECT(dpr);
    }
    group_mutex_write_unlock(&dnssec_policy_roll_mtx);
}

dnssec_policy_key *
dnssec_policy_key_create(const char *id, u8 algorithm, u16 size, bool ksk, char* engine)
{
    log_debug("dnssec-policy-key: %s: algorithm=%hhu, size=%hu, ksk=%i, engine=%s",
            id, algorithm, size, ksk, STRNULL(engine));
    
    (void)engine;
    dnssec_policy_key *dpk = NULL;

    ZALLOC_OBJECT_OR_DIE( dpk, dnssec_policy_key, DPOLKEY_TAG);
    dpk->name = strdup(id);
    
    dpk->flags = (ksk)?DNSKEY_FLAGS_KSK:DNSKEY_FLAGS_ZSK;
    dpk->size = size;
    dpk->algorithm = algorithm;
    dpk->rc = 1;
    
    group_mutex_write_lock(&dnssec_policy_key_set_mtx);
    ptr_node *node = ptr_set_insert(&dnssec_policy_key_set, dpk->name);
    if(node->value != NULL)
    {
        dnssec_policy_key_release((dnssec_policy_key*)node->value);
        node->key = dpk->name;
    }
    node->value = dpk;
    group_mutex_write_unlock(&dnssec_policy_key_set_mtx);

    return dpk;
}

dnssec_policy_key *
dnssec_policy_key_acquire_from_name(const char *id)
{
    dnssec_policy_key *dpk = NULL;

    group_mutex_read_lock(&dnssec_policy_key_set_mtx);
    ptr_node *node = ptr_set_find(&dnssec_policy_key_set, id);
    if(node != NULL && node->value != NULL)
    {
        dpk = (dnssec_policy_key*)node->value;
        group_mutex_write_lock(&dnssec_policy_key_mtx);
        ++dpk->rc;
        group_mutex_write_unlock(&dnssec_policy_key_mtx);
    }
    group_mutex_read_unlock(&dnssec_policy_key_set_mtx);
    return dpk;
}

void
dnssec_policy_key_release(dnssec_policy_key *dpk)
{
    group_mutex_write_lock(&dnssec_policy_key_mtx);
    if(--dpk->rc == 0)
    {
        free(dpk->name);
        ZFREE_OBJECT(dpk);
    }
    group_mutex_write_unlock(&dnssec_policy_key_mtx);
}

dnssec_policy_key_suite *
dnssec_policy_key_suite_create(const char *id, dnssec_policy_key *dpk, dnssec_policy_roll *dpr)
{
    log_debug("dnssec-policy-key-suite: %s: policy-key=%s, policy-roll=%s", id, dpk->name, dpk->name, dpr->name);
    
    dnssec_policy_key_suite *dpks = NULL;

    ZALLOC_OBJECT_OR_DIE( dpks, dnssec_policy_key_suite, DPOLKYST_TAG);
    dpks->name = strdup(id);
    dpks->key = dnssec_policy_key_acquire_from_name(dpk->name);
    dpks->roll = dnssec_policy_roll_acquire_from_name(dpr->name);
    dpks->rc = 1;
    
    group_mutex_write_lock(&dnssec_policy_key_suite_set_mtx);
    ptr_node *node = ptr_set_insert(&dnssec_policy_key_suite_set, dpks->name);
    if(node->value != NULL)
    {
        dnssec_policy_key_suite_release((dnssec_policy_key_suite*)node->value);
    }
    node->key = dpks->name;
    node->value = dpks;
    group_mutex_write_unlock(&dnssec_policy_key_suite_set_mtx);

    return dpks;
}

dnssec_policy_key_suite *
dnssec_policy_key_suite_acquire_from_name(const char *id)
{
    dnssec_policy_key_suite *dpks = NULL;

    group_mutex_read_lock(&dnssec_policy_key_suite_set_mtx);
    ptr_node *node = ptr_set_find(&dnssec_policy_key_suite_set, id);
    if(node != NULL && node->value != NULL)
    {
        dpks = (dnssec_policy_key_suite*)node->value;
        group_mutex_write_lock(&dnssec_policy_key_suite_mtx);
        ++dpks->rc;
        group_mutex_write_unlock(&dnssec_policy_key_suite_mtx);
    }
    group_mutex_read_unlock(&dnssec_policy_key_suite_set_mtx);
    return dpks;
}

void
dnssec_policy_key_suite_acquire(dnssec_policy_key_suite *dpks)
{
    group_mutex_write_lock(&dnssec_policy_key_suite_mtx);
    ++dpks->rc;
    group_mutex_write_unlock(&dnssec_policy_key_suite_mtx);
}


void
dnssec_policy_key_suite_release(dnssec_policy_key_suite *dpks)
{
    group_mutex_write_lock(&dnssec_policy_key_suite_mtx);
    if(--dpks->rc == 0)
    {
        free(dpks->name);
        dnssec_policy_key_release(dpks->key);
        dnssec_policy_roll_release(dpks->roll);
        ZFREE_OBJECT(dpks);
    }
    group_mutex_write_unlock(&dnssec_policy_key_suite_mtx);
}

static int ptr_vector_qsort_key_suite_callback(const void *ptr1, const void *ptr2)
{
    const dnssec_policy_key_suite *ks1 = (const dnssec_policy_key_suite*)ptr1;
    const dnssec_policy_key_suite *ks2 = (const dnssec_policy_key_suite*)ptr2;

    if(ks1->key != NULL)
    {
        if(ks2->key != NULL)
        {
            int f1 = ntohs(ks1->key->flags);
            int f2 = ntohs(ks2->key->flags);

            int ret = f2 - f1; // KSK before ZSK

            if(ret == 0)
            {
                ret = ks2->key->algorithm - ks1 ->key->algorithm; // recent algorithms before older ones
                if(ret == 0)
                {
                    ret = ks2->key->size - ks1->key->size;
                    if(ret == 0)
                    {
                        ret = strcmp(ks1->name, ks2->name);
                    }
                }
            }

            return ret;
        }
        else
        {
            return 1;
        }
    }
    else
    {
        if(ks2->key != NULL)
        {
            return -1;
        }
        else
        {
            return 0;
        }
    }
}

dnssec_policy *
dnssec_policy_create(char *name, ptr_vector *key_suite)
{
    dnssec_policy *dp = NULL;

    log_debug("dnssec-policy: %s", name);

    bool has_zsk = FALSE;
    ZALLOC_OBJECT_OR_DIE( dp, dnssec_policy, DNSECPOL_TAG);
    dp->name = strdup(name);
    ptr_vector_init_ex(&dp->key_suite, ptr_vector_size(key_suite));
    for(int i = 0; i <= ptr_vector_last_index(key_suite); ++i)
    {
        dnssec_policy_key_suite *dpks = (dnssec_policy_key_suite*)ptr_vector_get(key_suite, i);
        if((dpks->key->flags & DNSKEY_FLAGS_KSK) != DNSKEY_FLAGS_KSK)
        {
            has_zsk = TRUE;
        }
        
        dnssec_policy_key_suite *dpks_a = dnssec_policy_key_suite_acquire_from_name(dpks->name);
        
        for(int j = 0; j <= ptr_vector_last_index(&dp->key_suite); ++j)
        {
            dnssec_policy_key_suite* dpks_b = (dnssec_policy_key_suite*)ptr_vector_get(&dp->key_suite, j);
            if(dpks_a == dpks_b)
            {
                // dup
                log_warn("dnssec-policy: %s: key-suite %s is a duplicate entry", name, dpks->name);
                dnssec_policy_key_suite_release(dpks_a);
                dpks_a = NULL;
                break;
            }
        }
        
        if(dpks_a != NULL)
        {
            ptr_vector_append(&dp->key_suite, dpks_a);
            log_debug("dnssec-policy: %s: key-suite %s added", name, dpks->name);
        }
    }

    dp->rc = 1;

    ptr_vector_qsort(&dp->key_suite, ptr_vector_qsort_key_suite_callback);
    
    if(has_zsk)
    {
        log_warn("dnssec-policy: %s: no key-signing-key in the key-suite", name);
    }
    
    group_mutex_write_lock(&dnssec_policy_set_mtx);
    ptr_node *node = ptr_set_insert(&dnssec_policy_set, dp->name);
    if(node->value != NULL)
    {
        dnssec_policy_release((dnssec_policy*)node->value);
        node->key = dp->name;
    }
    node->value = dp;
    group_mutex_write_unlock(&dnssec_policy_set_mtx);
    
    return dp;
}

dnssec_policy *
dnssec_policy_acquire_from_name(const char *id)
{
    dnssec_policy *dp = NULL;

    group_mutex_read_lock(&dnssec_policy_set_mtx);
    ptr_node *node = ptr_set_find(&dnssec_policy_set, id);
    if(node != NULL && node->value != NULL)
    {
        dp = (dnssec_policy*)node->value;
        group_mutex_write_lock(&dnssec_policy_mtx);
        ++dp->rc;
        group_mutex_write_unlock(&dnssec_policy_mtx);
    }
    group_mutex_read_unlock(&dnssec_policy_set_mtx);
    return dp;
}

void
dnssec_policy_acquire(dnssec_policy *dp)
{
    group_mutex_write_lock(&dnssec_policy_mtx);
    ++dp->rc;
    group_mutex_write_unlock(&dnssec_policy_mtx);
}

void
dnssec_policy_release(dnssec_policy *dp)
{
    group_mutex_write_lock(&dnssec_policy_mtx);
    if(--dp->rc == 0)
    {
        free(dp->name);
        for(int i = 0; i <= ptr_vector_last_index(&dp->key_suite); ++i)
        {
            dnssec_policy_key_suite *dpks = (dnssec_policy_key_suite*)ptr_vector_get(&dp->key_suite, i);
            dnssec_policy_key_suite_release(dpks);
        }
        ZFREE_OBJECT(dp);
    }
    group_mutex_write_unlock(&dnssec_policy_mtx);
}

ya_result
dnssec_policy_zone_desc_config(const char *value, void *dest, anytype sizeoftarget)
{
    (void)sizeoftarget;
    dnssec_policy **dp = (dnssec_policy**)dest;
    if(*dp != NULL)
    {
        dnssec_policy_release(*dp);
    }
    if(value != NULL)
    {
        *dp = dnssec_policy_acquire_from_name(value);
        return (*dp != NULL)?SUCCESS:POLICY_UNDEFINED;
    }
    else
    {
        return POLICY_NULL_REQUESTED;
    }
}

static void
dnssec_policy_process_release_keys_cb(void *ptr)
{
    dnssec_key *key = (dnssec_key*)ptr;
    if(key != NULL)
    {
        dnskey_release(key);
    }
}

static ya_result
dnssec_policy_key_roll_keys_generate_at(keyroll_t *keyroll, struct dnssec_policy_key_suite *kr, ptr_vector *key_roll_keys_vector, time_t now)
{
    const u8 *origin = keyroll->domain;
    ya_result ret = ERROR;

    log_debug("dnssec-policy: %{dnsname}: %s: key suite has %i matching keys", origin, kr->name, ptr_vector_size(key_roll_keys_vector));

    if(ptr_vector_size(key_roll_keys_vector) > 0)
    {
        // sort array by time

        if(ptr_vector_last_index(key_roll_keys_vector) > 0) // more than one item in the collection
        {
            ptr_vector_qsort(key_roll_keys_vector, dnssec_policy_dnssec_key_ptr_vector_qsort_by_activation_time_callback);
        }

        // ensure we have continuity
        // start with a base period

        dnssec_key *previous_key = NULL;
        s64 previous_begin_period;
        s64 previous_next_period;
        s64 previous_end_period;

        {
            previous_key = (dnssec_key*)ptr_vector_get(key_roll_keys_vector, 0);
#if DEBUG
            log_debug("dnssec-policy: %s: %s: key %05d/%d timings: %U %U %U %U %U [0]",
                      previous_key->origin,
                      kr->name,
                      dnskey_get_tag_const(previous_key), ntohs(previous_key->flags),
                      previous_key->epoch_created, previous_key->epoch_publish, previous_key->epoch_activate, previous_key->epoch_inactive, previous_key->epoch_delete);
#endif

            previous_begin_period = previous_key->epoch_activate;
            previous_next_period = previous_begin_period;
            previous_end_period = previous_key->epoch_inactive;
        }

        log_debug("dnssec-policy: %{dnsname}: %s: first key will be inactive at %U", origin, kr->name, previous_end_period);

        for(int i = 1; i <= ptr_vector_last_index(key_roll_keys_vector); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(key_roll_keys_vector, i);

            bool print_details = (i > MAX(0, ptr_vector_last_index(key_roll_keys_vector) - 3));

#if DEBUG
            if(print_details)
            {
                log_debug("dnssec-policy: %s: %s: key %05d/%d timings: %U %U %U %U %U [%i / %i]",
                          key->origin,
                          kr->name,
                          dnskey_get_tag_const(key), ntohs(key->flags),
                          key->epoch_created, key->epoch_publish, key->epoch_activate, key->epoch_inactive, key->epoch_delete, i, ptr_vector_last_index(key_roll_keys_vector));
            }
#endif
            previous_next_period = key->epoch_activate;

            // ensure the key chains with this interval
            if(key->epoch_activate > previous_end_period /*|| key->epoch_inactive < begin_period irrelevant because of the sort */)
            {
                // bad
                log_err("dnssec-policy: %{dnsname}: timeline hole of %d seconds (%.1f days) from %U to %U (%U)", origin, key->epoch_activate - previous_end_period,
                        (1.0f * (key->epoch_activate - previous_end_period)) / 86400.0f,
                        previous_end_period, key->epoch_activate, now);

                dnssec_policy_log_debug_key("dnssec-policy: unchained ", key);

                /*
                 * This case happens if there is at least one key K with timings in the future but the last key L of the valid chain is made inactive
                 * before K is being made active.
                 */

                ret = KEYROLL_HOLE_IN_TIMELINE;
                return ret;
            }
            else // the key chains fine
            {
                // if the previous key ends before this one we keep it

                if(previous_end_period < key->epoch_inactive)
                {
                    previous_key = key;
                    previous_end_period = key->epoch_inactive;
                }
                else
                {
                    // else the key is irrelevant for the chain
                }
            }
        }

        if(dnskey_get_flags(previous_key) == DNSKEY_FLAGS_KSK)
        {
            keyroll->ksk_next_deactivation = ONE_SECOND_US * dnskey_get_inactive_epoch(previous_key);
        }
        else
        {
            keyroll->zsk_next_deactivation = ONE_SECOND_US * dnskey_get_inactive_epoch(previous_key);
        }

        log_debug("dnssec-policy: %{dnsname}: %s: covered from %U to %U, last key activates at %U (kr: K=%lU, Z=%lU)",
                  origin, kr->name, previous_begin_period, previous_end_period, previous_next_period,
                  keyroll->ksk_next_deactivation, keyroll->zsk_next_deactivation);

        if(previous_key->epoch_created <= now)
        {
            if(kr->roll->time_table.created.type.type == ZONE_POLICY_RELATIVE)
            {
                if(FAIL(ret = dnssec_policy_add_generate_key_create_at(keyroll, kr, previous_key->epoch_created, NULL)))
                {
                    log_err("dnssec-policy: %{dnsname}: %s: failed to setup key generation from previous key: %r", origin, kr->name, ret);
                }
            }
            else if(kr->roll->time_table.created.type.type == ZONE_POLICY_RULE)
            {
                if(FAIL(ret = dnssec_policy_add_generate_key_active_at(keyroll, kr, previous_end_period + 60)))
                {
                    log_err("dnssec-policy: %{dnsname}: %s: failed to setup key generation from previous end period: %r", origin, kr->name, ret);
                }
            }
            else
            {
                log_err("dnssec-policy: %{dnsname}: %s: is not supported by this version of the policies", origin, kr->name);
            }
        }
        else
        {
            // formatln("%U <= %U", previous_key->epoch_created <= now);
            ret = SUCCESS; // ignore
        }

        ptr_vector_callback_and_destroy(key_roll_keys_vector, dnssec_policy_process_release_keys_cb);
    }
    else
    {
        // no key at all ? do a full init (with (re)signature)

        log_info("dnssec-policy: %{dnsname}: %s: will be completely initialised", origin, kr->name);

        // for relative rules: do it now
        // for cron rules: generate it back-dated

        if(kr->roll->time_table.created.type.type == ZONE_POLICY_RELATIVE)
        {
            // add the command, aim to be active "now"

            s32 delta = kr->roll->time_table.created.relative.seconds + // from the previous created key ...
                        kr->roll->time_table.publish.relative.seconds +
                        kr->roll->time_table.activate.relative.seconds ;

            if(delta > now)
            {
                delta = now - 1;
            }

            log_debug("dnssec-policy: %{dnsname}: %s: will generate a first key at %U minus %i = %U", origin, kr->name, now, delta, now - delta);

            if(FAIL(ret = dnssec_policy_add_generate_key_create_at(keyroll, kr, now - delta, NULL))) // works on any kind of dates
            {
                log_err("dnssec-policy: %{dnsname}: %s: failed to setup key generation before %U: %r", origin, kr->name, now - delta, ret);
            }
        }
        else if(kr->roll->time_table.created.type.type == ZONE_POLICY_RULE)
        {
            // compute the back-dated epoch

            if(FAIL(ret = dnssec_policy_add_generate_key_active_at(keyroll, kr, now))) // @note : only works on rules
            {
                log_err("dnssec-policy: %{dnsname}: %s: failed to setup key generation from %U: %r", origin, kr->name, now, ret);
            }
        }
        else
        {
            log_err("dnssec-policy: %{dnsname}: %s: don't know how to proceed", origin, kr->name);
            ret = INVALID_STATE_ERROR;
        }
    }

    return ret;
}

ya_result
dnssec_policy_process_at(keyroll_t *keyroll, const dnssec_policy *policy, time_t now)
{
    // the policy is referenced by the zone desc
    // and the zone desc by the parent
    // no need to acquire anything here

    ya_result ret = SUCCESS;

    const u8 *origin = keyroll->domain;

    log_debug("dnssec-policy: %{dnsname} applying policy %s with %i keys", origin, policy->name, ptr_vector_size(&policy->key_suite));

    //

    // enumerate the available keys and if they are in the zone and being used and so on.
    
    // KEEP, IGNORE, REMOVE

    ptr_vector key_roll_keys[DNSSEC_POLICY_KEY_ROLL_COUNT_MAXIMUM];
    
    for(int i = 0; i < DNSSEC_POLICY_KEY_ROLL_COUNT_MAXIMUM; ++i)
    {
        ptr_vector_init_ex(&key_roll_keys[i], 0); // with an initial capacity set to 0, no allocation is made until at one item is added
    }
    
    yassert(ptr_vector_size(&policy->key_suite) <= 8);

    int origin_key_count = 0;
    int origin_ksk_count = 0;
    int origin_zsk_count = 0;
    int origin_key_ignored = 0;
    int origin_key_added = 0;
    int origin_key_not_matched = 0;

    for(int keystore_key_index = 0;; ++keystore_key_index)
    {
        dnssec_key *key = dnssec_keystore_acquire_key_from_fqdn_at_index(origin, keystore_key_index);
        
        if(key == NULL)
        {
            // formatln("origin_key_count=%i origin_ksk_count=%i origin_zsk_count=%i origin_key_ignored=%i origin_key_added=%i origin_key_not_matched=%i", origin_key_count, origin_ksk_count, origin_zsk_count, origin_key_ignored, origin_key_added, origin_key_not_matched);
            break;
        }

        ++origin_key_count;

        if(dnskey_get_flags(key) == DNSKEY_FLAGS_KSK)
        {
            ++origin_ksk_count;
        }
        else
        {
            ++origin_zsk_count;
        }

        dnssec_policy_log_debug_key("dnssec-policy: found ", key);
        
        /*
         * @note 20160425 edf -- care must be taken here, keys may be generated in a background processing.
         *                       also, a key can only effectively be found after its generation (which discards the idea of virtual key)
         *                       so whatever is done here, pending key creation tasks should be taken into account (other operations are "real time")
         *
         * If the key is expired,
         *      ignore it (it should be handled by the smart signing).
         * If the key is out of the expected parameters (size/alg) and it is not acceptable,
         *      edit the times of the keys and remember the smart signing should be triggered.
         * If the key is valid, keep it on the side.
         * 
         */

        if(!dnskey_is_private(key) ||
           dnskey_is_expired(key, now) ||
           (key->epoch_publish == 0) ||
           (key->epoch_inactive == 0))
        {
            //dnssec_policy_log_debug_key("dnssec-policy: ignore ", key);
            //dnssec_policy_print_key("dnssec-policy: ignore ", key);
            // this key is irrelevant. It will be released after this control block.
            ++origin_key_ignored;
        }
        else
        {
            // for all key suite, if the key matches the suite, add the key to the suite array

            bool got_match = FALSE;

            //formatln("%{dnsname}: suite '%s' contains %i suites", origin, policy->name, ptr_vector_size(&policy->key_suite));

            for(int ksi = 0; ksi <= ptr_vector_last_index(&policy->key_suite); ++ksi)
            {
                const struct dnssec_policy_key_suite *kr = (const struct dnssec_policy_key_suite*)ptr_vector_get(&policy->key_suite, ksi);

                if(dnssec_policy_key_roll_matches(kr, key))
                {
                    log_debug("%{dnsname}: key matches suite '%s'", origin, kr->name);

                    dnskey_acquire(key);
                    ptr_vector_append(&key_roll_keys[ksi], key);
                    ++origin_key_added;
                    got_match = TRUE;
                }
                // else not part of this policy
            }

            if(!got_match)
            {
                log_debug("%{dnsname}: key doesn't match any suite", origin);
                ++origin_key_not_matched;
            }
        }
        
        dnskey_release(key);
    }

    log_debug("dnssec-policy: %{dnsname} released", origin);
    
    /*
     * sort-out the remaining keys
     * trigger the generation of keys
     * 
     * keys of the array are matching the policy
     */
    for(int ksi = 0; ksi <= ptr_vector_last_index(&policy->key_suite); ++ksi)
    {
        struct dnssec_policy_key_suite *kr = (struct dnssec_policy_key_suite*)ptr_vector_get(&policy->key_suite, ksi);

        if(FAIL(ret = dnssec_policy_key_roll_keys_generate_at(keyroll, kr, &key_roll_keys[ksi], now)))
        {
            break;
        }

    } // for all key suites

    for(int i = 0; i < DNSSEC_POLICY_KEY_ROLL_COUNT_MAXIMUM; ++i)
    {
        ptr_vector_callback_and_destroy(&key_roll_keys[i], dnssec_policy_process_release_keys_cb);
    }

    // decide what to do
    
    return ret;   // returns success or the last error from the key generation part
}

ya_result
dnssec_policy_process(keyroll_t *keyroll, const dnssec_policy *policy, s64 from, s64 until)
{
    s64 t = from;

    if(t < until)
    {
        ya_result  ret;

        do
        {
#if DEBUG
            log_debug("------------------------------------------------------------------------------");
#endif
            log_info("keyroll: %{dnsname} processing: %s from %llU to %llU", keyroll->domain, policy->name, t, until);
            formatln("keyroll: %{dnsname} processing: %s from %llU to %llU", keyroll->domain, policy->name, t, until);
#if DEBUG
            logger_flush(); // 2019-08-13 23:45:00.000000
            flushout();
            flusherr();
#endif
            if(ISOK(ret = dnssec_policy_process_at(keyroll, policy, t / ONE_SECOND_US)))
            {
                t = MIN(keyroll->ksk_next_deactivation, keyroll->zsk_next_deactivation);

                log_debug("keyroll: %{dnsname}: processed: %s covers: %llU , %llU", keyroll->domain, policy->name, keyroll->ksk_next_deactivation, keyroll->zsk_next_deactivation);
#if DEBUG
                logger_flush(); // 2019-08-13 23:45:00.000000
#endif
            }
            else
            {
                break;
            }

            if(dnscore_shuttingdown())
            {
                ret = STOPPED_BY_APPLICATION_SHUTDOWN;
                break;
            }
        }
        while(t < until);

        return ret;
    }
    else
    {
        return INVALID_STATE_ERROR;
    }
}

/**
 * @}
 */
