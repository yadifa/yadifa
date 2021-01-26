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

#include "server-config.h"

#include "zone-signature-policy.h"
#include "zone_desc.h"
#include "confs.h"

#include <dnscore/mutex.h>
#include <dnscore/ptr_set.h>
#include <dnscore/u32_set.h>
#include <dnscore/dnskey.h>
#include <dnscore/logger.h>
#include <dnscore/timems.h>
#include <dnscore/random.h>
#include <dnscore/packet_reader.h>
#include <dnscore/timeformat.h>
#include <dnscore/service.h>
#include <dnscore/threaded_dll_cw.h>

#include <dnsdb/dnssec-keystore.h>
#include <dnsdb/zdb_icmtl.h>
#include <dnsdb/nsec.h>
#include <dnsdb/nsec3.h>

#include "database-service-zone-resignature.h"

#if HAS_EVENT_DYNAMIC_MODULE
#include "dynamic-module-handler.h"
#endif

#ifndef HAS_DYNUPDATE_DIFF_ENABLED
#error "HAS_DYNUPDATE_DIFF_ENABLED not defined"
#endif

#define MODULE_MSG_HANDLE g_dnssec_logger
extern logger_handle *g_dnssec_logger;

#include "server_error.h"
#include "zone.h"

#define DNSECPOL_TAG 0x4c4f504345534e44
#define DPOLKYST_TAG 0x5453594b4c4f5044
#define DPOLKEY_TAG  0x0059454b4c4f5044
#define DPOLDNIL_TAG 0x4c494e444c4f5044
#define DPOLSALT_TAG 0x544c41534c4f5044
#define DPOLROLL_TAG 0x4c4c4f524c4f5044
#define DPOLRULE_TAG 0x454c55524c4f5044
#define DPOLQUEU_TAG 0x554555514c4f5044

#define KEY_POLICY_EPOCH_MATCH_MARGIN 180 // how close two epochs have to be to be considered a match

#define DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS 0
#if DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS
#pragma message("WARNING: DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS enabled !")
#endif


static u32_set zone_policy_rule_definition_set = U32_SET_EMPTY;
static group_mutex_t zone_policy_rule_definition_set_mtx = GROUP_MUTEX_INITIALIZER;
static volatile u32 zone_policy_rule_definition_next_index = 0;

// local functions definitions

ya_result zone_policy_date_init_at_next_rule(zone_policy_date *date, const zone_policy_date *from, const zone_policy_date *rule);
ya_result zone_policy_date_init_at_prev_rule(zone_policy_date *date, const zone_policy_date *from, const zone_policy_date *rule);
ya_result zone_policy_date_init_from_rule(zone_policy_date *date, const zone_policy_date *from, const zone_policy_date *rule);
ya_result zone_policy_date_init_from_date(zone_policy_date *date, const zone_policy_date *from, const zone_policy_date *rule);
static ya_result dnssec_policy_alarm_handler(void *args, bool cancel);

//

static ptr_set origin_to_dnssec_policy_queue_set = PTR_SET_DNSNAME_EMPTY;
static mutex_t origin_to_dnssec_policy_queue_mtx = MUTEX_INITIALIZER;

//

static ptr_set dnssec_policy_roll_set = PTR_SET_ASCIIZ_EMPTY;
static group_mutex_t dnssec_policy_roll_set_mtx = GROUP_MUTEX_INITIALIZER;
static group_mutex_t dnssec_policy_roll_mtx = GROUP_MUTEX_INITIALIZER;

//

static ptr_set dnssec_policy_set = PTR_SET_ASCIIZ_EMPTY;
static group_mutex_t dnssec_policy_set_mtx = GROUP_MUTEX_INITIALIZER;
static group_mutex_t dnssec_policy_mtx = GROUP_MUTEX_INITIALIZER;

//

static ptr_set dnssec_denial_set = PTR_SET_ASCIIZ_EMPTY;
static group_mutex_t dnssec_denial_set_mtx = GROUP_MUTEX_INITIALIZER;
static group_mutex_t dnssec_denial_mtx = GROUP_MUTEX_INITIALIZER;

//

static ptr_set dnssec_policy_key_set = PTR_SET_ASCIIZ_EMPTY;
static group_mutex_t dnssec_policy_key_set_mtx = GROUP_MUTEX_INITIALIZER;
static group_mutex_t dnssec_policy_key_mtx = GROUP_MUTEX_INITIALIZER;

//

static ptr_set dnssec_policy_key_suite_set = PTR_SET_ASCIIZ_EMPTY;
static group_mutex_t dnssec_policy_key_suite_set_mtx = GROUP_MUTEX_INITIALIZER;
static group_mutex_t dnssec_policy_key_suite_mtx = GROUP_MUTEX_INITIALIZER;

//

static volatile int dnssec_policy_queue_serial = 0;

static void
zone_policy_date_format_handler_method(const void *restrict val, output_stream *os, s32 padding, char pad_char, bool left_justified, void * restrict reserved_for_method_parameters)
{
    zone_policy_date *date = (zone_policy_date*)val;
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
            zone_policy_rule_definition_s *def = zone_policy_rule_definition_get_from_rule(date);
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

dnssec_policy_queue*
dnssec_policy_queue_new(const u8 *fqdn)
{
    dnssec_policy_queue *cmd;
    ZALLOC_OBJECT_OR_DIE( cmd, dnssec_policy_queue, DPOLQUEU_TAG);
    ZEROMEMORY(cmd, sizeof(dnssec_policy_queue));
    cmd->origin = dnsname_zdup(fqdn); // weak
    return cmd;
}

bool
dnssec_policy_queue_equals(const dnssec_policy_queue *a, const dnssec_policy_queue *b)
{
    if(a->command == b->command)
    {
        switch(a->command)
        {
            case DNSSEC_POLICY_COMMAND_INIT:
            {
                return TRUE; // as time is "asap"
            }
            case DNSSEC_POLICY_COMMAND_GENERATE_KEY:
            {
                return (a->epoch == b->epoch) && (a->parameters.generate_key.suite == b->parameters.generate_key.suite);
            }
            default:
            {
                // not implemented
                log_err("dnssec_policy_queue_equals: command not implemented");
                abort();
            }
        }
    }
    else
    {
        return FALSE;
    }
}

bool
dnssec_policy_queue_has_command(dnssec_policy_queue *cmd)
{
    bool ret = FALSE;
    mutex_lock(&origin_to_dnssec_policy_queue_mtx);

    ptr_node *queue_node = ptr_set_find(&origin_to_dnssec_policy_queue_set, cmd->origin);
    if(queue_node != NULL)
    {
        dnssec_policy_queue* cmdq = (dnssec_policy_queue*)queue_node->value;

        while(cmdq != NULL)
        {
            if(dnssec_policy_queue_equals(cmdq, cmd))
            {
                ret = TRUE;
                break;
            }

            cmdq = cmdq->next;
        }
    }
    mutex_unlock(&origin_to_dnssec_policy_queue_mtx);
    return ret;
}

bool
dnssec_policy_queue_has_command_type(const u8 *fqdn, int command)
{
    bool ret = FALSE;

    mutex_lock(&origin_to_dnssec_policy_queue_mtx);
    ptr_node *queue_node = ptr_set_find(&origin_to_dnssec_policy_queue_set, fqdn);

    if(queue_node != NULL)
    {
        dnssec_policy_queue* cmdq = (dnssec_policy_queue*)queue_node->value;

        while(cmdq != NULL)
        {
            if(cmdq->command == command)
            {
                ret = TRUE;
                break;
            }

            cmdq = cmdq->next;
        }
    }

    mutex_unlock(&origin_to_dnssec_policy_queue_mtx);
    return ret;
}

static int
dnssec_policy_queue_add_command(dnssec_policy_queue *cmd)
{
#if DEBUG
    log_debug("dnssec-policy: %{dnsname}: add command %p", cmd->origin, cmd);
#endif

    yassert(!cmd->queued);

    mutex_lock(&origin_to_dnssec_policy_queue_mtx);
    int ret = dnssec_policy_queue_serial;
    dnssec_policy_queue_serial += 0x100;
    ptr_node *queue_node = ptr_set_insert(&origin_to_dnssec_policy_queue_set, cmd->origin);
    if(queue_node->value == NULL)
    {
        queue_node->key = dnsname_zdup(cmd->origin);
    }
    dnssec_policy_queue** cmdqp = (dnssec_policy_queue**)&queue_node->value;
    cmd->next = *cmdqp;
    cmd->queued = TRUE;
    *cmdqp = cmd;

    mutex_unlock(&origin_to_dnssec_policy_queue_mtx);
    return ret;
}

void
dnssec_policy_queue_add_command_at_epoch(dnssec_policy_queue *cmd, alarm_t hndl, time_t at)
{
    int serial = dnssec_policy_queue_add_command(cmd) | ALARM_KEY_DNSSEC_POLICY_EVENT;

    alarm_event_node *event = alarm_event_new(
        at,
        serial,
        dnssec_policy_alarm_handler,
        cmd,
        ALARM_DUP_REMOVE_LATEST,
        "dnssec-policy-generate-key");

    alarm_set(hndl, event);
}

void
dnssec_policy_queue_remove_command(dnssec_policy_queue *cmd)
{
    if(cmd->queued)
    {
#if DEBUG
        log_debug("dnssec-policy: %{dnsname}: remove command %p", cmd->origin, cmd);
#endif

        mutex_lock(&origin_to_dnssec_policy_queue_mtx);

        ptr_node *queue_node = ptr_set_insert(&origin_to_dnssec_policy_queue_set, cmd->origin);
        dnssec_policy_queue** cmdqp = (dnssec_policy_queue**)&queue_node->value;

        while(*cmdqp != NULL)
        {
            if(*cmdqp == cmd)
            {
                *cmdqp = cmd->next;
                cmd->next = NULL;
                cmd->queued = FALSE;
                break;
            }
            cmdqp = &(*cmdqp)->next;
        }

        if(queue_node->value == NULL)
        {
            u8* key = (u8*)queue_node->key;
            ptr_set_delete(&origin_to_dnssec_policy_queue_set, cmd->origin);
            dnsname_zfree(key);
        }

        mutex_unlock(&origin_to_dnssec_policy_queue_mtx);
    }
#if DEBUG
    else
    {
        log_debug("dnssec-policy: %{dnsname}: remove command %p: not queued", cmd->origin, cmd);
    }
#endif
}

void
dnssec_policy_queue_delete_command(dnssec_policy_queue *cmd)
{
#if DEBUG
    log_debug("dnssec-policy: %{dnsname}: delete command %p", cmd->origin, cmd);
#endif
    dnssec_policy_queue_remove_command(cmd);

    switch(cmd->command)
    {
        case DNSSEC_POLICY_COMMAND_INIT:
        {
            break;
        }
        case DNSSEC_POLICY_COMMAND_GENERATE_KEY:
        {
            if(cmd->parameters.generate_key.suite != NULL)
            {
                dnssec_policy_key_suite_release(cmd->parameters.generate_key.suite);
                zone_release(cmd->parameters.generate_key.zone_desc);
            }
            break;
        }
    }

#if DEBUG
    intptr cmd_address = (intptr)cmd;
#endif

    dnsname_zfree(cmd->origin);
    ZFREE_OBJECT(cmd);

#if DEBUG
    log_debug("dnssec-policy: delete command %p: done", cmd_address); // scan-build false positive : the memory pointed by cmd is freed, but cmd's value is still valid.
#endif
}

ya_result
dnssec_policy_queue_add_generate_key_create_at(zone_desc_s *zone_desc, struct dnssec_policy_key_suite *kr, time_t epoch)
{
    zone_policy_table_s tbl;
    zone_policy_date now_date;
    ya_result ret;

    ret = zone_policy_date_init_from_epoch(&now_date, epoch);

    if(FAIL(ret))
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_table_init_from_date returned an error: %r", ret);
        return ret;
    }

    ret = zone_policy_table_init_from_date(&tbl, &kr->roll->time_table, &now_date);

    if(FAIL(ret))
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_table_init_from_date returned an error: %r", ret);
        return ret;
    }

#if DEBUG
    format_writer n_fw = {zone_policy_date_format_handler_method, &now_date};
    format_writer c_fw = {zone_policy_date_format_handler_method, &tbl.created};
    format_writer p_fw = {zone_policy_date_format_handler_method, &tbl.publish};
    format_writer a_fw = {zone_policy_date_format_handler_method, &tbl.activate};
    format_writer d_fw = {zone_policy_date_format_handler_method, &tbl.inactive};
    format_writer r_fw = {zone_policy_date_format_handler_method, &tbl.delete};

    log_debug("dnssec-policy: %{dnsname}: %s: at %T = %U = %w: queued key: create=%w, publish=%w, activate=%w, deactivate=%w, remove=%w",
            zone_origin(zone_desc), kr->name, epoch, epoch, &n_fw,
            &c_fw, &p_fw, &a_fw, &d_fw, &r_fw);
#endif

#if 1
    yassert(tbl.created.type.type == ZONE_POLICY_ABSOLUTE);

    time_t alarm_epoch;

    if(FAIL(ret = zone_policy_date_get_epoch(&tbl.created, &alarm_epoch))) // note: created should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_date_get_epoch returned an error: %r", ret);
        return ret;
    }

#if DEBUG
    log_debug("dnssec-policy: %{dnsname}: %s: alarm set to %T", zone_origin(zone_desc), kr->name, alarm_epoch);
    logger_flush();
#endif

    dnssec_policy_queue *cmd = dnssec_policy_queue_new(zone_origin(zone_desc));
    cmd->epoch = epoch;
    cmd->command = DNSSEC_POLICY_COMMAND_GENERATE_KEY;
    dnssec_policy_key_suite_acquire(kr);
    cmd->parameters.generate_key.suite = kr; // must be done else the dnssec_policy_queue_has_command will fail
    cmd->parameters.generate_key.zone_desc = zone_desc;
    zone_acquire(zone_desc);

    if(!dnssec_policy_queue_has_command(cmd))
    {
        log_debug("dnssec-policy: %{dnsname}: %s: at %T will generate a key with time parameter: %T", zone_origin(zone_desc), kr->name, alarm_epoch, epoch);

        // add the command

        zone_policy_key_suite_mark_processed(zone_desc, kr);

        dnssec_policy_queue_add_command_at_epoch(cmd, zone_desc->loaded_zone->alarm_handle, alarm_epoch);
    }
    else
    {
        // note: kr is part of cmd, so it cannot be use dafter cmd has been deleted
        log_debug("dnssec-policy: %{dnsname}: %s: key generation for policy already set", zone_origin(zone_desc), kr->name);

        dnssec_policy_queue_delete_command(cmd);
    }
#else
    time_t created_epoch;
    time_t publish_epoch;
    time_t activate_epoch;
    time_t deactivate_epoch;
    time_t unpublish_epoch;

    if(FAIL(ret = zone_policy_date_get_epoch(&tbl.created, &created_epoch))) // note: created should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_date_get_epoch (created_epoch) returned an error: %r", ret);
        return ret;
    }

    if(FAIL(ret = zone_policy_date_get_epoch(&tbl.publish, &publish_epoch))) // note: publish should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_date_get_epoch (publish_epoch) returned an error: %r", ret);
        return ret;
    }

    if(FAIL(ret = zone_policy_date_get_epoch(&tbl.activate, &activate_epoch))) // note: activate should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_date_get_epoch (activate_epoch) returned an error: %r", ret);
        return ret;
    }

    if(FAIL(ret = zone_policy_date_get_epoch(&tbl.inactive, &deactivate_epoch))) // note: deactivate should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_date_get_epoch (deactivate_epoch) returned an error: %r", ret);
        return ret;
    }

    if(FAIL(ret = zone_policy_date_get_epoch(&tbl.delete, &unpublish_epoch))) // note: unpublish should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_date_get_epoch (unpublish_epoch) returned an error: %r", ret);
        return ret;
    }

    keyroll_generate_dnskey_ex(keyroll, kr->key->size, kr->key->algorithm, ONE_SECOND_US * created_epoch, ONE_SECOND_US * publish_epoch, ONE_SECOND_US * activate_epoch,
                               ONE_SECOND_US * deactivate_epoch, ONE_SECOND_US * unpublish_epoch, (kr->key->flags == DNSKEY_FLAGS_KSK));

    yassert(tbl.created.type.type == ZONE_POLICY_ABSOLUTE);

    time_t alarm_epoch;

    if(FAIL(ret = zone_policy_date_get_epoch(&tbl.created, &alarm_epoch))) // note: created should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_date_get_epoch returned an error: %r", ret);
        return ret;
    }

#if DEBUG
    log_debug("dnssec-policy: %{dnsname}: %s: key created set at %T", zone_origin(zone_desc), kr->name, alarm_epoch);
#endif

#endif // #if 0 #else

    return SUCCESS;
}

/**
 * Works only with RULEs (cron) key suites
 * 
 * @param zone_desc
 * @param kr
 * @param active_at
 * @param will_be_inactive_at a pointer that'll receive the inactive epoch (can be NULL)
 */

ya_result
dnssec_policy_queue_add_generate_key_active_at(zone_desc_s *zone_desc, struct dnssec_policy_key_suite *kr, time_t active_at, time_t *will_be_inactive_at)
{
    zone_policy_date creation_date;
    zone_policy_date publish_date;
    zone_policy_date activate_date;
    zone_policy_date inactive_date;
    zone_policy_date unpublish_date;
    zone_policy_date now_date;

    ya_result ret;

    if(FAIL(ret = zone_policy_date_init_from_epoch(&now_date, active_at)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_prev_rule(&activate_date, &now_date, &kr->roll->time_table.activate)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_prev_rule(&publish_date, &activate_date, &kr->roll->time_table.publish)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_prev_rule(&creation_date, &publish_date, &kr->roll->time_table.created)))
    {
        return ret;
    }

    time_t creation_epoch = 60;
    time_t activate_epoch = 60;

    if(FAIL(ret = zone_policy_date_get_epoch(&creation_date, &creation_epoch)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_get_epoch(&activate_date, &activate_epoch)))
    {
        return ret;
    }

#if DEBUG
    format_writer c_fw = {zone_policy_date_format_handler_method, &creation_date};

    {
        format_writer a_fw0 = {zone_policy_date_format_handler_method, &activate_date};
        format_writer p_fw0 = {zone_policy_date_format_handler_method, &publish_date};

        log_debug1("dnssec-policy: %{dnsname}: %s: base %w <= %w <= %w : %T", zone_origin(zone_desc), kr->name, &c_fw, &p_fw0, &a_fw0, creation_epoch);
    }
#endif

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&publish_date, &creation_date, &kr->roll->time_table.publish)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&activate_date, &publish_date, &kr->roll->time_table.activate)))
    {
        return ret;
    }

#if DEBUG
    format_writer p_fw = {zone_policy_date_format_handler_method, &publish_date};
    format_writer a_fw = {zone_policy_date_format_handler_method, &activate_date};
    {
        log_debug1("dnssec-policy: %{dnsname}: %s: base %w => %w => %w : %T (after forward correction)", zone_origin(zone_desc), kr->name, &c_fw, &p_fw, &a_fw, creation_epoch);
    }
#endif

    // compute the future key timings to ensure there will be no period without a signature

    zone_policy_date next_creation_date;
    zone_policy_date next_publish_date;
    zone_policy_date next_activate_date;

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&next_creation_date, &activate_date, &kr->roll->time_table.created)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&next_publish_date, &next_creation_date, &kr->roll->time_table.publish)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&next_activate_date, &next_publish_date, &kr->roll->time_table.activate)))
    {
        return ret;
    }

#if DEBUG
    {
        format_writer na_fw = {zone_policy_date_format_handler_method, &next_activate_date};
        format_writer np_fw = {zone_policy_date_format_handler_method, &next_publish_date};
        format_writer nc_fw = {zone_policy_date_format_handler_method, &next_creation_date};

        log_debug1("dnssec-policy: %{dnsname}: %s: next %w => %w => %w", zone_origin(zone_desc), kr->name, &nc_fw, &np_fw, &na_fw);
    }
#endif

    // and use this next_activate as a base for the current deactivate

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&inactive_date, &next_activate_date, &kr->roll->time_table.inactive)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&unpublish_date, &inactive_date, &kr->roll->time_table.delete)))
    {
        return ret;
    }

    time_t inactive_epoch = 0;

    if(FAIL(ret = zone_policy_date_get_epoch(&inactive_date, &inactive_epoch)))
    {
        return ret;
    }

    if(inactive_epoch - activate_epoch < DNSSEC_POLICY_MINIMUM_ACTIVATED_TIME_SUGGESTION_SECONDS)
    {
        double d = inactive_epoch - activate_epoch;
        d /= 86400.0;
        double c = DNSSEC_POLICY_MINIMUM_ACTIVATED_TIME_SUGGESTION_SECONDS;
        c /= 86400.0;
        log_warn("dnssec-policy: %{dnsname}: %s: the key will only be activated for %.3f days, consider increasing this value to at least %.3f days", zone_origin(zone_desc), kr->name, d, c);
    }

    if(inactive_epoch < active_at)
    {
        log_err("dnssec-policy: %{dnsname}: %s: computing timings to be in the current activated time window produces an already expired key", zone_origin(zone_desc), kr->name );

        return INVALID_STATE_ERROR;
    }

    if(will_be_inactive_at != NULL)
    {
        *will_be_inactive_at = inactive_epoch;
    }

#if DEBUG
    format_writer d_fw = {zone_policy_date_format_handler_method, &inactive_date};
    zone_policy_date remove_date;
    ret = zone_policy_date_init_at_next_rule(&remove_date, &inactive_date, &kr->roll->time_table.delete);
    (void)ret;
    format_writer r_fw = {zone_policy_date_format_handler_method, &unpublish_date};

    log_debug("dnssec-policy: %{dnsname}: %s: rule key: create=%w, publish=%w, activate=%w, deactivate=%w, remove=%w",
            zone_origin(zone_desc), kr->name,
            &c_fw, &p_fw, &a_fw, &d_fw, &r_fw);
#endif

    log_debug("dnssec-policy: %{dnsname}: %s: will generate a key at %T (rule new) to be active at %T", zone_origin(zone_desc), kr->name, creation_epoch, active_at);

#if DEBUG
    logger_flush();
#endif

    // add the command

    ret = dnssec_policy_queue_add_generate_key_create_at(zone_desc, kr, creation_epoch);

    return ret;
}

ya_result
dnssec_policy_roll_test_at(struct dnssec_policy_roll *kr, time_t active_at, time_t *will_be_inactive_at, bool print_text, bool log_text)
{
    zone_policy_date creation_date;
    zone_policy_date publish_date;
    zone_policy_date activate_date;
    zone_policy_date inactive_date;
    zone_policy_date unpublish_date;
    zone_policy_date now_date;

    ya_result ret;

    if(FAIL(ret = zone_policy_date_init_from_epoch(&now_date, active_at)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_prev_rule(&activate_date, &now_date, &kr->time_table.activate)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_prev_rule(&publish_date, &activate_date, &kr->time_table.publish)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_prev_rule(&creation_date, &publish_date, &kr->time_table.created)))
    {
        return ret;
    }

    time_t creation_epoch = 60;
    time_t activate_epoch = 60;

    if(FAIL(ret = zone_policy_date_get_epoch(&creation_date, &creation_epoch)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_get_epoch(&activate_date, &activate_epoch)))
    {
        return ret;
    }

#if DEBUG
    format_writer c_fw = {zone_policy_date_format_handler_method, &creation_date};

    {
        format_writer a_fw0 = {zone_policy_date_format_handler_method, &activate_date};
        format_writer p_fw0 = {zone_policy_date_format_handler_method, &publish_date};

        log_debug1("key-roll: %s: base %w <= %w <= %w : %T", kr->name, &c_fw, &p_fw0, &a_fw0, creation_epoch);
    }
#endif

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&publish_date, &creation_date, &kr->time_table.publish)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&activate_date, &publish_date, &kr->time_table.activate)))
    {
        return ret;
    }

#if DEBUG
    format_writer p_fw = {zone_policy_date_format_handler_method, &publish_date};
    format_writer a_fw = {zone_policy_date_format_handler_method, &activate_date};
    {
        log_debug1("key-roll: %s: base %w => %w => %w : %T (after forward correction)", kr->name, &c_fw, &p_fw, &a_fw, creation_epoch);
    }
#endif

    // compute the future key timings to ensure there will be no period without a signature

    zone_policy_date next_creation_date;
    zone_policy_date next_publish_date;
    zone_policy_date next_activate_date;

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&next_creation_date, &activate_date, &kr->time_table.created)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&next_publish_date, &next_creation_date, &kr->time_table.publish)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&next_activate_date, &next_publish_date, &kr->time_table.activate)))
    {
        return ret;
    }

#if DEBUG
    {
        format_writer na_fw = {zone_policy_date_format_handler_method, &next_activate_date};
        format_writer np_fw = {zone_policy_date_format_handler_method, &next_publish_date};
        format_writer nc_fw = {zone_policy_date_format_handler_method, &next_creation_date};

        log_debug1("key-roll: %s: next %w => %w => %w", kr->name, &nc_fw, &np_fw, &na_fw);
    }
#endif

    // and use this next_activate as a base for the current deactivate

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&inactive_date, &next_activate_date, &kr->time_table.inactive)))
    {
        return ret;
    }

    if(FAIL(ret = zone_policy_date_init_at_next_rule(&unpublish_date, &inactive_date, &kr->time_table.delete)))
    {
        return ret;
    }

    time_t inactive_epoch = 0;

    if(FAIL(ret = zone_policy_date_get_epoch(&inactive_date, &inactive_epoch)))
    {
        return ret;
    }

    if(inactive_epoch - activate_epoch < DNSSEC_POLICY_MINIMUM_ACTIVATED_TIME_SUGGESTION_SECONDS)
    {
        double d = inactive_epoch - activate_epoch;
        d /= 86400.0;
        double c = DNSSEC_POLICY_MINIMUM_ACTIVATED_TIME_SUGGESTION_SECONDS;
        c /= 86400.0;
        if(log_text)
        {
            log_warn("key-roll: %s: the key will only be activated for %.3f days, consider increasing this value to at least %.3f days", kr->name, d, c);
        }
        if(print_text)
        {
            formatln("key-roll: %s: the key will only be activated for %.3f days, consider increasing this value to at least %.3f days", kr->name, d, c);
        }
    }

    if(inactive_epoch < active_at)
    {
        if(log_text)
        {
            log_err("key-roll: %s: computing timings to be in the current activated time window produces an already expired key", kr->name);
        }
        if(print_text)
        {
            formatln("key-roll: %s: computing timings to be in the current activated time window produces an already expired key", kr->name);
        }

        return INVALID_STATE_ERROR;
    }

    if(will_be_inactive_at != NULL)
    {
        *will_be_inactive_at = inactive_epoch;
    }

#if DEBUG
    format_writer d_fw = {zone_policy_date_format_handler_method, &inactive_date};
    zone_policy_date remove_date;
    ret = zone_policy_date_init_at_next_rule(&remove_date, &inactive_date, &kr->time_table.delete);
    (void)ret;
    format_writer r_fw = {zone_policy_date_format_handler_method, &unpublish_date};

    log_debug("key-roll: %s: rule key: create=%w, publish=%w, activate=%w, deactivate=%w, remove=%w",
              kr->name,
              &c_fw, &p_fw, &a_fw, &d_fw, &r_fw);
#endif

    log_debug("key-roll: %s: will generate a key at %T (rule new) to be active at %T", kr->name, creation_epoch, active_at);

    if(log_text || print_text)
    {
        format_writer c_fw0 = {zone_policy_date_format_handler_method, &creation_date};
        format_writer p_fw0 = {zone_policy_date_format_handler_method, &publish_date};
        format_writer a_fw0 = {zone_policy_date_format_handler_method, &activate_date};
        format_writer i_fw0 = {zone_policy_date_format_handler_method, &inactive_date};
        format_writer u_fw0 = {zone_policy_date_format_handler_method, &unpublish_date};
        u32 delta_seconds = inactive_epoch - activate_epoch;
        float delta_value;
        const char *delta_units;

        if(delta_seconds > 2592000)
        {
            delta_value = 1.0f * delta_seconds / 2592000.f;
            delta_units = "months";
        }
        else if(delta_seconds > 604800)
        {
            delta_value = 1.f * delta_seconds / 604800.f;
            delta_units = "weeks";
        }
        else if(delta_seconds > 86400)
        {
            delta_value = 1.f * delta_seconds / 86400.f;
            delta_units = "days";
        }
        else if(delta_seconds > 3600)
        {
            delta_value = 1.f * delta_seconds / 3600.f;
            delta_units = "hours";
        }
        else if(delta_seconds > 60)
        {
            delta_value = 1.f * delta_seconds / 60.f;
            delta_units = "minutes";
        }
        else
        {
            delta_value = 1.f * delta_seconds;
            delta_units = "seconds";
        }

        if(log_text)
        {
            log_info("key-roll: %s: creation at %w, publication at %w, activation at %w, deactivation at %w, removal at %w, %6.1f %s",
                     kr->name, &c_fw0, &p_fw0, &a_fw0, &i_fw0, &u_fw0, delta_value, delta_units);
        }

        if(print_text)
        {
            formatln("key-roll: %s: creation at %w, publication at %w, activation at %w, deactivation at %w, removal at %w, %6.1f %s",
                     kr->name, &c_fw0, &p_fw0, &a_fw0, &i_fw0, &u_fw0, delta_value, delta_units);
        }
    }

#if DEBUG
    logger_flush();
#endif

    return ret;
}

ya_result
dnssec_policy_roll_test(struct dnssec_policy_roll *kr, time_t active_at, u32 duration_seconds, bool print_text, bool log_text)
{
    ya_result ret;
    time_t end_at =  active_at + duration_seconds;
    time_t inactive_at = 0;

    if(print_text)
    {
        formatln("key-roll: %s: testing policy sets of dates from %T to %T", kr->name, active_at, end_at);
    }

    if(log_text)
    {
        formatln("key-roll: %s: testing policy sets of dates from %T to %T", kr->name, active_at, end_at);
    }

    while(active_at < end_at)
    {
        if(FAIL(ret = dnssec_policy_roll_test_at(kr, active_at, &inactive_at, print_text, log_text)))
        {
            if(log_text)
            {
                log_info("key-roll: %s: could not find a matching set of dates from %T", kr->name, active_at);
            }
            if(print_text)
            {
                formatln("key-roll: %s: could not find a matching set of dates from %T", kr->name, active_at);
            }
            return ret;
        }

        active_at = inactive_at;
    }

    if(print_text)
    {
        formatln("key-roll: %s: policy sets of dates from %T to %T computed", kr->name, active_at, end_at);
    }

    if(log_text)
    {
        formatln("key-roll: %s: policy sets of dates from %T to %T computed", kr->name, active_at, end_at);
    }

    return SUCCESS;
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
zone_policy_date_compare(const zone_policy_date *d1, const zone_policy_date *d2)
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
zone_policy_get_mday_from_year_month_week_wday(int year, int month, int week, int wday)
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
zone_policy_date_init_from_year_month_week_wday(zone_policy_date *date, int year, int month, int week, int wday)
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
zone_policy_date_init_from_epoch(zone_policy_date *date, time_t epoch)
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
zone_policy_date_get_epoch(const zone_policy_date *date, time_t *epoch)
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
zone_policy_date_init_after_epoch(zone_policy_date *date, time_t epoch, u32 seconds)
{
    ya_result ret = zone_policy_date_init_from_epoch(date, epoch + seconds);
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
zone_policy_date_init_after_date(zone_policy_date *date, const zone_policy_date *from, u32 seconds)
{
    ya_result ret;
    time_t epoch;
    if(ISOK(ret = zone_policy_date_get_epoch(from, &epoch)))
    {
        ret = zone_policy_date_init_from_epoch(date, epoch + seconds);
    }
    return ret;
}

/**
 * Initialises a date using a rule applied on an epoch
 * 
 * @param result_date
 * @param rule_date
 * @param after_epoch
 * @return 
 */

ya_result
zone_policy_date_init_from_rule_applied_with_epoch(zone_policy_date *result_date, const zone_policy_date *rule_date, time_t after_epoch)
{
    zone_policy_date after_date;
    ya_result ret;
    if(ISOK(ret = zone_policy_date_init_from_epoch(&after_date, after_epoch)))
    {
        ret = zone_policy_date_init_at_next_date(result_date, &after_date, rule_date);
    }
    
    return ret;
}

/**
 * Initialises an epoch from a rule applied on an epoch
 * 
 * @param rule_date
 * @param after_epoch
 * @param result_epoch
 * @return 
 */

ya_result
zone_policy_get_epoch_from_rule_applied_with_epoch(const zone_policy_date *rule_date, time_t after_epoch, time_t *result_epoch)
{
    zone_policy_date result_date;
    ya_result ret;
    if(ISOK(ret = zone_policy_date_init_from_rule_applied_with_epoch(&result_date, rule_date, after_epoch)))
    {
        ret = zone_policy_date_get_epoch(&result_date, result_epoch);
    }
    return ret;
}

zone_policy_rule_definition_s*
zone_policy_rule_definition_get_from_index(u32 index)
{
    zone_policy_rule_definition_s *ret = NULL;
    group_mutex_read_lock(&zone_policy_rule_definition_set_mtx);
    u32_node *node = u32_set_find(&zone_policy_rule_definition_set, index);
    if(node != NULL)
    {
        ret = (zone_policy_rule_definition_s*)node->value;
    }
    group_mutex_read_unlock(&zone_policy_rule_definition_set_mtx);
    return ret;
}

zone_policy_rule_definition_s*
zone_policy_rule_definition_get_from_rule(const zone_policy_date *rule)
{
    zone_policy_rule_definition_s *ret = NULL;
    if(rule->type.type == ZONE_POLICY_RULE)
    {
        ret = zone_policy_rule_definition_get_from_index(rule->rule.index);
    }
    return ret;
}

void
zone_policy_rule_init(zone_policy_rule_s *rule, const zone_policy_rule_definition_s *rule_definition)
{   
    group_mutex_write_lock(&zone_policy_rule_definition_set_mtx);
    yassert(zone_policy_rule_definition_next_index < 0x40000000);
    
    for(;;)
    {
        ++zone_policy_rule_definition_next_index;
        if(zone_policy_rule_definition_next_index == 0x40000000)
        {
            zone_policy_rule_definition_next_index = 0;
        }

        u32_node *node = u32_set_insert(&zone_policy_rule_definition_set, zone_policy_rule_definition_next_index);
        
        if(node->value == NULL)
        {
            rule->index = zone_policy_rule_definition_next_index;
            rule->type = ZONE_POLICY_RULE;

            zone_policy_rule_definition_s *new_rule_definition;
            ZALLOC_OBJECT_OR_DIE( new_rule_definition, zone_policy_rule_definition_s, DPOLRULE_TAG);
            memcpy(new_rule_definition, rule_definition, sizeof(zone_policy_rule_definition_s));
            node->value = new_rule_definition;
            break;
        }
    }
    
    group_mutex_write_unlock(&zone_policy_rule_definition_set_mtx);
}

void
zone_policy_rule_finalize(zone_policy_rule_s *rule)
{
    group_mutex_write_lock(&zone_policy_rule_definition_set_mtx);
    u32_node *node = u32_set_find(&zone_policy_rule_definition_set, rule->index);
    if(node != NULL)
    {
        if(node->value != NULL)
        {
            ZFREE(node->value, zone_policy_rule_definition_s);
        }
        
        u32_set_delete(&zone_policy_rule_definition_set, rule->index);
    }
    group_mutex_write_unlock(&zone_policy_rule_definition_set_mtx);
}

void
zone_policy_date_init_from_rule_definition(zone_policy_date *date, const zone_policy_rule_definition_s *rule_definition)
{
    
    date->type.type = ZONE_POLICY_RULE;
    zone_policy_rule_init(&date->rule, rule_definition);
}

/**
 * Initialises a date with the earliest matching of the rule starting after 'from'
 * 
 * @param date
 * @param from
 * @param rule
 * 
 * @return an error code
 */
ya_result
zone_policy_date_init_at_next_date(zone_policy_date *date, const zone_policy_date *from, const zone_policy_date *rule)
{
    ya_result ret;

    if((((intptr)date) == 0) | (((intptr)from) == 0) | (((intptr)rule) == 0))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

#if DEBUG
    format_writer from_fw = {zone_policy_date_format_handler_method, from};
    format_writer rule_fw = {zone_policy_date_format_handler_method, rule};
    format_writer date_fw = {zone_policy_date_format_handler_method, date};
#endif
    
    if(from->type.type != ZONE_POLICY_ABSOLUTE)
    {
#if DEBUG
        log_debug1("zone_policy_date_init_at_next_date(%p, %w, %w): can only work from an absolute time", date, &from_fw, &rule_fw);
#endif
        return POLICY_ILLEGAL_DATE_TYPE;
    }
    
    switch(rule->type.type)
    {
        case ZONE_POLICY_RELATIVE:
        {
            memcpy(date, from, sizeof(zone_policy_date));
#if DEBUG
            log_debug1("zone_policy_date_init_at_next_date(%p, %w, %w): initialising relative time", date, &from_fw, &rule_fw);
#endif
            ret = zone_policy_date_init_after_date(date, from, rule->relative.seconds); // +60 because it must be after and because of minute granularity
#if DEBUG
            log_debug1("zone_policy_date_init_at_next_date: %w = %w + %w", &date_fw, &from_fw, &rule_fw);
#endif
            return ret;
        }
        case ZONE_POLICY_RULE:
        {
#if DEBUG
            log_debug1("zone_policy_date_init_at_next_date(%p, %w, %w): initialising rule-based time", date, &from_fw, &rule_fw);
#endif
            ret = zone_policy_date_init_at_next_rule(date, from, rule);
#if DEBUG
            log_debug1("zone_policy_date_init_at_next_date: %w = %w + %w", &date_fw, &from_fw, &rule_fw);
#endif
            return ret;
        }
        default:
        {
#if DEBUG
            log_debug1("zone_policy_date_init_at_next_date(%p, %w, %w): unexpected type", date, &from_fw, &rule_fw);
#endif
            return POLICY_ILLEGAL_DATE_TYPE;
        }
    }
}

static zone_policy_date*
zone_policy_table_get_date_by_index(zone_policy_table_s *tbl, int index)
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
            log_err("zone_policy_table_get_date_by_index(%p, %i): index out of range [%i, %i]", tbl, index, ZONE_POLICY_RELATIVE_TO_GENERATE, ZONE_POLICY_RELATIVE_TO_REMOVE);
            return NULL;
    }
}

/**
 * This initialises a date with the earliest matching of the rule starting from 'from'
 *
 * @param date
 * @param from
 * @param rule
 *
 * @return an error code
 */
ya_result
zone_policy_date_init_from_date(zone_policy_date *date, const zone_policy_date *from, const zone_policy_date *rule)
{
    ya_result ret;

#if DEBUG
    format_writer from_fw = {zone_policy_date_format_handler_method, from};
    format_writer rule_fw = {zone_policy_date_format_handler_method, rule};
    format_writer date_fw = {zone_policy_date_format_handler_method, date};
#endif

    if(from->type.type != ZONE_POLICY_ABSOLUTE)
    {
#if DEBUG
        log_debug1("zone_policy_date_init_from_date(%p, %w, %w): can only work from an absolute time", date, &from_fw, &rule_fw);
#endif
        return POLICY_ILLEGAL_DATE_TYPE;
    }

    switch(rule->type.type)
    {
        case ZONE_POLICY_RELATIVE:
        {
            memcpy(date, from, sizeof(zone_policy_date));
#if DEBUG
            log_debug1("zone_policy_date_init_from_date(%p, %w, %w): initialising relative time", date, &from_fw, &rule_fw);
#endif
            ret = zone_policy_date_init_after_date(date, from, rule->relative.seconds);
#if DEBUG
            log_debug1("zone_policy_date_init_from_date: %w = %w + %w", &date_fw, &from_fw, &rule_fw);
#endif
            return ret;
        }
        case ZONE_POLICY_RULE:
        {
#if DEBUG
            log_debug1("zone_policy_date_init_from_date(%p, %w, %w): initialising rule-based time", date, &from_fw, &rule_fw);
#endif
            ret = zone_policy_date_init_from_rule(date, from, rule);
#if DEBUG
            log_debug1("zone_policy_date_init_from_date: %w = %w + %w", &date_fw, &from_fw, &rule_fw);
#endif
            return ret;
        }
        default:
        {
#if DEBUG
            log_debug1("zone_policy_date_init_from_date(%p, %w, %w): unexpected type", date, &from_fw, &rule_fw);
#endif
            return POLICY_ILLEGAL_DATE_TYPE;
        }
    }
}

ya_result
zone_policy_table_init_from_date(zone_policy_table_s *tbl, zone_policy_table_s *with, zone_policy_date *from)
{
    ya_result ret;
    
    if(with->created.type.type == ZONE_POLICY_RULE)
    {
        if(ISOK(ret = zone_policy_date_init_from_date(&tbl->created, from, &with->created)))
        {
            if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->publish, &tbl->created, &with->publish)))
            {
                if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->activate, &tbl->publish, &with->activate)))
                {
#if DEBUG
                    format_writer c_fw = {zone_policy_date_format_handler_method, &tbl->created};
                    format_writer p_fw = {zone_policy_date_format_handler_method, &tbl->publish};
                    format_writer a_fw = {zone_policy_date_format_handler_method, &tbl->activate};

                    log_debug("zone_policy_table_init: base c:%w => p:%w => a:%w", &c_fw, &p_fw, &a_fw);
#endif
                    // compute the future key timings to ensure there will be no period without a signature
                
                    zone_policy_date next_creation_date;
                    zone_policy_date next_publish_date;
                    zone_policy_date next_activate_date;

                    if(ISOK(ret = zone_policy_date_init_at_next_date(&next_creation_date, &tbl->activate, &with->created)))
                    {
                        if(ISOK(ret = zone_policy_date_init_at_next_date(&next_publish_date, &next_creation_date, &with->publish)))
                        {
                            if(ISOK(ret = zone_policy_date_init_at_next_date(&next_activate_date, &next_publish_date, &with->activate)))
                            {
#if DEBUG
                                format_writer na_fw = {zone_policy_date_format_handler_method, &next_activate_date};
                                format_writer np_fw = {zone_policy_date_format_handler_method, &next_publish_date};
                                format_writer nc_fw = {zone_policy_date_format_handler_method, &next_creation_date};

                                log_debug("zone_policy_table_init: next c:%w => p:%w => a:%w", &nc_fw, &np_fw, &na_fw);
#endif
                                if(ISOK(ret = zone_policy_date_init_from_date(&tbl->inactive, &next_activate_date, &with->inactive)))
                                {
#if HAS_DS_PUBLICATION_SUPPORT
                                    if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->delete, &tbl->inactive, &with->delete)))
                                    {
                                        if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->ds_add, &tbl->created, &with->ds_add)))
                                        {
                                            ret = zone_policy_date_init_at_next_date(&tbl->ds_del, &tbl->ds_add, &with->ds_del);
                                        }
                                    }
#else
                                    ret = zone_policy_date_init_at_next_date(&tbl->delete, &tbl->inactive, &with->delete);
#if DEBUG
                                    format_writer i_fw = {zone_policy_date_format_handler_method, &tbl->inactive};
                                    format_writer d_fw = {zone_policy_date_format_handler_method, &tbl->delete};

                                    log_debug("zone_policy_table_init_from_date: base i:%w => d:%w", &i_fw, &d_fw);
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
        if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->created, from, &with->created))) // here !
        {
            if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->publish, &tbl->created, &with->publish)))
            {
                if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->activate, zone_policy_table_get_date_by_index(tbl, with->activate.relative.relativeto), &with->activate)))
                {
                    if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->inactive, zone_policy_table_get_date_by_index(tbl, with->inactive.relative.relativeto), &with->inactive)))
                    {
                        if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->delete, zone_policy_table_get_date_by_index(tbl, with->delete.relative.relativeto), &with->delete)))
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
zone_policy_table_init_from_created_epoch(zone_policy_table_s *tbl, zone_policy_table_s *with, time_t created_epoch)
{
    ya_result ret;
    
    if(FAIL(ret = zone_policy_date_init_from_epoch(&tbl->created, created_epoch)))
    {
        return ret;
    }
    
    if(with->created.type.type == ZONE_POLICY_RULE)
    {
        if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->publish, &tbl->created, &with->publish)))
        {
            if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->activate, &tbl->publish, &with->activate)))
            {
#if DEBUG
                format_writer c_fw = {zone_policy_date_format_handler_method, &tbl->created};
                format_writer p_fw = {zone_policy_date_format_handler_method, &tbl->publish};
                format_writer a_fw = {zone_policy_date_format_handler_method, &tbl->activate};

                log_debug("zone_policy_table_init: base %w => %w => %w", &c_fw, &p_fw, &a_fw);
#endif
                // compute the future key timings to ensure there will be no period without a signature

                zone_policy_date next_creation_date;
                zone_policy_date next_publish_date;
                zone_policy_date next_activate_date;

                if(ISOK(ret = zone_policy_date_init_at_next_date(&next_creation_date, &tbl->activate, &with->created)))
                {
                    if(ISOK(ret = zone_policy_date_init_at_next_date(&next_publish_date, &next_creation_date, &with->publish)))
                    {
                        if(ISOK(ret = zone_policy_date_init_at_next_date(&next_activate_date, &next_publish_date, &with->activate)))
                        {
#if DEBUG
                            format_writer na_fw = {zone_policy_date_format_handler_method, &next_activate_date};
                            format_writer np_fw = {zone_policy_date_format_handler_method, &next_publish_date};
                            format_writer nc_fw = {zone_policy_date_format_handler_method, &next_creation_date};

                            log_debug("zone_policy_table_init: next %w => %w => %w", &nc_fw, &np_fw, &na_fw);
#endif
                            if(ISOK(ret = zone_policy_date_init_from_date(&tbl->inactive, &next_activate_date, &with->inactive)))
                            {
#if HAS_DS_PUBLICATION_SUPPORT
                                if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->delete, &tbl->inactive, &with->delete)))
                                {
                                    if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->ds_add, &tbl->created, &with->ds_add)))
                                    {
                                        ret = zone_policy_date_init_at_next_date(&tbl->ds_del, &tbl->ds_add, &with->ds_del);
                                    }
                                }
#else
                                ret = zone_policy_date_init_at_next_date(&tbl->delete, &tbl->inactive, &with->delete);
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
        if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->publish, &tbl->created, &with->publish)))
        {
            if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->activate, zone_policy_table_get_date_by_index(tbl, with->activate.relative.relativeto), &with->activate)))
            {
                if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->inactive, zone_policy_table_get_date_by_index(tbl, with->inactive.relative.relativeto), &with->inactive)))
                {
                    if(ISOK(ret = zone_policy_date_init_at_next_date(&tbl->delete, zone_policy_table_get_date_by_index(tbl, with->delete.relative.relativeto), &with->delete)))
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

ya_result
zone_policy_table_init_from_epoch(zone_policy_table_s *tbl, zone_policy_table_s *with, time_t created_epoch)
{
    ya_result ret;
    
    zone_policy_date epoch_date;
    zone_policy_date_init_from_epoch(&epoch_date, created_epoch);
    ret = zone_policy_table_init_from_date(tbl, with, &epoch_date);

    return ret;
}

static bool
zone_policy_key_roll_matches(const struct dnssec_policy_key_suite *kr, const dnssec_key *key)
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
                    log_debug1("dnssec-policy: %s: %s: key %05d/%d timings: %T %T %T %T %T",
                            key->origin,
                            kr->name,
                            dnskey_get_tag_const(key), ntohs(key->flags),
                            key->epoch_created, key->epoch_publish, key->epoch_activate, key->epoch_inactive, key->epoch_delete);
                    
                    zone_policy_table_s key_tbl;
                    if(ISOK(zone_policy_table_init_from_created_epoch(&key_tbl, &kr->roll->time_table, key->epoch_created)))
                    {
                        time_t key_created = 0, key_publish = 0, key_activate = 0, key_inactive = 0, key_delete = 0;
                        zone_policy_date_get_epoch(&key_tbl.created, &key_created);
                        zone_policy_date_get_epoch(&key_tbl.publish, &key_publish);
                        zone_policy_date_get_epoch(&key_tbl.activate, &key_activate);
                        zone_policy_date_get_epoch(&key_tbl.inactive, &key_inactive);
                        zone_policy_date_get_epoch(&key_tbl.delete, &key_delete);

                        s64 pait = key_inactive - key_activate;
                        s64 kait = key->epoch_inactive - key->epoch_activate;
                        s64 dait = labs(pait - kait);

                        s64 pidt = key_delete - key_inactive;
                        s64 kidt = key->epoch_delete - key->epoch_inactive;
                        s64 didt = labs(pidt - kidt);

                        s64 dc = labs(key_created - key->epoch_created);
                        s64 dp = labs(key_publish - key->epoch_publish);
                        s64 da = labs(key_activate - key->epoch_activate);
                        s64 di = labs(key_inactive - key->epoch_inactive);
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

                        log_debug1("dnssec-policy: %s: %s: key %05d/%d expects: %T %T %T %T %T : %s",
                                key->origin,
                                kr->name,
                                dnskey_get_tag_const(key), ntohs(key->flags),
                                key_created, key_publish, key_activate, key_inactive, key_delete,
                                ((match)?"MATCH":"DIFFERS"));

                        return match;
                    } // else zone_policy_table_init_from_created_epoch failed and something is wrong => false
                    else
                    {
                        log_err("dnssec-policy: %s: %s: key %05d/%d matching triggered an error in zone_policy_table_init_from_created_epoch",
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

static int zone_policy_dnssec_key_ptr_vector_qsort_by_activation_time_callback(const void *a_, const void *b_)
{
    const dnssec_key *a = (const dnssec_key*)a_;
    const dnssec_key *b = (const dnssec_key*)b_;
    
    s64 a_a = a->epoch_activate;
    if(a_a == 0)
    {
        a_a = MAX_S64;
    }
    
    s64 b_a = b->epoch_activate;
    if(b_a == 0)
    {
        b_a = MAX_S64;
    }
    
    s64 r = a_a - b_a;
    
    if(r == 0)
    {
        s64 a_i = a->epoch_inactive;
        if(a_i == 0)
        {
            a_i = MAX_S64;
        }

        s64 b_i = b->epoch_inactive;
        if(b_i == 0)
        {
            b_i = MAX_S64;
        }
        
        r = a_i - b_i;
        
        if(r == 0)
        {
            r = dnskey_get_tag_const(a) - dnskey_get_tag_const(b);
        }
    }
    
    return r;
}

static void
zone_policy_log_debug_key(const char *prefix, const dnssec_key *key)
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

static struct service_s dnssec_policy_command_service_handler = UNINITIALIZED_SERVICE;
static threaded_dll_cw dnssec_policy_command_service_handler_queue;
static bool dnssec_policy_command_service_handler_initialised = FALSE;

static ya_result dnssec_policy_alarm_command_generate_key(dnssec_policy_queue *cmd);
void dnssec_policy_queue_delete_command(dnssec_policy_queue *cmd);

static int dnssec_policy_command_service(struct service_worker_s *worker)
{
    log_info("dnssec-policy: command execution service started");

    while(service_should_run(worker))
    {
        dnssec_policy_queue *cmd = (dnssec_policy_queue*)threaded_dll_cw_dequeue(&dnssec_policy_command_service_handler_queue);

        if(cmd == NULL)
        {
            break;
        }

        switch(cmd->command)
        {
            case DNSSEC_POLICY_COMMAND_INIT:
            {
#if DEBUG
                log_debug("dnssec-policy: init command");
#endif
                dnssec_policy_queue_delete_command(cmd);
                break;
            }
            case DNSSEC_POLICY_COMMAND_GENERATE_KEY:
            {
#if DEBUG
                log_debug("dnssec-policy: generate key command");
#endif
                dnssec_policy_alarm_command_generate_key(cmd); // deletes the command
                break;
            }
            default:
            {
                log_err("dnssec-policy: unknown command %i", cmd->command);
                dnssec_policy_queue_delete_command(cmd);
                break;
            }
        }

    }

    log_info("dnssec-policy: command execution service stopped");

    return SUCCESS;
}

void
dnssec_policy_command_service_start()
{
    ya_result ret;
    if(!dnssec_policy_command_service_handler_initialised)
    {
        if(ISOK(ret = service_init_ex(&dnssec_policy_command_service_handler, dnssec_policy_command_service, "dpcmd", 8)))
        {
            threaded_dll_cw_init(&dnssec_policy_command_service_handler_queue, 1000000);
            dnssec_policy_command_service_handler_initialised = TRUE;
        }

        service_start(&dnssec_policy_command_service_handler);
    }
}

void
dnssec_policy_command_service_stop()
{
    threaded_dll_cw_finalize(&dnssec_policy_command_service_handler_queue);
}

void
dnssec_policy_command_queue(dnssec_policy_queue *cmd)
{
    threaded_dll_cw_enqueue(&dnssec_policy_command_service_handler_queue, cmd);
}

static ya_result
dnssec_policy_alarm_command_generate_key(dnssec_policy_queue *cmd)
{
    zone_policy_table_s tbl;
    zone_policy_date from;
    const char *algorithm_name = dns_encryption_algorithm_get_name(cmd->parameters.generate_key.suite->key->algorithm);
    char domain[MAX_DOMAIN_LENGTH];
    // from ... the time to take as a base for generation, which is the previous 


    log_info("dnssec-policy: %{dnsname}: generating %s key of size %hu with time parameter %T",
             cmd->origin,
             algorithm_name,
             cmd->parameters.generate_key.suite->key->size,
             cmd->epoch);

    dnsname_to_cstr(domain, cmd->origin);

    ya_result ret;

    if(FAIL(ret = zone_policy_date_init_from_epoch(&from, cmd->epoch)))
    {
        log_err("dnssec-policy: %{dnsname}: failed to generate %s key of size %hu with time parameter %T: %r",
                cmd->origin,
                algorithm_name,
                cmd->parameters.generate_key.suite->key->size,
                cmd->epoch,
                ret);

        zone_policy_key_suite_unmark_processed(cmd->parameters.generate_key.zone_desc, cmd->parameters.generate_key.suite);

        dnssec_policy_key_suite_release(cmd->parameters.generate_key.suite);
        cmd->parameters.generate_key.suite = NULL;

        dnssec_policy_queue_delete_command(cmd);

        return ret;
    }

    if(FAIL(ret = zone_policy_table_init_from_date(&tbl, &cmd->parameters.generate_key.suite->roll->time_table, &from)))
    {
        log_err("dnssec-policy: %{dnsname}: failed to generate time-table for %s key of size %hu with time parameter %T: %r",
                cmd->origin,
                algorithm_name,
                cmd->parameters.generate_key.suite->key->size,
                cmd->epoch,
                ret);

        zone_policy_key_suite_unmark_processed(cmd->parameters.generate_key.zone_desc, cmd->parameters.generate_key.suite);
        dnssec_policy_key_suite_release(cmd->parameters.generate_key.suite);
        cmd->parameters.generate_key.suite = NULL;
        dnssec_policy_queue_delete_command(cmd);

        return ret;
    }

    log_debug("dnssec-policy: %{dnsname}: time-table for %s key of size %hu with time parameter %T generated",
              cmd->origin,
              algorithm_name,
              cmd->parameters.generate_key.suite->key->size,
              cmd->epoch);

    time_t created_epoch;
    time_t publish_epoch;
    time_t activate_epoch;
    time_t deactivate_epoch;
    time_t unpublish_epoch;

    if(FAIL(ret = zone_policy_date_get_epoch(&tbl.created, &created_epoch))) // note: created should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_date_get_epoch (created_epoch) returned an error: %r", ret);
        zone_policy_key_suite_unmark_processed(cmd->parameters.generate_key.zone_desc, cmd->parameters.generate_key.suite);
        dnssec_policy_key_suite_release(cmd->parameters.generate_key.suite);
        cmd->parameters.generate_key.suite = NULL;
        dnssec_policy_queue_delete_command(cmd);
        return ret;
    }

    if(FAIL(ret = zone_policy_date_get_epoch(&tbl.publish, &publish_epoch))) // note: publish should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_date_get_epoch (publish_epoch) returned an error: %r", ret);
        zone_policy_key_suite_unmark_processed(cmd->parameters.generate_key.zone_desc, cmd->parameters.generate_key.suite);
        dnssec_policy_key_suite_release(cmd->parameters.generate_key.suite);
        cmd->parameters.generate_key.suite = NULL;
        dnssec_policy_queue_delete_command(cmd);
        return ret;
    }

    if(FAIL(ret = zone_policy_date_get_epoch(&tbl.activate, &activate_epoch))) // note: activate should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_date_get_epoch (activate_epoch) returned an error: %r", ret);
        zone_policy_key_suite_unmark_processed(cmd->parameters.generate_key.zone_desc, cmd->parameters.generate_key.suite);
        dnssec_policy_key_suite_release(cmd->parameters.generate_key.suite);
        cmd->parameters.generate_key.suite = NULL;
        dnssec_policy_queue_delete_command(cmd);
        return ret;
    }

    if(FAIL(ret = zone_policy_date_get_epoch(&tbl.inactive, &deactivate_epoch))) // note: deactivate should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_date_get_epoch (deactivate_epoch) returned an error: %r", ret);
        zone_policy_key_suite_unmark_processed(cmd->parameters.generate_key.zone_desc, cmd->parameters.generate_key.suite);
        dnssec_policy_key_suite_release(cmd->parameters.generate_key.suite);
        cmd->parameters.generate_key.suite = NULL;
        dnssec_policy_queue_delete_command(cmd);
        return ret;
    }

    if(FAIL(ret = zone_policy_date_get_epoch(&tbl.delete, &unpublish_epoch))) // note: unpublish should be of type ZONE_POLICY_ABSOLUTE
    {
        log_err("dnssec_policy_queue_add_generate_key_create_at: zone_policy_date_get_epoch (unpublish_epoch) returned an error: %r", ret);
        zone_policy_key_suite_unmark_processed(cmd->parameters.generate_key.zone_desc, cmd->parameters.generate_key.suite);
        dnssec_policy_key_suite_release(cmd->parameters.generate_key.suite);
        cmd->parameters.generate_key.suite = NULL;
        dnssec_policy_queue_delete_command(cmd);
        return ret;
    }

    dnssec_key *key;
    ret = dnssec_keystore_new_key(cmd->parameters.generate_key.suite->key->algorithm,
                                  cmd->parameters.generate_key.suite->key->size,
                                  cmd->parameters.generate_key.suite->key->flags|DNSKEY_FLAGS_ZSK,
                                  domain,
                                  &key);

    if(ISOK(ret))
    {
        key->epoch_created = created_epoch;
        key->epoch_publish = publish_epoch;
        key->epoch_activate = activate_epoch;
        key->epoch_inactive = deactivate_epoch;
        key->epoch_delete = unpublish_epoch;

        key->status |= DNSKEY_KEY_HAS_SMART_FIELD_CREATED|DNSKEY_KEY_HAS_SMART_FIELD_PUBLISH|DNSKEY_KEY_HAS_SMART_FIELD_DELETE|DNSKEY_KEY_HAS_SMART_FIELD_ACTIVATE|DNSKEY_KEY_HAS_SMART_FIELD_INACTIVE;

        dnssec_keystore_store_private_key(key);
        dnssec_keystore_store_public_key(key);

        log_info("dnssec-policy: %{dnsname}: key K%{dnsname}+%03d+%05d/%d generated from %T: created at %T, publish at %T, activate at %T, inactive at %T, delete at %T",
                 cmd->origin, cmd->origin, key->algorithm, dnskey_get_tag(key), ntohs(key->flags), cmd->epoch,
                 key->epoch_created, key->epoch_publish, key->epoch_activate, key->epoch_inactive, key->epoch_delete
        );

#if HAS_EVENT_DYNAMIC_MODULE
        if(dynamic_module_dnskey_interface_chain_available())
        {
            dynamic_module_on_dnskey_created(key);
        }
#endif
        zdb_zone* zone = zdb_acquire_zone_read_from_fqdn(g_config->database, cmd->origin);
        if(zone != NULL)
        {
            database_service_zone_dnskey_set_alarms(zone);
            zdb_zone_release(zone);
        }

        zone_desc_s *zone_desc = cmd->parameters.generate_key.zone_desc;
        dnssec_policy_key_suite *kr = cmd->parameters.generate_key.suite;

        if(kr->roll->time_table.created.type.type == ZONE_POLICY_RELATIVE)
        {
            if(FAIL(ret = dnssec_policy_queue_add_generate_key_create_at(zone_desc, kr, key->epoch_created)))
            {
                log_err("dnssec-policy: %{dnsname}: %s: failed to setup key generation from previous key: %r", zone_origin(zone_desc), kr->name, ret);
            }
        }
        else if(kr->roll->time_table.created.type.type == ZONE_POLICY_RULE)
        {
            if(FAIL(ret = dnssec_policy_queue_add_generate_key_active_at(zone_desc, kr, key->epoch_inactive, NULL)))
            {
                log_err("dnssec-policy: %{dnsname}: %s: failed to setup key generation from previous end period: %r", zone_origin(zone_desc), kr->name, ret);
            }
        }

        dnskey_release(key);
    }
    else
    {
        log_err("dnssec-policy: %{dnsname}: failed to generate key: %r This is likely to break the policy maintenance state for the zone.", cmd->origin, ret);
    }

    zone_policy_key_suite_unmark_processed(cmd->parameters.generate_key.zone_desc, cmd->parameters.generate_key.suite);

    dnssec_policy_key_suite_release(cmd->parameters.generate_key.suite);
    cmd->parameters.generate_key.suite = NULL;

    dnssec_policy_queue_delete_command(cmd);

    return ret;
}

static ya_result
dnssec_policy_alarm_handler(void *args, bool cancel)
{
    dnssec_policy_queue *cmd = (dnssec_policy_queue*)args;

#if DEBUG
    log_debug("dnssec-policy: alarm(%p,%i)", cmd, cancel);
#endif

    if(cancel)
    {
        dnssec_policy_queue_remove_command(cmd);
        dnssec_policy_queue_delete_command(cmd);
        return SUCCESS;
    }

    dnssec_policy_command_queue(cmd);

    return SUCCESS;
}

static void
zone_policy_nsec_enable(zdb_zone *zone)
{
    //zdb_zone_double_lock();
    zdb_zone_double_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
    zdb_rr_label_flag_or(zone->apex, ZDB_RR_LABEL_NSEC);
    if(zdb_rr_label_has_rrset(zone->apex, TYPE_DNSKEY))
    {
        nsec_zone_set_status(zone, ZDB_ZONE_MUTEX_DYNUPDATE, NSEC_ZONE_ENABLED|NSEC_ZONE_GENERATING);
    }
    zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
}

static void
zone_policy_nsec3_enable(zdb_zone *zone, dnssec_denial *denial)
{
    u8 *salt;
    u8 salt_len;
    u8 salt_buffer[256];

    if(denial->salt != NULL)
    {
        salt = denial->salt;
        salt_len = denial->salt_length;
    }
    else
    {
        random_ctx rnd = random_init_auto();

        salt = &salt_buffer[0];
        salt_len = denial->salt_length;
        for(int i = 0; i < salt_len; ++i)
        {
            salt[i] = random_next(rnd);
        }

        random_finalize(rnd);
    }

    u8 flags = (denial->optout)?1:0;
    u8 current_status = 0;

    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);

    if(zdb_rr_label_has_rrset(zone->apex, TYPE_DNSKEY))
    {
        ya_result got_status = nsec3_zone_get_status(zone, denial->algorithm, flags, denial->iterations, salt, salt_len, &current_status);
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        if(got_status == 1)
        {
            if(current_status & NSEC3_ZONE_ENABLED)
            {
                return;
            }
        }
        zdb_zone_double_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
        nsec3_zone_set_status(zone, ZDB_ZONE_MUTEX_DYNUPDATE, denial->algorithm, flags, denial->iterations, salt, salt_len, NSEC3_ZONE_ENABLED|NSEC3_ZONE_GENERATING);
        zdb_zone_double_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER, ZDB_ZONE_MUTEX_DYNUPDATE);
    }
    else
    {
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    }
}

ya_result
zone_policy_roll_create_from_rules(const char *id,
                                   const zone_policy_rule_definition_s *generate,
                                   const zone_policy_rule_definition_s *publish,
                                   const zone_policy_rule_definition_s *activate,
                                   const zone_policy_rule_definition_s *inactive,
                                   const zone_policy_rule_definition_s *remove,
                                   const zone_policy_rule_definition_s *ds_publish,
                                   const zone_policy_rule_definition_s *ds_remove)
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

    zone_policy_rule_init(&dpr->time_table.created.rule, generate);
    zone_policy_rule_init(&dpr->time_table.publish.rule, publish);
    zone_policy_rule_init(&dpr->time_table.activate.rule, activate);
    zone_policy_rule_init(&dpr->time_table.inactive.rule, inactive);
    zone_policy_rule_init(&dpr->time_table.delete.rule, remove);
#if HAS_DS_PUBLICATION_SUPPORT
    zone_policy_rule_init(&dpr->time_table.ds_add.rule, ds_publish);
    zone_policy_rule_init(&dpr->time_table.ds_del.rule, ds_remove);
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
zone_policy_roll_create_from_relatives(const char *id,
                                       const zone_policy_relative_s *generate,
                                       u8 generate_from,
                                       const zone_policy_relative_s *publish,
                                       u8 publish_from,
                                       const zone_policy_relative_s *activate,
                                       u8 activate_from,
                                       const zone_policy_relative_s *inactive,
                                       u8 inactive_from,
                                       const zone_policy_relative_s *remove,
                                       u8 remove_from
#if HAS_DS_PUBLICATION_SUPPORT
                                       ,
                                       const zone_policy_relative_s *ds_publish,
                                       u8 ds_publish_from,
                                       const zone_policy_relative_s *ds_remove,
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

ya_result
dnssec_policy_roll_test_all(time_t active_at, u32 duration_seconds, bool print_text, bool log_text)
{
    ya_result ret = SUCCESS;

    group_mutex_read_lock(&dnssec_policy_roll_set_mtx);

    ptr_set_iterator iter;
    ptr_set_iterator_init(&dnssec_policy_roll_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        if(node->value != NULL)
        {
            dnssec_policy_roll *dpr = (dnssec_policy_roll*)node->value;
            if(FAIL(ret = dnssec_policy_roll_test(dpr, active_at, duration_seconds, print_text, log_text)))
            {
                break;
            }
        }
    }

    group_mutex_read_unlock(&dnssec_policy_roll_set_mtx);

    return ret;
}

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
            zone_policy_rule_finalize(&dpr->time_table.created.rule);
        }
        if(dpr->time_table.publish.type.type == ZONE_POLICY_RULE)
        {
            zone_policy_rule_finalize(&dpr->time_table.publish.rule);
        }
        if(dpr->time_table.activate.type.type == ZONE_POLICY_RULE)
        {
            zone_policy_rule_finalize(&dpr->time_table.activate.rule);
        }
        if(dpr->time_table.inactive.type.type == ZONE_POLICY_RULE)
        {
            zone_policy_rule_finalize(&dpr->time_table.inactive.rule);
        }
        if(dpr->time_table.delete.type.type == ZONE_POLICY_RULE)
        {
            zone_policy_rule_finalize(&dpr->time_table.delete.rule);
        }
#if HAS_DS_PUBLICATION_SUPPORT
        if(dpr->time_table.ds_add.type.type == ZONE_POLICY_RULE)
        {
            zone_policy_rule_finalize(&dpr->time_table.ds_add.rule);
        }
        if(dpr->time_table.ds_del.type.type == ZONE_POLICY_RULE)
        {
            zone_policy_rule_finalize(&dpr->time_table.ds_del.rule);
        }
#endif
        free(dpr->name);
        ZFREE_OBJECT(dpr);
    }
    group_mutex_write_unlock(&dnssec_policy_roll_mtx);
}

dnssec_denial *
dnssec_policy_denial_create(const char *id, u8 algorithm, u16 iterations, const u8 *salt, u8 salt_length, u32 resalting, bool optout)
{
    log_debug("dnssec-policy-denial: %s: algorithm=%hhu, iterations=%hu, salt@%p, salt_length=%hhu, resalting=%u",
            id, algorithm, iterations, salt, salt_length, resalting);
    
    dnssec_denial *dd = NULL;
    ZALLOC_OBJECT_OR_DIE( dd, dnssec_denial, DPOLDNIL_TAG);
    dd->name = strdup(id);
    if(salt != NULL && salt_length > 0)
    {
        ZALLOC_ARRAY_OR_DIE(u8*, dd->salt, salt_length, DPOLSALT_TAG);
        memcpy(dd->salt, salt, salt_length);
    }
    else
    {
        dd->salt = NULL;
    }
    
    dd->resalting = resalting;
    dd->iterations = iterations;
    dd->algorithm = algorithm;
    dd->salt_length = salt_length;
    dd->optout = optout;
    dd->rc = 1;
    
    group_mutex_write_lock(&dnssec_denial_set_mtx);
    ptr_node *node = ptr_set_insert(&dnssec_denial_set, dd->name);
    if(node->value != NULL)
    {
        dnssec_policy_denial_release((dnssec_denial*)node->value);
    }
    node->key = dd->name;
    node->value = dd;
    group_mutex_write_unlock(&dnssec_denial_set_mtx);

    return dd;
}


dnssec_denial *
dnssec_policy_denial_acquire(const char *id)
{
    dnssec_denial *dd = NULL;
    group_mutex_read_lock(&dnssec_denial_set_mtx);
    ptr_node *node = ptr_set_find(&dnssec_denial_set, id);
    if(node != NULL && node->value != NULL)
    {
        dd = (dnssec_denial*)node->value;
        group_mutex_write_lock(&dnssec_denial_mtx);
        ++dd->rc;
        group_mutex_write_unlock(&dnssec_denial_mtx);
    }
    group_mutex_read_unlock(&dnssec_denial_set_mtx);

    return dd;
}

void
dnssec_policy_denial_release(dnssec_denial *dd)
{
    if(dd == NULL) return;
    
    group_mutex_write_lock(&dnssec_denial_mtx);
    if(--dd->rc == 0)
    {
        if(dd->salt != NULL)
        {
            ZFREE_ARRAY(dd->salt, dd->salt_length);
        }
        free(dd->name);
        ZFREE_OBJECT(dd);
    }
    group_mutex_write_unlock(&dnssec_denial_mtx);
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

dnssec_policy *
dnssec_policy_create(char *name, dnssec_denial *dd, ptr_vector *key_suite)
{
    dnssec_policy *dp = NULL;

    log_debug("dnssec-policy: %s: denial=%s", name, (dd!=NULL)?dd->name:"nsec");
    bool has_zsk = FALSE;
    ZALLOC_OBJECT_OR_DIE( dp, dnssec_policy, DNSECPOL_TAG);
    dp->name = strdup(name);
    dp->denial= (dd!=NULL)?dnssec_policy_denial_acquire(dd->name):NULL;
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
        dnssec_policy_denial_release(dp->denial);
        for(int i = 0; i <= ptr_vector_last_index(&dp->key_suite); ++i)
        {
            dnssec_policy_key_suite *dpks = (dnssec_policy_key_suite*)ptr_vector_get(&dp->key_suite, i);
            dnssec_policy_key_suite_release(dpks);
        }
        ptr_vector_destroy(&dp->key_suite);
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
zone_policy_process_release_keys_cb(void *ptr)
{
    dnssec_key *key = (dnssec_key*)ptr;
    if(key != NULL)
    {
        dnskey_release(key);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////
//
// This is where yadifad and the keyroll fundamentally differs
//
////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Sets the DNSSEC mode of the zone using the policy.
 */

ya_result
zone_policy_process_dnssec_chain(zone_desc_s *zone_desc)
{
    zdb_zone *zone = zone_desc->loaded_zone;

    if(zone == NULL)
    {
        return INVALID_STATE_ERROR;
    }

    const dnssec_policy *policy = zone_desc->dnssec_policy;

    if(policy == NULL)
    {
        return SUCCESS; // nothing to do
    }

    u8 zone_dnssec_type = zone_policy_guess_dnssec_type(zone);

    if(policy->denial == NULL)
    {
        // zone is expected to be NSEC

        zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC);

        switch(zone_dnssec_type)
        {
            case ZONE_DNSSEC_FL_NOSEC:
            {
                // generate NSEC now
                log_info("dnssec-policy: %{dnsname}: zone will be secured with NSEC", zone_origin(zone_desc));
                zone_policy_nsec_enable(zone);
                break;
            }
            case ZONE_DNSSEC_FL_NSEC:
            {
                // do nothing
                if((zone->nsec.nsec->children.lr.right == NULL) && (zone->nsec.nsec->children.lr.left == NULL))
                {
                    log_info("dnssec-policy: %{dnsname}: zone is NSEC, chain is probably incomplete", zone_origin(zone_desc));
                    zone_policy_nsec_enable(zone);
                }
                else
                {
                    log_info("dnssec-policy: %{dnsname}: zone is NSEC", zone_origin(zone_desc));
                }
                break;
            }
            case ZONE_DNSSEC_FL_NSEC3:
            case ZONE_DNSSEC_FL_NSEC3_OPTOUT:
            {
                log_warn("dnssec-policy: %{dnsname}: zone is secured by NSEC3 but policy is made for NSEC", zone_origin(zone_desc));
                break;
            }
        }
    }
    else
    {
        if(policy->denial->optout)
        {
            zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT);
        }
        else
        {
            zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3);
        }

        // zone is expected to be NSEC3
        switch(zone_dnssec_type)
        {
            case ZONE_DNSSEC_FL_NOSEC:
            {
                // generate NSEC now
                log_info("dnssec-policy: %{dnsname}: zone will be secured with NSEC3", zone_origin(zone_desc));

                zone_policy_nsec3_enable(zone, policy->denial);

                break;
            }
            case ZONE_DNSSEC_FL_NSEC:
            {
                // do nothing
                log_warn("dnssec-policy: %{dnsname}: zone is an NSEC type but policy is made for NSEC3", zone_origin(zone_desc));
                break;
            }
            case ZONE_DNSSEC_FL_NSEC3:
            case ZONE_DNSSEC_FL_NSEC3_OPTOUT:
            {
                if((zone->nsec.nsec3->items->children.lr.left == NULL) && (zone->nsec.nsec3->items->children.lr.right == NULL))
                {
                    log_info("dnssec-policy: %{dnsname}: zone is NSEC3, chain is probably incomplete", zone_origin(zone_desc));
                    zone_policy_nsec3_enable(zone, policy->denial);
                }
                else
                {
                    log_info("dnssec-policy: %{dnsname}: zone is NSEC3", zone_origin(zone_desc));
                }
                break;
            }
        }
    }

    return SUCCESS;
}

ya_result
zone_policy_process(zone_desc_s *zone_desc)
{
    // the policy is referenced by the zone desc
    // and the zone desc by the parent
    // no need to acquire anything here

    ya_result final_ret = SUCCESS;
    ya_result ret;

    dnssec_policy_initialise();

    log_debug("dnssec-policy: %{dnsname} process", zone_origin(zone_desc));

    if(zone_desc->type != ZT_MASTER)
    {
        log_debug("dnssec-policy: %{dnsname} is not a master zone", zone_origin(zone_desc));

        return INVALID_STATE_ERROR;   // not a master zone
    }

    const dnssec_policy *policy = zone_desc->dnssec_policy;

    if(policy == NULL)
    {
        log_debug("dnssec-policy: %{dnsname} has no policy", zone_origin(zone_desc));

        zone_lock(zone_desc, ZONE_LOCK_READONLY);
        zdb_zone *zone = zone_desc->loaded_zone;
        if(zone != NULL)
        {
            zdb_zone_acquire(zone);

            if(zdb_zone_isvalid(zone))
            {
                /*
                if(zone_desc->dnssec_mode != 0)
                {
                    zdb_zone_set_maintained(zone, TRUE);
                    //zone_desc_dnssec_mode = zone_desc->dnssec_mode << ZDB_ZONE_DNSSEC_SHIFT;
                }
                */
            }
            zdb_zone_release(zone);
        }

        zone_unlock(zone_desc, ZONE_LOCK_READONLY);

        return SUCCESS;
    }

    // Look in the commands for a full init.  If one is present then nothing more can be done.

    if(dnssec_policy_queue_has_command_type(zone_origin(zone_desc), DNSSEC_POLICY_COMMAND_INIT))
    {
        log_debug("dnssec-policy: %{dnsname} is already marked for full generation", zone_origin(zone_desc));
        return SUCCESS;
    }

    const char *denial_name = (policy->denial == NULL)?"nsec":policy->denial->name;

    log_debug("dnssec-policy: %{dnsname} has policy %s/%s with %i keys", zone_origin(zone_desc), policy->name, denial_name, ptr_vector_size(&policy->key_suite));

    // get the current DNSSEC status of the zone

    zone_lock(zone_desc, ZONE_LOCK_READONLY);
    zdb_zone *zone = zone_desc->loaded_zone;
    if(zone != NULL)
    {
        zdb_zone_acquire(zone);
        zone_unlock(zone_desc, ZONE_LOCK_READONLY);
    }
    else
    {
        log_warn("dnssec-policy: %{dnsname}: settings are not linked to a loaded zone", zone_origin(zone_desc));
        zone_unlock(zone_desc, ZONE_LOCK_READONLY);
        return POLICY_ZONE_NOT_READY;
    }

    log_debug("dnssec-policy: %{dnsname} zone acquired", zone->origin);

    if(zdb_zone_isvalid(zone))
    {
        zone->sig_validity_regeneration_seconds = zone_desc->signature.sig_validity_regeneration * SIGNATURE_VALIDITY_REGENERATION_S;
        zone->sig_validity_interval_seconds = zone_desc->signature.sig_validity_interval * SIGNATURE_VALIDITY_INTERVAL_S;
        zone->sig_validity_jitter_seconds = zone_desc->signature.sig_validity_jitter * SIGNATURE_VALIDITY_JITTER_S;

#if DEBUG_FORCE_INSANE_SIGNATURE_MAINTENANCE_PARAMETERS
        zone->sig_validity_regeneration_seconds = 90;
        zone->sig_validity_interval_seconds = 180;
        zone->sig_validity_jitter_seconds = 5;
#endif

        zdb_zone_set_maintained(zone, TRUE);

        // set DNSSEC mode using the policy

        zone_policy_process_dnssec_chain(zone_desc);
    }
    else // zone is not valid
    {
        log_err("dnssec-policy: %{dnsname}: unable to manage DNSSEC status of invalid zone", zone_origin(zone_desc));
        log_debug("dnssec-policy: %{dnsname} released", zone->origin);
        zdb_zone_release(zone);
        return INVALID_STATE_ERROR;
    }

    // enumerate the available keys and if they are in the zone and being used and so on.

    // KEEP, IGNORE, REMOVE

    ptr_vector key_roll_keys[DNSSEC_POLICY_KEY_ROLL_COUNT_MAXIMUM];

    for(int i = 0; i < DNSSEC_POLICY_KEY_ROLL_COUNT_MAXIMUM; ++i)
    {
        ptr_vector_init_ex(&key_roll_keys[i], 0); // with an initial capacity set to 0, no allocation is made until at least one item is added
    }

    yassert(ptr_vector_size(&policy->key_suite) <= 8);

    for(int i = 0; ; ++i)
    {
        dnssec_key *key = dnssec_keystore_acquire_key_from_fqdn_at_index(zone_origin(zone_desc), i);

        if(key == NULL)
        {
            break;
        }

        zone_policy_log_debug_key("dnssec-policy: found ", key);

        /*
         * @note 20160425 edf -- care must be taken here, keys may be generated in an another thread.
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

        if(dnskey_is_expired_now(key) ||

           (key->epoch_publish == 0) ||
           (key->epoch_inactive == 0))
        {
            zone_policy_log_debug_key("dnssec-policy: ignore ", key);
            // this key is irrelevant. It will be released after this control block.
        }

        else
        {
            // for all key suite, if the key matches the suite, add the key to the suite array
            for(int j = 0; j <= ptr_vector_last_index(&policy->key_suite); ++j)
            {
                const struct dnssec_policy_key_suite *kr = (const struct dnssec_policy_key_suite*)ptr_vector_get(&policy->key_suite, j);

                if(zone_policy_key_suite_is_marked_processed(zone_desc, kr))
                {
                    continue;
                }

                if(zone_policy_key_roll_matches(kr, key))
                {
                    char tmp[512];
                    snformat(tmp,sizeof(tmp), "dnssec-policy: matches %s", policy->name);
                    zone_policy_log_debug_key(tmp, key);

                    dnskey_acquire(key);
                    ptr_vector_append(&key_roll_keys[j], key);
                }
            }
        }

        dnskey_release(key);
    }

    /*
     * For all key suites ...
     *
     * sort-out the remaining keys
     * trigger the generation of keys
     *
     * keys of the array are matching the policy
     */
    for(int ksi = 0; ksi <= ptr_vector_last_index(&policy->key_suite); ++ksi)
    {
        struct dnssec_policy_key_suite *kr = (struct dnssec_policy_key_suite*)ptr_vector_get(&policy->key_suite, ksi);

        if(zone_policy_key_suite_is_marked_processed(zone_desc, kr))
        {
            log_debug("dnssec-policy: %{dnsname}: %s: key suite is already being processed", zone_origin(zone_desc), kr->name);
            continue;
        }

        log_debug("dnssec-policy: %{dnsname}: %s: key suite has %i matching keys", zone_origin(zone_desc), kr->name, ptr_vector_size(&key_roll_keys[ksi]));

        if(ptr_vector_size(&key_roll_keys[ksi]) > 0)
        {
            // sort array by time

            if(ptr_vector_size(&key_roll_keys[ksi]) > 1) // avoids the call but ptr_vector_qsort already checks this
            {
                ptr_vector_qsort(&key_roll_keys[ksi], zone_policy_dnssec_key_ptr_vector_qsort_by_activation_time_callback);
            }

            // ensure we have continuity
            // start with a base period

            dnssec_key *previous_key = NULL;
            s64 previous_begin_period;
            s64 previous_next_period;
            s64 previous_end_period;

            {
                previous_key = (dnssec_key*)ptr_vector_get(&key_roll_keys[ksi], 0);

#if DEBUG
                log_debug("dnssec-policy: %s: %s: key %05d/%d timings: %T %T %T %T %T [0]",
                          previous_key->origin,
                          kr->name,
                          dnskey_get_tag_const(previous_key), ntohs(previous_key->flags),
                          previous_key->epoch_created, previous_key->epoch_publish, previous_key->epoch_activate, previous_key->epoch_inactive, previous_key->epoch_delete);
#endif

                database_service_zone_dnskey_set_alarms_for_key(zone, previous_key);

                previous_begin_period = previous_key->epoch_activate;
                previous_next_period = previous_begin_period;
                previous_end_period = previous_key->epoch_inactive;
            }

            log_debug("dnssec-policy: %{dnsname}: %s: first key will be inactive at %T", zone_origin(zone_desc), kr->name, previous_end_period);

            for(int i = 1; i <= ptr_vector_last_index(&key_roll_keys[ksi]); ++i)
            {
                dnssec_key *key = (dnssec_key*)ptr_vector_get(&key_roll_keys[ksi], i);
#if DEBUG
                log_debug("dnssec-policy: %s: %s: key %05d/%d timings: %T %T %T %T %T [%i]",
                          key->origin,
                          kr->name,
                          dnskey_get_tag_const(key), ntohs(key->flags),
                          key->epoch_created, key->epoch_publish, key->epoch_activate, key->epoch_inactive, key->epoch_delete, i);
#endif
                previous_next_period = key->epoch_activate;

                // ensure the key chains with this interval
                if(key->epoch_activate > previous_end_period /*|| key->epoch_inactive < begin_period irrelevant because of the sort */)
                {
                    // bad
                    log_warn("dnssec-policy: timeline hole of %d seconds from %d to %d", key->epoch_activate - previous_end_period , previous_end_period, key->epoch_activate);
                    zone_policy_log_debug_key("dnssec-policy: unchained ", key);

                    /*
                     * This case happens if there is at least one key K with timings in the future but the last key L of the valid chain is made inactive
                     * before K is being made active.
                     *
                     * _ Create key(s) for the gap ?
                     * _ Only create one key to fill that gap <- probably the best solution
                     */
                    break;
                }
                else // the key chains fine
                {
                    // if the previous key ends before this one we keep it

                    if(previous_end_period < key->epoch_inactive)
                    {
                        database_service_zone_dnskey_set_alarms_for_key(zone, key);

                        previous_key = key;
                        previous_end_period = key->epoch_inactive;
                    }
                    else
                    {
                        // else the key is irrelevant for the chain
                    }
                }
            }

            log_debug("dnssec-policy: %{dnsname}: %s: covered from %T to %T, last key activates at %T", zone_origin(zone_desc), kr->name, previous_begin_period, previous_end_period, previous_next_period);

            time_t now = time(NULL);

            if(previous_key->epoch_created <= now)
            {
                if(kr->roll->time_table.created.type.type == ZONE_POLICY_RELATIVE)
                {
                    if(FAIL(ret = dnssec_policy_queue_add_generate_key_create_at(zone_desc, kr, previous_key->epoch_created)))
                    {
                        log_err("dnssec-policy: %{dnsname}: %s: failed to setup key generation from previous key: %r", zone_origin(zone_desc), kr->name, ret);
                        final_ret = ret;
                    }
                }
                else if(kr->roll->time_table.created.type.type == ZONE_POLICY_RULE)
                {
                    if(FAIL(ret = dnssec_policy_queue_add_generate_key_active_at(zone_desc, kr, previous_end_period, NULL)))
                    {
                        log_err("dnssec-policy: %{dnsname}: %s: failed to setup key generation from previous end period: %r", zone_origin(zone_desc), kr->name, ret);
                        final_ret = ret;
                    }
                }
                else
                {
                    log_err("dnssec-policy: %{dnsname}: %s: is not supported by this version of the policies", zone_origin(zone_desc), kr->name);
                }
            }
            ptr_vector_callback_and_destroy(&key_roll_keys[ksi], zone_policy_process_release_keys_cb);
        }
        else
        {
            // no key at all ? do a full init (with (re)signature)

            log_info("dnssec-policy: %{dnsname}: %s: will be completely initialised", zone_origin(zone_desc), kr->name);

            // for relative rules: do it now
            // for cron rules: generate it back-dated

            if(kr->roll->time_table.created.type.type == ZONE_POLICY_RELATIVE)
            {
                // now

                time_t now = time(NULL);

                // add the command, aim to be active "now"

                s64 delta = kr->roll->time_table.created.relative.seconds + // from the previous created key ...
                            kr->roll->time_table.publish.relative.seconds +
                            kr->roll->time_table.activate.relative.seconds ;

                if(delta > (s64)now)
                {
                    delta = (s64)now;   //
                }

                time_t first_key_create = now - (s32)delta;

                if(ISOK(ret = dnssec_policy_queue_add_generate_key_create_at(zone_desc, kr, first_key_create))) // works on any kind of dates
                {
                    log_debug("dnssec-policy: %{dnsname}: %s: will generate a first key at %T minus %i = %T", zone_origin(zone_desc), kr->name, now, (s32)delta, first_key_create);

                    // scan-build false-positive : kr isn't freed here (scan-build missed the acquire before the release)

                }
                else
                {
                    log_err("dnssec-policy: %{dnsname}: %s: failed to setup key generation before now: %r", zone_origin(zone_desc), kr->name, ret);
                    final_ret = ret;
                }
            }
            else if(kr->roll->time_table.created.type.type == ZONE_POLICY_RULE)
            {
                // compute the back-dated epoch

                time_t now = time(NULL);
                time_t will_be_inactive_at = 0;
                if(ISOK(ret = dnssec_policy_queue_add_generate_key_active_at(zone_desc, kr, now, &will_be_inactive_at))) // @note : only works on rules
                {
                    log_debug("dnssec-policy: %{dnsname}: %s: will generate a first key that'll be inactive at %T", zone_origin(zone_desc), kr->name, will_be_inactive_at);

                    // scan-build false-positive : kr isn't freed here (scan-build missed the acquire before the release)

                }
                else
                {
                    log_err("dnssec-policy: %{dnsname}: %s: failed to setup key generation from now: %r", zone_origin(zone_desc), kr->name, ret);
                    final_ret = ret;
                }
            }
            else
            {
                log_err("dnssec-policy: %{dnsname}: %s: don't know how to proceed", zone_origin(zone_desc), kr->name);
            }
        }
    } // for all key suites

    zdb_zone_release(zone);

    log_debug("dnssec-policy: %{dnsname} released", zone_origin(zone_desc));

    for(int i = 0; i < DNSSEC_POLICY_KEY_ROLL_COUNT_MAXIMUM; ++i)
    {
        ptr_vector_callback_and_destroy(&key_roll_keys[i], zone_policy_process_release_keys_cb);
    }

    // decide what to do

    return final_ret;   // returns success or the last error from the key generation part
}

void
dnssec_policy_initialise()
{
    dnssec_policy_command_service_start();
}

void
dnssec_policy_finalize()
{
    ptr_set_iterator iter;

    //

    group_mutex_write_lock(&dnssec_policy_set_mtx);
    ptr_set_iterator_init(&dnssec_policy_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        dnssec_policy *dp = (dnssec_policy*)node->value;
        group_mutex_write_lock(&dnssec_policy_mtx);
        int rc = dp->rc;
        group_mutex_write_unlock(&dnssec_policy_mtx);
        if(rc == 1)
        {
            // destroy it
            log_debug("dnssec-policy: %s: policy released", dp->name);
            dnssec_policy_release(dp);
        }
        else
        {
            log_warn("dnssec-policy: %s: policy is still referenced %i times", dp->name, rc);
        }
    }

    ptr_set_destroy(&dnssec_policy_set);

    group_mutex_write_unlock(&dnssec_policy_set_mtx);

    //

    group_mutex_write_lock(&dnssec_policy_key_suite_set_mtx);
    ptr_set_iterator_init(&dnssec_policy_key_suite_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        dnssec_policy_key_suite *dpks = (dnssec_policy_key_suite*)node->value;
        group_mutex_write_lock(&dnssec_policy_key_suite_mtx);
        int rc = dpks->rc;
        group_mutex_write_unlock(&dnssec_policy_key_suite_mtx);
        if(rc == 1)
        {
            // destroy it
            log_debug("dnssec-policy: %s: key suite released", dpks->name);
            dnssec_policy_key_suite_release(dpks);
        }
        else
        {
            log_warn("dnssec-policy: %s: key suite is still referenced %i times", dpks->name, rc);
        }
    }

    ptr_set_destroy(&dnssec_policy_key_suite_set);

    group_mutex_write_unlock(&dnssec_policy_key_suite_set_mtx);

    //

    group_mutex_write_lock(&dnssec_policy_key_set_mtx);
    ptr_set_iterator_init(&dnssec_policy_key_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        dnssec_policy_key *dpk = (dnssec_policy_key*)node->value;
        group_mutex_write_lock(&dnssec_policy_key_mtx);
        int rc = dpk->rc;
        group_mutex_write_unlock(&dnssec_policy_key_mtx);
        if(rc == 1)
        {
            // destroy it
            log_debug("dnssec-policy: %s: key released", dpk->name);
            dnssec_policy_key_release(dpk);
        }
        else
        {
            log_warn("dnssec-policy: %s: key is still referenced %i times", dpk->name, rc);
        }
    }

    ptr_set_destroy(&dnssec_policy_key_set);

    group_mutex_write_unlock(&dnssec_policy_key_set_mtx);

    //

    group_mutex_write_lock(&dnssec_policy_roll_set_mtx);
    ptr_set_iterator_init(&dnssec_policy_roll_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        dnssec_policy_roll *dpr = (dnssec_policy_roll*)node->value;
        group_mutex_write_lock(&dnssec_policy_roll_mtx);
        int rc = dpr->rc;
        group_mutex_write_unlock(&dnssec_policy_roll_mtx);
        if(rc == 1)
        {
            // destroy it
            log_debug("dnssec-policy: %s: roll released", dpr->name);
            dnssec_policy_roll_release(dpr);
        }
        else
        {
            log_warn("dnssec-policy: %s: roll is still referenced %i times", dpr->name, rc);
        }
    }

    ptr_set_destroy(&dnssec_policy_roll_set);

    group_mutex_write_unlock(&dnssec_policy_roll_set_mtx);
    //

    group_mutex_write_lock(&dnssec_denial_set_mtx);
    ptr_set_iterator_init(&dnssec_denial_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        dnssec_denial *dd = (dnssec_denial*)node->value;
        group_mutex_write_lock(&dnssec_denial_mtx);
        int rc = dd->rc;
        group_mutex_write_unlock(&dnssec_denial_mtx);
        if(rc == 1)
        {
            // destroy it
            log_debug("dnssec-policy: %s: denial released", dd->name);
            dnssec_policy_denial_release(dd);
        }
        else
        {
            log_warn("dnssec-policy: %s: denial is still referenced %i times", dd->name, rc);
        }
    }

    ptr_set_destroy(&dnssec_denial_set);

    mutex_lock(&origin_to_dnssec_policy_queue_mtx);
    ptr_set_iterator_init(&origin_to_dnssec_policy_queue_set, &iter);
    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *node = ptr_set_iterator_next_node(&iter);
        dnsname_zfree(node->key);
        dnssec_policy_queue* cmd = (dnssec_policy_queue*)node->value;
        while(cmd != NULL)
        {
            dnssec_policy_queue *tmp = cmd;
            dnsname_zfree(cmd->origin);
            cmd = cmd->next;
            ZFREE_OBJECT(tmp);
        }
    }
    ptr_set_destroy(&origin_to_dnssec_policy_queue_set);
    mutex_unlock(&origin_to_dnssec_policy_queue_mtx);

    group_mutex_write_unlock(&dnssec_denial_set_mtx);
}



/**
 * @}
 */
