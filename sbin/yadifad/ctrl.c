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
 * @defgroup server
 * @ingroup yadifad
 * @brief server
 *
 *  Handles queries made in the CH class (ie: version.*)
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "server_config.h"

#include <dnscore/file_output_stream.h>
#include <dnscore/logger.h>
#include <dnscore/rfc.h>
#include <dnscore/ctrl_rfc.h>
#include <dnscore/threaded_queue.h>

#include <dnsdb/zdb_zone.h>
#include <dnscore/format.h>
#include <dnscore/dns_packet_writer.h>

#include <dnscore/error_state.h>

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "server_config.h"
#include "confs.h"
#include <dnscore/tcp_io_stream.h>
#include "notify.h"

#if HAS_CTRL

#if HAS_EXPERIMENTAL
#include "ctrl_query_message.h"
#include "ctrl_query_axfr.h"
#endif

#include "ctrl_query.h"
#include "ctrl.h"

#include "database_service.h"

extern logger_handle_t *g_server_logger;

/* Zone file variables */
extern zone_data_set    database_zone_desc;

static config_control_t g_ctrl_config = {
#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING
    NULL,
    NULL,
    NULL,
    NULL,
#endif
    NULL,
    true};

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING
static error_state_t    ctrl_tcp_reply_error_state = ERROR_STATE_INITIALIZER;

static inline ya_result ctrl_tcp_reply(dns_message_t *mesg, int sockfd)
{
    ssize_t ret;

    if(ISOK(ret = dns_message_update_length_send_tcp_with_default_minimum_throughput(mesg, sockfd)))
    {
        error_state_clear_locked(&ctrl_tcp_reply_error_state, NULL, 0, NULL);
    }
    else
    {
        if(error_state_log_locked(&ctrl_tcp_reply_error_state, ret))
        {
            log_err("ctrl: tcp: could not answer: %r", (ya_result)ret);
        }
    }

    return (ya_result)ret;
}

static inline ya_result ctrl_tcp_reply_error(dns_message_t *mesg, int sockfd, uint16_t error_code)
{
    ssize_t ret;
    if(ISOK(ret = dns_message_make_error_and_reply_tcp_with_default_minimum_throughput(mesg, error_code, sockfd)))
    {
        error_state_clear_locked(&ctrl_tcp_reply_error_state, NULL, 0, NULL);
    }
    else
    {
        if(error_state_log_locked(&ctrl_tcp_reply_error_state, ret))
        {
            log_err("ctrl: tcp: could not answer: %r", (ya_result)ret);
        }
    }

    return (ya_result)ret;
}
#endif

void ctrl_set_listen(host_address_t *hosts)
{
    if(g_ctrl_config.listen != NULL)
    {
        host_address_delete_list(g_ctrl_config.listen);
    }

    g_ctrl_config.listen = hosts;
}

host_address_t *ctrl_get_listen() { return g_ctrl_config.listen; }

void            ctrl_set_enabled(bool b) { g_ctrl_config.enabled = b; }

bool            ctrl_get_enabled() { return g_ctrl_config.enabled; }

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING

static config_control g_ctrl_config = {NULL, NULL, NULL, NULL, NULL, true};

/**
 *
 * Simple checksum function
 *
 * @param buffer
 * @param size
 *
 * @return 32 bits checksum
 */

static uint32_t ctrl_checksum(const uint8_t *buffer, uint32_t size)
{
    uint32_t             base_value = 3765432173;
    uint32_t             sum = 0;

    const uint8_t *const limit = &buffer[size];

    while(buffer < limit)
    {
        sum += base_value * *buffer;
        base_value = (base_value << 1) | (base_value >> 31);
        buffer++;
    }

    return sum;
}

host_address *ctrl_get_primaries() { return g_ctrl_config.primaries; }

void          ctrl_set_primaries(host_address *hosts)
{
    if(g_ctrl_config.primaries != NULL)
    {
        host_address_delete_list(g_ctrl_config.primaries);
    }

    g_ctrl_config.primaries = hosts;
}

bool           ctrl_is_host_primary(const host_address *host) { return host_address_list_contains_host(ctrl_get_primaries(), host); }

bool           ctrl_is_ip_tsig_primary(const socketaddress *sa, const tsig_key_t *tsig) { return host_address_list_contains_ip_tsig(ctrl_get_primaries(), sa, tsig); }

const uint8_t *ctrl_get_dynamic_mname() { return g_ctrl_config.dynamic_mname; }

void           ctrl_set_dynamic_mname(const uint8_t *fqdn)
{
    if(g_ctrl_config.dynamic_mname != NULL)
    {
        free(g_ctrl_config.dynamic_mname);
    }
    if(fqdn != NULL)
    {
        g_ctrl_config.dynamic_mname = dnsname_dup(fqdn);
    }
}

const uint8_t *ctrl_get_dynamic_rname() { return g_ctrl_config.dynamic_rname; }

void           ctrl_set_dynamic_rname(const uint8_t *fqdn)
{
    if(g_ctrl_config.dynamic_rname != NULL)
    {
        free(g_ctrl_config.dynamic_rname);
    }
    if(fqdn != NULL)
    {
        g_ctrl_config.dynamic_rname = dnsname_dup(fqdn);
    }
}

host_address *ctrl_get_dynamic_mname_ip_addresses() { return g_ctrl_config.dynamic_mname_ip_addresses; }

void          ctrl_set_dynamic_mname_ip_addresses(host_address *hosts)
{
    if(g_ctrl_config.dynamic_mname_ip_addresses != NULL)
    {
        host_address_delete_list(g_ctrl_config.dynamic_mname_ip_addresses);
    }

    g_ctrl_config.dynamic_mname_ip_addresses = hosts;
}

const config_control *ctrl_get_config() { return &g_ctrl_config; }

ya_result             ctrl_store_dynamic_config()
{
    ya_result return_value;
    char      config_file_edits_bak[PATH_MAX];

    snformat(config_file_edits_bak, sizeof(config_file_edits_bak), "%s.bak", g_config->config_file_dynamic);

    unlink(config_file_edits_bak);
    rename(g_config->config_file_dynamic, config_file_edits_bak);

    output_stream_t cfeos;

    if(FAIL(return_value = file_output_stream_create(&cfeos, g_config->config_file_dynamic, 0600)))
    {
        return return_value;
    }

    zone_set_lock(&database_zone_desc);

    osprintln(&cfeos, "# THIS FILE IS DYNAMICALLY GENERATED BY YADIFAD AND CONTAINS SPECIFIC FIELDS : DO NOT EDIT");
    osprintln(&cfeos, "");

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *zone_node = ptr_treemap_iterator_next_node(&iter);
        zone_desc_s        *zone_desc = (zone_desc_s *)zone_node->data;

        if((zone_desc->dynamic_provisioning.flags & ZONE_CTRL_FLAG_EDITED) != 0)
        {
            osprintln(&cfeos, "<zone>");

#ifdef WORDS_BIGENDIAN
            zone_desc->dynamic_provisioning.version = 0x81;
#else
            zone_desc->dynamic_provisioning.version = 0x01;
#endif
            zone_desc->dynamic_provisioning.padding = 0;
            zone_desc->dynamic_provisioning.checksum = ctrl_checksum((uint8_t *)&zone_desc->dynamic_provisioning, offsetof(dynamic_provisioning_s, checksum));

            config_zone_print(zone_desc, &cfeos);

            osprintln(&cfeos, "</zone>\n");
        }
    }

    output_stream_close(&cfeos);

    zone_set_unlock(&database_zone_desc);

    return return_value;
}

void ctrl_notify_all_secondaries()
{
    zone_set_lock(&database_zone_desc);

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *zone_node = ptr_treemap_iterator_next_node(&iter);
        zone_desc_s        *zone_desc = (zone_desc_s *)zone_node->data;

        if((zone_desc->dynamic_provisioning.flags & ZONE_CTRL_FLAG_EDITED) != 0)
        {
            /* primary of zone */

            if(zone_desc->type == ZT_PRIMARY)
            {
                /* has secondaries */
                if(!host_address_empty(zone_desc->secondaries))
                {
                    /* copy the list */
                    host_address *secondaries = host_address_copy_list(zone_desc->secondaries);
                    /* notify secondaries from the list */
                    notify_host_list(zone_desc, secondaries, CLASS_CTRL);
                }
            }
        }
    }

    zone_set_unlock(&database_zone_desc);
}

void ctrl_notify_all_primaries()
{
    host_address *primaries = ctrl_get_primaries();

    if(!host_address_empty(primaries))
    {
        primaries = host_address_copy_list(primaries);
        notify_primaries_list(primaries);
    }
}

void ctrl_notify_secondary(host_address *secondary)
{
    if(!host_address_empty(secondary))
    {
        zone_set_lock(&database_zone_desc);

        ptr_treemap_iterator_t iter;
        ptr_treemap_iterator_init(&database_zone_desc.set, &iter);

        while(ptr_treemap_iterator_hasnext(&iter))
        {
            ptr_treemap_node_t *zone_node = ptr_treemap_iterator_next_node(&iter);
            zone_desc_s        *zone_desc = (zone_desc_s *)zone_node->data;

            if((zone_desc->dynamic_provisioning.flags & ZONE_CTRL_FLAG_EDITED) != 0)
            {
                /* primary of zone */

                if(zone_desc->type == ZT_PRIMARY)
                {
                    /* has secondaries */
                    if(!host_address_empty(zone_desc->secondaries))
                    {
                        if(host_address_list_contains_host(zone_desc->secondaries, secondary))
                        {
                            /* look if the secondary is in the list*/
                            host_address *secondary_list = host_address_copy_list(secondary);
                            /* notify secondaries from the list */
                            notify_host_list(zone_desc, secondary_list, CLASS_CTRL);
                        }
                    }
                }
            }
        }

        zone_set_unlock(&database_zone_desc);
    }
}

#endif // HAS_CTRL_DYNAMIC_PROVISIONING

ya_result ctrl_message_process(dns_message_t *mesg)
{
    ya_result ret;

    bool      received_query = dns_message_is_query(mesg);

    if(ISOK(ret = dns_message_process(mesg)))
    {
        switch(dns_message_get_query_class(mesg))
        {
            case CLASS_CTRL:
            {
                ctrl_query_process(mesg);
                break;
            } // ctrl class CTRL
#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING
#pragma message("TODO: WTF is this? (Besides wrong)")
#if 0
            case OPCODE_UPDATE:
            {
                if((g_config->server_flags & SERVER_FL_DYNAMIC_PROVISIONING) != 0)
                {
                    ctrl_update_process(mesg);

                    if(message_has_tsig(mesg))  /* NOTE: the TSIG information is in mseg */
                    {
                        tsig_sign_query(mesg);
                    }
                }
                else
                {
                    log_warn("update [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : dynamic provisioning disabled",
                            ntohs(message_get_id(mesg)),
                            message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg),
                            message_get_sender_sa(mesg));

                    ctrl_tcp_reply_error(mesg, sockfd, FP_FEATURE_DISABLED);
                }

                break;
            }
            case OPCODE_NOTIFY:
            {
                if((g_config->server_flags & SERVER_FL_DYNAMIC_PROVISIONING) != 0)
                {
                    ctrl_notify_process(mesg);
                }
                else
                {
                    log_warn("notify [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : dynamic provisioning disabled",
                            ntohs(message_get_id(mesg)),
                            message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_query_class_ptr(mesg),
                            message_get_sender_sa(mesg));

                    ctrl_tcp_reply_error(mesg, sockfd, FP_FEATURE_DISABLED);
                }
                break;
            }
#endif
#endif // HAS_CTRL_DYNAMIC_PROVISIONING

            default:
            {
                log_warn("ctrl [%04hx] %{dnsname} %{dnstype} %{dnsclass} (%{sockaddrip}) : unsupported class",
                         ntohs(dns_message_get_id(mesg)),
                         dns_message_get_canonised_fqdn(mesg),
                         dns_message_get_query_type_ptr(mesg),
                         dns_message_get_query_class_ptr(mesg),
                         dns_message_get_sender_sa(mesg));

                dns_message_set_status(mesg, FP_CLASS_NOTFOUND);
                dns_message_transform_to_signed_error(mesg);

                break;
            }
        } // switch(class)
    }
    else // an error occurred : no query to be done at all
    {
        log_warn("ctrl [%04hx] from %{sockaddr} error %i : %r", ntohs(dns_message_get_id(mesg)), dns_message_get_sender_sa(mesg), dns_message_get_status(mesg), ret);

        if((ret == INVALID_MESSAGE) && (g_config->server_flags & SERVER_FL_LOG_UNPROCESSABLE))
        {
            log_memdump_ex(MODULE_MSG_HANDLE, MSG_WARNING, dns_message_get_buffer(mesg), dns_message_get_size(mesg), 16, OSPRINT_DUMP_BUFFER);
        }

        if((ret != INVALID_MESSAGE) && (((g_config->server_flags & SERVER_FL_ANSWER_FORMERR) != 0) || dns_message_get_status(mesg) != RCODE_FORMERR) && received_query)
        {
            if(!dns_message_has_tsig(mesg) && (dns_message_get_status(mesg) != FP_RCODE_NOTAUTH))
            {
                dns_message_transform_to_error(mesg);
            }

            ret = SUCCESS;
        }
        else
        {
            ret = SUCCESS_DROPPED;
        }
    }

    return ret;
}

#endif // HAS_CTRL

/** @} */
