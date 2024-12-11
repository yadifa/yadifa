/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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
#include <dnscore/dns_packet_reader.h>
#include <dnscore/dns_packet_writer.h>

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "confs.h"
#include "signals.h"
#include <dnscore/acl.h>

#if HAS_EXPERIMENTAL
#include "ctrl_query_message.h"
#include "ctrl_query_axfr.h"
#endif

#if HAS_CTRL

#include "ctrl_zone.h"

#include "log_query.h"

#include "database_service.h"

#include "notify.h"

extern zone_data_set database_zone_desc;

// CH fqdn TXT command
// freeze zone
// unfreeze zone
// reload zone
// load zone
// drop zone

/**
 * The q&d model used types for control.
 *
 * Do we want a script model ? A loop could make sense but I don't see a real practical use yet.
 *
 * for $z in (a,b,c,d){load $z}
 * if(whatever) {notify hostname}
 *
 * Do we want optional encryption ? (This may be interesting).
 *
 * ie: one may want to send a command with a TSIG through an unsafe network.
 *
 * If we use TXT we can simply have:
 *
 * script. TXT load this;foreach(a,b,c,d){drop $};if(whateverstatus){reload whatever}
 * key. TXT mycbckeyname
 *
 *
 */

#if 0
/**
 * 
 * Simple checksum function
 * 
 * @param buffer
 * @param size
 * 
 * @return 32 bits checksum
 */

static uint32_t
ctrl_checksum(const uint8_t *buffer, uint32_t size)
{
    uint32_t base_value = 3765432173;
    uint32_t sum = 0;
    
    const uint8_t * const limit = &buffer[size];
    
    while(buffer < limit)
    {
        sum += base_value * *buffer;
        base_value = (base_value << 1) | (base_value >> 31);
        buffer++;
    }
    
    return sum;
}

/**/

#endif

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING

extern zone_data_set database_dynamic_zone_desc;

/**
 * Merge ONE zone temporary configuration into the active configuration
 *
 * @param mesg
 */

static void ctrl_query_config_merge(dns_message_t *mesg)
{
    /*
     * Schedule the unfreeze of the zone on the disk (and the restart of the maintenance)
     */

    uint16_t     tmp_status = RCODE_NXDOMAIN;

    zone_desc_s *zone_desc = zone_acquiredynamicbydnsname(message_get_canonised_fqdn(mesg));

    if(zone_desc != NULL)
    {
        tmp_status = RCODE_NOTAUTH;

        if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
        {
            tmp_status = RCODE_NXDOMAIN;

            if(ISOK(ctrl_zone_config_merge(zone_desc, true))) // source from dynamic
            {
                zone_release(zone_desc);

                tmp_status = RCODE_NOERROR;

                message_set_status(mesg, (finger_print)tmp_status);

                return;
            }
        }
        else
        {
            log_notice("ctrl: zone merge: rejected by ACL '%{dnsname}'", message_get_canonised_fqdn(mesg));
        }

        zone_release(zone_desc);
    }
    else
    {
        log_warn("ctrl: zone merge: zone '%{dnsname}' %{dnsclass} not found", message_get_canonised_fqdn(mesg), &rclass);
    }

    message_make_error(mesg, tmp_status);
}

/**
 *
 * Merge ALL zones (that are controllable by the current sender)
 * temporary configuration into the active configuration
 *
 * The proper way to handle all zones from an external command is to try them one by one
 * (because of the ACL)
 *
 * @param mesg
 */

static void ctrl_query_config_merge_all(dns_message_t *mesg)
{
    uint32_t success = 0;
    uint32_t error = 0;

    zone_set_lock(&database_dynamic_zone_desc);

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&database_dynamic_zone_desc.set, &iter);

    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *zone_node = ptr_treemap_iterator_next_node(&iter);
        zone_desc_s        *zone_desc = (zone_desc_s *)zone_node->data;

        if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
        {
            ya_result return_value;

            if(ISOK(return_value = ctrl_zone_config_merge(zone_desc, false))) // source from dynamic
            {
                success++;
            }
            else
            {
                error++;
            }
        }
        else
        {
            // no need to handle this, it just means that the controller has no rights on this
        }
    }

    if(success > 0)
    {
        // part was ok
        message_set_status(mesg, RCODE_NOERROR);
    }
    else if(error > 0)
    {
        // part was wrong
        message_make_error(mesg, RCODE_SERVFAIL);
    }
    else
    {
        // no zone accepts this controller
        message_make_error(mesg, RCODE_REFUSED);
    }

    zone_set_unlock(&database_dynamic_zone_desc);
}

#endif

/*****************************************************************************/
#if 0
static void
ctrl_query_zone_status(dns_message_t *mesg)
{
    /*
     * Schedule the unfreeze of the zone on the disk (and the restart of the maintenance)
     */

    zdb_zone* zone;
    dnsname_vector fqdn_vector;
    dnsname_to_dnsname_vector(message_get_canonised_fqdn(mesg), &fqdn_vector);

    uint16_t tmp_status = RCODE_NXDOMAIN;

    zone_desc_s *zone_desc = zone_getbydnsname(message_get_canonised_fqdn(mesg));

    if(zone_desc_s != NULL)
    {
        if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
        {
            dns_packet_writer pw;
            dns_packet_writer_init_append_to_message(&pw, &mesg);

            ctrl_query_message_add_text_txt(&pw, "ctx.domain", zone_domain(zone_desc));
            ctrl_query_message_add_u32_txt(&pw, "ctx.type", zone_desc->type);
            ctrl_query_message_add_text_txt(&pw, "ctx.file.name", zone_desc->file_name);
            ctrl_query_message_add_u32_txt(&pw, "ctx.loading", zone_isloading(zone_desc_s));
            ctrl_query_message_add_time_txt(&pw, "ctx.refresh.time", zone_desc->refresh.refreshed_time);
            ctrl_query_message_add_time_txt(&pw, "ctx.retried.time", zone_desc->refresh.retried_time);
            
            message_set_answer_count(mesg, 6);
            
            ctrl_query_message_add_ams_txt(&pw, "control", &zone_desc->ac.allow_control);
            ctrl_query_message_add_ams_txt(&pw, "notify", &zone_desc->ac.allow_notify);
            ctrl_query_message_add_ams_txt(&pw, "query", &zone_desc->ac.allow_query);
            ctrl_query_message_add_ams_txt(&pw, "transfer", &zone_desc->ac.allow_transfer);
            ctrl_query_message_add_ams_txt(&pw, "update", &zone_desc->ac.allow_update);
            ctrl_query_message_add_ams_txt(&pw, "update-forwarding", &zone_desc->ac.allow_update_forwarding);

            message_set_authority_count(mesg, 18);
            
            if((zone = zdb_zone_find(g_config->database, &fqdn_vector, CLASS_IN)) != NULL) // OBSOLETE
            {
                uint32_t soa_ttl;
                uint16_t soa_rdata_size;
                const uint8_t *soa_rdata;

                if(ISOK(zdb_zone_getsoa_ttl_rdata(zone, &soa_ttl, &soa_rdata_size, &soa_rdata)))
                {
                    dns_packet_writer_add_fqdn(&pw, message_get_canonised_fqdn(mesg));
                    dns_packet_writer_add_u16(&pw, TYPE_SOA);
                    dns_packet_writer_add_u16(&pw, CLASS_IN);
                    dns_packet_writer_add_u32(&pw, htonl(soa_ttl));
                    dns_packet_writer_add_rdata(&pw, TYPE_SOA, soa_rdata, soa_rdata_size);
                }

                ctrl_query_message_add_u32_txt(&pw, "sig.validity.interval.s", zone->sig_validity_interval_seconds);
                ctrl_query_message_add_u32_txt(&pw, "sig.validity.jitter.s", zone->sig_validity_jitter_seconds);
                ctrl_query_message_add_u32_txt(&pw, "sig.validity.regeneration.s", zone->sig_validity_regeneration_seconds);
                ctrl_query_message_add_time_txt(&pw, "sig.invalid.first.time", zone->sig_invalid_first);

                ctrl_query_message_add_u32_txt(&pw, "mutex.owner", zone->mutex_owner);
                ctrl_query_message_add_u32_txt(&pw, "mutex.count", zone->mutex_count);

                ctrl_query_message_add_u32_txt(&pw, "flag.frozen", zdb_zone_is_frozen(zone));
                ctrl_query_message_add_u32_txt(&pw, "flag.nsec", (zone->apex->flags & ZDB_RR_LABEL_NSEC) != 0);
                ctrl_query_message_add_u32_txt(&pw, "flag.nsec3", (zone->apex->flags & ZDB_RR_LABEL_NSEC3) != 0);
                ctrl_query_message_add_u32_txt(&pw, "flag.dnssec.edit", (zone->apex->flags & ZDB_RR_LABEL_DNSSEC_EDIT) != 0);

                message_add_authority_count(mesg, 11);

                alarm_lock();

                alarm_event_node *node = alarm_get_first(zone->alarm_handle);

                if(node != NULL)
                {
                    uint16_t count = 0;

                    while(node->hndl_next != NULL)
                    {
                        uint32_t mark = pw.packet_offset;

                        if(FAIL(ctrl_query_message_add_time_txt(&pw, "alarm.time", node->epoch)))
                        {
                            break;
                        }

                        if(FAIL(ctrl_query_message_add_text_txt(&pw, "alarm.text", node->text)))
                        {
                            pw.packet_offset = mark;

                            break;
                        }

                        count += 2;

                        node = node->hndl_next;
                    }

                    message_set_additional_count(mesg, count);
                }

                alarm_unlock();
            }

            message_set_size(mesg, pw.packet_offset);

            return;
        }
        else
        {
            log_notice("ctrl: zone status: rejected by ACL");
            
            tmp_status = RCODE_REFUSED;
        }
    }

    message_make_error(mesg, tmp_status);
}
#endif

static ya_result ctrl_query_parse_no_parameters(dns_packet_reader_t *pr)
{
    (void)pr;
    return SUCCESS;
}

static ya_result ctrl_query_parse_bytes(dns_packet_reader_t *pr, void *out, uint32_t out_size)
{
    struct type_class_ttl_rdlen_s cmd_tctr;

    ya_result                     ret;
    if(FAIL(ret = dns_packet_reader_skip_fqdn(pr)))
    {
        return ret;
    }

    if(FAIL(ret = dns_packet_reader_read(pr, &cmd_tctr, 10))) // exact
    {
        return ret;
    }

    cmd_tctr.rdlen = ntohs(cmd_tctr.rdlen);

    if(cmd_tctr.rdlen <= out_size)
    {
        cmd_tctr.rdlen -= out_size;
        ret = dns_packet_reader_read(pr, out, out_size); // exact
        return ret;
    }
    else
    {
        return BUFFER_WOULD_OVERFLOW; // not enough bytes
    }
}

/*
 *
 * rdata = "apple.com"
 * rdata = "apple.com" CH
 * rdata = "apple.com" CH "bla bla"
 *
 */

static ya_result ctrl_query_parse_fqdn_class_view(dns_packet_reader_t *pr, uint8_t *fqdn, uint32_t fqdn_size, uint16_t *rclass, char *view, uint32_t view_size)
{
    struct type_class_ttl_rdlen_s cmd_tctr;
    ya_result                     ret = 0;

    if(FAIL(ret = dns_packet_reader_skip_fqdn(pr)))
    {
        return ret;
    }

    if(FAIL(ret = dns_packet_reader_read(pr, &cmd_tctr, 10))) // exact
    {
        return ret;
    }

    cmd_tctr.rdlen = ntohs(cmd_tctr.rdlen);

    fqdn[0] = '\0';
    *rclass = CLASS_IN;
    view[0] = '\0';

    if(cmd_tctr.rdlen != 0)
    {
        uint32_t from = pr->packet_offset;
        if(ISOK(ret = dns_packet_reader_read_fqdn(pr, fqdn, fqdn_size)))
        {
            cmd_tctr.rdlen -= pr->packet_offset - from;

            ya_result parameters = 1;

            if(cmd_tctr.rdlen > 2)
            {
                if(ISOK(ret = dns_packet_reader_read(pr, rclass, 2))) // exact
                {
                    ++parameters;

                    cmd_tctr.rdlen -= 2;

                    if(cmd_tctr.rdlen > 0)
                    {
                        uint32_t n = MIN(cmd_tctr.rdlen, view_size - 1);
                        if(ISOK(ret = dns_packet_reader_read(pr, view, n))) // exact
                        {
                            ++parameters;
                            view[n] = '\0';

                            cmd_tctr.rdlen -= ret;
                        }
                    }
                }
            }

            if(ISOK(ret))
            {
                if(cmd_tctr.rdlen == 0)
                {
                    ret = parameters;
                }
                else
                {
                    ret = MAKE_RCODE_ERROR(RCODE_FORMERR); // must end on an exact match
                }
            }
        }
    }

    return ret;
}

static ya_result ctrl_query_parse_byte_fqdn_class_view(dns_packet_reader_t *pr, uint8_t *one_byte, uint8_t *fqdn, uint32_t fqdn_size, uint16_t *rclass, char *view, uint32_t view_size)
{
    struct type_class_ttl_rdlen_s cmd_tctr;
    ya_result                     ret = 0;

    if(FAIL(ret = dns_packet_reader_skip_fqdn(pr)))
    {
        return ret;
    }

    if(FAIL(ret = dns_packet_reader_read(pr, &cmd_tctr, 10))) // exact
    {
        return ret;
    }

    cmd_tctr.rdlen = ntohs(cmd_tctr.rdlen);

    fqdn[0] = '\0';
    *rclass = CLASS_IN;
    view[0] = '\0';

    if(cmd_tctr.rdlen != 0)
    {
        uint32_t from = pr->packet_offset;

        // read the byte

        if(ISOK(ret = dns_packet_reader_read(pr, one_byte, 1)))
        {
            // read the fqdn

            if(ISOK(ret = dns_packet_reader_read_fqdn(pr, fqdn, fqdn_size)))
            {
                // adjust the remaining bytes to process

                cmd_tctr.rdlen -= pr->packet_offset - from;

                // if there is enough for a class ...

                if(cmd_tctr.rdlen > 2)
                {
                    // read the class

                    if(ISOK(ret = dns_packet_reader_read(pr, rclass, 2)))
                    {
                        cmd_tctr.rdlen -= 2;

                        // if there is something left it's the view parameter

                        if(cmd_tctr.rdlen > 0)
                        {
                            uint32_t n = MIN(cmd_tctr.rdlen, view_size - 1);
                            if(ISOK(ret = dns_packet_reader_read(pr, view, n)))
                            {
                                view[n] = '\0';
                            }
                        }
                    }
                }
                else // the value can only be 0 else it's a format error
                {
                    if(cmd_tctr.rdlen != 0)
                    {
                        return MAKE_RCODE_ERROR(RCODE_FORMERR); // the one forbidden value is 1 byte available
                    }
                }
            }
        }

        return pr->packet_offset - from;
    }
    else
    {
        if(cmd_tctr.rdlen == 0)
        {
            return 0; // nothing read
        }
        else
        {
            return ERROR; // not enough bytes
        }
    }
}

static void ctrl_query_server_shutdown_call()
{
    program_mode = SA_SHUTDOWN;
    server_service_stop_nowait();
    dnscore_shutdown();
}

static void ctrl_query_server_shutdown(dns_message_t *mesg)
{
    dns_packet_reader_t pr;
    ya_result           return_code;
    uint16_t            cmd_type;
    uint16_t            cmd_class;

    dns_packet_reader_init_from_message(&pr, mesg);

    if(FAIL(dns_packet_reader_skip_fqdn(&pr))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    if(FAIL(dns_packet_reader_read_u16(&pr, &cmd_type))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    return_code = dns_packet_reader_read_u16(&pr, &cmd_class);

    uint16_t qc = dns_message_get_query_count(mesg);
    uint16_t pc = dns_message_get_answer_count(mesg);
    uint16_t an = dns_message_get_authority_count(mesg);

    if(ISOK(return_code) && (qc == 1) && (pc == 0) && (an == 0) && (cmd_type == TYPE_CTRL_SRVSHUTDOWN) && (cmd_class == CLASS_CTRL))
    {
        if(ISOK(return_code = ctrl_query_parse_no_parameters(&pr)))
        {
            log_info("ctrl: shutdown");

            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_control)))
            {
                if(!dnscore_shuttingdown())
                {
                    log_debug("ctrl: shutdown: in progress");

                    ctrl_query_server_shutdown_call();
                }
                else
                {
                    log_info("ctrl: shutdown: already shutting down");
                }
            }
            else
            {
                log_notice("ctrl: shutdown: rejected by ACL");
                dns_message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            log_notice("ctrl: shutdown: format error");
            dns_message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        log_notice("ctrl: shutdown: format error");
        dns_message_make_error(mesg, RCODE_FORMERR);
    }
}

static void ctrl_query_logger_reopen(dns_message_t *mesg)
{
    dns_packet_reader_t pr;
    uint16_t            cmd_type;
    uint16_t            cmd_class;

    dns_packet_reader_init_from_message(&pr, mesg);

    if(FAIL(dns_packet_reader_skip_fqdn(&pr))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    if(FAIL(dns_packet_reader_read_u16(&pr, &cmd_type))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    ya_result return_code = dns_packet_reader_read_u16(&pr, &cmd_class);

    uint16_t  qc = dns_message_get_query_count(mesg);
    uint16_t  pc = dns_message_get_answer_count(mesg);
    uint16_t  an = dns_message_get_authority_count(mesg);

    if(ISOK(return_code) && (qc == 1) && (pc == 0) && (an == 0) && (cmd_type == TYPE_CTRL_SRVLOGREOPEN) && (cmd_class == CLASS_CTRL))
    {
        if(ISOK(return_code = ctrl_query_parse_no_parameters(&pr)))
        {
            log_info("ctrl: logger reopen");

            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_control)))
            {
                logger_reopen();
            }
            else
            {
                log_notice("ctrl: logger reopen: rejected by ACL");
                dns_message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            log_notice("ctrl: logger reopen: format error");
            dns_message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        log_notice("ctrl: logger reopen: format error");
        dns_message_make_error(mesg, RCODE_FORMERR);
    }
}

/*
 * Funny thing ...
 * A re-configure in a controller is likely to be in a TCP server.
 * Which means the operation needs to be set on another thread or the server will be blocked forever.
 */

void *ctrl_config_reload_thread(void *args)
{
    (void)args;
    ya_result ret;
    if(ISOK(ret = yadifad_config_update(g_config->config_file)))
    {
        logger_reopen();

        if(!server_context_matches_config())
        {
            log_try_debug1("network configuration has changed");

            server_service_reconfigure();
        }
        else
        {
            log_try_debug1("network configuration has not changed");
        }
    }
    return NULL;
}

ya_result ctrl_config_reload()
{
    thread_t thread;
    thread_create(&thread, ctrl_config_reload_thread, NULL);
    thread_join(thread, NULL);
    return SUCCESS;
}

static void ctrl_query_config_reload(dns_message_t *mesg)
{
    dns_packet_reader_t pr;
    uint16_t            cmd_type;
    uint16_t            cmd_class;

    dns_packet_reader_init_from_message(&pr, mesg);

    if(FAIL(dns_packet_reader_skip_fqdn(&pr))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    if(FAIL(dns_packet_reader_read_u16(&pr, &cmd_type))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    ya_result return_code = dns_packet_reader_read_u16(&pr, &cmd_class);

    uint16_t  qc = dns_message_get_query_count(mesg);
    uint16_t  pc = dns_message_get_answer_count(mesg);
    uint16_t  an = dns_message_get_authority_count(mesg);

    if(ISOK(return_code) && (qc == 1) && (pc == 0) && (an == 0) && (cmd_type == TYPE_CTRL_SRVCFGRELOAD) && (cmd_class == CLASS_CTRL))
    {
        if(ISOK(return_code = ctrl_query_parse_no_parameters(&pr)))
        {
            log_info("ctrl: config reload");

            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_control)))
            {
                ctrl_config_reload();
            }
            else
            {
                log_notice("ctrl: config reload: rejected by ACL");
                dns_message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            log_notice("ctrl: config reload: rejected by ACL");
            dns_message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        log_notice("ctrl: config reload: rejected by ACL");
        dns_message_make_error(mesg, RCODE_FORMERR);
    }
}

static void ctrl_query_log_query_enable(dns_message_t *mesg)
{
    dns_packet_reader_t pr;
    uint16_t            cmd_type;
    uint16_t            cmd_class;

    dns_packet_reader_init_from_message(&pr, mesg);

    if(FAIL(dns_packet_reader_skip_fqdn(&pr))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    if(FAIL(dns_packet_reader_read_u16(&pr, &cmd_type))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    ya_result return_code = dns_packet_reader_read_u16(&pr, &cmd_class);

    uint16_t  qc = dns_message_get_query_count(mesg);
    uint16_t  pc = dns_message_get_answer_count(mesg);
    uint16_t  an = dns_message_get_authority_count(mesg);

    if(ISOK(return_code) && (qc == 1) && (pc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_SRVQUERYLOG) && (cmd_class == CLASS_CTRL))
    {
        uint8_t on_off = 0;

        if(ISOK(return_code = ctrl_query_parse_bytes(&pr, &on_off, 1)))
        {
            log_info("ctrl: log query: %hhu", on_off & 1);

            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_control)))
            {
                if((on_off & 1) != 0)
                {
                    if(g_config->queries_log_type != 0)
                    {
                        log_query_mode_set(g_config->queries_log_type);
                    }
                    else
                    {
                        log_query_mode_set(1); // yadifa
                    }
                }
                else
                {
                    log_query_mode_set(0); // none
                }
            }
            else
            {
                log_notice("ctrl: log query: %s: rejected by ACL", (on_off & 1) ? "on" : "off");
                dns_message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            log_notice("ctrl: log query: format error");
            dns_message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        log_notice("ctrl: log query: format error");
        dns_message_make_error(mesg, RCODE_FORMERR);
    }
}

static void ctrl_query_log_level(dns_message_t *mesg)
{
    dns_packet_reader_t pr;
    uint16_t            cmd_type;
    uint16_t            cmd_class;

    dns_packet_reader_init_from_message(&pr, mesg);

    if(FAIL(dns_packet_reader_skip_fqdn(&pr))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    if(FAIL(dns_packet_reader_read_u16(&pr, &cmd_type))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    ya_result return_code = dns_packet_reader_read_u16(&pr, &cmd_class);

    uint16_t  qc = dns_message_get_query_count(mesg);
    uint16_t  pc = dns_message_get_answer_count(mesg);
    uint16_t  an = dns_message_get_authority_count(mesg);

    if(ISOK(return_code) && (qc == 1) && (pc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_SRVLOGLEVEL) && (cmd_class == CLASS_CTRL))
    {
        uint8_t level = 0;

        if(ISOK(return_code = ctrl_query_parse_bytes(&pr, &level, 1)))
        {
            log_info("ctrl: log level: %hhu", level);

            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_control)))
            {
                logger_set_level(level);
            }
            else
            {
                log_notice("ctrl: log level: rejected by ACL");
                dns_message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            log_info("ctrl: log level: format error");
            dns_message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        log_info("ctrl: log level: format error");
        dns_message_make_error(mesg, RCODE_FORMERR);
    }
}

/**
 * Freeze ONE zone
 *
 * @param mesg
 */

/**
 *
 * Apply a single command to all zones (that are controllable by the current sender)
 *
 * The proper way to handle all zones from an external command is to try them one by one
 * (because of the ACL)
 *
 * @param mesg
 */

static uint16_t ctrl_query_zone_apply_all(dns_message_t *mesg, ya_result (*ctrl_zone_single)(zone_desc_t *, bool), const char *name)
{
    uint32_t success_count = 0;
    uint32_t error_count = 0;

    log_info("ctrl: zone %s: all", name);

    zone_set_lock(&database_zone_desc);

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *zone_node = ptr_treemap_iterator_next_node(&iter);
        zone_desc_t        *zone_desc = (zone_desc_t *)zone_node->value;

        if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
        {
            ya_result return_value;

            if(ISOK(return_value = ctrl_zone_single(zone_desc, false)))
            {
                ++success_count;
            }
            else
            {
                ++error_count;
            }
        }
        else
        {
            // no need to handle this, it just means that the controller has no rights on this
            log_notice("ctrl: zone %s: all: rejected by ACL", name);
        }
    }

    zone_set_unlock(&database_zone_desc);

    log_info("ctrl: zone %s: all: %i successes, %i errors", name, success_count, error_count);

    if(success_count > 0)
    {
        // part was ok
        return RCODE_NOERROR;
    }
    else if(error_count > 0)
    {
        // part was wrong
        return RCODE_SERVFAIL;
    }
    else
    {
        // no zone accepts this controller
        return RCODE_REFUSED;
    }
}

/**
 * Decodes a command that applies for one or all zones optionally using an fqdn parameter
 * No parameter implies "all"
 */

static void ctrl_query_zone_with_fqdn_class_view(dns_message_t *mesg, ya_result (*ctrl_zone_single)(zone_desc_t *, bool), uint16_t qtype, const char *name)
{
    dns_packet_reader_t pr;
    uint16_t            cmd_type;
    uint16_t            cmd_class;
    uint16_t            rclass = CLASS_IN;
    uint8_t             fqdn[DOMAIN_LENGTH_MAX];
    char                view[32];

    dns_packet_reader_init_from_message(&pr, mesg);

    if(FAIL(dns_packet_reader_skip_fqdn(&pr))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    if(FAIL(dns_packet_reader_read_u16(&pr, &cmd_type))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    ya_result return_code = dns_packet_reader_read_u16(&pr, &cmd_class);

    uint16_t  qc = dns_message_get_query_count(mesg);
    uint16_t  pc = dns_message_get_answer_count(mesg);
    uint16_t  an = dns_message_get_authority_count(mesg);

    uint16_t  tmp_status = RCODE_FORMERR;

    if(ISOK(return_code) && (qc == 1) && (an == 0) && (cmd_type == qtype) && (cmd_class == CLASS_CTRL))
    {
        if(pc == 1)
        {
            if(ISOK(return_code = ctrl_query_parse_fqdn_class_view(&pr, fqdn, sizeof(fqdn), &rclass, view, sizeof(view))))
            {
                if(return_code > 0)
                {
                    log_info("ctrl: zone %s: '%{dnsname}' %{dnsclass}", name, fqdn, &rclass);

                    zone_desc_t *zone_desc = zone_acquirebydnsname(fqdn);
                    tmp_status = RCODE_REFUSED;

                    if(zone_desc != NULL)
                    {
                        if((rclass == zone_desc->qclass) && (view[0] == '\0'))
                        {
                            tmp_status = RCODE_NOTAUTH;

                            if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
                            {
                                ya_result return_value;

                                if(ISOK(return_value = ctrl_zone_single(zone_desc, true)))
                                {
                                    tmp_status = RCODE_NOERROR;
                                }
                                else
                                {
                                    tmp_status = return_value & 0x1f;
                                }
                            }
                            else
                            {
                                log_notice("ctrl: zone %s: rejected by ACL", name);
                            }
                        }
                        else
                        {
                            log_warn("ctrl: zone %s: zone '%{dnsname}' doesn't exist in class %{dnsclass}", name, fqdn, &rclass);
                        }

                        zone_release(zone_desc);
                    }
                    else
                    {
                        log_warn("ctrl: zone %s: zone '%{dnsname}' %{dnsclass} not found", name, fqdn, &rclass);
                    }
                }
                else
                {
                    tmp_status = ctrl_query_zone_apply_all(mesg, ctrl_zone_single, name);
                }
            }
            else
            {
                // an error occurred (FORMERR is already set)
            }
        }
        else if(pc == 0) // no parameter record
        {
            tmp_status = ctrl_query_zone_apply_all(mesg, ctrl_zone_single, name);
        }
        else
        {
            // an error occurred (FORMERR is already set)
        }
    }

    if(tmp_status != RCODE_NOERROR)
    {
        log_notice("ctrl: zone %s: failure (%s)", name, dns_message_rcode_get_name(tmp_status));
        dns_message_make_error(mesg, tmp_status);
    }
}

/**
 * Freeze zone(s)
 *
 * @param mesg
 */

static void ctrl_query_zone_freeze(dns_message_t *mesg) { ctrl_query_zone_with_fqdn_class_view(mesg, ctrl_zone_freeze, TYPE_CTRL_ZONEFREEZE, "freeze"); }

/**
 * Unfreeze zone(s)
 *
 * @param mesg
 */

static void ctrl_query_zone_unfreeze(dns_message_t *mesg) { ctrl_query_zone_with_fqdn_class_view(mesg, ctrl_zone_unfreeze, TYPE_CTRL_ZONEUNFREEZE, "unfreeze"); }

static void ctrl_query_zone_notify(dns_message_t *mesg) { ctrl_query_zone_with_fqdn_class_view(mesg, ctrl_zone_notify, TYPE_CTRL_ZONENOTIFY, "notify"); }

static void ctrl_query_zonereload(dns_message_t *mesg) { ctrl_query_zone_with_fqdn_class_view(mesg, ctrl_zone_reload, TYPE_CTRL_ZONERELOAD, "reload"); }

static void ctrl_query_zone_sync(dns_message_t *mesg)
{
    dns_packet_reader_t pr;
    uint16_t            cmd_type;
    uint16_t            cmd_class;
    uint16_t            rclass;
    uint8_t             fqdn[DOMAIN_LENGTH_MAX];
    char                view[32];

    dns_packet_reader_init_from_message(&pr, mesg);

    if(FAIL(dns_packet_reader_skip_fqdn(&pr))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    if(FAIL(dns_packet_reader_read_u16(&pr, &cmd_type))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    ya_result return_code = dns_packet_reader_read_u16(&pr, &cmd_class);

    uint16_t  qc = dns_message_get_query_count(mesg);
    uint16_t  pc = dns_message_get_answer_count(mesg);
    uint16_t  an = dns_message_get_authority_count(mesg);

    uint16_t  tmp_status = RCODE_FORMERR;

    if(ISOK(return_code) && (qc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_ZONESYNC) && (cmd_class == CLASS_CTRL))
    {
        if(pc == 1)
        {
            uint8_t clean = 0;

            if(ISOK(return_code = ctrl_query_parse_byte_fqdn_class_view(&pr, &clean, fqdn, sizeof(fqdn), &rclass, view, sizeof(view))))
            {
                if(return_code > 1)
                {
                    log_info("ctrl: zone sync: clean=%hhu '%{dnsname}' %{dnsclass}", clean & 1, fqdn, &rclass);

                    zone_desc_t *zone_desc = zone_acquirebydnsname(fqdn);
                    tmp_status = RCODE_REFUSED;

                    if(zone_desc != NULL)
                    {
                        if((rclass == zone_desc->qclass) && (view[0] == '\0'))
                        {
                            tmp_status = RCODE_NOTAUTH;

                            if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
                            {
                                tmp_status = ctrl_zone_sync(zone_desc, true, (clean & 1) != 0);
                            }
                            else
                            {
                                log_notice("ctrl: zone sync: '%{dnsname}': rejected by ACL", fqdn);
                            }
                        }
                        else
                        {
                            log_notice("ctrl: zone sync: zone '%{dnsname}' not found in class %{dnsclass}", fqdn, &rclass);
                        }

                        zone_release(zone_desc);
                    }
                    else
                    {
                        log_notice("ctrl: zone sync: zone '%{dnsname}' %{dnsclass} not found", fqdn, &rclass);
                    }
                }
                else
                {
                    tmp_status = ctrl_query_zone_apply_all(mesg, ctrl_zone_sync_noclean, "sync");
                }
            }
            else
            {
                // some error (FORMERR already set)
            }
        }
        else if(pc == 0)
        {
            tmp_status = ctrl_query_zone_apply_all(mesg, ctrl_zone_sync_noclean, "sync");
        }
        else
        {
            // some error (FORMERR already set)
        }
    }

    if(tmp_status != RCODE_NOERROR)
    {
        log_notice("ctrl: zone sync: failure (%s)", dns_message_rcode_get_name(tmp_status));
        dns_message_make_error(mesg, tmp_status);
    }
}

static void ctrl_query_zonecfgreload(dns_message_t *mesg)
{
    // This doesnt work in a do once/do all once way, hence ...
    // CANNOT: ctrl_query_zone_with_fqdn_class_view(mesg, ctrl_zone_notify, TYPE_CTRL_ZONECFGRELOAD, "config reload");

    dns_packet_reader_t pr;
    uint16_t            cmd_type;
    uint16_t            cmd_class;
    uint16_t            rclass;
    uint8_t             fqdn[DOMAIN_LENGTH_MAX];
    char                view[32];

    dns_packet_reader_init_from_message(&pr, mesg);

    if(FAIL(dns_packet_reader_skip_fqdn(&pr))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    if(FAIL(dns_packet_reader_read_u16(&pr, &cmd_type))) // shouldn't fail
    {
        log_info("ctrl: shutdown FORMERR");
        return;
    }

    ya_result return_code = dns_packet_reader_read_u16(&pr, &cmd_class);

    uint16_t  qc = dns_message_get_query_count(mesg);
    uint16_t  pc = dns_message_get_answer_count(mesg);
    uint16_t  an = dns_message_get_authority_count(mesg);

    uint16_t  tmp_status = RCODE_FORMERR;

    if(ISOK(return_code) && (qc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_ZONECFGRELOAD) && (cmd_class == CLASS_CTRL))
    {
        if(pc == 1)
        {
            if(ISOK(return_code = ctrl_query_parse_fqdn_class_view(&pr, fqdn, sizeof(fqdn), &rclass, view, sizeof(view))))
            {
                if(return_code > 0)
                {
                    log_info("ctrl: zone config reload: '%{dnsname}' %{dnsclass}", fqdn, &rclass);

                    zone_desc_t *zone_desc = zone_acquirebydnsname(fqdn);
                    tmp_status = RCODE_REFUSED;

                    if(zone_desc != NULL)
                    {
                        if((rclass == zone_desc->qclass) && (view[0] == '\0'))
                        {
                            tmp_status = RCODE_NOTAUTH;

                            if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
                            {
                                tmp_status = RCODE_SERVFAIL;

                                // const_ptr_treemap_of_one is a quick and cheap way to generate constant ptr_treemap_t
                                // of a single element

                                const_ptr_treemap_of_one fqdn_set;
                                const_ptr_treemap_of_one_init(&fqdn_set, fqdn, fqdn, ptr_treemap_dnsname_node_compare);

                                ya_result return_code = yadifad_config_update_zone(g_config->config_file, &fqdn_set.set);

                                if(ISOK(return_code))
                                {
                                    // tmp_status = RCODE_NOERROR;
                                    zone_release(zone_desc);

                                    return;
                                }
                            }
                            else
                            {
                                log_notice("ctrl: zone config reload: zone '%{dnsname}': rejected by ACL", fqdn);
                            }
                        }
                        else
                        {
                            log_warn("ctrl: zone config reload: zone '%{dnsname}' doesn't exist in class %{dnsclass}", fqdn, &rclass);
                        }

                        zone_release(zone_desc);
                    }
                    else
                    {
                        log_warn("ctrl: zone config reload: zone '%{dnsname}' %{dnsclass} not found", fqdn, &rclass);
                    }
                }
                else
                {
                    log_info("ctrl: zone config reload: all");

                    tmp_status = RCODE_NOTAUTH;

                    if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_control)))
                    {
                        tmp_status = RCODE_SERVFAIL;

                        ya_result return_code = yadifad_config_update_zone(g_config->config_file, NULL);

                        if(ISOK(return_code))
                        {
                            tmp_status = RCODE_NOERROR;
                        }
                    }
                    else
                    {
                        log_notice("ctrl: zone config reload: all: rejected by ACL");
                    }
                }
            }
            else
            {
                log_warn("ctrl: zone config reload: zone '%{dnsname}' %{dnsclass} not found", fqdn, &rclass);
            }
        }
        else if(pc == 0)
        {
            log_info("ctrl: zone config reload: all");

            tmp_status = RCODE_NOTAUTH;

            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_control)))
            {
                tmp_status = RCODE_SERVFAIL;

                ya_result return_code = yadifad_config_update_zone(g_config->config_file, NULL);

                if(ISOK(return_code))
                {
                    tmp_status = RCODE_NOERROR;
                }
            }
            else
            {
                log_notice("ctrl: zone config reload: all: rejected by ACL");
            }
        }
    }

    if(tmp_status != RCODE_NOERROR)
    {
        dns_message_make_error(mesg, tmp_status);
    }
}

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING

static void ctrl_query_cfgsave(dns_message_t *mesg)
{
    if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_control)))
    {
        ctrl_store_dynamic_config();
    }
    else
    {
        log_notice("ctrl: cfg save: rejected by ACL");

        message_make_error(mesg, RCODE_REFUSED);
    }
}

static void ctrl_query_cfgdrop(dns_message_t *mesg)
{
    uint16_t     tmp_status = RCODE_NXDOMAIN;

    zone_desc_s *zone_desc = zone_acquiredynamicbydnsname(message_get_canonised_fqdn(mesg));

    if(zone_desc != NULL)
    {
        tmp_status = RCODE_NOTAUTH;

        if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
        {
            tmp_status = RCODE_NXDOMAIN;

            if(ISOK(ctrl_zone_config_delete(zone_desc, true)))
            {
                zone_release(zone_desc);

                tmp_status = RCODE_NOERROR;

                message_set_status(mesg, (finger_print)tmp_status);

                return;
            }
        }
        else
        {
            log_notice("ctrl: zone unfreeze: rejected by ACL");
        }

        zone_release(zone_desc);
    }

    message_make_error(mesg, tmp_status);
}

#endif // HAS_DYNAMIC_PROVISIONING

bool ctrl_query_is_listened(int sockfd)
{
#if 0
    host_address *ha;
    if((ha = ctrl_get_listen()) == NULL)
    {
        return true;
    }

    socketaddress sa;
    socklen_t sa_len = sizeof(sa);
    if(getsockname(sockfd, &sa.sa, &sa_len) == 0)
    {
        while(ha != NULL)
        {
            if(host_address_list_contains_ip(ha, &sa))
            {
                return true;
            }

            ha = ha->next;
        }
    }

    return false;
#else
    (void)sockfd;
    return true;
#endif
}

void ctrl_query_process(dns_message_t *mesg)
{
    log_info("CTRL (%04hx) %{dnsname} %{dnstype}", ntohs(dns_message_get_id(mesg)), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg));

    if(!ctrl_get_enabled())
    {
        dns_message_make_error(mesg, RCODE_REFUSED);

#if DNSCORE_HAS_TSIG_SUPPORT
        if(dns_message_has_tsig(mesg)) /* NOTE: the TSIG information is in mesg */
        {
            tsig_sign_answer(mesg);
        }
#endif
        return;
    }

    if(dns_message_get_canonised_fqdn(mesg)[0] != '\0')
    {
        dns_message_make_error(mesg, RCODE_FORMERR);

#if DNSCORE_HAS_TSIG_SUPPORT
        if(dns_message_has_tsig(mesg)) /* NOTE: the TSIG information is in mesg */
        {
            tsig_sign_answer(mesg);
        }
#endif
        return;
    }

    dns_message_set_answer(mesg);
    dns_message_set_status(mesg, RCODE_NOERROR);

    // now can read the command

    switch(dns_message_get_query_type(mesg))
    {
        case TYPE_CTRL_SRVSHUTDOWN:
        {
            ctrl_query_server_shutdown(mesg);
            break;
        }
        case TYPE_CTRL_SRVLOGREOPEN:
        {
            ctrl_query_logger_reopen(mesg);
            break;
        }
        case TYPE_CTRL_SRVCFGRELOAD:
        {
            ctrl_query_config_reload(mesg);
            break;
        }
        case TYPE_CTRL_SRVQUERYLOG:
        {
            ctrl_query_log_query_enable(mesg);
            break;
        }
        case TYPE_CTRL_SRVLOGLEVEL:
        {
            ctrl_query_log_level(mesg);
            break;
        }
        case TYPE_CTRL_ZONEFREEZE: /* freeze */
        {
            ctrl_query_zone_freeze(mesg);
            break;
        }
        case TYPE_CTRL_ZONEUNFREEZE: /* unfreeze */
        {
            ctrl_query_zone_unfreeze(mesg);
            break;
        }
        case TYPE_CTRL_ZONESYNC: /* sync */
        {
            ctrl_query_zone_sync(mesg);
            break;
        }
        case TYPE_CTRL_ZONENOTIFY:
        {
            ctrl_query_zone_notify(mesg);
            break;
        }
        case TYPE_CTRL_ZONERELOAD:
        {
            ctrl_query_zonereload(mesg);
            break;
        }
        case TYPE_CTRL_ZONECFGRELOAD:
        {
            ctrl_query_zonecfgreload(mesg);
            break;
        }

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING
        case TYPE_CTRL_CFGMERGE:
        {
            if((g_config->server_flags & SERVER_FL_DYNAMIC_PROVISIONING) != 0)
            {
                ctrl_query_config_merge(mesg);
            }
            else
            {
                log_err("ctrl: dynamic provisioning disabled");
            }
            break;
        }
        case TYPE_CTRL_CFGMERGEALL:
        {
            if((g_config->server_flags & SERVER_FL_DYNAMIC_PROVISIONING) != 0)
            {
                ctrl_query_config_merge_all(mesg);
            }
            else
            {
                log_err("ctrl: dynamic provisioning disabled");
            }
            break;
        }
        case TYPE_CTRL_CFGSAVE:
        {
            if((g_config->server_flags & SERVER_FL_DYNAMIC_PROVISIONING) != 0)
            {
                ctrl_query_cfgsave(mesg);
            }
            else
            {
                log_err("ctrl: dynamic provisioning disabled");
            }
            break;
        }
        case TYPE_CTRL_CFGDROP:
        {
            if((g_config->server_flags & SERVER_FL_DYNAMIC_PROVISIONING) != 0)
            {
                ctrl_query_cfgdrop(mesg);
            }
            else
            {
                log_err("ctrl: dynamic provisioning disabled");
            }
            break;
        }
        case TYPE_CTRL_CFGLOAD:
        {
            /* how is this supposed to work ? */
            // ctrl_query_cfgload(mesg);
            break;
        }
        case TYPE_AXFR:
        {
            /* AXFR query (signed) from a secondary */
            /* prepare the <zone> stream */

            if((g_config->server_flags & SERVER_FL_DYNAMIC_PROVISIONING) != 0)
            {
                ctrl_query_axfr_make_answer(mesg);
            }
            else
            {
                log_err("ctrl: dynamic provisioning disabled");
            }
            /* and send it back (done by the caller) */
            break;
        }
#endif // HAS_DYNAMIC_PROVISIONING

#if 0
        case TYPE_CMD_ZONE_STATUS:
        {
            ctrl_query_zone_status(mesg);

            break;
        }
        
        case TYPE_CMD_SERVER_STATUS:
        {
            ctrl_query_server_status(mesg);

            break;
        }
#endif

        default:
        {
            dns_message_make_error(mesg, RCODE_NOTIMP); /* or do we drop ? */

            break;
        }
    } /* switch qtype */

#if DNSCORE_HAS_TSIG_SUPPORT
    if(dns_message_has_tsig(mesg)) /* NOTE: the TSIG information is in mesg */
    {
        tsig_sign_answer(mesg);
    }
#endif
}

#if 0
static void
ctrl_query_server_status(dns_message_t *mesg)
{
    /*
     * Schedule the unfreeze of the zone on the disk (and the restart of the maintenance)
     */

    ya_result tmp_status = RCODE_REFUSED;

    if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_control)))
    {
        tmp_status = RCODE_SERVFAIL;

        zdb *db = g_config->database;

        if(db != NULL)
        {
            dns_packet_writer pw;
            dns_packet_writer_init_append_to_message(&pw, &mesg);

            ctrl_query_message_add_time_txt(&pw, "now", time(NULL));

            message_set_answer_count_ne(mesg, NETWORK_ONE_16);

            alarm_lock();

            alarm_event_node *node = alarm_get_first(db->alarm_handle);

            if(node != NULL)
            {
                uint16_t count = 0;

                while(node->hndl_next != NULL)
                {
                    uint32_t mark = pw.packet_offset;

                    if(FAIL(ctrl_query_message_add_time_txt(&pw, "alarm.time", node->epoch)))
                    {
                        break;
                    }

                    if(FAIL(ctrl_query_message_add_text_txt(&pw, "alarm.text", node->text)))
                    {
                        pw.packet_offset = mark;

                        break;
                    }

                    count += 2;

                    node = node->hndl_next;
                }

                message_set_additional_count(mesg, count);
            }

            alarm_unlock();

            message_set_size(mesg, pw.packet_offset);

            return;
        }
    }
    else
    {
        log_notice("ctrl: server status: rejected by ACL");
    }

    message_make_error(mesg, tmp_status);
}
#endif

#endif // HAS_CTRL

/** @} */
