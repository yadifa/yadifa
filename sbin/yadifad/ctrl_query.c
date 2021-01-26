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

/** @defgroup server
 *  @ingroup yadifad
 *  @brief server
 *
 *  Handles queries made in the CH class (ie: version.*)
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#include "server-config.h"

#include <dnscore/file_output_stream.h>
#include <dnscore/logger.h>
#include <dnscore/rfc.h>
#include <dnscore/ctrl-rfc.h>
#include <dnscore/threaded_queue.h>

#include <dnsdb/zdb_zone.h>
#include <dnscore/format.h>
#include <dnscore/packet_reader.h>
#include <dnscore/packet_writer.h>

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "confs.h"
#include "signals.h"
#include <dnscore/acl.h>



#if HAS_CTRL

#include "ctrl_zone.h"

#include "log_query.h"

#include "database-service.h"

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





/*****************************************************************************/


static ya_result
ctrl_query_parse_no_parameters(packet_unpack_reader_data *pr)
{
    (void)pr;
    return SUCCESS;
}

static ya_result
ctrl_query_parse_bytes(packet_unpack_reader_data *pr, void *out, u32 out_size)
{
    struct type_class_ttl_rdlen cmd_tctr;
    packet_reader_skip_fqdn(pr);
    packet_reader_read(pr, &cmd_tctr, 10); // exact
    cmd_tctr.rdlen = ntohs(cmd_tctr.rdlen);
    
    if(cmd_tctr.rdlen <= out_size)
    {
        cmd_tctr.rdlen -= out_size;
        ya_result return_code = packet_reader_read(pr, out, out_size); // exact
        return return_code;
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

static ya_result
ctrl_query_parse_fqdn_class_view(packet_unpack_reader_data *pr, u8 *fqdn, u32 fqdn_size, u16 *rclass, char *view, u32 view_size)
{
    struct type_class_ttl_rdlen cmd_tctr;
    packet_reader_skip_fqdn(pr);
    packet_reader_read(pr, &cmd_tctr, 10); // exact
    cmd_tctr.rdlen = ntohs(cmd_tctr.rdlen);
    
    fqdn[0] = '\0';
    *rclass = CLASS_IN;
    view[0] = '\0';

    ya_result return_code = 0;

    if(cmd_tctr.rdlen != 0)
    {
        u32 from = pr->offset;
        if(ISOK(return_code = packet_reader_read_fqdn(pr, fqdn, fqdn_size)))
        {
            cmd_tctr.rdlen -= pr->offset -from;

            ya_result parameters = 1;
            
            if(cmd_tctr.rdlen > 2)
            {
                if(ISOK(return_code = packet_reader_read(pr, rclass, 2))) // exact
                {
                    ++parameters;

                    cmd_tctr.rdlen -= 2;
                    
                    if(cmd_tctr.rdlen > 0)
                    {
                        u32 n = MIN(cmd_tctr.rdlen, view_size - 1);
                        if(ISOK(return_code = packet_reader_read(pr, view, n))) // exact
                        {
                            ++parameters;
                            view[n] = '\0';

                            cmd_tctr.rdlen -= return_code;
                        }
                    }
                }
            }

            if(ISOK(return_code))
            {
                if(cmd_tctr.rdlen == 0)
                {
                    return_code = parameters;
                }
                else
                {
                    return_code = MAKE_DNSMSG_ERROR(RCODE_FORMERR); // must end on an exact match
                }
            }
        }
    }

    return return_code;
}

static ya_result
ctrl_query_parse_byte_fqdn_class_view(packet_unpack_reader_data *pr, u8* one_byte, u8 *fqdn, u32 fqdn_size, u16 *rclass, char *view, u32 view_size)
{
    struct type_class_ttl_rdlen cmd_tctr;
    packet_reader_skip_fqdn(pr);
    packet_reader_read(pr, &cmd_tctr, 10);
    cmd_tctr.rdlen = ntohs(cmd_tctr.rdlen);
    
    fqdn[0] = '\0';
    *rclass = CLASS_IN;
    view[0] = '\0';
    
    if(cmd_tctr.rdlen != 0)
    {
        ya_result return_code;
        u32 from = pr->offset;

        // read the byte

        if(ISOK(return_code = packet_reader_read(pr, one_byte, 1)))
        {
            // read the fqdn

            if(ISOK(return_code = packet_reader_read_fqdn(pr, fqdn, fqdn_size)))
            {
                // adjust the remaining bytes to process

                cmd_tctr.rdlen -= pr->offset - from;

                // if there is enough for a class ...

                if(cmd_tctr.rdlen > 2)
                {
                    // read the class

                    if(ISOK(return_code = packet_reader_read(pr, rclass, 2)))
                    {
                        cmd_tctr.rdlen -= 2;

                        // if there is something left it's the view parameter

                        if(cmd_tctr.rdlen > 0)
                        {
                            u32 n = MIN(cmd_tctr.rdlen, view_size - 1);
                            if(ISOK(return_code = packet_reader_read(pr, view, n)))
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
                        return DNS_ERROR_CODE(RCODE_FORMERR); // the one forbidden value is 1 byte available
                    }
                }
            }
        }
        
        return pr->offset - from;
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

static void
ctrl_query_server_shutdown(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    
    packet_reader_init_from_message(&pr, mesg);
    
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = message_get_query_count(mesg);
    u16 pc = message_get_answer_count(mesg);
    u16 an = message_get_authority_count(mesg);
    
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

                    program_mode = SA_SHUTDOWN;
                    server_service_stop_nowait();

                    dnscore_shutdown();
                }
                else
                {
                    log_info("ctrl: shutdown: already shutting down");
                }
            }
            else
            {
                log_notice("ctrl: shutdown: rejected by ACL");
                message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            log_notice("ctrl: shutdown: format error");
            message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        log_notice("ctrl: shutdown: format error");
        message_make_error(mesg, RCODE_FORMERR);
    }
}

static void
ctrl_query_logger_reopen(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    
    packet_reader_init_from_message(&pr, mesg);
    
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = message_get_query_count(mesg);
    u16 pc = message_get_answer_count(mesg);
    u16 an = message_get_authority_count(mesg);
    
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
                message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            log_notice("ctrl: logger reopen: format error");
            message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        log_notice("ctrl: logger reopen: format error");
        message_make_error(mesg, RCODE_FORMERR);
    }
}

static void
ctrl_query_config_reload(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    
    packet_reader_init_from_message(&pr, mesg);
    
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = message_get_query_count(mesg);
    u16 pc = message_get_answer_count(mesg);
    u16 an = message_get_authority_count(mesg);
    
    if(ISOK(return_code) && (qc == 1) && (pc == 0) && (an == 0) && (cmd_type == TYPE_CTRL_SRVCFGRELOAD) && (cmd_class == CLASS_CTRL))
    {        
        if(ISOK(return_code = ctrl_query_parse_no_parameters(&pr)))
        {
            log_info("ctrl: config reload");
            
            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_control)))
            {
                if(ISOK(yadifad_config_update(g_config->config_file)))
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
            }
            else
            {
                log_notice("ctrl: config reload: rejected by ACL");
                message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            log_notice("ctrl: config reload: rejected by ACL");
            message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        log_notice("ctrl: config reload: rejected by ACL");
        message_make_error(mesg, RCODE_FORMERR);
    }
}

static void
ctrl_query_log_query_enable(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    
    packet_reader_init_from_message(&pr, mesg);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);

    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);

    u16 qc = message_get_query_count(mesg);
    u16 pc = message_get_answer_count(mesg);
    u16 an = message_get_authority_count(mesg);
    
    if(ISOK(return_code) && (qc == 1) && (pc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_SRVQUERYLOG) && (cmd_class == CLASS_CTRL))
    {        
        u8 on_off = 0;
        
        if(ISOK(return_code = ctrl_query_parse_bytes(&pr, &on_off, 1)))
        {
            log_info("ctrl: log query: %hhu", on_off & 1);
            
            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_control)))
            {
                if((on_off & 1) != 0)
                {
                    if(g_config->queries_log_type != 0)
                    {
                        log_query_set_mode(g_config->queries_log_type);
                    }
                    else
                    {
                        log_query_set_mode(1); // yadifa
                    }
                }
                else
                {
                    log_query_set_mode(0); // none
                }
            }
            else
            {
                log_notice("ctrl: log query: %s: rejected by ACL", (on_off&1)?"on":"off");
                message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            log_notice("ctrl: log query: format error");
            message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        log_notice("ctrl: log query: format error");
        message_make_error(mesg, RCODE_FORMERR);
    }
}

static void
ctrl_query_log_level(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    
    packet_reader_init_from_message(&pr, mesg);
    
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = message_get_query_count(mesg);
    u16 pc = message_get_answer_count(mesg);
    u16 an = message_get_authority_count(mesg);
    
    if(ISOK(return_code) && (qc == 1) && (pc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_SRVLOGLEVEL) && (cmd_class == CLASS_CTRL))
    {
        u8 level = 0;
        
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
                message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            log_info("ctrl: log level: format error");
            message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        log_info("ctrl: log level: format error");
        message_make_error(mesg, RCODE_FORMERR);
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

static u16
ctrl_query_zone_apply_all(message_data *mesg, ya_result (*ctrl_zone_single)(zone_desc_s *, bool), const char* name)
{
    u32 success_count = 0;
    u32 error_count = 0;

    log_info("ctrl: zone %s: all", name);

    zone_set_lock(&database_zone_desc);

    ptr_set_iterator iter;
    ptr_set_iterator_init(&database_zone_desc.set, &iter);

    while(ptr_set_iterator_hasnext(&iter))
    {
        ptr_node *zone_node = ptr_set_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->value;

        if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
        {
            ya_result return_value;

            if(ISOK(return_value = ctrl_zone_single(zone_desc, FALSE)))
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

static void
ctrl_query_zone_with_fqdn_class_view(message_data *mesg,
    ya_result (*ctrl_zone_single)(zone_desc_s *, bool),
    u16 qtype,
    const char *name
    )
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    u16 rclass = CLASS_IN;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    char view[32];

    packet_reader_init_from_message(&pr, mesg);

    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);

    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);

    u16 qc = message_get_query_count(mesg);
    u16 pc = message_get_answer_count(mesg);
    u16 an = message_get_authority_count(mesg);

    u16 tmp_status = RCODE_FORMERR;

    if(ISOK(return_code) && (qc == 1) && (an == 0) && (cmd_type == qtype) && (cmd_class == CLASS_CTRL))
    {
        if(pc == 1)
        {
            if(ISOK(return_code = ctrl_query_parse_fqdn_class_view(&pr, fqdn, sizeof(fqdn), &rclass, view, sizeof(view))))
            {
                if(return_code > 0)
                {
                    log_info("ctrl: zone %s: '%{dnsname}' %{dnsclass}", name, fqdn, &rclass);

                    zone_desc_s* zone_desc = zone_acquirebydnsname(fqdn);
                    tmp_status = RCODE_REFUSED;

                    if(zone_desc != NULL)
                    {
                        if((rclass == zone_desc->qclass) && (view[0] == '\0'))
                        {
                            tmp_status = RCODE_NOTAUTH;

                            if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
                            {
                                ya_result return_value;

                                if(ISOK(return_value = ctrl_zone_single(zone_desc, TRUE)))
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
        message_make_error(mesg, tmp_status);
    }
}

/**
 * Freeze zone(s)
 *
 * @param mesg
 */

static void
ctrl_query_zone_freeze(message_data *mesg)
{
    ctrl_query_zone_with_fqdn_class_view(mesg, ctrl_zone_freeze, TYPE_CTRL_ZONEFREEZE, "freeze");
}

/**
 * Unfreeze zone(s)
 * 
 * @param mesg
 */

static void
ctrl_query_zone_unfreeze(message_data *mesg)
{
    ctrl_query_zone_with_fqdn_class_view(mesg, ctrl_zone_unfreeze, TYPE_CTRL_ZONEUNFREEZE, "unfreeze");
}

static void
ctrl_query_zone_notify(message_data *mesg)
{
    ctrl_query_zone_with_fqdn_class_view(mesg, ctrl_zone_notify, TYPE_CTRL_ZONENOTIFY, "notify");
}

static void
ctrl_query_zonereload(message_data *mesg)
{
    ctrl_query_zone_with_fqdn_class_view(mesg, ctrl_zone_reload, TYPE_CTRL_ZONERELOAD, "reload");
}

static void
ctrl_query_zone_sync(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    u16 rclass;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    char view[32];
    
    packet_reader_init_from_message(&pr, mesg);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = message_get_query_count(mesg);
    u16 pc = message_get_answer_count(mesg);
    u16 an = message_get_authority_count(mesg);
    
    u16 tmp_status = RCODE_FORMERR;
    
    if(ISOK(return_code) && (qc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_ZONESYNC) && (cmd_class == CLASS_CTRL))
    {
        if(pc == 1)
        {
            u8 clean = 0;

            if(ISOK(return_code = ctrl_query_parse_byte_fqdn_class_view(&pr, &clean, fqdn, sizeof(fqdn), &rclass, view, sizeof(view))))
            {
                if(return_code > 1)
                {
                    log_info("ctrl: zone sync: clean=%hhu '%{dnsname}' %{dnsclass}", clean & 1, fqdn, &rclass);

                    zone_desc_s* zone_desc = zone_acquirebydnsname(fqdn);
                    tmp_status = RCODE_REFUSED;

                    if(zone_desc != NULL)
                    {
                        if((rclass == zone_desc->qclass) && (view[0] == '\0'))
                        {
                            tmp_status = RCODE_NOTAUTH;

                            if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
                            {
                                tmp_status = ctrl_zone_sync(zone_desc, TRUE, (clean & 1) != 0);
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
        message_make_error(mesg, tmp_status);
    }
}

static void
ctrl_query_zonecfgreload(message_data *mesg)
{
    // This doesnt work in a do once/do all once way, hence ...
    // CANNOT: ctrl_query_zone_with_fqdn_class_view(mesg, ctrl_zone_notify, TYPE_CTRL_ZONECFGRELOAD, "config reload");

    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    u16 rclass;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    char view[32];
    
    packet_reader_init_from_message(&pr, mesg);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = message_get_query_count(mesg);
    u16 pc = message_get_answer_count(mesg);
    u16 an = message_get_authority_count(mesg);
    
    u16 tmp_status = RCODE_FORMERR;
    
    if(ISOK(return_code) && (qc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_ZONECFGRELOAD) && (cmd_class == CLASS_CTRL))
    {
        if(pc == 1)
        {
            if(ISOK(return_code = ctrl_query_parse_fqdn_class_view(&pr, fqdn, sizeof(fqdn), &rclass, view, sizeof(view))))
            {
                if(return_code > 0)
                {
                    log_info("ctrl: zone config reload: '%{dnsname}' %{dnsclass}", fqdn, &rclass);

                    zone_desc_s *zone_desc = zone_acquirebydnsname(fqdn);
                    tmp_status = RCODE_REFUSED;

                    if(zone_desc != NULL)
                    {
                        if((rclass == zone_desc->qclass) && (view[0] == '\0'))
                        {
                            tmp_status = RCODE_NOTAUTH;

                            if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
                            {
                                tmp_status = RCODE_SERVFAIL;

                                // const_ptr_set_of_one is a quick and cheap way to generate constant ptr_set of a single element

                                const_ptr_set_of_one fqdn_set;
                                const_ptr_set_of_one_init(&fqdn_set, fqdn, fqdn, ptr_set_dnsname_node_compare);

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
        message_make_error(mesg, tmp_status);
    }
}

bool
ctrl_query_is_listened(int sockfd)
{
#if 0 /* fix */
#else
    (void)sockfd;
    return TRUE;
#endif
}

void
ctrl_query_process(message_data *mesg)
{
    log_info("CTRL (%04hx) %{dnsname} %{dnstype}", ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg));

    if(!ctrl_get_enabled())
    {
        message_make_error(mesg, RCODE_REFUSED);
        
#if DNSCORE_HAS_TSIG_SUPPORT
        if(message_has_tsig(mesg))  /* NOTE: the TSIG information is in mesg */
        {
            tsig_sign_answer(mesg);
        }
#endif
        return;
    }

    if(message_get_canonised_fqdn(mesg)[0] != '\0')
    {
        message_make_error(mesg, RCODE_FORMERR);
        
#if DNSCORE_HAS_TSIG_SUPPORT
        if(message_has_tsig(mesg))  /* NOTE: the TSIG information is in mesg */
        {
            tsig_sign_answer(mesg);
        }
#endif
        return;
    }
    
    message_set_answer(mesg);
    message_set_status(mesg, RCODE_NOERROR);

    // now can read the command
    
    switch(message_get_query_type(mesg))
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
        case TYPE_CTRL_ZONEFREEZE:   /* freeze */
        {
            ctrl_query_zone_freeze(mesg);
            break;
        }
        case TYPE_CTRL_ZONEUNFREEZE:   /* unfreeze */
        {
            ctrl_query_zone_unfreeze(mesg);
            break;
        }
        case TYPE_CTRL_ZONESYNC:   /* sync */
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
        

        


        default:
        {
            message_make_error(mesg, RCODE_NOTIMP); /* or do we drop ? */
            
            break;
        }
    }   /* switch qtype */
    
#if DNSCORE_HAS_TSIG_SUPPORT
    if(message_has_tsig(mesg))  /* NOTE: the TSIG information is in mesg */
    {
        tsig_sign_answer(mesg);
    }
#endif
}



#endif // HAS_CTRL

/** @} */
