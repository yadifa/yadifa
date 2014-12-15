/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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

#include "config.h"

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
#include "acl.h"

#include "ctrl.h"
#include "ctrl_zone.h"

#include "log_query.h"

#include "database-service.h"

#include "notify.h"

#if HAS_CTRL

extern zone_data_set database_zone_desc;

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
    packet_reader_read(pr, &cmd_tctr, 10);
    cmd_tctr.rdlen = ntohs(cmd_tctr.rdlen);
    
    if(cmd_tctr.rdlen <= out_size)
    {
        cmd_tctr.rdlen -= out_size;
        ya_result return_code = packet_reader_read(pr, out, out_size);
        return return_code;
    }
    else
    {
        return ERROR; // not enough bytes
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
    packet_reader_read(pr, &cmd_tctr, 10);
    cmd_tctr.rdlen = ntohs(cmd_tctr.rdlen);
    
    fqdn[0] = '\0';
    *rclass = CLASS_IN;
    view[0] = '\0';
    
    if(cmd_tctr.rdlen != 0)
    {
        ya_result return_code;
        u32 from = pr->offset;
        if(ISOK(return_code = packet_reader_read_fqdn(pr, fqdn, fqdn_size)))
        {
            cmd_tctr.rdlen -= pr->offset -from;
            
            if(cmd_tctr.rdlen > 2)
            {
                if(ISOK(return_code = packet_reader_read(pr, rclass, 2)))
                {
                    cmd_tctr.rdlen -= 2;
                    
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
            else
            {
                if(cmd_tctr.rdlen != 0)
                {
                    return_code = ERROR; // the one forbidden value is 1 byte available
                }
            }
        }
        
        return return_code;
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
    
    packet_reader_init(&pr, mesg->buffer, mesg->received);
    packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = ntohs(MESSAGE_QD(mesg->buffer));
    u16 pc = ntohs(MESSAGE_AN(mesg->buffer));
    u16 an = ntohs(MESSAGE_NS(mesg->buffer));
    
    if(ISOK(return_code) && (qc == 1) && (pc == 0) && (an == 0) && (cmd_type == TYPE_CTRL_SRVSHUTDOWN) && (cmd_class == CLASS_CTRL))
    {
        if(ISOK(return_code = ctrl_query_parse_no_parameters(&pr)))
        {
            log_info("ctrl: shutdown");
            
            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac.allow_control)))
            {
                program_mode = SA_SHUTDOWN;

                dnscore_shutdown();

                mesg->send_length = mesg->received;
            }
            else
            {
                log_err("ctrl: shutdown: rejected by ACL");

                message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        message_make_error(mesg, RCODE_FORMERR);
    }
}

static void
ctrl_query_logger_reopen(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    
    packet_reader_init(&pr, mesg->buffer, mesg->received);
    packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = ntohs(MESSAGE_QD(mesg->buffer));
    u16 pc = ntohs(MESSAGE_AN(mesg->buffer));
    u16 an = ntohs(MESSAGE_NS(mesg->buffer));
    
    if(ISOK(return_code) && (qc == 1) && (pc == 0) && (an == 0) && (cmd_type == TYPE_CTRL_SRVLOGREOPEN) && (cmd_class == CLASS_CTRL))
    {
        if(ISOK(return_code = ctrl_query_parse_no_parameters(&pr)))
        {
            log_info("ctrl: logger reopen");
            
            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac.allow_control)))
            {
                logger_reopen();

                mesg->send_length = mesg->received;
            }
            else
            {
                log_err("ctrl: logger reopen: rejected by ACL");

                message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        message_make_error(mesg, RCODE_FORMERR);
    }
}

static void
ctrl_query_config_reload(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    
    packet_reader_init(&pr, mesg->buffer, mesg->received);
    packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = ntohs(MESSAGE_QD(mesg->buffer));
    u16 pc = ntohs(MESSAGE_AN(mesg->buffer));
    u16 an = ntohs(MESSAGE_NS(mesg->buffer));
    
    if(ISOK(return_code) && (qc == 1) && (pc == 0) && (an == 0) && (cmd_type == TYPE_CTRL_SRVCFGRELOAD) && (cmd_class == CLASS_CTRL))
    {        
        if(ISOK(return_code = ctrl_query_parse_no_parameters(&pr)))
        {
            log_info("ctrl: config reload");
            
            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac.allow_control)))
            {
                yadifad_config_update(g_config->config_file);

                mesg->send_length = mesg->received;
            }
            else
            {
                log_err("ctrl: config reload: rejected by ACL");

                message_make_error(mesg, RCODE_REFUSED);
            }
        }
        else
        {
            message_make_error(mesg, RCODE_FORMERR);
        }
    }
    else
    {
        message_make_error(mesg, RCODE_FORMERR);
    }
}

static void
ctrl_query_log_query_enable(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    
    packet_reader_init(&pr, mesg->buffer, mesg->received);
    packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = ntohs(MESSAGE_QD(mesg->buffer));
    u16 pc = ntohs(MESSAGE_AN(mesg->buffer));
    u16 an = ntohs(MESSAGE_NS(mesg->buffer));
    
    if(ISOK(return_code) && (qc == 1) && (pc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_SRVQUERYLOG) && (cmd_class == CLASS_CTRL))
    {        
        u8 on_off = 0;
        
        if(ISOK(return_code = ctrl_query_parse_bytes(&pr, &on_off, 1)))
        {
            log_info("ctrl: log query: %hhu", on_off & 1);
            
            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac.allow_control)))
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

                mesg->send_length = mesg->received;
            }
            else
            {
                log_err("ctrl: log query enable: rejected by ACL");

                message_make_error(mesg, RCODE_REFUSED);
            }
        }
    }
    else
    {
        message_make_error(mesg, RCODE_FORMERR);
    }
}

static void
ctrl_query_log_level(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    
    packet_reader_init(&pr, mesg->buffer, mesg->received);
    packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = ntohs(MESSAGE_QD(mesg->buffer));
    u16 pc = ntohs(MESSAGE_AN(mesg->buffer));
    u16 an = ntohs(MESSAGE_NS(mesg->buffer));
    
    if(FAIL(return_code) && (qc == 1) && (pc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_SRVLOGLEVEL) && (cmd_class == CLASS_CTRL))
    {        
        u8 level = 0;
        
        if(ISOK(return_code = ctrl_query_parse_bytes(&pr, &level, 1)))
        {
            log_info("ctrl: log level: %hhu", level);
            
            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac.allow_control)))
            {
                logger_set_level(level);

                mesg->send_length = mesg->received;
            }
            else
            {
                log_err("ctrl: log level: rejected by ACL");

                message_make_error(mesg, RCODE_REFUSED);
            }
        }
    }
    else
    {
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
 * Freeze ALL zones (that are controllable by the current sender)
 * 
 * The proper way to handle all zones from an external command is to try them one by one
 * (because of the ACL)
 * 
 * @param mesg
 */

static u16
ctrl_query_zone_freeze_all(message_data *mesg)
{
    u32 success = 0;
    u32 error = 0;
    
    zone_set_lock(&database_zone_desc);
    
    mesg->send_length = mesg->received;
    
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&database_zone_desc.set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->data;

        if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
        {
            ya_result return_value;

            if(ISOK(return_value = ctrl_zone_freeze(zone_desc, FALSE)))
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
    
    zone_set_unlock(&database_zone_desc);
    
    if(success > 0)
    {
        // part was ok
        return RCODE_NOERROR;
    }
    else if(error > 0)
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

static void
ctrl_query_zone_freeze(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    u16 rclass;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    char view[32];
    
    packet_reader_init(&pr, mesg->buffer, mesg->received);
    packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = ntohs(MESSAGE_QD(mesg->buffer));
    u16 pc = ntohs(MESSAGE_AN(mesg->buffer));
    u16 an = ntohs(MESSAGE_NS(mesg->buffer));
    
    u16 tmp_status = RCODE_FORMERR;
    
    if(ISOK(return_code) && (qc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_ZONEFREEZE) && (cmd_class == CLASS_CTRL))
    {
        if(pc == 1)
        {
            if(ISOK(return_code = ctrl_query_parse_fqdn_class_view(&pr, fqdn, sizeof(fqdn), &rclass, view, sizeof(view))))
            {
                log_info("ctrl: zone freeze: '%{dnsname}' %{dnsclass}", fqdn, &rclass);
                
                zone_desc_s* zone_desc = zone_acquirebydnsname(fqdn);
                tmp_status = RCODE_REFUSED;

                if((zone_desc != NULL) && (rclass == zone_desc->qclass) && (view[0] == '\0'))
                {
                    tmp_status = RCODE_NOTAUTH;

                    if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
                    {
                        ya_result return_value;

                        if(ISOK(return_value = ctrl_zone_freeze(zone_desc, TRUE)))
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
                        log_err("ctrl: zone freeze: rejected by ACL");
                    }

                    zone_release(zone_desc);
                }
                else
                {
                    log_err("ctrl: zone freeze: zone '%{dnsname}' %{dnsclass} not found", fqdn, &rclass);
                }
            }
        }
        else if(pc == 0)
        {
            tmp_status = ctrl_query_zone_freeze_all(mesg);
        }
    }
    
    if(tmp_status != RCODE_NOERROR)
    {
        message_make_error(mesg, tmp_status);
    }
}

/**
 * 
 * Unfreeze ALL zones (that are controllable by the current sender)
 * 
 * The proper way to handle all zones from an external command is to try them one by one
 * (because of the ACL)
 * 
 * @param mesg
 */

static u16
ctrl_query_zone_unfreeze_all(message_data *mesg)
{
    u32 success = 0;
    u32 error = 0;
    
    zone_set_lock(&database_zone_desc);
    
    mesg->send_length = mesg->received;
    
    treeset_avl_iterator iter;
    treeset_avl_iterator_init(&database_zone_desc.set, &iter);

    while(treeset_avl_iterator_hasnext(&iter))
    {
        treeset_node *zone_node = treeset_avl_iterator_next_node(&iter);
        zone_desc_s *zone_desc = (zone_desc_s *)zone_node->data;

        if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
        {
            ya_result return_value;

            if(ISOK(return_value = ctrl_zone_unfreeze(zone_desc, FALSE)))
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
    
    zone_set_unlock(&database_zone_desc);
    
    if(success > 0)
    {
        // part was ok
        return RCODE_NOERROR;
    }
    else if(error > 0)
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
 * Unfreeze ONE zone
 * 
 * @param mesg
 */

static void
ctrl_query_zone_unfreeze(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    u16 rclass;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    char view[32];
    
    packet_reader_init(&pr, mesg->buffer, mesg->received);
    packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = ntohs(MESSAGE_QD(mesg->buffer));
    u16 pc = ntohs(MESSAGE_AN(mesg->buffer));
    u16 an = ntohs(MESSAGE_NS(mesg->buffer));
    
    u16 tmp_status = RCODE_FORMERR;
    
    if(ISOK(return_code) && (qc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_ZONEUNFREEZE) && (cmd_class == CLASS_CTRL))
    {
        if(pc == 1)
        {
            if(ISOK(return_code = ctrl_query_parse_fqdn_class_view(&pr, fqdn, sizeof(fqdn), &rclass, view, sizeof(view))))
            {
                log_info("ctrl: zone unfreeze: '%{dnsname}' %{dnsclass}", fqdn, &rclass);
                
                zone_desc_s* zone_desc = zone_acquirebydnsname(fqdn);
                tmp_status = RCODE_REFUSED;

                if((zone_desc != NULL) && (rclass == zone_desc->qclass) && (view[0] == '\0'))
                {
                    tmp_status = RCODE_NOTAUTH;

                    if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
                    {
                        ya_result return_value;
                        
                        tmp_status = RCODE_SERVFAIL;

                        if(ISOK(return_value = ctrl_zone_unfreeze(zone_desc, TRUE)))
                        {
                            tmp_status = RCODE_NOERROR;
                            mesg->send_length = mesg->received;
                        }
                        else
                        {
                            tmp_status = return_value & 0x1f;
                        }
                    }
                    else
                    {
                        log_err("ctrl: zone unfreeze: rejected by ACL");
                    }

                    zone_release(zone_desc);
                }
                else
                {
                    log_err("ctrl: zone unfreeze: zone '%{dnsname}' %{dnsclass} not found", fqdn, &rclass);
                }
                
            }
        }
        else if(pc == 0)
        {
            tmp_status = ctrl_query_zone_unfreeze_all(mesg);
        }
    }
    
    if(tmp_status != RCODE_NOERROR)
    {
        message_make_error(mesg, tmp_status);
    }
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
    
    packet_reader_init(&pr, mesg->buffer, mesg->received);
    packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = ntohs(MESSAGE_QD(mesg->buffer));
    u16 pc = ntohs(MESSAGE_AN(mesg->buffer));
    u16 an = ntohs(MESSAGE_NS(mesg->buffer));
    
    u16 tmp_status = RCODE_FORMERR;
    
    if(ISOK(return_code) && (qc == 1) && (pc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_ZONESYNC) && (cmd_class == CLASS_CTRL))
    {
        u8 clean;
        
        if(ISOK(return_code = ctrl_query_parse_bytes(&pr, &clean, 1)))
        {
            if(ISOK(return_code = ctrl_query_parse_fqdn_class_view(&pr, fqdn, sizeof(fqdn), &rclass, view, sizeof(view))))
            {
                log_info("ctrl: zone sync: clean=%hhu '%{dnsname}' %{dnsclass}", clean & 1, fqdn, &rclass);
                
                zone_desc_s* zone_desc = zone_acquirebydnsname(fqdn);
                tmp_status = RCODE_REFUSED;

                if((zone_desc != NULL) && (rclass == zone_desc->qclass) && (view[0] == '\0'))
                {
                    tmp_status = RCODE_NOTAUTH;

                    if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
                    {
                        if((clean & 1) != 0)
                        {
                            log_warn("ctrl: zone sync: clean feature not supported yet");
                        }
                        
                        database_zone_save(fqdn);
                        
                        tmp_status = RCODE_NOERROR;
                        mesg->send_length = mesg->received;
                    }
                    else
                    {
                        log_err("ctrl: zone sync: rejected by ACL");
                    }

                    zone_release(zone_desc);
                }
                else
                {
                    log_err("ctrl: zone sync: zone '%{dnsname}' %{dnsclass} not found", fqdn, &rclass);
                }
            }
        }
    }
    
    if(tmp_status != RCODE_NOERROR)
    {
        message_make_error(mesg, tmp_status);
    }
}

static void
ctrl_query_zonenotify(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    u16 rclass;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    char view[32];
    
    packet_reader_init(&pr, mesg->buffer, mesg->received);
    packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = ntohs(MESSAGE_QD(mesg->buffer));
    u16 pc = ntohs(MESSAGE_AN(mesg->buffer));
    u16 an = ntohs(MESSAGE_NS(mesg->buffer));
    
    u16 tmp_status = RCODE_FORMERR;
    
    if(ISOK(return_code) && (qc == 1) && (pc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_ZONENOTIFY) && (cmd_class == CLASS_CTRL))
    {
        if(ISOK(return_code = ctrl_query_parse_fqdn_class_view(&pr, fqdn, sizeof(fqdn), &rclass, view, sizeof(view))))
        {
            log_info("ctrl: zone notify: '%{dnsname}' %{dnsclass}", fqdn, &rclass);
            
            zone_desc_s *zone_desc = zone_acquirebydnsname(fqdn);
            tmp_status = RCODE_REFUSED;

            if((zone_desc != NULL) && (rclass == zone_desc->qclass) && (view[0] == '\0'))
            {
                tmp_status = RCODE_NOTAUTH;

                if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
                {
                    notify_slaves(fqdn);
                    
                    tmp_status = RCODE_NOERROR;
                    mesg->send_length = mesg->received;
                }
                else
                {
                    log_err("ctrl: zone notify: rejected by ACL");
                }

                zone_release(zone_desc);
            }
        }
        else
        {
            log_err("ctrl: zone notify: zone '%{dnsname}' %{dnsclass} not found", fqdn, &rclass);
        }
    }

    if(tmp_status != RCODE_NOERROR)
    {
        message_make_error(mesg, tmp_status);
    }
}

static void
ctrl_query_zonereload(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    u16 rclass;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    char view[32];
    
    packet_reader_init(&pr, mesg->buffer, mesg->received);
    packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = ntohs(MESSAGE_QD(mesg->buffer));
    u16 pc = ntohs(MESSAGE_AN(mesg->buffer));
    u16 an = ntohs(MESSAGE_NS(mesg->buffer));
    
    u16 tmp_status = RCODE_FORMERR;
    
    if(ISOK(return_code) && (qc == 1) && (pc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_ZONERELOAD) && (cmd_class == CLASS_CTRL))
    {
        if(ISOK(return_code = ctrl_query_parse_fqdn_class_view(&pr, fqdn, sizeof(fqdn), &rclass, view, sizeof(view))))
        {
            log_info("ctrl: zone reload: '%{dnsname}' %{dnsclass}", fqdn, &rclass);
            
            zone_desc_s *zone_desc = zone_acquirebydnsname(fqdn);
            tmp_status = RCODE_REFUSED;

            if((zone_desc != NULL) && (rclass == zone_desc->qclass) && (view[0] == '\0'))
            {
                tmp_status = RCODE_NOTAUTH;

                if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
                {
                    database_zone_load(fqdn);
                    
                    tmp_status = RCODE_NOERROR;
                    mesg->send_length = mesg->received;
                }
                else
                {
                    log_err("ctrl: zone reload: rejected by ACL");
                }

                zone_release(zone_desc);
            }
        }
        else
        {
            log_err("ctrl: zone reload: zone '%{dnsname}' %{dnsclass} not found", fqdn, &rclass);
        }
    }

    if(tmp_status != RCODE_NOERROR)
    {
        message_make_error(mesg, tmp_status);
    }
}

static void
ctrl_query_zonecfgreload(message_data *mesg)
{
    packet_unpack_reader_data pr;
    u16 cmd_type;
    u16 cmd_class;
    u16 rclass;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    char view[32];
    
    packet_reader_init(&pr, mesg->buffer, mesg->received);
    packet_reader_skip(&pr, DNS_HEADER_LENGTH);
    packet_reader_skip_fqdn(&pr);
    packet_reader_read_u16(&pr, &cmd_type);
    
    ya_result return_code = packet_reader_read_u16(&pr, &cmd_class);
    
    u16 qc = ntohs(MESSAGE_QD(mesg->buffer));
    u16 pc = ntohs(MESSAGE_AN(mesg->buffer));
    u16 an = ntohs(MESSAGE_NS(mesg->buffer));
    
    u16 tmp_status = RCODE_FORMERR;
    
    if(ISOK(return_code) && (qc == 1) && (an == 0) && (cmd_type == TYPE_CTRL_ZONECFGRELOAD) && (cmd_class == CLASS_CTRL))
    {
        if(pc == 1)
        {
            if(ISOK(return_code = ctrl_query_parse_fqdn_class_view(&pr, fqdn, sizeof(fqdn), &rclass, view, sizeof(view))))
            {
                log_info("ctrl: zone config reload: '%{dnsname}' %{dnsclass}", fqdn, &rclass);

                zone_desc_s *zone_desc = zone_acquirebydnsname(fqdn);
                tmp_status = RCODE_REFUSED;

                if((zone_desc != NULL) && (rclass == zone_desc->qclass) && (view[0] == '\0'))
                {
                    tmp_status = RCODE_NOTAUTH;

                    if(!ACL_REJECTED(acl_check_access_filter(mesg, &zone_desc->ac.allow_control)))
                    {
                        tmp_status = RCODE_SERVFAIL;

                        ya_result return_code = yadifad_config_update_zone(g_config->config_file, fqdn);

                        if(ISOK(return_code))
                        {
                            tmp_status = RCODE_NOERROR;
                            mesg->send_length = mesg->received;
                            zone_release(zone_desc);

                            return;
                        }
                    }
                    else
                    {
                        log_err("ctrl: zone config reload: rejected by ACL");
                    }

                    zone_release(zone_desc);
                }
            }
            else
            {
                log_err("ctrl: zone config reload: zone '%{dnsname}' %{dnsclass} not found", fqdn, &rclass);
            }
        }
        else if(pc == 0)
        {
            tmp_status = RCODE_NOTAUTH;

            if(!ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac.allow_control)))
            {
                tmp_status = RCODE_SERVFAIL;
                
                ya_result return_code = yadifad_config_update_zone(g_config->config_file, NULL);

                if(ISOK(return_code))
                {
                    tmp_status = RCODE_NOERROR;
                    return;
                }
            }
        }
    }

    if(tmp_status != RCODE_NOERROR)
    {
        message_make_error(mesg, tmp_status);
    }
}



void
ctrl_query_process(message_data *mesg)
{
    log_info("CTRL (%04hx) %{dnsname} %{dnstype}", ntohs(MESSAGE_ID(mesg->buffer)), mesg->qname, &mesg->qtype);

    if(!ctrl_get_enabled())
    {
        message_make_error(mesg, RCODE_REFUSED);
        
#if HAS_TSIG_SUPPORT
        if(TSIG_ENABLED(mesg))  /* NOTE: the TSIG information is in mesg */
        {
            tsig_sign_answer(mesg);
        }
#endif
        return;
    }
    
    if(mesg->qname[0] != '\0')
    {
        message_make_error(mesg, RCODE_FORMERR);
        
#if HAS_TSIG_SUPPORT
        if(TSIG_ENABLED(mesg))  /* NOTE: the TSIG information is in mesg */
        {
            tsig_sign_answer(mesg);
        }
#endif
        return;
    }
    
    MESSAGE_HIFLAGS(mesg->buffer) |= QR_BITS;
    mesg->status = RCODE_NOERROR;
    mesg->send_length = mesg->received;

    // now can read the command
    
    switch(mesg->qtype)
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
            ctrl_query_zonenotify(mesg);
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
    
#if HAS_TSIG_SUPPORT
    if(TSIG_ENABLED(mesg))  /* NOTE: the TSIG information is in mesg */
    {
        tsig_sign_answer(mesg);
    }
#endif
}



#endif // HAS_CTRL

/** @} */
