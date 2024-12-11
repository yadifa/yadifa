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

#include <dnscore/format.h>
#include <dnscore/dns_packet_writer.h>
#include <dnscore/dns_packet_reader.h>

#include <dnsdb/zdb_zone.h>
#include <dnsdb/zdb_zone_find.h>

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "confs.h"
#include "signals.h"
#include <dnscore/acl.h>

#include "database_service.h"
#include "notify.h"
#if HAS_RRSIG_MANAGEMENT_SUPPORT && ZDB_HAS_DNSSEC_SUPPORT
#include "database_service_zone_resignature.h"
#endif

#ifdef HAS_CTRL
extern logger_handle_t *g_server_logger;

extern zone_data_set    database_zone_desc;

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING
extern zone_data_set database_dynamic_zone_desc;

static int32_t       config_clamp_s32(int32_t minval, int32_t maxval, int32_t val, const char *name)
{
    int32_t oldval = val;

    if(val < minval)
    {
        val = minval;
    }
    else if(val > maxval)
    {
        val = maxval;
    }

    if(val != oldval)
    {
        log_debug("%s = %d out of bounds [%d;%d], set to %d", name, oldval, minval, maxval, val);
    }

    return val;
}

#endif

ya_result ctrl_zone_freeze(zone_desc_t *zone_desc, bool dolock)
{
    ya_result ret;

    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }

    ret = MAKE_RCODE_ERROR(RCODE_SERVFAIL);

    if(zdb_zone_exists_from_dnsname(g_config->database, zone_origin(zone_desc)))
    {
        ret = SUCCESS;

#if DEBUG
        log_debug("ctrl: zone freeze for %{dnsname}", zone_origin(zone_desc));
#endif

        database_zone_freeze(zone_origin(zone_desc));
    }

    /* add the zone to the database */

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }

    return ret;
}

ya_result ctrl_zone_unfreeze(zone_desc_t *zone_desc, bool dolock)
{
    ya_result ret;

    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }

    ret = MAKE_RCODE_ERROR(RCODE_SERVFAIL);

    if(zdb_zone_exists_from_dnsname(g_config->database, zone_origin(zone_desc)))
    {
        ret = SUCCESS;

#if DEBUG
        log_debug("ctrl: zone unfreeze for %{dnsname}", zone_origin(zone_desc));
#endif

        database_zone_unfreeze(zone_origin(zone_desc));
    }

    /* add the zone to the database */

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }

    return ret;
}

ya_result ctrl_zone_refresh(zone_desc_t *zone_desc, bool dolock)
{
    ya_result ret;

    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }

    ret = MAKE_RCODE_ERROR(RCODE_SERVFAIL);

    if(zdb_zone_exists_from_dnsname(g_config->database, zone_origin(zone_desc)))
    {
        ret = SUCCESS;

#if DEBUG
        log_debug("ctrl: zone maintenance for %{dnsname}", zone_origin(zone_desc));
#endif
        // not this call, this causes a refresh
#if ZDB_HAS_PRIMARY_SUPPORT && ZDB_HAS_RRSIG_MANAGEMENT_SUPPORT
        if(zone_is_primary(zone_desc))
        {
            database_service_zone_dnssec_maintenance(zone_desc);
        }
#endif
    }

    /* add the zone to the database */

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }

    return ret;
}

ya_result ctrl_zone_sync(zone_desc_t *zone_desc, bool dolock, bool clear_journal)
{
    ya_result ret;
    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }

    ret = MAKE_RCODE_ERROR(RCODE_SERVFAIL);

    if(zdb_zone_exists_from_dnsname(g_config->database, zone_origin(zone_desc)))
    {
        if(zone_desc->loaded_zone != NULL)
        {
            ret = SUCCESS;
            database_zone_store_ex(zone_origin(zone_desc), clear_journal);
        }
        else
        {
            ret = MAKE_RCODE_ERROR(RCODE_SERVFAIL);
        }
    }

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }

    return ret;
}

ya_result ctrl_zone_sync_doclean(zone_desc_t *zone_desc, bool dolock)
{
    ya_result ret = ctrl_zone_sync(zone_desc, dolock, true);
    return ret;
}

ya_result ctrl_zone_sync_noclean(zone_desc_t *zone_desc, bool dolock)
{
    ya_result ret = ctrl_zone_sync(zone_desc, dolock, false);
    return ret;
}

ya_result ctrl_zone_notify(zone_desc_t *zone_desc, bool dolock)
{
    ya_result ret;
    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }

    ret = MAKE_RCODE_ERROR(RCODE_REFUSED);

    if(zdb_zone_exists_from_dnsname(g_config->database, zone_origin(zone_desc)))
    {
        if(zone_desc->loaded_zone != NULL)
        {
            ret = SUCCESS;
            notify_secondaries(zone_origin(zone_desc));
        }
        else
        {
            ret = MAKE_RCODE_ERROR(RCODE_SERVFAIL);
        }
    }

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }

    return ret;
}

ya_result ctrl_zone_reload(zone_desc_t *zone_desc, bool dolock)
{
    ya_result ret;
    if(dolock)
    {
        zone_set_lock(&database_zone_desc);
    }

    ret = MAKE_RCODE_ERROR(RCODE_SERVFAIL);

    if(zdb_zone_exists_from_dnsname(g_config->database, zone_origin(zone_desc)))
    {
        ret = SUCCESS;
        database_zone_load(zone_origin(zone_desc));
    }

    if(dolock)
    {
        zone_set_unlock(&database_zone_desc);
    }

    return ret;
}

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING

ya_result ctrl_zone_setup_from_message(zone_desc_s *zone_desc, dns_message_t *mesg)
{
    ya_result return_value;
    uint16_t  rtype = 0;
    uint16_t  rclass = 0;
    uint32_t  rttl = 0;
    uint16_t  rdatasize = 0;
    uint16_t  tc;
    uint8_t   ztype;

    switch(message_get_opcode(mesg))
    {
        case OPCODE_QUERY:
            ztype = ZT_SECONDARY;
            break;
        case OPCODE_UPDATE:
            ztype = ZT_PRIMARY;
            break;
        default:
            return ERROR; // dynamic provisioning
    }

    dns_packet_reader_t reader;

    dns_packet_reader_init_from_message_at(&reader, mesg, DNS_HEADER_LENGTH);

    dns_packet_reader_skip_fqdn(&reader);

    if(FAIL(return_value = dns_packet_reader_read_u16(&reader, &tc)) /* || (tc != TYPE_SOA)*/)
    {
        message_set_status(mesg, RCODE_FORMERR);

        return ERROR; // dynamic provisioning
    }

    if(FAIL(return_value = dns_packet_reader_read_u16(&reader, &tc)) || (tc != CLASS_CTRL))
    {
        message_set_status(mesg, RCODE_FORMERR);

        return ERROR; // dynamic provisioning
    }

    int32_t  origin_len = dnsname_len(message_get_canonised_fqdn(mesg));

    bool     dryrun = true;

    uint16_t section_start = reader.offset;

    for(;;)
    {
        reader.offset = section_start;

        uint16_t count;

        switch(message_get_opcode(mesg))
        {
            case OPCODE_QUERY:
                count = message_get_answer_count(mesg);
                break;
            case OPCODE_UPDATE:
                count = message_get_update_count(mesg);
                break;
            default:
                count = 0;
                break;
        }

        while(ISOK(return_value) && (count-- > 0))
        {
            uint8_t fqdn[DOMAIN_LENGTH_MAX];

            if(FAIL(return_value = dns_packet_reader_read_fqdn(&reader, fqdn, sizeof(fqdn))))
            {
                break;
            }

            if((return_value != origin_len) || !dnslabel_equals_ignorecase_left(&fqdn[return_value - origin_len], message_get_canonised_fqdn(mesg)))
            {
                return_value = ERROR;
                break;
            }

            dns_packet_reader_read_u16(&reader, &rtype);
            dns_packet_reader_read_u16(&reader, &rclass);
            dns_packet_reader_read_u32(&reader, &rttl);
            dns_packet_reader_read_u16(&reader, &rdatasize);
            rdatasize = htons(rdatasize);

            log_debug("ctrl: zone: %{dnsname} %{dnstype} type=%hhu", message_get_canonised_fqdn(mesg), &rtype, ztype);

            switch(rtype)
            {
                case TYPE_ZONE_TYPE:
                {
                    return_value = ERROR;

                    if(rdatasize == 1)
                    {
                        uint8_t zt;

                        if(ISOK(return_value = dns_packet_reader_read(&reader, &zt, 1)))
                        {
                            return_value = ERROR;

                            if(zt <= ZT_STUB)
                            {
                                if(!dryrun)
                                {
                                    log_info("ctrl: zone: %{dnsname} type=%hhu", message_get_canonised_fqdn(mesg), zt);

                                    zone_desc->type = (zone_type)zt;
                                }

                                return_value = SUCCESS;
                            }
                        }
                    }

                    break;
                }
                case TYPE_ZONE_FILE:
                {
                    return_value = dns_packet_reader_read_utf8(&reader, rdatasize, rclass, &zone_desc->file_name, dryrun); /* defined in process_class_ctrl.c */
                    if(!dryrun && ISOK(return_value))
                    {
                        log_info("ctrl: zone: %{dnsname} file=%s", message_get_canonised_fqdn(mesg), zone_desc->file_name);

                        zone_desc->dynamic_provisioning.flags &= ~ZONE_CTRL_FLAG_GENERATE_ZONE;
                    }
                    break;
                }
                case TYPE_ZONE_NOTIFY:
                {
                    return_value = dns_packet_reader_read_remote_server(&reader, rdatasize, rclass, &zone_desc->notifies, dryrun); /* defined in process_class_ctrl.c */

                    if(ISOK(return_value))
                    {
                        log_info("ctrl: zone: %{dnsname} also-notify=%{hostaddrlist}", message_get_canonised_fqdn(mesg), zone_desc->notifies);
                    }

                    break;
                }
                case TYPE_ZONE_PRIMARY:
                {
                    return_value = dns_packet_reader_read_remote_server(&reader, rdatasize, rclass, &zone_desc->primaries, dryrun); /* defined in process_class_ctrl.c */

                    if(ISOK(return_value))
                    {
                        log_info("ctrl: zone: %{dnsname} primaries=%{hostaddrlist}", message_get_canonised_fqdn(mesg), zone_desc->primaries);
                    }

                    break;
                }
                case TYPE_ZONE_SECONDARIES:
                {
                    return_value = dns_packet_reader_read_remote_server(&reader, rdatasize, rclass, &zone_desc->secondaries, dryrun); /* defined in process_class_ctrl.c */

                    if(ISOK(return_value))
                    {
                        log_info("ctrl: zone: %{dnsname} secondaries=%{hostaddrlist}", message_get_canonised_fqdn(mesg), zone_desc->secondaries);
                    }

                    break;
                }
                case TYPE_ZONE_DNSSEC:
                {
                    return_value = ERROR;

                    if(rdatasize == 1)
                    {
                        uint8_t zd;

                        if(ISOK(return_value = dns_packet_reader_read(&reader, &zd, 1)))
                        {
                            return_value = ERROR;

                            if(zd <= ZONE_DNSSEC_FL_NSEC3_OPTOUT)
                            {
                                if(!dryrun)
                                {
                                    log_info("ctrl: zone: %{dnsname} dnssec=%hhu", message_get_canonised_fqdn(mesg), zd);

                                    zone_desc->dnssec_mode = (zone_type)zd;
                                }

                                return_value = SUCCESS;
                            }
                        }
                    }

                    break;
                }
                case TYPE_SIGINTV:
                {
                    return_value = ERROR;

                    if(rdatasize == 4)
                    {
                        uint32_t value;

                        if(ISOK(return_value = dns_packet_reader_read_u32(&reader, &value)))
                        {
                            if(!dryrun)
                            {
                                zone_desc->signature.sig_validity_interval = ntohl(value);
                                log_info("ctrl: zone: %{dnsname} sig-validity-interval=%u", message_get_canonised_fqdn(mesg), zone_desc->signature.sig_validity_interval);
                            }
                        }
                    }
                    break;
                }
                case TYPE_SIGREGN:
                {
                    return_value = ERROR;

                    if(rdatasize == 4)
                    {
                        uint32_t value;

                        if(ISOK(return_value = dns_packet_reader_read_u32(&reader, &value)))
                        {
                            if(!dryrun)
                            {
                                zone_desc->signature.sig_validity_regeneration = ntohl(value);
                                log_info("ctrl: zone: %{dnsname} sig-validity-regeneration=%u", message_get_canonised_fqdn(mesg), zone_desc->signature.sig_validity_regeneration);
                            }
                        }
                    }
                    break;
                }
                case TYPE_SIGJITR:
                {
                    return_value = ERROR;

                    if(rdatasize == 4)
                    {
                        uint32_t value;

                        if(ISOK(return_value = dns_packet_reader_read_u32(&reader, &value)))
                        {
                            if(!dryrun)
                            {
                                zone_desc->signature.sig_validity_jitter = ntohl(value);
                                log_info("ctrl: zone: %{dnsname} sig-validity-jitter=%u", message_get_canonised_fqdn(mesg), zone_desc->signature.sig_validity_jitter);
                            }
                        }
                    }
                    break;
                }
                case TYPE_NTFRC:
                {
                    return_value = ERROR;

                    if(rdatasize == 4)
                    {
                        uint32_t value;

                        if(ISOK(return_value = dns_packet_reader_read_u32(&reader, &value)))
                        {
                            if(!dryrun)
                            {
                                zone_desc->notify.retry_count = ntohl(value);
                                log_info("ctrl: zone: %{dnsname} notify-retry-count=%u", message_get_canonised_fqdn(mesg), zone_desc->notify.retry_count);
                            }
                        }
                    }
                    break;
                }
                case TYPE_NTFRP:
                {
                    return_value = ERROR;

                    if(rdatasize == 4)
                    {
                        uint32_t value;

                        if(ISOK(return_value = dns_packet_reader_read_u32(&reader, &value)))
                        {
                            if(!dryrun)
                            {
                                zone_desc->notify.retry_period = ntohl(value);
                                log_info("ctrl: zone: %{dnsname} notify-retry-period=%u", message_get_canonised_fqdn(mesg), zone_desc->notify.retry_period);
                            }
                        }
                    }
                    break;
                }
                case TYPE_NTFRPI:
                {
                    return_value = ERROR;

                    if(rdatasize == 4)
                    {
                        uint32_t value;

                        if(ISOK(return_value = dns_packet_reader_read_u32(&reader, &value)))
                        {
                            if(!dryrun)
                            {
                                zone_desc->notify.retry_period_increase = ntohl(value);
                                log_info("ctrl: zone: %{dnsname} notify-retry-period-increase=%u", message_get_canonised_fqdn(mesg), zone_desc->notify.retry_period_increase);
                            }
                        }
                    }
                    break;
                }
                case TYPE_NTFAUTO:
                {
                    return_value = ERROR;

                    if(rdatasize == 1)
                    {
                        uint8_t value;

                        if(ISOK(return_value = dns_packet_reader_read(&reader, &value, 1)))
                        {
                            if(!dryrun)
                            {
                                zone_auto_notify_set(zone_desc, (value != 0));
                                log_info("ctrl: zone: %{dnsname} notify-flags=%u", message_get_canonised_fqdn(mesg), zone_is_auto_notify(zone_desc));
                            }
                        }
                    }
                    break;
                }
                case TYPE_SOA:
                {
                    uint16_t two_empty_fqdn;
                    if(FAIL(return_value = dns_packet_reader_read_u16(&reader, &two_empty_fqdn))) /* covers mname and rname */
                    {
                        break;
                    }
                    if(two_empty_fqdn != 0)
                    {
                        return_value = ERROR;
                        break;
                    }

                    uint32_t timestamp;
                    uint32_t refresh;
                    uint32_t retry;
                    uint32_t expire;
                    uint32_t should_be_zero;

                    dns_packet_reader_read_u32(&reader, &timestamp);

                    if(zone_desc->dynamic_provisioning.timestamp > timestamp)
                    {
                        /* the serial is bigger : this is wrong */

                        log_err("CTRL (%04hx) %{dnsname} SOA serial smaller or equal than current one %d < %d", ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), timestamp, zone_desc->dynamic_provisioning.timestamp);
                        return_value = ERROR;
                        break;
                    }

                    dns_packet_reader_read_u32(&reader, &refresh);
                    dns_packet_reader_read_u32(&reader, &retry);
                    dns_packet_reader_read_u32(&reader, &expire);

                    if(FAIL(return_value = dns_packet_reader_read_u32(&reader, &should_be_zero)))
                    {
                        break;
                    }

                    if(should_be_zero != 0)
                    {
                        log_warn("CTRL (%04hx) %{dnsname} SOA last field not 0", ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), &rtype, return_value);
                    }

                    if(!dryrun)
                    {
                        zone_desc->dynamic_provisioning.timestamp = ntohl(timestamp);
                        zone_desc->dynamic_provisioning.refresh = ntohl(refresh);
                        zone_desc->dynamic_provisioning.retry = ntohl(retry);
                        zone_desc->dynamic_provisioning.expire = ntohl(expire);

                        log_info("ctrl: zone: %{dnsname} dynamic-provisioning-timestamp=%u", message_get_canonised_fqdn(mesg), zone_desc->dynamic_provisioning.timestamp);
                        log_info("ctrl: zone: %{dnsname} dynamic-provisioning-refresh=%u", message_get_canonised_fqdn(mesg), zone_desc->dynamic_provisioning.refresh);
                        log_info("ctrl: zone: %{dnsname} dynamic-provisioning-retry=%u", message_get_canonised_fqdn(mesg), zone_desc->dynamic_provisioning.retry);
                        log_info("ctrl: zone: %{dnsname} dynamic-provisioning-expire=%u", message_get_canonised_fqdn(mesg), zone_desc->dynamic_provisioning.expire);
                    }

                    break;
                }
                default:
                {
                    log_err("CTRL (%04hx) %{dnsname} unsupported type %{dnstype}", ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), &rtype, return_value);
                    return_value = ERROR;
                    break;
                }
            } // switch
        } // while isok & count

        if(FAIL(return_value))
        {
            log_err("CTRL (%04hx) %{dnsname} %{dnstype}, last type read is %{dnstype} : %r", ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), &rtype, return_value);

            break;
        }

        if(!dryrun)
        {
            break;
        }

        dryrun = false;
    }

    zone_desc->signature.sig_validity_interval = config_clamp_s32(SIGNATURE_VALIDITY_INTERVAL_MIN, SIGNATURE_VALIDITY_INTERVAL_MAX, zone_desc->signature.sig_validity_interval, "sig-validity-interval");
    zone_desc->signature.sig_validity_regeneration = config_clamp_s32(SIGNATURE_VALIDITY_REGENERATION_MIN, SIGNATURE_VALIDITY_REGENERATION_MAX, zone_desc->signature.sig_validity_regeneration, "sig-validity-regeneration");
    zone_desc->signature.sig_validity_jitter = config_clamp_s32(SIGNATURE_VALIDITY_JITTER_MIN, SIGNATURE_VALIDITY_JITTER_MAX, zone_desc->signature.sig_validity_jitter, "sig-validity-jitter");
    zone_desc->notify.retry_count = config_clamp_s32(NOTIFY_RETRY_COUNT_MIN, NOTIFY_RETRY_COUNT_MAX, zone_desc->notify.retry_count, "notify-retry-count");
    zone_desc->notify.retry_period = config_clamp_s32(NOTIFY_RETRY_PERIOD_MIN, NOTIFY_RETRY_PERIOD_MAX, zone_desc->notify.retry_period, "notify-period-count");
    zone_desc->notify.retry_period_increase = config_clamp_s32(NOTIFY_RETRY_PERIOD_INCREASE_MIN, NOTIFY_RETRY_PERIOD_INCREASE_MAX, zone_desc->notify.retry_period_increase, "notify-period-increase");

    if(ISOK(return_value))
    {
        if(ztype == ZT_SECONDARY)
        {
            /* assign the primary automatically if needs to be */

            if(zone_desc->primaries == NULL)
            {
                host_address *primary = host_address_alloc();
                if(ISOK(return_value = host_address_set_with_sockaddr(primary, message_get_sender(mesg))))
                {
                    primary->tsig = message_tsig_get_key(mesg);
                    zone_desc->primaries = primary;
                }
                else
                {
                    log_err("CTRL (%04hx) %{dnsname} %{dnstype} %{sockaddr}: unable to auto-assign primary: %r", ntohs(message_get_id(mesg)), message_get_canonised_fqdn(mesg), message_get_query_type_ptr(mesg), message_get_sender_sa(mesg));
                }
            }
        }
    }
    else
    {
        message_set_status(mesg, RCODE_FORMERR);
    }

    return return_value;
}

/**
 * Parses both dynamic update & axfr messages
 *
 * dynamic = PRIMARY (and it's a question)
 * axfr    = SECONDARY (and it's an answer)
 *
 *
 *
 * qname = domain to add (delete?)
 * class = CTRL
 * type  = SOA (none to delete, on a primary ?)
 *
 * @param mesg
 * @return
 */

ya_result ctrl_zone_generate_from_message(dns_message_t *mesg)
{
    ya_result return_value;
    uint8_t   ztype = 0;

    if(message_get_query_class(mesg) != CLASS_CTRL)
    {
        message_set_status(mesg, RCODE_FORMERR);
        return_value = MAKE_RCODE_ERROR(message_get_status(mesg));
        return return_value;
    }

    /* update & prerequisites = error */

    bool zone_add = true;

    if((message_get_opcode(mesg) == OPCODE_UPDATE) && ((message_get_query_type(mesg) == TYPE_SOA) || (message_get_query_type(mesg) == TYPE_NONE)))
    {
        if(message_get_prerequisite_count_ne(mesg) != 0)
        {
            message_set_status(mesg, RCODE_FORMERR);
            return_value = MAKE_RCODE_ERROR(message_get_status(mesg));
            return return_value;
        }

        ztype = ZT_PRIMARY;

        if(message_get_query_type(mesg) == TYPE_NONE)
        {
            zone_add = false;
        }
    }
    else if((message_get_opcode(mesg) == OPCODE_QUERY) && (message_get_query_type(mesg) == TYPE_AXFR))
    {
        ztype = ZT_SECONDARY;
    }
    else
    {
        message_set_status(mesg, RCODE_FORMERR);
        return_value = MAKE_RCODE_ERROR(message_get_status(mesg));
        return return_value;
    }

    if(zone_add)
    {
        log_debug("control: update: adding or updating zone %{dnsname}", message_get_canonised_fqdn(mesg));

        zone_desc_s *zone_desc = zone_acquiredynamicbydnsname(message_get_canonised_fqdn(mesg));

        if(zone_desc == NULL) // is a dynamic zone ?
        {
            zone_desc_s *zone_current_desc = zone_acquirebydnsname(message_get_canonised_fqdn(mesg));

            if(zone_current_desc == NULL)
            {
                char domain[DOMAIN_LENGTH_MAX];

                zone_desc = zone_alloc();

                zone_setdefaults(zone_desc);
                cstr_init_with_dnsname(domain, message_get_canonised_fqdn(mesg));
                zone_desc->domain = strdup(domain);

                if(ISOK(return_value = ctrl_zone_setup_from_message(zone_desc, mesg))) /* overwrites with the "primary" setup so ... */
                {
                    zone_desc->qclass = CLASS_IN;
                    zone_desc->type = ztype;
                    zone_origin(zone_desc) = dnsname_dup(message_get_canonised_fqdn(mesg));

                    zone_register(&database_dynamic_zone_desc, zone_desc);

                    zone_desc->dynamic_provisioning.flags = ZONE_CTRL_FLAG_EDITED;

                    log_info("control: update: created dynamic zone %{dnsname}", message_get_canonised_fqdn(mesg));
                }
                else
                {
                    log_err("control: update: dynamic zone creation %{dnsname} cancelled", message_get_canonised_fqdn(mesg));
                    zone_release(zone_desc);
                }
            }
            else
            {
                zone_desc = zone_clone(zone_current_desc);

                zone_release(zone_current_desc);

                if(ISOK(return_value = ctrl_zone_setup_from_message(zone_desc, mesg)))
                {
                    zone_register(&database_dynamic_zone_desc, zone_desc);

                    if((zone_desc->dynamic_provisioning.flags & ZONE_CTRL_FLAG_EDITED) == 0)
                    {
                        zone_desc->dynamic_provisioning.flags |= ZONE_CTRL_FLAG_CLONE | ZONE_CTRL_FLAG_EDITED;
                    }
                }
                else
                {
                    log_err("control: update: dynamic zone update %{dnsname} cancelled", message_get_canonised_fqdn(mesg));
                    zone_release(zone_desc);
                }
            }
        }
        else // update temporary config
        {
            zone_desc_s *new_zone_desc = zone_alloc();

            zone_setdefaults(new_zone_desc);
            new_zone_desc->domain = strdup(zone_domain(zone_desc));

            if(ISOK(return_value = ctrl_zone_setup_from_message(new_zone_desc, mesg))) /* overwrites with the "primary" setup so ... */
            {
                new_zone_desc->qclass = CLASS_IN;
                if(ztype != zone_desc->type)
                {
                    log_warn("control: update: zone type change not supported yet");
                }
                new_zone_desc->type = zone_desc->type;
                new_zone_origin(zone_desc) = dnsname_dup(message_get_canonised_fqdn(mesg));

                // merge

                zone_lock(zone_desc, ZONE_LOCK_LOAD_DESC);
                if(ISOK(zone_setwithzone(zone_desc, new_zone_desc)))
                {
                    zone_desc->dynamic_provisioning.flags |= ZONE_CTRL_FLAG_EDITED;
                }
                zone_unlock(zone_desc, ZONE_LOCK_LOAD_DESC);

                log_info("control: update: created dynamic zone %{dnsname}", message_get_canonised_fqdn(mesg));
            }
            else
            {
                log_err("control: update: dynamic zone update %{dnsname} cancelled", message_get_canonised_fqdn(mesg));
                zone_release(new_zone_desc);
            }

            zone_release(zone_desc);

            return return_value;
        }
    }
    else
    {
        log_debug("control: update: deleting zone %{dnsname}", message_get_canonised_fqdn(mesg));

        zone_desc_s *zone_desc = zone_acquiredynamicbydnsname(message_get_canonised_fqdn(mesg));

        if(zone_desc == NULL) // is a dynamic zone ?
        {
            // drop the zone from the DB
            // drop the zone descriptor

            return_value = SUCCESS;
        }
        else
        {
            log_warn("control: update: zone %{dnsname} is not dynamic", message_get_canonised_fqdn(mesg));

            zone_release(zone_desc);

            message_set_status(mesg, RCODE_SERVFAIL);
            return_value = MAKE_RCODE_ERROR(message_get_status(mesg));
            return return_value;
        }
    }

    return return_value;
}

/**
 *
 * @param zone_desc is a a zone from the dynamic tree that needs to be merged with the main tree (copy)
 * @param dolock
 * @return
 */

ya_result ctrl_zone_config_merge(zone_desc_s *zone_desc, bool dolock)
{
    if(dolock)
    {
        zone_set_lock(&database_dynamic_zone_desc);
    }

    zone_desc_s *zone_current_desc = zone_acquirebydnsname(zone_origin(zone_desc));

    if(zone_current_desc == NULL)
    {
        log_debug("ctrl: config merge: activating %{dnsname}", zone_origin(zone_desc));

        zone_desc_s *zone_new_desc = zone_alloc();
        zone_setwithzone(zone_new_desc, zone_desc);
        database_zone_desc_load(zone_new_desc);
    }
    else
    {
        log_debug("ctrl: config merge: updating %{dnsname}", zone_origin(zone_desc));

        zone_desc_s *zone_new_desc = zone_alloc();
        zone_setwithzone(zone_new_desc, zone_current_desc);
        if(zone_setwithzone(zone_new_desc, zone_desc) > 0)
        {
            // actually merged
            log_debug("ctrl: config merge: updated %{dnsname}", zone_origin(zone_desc));

            // database_load_zone_desc_unload(zone_current_desc->origin);
            database_zone_desc_load(zone_new_desc);
        }

        zone_release(zone_current_desc);
    }

    /* add the zone to the database */

    zone_desc->dynamic_provisioning.flags |= ZONE_CTRL_FLAG_CLONE;

    if(dolock)
    {
        zone_set_unlock(&database_dynamic_zone_desc);
    }

    return SUCCESS;
}

ya_result ctrl_zone_config_merge_all()
{
    zone_set_lock(&database_dynamic_zone_desc);

    ptr_treemap_iterator_t iter;
    ptr_treemap_iterator_init(&database_dynamic_zone_desc.set, &iter);

    while(ptr_treemap_iterator_hasnext(&iter))
    {
        ptr_treemap_node_t *zone_node = ptr_treemap_iterator_next_node(&iter);
        zone_desc_s        *zone_desc = (zone_desc_s *)zone_node->value;

        ctrl_zone_config_merge(zone_desc, false); // source from dynamic

        zone_node->value = NULL;
    }

    ptr_treemap_finalise(&database_dynamic_zone_desc.set);

    zone_set_unlock(&database_dynamic_zone_desc);

    return SUCCESS;
}

ya_result ctrl_zone_config_delete(zone_desc_s *zone_desc, bool dolock)
{
    if(dolock)
    {
        zone_set_lock(&database_dynamic_zone_desc);
    }

#if DEBUG
    log_debug("ctrl: config delete for %{dnsname}", zone_origin(zone_desc));
#endif

    database_zone_desc_unload(zone_origin(zone_desc));

    if(dolock)
    {
        zone_set_unlock(&database_dynamic_zone_desc);
    }

    return SUCCESS;
}

#endif // HAS_DYNAMIC_PROVISIONING
#endif

/** @} */
