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
 * @defgroup dnspacket DNS Messages
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"

#include <unistd.h>
#include <stddef.h>
#include <fcntl.h>

#include "dnscore/dns_message.h"
#include "dnscore/logger.h"
#include "dnscore/dnscore.h"
#include "dnscore/format.h"
#include "dnscore/fingerprint.h"
#include <dnscore/dns_packet_reader.h>
#include <dnscore/dns_packet_writer.h>
#include "dnscore/tsig.h"
#include "dnscore/fdtools.h"
#include "dnscore/tcp_io_stream.h"
#include "dnscore/counter_output_stream.h"
#include "dnscore/network.h"

#include "dnscore/thread_pool.h"

#if DNSCORE_HAS_CTRL
#include "dnscore/ctrl_rfc.h"
#endif

#include "dnscore/dns_message_opt.h"

/*------------------------------------------------------------------------------
 * GLOBAL VARIABLES */

extern logger_handle_t *g_system_logger;
#define MODULE_MSG_HANDLE g_system_logger

#ifndef DNSCORE_RFC_C
extern uint32_t edns0_record_size;
extern uint8_t *edns0_rdatasize_nsid_option_wire;
extern uint32_t edns0_rdatasize_nsid_option_wire_size;
#endif

#define SA_LOOP  3
#define SA_PRINT 4

/*------------------------------------------------------------------------------
 * FUNCTIONS */

uint16_t        edns0_maxsize = EDNS0_LENGTH_MAX;

double          g_message_data_minimum_troughput_default = 0;
static uint16_t g_dns_message_fudge = 300;

void            dns_message_fudge_set(uint16_t fudge) { g_dns_message_fudge = fudge; }

void            dns_message_set_minimum_troughput_default(double rate)
{
    if(rate >= 0)
    {
        g_message_data_minimum_troughput_default = rate;
    }
}

void               dns_message_edns0_setmaxsize(uint16_t maxsize) { edns0_maxsize = maxsize; }

uint16_t           dns_message_edns0_getmaxsize() { return edns0_maxsize; }

static inline void dns_message_cookie_set(dns_message_t *mesg) { mesg->_opt |= MESSAGE_OPT_COOKIE; }

static inline bool dns_message_cookie_size_valid(int cookie_size)
{
    return (cookie_size == DNS_MESSAGE_COOKIE_CLIENT_SIZE) || ((cookie_size >= (DNS_MESSAGE_COOKIE_CLIENT_SIZE + DNS_MESSAGE_COOKIE_SERVER_SIZE)) && (cookie_size <= (DNS_MESSAGE_COOKIE_CLIENT_SIZE + DNS_MESSAGE_COOKIE_SERVER_SIZE_MAX)));
}

// address fields

ya_result dns_message_set_sender_port(dns_message_t *mesg, uint16_t port)
{
    switch(mesg->_sender.sa.sa_family)
    {
        case AF_INET:
        {
            mesg->_sender.sa4.sin_port = port;
            return port;
        }
        case AF_INET6:
        {
            mesg->_sender.sa6.sin6_port = port;
            return port;
        }
        default:
        {
            return INVALID_STATE_ERROR;
        }
    }
}

uint8_t *dns_message_get_sender_address_ptr(dns_message_t *mesg)
{
    switch(mesg->_sender.sa.sa_family)
    {
        case AF_INET:
        {
            return (uint8_t *)&mesg->_sender.sa4.sin_addr;
        }
        case AF_INET6:
        {
            return (uint8_t *)&mesg->_sender.sa6.sin6_addr;
        }
        default:
        {
            return NULL;
        }
    }
}

uint32_t dns_message_get_sender_address_size(dns_message_t *mesg)
{
    switch(mesg->_sender.sa.sa_family)
    {
        case AF_INET:
        {
            return 4;
        }
        case AF_INET6:
        {
            return 16;
        }
        default:
        {
            return 0;
        }
    }
}

size_t dns_message_get_sender_sa_family_size(const dns_message_t *mesg)
{
    switch(mesg->_sender.sa.sa_family)
    {
        case AF_INET:
        {
            return sizeof(struct sockaddr_in);
        }
        case AF_INET6:
        {
            return sizeof(struct sockaddr_in6);
        }
        default:
        {
            return 0;
        }
    }
}

// Handles OPT and TSIG

static inline void message_process_adjust_buffer_size(dns_message_t *mesg, uint16_t edns0_size)
{
    uint32_t mesg_buffer_size = dns_message_get_buffer_size_max(mesg);
    uint32_t query_buffer_size = edns0_size;
    if(mesg_buffer_size > query_buffer_size)
    {
        mesg_buffer_size = query_buffer_size;
        if(mesg_buffer_size < EDNS0_LENGTH_MIN)
        {
            mesg_buffer_size = EDNS0_LENGTH_MIN;
        }
    }
    dns_message_set_buffer_size(mesg, mesg_buffer_size);
}

static ya_result dns_message_process_additionals(dns_message_t *mesg, uint8_t *s, uint16_t ar_count)
{
    (void)s;
    /*
     * @note: I've moved this in the main function (the one calling this one)
     */

    // yassert(ar_count != 0 && ar_count == message_get_additional_count(mesg));

    uint8_t  *buffer = mesg->_buffer;
    ya_result ret;

    ar_count = ntohs(MESSAGE_AR(buffer));

    /*
     * rfc2845
     *
     * If there is a TSIG then
     * _ It must be put aside, safely
     * _ It must be removed from the query
     * _ It must be processed
     *
     * rfc2671
     *
     * Handle OPT
     *
     */

    /*
     * Read DNS name (decompression on)
     * Read type (TSIG = 250)
     * Read class (ANY)
     * Read TTL (0)
     * Read RDLEN
     *
     */

    uint32_t            query_end = dns_message_get_size(mesg);

    dns_packet_reader_t purd;
    purd.packet = buffer;
    purd.packet_size = query_end;

    if(mesg->_ar_start == NULL)
    {
        uint32_t ar_index = ntohs(MESSAGE_AN(buffer)) + ntohs(MESSAGE_NS(buffer));

        purd.packet_offset = DNS_HEADER_LENGTH;    // header
        dns_packet_reader_skip_fqdn(&purd);        // checked below
        if(FAIL(dns_packet_reader_skip(&purd, 4))) // type class
        {
            dns_message_set_status(mesg, FP_ERROR_READING_QUERY);
            return UNPROCESSABLE_MESSAGE;
        }

        while(ar_index > 0) /* Skip all until AR records */
        {
            /*
             * It should be in this kind of processing that we read the EDNS0 flag
             */

            if(FAIL(ret = dns_packet_reader_skip_record(&purd)))
            {
                dns_message_set_status(mesg, FP_ERROR_READING_QUERY);
                return UNPROCESSABLE_MESSAGE;
            }

            ar_index--;
        }

        query_end = purd.packet_offset; // ready to remove all additionals in one fell swoop

        mesg->_ar_start = &mesg->_buffer[purd.packet_offset];
    }
    else
    {
        purd.packet_offset = dns_message_get_additional_section_ptr(mesg) - mesg->_buffer;
    }

    /* We are now at the start of the ar */

    struct type_class_ttl_rdlen_s tctr;
    uint8_t                       tsigname[DOMAIN_LENGTH_MAX];
#if DNSCORE_HAS_TSIG_SUPPORT
    uint32_t record_offset;
#endif

    while(ar_count-- > 0)
    {
#if DNSCORE_HAS_TSIG_SUPPORT
        record_offset = purd.packet_offset;
#endif

        if(FAIL(dns_packet_reader_read_fqdn(&purd, tsigname, sizeof(tsigname))))
        {
            /* oops */

            dns_message_set_status(mesg, FP_ERROR_READING_QUERY);

            return UNPROCESSABLE_MESSAGE;
        }

        if(dns_packet_reader_read(&purd, &tctr, 10) == 10) // exact
        {
            /*
             * EDNS (0)
             */

            if(tctr.rtype == TYPE_OPT)
            {
                /**
                 * Handle EDNS
                 */

                if((tctr.ttl & NU32(0x00ff0000)) == 0) /* ensure version is 0 */
                {
                    uint32_t rdlen = ntohs(tctr.rdlen);

#if DNSCORE_HAS_NSID_SUPPORT
                    if(rdlen != 0)
                    {
                        uint32_t next = purd.packet_offset + rdlen;
                        for(int_fast32_t remain = (int32_t)rdlen; remain >= 4; remain -= 4)
                        {
                            uint32_t opt_type_size;

                            if(ISOK(dns_packet_reader_read_u32(&purd,
                                                               &opt_type_size))) // read the option-code and the option-length in one operation
                            {
                                if(opt_type_size == NU32(0x00030000)) // check if it's NSID request
                                {
                                    // nsid
                                    dns_message_nsid_set(mesg);
                                    continue;
                                }

                                if((opt_type_size & 0xffff) == OPT_COOKIE) // check if it's COOKIE
                                {
                                    // cookie
                                    int32_t cookie_len = ntohl(opt_type_size) & 0xffff;

                                    // yadifad uses server cookies of 8 bytes
                                    if((cookie_len == DNS_MESSAGE_COOKIE_CLIENT_SIZE) || (cookie_len == (DNS_MESSAGE_COOKIE_CLIENT_SIZE + DNS_MESSAGE_COOKIE_SERVER_SIZE)))
                                    {
                                        dns_message_cookie_set(mesg);
                                        remain -= cookie_len;
                                        if(dns_packet_reader_read(&purd, mesg->_cookie.bytes, cookie_len) == cookie_len)
                                        {
                                            mesg->_cookie.size = cookie_len;

                                            if(cookie_len == (DNS_MESSAGE_COOKIE_CLIENT_SIZE + DNS_MESSAGE_COOKIE_SERVER_SIZE))
                                            {
                                                // there is a server cookie present: verify it

                                                /// @todo 20230328 edf -- compare with the server_cookie, if present

                                                // Checks if the server cookie in that message matches the expected
                                                // value.
                                                if(dns_message_cookie_server_check(mesg))
                                                {
                                                    // all good
                                                }
                                                else
                                                {
                                                    // discard or send a BADCOOKIE
                                                    dns_message_set_rcode(mesg, RCODE_BADCOOKIE);
                                                    return UNPROCESSABLE_MESSAGE;
                                                }
                                            }
                                            else
                                            {
                                                /// @todo 20230328 edf -- compute the server cookie
                                                /// @todo 20230328 edf -- store server cookie for the reply
                                                dns_message_cookie_server_set(mesg);
                                            }
                                        }
                                        else
                                        {
                                            // failed to read the cookie
                                            return UNPROCESSABLE_MESSAGE;
                                        }

                                        continue;
                                    }
                                    else
                                    {
                                        if((cookie_len < DNS_MESSAGE_COOKIE_CLIENT_SIZE) ||                                    // too short
                                           (cookie_len < DNS_MESSAGE_COOKIE_CLIENT_SIZE + DNS_MESSAGE_COOKIE_SERVER_SIZE) ||   // too short for server
                                           (cookie_len > DNS_MESSAGE_COOKIE_CLIENT_SIZE + DNS_MESSAGE_COOKIE_SERVER_SIZE_MAX)) // too big
                                        {
                                            dns_message_set_rcode(mesg, RCODE_FORMERR);
                                        }
                                        // yadifad only sends server cookies of DNS_MESSAGE_COOKIE_CLIENT_SIZE +
                                        // DNS_MESSAGE_COOKIE_SERVER_SIZE bytes this means this cookie can't be right
                                        // for the server
                                        return UNPROCESSABLE_MESSAGE;
                                    }
                                }

                                uint32_t opt_type_len = ntohl(opt_type_size) & 0xffff;

                                if(FAIL(dns_packet_reader_skip(&purd, opt_type_len))) // skip the data
                                {
                                    return UNPROCESSABLE_MESSAGE;
                                }

                                remain -= opt_type_len;
                            }
                            else
                            {
                                break;
                            }
                        }

                        if(FAIL(dns_packet_reader_skip(&purd, next - purd.packet_offset)))
                        {
                            return UNPROCESSABLE_MESSAGE;
                        }
                    }
#else
                    if(FAIL(dns_packet_reader_skip(&purd, rdlen)))
                    {
                        return UNPROCESSABLE_MESSAGE;
                    }
#endif
                    if(tsigname[0] == '\0')
                    {
                        message_process_adjust_buffer_size(mesg, ntohs(tctr.rclass));
                        dns_message_edns0_set(mesg);
                        mesg->_edns0_opt_ttl.as_u32 = tctr.ttl;
#if DEBUG
                        log_debug("EDNS: udp-size=%d rcode-ext=%08x desc=%04x", dns_message_get_size(mesg), tctr.ttl, rdlen);
#endif
                        continue;
                    }
#if DEBUG
                    log_debug("OPT record is not processable (broken)");
#endif
                    return UNPROCESSABLE_MESSAGE;
                }
                else
                {
                    dns_message_set_status(mesg, FP_EDNS_BAD_VERSION);
                    message_process_adjust_buffer_size(mesg, ntohs(tctr.rclass));

                    dns_message_edns0_set(mesg);
                    mesg->_edns0_opt_ttl.as_u32 = 0;
#if DEBUG
                    log_debug("OPT record is not processable (not supported)");
#endif
                    return MAKE_RCODE_ERROR(FP_EDNS_BAD_VERSION);
                }
            }
#if DNSCORE_HAS_TSIG_SUPPORT
            /*
             * TSIG
             */

            else if(tctr.rtype == TYPE_TSIG)
            {
                if(ar_count == 0)
                {
                    /*
                     * It looks like a TSIG ...
                     */

                    ya_result return_code;

                    if(dns_message_is_query(mesg))
                    {
                        if(FAIL(return_code = tsig_process_query(mesg, &purd, record_offset, tsigname, &tctr)))
                        {
#if DEBUG
                            // this should be reported above
                            log_notice("%r query error from %{sockaddr}", return_code, dns_message_get_sender_sa(mesg));
#endif
                            return return_code;
                        }
                    }
                    else
                    {
                        tsig_key_t *key = tsig_get(tsigname);

                        if(key != NULL)
                        {
                            if(FAIL(return_code = tsig_process(mesg, &purd, record_offset, key, &tctr)))
                            {
#if DEBUG
                                // this should be reported above
                                log_notice("%r answer error from %{sockaddr}", return_code, dns_message_get_sender_sa(mesg));
#endif
                                return return_code;
                            }
                        }
                        else
                        {
                            log_notice("answer error from %{sockaddr}: TSIG when none expected", dns_message_get_sender_sa(mesg));

                            dns_message_set_status(mesg, FP_TSIG_UNEXPECTED);

                            return MAKE_RCODE_ERROR(FP_TSIG_UNEXPECTED);
                        }
                    }

                    break; /* we know there is no need to loop anymore */
                }
                else
                {
                    /*
                     * Error: TSIG is not the last AR record
                     */

#if DEBUG
                    log_debug("TSIG record is not the last AR");
#endif

                    dns_message_set_status(mesg, FP_TSIG_IS_NOT_LAST);

                    return UNPROCESSABLE_MESSAGE;
                }
            }
#endif
            else
            {
                /* Unhandled AR TYPE */

                log_debug("unhandled AR type %{dnstype}", &tctr.rtype);

                dns_message_set_status(mesg, FP_UNEXPECTED_RR_IN_QUERY);

                return UNPROCESSABLE_MESSAGE;
            }
        }
    } /* While there are AR to process */

    dns_message_set_additional_count_ne(mesg, 0);
    dns_message_set_size(mesg, query_end);

    return SUCCESS;
}

/**
 * Handles the OPT and TSIG records of an answer.
 *
 * @param mesg
 * @param ar_count
 * @return
 */

static ya_result dns_message_process_answer_additionals(dns_message_t *mesg, uint16_t ar_count /* network order */)
{
    /*
     * @note: I've moved this in the main function (the one calling this one)
     */

    yassert(ar_count != 0 && ar_count == dns_message_get_additional_count_ne(mesg));

    uint8_t *buffer = dns_message_get_buffer(mesg);

    ar_count = ntohs(ar_count);

    /*
     * rfc2845
     *
     * If there is a TSIG then
     * _ It must be put aside, safely
     * _ It must be removed from the query
     * _ It must be processed
     *
     * rfc2671
     *
     * Handle OPT
     *
     */

    /*
     * Read DNS name (decompression on)
     * Read type (TSIG = 250)
     * Read class (ANY)
     * Read TTL (0)
     * Read RDLEN
     *
     */

    uint32_t            message_size = dns_message_get_size(mesg);

    dns_packet_reader_t purd;
    purd.packet = buffer;
    purd.packet_size = message_size;
    // uint16_t ar_sub = 0;

    purd.packet_offset = dns_message_get_additional_section_ptr(mesg) - mesg->_buffer; // size up to additional sections
    message_size = purd.packet_offset;

    /* We are now at the start of the ar */

    struct type_class_ttl_rdlen_s tctr;
    uint8_t                       tsigname[DOMAIN_LENGTH_MAX];

#if DNSCORE_HAS_TSIG_SUPPORT
    uint32_t record_offset;
#endif

    while(ar_count-- > 0)
    {
#if DNSCORE_HAS_TSIG_SUPPORT
        record_offset = purd.packet_offset;
#endif
        if(FAIL(dns_packet_reader_read_fqdn(&purd, tsigname, sizeof(tsigname))))
        {
            /* oops */

            dns_message_set_status(mesg, FP_ERROR_READING_QUERY);

            return UNPROCESSABLE_MESSAGE;
        }

        if(dns_packet_reader_read(&purd, &tctr, 10) == 10) // exact
        {
            /*
             * EDNS (0)
             */

            if(tctr.rtype == TYPE_OPT)
            {
                /**
                 * Handle EDNS
                 */

                if((tctr.ttl & NU32(0x00ff0000)) == 0) /* ensure version is 0 */
                {
                    uint32_t rdlen = ntohs(tctr.rdlen);

                    if(rdlen != 0)
                    {
                        uint32_t next = purd.packet_offset + rdlen;
                        for(int_fast32_t remain = (int32_t)rdlen; remain >= 4; remain -= 4)
                        {
                            uint32_t opt_type_size;

                            if(ISOK(dns_packet_reader_read_u32(&purd,
                                                               &opt_type_size))) // read the option-code and the option-length in one operation
                            {
                                uint32_t data_len = ntohl(opt_type_size) & 0xffff;
                                switch(opt_type_size & 0xffff)
                                {
                                    case OPT_NSID:
                                    {
                                        // nsid
                                        dns_message_nsid_set(mesg);
                                        if(FAIL(dns_packet_reader_skip(&purd, data_len))) // skip the data
                                        {
                                            return UNPROCESSABLE_MESSAGE;
                                        }
                                        break;
                                    }
                                    case OPT_COOKIE: // check if it's COOKIE
                                    {
                                        // cookie
                                        int32_t cookie_len = ntohl(opt_type_size) & 0xffff;

                                        if(!dns_message_cookie_size_valid(cookie_len))
                                        {
                                            dns_message_set_rcode(mesg, RCODE_FORMERR);
                                            return UNPROCESSABLE_MESSAGE;
                                        }

                                        dns_message_cookie_set(mesg);
                                        remain -= cookie_len;
                                        if(dns_packet_reader_read(&purd, mesg->_cookie.bytes, cookie_len) == cookie_len)
                                        {
                                            mesg->_cookie.size = cookie_len;
                                            dns_message_cookie_set(mesg);
                                        }
                                        else
                                        {
                                            // failed to read the cookie
                                            return UNPROCESSABLE_MESSAGE;
                                        }

                                        break;
                                    }
                                    default:
                                    {
                                        if(FAIL(dns_packet_reader_skip(&purd, data_len))) // skip the data
                                        {
                                            return UNPROCESSABLE_MESSAGE;
                                        }
                                    }
                                }

                                remain -= data_len;
                            }
                            else
                            {
                                return UNPROCESSABLE_MESSAGE;
                            }
                        }

                        if(FAIL(dns_packet_reader_skip(&purd, next - purd.packet_offset)))
                        {
                            return UNPROCESSABLE_MESSAGE;
                        }
                    }

                    if(tsigname[0] == '\0')
                    {
                        //++ar_sub;

                        dns_message_edns0_set(mesg);
                        mesg->_edns0_opt_ttl.as_u32 = tctr.ttl;

                        log_debug("EDNS: udp-size=%d rcode-ext=%08x desc=%04x", dns_message_get_buffer_size(mesg), tctr.ttl, ntohs(tctr.rdlen));
                        continue;
                    }
                }
                else
                {
                    dns_message_edns0_set(mesg);
                    mesg->_edns0_opt_ttl.as_u32 = tctr.ttl;
                }

                log_debug("OPT record is not processable (broken or not supported)");

                return UNPROCESSABLE_MESSAGE;
            }
#if DNSCORE_HAS_TSIG_SUPPORT

            /*
             * TSIG
             */

            else if(tctr.rtype == TYPE_TSIG)
            {
                if(ar_count == 0)
                {
                    /*
                     * It looks like a TSIG ...
                     */

                    ya_result return_code;

                    if(dns_message_is_query(mesg))
                    {
                        if(FAIL(return_code = tsig_process_query(mesg, &purd, record_offset, tsigname, &tctr)))
                        {
                            log_err("%r query error from %{sockaddr}", return_code, dns_message_get_sender_sa(mesg));
                            return UNPROCESSABLE_MESSAGE;
                        }
                    }
                    else // not a query (an answer)
                    {
                        if(dns_message_has_tsig(mesg))
                        {
                            if(dnsname_equals(tsigname, dns_message_tsig_get_name(mesg)))
                            {
                                if(FAIL(return_code = tsig_process_answer(mesg, &purd, record_offset, &tctr)))
                                {
                                    log_err("%r answer error from %{sockaddr}", return_code, dns_message_get_sender_sa(mesg));
                                    return UNPROCESSABLE_MESSAGE;
                                }
                            }
                            else
                            {
                                log_err("TSIG name mismatch from %{sockaddr}", dns_message_get_sender_sa(mesg));

                                return UNPROCESSABLE_MESSAGE;
                            }
                        }
                        else // no tsig
                        {
                            log_err("answer error from %{sockaddr}: TSIG when none expected", dns_message_get_sender_sa(mesg));

                            dns_message_set_status(mesg, FP_TSIG_UNEXPECTED);

                            return UNPROCESSABLE_MESSAGE;
                        }
                    }

                    break; /* we know there is no need to loop anymore */
                }
                else
                {
                    /*
                     * Error: TSIG is not the last AR record
                     */

                    log_debug("TSIG record is not the last AR");

                    dns_message_set_status(mesg, FP_TSIG_IS_NOT_LAST);

                    return UNPROCESSABLE_MESSAGE;
                }
            }
#endif
            else
            {
                /* Unhandled AR TYPE */
#if DEBUG
                log_debug("skipping AR type %{dnstype}", &tctr.rtype);
#endif
                purd.packet_offset += ntohs(tctr.rdlen);

                message_size = purd.packet_offset;
            }
        }
    } /* While there are AR to process */

    // message_sub_additional_count(mesg, 1);

    dns_message_set_additional_count_ne(mesg, 0);
    dns_message_set_size(mesg, message_size);

    return SUCCESS;
}

/** \brief Processing DNS packet
 *
 *  @param mesg
 *
 *  @retval OK
 *  @return status of message is written in dns_message_get_status(mesg)
 */

/* Defines a mask and the expected result for the 4 first 16 bits of the header */
#ifdef WORDS_BIGENDIAN
#define MESSAGE_HEADER_MASK          (((uint64_t)0) | (((uint64_t)(QR_BITS | AA_BITS | RA_BITS | TC_BITS)) << 40) | (((uint64_t)(RA_BITS | RCODE_BITS)) << 32) | (((uint64_t)0xffffLL) << 16))

#define MESSAGE_HEADER_RESULT        (((uint64_t)1LL) << 16)

/* Bind gives "RA" here (seems irrelevant, nonsense, but we need to accept it) */

#define NOTIFY_MESSAGE_HEADER_MASK   (((uint64_t)0LL) | (((uint64_t)(TC_BITS)) << 40) | (((uint64_t)0xffffLL) << 16))

#define NOTIFY_MESSAGE_HEADER_RESULT (((uint64_t)1LL) << 16)

#else
// 0    16   32   48
// 0000 0000 0000 0000
#define MESSAGE_HEADER_MASK          (((uint64_t)0LL) | (((uint64_t)(QR_BITS | AA_BITS | RA_BITS | TC_BITS)) << 16) | (((uint64_t)(RA_BITS | RCODE_BITS)) << 24) | (((uint64_t)0xffffLL) << 32))

#define MESSAGE_HEADER_RESULT        (((uint64_t)1LL) << 40)

/* Bind gives "RA" here (seems irrelevant, nonsense, but we need to accept it) */

#define NOTIFY_MESSAGE_HEADER_MASK   (((uint64_t)0LL) | (((uint64_t)(TC_BITS)) << 16) | (((uint64_t)0xffffLL) << 32))

#define NOTIFY_MESSAGE_HEADER_RESULT (((uint64_t)1LL) << 40)

#endif

/* EDF: this takes about 150 cycles [144;152] with peaks at 152 */

/**
 * Canonises the query:
 * _ copies the query fqdn lowercase
 * _ copies the query type and class for easy access
 *
 * (should be renamed to message_query_canonise or something of that effect)
 *
 * @param mesg
 * @return a pointer to the answer section (or more accurately, just after the class of the (first) query
 */

static inline uint8_t *dns_message_process_copy_fqdn(dns_message_t *mesg)
{
    uint8_t *src = dns_message_get_query_section_ptr(mesg);
    uint8_t *dst = &mesg->_canonised_fqdn[0];

    uint8_t *base = dst;
    uint32_t len;

    for(;;)
    {
        len = *src++;
        *dst++ = len;

        if(len == 0)
        {
            break;
        }

        if((len & 0xC0) == 0)
        {
            const uint8_t *const limit = dst + len;

            if(limit - base < DOMAIN_LENGTH_MAX)
            {
                do
                {
                    *dst++ = LOCASE(*src++); /* Works with the dns character set */
                } while(dst < limit);
            }
            else
            {
                dns_message_set_status(mesg, FP_NAME_TOO_LARGE);

                DERROR_MSG("FP_NAME_TOO_LARGE");

                return NULL;
            }
        }
        else
        {
            dns_message_set_status(mesg, ((len & 0xC0) == 0xC0) ? FP_QNAME_COMPRESSED : FP_NAME_FORMAT_ERROR);

            return NULL;
        }
    }

    /* Get qtype & qclass */

    mesg->_query_type = GET_U16_AT(src[0]);  /** @note : NATIVETYPE  */
    mesg->_query_class = GET_U16_AT(src[2]); /** @note : NATIVECLASS */

    // the next section starts at &src[4]

    return &src[4];
}

ya_result dns_message_process_query(dns_message_t *mesg)
{
    uint8_t *buffer = dns_message_get_buffer(mesg);

    /** CHECK DNS HEADER */
    /** Drop dns packet if query is answer or does not have correct header length */

    /*
     * +5 <=> 1 qd record ar least
     */

    uint64_t *h64 = (uint64_t *)buffer;
    uint64_t  m64 = MESSAGE_HEADER_MASK;
    uint64_t  r64 = MESSAGE_HEADER_RESULT;

    if((dns_message_get_size(mesg) < DNS_HEADER_LENGTH + 5) || ((*h64 & m64) != r64))
    {
        /** Return if QDCOUNT is not 1
         *
         *  @note Previous test was actually testing if QDCOUNT was > 1
         *        I assumed either 0 or >1 is wrong for us so I used the same trick than for QCCOUNT
         */

        if(MESSAGE_QR(buffer))
        {
            dns_message_set_status(mesg, FP_QR_BIT_SET);
            return INVALID_MESSAGE;
        }

        MESSAGE_FLAGS_AND(buffer, OPCODE_BITS | RD_BITS, 0);

        if(NETWORK_ONE_16 != MESSAGE_QD(buffer))
        {
            if(0 == MESSAGE_QD(buffer))
            {
                dns_message_set_status(mesg, FP_QDCOUNT_IS_0);
                return INVALID_MESSAGE; /* will be dropped */
            }
            else
            {
                dns_message_set_status(mesg, FP_QDCOUNT_BIG_1);
            }
        }
        else
        {
            dns_message_set_status(mesg, FP_PACKET_DROPPED);
        }

        return UNPROCESSABLE_MESSAGE;
    }
    /* IXFR has NS == 1
    if(MESSAGE_NS(buffer) != 0)
    {
        dns_message_set_status(mesg, FP_NSCOUNT_NOT_0);
        return UNPROCESSABLE_MESSAGE;
    }
    */
    uint8_t *s = dns_message_process_copy_fqdn(mesg);

    if(s == NULL)
    {
        dns_message_set_status(mesg, FP_NAME_FORMAT_ERROR);
        return UNPROCESSABLE_MESSAGE;
    }

    /**
     * @note Past this point, a message could be processable.
     *       It's the right place to reset the message's defaults.
     *
     */

    dns_message_reset_buffer_size(mesg);
    mesg->_ar_start = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
    mesg->_tsig.tsig = NULL;
#endif
    mesg->_edns0_opt_ttl.as_u32 = 0;
    dns_message_edns0_clear(mesg);
#if DNSCORE_HAS_NSID_SUPPORT
    dns_message_clear_nsid(mesg);
#endif

    /*
     * Handle the OPT and TSIG records
     */

    {
        ya_result return_code;
        uint32_t  nsar_count;

        if((nsar_count = MESSAGE_NSAR(buffer)) != 0)
        {
            if(FAIL(return_code = dns_message_process_additionals(mesg, s, nsar_count)))
            {
                // message_set_size(mesg, s - buffer);

                return return_code;
            }
        }

        if(dns_message_get_query_type(mesg) != TYPE_IXFR)
        {
            dns_message_set_size(mesg, s - buffer);
        }
    }

    /* cut the trash here */

    /* At this point the TSIG has been computed and removed */

    /* Clear some bits */
    dns_message_apply_mask(mesg, ~(QR_BITS | TC_BITS | AA_BITS), ~(Z_BITS | AD_BITS | CD_BITS | RA_BITS | RCODE_BITS));
    dns_message_set_status(mesg, FP_MESG_OK);

    return SUCCESS;
}

int dns_message_process(dns_message_t *mesg)
{
    uint8_t *buffer = dns_message_get_buffer(mesg);

    switch(MESSAGE_OP(buffer))
    {
        case OPCODE_QUERY:
        {
            /** CHECK DNS HEADER */
            /** Drop dns packet if query is answer or does not have correct header length */

            /*
             * +5 <=> 1 qd record ar least
             */

            uint64_t *h64 = (uint64_t *)buffer;
            uint64_t  m64 = MESSAGE_HEADER_MASK;
            uint64_t  r64 = MESSAGE_HEADER_RESULT;

            if((dns_message_get_size(mesg) < DNS_HEADER_LENGTH + 5) || ((*h64 & m64) != r64))
            {
                /** Return if QDCOUNT is not 1
                 *
                 *  @note Previous test was actually testing if QDCOUNT was > 1
                 *        I assumed either 0 or >1 is wrong for us so I used the same trick than for QCCOUNT
                 */

                if(MESSAGE_QR(buffer))
                {
                    dns_message_set_status(mesg, FP_QR_BIT_SET);
                    return INVALID_MESSAGE;
                }

                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS | RD_BITS, 0);

                if(NETWORK_ONE_16 != MESSAGE_QD(buffer))
                {
                    if(0 == MESSAGE_QD(buffer))
                    {
                        DERROR_MSG("FP_QDCOUNT_IS_0");
                        dns_message_set_status(mesg, FP_QDCOUNT_IS_0);
                        return INVALID_MESSAGE; /* will be dropped */
                    }
                    else
                    {
                        dns_message_set_status(mesg, FP_QDCOUNT_BIG_1);

                        DERROR_MSG("FP_QDCOUNT_BIG_1");
                    }
                }
                else
                {
                    dns_message_set_status(mesg, FP_PACKET_DROPPED);
                }

                return UNPROCESSABLE_MESSAGE;
            }
            if(MESSAGE_NS(buffer) != 0)
            {
                dns_message_set_status(mesg, FP_NSCOUNT_NOT_0);
                return UNPROCESSABLE_MESSAGE;
            }

            /**
             * @note Past this point, a message could be processable.
             *       It's the right place to reset the message's defaults.
             *
             */

            dns_message_reset_buffer_size(mesg);
            mesg->_ar_start = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
            mesg->_tsig.tsig = NULL;
#endif
            mesg->_edns0_opt_ttl.as_u32 = 0;
            dns_message_edns0_clear(mesg);
#if DNSCORE_HAS_NSID_SUPPORT
            dns_message_clear_nsid(mesg);
#endif
            uint8_t *s = dns_message_process_copy_fqdn(mesg);

            if(s == NULL)
            {
                dns_message_set_status(mesg, FP_NAME_FORMAT_ERROR);
                return UNPROCESSABLE_MESSAGE;
            }

            /*
             * Handle the OPT and TSIG records
             */

            {
                ya_result return_code;
                uint32_t  nsar_count;

                if((nsar_count = MESSAGE_NSAR(buffer)) != 0)
                {
                    if(FAIL(return_code = dns_message_process_additionals(mesg, s, nsar_count)))
                    {
                        dns_message_set_size(mesg, s - buffer);

                        return return_code;
                    }
                }

                if(dns_message_get_query_type(mesg) != TYPE_IXFR)
                {
                    dns_message_set_size(mesg, s - buffer);
                }
            }

            /* At this point the TSIG has been computed and removed */
            /* Clear zome bits */
            dns_message_apply_mask(mesg, ~(QR_BITS | TC_BITS | AA_BITS), ~(Z_BITS | RA_BITS | AD_BITS | CD_BITS | RCODE_BITS));

            dns_message_set_status(mesg, FP_MESG_OK);

            return OK;
        }
        case OPCODE_NOTIFY:
        {
            MESSAGE_LOFLAGS(buffer) &= ~(Z_BITS | AD_BITS | CD_BITS);

            /** CHECK DNS HEADER */
            /** Drop dns packet if query is answer or does not have correct header length */

            /*
             * +5 <=> 1 qd record ar least
             */

            uint64_t *h64 = (uint64_t *)buffer;
            uint64_t  m64 = NOTIFY_MESSAGE_HEADER_MASK;
            uint64_t  r64 = NOTIFY_MESSAGE_HEADER_RESULT;
            /* ... A400 0001 ... */
            if((dns_message_get_size(mesg) < DNS_HEADER_LENGTH + 5) || ((*h64 & m64) != r64))
            {
                /** Return if QDCOUNT is not 1
                 *
                 *  @note Previous test was actually testing if QDCOUNT was > 1
                 *        I assumed either 0 or >1 is wrong for us so I used the same trick than for QCCOUNT
                 */
                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS, 0);

                if(NETWORK_ONE_16 != MESSAGE_QD(buffer))
                {
                    if(0 == MESSAGE_QD(buffer))
                    {
                        DERROR_MSG("FP_QDCOUNT_IS_0");
                        dns_message_set_status(mesg, FP_QDCOUNT_IS_0);
                        return INVALID_MESSAGE;
                    }
                    else
                    {
                        dns_message_set_status(mesg, FP_QDCOUNT_BIG_1);

                        DERROR_MSG("FP_QDCOUNT_BIG_1");
                    }
                }
                else
                {
                    dns_message_set_status(mesg, FP_PACKET_DROPPED);
                }

                return UNPROCESSABLE_MESSAGE;
            }

            uint8_t *s = dns_message_process_copy_fqdn(mesg);

            if(s == NULL)
            {
                dns_message_set_status(mesg, FP_NAME_FORMAT_ERROR);
                return UNPROCESSABLE_MESSAGE;
            }

            /**
             * @note Past this point, a message could be processable.
             *       It's the right place to reset the message's defaults.
             *
             */

            dns_message_reset_buffer_size(mesg);
            mesg->_ar_start = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
            mesg->_tsig.tsig = NULL;
#endif
            mesg->_edns0_opt_ttl.as_u32 = 0;
            dns_message_edns0_clear(mesg);
#if DNSCORE_HAS_NSID_SUPPORT
            dns_message_clear_nsid(mesg);
#endif
            /*
             * If there is a TSIG, it is here ...
             */

#if DNSCORE_HAS_TSIG_SUPPORT
            {
                ya_result return_code;
                uint16_t  ar_count;

                if((ar_count = MESSAGE_AR(buffer)) != 0)
                {
                    if(FAIL(return_code = dns_message_process_additionals(mesg, s, ar_count)))
                    {
                        return return_code;
                    }
                }
            }
#endif
            /* At this point the TSIG has been computed and removed */

            dns_message_set_status(mesg, FP_MESG_OK);

            return OK;
        }
        case OPCODE_UPDATE:
        {
            MESSAGE_LOFLAGS(buffer) &= ~(Z_BITS | AD_BITS | CD_BITS | RCODE_BITS);

            /** CHECK DNS HEADER */
            /** Drop dns packet if query is answer or does not have correct header length */

            /*
             * +5 <=> 1 qd record ar least
             */

            uint64_t *h64 = (uint64_t *)buffer;
            uint64_t  m64 = MESSAGE_HEADER_MASK;
            uint64_t  r64 = MESSAGE_HEADER_RESULT;

            if((dns_message_get_size(mesg) < DNS_HEADER_LENGTH + 5) || ((*h64 & m64) != r64))
            {
                /** Return if QDCOUNT is not 1
                 *
                 *  @note Previous test was actually testing if QDCOUNT was > 1
                 *        I assumed either 0 or >1 is wrong for us so I used the same trick than for QCCOUNT
                 */

                if(MESSAGE_QR(buffer))
                {
                    dns_message_set_status(mesg, FP_QR_BIT_SET);
                    return INVALID_MESSAGE;
                }

                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS, 0);

                if(NETWORK_ONE_16 != MESSAGE_QD(buffer))
                {
                    if(0 == MESSAGE_QD(buffer))
                    {
                        DERROR_MSG("FP_QDCOUNT_IS_0");
                        dns_message_set_status(mesg, FP_QDCOUNT_IS_0);
                        return INVALID_MESSAGE;
                    }
                    else
                    {
                        DERROR_MSG("FP_QDCOUNT_BIG_1");
                        dns_message_set_status(mesg, FP_QDCOUNT_BIG_1);
                    }

                    return UNPROCESSABLE_MESSAGE;
                }

                dns_message_set_status(mesg, FP_PACKET_DROPPED);

                return UNPROCESSABLE_MESSAGE;
            }

            uint8_t *s = dns_message_process_copy_fqdn(mesg);

            if(s == NULL)
            {
                dns_message_set_status(mesg, FP_NAME_FORMAT_ERROR);
                return UNPROCESSABLE_MESSAGE;
            }

            /**
             * @note Past this point, a message could be processable.
             *       It's the right place to reset the message's defaults.
             *
             */

            dns_message_reset_buffer_size(mesg);
            mesg->_ar_start = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
            mesg->_tsig.tsig = NULL;
#endif
            mesg->_edns0_opt_ttl.as_u32 = 0;
            dns_message_edns0_clear(mesg);
#if DNSCORE_HAS_NSID_SUPPORT
            dns_message_clear_nsid(mesg);
#endif
            /*
             * If there is a TSIG, it is here ...
             */

#if DNSCORE_HAS_TSIG_SUPPORT
            {
                ya_result return_code;
                uint16_t  ar_count;

                if((ar_count = MESSAGE_AR(buffer)) != 0)
                {
                    if(FAIL(return_code = dns_message_process_additionals(mesg, s, ar_count)))
                    {
                        return return_code;
                    }
                }
            }
#endif
            /* At this point the TSIG has been computed and removed */

            dns_message_apply_mask(mesg, ~(QR_BITS | TC_BITS | AA_BITS), ~(RA_BITS | RCODE_BITS));

            dns_message_set_status(mesg, FP_MESG_OK);

            return OK;
        }
#if DNSCORE_HAS_CTRL
        case OPCODE_CTRL:
        {
            MESSAGE_LOFLAGS(buffer) &= ~(Z_BITS | AD_BITS | CD_BITS | RCODE_BITS);

            /*
               rdtsc_init(&mpb);
             */

            /** CHECK DNS HEADER */
            /** Drop dns packet if query is answer or does not have correct header length */

            /*
             * +5 <=> 1 qd record ar least
             */

            uint64_t *h64 = (uint64_t *)buffer;
            uint64_t  m64 = MESSAGE_HEADER_MASK;
            uint64_t  r64 = MESSAGE_HEADER_RESULT;

            if((dns_message_get_size(mesg) < DNS_HEADER_LENGTH + 5) || ((*h64 & m64) != r64))
            {
                /** Return if QDCOUNT is not 1
                 *
                 *  @note Previous test was actually testing if QDCOUNT was > 1
                 *        I assumed either 0 or >1 is wrong for us so I used the same trick than for QCCOUNT
                 */

                if(MESSAGE_QR(buffer))
                {
                    dns_message_set_status(mesg, FP_QR_BIT_SET);
                    return INVALID_MESSAGE;
                }

                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS, 0);

                if(NETWORK_ONE_16 != MESSAGE_QD(buffer))
                {
                    if(0 == MESSAGE_QD(buffer))
                    {
                        DERROR_MSG("FP_QDCOUNT_IS_0");
                        dns_message_set_status(mesg, FP_QDCOUNT_IS_0);
                        return INVALID_MESSAGE;
                    }
                    else
                    {
                        DERROR_MSG("FP_QDCOUNT_BIG_1");
                        dns_message_set_status(mesg, FP_QDCOUNT_BIG_1);
                    }

                    return UNPROCESSABLE_MESSAGE;
                }

                dns_message_set_status(mesg, FP_PACKET_DROPPED);

                return UNPROCESSABLE_MESSAGE;
            }

            uint8_t *s = dns_message_process_copy_fqdn(mesg);

            if(s == NULL)
            {
                dns_message_set_status(mesg, FP_NAME_FORMAT_ERROR);
                return UNPROCESSABLE_MESSAGE;
            }

            /**
             * @note Past this point, a message could be processable.
             *       It's the right place to reset the message's defaults.
             *
             */

            dns_message_reset_buffer_size(mesg);
            mesg->_ar_start = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
            dns_message_tsig_clear_key(mesg);
#endif
            mesg->_edns0_opt_ttl.as_u32 = 0;
            dns_message_edns0_clear(mesg);
#if DNSCORE_HAS_NSID_SUPPORT
            dns_message_clear_nsid(mesg);
#endif
            /*
             * If there is a TSIG, it is here ...
             */

#if DNSCORE_HAS_TSIG_SUPPORT
            {
                ya_result return_code;
                uint16_t  ar_count;

                if((ar_count = MESSAGE_AR(buffer)) != 0)
                {
                    if(FAIL(return_code = dns_message_process_additionals(mesg, s, ar_count)))
                    {
                        return return_code;
                    }
                }
            }
#endif
            // At this point the TSIG has been computed and removed

            dns_message_apply_mask(mesg, ~(QR_BITS | TC_BITS | AA_BITS), ~(RA_BITS | RCODE_BITS));

            dns_message_set_status(mesg, FP_MESG_OK);

            return OK;
        }
#endif // HAS_CTRL
        default:
        {
            uint8_t hf = MESSAGE_HIFLAGS(buffer);
            if((hf & QR_BITS) == 0)
            {
                MESSAGE_LOFLAGS(buffer) &= ~(Z_BITS | AD_BITS | CD_BITS | RCODE_BITS);
                MESSAGE_FLAGS_AND(buffer, OPCODE_BITS, 0);

                dns_message_reset_buffer_size(mesg);
                mesg->_ar_start = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
                mesg->_tsig.tsig = NULL;
#endif
                mesg->_edns0_opt_ttl.as_u32 = 0;
                dns_message_edns0_clear(mesg);
#if DNSCORE_HAS_NSID_SUPPORT
                dns_message_clear_nsid(mesg);
#endif
                dns_message_set_status(mesg, FP_NOT_SUPP_OPC);
                dns_message_set_size(mesg, DNS_HEADER_LENGTH);
                SET_U32_AT(mesg->_buffer[4], 0); /* aligned to 32 bits, so two 32 bits instead of one 64 */
                SET_U32_AT(mesg->_buffer[8], 0);

                /* reserved for future use */

                return UNPROCESSABLE_MESSAGE;
            }
            else
            {
                dns_message_set_status(mesg, FP_PACKET_DROPPED);

                return INVALID_MESSAGE;
            }
        }
    }
}

static ya_result dns_message_find_ar_start(dns_message_t *mesg)
{
    const uint8_t      *buffer = dns_message_get_buffer_const(mesg);

    dns_packet_reader_t purd;
    purd.packet = buffer;
    purd.packet_size = dns_message_get_size(mesg);

    if(mesg->_ar_start == NULL)
    {
        uint32_t ar_index = ntohs(MESSAGE_AN(buffer)) + ntohs(MESSAGE_NS(buffer));

        // we know it's exactly one

        purd.packet_offset = DNS_HEADER_LENGTH; // header

        if(FAIL(dns_packet_reader_skip_query_section(&purd)))
        {
            return UNPROCESSABLE_MESSAGE;
        }

        while(ar_index > 0) /* Skip all until AR records */
        {
            /*
             * It should be in this kind of processing that we read the EDNS0 flag
             */

            if(FAIL(dns_packet_reader_skip_record(&purd)))
            {
                return UNPROCESSABLE_MESSAGE;
            }

            ar_index--;
        }

        mesg->_ar_start = &mesg->_buffer[purd.packet_offset];
    }

    return SUCCESS;
}

int dns_message_process_lenient(dns_message_t *mesg)
{
    if(dns_message_get_size(mesg) < DNS_HEADER_LENGTH)
    {
        return UNPROCESSABLE_MESSAGE;
    }

    uint8_t *s = dns_message_process_copy_fqdn(mesg);

    if(s == NULL)
    {
        return UNPROCESSABLE_MESSAGE;
    }

    /**
     * @note Past this point, a message could be processable.
     *       It's the right place to reset the message's defaults.
     *
     */

    dns_message_reset_buffer_size(mesg);
    mesg->_ar_start = NULL;
#if DNSCORE_HAS_TSIG_SUPPORT
    // mesg->_tsig.tsig = NULL;
#endif
    mesg->_edns0_opt_ttl.as_u32 = 0;
    dns_message_edns0_clear(mesg);
#if DNSCORE_HAS_NSID_SUPPORT
    dns_message_clear_nsid(mesg);
#endif

    /*
     * Handle the OPT and TSIG records
     */

    {
        ya_result ret;
        uint16_t  ar_count_ne;

        if((ar_count_ne = dns_message_get_additional_count_ne(mesg)) != 0)
        {
            if(FAIL(ret = dns_message_find_ar_start(mesg)))
            {
                return ret;
            }

            if(FAIL(ret = dns_message_process_answer_additionals(mesg, ar_count_ne)))
            {
                return ret;
            }
        }
#if DNSCORE_HAS_TSIG_SUPPORT
        else
        {
            mesg->_tsig.tsig = NULL;

            /* cut the trash here */
            /*message_set_size(mesg, s - buffer);(*/
        }
#endif
    }

    /* At this point the TSIG has been computed and removed */

    dns_message_set_status(mesg, (mesg->_buffer[3] & 0xf));

    return SUCCESS;
}

#if ONLY_USED_IN_TESTS_XFR
// This is only used in tests/xfr
// I'll have to analysed it later
// Right now I'm disabling it.

// ?
static ya_result dns_message_answer_verify_additionals(dns_message_t *mesg, dns_packet_reader_t *purd, int ar_count)
{
    /* We are now at the start of the ar */

    struct type_class_ttl_rdlen *tctr;
#if DNSCORE_HAS_TSIG_SUPPORT
    uint32_t record_offset;
    uint8_t  fqdn[DOMAIN_LENGTH_MAX];
#endif

    while(ar_count-- > 0)
    {
#if DNSCORE_HAS_TSIG_SUPPORT
        record_offset = purd->offset;
#endif

        if(FAIL(dns_packet_reader_read_fqdn(purd, fqdn, sizeof(fqdn))))
        {
            /* oops */

            dns_message_set_status(mesg, FP_ERROR_READING_QUERY);

            return UNPROCESSABLE_MESSAGE;
        }

        if(dns_packet_reader_available(purd) < 10)
        {
            dns_message_set_status(mesg, FP_ERROR_READING_QUERY);

            return UNPROCESSABLE_MESSAGE;
        }

        tctr = (struct type_class_ttl_rdlen *)dns_packet_reader_get_next_u8_ptr_const(purd);

        purd->offset += 10;

        switch(tctr->qtype)
        {
                /*
                 * EDNS (0)
                 */

            case TYPE_OPT:
            {
                /**
                 * Handle EDNS
                 */

                dns_message_sub_additional_count(mesg, 1);

                if((tctr->ttl & NU32(0x00ff0000)) == 0) /* ensure version is 0 */
                {
                    if(fqdn[0] == '\0')
                    {
                        dns_message_set_buffer_size(mesg, edns0_maxsize); /* our own limit, taken from the config file */
                        dns_message_edns0_set(mesg);
                        mesg->_edns0_opt_ttl.as_u32 = tctr->ttl;

                        log_debug("EDNS: udp-size=%d rcode-ext=%08x desc=%04x", dns_message_get_size(mesg), tctr->ttl, ntohs(tctr->rdlen));
                        continue;
                    }
                }
                else
                {
                    dns_message_set_status(mesg, FP_EDNS_BAD_VERSION);
                    dns_message_set_buffer_size(mesg, edns0_maxsize);
                    dns_message_edns0_set(mesg);
                    mesg->_edns0_opt_ttl.as_u32 = 0;

                    break;
                }

                log_debug("OPT record is not processable (broken or not supported)");

                return UNPROCESSABLE_MESSAGE;
            }
#if DNSCORE_HAS_TSIG_SUPPORT

                /*
                 * TSIG
                 */

            case TYPE_TSIG:
            {
                if(ar_count == 0)
                {
                    /*
                     * It looks like a TSIG ...
                     */

                    ya_result return_code;

                    if(dns_message_has_tsig(mesg))
                    {
                        if(dnsname_equals(fqdn, dns_message_tsig_get_name(mesg)))
                        {
                            if(FAIL(return_code = tsig_process_answer(mesg, purd, record_offset, tctr)))
                            {
                                log_err("%r answer error from %{sockaddr}", return_code, dns_message_get_sender_sa(mesg));

                                return return_code;
                            }
                        }
                        else
                        {
                            log_err("TSIG name mismatch from %{sockaddr}", dns_message_get_sender_sa(mesg));

                            return UNPROCESSABLE_MESSAGE;
                        }
                    }
                    else // no tsig
                    {
                        log_err("answer error from %{sockaddr}: TSIG when none expected", dns_message_get_sender_sa(mesg));

                        dns_message_set_status(mesg, FP_TSIG_UNEXPECTED);

                        return UNPROCESSABLE_MESSAGE;
                    }

                    return SUCCESS; /* we know there is no need to loop anymore */
                }
                else
                {
                    /*
                     * Error: TSIG is not the last AR record
                     */

                    log_debug("TSIG record is not the last AR");

                    dns_message_set_status(mesg, FP_TSIG_IS_NOT_LAST);

                    return UNPROCESSABLE_MESSAGE;
                }
            }
#endif
            default:
            {
                /* Unhandled AR TYPE */
#if DEBUG
                log_debug("skipping AR type %{dnstype}", &tctr->qtype);
#endif
                purd->offset += ntohs(tctr->rdlen);
                break;
            }
        }
    } /* While there are AR to process */

    return SUCCESS;
}

int dns_message_answer_verify(dns_message_t *mesg)
{
    if(dns_message_get_size(mesg) < DNS_HEADER_LENGTH)
    {
        return UNPROCESSABLE_MESSAGE;
    }

    uint8_t *after_query_section;

    if(dns_message_get_query_count_ne(mesg) != 0)
    {
        after_query_section = dns_message_process_copy_fqdn(mesg); // canonises the query fqdn and fetches its type and class

        if(after_query_section == NULL)
        {
            return UNPROCESSABLE_MESSAGE;
        }
    }
    else
    {
        if(mesg->_tcp_serial == 0) // needed at the beginning of the stream
        {
            return UNPROCESSABLE_MESSAGE;
        }

        after_query_section = dns_message_get_query_section_ptr(mesg); // as there is no query section
    }

    /**
     * @note Past this point, a message could be processable.
     *       It's the right place to reset the message's defaults.
     *
     */

    uint16_t ar_count_ne;

    if((ar_count_ne = dns_message_get_additional_count_ne(mesg)) != 0)
    {
        // find the additional section

        dns_packet_reader_t purd;
        purd.packet = dns_message_get_buffer_const(mesg);
        purd.packet_size = dns_message_get_size(mesg);
        purd.offset = after_query_section - purd.packet;

        // skip all records before the additional section

        for(int_fast32_t ar_index = dns_message_get_answer_count(mesg) + dns_message_get_authority_count(mesg); ar_index > 0; --ar_index)
        {
            if(FAIL(dns_packet_reader_skip_record(&purd)))
            {
                return UNPROCESSABLE_MESSAGE;
            }
        }

        mesg->_ar_start = &mesg->_buffer[purd.offset];

        // ar_start is ready

        dns_message_answer_verify_additionals(mesg, &purd, ntohs(ar_count_ne));
    }
    else
    {
        mesg->_ar_start = NULL;
        mesg->_edns0_opt_ttl.as_u32 = 0;
        dns_message_edns0_clear(mesg);
#if DNSCORE_HAS_NSID_SUPPORT
        dns_message_clear_nsid(mesg);
#endif
    }

    dns_message_set_status(mesg, FP_MESG_OK);

    return OK;
}

#endif

/**
 * This will add an OPT record to the end of the message.
 * It doesn't check there is already an OPT present.
 * Cookies, if set, are added.
 * NSID isn't handled at this level so it is ignored.
 *
 * @param mesg the message
 *
 * @return an error code (e.g. the buffer is full)
 */

ya_result dns_message_add_opt(dns_message_t *mesg)
{
    // go to the end of the buffer
    // try to add the record
    // if it doesn't overflow, add the record and increment the AR count

    uint8_t *buffer_end = dns_message_get_buffer_limit(mesg);
    uint8_t *buffer_limit = dns_message_get_buffer(mesg) + dns_message_get_buffer_size_max(mesg);
    size_t   avail = buffer_limit - buffer_end;

    bool     answer = dns_message_is_answer(mesg);
    uint16_t rdata_size = 0;

    if(answer)
    {
        if(dns_message_has_nsid(mesg))
        {
            rdata_size += edns0_nsid_option_wire_size;
        }
    }

    if(dns_message_has_cookie(mesg))
    {
        rdata_size += mesg->_cookie.size + 4;
    }

    if(avail < 11U + rdata_size)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    dns_message_set_size(mesg, dns_message_get_size(mesg) + 11 + rdata_size);

    // 00 00 29 [MAX SIZE:16] [FLAGS:32] [RDATALEN] [FIELDS]
    uint8_t *p = buffer_end;
    *p = 0x00;
    p++;
    *p = 0x00;
    p++;
    *p = 0x29;
    p++;
    SET_U16_AT_P(p, htons(dns_message_edns0_getmaxsize()));
    p += 2;
    SET_U32_AT_P(p, dns_message_get_edns0_opt_ttl(mesg));
    p += 4;
    SET_U16_AT_P(p, htons(rdata_size));
    p += 2;

    if(answer)
    {
        if(dns_message_has_nsid(mesg))
        {
            memcpy(p, edns0_nsid_option_wire, edns0_nsid_option_wire_size);
            p += edns0_nsid_option_wire_size;
        }
    }

    if(dns_message_has_cookie(mesg))
    {
        SET_U16_AT_P(p, OPT_COOKIE);
        p += 2;
        SET_U16_AT_P(p, htons(mesg->_cookie.size));
        p += 2;
        memcpy(p, mesg->_cookie.bytes, mesg->_cookie.size);
    }

    dns_message_set_additional_count(mesg, dns_message_get_additional_count(mesg) + 1);

    return SUCCESS;
}

void dns_message_transform_to_error(dns_message_t *mesg)
{
    dns_message_set_answer(mesg);
    dns_message_set_rcode(mesg, dns_message_get_status(mesg));

    if(dns_message_get_status(mesg) == RCODE_FORMERR)
    {
        SET_U64_AT(mesg->_buffer[4], 0);
        dns_message_set_size(mesg, DNS_HEADER_LENGTH);
    }
    else
    {
        dns_message_set_size(mesg, dns_message_get_additional_section_ptr(mesg) - mesg->_buffer);
    }

    dns_message_edns0_append(mesg);
}

void dns_message_transform_to_signed_error(dns_message_t *mesg)
{
    dns_message_transform_to_error(mesg);

    if(dns_message_has_tsig(mesg))
    {
        tsig_sign_answer(mesg);
    }
}

/**
 * Create a query message.
 *
 * @param mesg the message
 * @param id the id of the message
 * @param qname the fqdn to query
 * @param qtype the type to query
 * @param qclass the class to query
 */

void dns_message_make_query(dns_message_t *mesg, uint16_t id, const uint8_t *qname, uint16_t qtype, uint16_t qclass)
{
#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000000000010000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000000000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#endif
    dns_message_set_id(mesg, id);

    dnsname_canonize(qname, mesg->_canonised_fqdn);

    ya_result qname_len = dnsname_len(qname);
    uint8_t  *tc = dns_message_get_query_section_ptr(mesg);
    memcpy(tc, qname, qname_len);
    tc += qname_len;
    SET_U16_AT(tc[0], qtype);
    tc += 2;
    SET_U16_AT(tc[0], qclass);
    tc += 2;
#if DNSCORE_HAS_TSIG_SUPPORT
    mesg->_tsig.tsig = NULL;
#endif

    mesg->_ar_start = tc;
    dns_message_reset_buffer_size(mesg);
    dns_message_set_size(mesg, tc - dns_message_get_buffer_const(mesg));
    dns_message_set_status(mesg, FP_MESG_OK);
    mesg->_edns0_opt_ttl.as_u32 = 0;
}

/**
 * Create a query message.
 *
 * @param mesg the message
 * @param id the id of the message
 * @param qname the fqdn to query
 * @param qtype the type to query
 * @param qclass the class to query
 * @param flags adds an OPT if not zero
 */

void dns_message_make_query_ex(dns_message_t *mesg, uint16_t id, const uint8_t *qname, uint16_t qtype, uint16_t qclass, uint32_t flags)
{
#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000000000010000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000000000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#endif
    dns_message_set_id(mesg, id);

    dnsname_canonize(qname, mesg->_canonised_fqdn);

    ya_result qname_len = dnsname_len(qname);
    uint8_t  *tc = dns_message_get_query_section_ptr(mesg);
    memcpy(tc, qname, qname_len);
    tc += qname_len;
    SET_U16_AT(tc[0], qtype);
    tc += 2;
    SET_U16_AT(tc[0], qclass);
    tc += 2;

    mesg->_ar_start = tc;
    dns_message_set_size(mesg, tc - dns_message_get_buffer_const(mesg));
    mesg->_edns0_opt_ttl.as_u32 = 0;

    dns_message_set_status(mesg, FP_MESG_OK);
#if DNSCORE_HAS_TSIG_SUPPORT
    dns_message_tsig_clear_key(mesg);
#endif

    if(dns_message_has_edns0(mesg) || (flags != 0))
    {
        dns_message_set_additional_count_ne(mesg, NETWORK_ONE_16);

        mesg->_edns0_opt_ttl.as_u32 |= MESSAGE_EDNS0_DNSSEC;

        uint8_t *buffer = dns_message_get_buffer_limit(mesg);
        buffer[0] = 0;
        buffer[1] = 0;                                 // TYPE
        buffer[2] = 0x29;                              // no alternative for now
        buffer[3] = edns0_maxsize >> 8;                // CLASS = SIZE
        buffer[4] = edns0_maxsize;                     //
        buffer[5] = dns_message_get_status(mesg) >> 4; // extended RCODE & FLAGS
        buffer[6] = 0x00 /* mesg->_rcode_ext >> 16 */;
        buffer[7] = 0x80 /* mesg->_rcode_ext >> 8 */;
        buffer[8] = 0x00 /* mesg->_rcode_ext */;
        buffer[9] = 0; // RDATA descriptor
        buffer[10] = 0;

        dns_message_increase_size(mesg, 11);
    }
}

void dns_message_make_query_ex_with_edns0(dns_message_t *mesg, uint16_t id, const uint8_t *qname, uint16_t qtype, uint16_t qclass, uint32_t edns0_ttl)
{
#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000000000010000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000000000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#endif
    dns_message_set_id(mesg, id);

    dnsname_canonize(qname, mesg->_canonised_fqdn);

    ya_result qname_len = dnsname_len(qname);
    uint8_t  *tc = dns_message_get_query_section_ptr(mesg);
    memcpy(tc, qname, qname_len);
    tc += qname_len;
    SET_U16_AT(tc[0], qtype);
    tc += 2;
    SET_U16_AT(tc[0], qclass);
    tc += 2;

    mesg->_ar_start = tc;
    dns_message_set_size(mesg, tc - dns_message_get_buffer_const(mesg));
    mesg->_edns0_opt_ttl.as_u32 = edns0_ttl;

    dns_message_set_status(mesg, FP_MESG_OK);
#if DNSCORE_HAS_TSIG_SUPPORT
    dns_message_tsig_clear_key(mesg);
#endif

    dns_message_set_additional_count_ne(mesg, NETWORK_ONE_16);
    // mesg->_rcode_ext |= MESSAGE_EDNS0_DNSSEC;

    uint8_t *buffer = dns_message_get_buffer_limit(mesg);
    buffer[0] = 0;
    buffer[1] = 0;                                 // TYPE
    buffer[2] = 0x29;                              // no alternative for now
    buffer[3] = edns0_maxsize >> 8;                // CLASS = SIZE
    buffer[4] = edns0_maxsize;                     //
    buffer[5] = dns_message_get_status(mesg) >> 4; // extended RCODE & FLAGS
    buffer[6] = edns0_ttl >> 16;
    buffer[7] = edns0_ttl >> 8;
    buffer[8] = edns0_ttl;
    buffer[9] = 0; // RDATA descriptor
    buffer[10] = 0;

    dns_message_increase_size(mesg, 11);
}

void dns_message_make_message(dns_message_t *mesg, uint16_t id, const uint8_t *qname, uint16_t qtype, uint16_t qclass, dns_packet_writer_t *uninitialised_packet_writer)
{
    assert(uninitialised_packet_writer != NULL);
    assert(dns_packet_writer_get_offset(uninitialised_packet_writer) <= dns_message_get_buffer_size_max(mesg));

#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000000000010000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000000000LL);
    SET_U32_AT(mesg->_buffer[8], 0);
#endif
    dns_message_set_id(mesg, id);

    dnsname_canonize(qname, mesg->_canonised_fqdn);

    dns_packet_writer_create(uninitialised_packet_writer, dns_message_get_buffer(mesg), DNSPACKET_LENGTH_MAX);

    dns_packet_writer_add_fqdn(uninitialised_packet_writer, qname);
    dns_packet_writer_add_u16(uninitialised_packet_writer, qtype);
    dns_packet_writer_add_u16(uninitialised_packet_writer, qclass);
#if DNSCORE_HAS_TSIG_SUPPORT
    dns_message_tsig_clear_key(mesg);
#endif

    dns_message_set_size(mesg, dns_packet_writer_get_offset(uninitialised_packet_writer));
    mesg->_ar_start = dns_message_get_buffer_limit(mesg);

    dns_message_reset_buffer_size(mesg);

    dns_message_set_status(mesg, FP_MESG_OK);
}

void dns_message_make_notify(dns_message_t *mesg, uint16_t id, const uint8_t *qname, uint16_t qtype, uint16_t qclass)
{
#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000240000010000LL); // notify + AA
    SET_U32_AT(mesg->_buffer[8], 0);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000240000LL); // notify + AA
    SET_U32_AT(mesg->_buffer[8], 0);
#endif
    dns_message_set_id(mesg, id);

    dnsname_canonize(qname, mesg->_canonised_fqdn);

    ya_result qname_len = dnsname_len(qname);
    uint8_t  *tc = dns_message_get_query_section_ptr(mesg);
    memcpy(tc, qname, qname_len);
    tc += qname_len;
    SET_U16_AT(tc[0], qtype);
    tc += 2;
    SET_U16_AT(tc[0], qclass);
    tc += 2;
#if DNSCORE_HAS_TSIG_SUPPORT
    dns_message_tsig_clear_key(mesg);
#endif

    dns_message_set_size(mesg, tc - dns_message_get_buffer_const(mesg));
    mesg->_ar_start = tc;
    dns_message_set_status(mesg, FP_MESG_OK);
}

void dns_message_make_ixfr_query(dns_message_t *mesg, uint16_t id, const uint8_t *qname, int32_t soa_ttl, uint16_t soa_rdata_size, const uint8_t *soa_rdata)
{
    dns_packet_writer_t pw;

#ifdef WORDS_BIGENDIAN
    SET_U64_AT(mesg->_buffer[0], 0x0000000000010000LL);
    SET_U32_AT(mesg->_buffer[8], 0x00010000);
#else
    SET_U64_AT(mesg->_buffer[0], 0x0000010000000000LL);
    SET_U32_AT(mesg->_buffer[8], 0x00000100);
#endif

    dns_message_set_id(mesg, id);

    dnsname_canonize(qname, mesg->_canonised_fqdn);

    dns_packet_writer_create(&pw, dns_message_get_buffer(mesg), dns_message_get_buffer_size_max(mesg));

    dns_packet_writer_add_fqdn(&pw, qname);
    dns_packet_writer_add_u16(&pw, TYPE_IXFR);
    dns_packet_writer_add_u16(&pw, CLASS_IN);

    dns_packet_writer_add_fqdn(&pw, qname);
    dns_packet_writer_add_u16(&pw, TYPE_SOA);
    dns_packet_writer_add_u16(&pw, CLASS_IN);
    dns_packet_writer_add_u32(&pw, htonl(soa_ttl));
    dns_packet_writer_add_rdata(&pw, TYPE_SOA, soa_rdata, soa_rdata_size);

#if DNSCORE_HAS_TSIG_SUPPORT
    dns_message_tsig_clear_key(mesg);
#endif
    mesg->_ar_start = &mesg->_buffer[dns_packet_writer_get_offset(&pw)];
    dns_message_reset_buffer_size(mesg);
    dns_message_set_size(mesg, dns_packet_writer_get_offset(&pw));
    dns_message_set_status(mesg, FP_MESG_OK);
}

#if DNSCORE_HAS_TSIG_SUPPORT

ya_result dns_message_sign_query_by_name(dns_message_t *mesg, const uint8_t *tsig_name)
{
    const tsig_key_t *key = tsig_get(tsig_name);

    return dns_message_sign_query(mesg, key);
}

ya_result dns_message_sign_query_by_name_with_epoch_and_fudge(dns_message_t *mesg, const uint8_t *tsig_name, int64_t epoch, uint16_t fudge)
{
    const tsig_key_t *key = tsig_get(tsig_name);

    return dns_message_sign_query_with_epoch_and_fudge(mesg, key, epoch, fudge);
}

ya_result dns_message_sign_answer(dns_message_t *mesg)
{
    ya_result ret = tsig_sign_answer(mesg);
    return ret;
}

ya_result dns_message_sign_query(dns_message_t *mesg, const tsig_key_t *key)
{
    if(key != NULL)
    {
        ZEROMEMORY(&mesg->_tsig, sizeof(message_tsig_t));

        mesg->_tsig.tsig = key;
        mesg->_tsig.mac_size = mesg->_tsig.tsig->mac_size;

        uint64_t now = time(NULL);
        mesg->_tsig.timehi = htons((uint16_t)(now >> 32));
        mesg->_tsig.timelo = htonl((uint32_t)now);

        mesg->_tsig.fudge = htons(g_dns_message_fudge); /* 5m */

        mesg->_tsig.mac_algorithm = key->mac_algorithm;

        mesg->_tsig.original_id = dns_message_get_id(mesg);

        // mesg->tsig.error = 0;     zeromem
        // mesg->tsig.other_len = 0; zeromem

        return tsig_sign_query(mesg);
    }

    return TSIG_BADKEY;
}

ya_result dns_message_sign_query_with_epoch_and_fudge(dns_message_t *mesg, const tsig_key_t *key, int64_t epoch, uint16_t fudge)
{
    if(key != NULL)
    {
        ZEROMEMORY(&mesg->_tsig, sizeof(message_tsig_t));

        mesg->_tsig.tsig = key;
        mesg->_tsig.mac_size = mesg->_tsig.tsig->mac_size;

        mesg->_tsig.timehi = htons((uint16_t)(epoch >> 32));
        mesg->_tsig.timelo = htonl((uint32_t)epoch);

        mesg->_tsig.fudge = htons(fudge); /* 5m */

        mesg->_tsig.mac_algorithm = key->mac_algorithm;

        mesg->_tsig.original_id = dns_message_get_id(mesg);

        // mesg->tsig.error = 0;     zeromem
        // mesg->tsig.other_len = 0; zeromem

        return tsig_sign_query(mesg);
    }

    return TSIG_BADKEY;
}

#endif

void dns_message_make_error(dns_message_t *mesg, uint16_t error_code)
{
    MESSAGE_FLAGS_OR(mesg->_buffer, QR_BITS, error_code);
#ifdef WORDS_BIGENDIAN
    SET_U32_AT(mesg->_buffer[4], 0x00010000);
    SET_U32_AT(mesg->_buffer[8], 0x00000000);
#else
    SET_U32_AT(mesg->_buffer[4], 0x00000100);
    SET_U32_AT(mesg->_buffer[8], 0x00000000);
#endif

    dns_message_reset_buffer_size(mesg);
    // + 4 is for TYPE + CLASS
    dns_message_set_size(mesg, DNS_HEADER_LENGTH + 4 + dnsname_len(dns_message_get_query_section_ptr(mesg)));
    mesg->_ar_start = dns_message_get_buffer_limit(mesg);
    dns_message_set_status(mesg, (finger_print)error_code);
}

void dns_message_make_signed_error(dns_message_t *mesg, uint16_t error_code)
{
    dns_message_make_error(mesg, error_code);

    if(dns_message_has_tsig(mesg))
    {
        tsig_sign_answer(mesg);
    }
}

ya_result dns_message_make_error_and_reply_tcp(dns_message_t *mesg, uint16_t error_code, int tcpfd)
{
    ya_result ret;

    dns_message_make_signed_error(mesg, error_code);

    if(ISOK(ret = dns_message_send_tcp(mesg, tcpfd)))
    {
        //
    }
    else
    {
        tcp_set_abortive_close(tcpfd);
    }

    return ret;
}

ssize_t dns_message_make_error_and_reply_tcp_with_default_minimum_throughput(dns_message_t *mesg, uint16_t error_code, int tcpfd)
{
    ssize_t ret;
    dns_message_make_signed_error(mesg, error_code);

    ret = dns_message_update_length_send_tcp_with_default_minimum_throughput(mesg, tcpfd);

    return ret;
}

#if 0
/**
 * Creates an answer with an OPT error code
 */

void
dns_message_make_error_ext(dns_message_t *mesg, uint32_t error_code)
{
    MESSAGE_FLAGS_OR(mesg->_buffer, QR_BITS, error_code & 0x0f);
#ifdef WORDS_BIGENDIAN
    SET_U32_AT(mesg->_buffer[4], 0x00010000);
    SET_U32_AT(mesg->_buffer[8], 0x00000000);
#else
    SET_U32_AT(mesg->_buffer[4], 0x00000100);
    SET_U32_AT(mesg->_buffer[8], 0x00000000);
#endif

    dns_message_reset_buffer_size(mesg);
    // + 4 is for TYPE + CLASS 
    size_t query_section_size = DNS_HEADER_LENGTH + 4 + dnsname_len(dns_message_get_query_section_ptr(mesg));
    mesg->_ar_start = &mesg->_buffer[query_section_size];
    
    // the upper 8 bits of the error code are to be put in OPT

    uint8_t *edns0 = mesg->_ar_start;
    edns0[0] = 0;                
    SET_U16_AT(edns0[1], TYPE_OPT);
    SET_U16_AT(edns0[3], htons(dns_message_edns0_getmaxsize()));
    SET_U32_AT(edns0[5], (((error_code & 0xff0) << 24) | (dns_message_get_rcode_ext(mesg) & 0x00ffffff)));
    SET_U16_AT(edns0[9], 0);
    dns_message_set_size(mesg, query_section_size + 11);
    dns_message_set_status(mesg, (finger_print) error_code);
}

#endif

ya_result dns_message_query_tcp(dns_message_t *mesg, const host_address_t *server)
{
    /* connect the server */

    ya_result return_value;

    if(ISOK(return_value = dns_message_set_sender_from_host_address(mesg, server)))
    {
        int sockfd;

        if((sockfd = socket(dns_message_get_sender_sa(mesg)->sa_family, SOCK_STREAM, SOCKET_PROTOCOL_FROM_TYPE(SOCK_STREAM))) >= 0)
        {
            fd_setcloseonexec(sockfd);

            socklen_t sa_len = return_value;

            if(connect(sockfd, dns_message_get_sender_sa(mesg), sa_len) == 0)
            {
#if DEBUG
                log_debug("sending %d+2 bytes to %{sockaddr} (tcp)", dns_message_get_size(mesg), dns_message_get_sender(mesg));
                log_memdump_ex(g_system_logger, MSG_DEBUG5, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 16, OSPRINT_DUMP_HEXTEXT);
#endif
                if(dns_message_send_tcp(mesg, sockfd) == (ssize_t)dns_message_get_size(mesg) + 2)
                {
                    uint16_t tcp_len;

                    shutdown(sockfd, SHUT_WR);

                    if(readfully(sockfd, &tcp_len, 2) == 2)
                    {
                        tcp_len = ntohs(tcp_len);

                        if(readfully(sockfd, dns_message_get_buffer(mesg), tcp_len) == tcp_len)
                        {
                            /*
                             * test the answser
                             * test the TSIG if any
                             */

                            dns_message_set_size(mesg, tcp_len);
#if DEBUG
                            log_debug("received %d bytes from %{sockaddr} (tcp)", dns_message_get_size(mesg), dns_message_get_sender(mesg));
                            log_memdump_ex(g_system_logger, MSG_DEBUG5, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 16, OSPRINT_DUMP_HEXTEXT);
#endif
                            return_value = dns_message_process_lenient(mesg);
                        }
                    }
                }
            }
            else
            {
                // Linux quirk ...

                if(errno != EINPROGRESS)
                {
                    return_value = ERRNO_ERROR;
                }
                else
                {
                    return_value = MAKE_ERRNO_ERROR(ETIMEDOUT);
                }
            }

            shutdown(sockfd, SHUT_RDWR);

            tcp_set_abortive_close(sockfd);

            socketclose_ex(sockfd);
        }
        else
        {
            return_value = ERRNO_ERROR;
        }
    }

    return return_value;
}

ya_result dns_message_query_tcp_ex(dns_message_t *mesg, const host_address_t *bindto, const host_address_t *server, dns_message_t *answer)
{
    /* connect the server */

    ya_result       ret;
    socklen_t       sa_len = 0; // silences a silly "maybe-uninitialized"
    socketaddress_t sa;

    if((mesg == NULL) || (server == NULL) || (answer == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    if(bindto != NULL)
    {
        ret = host_address2sockaddr(bindto, &sa);
        if(FAIL(ret))
        {
            return ret;
        }

        sa_len = (socklen_t)ret;
    }

    if(ISOK(ret = dns_message_set_sender_from_host_address(mesg, server)))
    {
        int sockfd;

        if((sockfd = socket(dns_message_get_sender_sa(mesg)->sa_family, SOCK_STREAM, SOCKET_PROTOCOL_FROM_TYPE(SOCK_STREAM))) >= 0)
        {
            fd_setcloseonexec(sockfd);

            if(bindto != NULL)
            {
                int on = 1;
                if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on))))
                {
                    ret = ERRNO_ERROR;
                    close(sockfd);
                    return ret;
                }
#ifdef SO_REUSEPORT
                if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on))))
                {
                    ret = ERRNO_ERROR;
                    close(sockfd);
                    return ret;
                }
#endif
                if(bind(sockfd, &sa.sa, sa_len) < 0) // sa_len initialised if bindto != NULL, which is the case
                {
                    ret = ERRNO_ERROR;
                    socketclose_ex(sockfd);
                    return ret;
                }
            }

            if(connect(sockfd, dns_message_get_sender_sa(mesg), dns_message_get_sender_size(mesg)) == 0)
            {
#if DEBUG
                log_debug("sending %d bytes to %{sockaddr} (tcp)", dns_message_get_size(mesg), dns_message_get_sender(mesg));
                log_memdump_ex(g_system_logger, MSG_DEBUG5, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 16, OSPRINT_DUMP_HEXTEXT);
#endif
                if(dns_message_send_tcp(mesg, sockfd) == (ssize_t)dns_message_get_size(mesg) + 2)
                {
                    uint16_t tcp_len;

                    shutdown(sockfd, SHUT_WR);

                    if(readfully(sockfd, &tcp_len, 2) == 2)
                    {
                        tcp_len = ntohs(tcp_len);

                        if(readfully(sockfd, dns_message_get_buffer(answer), tcp_len) == tcp_len)
                        {
                            /*
                             * test the answser
                             * test the TSIG if any
                             */

                            dns_message_set_size(answer, tcp_len);
#if DNSCORE_HAS_TSIG_SUPPORT
                            dns_message_tsig_copy_from(answer, mesg);
#endif
                            dns_message_copy_sender_from(answer, mesg);
#if DEBUG
                            log_debug("received %d bytes from %{sockaddr} (tcp)", dns_message_get_size(answer), dns_message_get_sender_sa(answer));
                            log_memdump_ex(g_system_logger, MSG_DEBUG5, dns_message_get_buffer_const(answer), dns_message_get_size(answer), 16, OSPRINT_DUMP_HEXTEXT);
#endif
                            ret = dns_message_process_lenient(answer);
                        }
                    }
                }
            }
            else
            {
                // Linux quirk ...

                if(errno != EINPROGRESS)
                {
                    ret = ERRNO_ERROR;
                }
                else
                {
                    ret = MAKE_ERRNO_ERROR(ETIMEDOUT);
                }
            }

            shutdown(sockfd, SHUT_RDWR);

            tcp_set_abortive_close(sockfd);

            socketclose_ex(sockfd);
        }
        else
        {
            ret = ERRNO_ERROR;
        }
    }

    return ret;
}

ya_result dns_message_query_tcp_with_timeout(dns_message_t *mesg, const host_address_t *server, uint8_t to_sec)
{
    ya_result ret;

    if((mesg == NULL) || (server == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    input_stream_t  is;
    output_stream_t os;

    if(ISOK(ret = tcp_input_output_stream_connect_host_address(server, &is, &os, to_sec)))
    {
        int sockfd = fd_input_stream_get_filedescriptor(&is);

        tcp_set_sendtimeout(sockfd, to_sec, 0);
        tcp_set_recvtimeout(sockfd, to_sec, 0);

        if(ISOK(ret = dns_message_write_tcp(mesg, &os)))
        {
            output_stream_flush(&os);

            shutdown(sockfd, SHUT_WR);

            uint16_t id = dns_message_get_id(mesg);
#if DEBUG
            dns_message_debug_trash_buffer(mesg);
#endif
            uint16_t len;
#if DEBUG
            len = ~0;
#endif
            if(ISOK(ret = input_stream_read_nu16(&is, &len)))
            {
                if(ISOK(ret = input_stream_read_fully(&is, dns_message_get_buffer(mesg), len)))
                {
                    dns_message_set_size(mesg, ret);

                    if(dns_message_get_id(mesg) != id)
                    {
                        ret = MESSAGE_HAS_WRONG_ID;
                    }
                    else if(!dns_message_is_answer(mesg))
                    {
                        ret = MESSAGE_IS_NOT_AN_ANSWER;
                    }
                    else if(dns_message_get_rcode(mesg) != RCODE_NOERROR)
                    {
                        ret = MAKE_RCODE_ERROR(dns_message_get_rcode(mesg));
                    }
                }
                else
                {
                    dns_message_set_size(mesg, 0);
                }
            }
        }

        shutdown(sockfd, SHUT_RDWR);

        tcp_set_abortive_close(sockfd);

        output_stream_close(&os);
        output_stream_close(&is);
    }

    return ret;
}

ya_result dns_message_query_tcp_with_timeout_ex(dns_message_t *mesg, const host_address_t *server, dns_message_t *answer, uint8_t to_sec)
{
    /* connect the server */

    ya_result return_value;

    if(ISOK(return_value = dns_message_set_sender_from_host_address(mesg, server)))
    {
        int sockfd;

        if((sockfd = socket(dns_message_get_sender_sa(mesg)->sa_family, SOCK_STREAM, SOCKET_PROTOCOL_FROM_TYPE(SOCK_STREAM))) >= 0)
        {
            fd_setcloseonexec(sockfd);

            socklen_t sa_len = return_value;

            if(connect(sockfd, dns_message_get_sender_sa(mesg), sa_len) == 0)
            {
#if DEBUG
                log_debug("sending %d bytes to %{sockaddr} (tcp)", dns_message_get_size(mesg), dns_message_get_sender(mesg));
                log_memdump_ex(g_system_logger, MSG_DEBUG5, dns_message_get_buffer_const(mesg), dns_message_get_size(mesg), 16, OSPRINT_DUMP_HEXTEXT);
#endif
                tcp_set_sendtimeout(sockfd, to_sec, 0);
                tcp_set_recvtimeout(sockfd, to_sec, 0);

                ssize_t n = dns_message_send_tcp(mesg, sockfd);

                if(n == (ssize_t)dns_message_get_size(mesg) + 2)
                {
                    uint16_t tcp_len;

                    shutdown(sockfd, SHUT_WR);

                    n = readfully(sockfd, &tcp_len, 2);

                    if(n == 2)
                    {
                        tcp_len = ntohs(tcp_len);

                        n = readfully(sockfd, dns_message_get_buffer(answer), tcp_len);

                        if(n == tcp_len)
                        {
                            /*
                             * test the answser
                             * test the TSIG if any
                             */

                            dns_message_set_size(answer, tcp_len);
#if DNSCORE_HAS_TSIG_SUPPORT
                            dns_message_tsig_copy_from(answer, mesg);
#endif
                            dns_message_copy_sender_from(answer, mesg);
#if DEBUG
                            log_debug("received %d bytes from %{sockaddr} (tcp)", dns_message_get_size(answer), dns_message_get_sender_sa(answer));
                            log_memdump_ex(g_system_logger, MSG_DEBUG5, dns_message_get_buffer_const(answer), dns_message_get_size(answer), 16, OSPRINT_DUMP_HEXTEXT);
#endif
                            return_value = dns_message_process_lenient(answer);
                        }
                        else
                        {
                            return_value = UNEXPECTED_EOF;
                        }
                    }
                    else
                    {
                        return_value = UNEXPECTED_EOF;
                    }
                }
                else
                {
                    return_value = UNABLE_TO_COMPLETE_FULL_WRITE;
                }
            }
            else
            {
                // Linux quirk ...

                if(errno != EINPROGRESS)
                {
                    return_value = ERRNO_ERROR;
                }
                else
                {
                    return_value = MAKE_ERRNO_ERROR(ETIMEDOUT);
                }
            }

            shutdown(sockfd, SHUT_RDWR);

            tcp_set_abortive_close(sockfd);

            socketclose_ex(sockfd);
        }
        else
        {
            return_value = ERRNO_ERROR;
        }
    }

    return return_value;
}

ya_result dns_message_query_udp(dns_message_t *mesg, const host_address_t *server)
{
    ya_result return_code = SUCCESS;

    int       seconds = 0;
    int       useconds = 500000;

    yassert(mesg != NULL);
    yassert(server != NULL);

    return_code = dns_message_query_udp_with_timeout(mesg, server, seconds, useconds);

    return return_code;
}

ya_result dns_message_query_udp_with_timeout_and_retries(dns_message_t *mesg, const host_address_t *server, int seconds, int useconds, uint8_t retries, uint8_t flags)
{
    ya_result    return_value = SUCCESS;
    random_ctx_t rndctx = thread_pool_get_random_ctx();
    uint16_t     id;

    for(uint_fast8_t countdown = retries; countdown > 0;)
    {
        if(flags & MESSAGE_QUERY_UDP_FLAG_RESET_ID)
        {
            id = (uint16_t)random_next(rndctx);
            dns_message_set_id(mesg, id);
        }
        else
        {
            id = dns_message_get_id(mesg);
        }

        if(ISOK(return_value = dns_message_query_udp_with_timeout(mesg, server, seconds, useconds)))
        {
            if(dns_message_get_id(mesg) != id)
            {
                return_value = MESSAGE_HAS_WRONG_ID;
            }
            else if(!dns_message_is_answer(mesg))
            {
                return_value = MESSAGE_IS_NOT_AN_ANSWER;
            }
            else if(dns_message_get_rcode(mesg) != RCODE_NOERROR)
            {
                return_value = MAKE_RCODE_ERROR(dns_message_get_rcode(mesg));
            }

            break;
        }

        if(return_value == MAKE_ERRNO_ERROR(EINTR))
        {
            continue;
        }

        if(return_value != MAKE_ERRNO_ERROR(EAGAIN) || countdown <= 0)
        {
            /*
             * Do not retry for any other kind of error
             */

            break;
        }

        countdown--;

        usleep_ex(10000); /* 10 ms */

        /*
        if (flags & CHANGE_NAME_SERVER)
        {
        }
        */
    }

    return return_value;
}

ya_result dns_message_query_udp_with_timeout(dns_message_t *mesg, const host_address_t *server, int seconds, int useconds)
{
    yassert(mesg != NULL);
    yassert(server != NULL);

    /* connect the server */

    ya_result ret;

    uint16_t  id;
    bool      has_fqdn = false;
    uint8_t   fqdn[DOMAIN_LENGTH_MAX + 1];

    if(ISOK(ret = dns_message_set_sender_from_host_address(mesg, server)))
    {
        int sockfd;

        if((sockfd = socket(dns_message_get_sender_sa(mesg)->sa_family, SOCK_DGRAM, SOCKET_PROTOCOL_FROM_TYPE(SOCK_DGRAM))) >= 0)
        {
            fd_setcloseonexec(sockfd);

            tcp_set_recvtimeout(sockfd, seconds, useconds); /* half a second for UDP is a lot ... */

            int     send_size = dns_message_get_size(mesg);

            ssize_t n;

            if((n = dns_message_send_udp(mesg, sockfd)) == send_size)
            {
                id = dns_message_get_id(mesg);

                if(dns_message_get_query_count_ne(mesg) != 0)
                {
                    has_fqdn = true;
                    dnsname_copy(fqdn, dns_message_get_buffer_const(mesg) + 12);
                }

                dns_message_with_buffer_t recv_mesg_buff;
                dns_message_t            *recv_mesg = dns_message_data_with_buffer_init(&recv_mesg_buff);

                // recv_mesg._tsig.hmac = mesg->_tsig.hmac;

                int64_t time_limit = seconds;
                time_limit *= ONE_SECOND_US;
                time_limit += useconds;
                time_limit += timeus();

                ret = SUCCESS;

                while((n = dns_message_recv_udp(recv_mesg, sockfd)) >= 0)
                {
#if DEBUG
                    log_memdump_ex(g_system_logger, MSG_DEBUG5, dns_message_get_buffer_const(recv_mesg), n, 16, OSPRINT_DUMP_HEXTEXT);
#endif
                    // check the id is right

                    if(dns_message_get_id(recv_mesg) == id)
                    {
                        // check that the sender is the one we spoke to

                        if(sockaddr_equals(dns_message_get_sender_sa(mesg), dns_message_get_sender_sa(recv_mesg)))
                        {
                            dns_message_tsig_copy_from(recv_mesg, mesg);

                            if(ISOK(ret = dns_message_process_lenient(recv_mesg)))
                            {
                                // check the domain is right

                                if(!has_fqdn || dnsname_equals(fqdn, dns_message_get_canonised_fqdn(recv_mesg)))
                                {
                                    // everything checks up

                                    dns_message_copy_sender_from(mesg, recv_mesg);
                                    mesg->_ar_start = &mesg->_buffer[recv_mesg->_ar_start - recv_mesg->_buffer];
                                    mesg->_iovec.iov_len = recv_mesg->_iovec.iov_len;
                                    mesg->_edns0_opt_ttl.as_u32 = recv_mesg->_edns0_opt_ttl.as_u32;
                                    mesg->_status = recv_mesg->_status;

                                    if(mesg->_buffer_size < mesg->_iovec.iov_len)
                                    {
                                        mesg->_buffer_size = mesg->_iovec.iov_len;
                                    }

                                    mesg->_query_type = recv_mesg->_query_type;
                                    mesg->_query_class = recv_mesg->_query_class;
                                    dns_message_opt_copy_from(mesg, recv_mesg);

                                    if((mesg->_control_buffer_size = recv_mesg->_control_buffer_size) > 0)
                                    {
                                        memcpy(mesg->_msghdr_control_buffer, recv_mesg->_msghdr_control_buffer, recv_mesg->_control_buffer_size);
                                    }

                                    dnsname_copy(mesg->_canonised_fqdn, recv_mesg->_canonised_fqdn);

                                    memcpy(mesg->_buffer, recv_mesg->_buffer, recv_mesg->_iovec.iov_len);

                                    break;
                                }
                                else
                                {
                                    ret = MESSAGE_UNEXPECTED_ANSWER_DOMAIN;
                                }
                            }

                            // ret is set to an error
                        }
                        else
                        {
                            ret = INVALID_MESSAGE;
                        }
                    }
                    else
                    {
                        ret = MESSAGE_HAS_WRONG_ID;
                    }

                    int64_t time_now = timeus();

                    if(time_now >= time_limit)
                    {
                        ret = MAKE_ERRNO_ERROR(EAGAIN);
                        break;
                    }

                    int64_t time_remaining = time_limit - time_now;

                    tcp_set_recvtimeout(sockfd, time_remaining / 1000000ULL, time_remaining % 1000000ULL); /* half a second for UDP is a lot ... */
                }

                dns_message_finalize(recv_mesg);

                // recv_mesg._tsig.hmac = NULL;

                if((n < 0) && ISOK(ret))
                {
                    ret = ERRNO_ERROR;
                }

                /* timeout */
            }
            else
            {
                ret = (n < 0) ? n : ERROR;
            }

            socketclose_ex(sockfd);
        }
        else
        {
            ret = ERRNO_ERROR;
        }
    }

    return ret;
}

ya_result dns_message_query(dns_message_t *mesg, const host_address_t *server)
{
    ya_result ret;
    size_t    size;
    uint8_t   header_copy[12];

    // keep a copy of the state, in case there is truncation

    size = dns_message_get_size(mesg);
    memcpy(header_copy, mesg->_buffer, sizeof(header_copy));

    if(ISOK(ret = dns_message_query_udp_with_timeout_and_retries(mesg, server, 1, 0, 3, 0)))
    {
        if(dns_message_is_truncated(mesg))
        {
            dns_message_set_size(mesg, size);
            memcpy(mesg->_buffer, header_copy, sizeof(header_copy));

            ret = dns_message_query_tcp_with_timeout(mesg, server, 3);
        }
    }

    return ret;
}

ya_result dns_message_ixfr_query_get_serial(const dns_message_t *mesg, uint32_t *serial)
{
    dns_packet_reader_t purd;
    ya_result           return_value;

    uint8_t             domain_fqdn[DOMAIN_LENGTH_MAX];
    uint8_t             soa_fqdn[DOMAIN_LENGTH_MAX];

    dns_packet_reader_init_from_message(&purd, mesg);

    /* Keep only the query */

    if(ISOK(return_value = dns_packet_reader_read_fqdn(&purd, domain_fqdn, sizeof(domain_fqdn))))
    {
        purd.packet_offset += 4;

        /* Get the queried serial */

        if(ISOK(return_value = dns_packet_reader_read_fqdn(&purd, soa_fqdn, sizeof(soa_fqdn))))
        {
            if(dnsname_equals(domain_fqdn, soa_fqdn))
            {
                uint16_t soa_type;
                uint16_t soa_class;
                uint32_t soa_ttl;
                uint16_t soa_rdata_size;
                uint32_t soa_serial;

                if(ISOK(return_value = dns_packet_reader_read_u16(&purd, &soa_type)))
                {
                    if(soa_type == TYPE_SOA)
                    {
                        if(dns_packet_reader_available(&purd) > 2 + 4 + 2)
                        {
                            dns_packet_reader_read_u16_unchecked(&purd, &soa_class);      // checked
                            dns_packet_reader_read_u32_unchecked(&purd, &soa_ttl);        // checked
                            dns_packet_reader_read_u16_unchecked(&purd, &soa_rdata_size); // checked

                            if(ISOK(return_value = dns_packet_reader_skip_fqdn(&purd)))
                            {
                                if(ISOK(return_value = dns_packet_reader_skip_fqdn(&purd)))
                                {
                                    if(ISOK(return_value = dns_packet_reader_read_u32(&purd, &soa_serial)))
                                    {
                                        *serial = ntohl(soa_serial);
                                    }
                                }
                            }
                        }
                        else
                        {
                            return_value = MAKE_RCODE_ERROR(RCODE_FORMERR);
                        }
                    }
                    else
                    {
                        return_value = MAKE_RCODE_ERROR(RCODE_FORMERR);
                    }
                }
            }
            else
            {
                return_value = MAKE_RCODE_ERROR(RCODE_FORMERR);
            }
        }
    }

    return return_value;
}

ya_result dns_message_query_serial(const uint8_t *origin, const host_address_t *server, uint32_t *serial_out)
{
    yassert(origin != NULL);
    yassert(server != NULL);
    yassert(serial_out != NULL);

    /* do an SOA query */

    ya_result                 ret;

    random_ctx_t              rndctx = thread_pool_get_random_ctx();
    dns_message_with_buffer_t soa_query_mesg_buff;
    dns_message_t            *soa_query_mesg = dns_message_data_with_buffer_init(&soa_query_mesg_buff);

    for(uint_fast16_t countdown = 5; countdown > 0;)
    {
        uint16_t id = (uint16_t)random_next(rndctx);

        dns_message_make_query(soa_query_mesg, id, origin, TYPE_SOA, CLASS_IN);

        if(ISOK(ret = dns_message_query_udp(soa_query_mesg, server)))
        {
            const uint8_t *buffer = dns_message_get_buffer_const(soa_query_mesg);

            if(MESSAGE_QR(buffer))
            {
                if(MESSAGE_ID(buffer) == id)
                {
                    if(MESSAGE_RCODE(buffer) == RCODE_NOERROR)
                    {
                        if((MESSAGE_QD(buffer) == NETWORK_ONE_16) && ((MESSAGE_AN(buffer) == NETWORK_ONE_16) || (MESSAGE_NS(buffer) == NETWORK_ONE_16)))
                        {
                            dns_packet_reader_t pr;
                            dns_packet_reader_init_from_message_at(&pr,
                                                                   soa_query_mesg,
                                                                   DNS_HEADER_LENGTH); // scan-build false positive: if message_query_udp returns no-error,
                                                                                       // then soa_query_mesg.received is set
                            dns_packet_reader_skip_fqdn(&pr);                          // checked below
                            dns_packet_reader_skip(&pr, 4);                            // checked below

                            if(!dns_packet_reader_eof(&pr))
                            {
                                uint8_t tmp[DOMAIN_LENGTH_MAX];

                                /* read and expect an SOA */

                                if(ISOK(dns_packet_reader_read_fqdn(&pr, tmp, sizeof(tmp))))
                                {
                                    if(dnsname_equals(tmp, origin))
                                    {
                                        struct type_class_ttl_rdlen_s tctr;

                                        if(dns_packet_reader_read(&pr, &tctr, 10) == 10) // exact
                                        {
                                            if((tctr.rtype == TYPE_SOA) && (tctr.rclass == CLASS_IN))
                                            {
                                                if(ISOK(ret = dns_packet_reader_skip_fqdn(&pr)))
                                                {
                                                    if(ISOK(ret = dns_packet_reader_skip_fqdn(&pr)))
                                                    {
                                                        if(dns_packet_reader_read(&pr, tmp, 4) == 4) // exact
                                                        {
                                                            *serial_out = ntohl(GET_U32_AT(tmp[0]));

                                                            return SUCCESS;
                                                        }
                                                        else
                                                        {
                                                            ret = MAKE_RCODE_ERROR(RCODE_FORMERR);
                                                        }
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                ret = MESSAGE_UNEXPECTED_ANSWER_TYPE_CLASS;
                                            }
                                        }
                                        else
                                        {
                                            ret = MAKE_RCODE_ERROR(RCODE_FORMERR);
                                        }
                                    }
                                    else
                                    {
                                        ret = MESSAGE_UNEXPECTED_ANSWER_DOMAIN;
                                    }
                                }
                                else
                                {
                                    ret = MAKE_RCODE_ERROR(RCODE_FORMERR);
                                }
                            }
                            else
                            {
                                ret = MAKE_RCODE_ERROR(RCODE_FORMERR);
                            }
                        }
                        else
                        {
                            ret = INVALID_MESSAGE;
                        }
                    }
                    else
                    {
                        ret = MAKE_RCODE_ERROR(dns_message_get_rcode(soa_query_mesg));
                    }
                }
                else
                {
                    ret = MESSAGE_HAS_WRONG_ID;
                }
            }
            else
            {
                ret = MESSAGE_IS_NOT_AN_ANSWER;
            }

            break;
        }

        if(ret == MAKE_ERRNO_ERROR(EINTR))
        {
            continue;
        }

        if(ret != MAKE_ERRNO_ERROR(EAGAIN) || (countdown <= 0))
        {
            /*
             * Do not retry for any other kind of error
             */

            break;
        }

        countdown--;

        usleep_ex(10000); /* 10 ms */
    }

    return ret; // fake positive, ret has been initialised
}

#if DNSCORE_MESSAGE_PAYLOAD_IS_POINTER

void dns_message_init_ex(dns_message_t *mesg, uint32_t mesg_size, void *buffer, size_t buffer_size)
{
    ZEROMEMORY(mesg, offsetof(dns_message_t, _msghdr_control_buffer)); // includes the tsig structure
    mesg->_msghdr.msg_name = &mesg->_sender.sa;
    mesg->_msghdr.msg_namelen = sizeof(mesg->_sender);
    mesg->_msghdr.msg_iov = &mesg->_iovec;
    mesg->_msghdr.msg_iovlen = 1;
#if __unix__
    mesg->_msghdr.msg_control = NULL;
    mesg->_msghdr.msg_controllen = 0;
#else
    mesg->_msghdr.msg_control.buf = NULL;
    mesg->_msghdr.msg_control.len = 0;
#endif
    mesg->_msghdr.msg_flags = 0;
    // mesg->_msghdr.msg_control = mesg->_msghdr_control_buffer;
    // mesg->_msghdr.msg_controllen = sizeof(mesg->_msghdr_control_buffer);
#if DNSCORE_MESSAGE_PAYLOAD_IS_POINTER
    //
#else
    mesg->_iovec.iov_base = mesg->_buffer;
#endif
    mesg->_iovec.iov_len = buffer_size;

#if DNSCORE_MESSAGE_PAYLOAD_IS_POINTER
    mesg->_message_data_size = mesg_size;
#endif

    mesg->_control_buffer_size = sizeof(mesg->_msghdr_control_buffer);
    mesg->_buffer_size = buffer_size;
    mesg->_buffer_size_limit = buffer_size;
    mesg->_tsig.hmac = NULL;

    mesg->_cookie.size = 0;

#if DNSCORE_MESSAGE_PAYLOAD_IS_POINTER
    mesg->_buffer = (uint8_t *)buffer;

    mesg->_iovec.iov_base = mesg->_buffer;
#if DEBUG
    memset(buffer, 0x5a, buffer_size);
#endif
#else
#if DEBUG
    memset(&mesg->_buffer, 0x5a, mesg->_buffer_size_limit);
#endif
#endif
}

#else // MESSAGE_PAYLOAD_IS_POINTER

void message_init(message_data *mesg)
{
    ZEROMEMORY(mesg, offsetof(message_data, _msghdr_control_buffer));
    mesg->_msghdr.msg_name = &mesg->_sender;
    mesg->_msghdr.msg_namelen = sizeof(mesg->_sender);
    mesg->_msghdr.msg_iov = &mesg->_iovec;
    mesg->_msghdr.msg_iovlen = 1;
    mesg->_msghdr.msg_control = NULL;
    mesg->_msghdr.msg_controllen = 0;
    mesg->_msghdr.msg_flags = 0;
    // mesg->_msghdr.msg_control = mesg->_msghdr_control_buffer;
    // mesg->_msghdr.msg_controllen = sizeof(mesg->_msghdr_control_buffer);
    mesg->_iovec.iov_base = mesg->_buffer;
    mesg->_iovec.iov_len = NETWORK_BUFFER_SIZE;
    mesg->_control_buffer_size = sizeof(mesg->_msghdr_control_buffer);
    mesg->_buffer_size = NETWORK_BUFFER_SIZE;
    mesg->_buffer_size_limit = NETWORK_BUFFER_SIZE;
    mesg->_tsig.hmac = NULL;
#if DEBUG
    memset(&mesg->_buffer, 0x5a, mesg->_buffer_size_limit);
#endif
}

#endif

/**
 * If pointer is NULL, the structure and buffer will be allocated together
 * Note that in the current implementation, 8 bytes are reserved for TCP
 */

dns_message_t *dns_message_new_instance_ex(void *ptr, uint32_t message_size) // should be size of edns0 or 64K for TCP
{
    dns_message_t *mesg;
    if(ptr == NULL)
    {
        uint8_t *tmp;
        size_t   message_data_size = ((sizeof(dns_message_t) + 7) & ~7) + message_size;
        MALLOC_OBJECT_ARRAY_OR_DIE(tmp, uint8_t, message_data_size, MESGDATA_TAG);
        ptr = &tmp[(sizeof(dns_message_t) + 7) & ~7];
        mesg = (dns_message_t *)tmp;
        dns_message_init_ex(mesg, message_data_size, ptr, message_size);
    }
    else
    {
        MALLOC_OBJECT_OR_DIE(mesg, dns_message_t, MESGDATA_TAG); // legit
        dns_message_init_ex(mesg, sizeof(dns_message_t), ptr, message_size);
    }
    return mesg;
}

dns_message_t *dns_message_new_instance()
{
    dns_message_t *mesg;
    mesg = dns_message_new_instance_ex(NULL, 65536);
    return mesg;
}

void dns_message_finalize(dns_message_t *mesg)
{
    dns_message_clear_hmac(mesg);
    if(mesg->_tsig.other != NULL)
    {
        free(mesg->_tsig.other);
    }
}

/**
 * Finalise and free the message instance.
 * Checks for NULL
 *
 * @parm mesg the message instance
 *
 */

void dns_message_delete(dns_message_t *mesg)
{
    if(mesg != NULL)
    {
        dns_message_finalize(mesg);
#if DEBUG
        memset(mesg, 0xfe, sizeof(dns_message_t));
#endif
        free(mesg); // legit, deletes the buffer too
    }
}

/*
 * Does not clone the pool.
 */

dns_message_t *dns_message_dup(const dns_message_t *mesg)
{
    size_t message_size = dns_message_get_size(mesg);
    if(message_size > mesg->_buffer_size_limit)
    {
        return NULL;
    }

    dns_message_t *clone = dns_message_new_instance_ex(NULL, mesg->_buffer_size_limit + 8);
    if(dns_message_get_additional_section_ptr_const(mesg) != NULL)
    {
        dns_message_set_additional_section_ptr(clone, &clone->_buffer[dns_message_get_additional_section_ptr_const(mesg) - dns_message_get_buffer_const(mesg)]);
    }

    memcpy(&clone->_edns0_opt_ttl, &mesg->_edns0_opt_ttl, offsetof(dns_message_t, _msghdr_control_buffer));

    dns_message_copy_sender_from(clone, mesg);
#if __unix__
    memcpy(clone->_msghdr_control_buffer, mesg->_msghdr_control_buffer, mesg->_msghdr.msg_controllen);
#else
#pragma message("TODO: check this works (non-unix systems)")
    memcpy(clone->_msghdr_control_buffer, mesg->_msghdr_control_buffer, mesg->_msghdr.msg_control.len);
#endif
    dnsname_copy(clone->_canonised_fqdn, dns_message_get_canonised_fqdn(mesg));
#if !DNSCORE_MESSAGE_PAYLOAD_IS_POINTER
    SET_U16_AT(clone->_buffer_tcp_len[0], GET_U16_AT(mesg->_buffer_tcp_len[0]));
#endif
    memcpy(clone->_cookie.bytes, mesg->_cookie.bytes, mesg->_cookie.size);
    clone->_cookie.size = mesg->_cookie.size;

    memcpy(dns_message_get_buffer(clone), dns_message_get_buffer_const(mesg), dns_message_get_size(mesg));
    dns_message_set_size(clone, dns_message_get_size(mesg));

    return clone;
}

void dns_message_log(logger_handle_t *logger, int level, const dns_message_t *mesg)
{
    ya_result                      ret;
    int                            index = 0;
    rdata_desc_t                   rrdesc = {0, 0, NULL};
    struct type_class_ttl_rdlen_s *tctrp;
    uint8_t                        rr[32768];

    logger_handle_msg(logger, level, "to: %{sockaddr}", dns_message_get_sender_sa(mesg));
    logger_handle_msg(logger, level, "id: %i ", dns_message_get_id(mesg));
    logger_handle_msg(logger,
                      level,
                      "flags: %02x %02x opcode: %s rcode: %s",
                      dns_message_get_flags_hi(mesg),
                      dns_message_get_flags_lo(mesg),
                      dns_message_opcode_get_name(dns_message_get_opcode(mesg) >> OPCODE_SHIFT),
                      dns_message_rcode_get_name(dns_message_get_rcode(mesg)));
    logger_handle_msg(logger, level, "qr: %i, an: %i, ns: %i, ar: %i", dns_message_get_query_count(mesg), dns_message_get_answer_count(mesg), dns_message_get_authority_count(mesg), dns_message_get_additional_count(mesg));
    dns_packet_reader_t pr;
    dns_packet_reader_init_from_message(&pr, mesg);

    /* fqdn + type + class */
    for(uint_fast16_t qc = dns_message_get_query_count(mesg); qc > 0; --qc)
    {
        if(FAIL(ret = dns_packet_reader_read_zone_record(&pr, rr, sizeof(rr))))
        {
            logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
            return;
        }

        uint16_t *type_class = (uint16_t *)&rr[dnsname_len(rr)];

        logger_handle_msg(logger, level, "Q%3i: %{dnsname} %{dnstype} %{dnsclass}", index++, rr, &type_class[0], &type_class[1]);
    }

    if((dns_message_get_opcode(mesg) == OPCODE_QUERY) || (dns_message_get_opcode(mesg) == OPCODE_NOTIFY))
    {
        for(int_fast32_t section = 1; section <= 3; ++section)
        {
            index = 0;

            for(uint_fast16_t sc = dns_message_get_section_count(mesg, section); sc > 0; --sc)
            {
                if(FAIL(ret = dns_packet_reader_read_record(&pr, rr, sizeof(rr))))
                {
                    logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
                    return;
                }

                tctrp = (struct type_class_ttl_rdlen_s *)&rr[dnsname_len(rr)];
                rrdesc.type = tctrp->rtype;
                rrdesc.len = ntohs(tctrp->rdlen);
                rrdesc.rdata = &((uint8_t *)tctrp)[10];

                logger_handle_msg(logger, level, "%c%3i: %{dnsname} %i %{typerdatadesc}", "QANa"[section], index++, rr, ntohl(tctrp->ttl), &rrdesc);
            }
        }
    }
    else if(dns_message_get_opcode(mesg) == OPCODE_UPDATE)
    {
        for(int_fast32_t section = 1; section <= 3; ++section)
        {
            index = 0;

            for(uint_fast16_t sc = dns_message_get_section_count(mesg, section); sc > 0; --sc)
            {
                uint8_t *rdata_buffer;
                int32_t  rttl;
                uint16_t rtype;
                uint16_t rclass;
                uint16_t rdata_buffer_size;
                uint16_t rdata_size;

                if(FAIL(ret = dns_packet_reader_read_fqdn(&pr, rr, sizeof(rr))))
                {
                    return;
                }

                rdata_buffer = &rr[ret];
                rdata_buffer_size = sizeof(rr) - ret;

                if(FAIL(ret = dns_packet_reader_read_u16(&pr, &rtype)))
                {
                    logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
                    return;
                }

                if(FAIL(ret = dns_packet_reader_read_u16(&pr, &rclass)))
                {
                    logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
                    return;
                    ;
                }

                if(FAIL(ret = dns_packet_reader_read_u32(&pr, (uint32_t *)&rttl)))
                {
                    logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
                    return;
                    ;
                }

                rttl = ntohl(rttl);

                if(FAIL(ret = dns_packet_reader_read_u16(&pr, &rdata_size)))
                {
                    logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
                    return;
                    ;
                }

                rdata_size = ntohs(rdata_size);

                if(rclass != TYPE_ANY)
                {
                    if(FAIL(ret = dns_packet_reader_read_rdata(&pr, rtype, rdata_size, rdata_buffer, rdata_buffer_size))) // fixed buffer
                    {
                        logger_handle_msg(logger, MSG_ERR, "failed to read zone record: %r", ret);
                        return;
                    }

                    rrdesc.type = rtype;
                    rrdesc.len = rdata_size;
                    rrdesc.rdata = rdata_buffer;

                    logger_handle_msg(logger, level, "%c%3i: %{dnsname} %i %{dnsclass} %{typerdatadesc}", "QANa"[section], index++, rr, rttl, &rclass, &rrdesc);
                }
                else
                {
                    logger_handle_msg(logger, level, "%c%3i: %{dnsname} %i %{dnsclass} %{dnstype}", "QANa"[section], index++, rr, rttl, &rclass, &rtype);
                }
            }
        }
    }
}

#if NOTUSED
ya_result dns_message_get_ixfr_query_serial(dns_message_t *mesg, uint32_t *serialp)
{
    dns_packet_reader_t purd;
    ya_result           ret;
    uint16_t            qtype;

    dns_packet_reader_init_from_message(&purd, mesg);

    if(FAIL(ret = dns_packet_reader_skip_fqdn(&purd)))
    {
        return ret;
    }

    if(FAIL(ret = dns_packet_reader_read_u16(&purd, &qtype)))
    {
        return ret;
    }

    if(qtype != TYPE_IXFR)
    {
        return ERROR; // not an IXFR
    }

    if(FAIL(ret = dns_packet_reader_skip(&purd, 2)))
    {
        return ret;
    }

    dns_message_set_size(mesg, purd.offset);

    /* Get the queried serial */

    if(FAIL(ret = dns_packet_reader_skip_fqdn(&purd)))
    {
        return ret;
    }

    if(FAIL(ret = dns_packet_reader_skip(&purd, 10)))
    {
        return ret;
    }

    if(FAIL(ret = dns_packet_reader_skip_fqdn(&purd)))
    {
        return ret;
    }

    if(FAIL(ret = dns_packet_reader_skip_fqdn(&purd)))
    {
        return ret;
    }

    if(serialp != NULL)
    {
        if(FAIL(ret = dns_packet_reader_read_u32(&purd, serialp)))
        {
            return ret;
        }

        *serialp = ntohl(*serialp);
    }

    return SUCCESS;
}
#endif

#if NOTUSED
#if DNSCORE_HAS_TSIG_SUPPORT
ya_result dns_message_terminate_then_write(dns_message_t *mesg, output_stream_t *tcpos, tsig_tcp_message_position pos)
#else
ya_result dns_message_terminate_then_write(dns_message_t *mesg, output_stream_t *tcpos, int unused)
#endif
{
    ya_result ret;

#if !DNSCORE_HAS_TSIG_SUPPORT
#pragma message("TSIG SUPPORT HAS BEEN DISABLED")
    (void)unused;
#endif

    if(dns_message_has_edns0(mesg)) // Dig does a TCP query with EDNS0
    {
        /* 00 00 29 SS SS rr vv 80 00 00 00 */

        uint8_t *buffer = dns_message_get_buffer_limit(mesg);
        buffer[0] = 0;
        buffer[1] = 0;
        buffer[2] = 0x29; // no alternative for now
#if DNSCORE_HAS_LITTLE_ENDIAN
        /*
                buffer[ 3] = edns0_maxsize >> 8;
                buffer[ 4] = edns0_maxsize;
        */
        SET_U16_AT(buffer[3], htons(edns0_maxsize));
#else
        SET_U16_AT(buffer[3], edns0_maxsize);
#endif
        SET_U32_AT(buffer[5], mesg->_edns0_opt_ttl.as_u32);

        buffer[9] = 0;
        buffer[10] = 0;

        dns_message_increase_size(mesg, 11);

        dns_message_set_additional_count_ne(mesg, NU16(1));
    }
    else
    {
        dns_message_set_additional_count_ne(mesg, 0);
    }

#if DNSCORE_HAS_TSIG_SUPPORT
    if(dns_message_has_tsig(mesg))
    {
        /// @todo 20230123 edf --  zdb_zone_answer_ixfr_send_message has also the following update:
        // message_set_additional_section_ptr(mesg, dns_packet_writer_get_next_u8_ptr(pw));
        if(FAIL(ret = tsig_sign_tcp_message(mesg, pos)))
        {
            return ret;
        }
    }
#endif

    ret = dns_message_write_tcp(mesg, tcpos);

    return ret;
}
#endif

/**
 * Maps records in a message to easily access them afterward.
 *
 * @param map the message map to initialise
 * @param mesg the message to map
 * @param tight do two passes to use the least amount of memory possible
 *
 * @return an error code
 */

ya_result dns_message_map_init(dns_message_map_t *map, const dns_message_t *mesg)
{
    map->mesg = mesg;

    dns_packet_reader_t purd;

    dns_packet_reader_init_from_message(&purd, mesg);

    ya_result ret;

    uint16_t  qc = dns_message_get_query_count(mesg);
    uint16_t  an = dns_message_get_answer_count(mesg);
    uint16_t  ns = dns_message_get_authority_count(mesg);
    uint16_t  ar = dns_message_get_additional_count(mesg);

    int       total = qc;
    total += an;
    total += ns;
    total += ar;

    ptr_vector_init_ex(&map->records, total);

    int i;

    for(i = 0; i < qc; ++i)
    {
        ptr_vector_append(&map->records, (void *)dns_packet_reader_get_next_u8_ptr_const(&purd));
        dns_packet_reader_skip_fqdn(&purd); // checked below
        if(FAIL(ret = dns_packet_reader_skip(&purd, 4)))
        {
            dns_message_map_finalize(map);
            return ret;
        }
    }

    for(; i < total; ++i)
    {
        ptr_vector_append(&map->records, (void *)dns_packet_reader_get_next_u8_ptr_const(&purd));

        if(FAIL(ret = dns_packet_reader_skip_record(&purd)))
        {
            dns_message_map_finalize(map);
            return ret;
        }
    }

    ret = ptr_vector_size(&map->records);

    map->section_base[0] = 0;
    map->section_base[1] = dns_message_get_section_count(map->mesg, 0) + map->section_base[0];
    map->section_base[2] = dns_message_get_section_count(map->mesg, 1) + map->section_base[1];
    map->section_base[3] = dns_message_get_section_count(map->mesg, 2) + map->section_base[2];

    return ret;
}

/**
 * Gets the fqdn of the record at index
 *
 * @param map
 * @param index
 * @param fqdn
 * @param fqdn_size
 *
 * @return an error code
 */

ya_result dns_message_map_get_fqdn(const dns_message_map_t *map, int index, uint8_t *fqdn, int fqdn_size)
{
    if((index >= 0) && (index <= ptr_vector_last_index(&map->records)))
    {
        if(dnsname_expand_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), ptr_vector_get(&map->records, index), fqdn, fqdn_size) != NULL)
        {
            return SUCCESS;
        }
    }

    return ERROR;
}

/**
 * Gets the type class ttl rdata_size of the record at index
 *
 * @param map
 * @param index
 * @param tctr
 *
 * @return an error code
 */

ya_result dns_message_map_get_tctr(const dns_message_map_t *map, int index, struct type_class_ttl_rdlen_s *tctr)
{
    if(index <= ptr_vector_last_index(&map->records))
    {
        const uint8_t *p;
        if((p = dnsname_skip_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), ptr_vector_get(&map->records, index))) != NULL)
        {
            if(index >= map->section_base[1])
            {
                if(dns_message_get_buffer_limit_const(map->mesg) - p >= 10)
                {
                    memcpy(tctr, p, 10);

                    return SUCCESS;
                }
            }
            else
            {
                if(dns_message_get_buffer_limit_const(map->mesg) - p >= 4)
                {
                    memcpy(tctr, p, 4);
                    tctr->ttl = 0;
                    tctr->rdlen = 0;

                    return SUCCESS;
                }
            }
        }
    }

    return ERROR;
}

/**
 * Gets the rdata of the record at index
 *
 * @param map
 * @param index
 * @param rdata
 * @param rdata_size
 *
 * @return the rdata size or an error code
 */

ya_result dns_message_map_get_rdata(const dns_message_map_t *map, int index, uint8_t *rdata, int rdata_size)
{
    if((index >= (int)map->section_base[1]) && (index <= ptr_vector_last_index(&map->records)))
    {
        const uint8_t *p;
        if((p = dnsname_skip_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), ptr_vector_get(&map->records, index))) != NULL)
        {
            if(dns_message_get_buffer_limit_const(map->mesg) - p >= 10)
            {
                const uint8_t *rdata_base = rdata;
                size_t         d;

                uint16_t       rtype = GET_U16_AT_P(p);
                p += 8;
                uint16_t n = ntohs(GET_U16_AT_P(p));
                p += 2;

                if(dns_message_get_buffer_limit_const(map->mesg) - p >= n)
                {
                    switch(rtype)
                    {
                            /******************************************************************************
                             * The types that requires special handling (dname compression)
                             ******************************************************************************/

                        case TYPE_MX:
                        case TYPE_AFSDB:
                        {
                            if(rdata_size < 3) // minimal expected size
                            {
                                return INVALID_RECORD;
                            }

                            SET_U16_AT_P(rdata, GET_U16_AT_P(p));
                            rdata += 2;
                            rdata_size -= 2;
                            p += 2;

                            if(dnsname_expand_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), p, rdata, rdata_size) != NULL)
                            {
                                return dnsname_len(rdata) + 2;
                            }

                            return INVALID_RECORD;
                        }

                        case TYPE_NS:
                        case TYPE_CNAME:
                        case TYPE_DNAME:
                        case TYPE_PTR:
                        case TYPE_MB:
                        case TYPE_MD:
                        case TYPE_MF:
                        case TYPE_MG:
                        case TYPE_MR:
                        {
                            if(dnsname_expand_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), p, rdata, rdata_size) != NULL)
                            {
                                return dnsname_len(rdata);
                            }

                            return INVALID_RECORD;
                        }
                        case TYPE_SOA:
                        {
                            if((p = dnsname_expand_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), p, rdata, rdata_size)) != NULL)
                            {
                                d = dnsname_len(rdata);
                                rdata += d;
                                rdata_size -= d;

                                if((p = dnsname_expand_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), p, rdata, rdata_size)) != NULL)
                                {
                                    d = dnsname_len(rdata);

                                    rdata += d;
                                    rdata_size -= d;

                                    if(rdata_size >= 20)
                                    {
                                        memcpy(rdata, p, 20);
                                        return &rdata[20] - rdata_base;
                                    }
                                }
                            }

                            return INVALID_RECORD;
                        }
                        case TYPE_RRSIG: /* not supposed to be compressed */
                        {
                            if(rdata_size > RRSIG_RDATA_HEADER_LEN)
                            {
                                const uint8_t *p_base = p;
                                memcpy(rdata, p, RRSIG_RDATA_HEADER_LEN);
                                rdata += RRSIG_RDATA_HEADER_LEN;
                                rdata_size -= RRSIG_RDATA_HEADER_LEN;
                                p += RRSIG_RDATA_HEADER_LEN;

                                if((p = dnsname_expand_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), p, rdata, rdata_size)) != NULL)
                                {
                                    d = dnsname_len(rdata);
                                    rdata += d;
                                    // rdata_size -= d;
                                    d = p - p_base;
                                    memcpy(rdata, p, d);

                                    return &rdata[d] - rdata_base;
                                }
                            }

                            return INVALID_RECORD;
                        }
                        case TYPE_NSEC: /* not supposed to be compressed */
                        {
                            const uint8_t *p_base = p;
                            if((p = dnsname_expand_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), p, rdata, rdata_size)) != NULL)
                            {
                                d = dnsname_len(rdata);
                                rdata += d;
                                // rdata_size -= d;
                                d = p - p_base;
                                memcpy(rdata, p, d);

                                return &rdata[d] - rdata_base;
                            }

                            return INVALID_RECORD;
                        }

                        default:
                        {
                            if(rdata_size >= n)
                            {
                                memcpy(rdata, p, n);
                                return n;
                            }

                            return INVALID_RECORD;
                        }
                    } // switch type
                }
            }
        }
    }

    return ERROR;
}

/**
 * Gets the type of the record at index
 *
 * @param map
 * @param index
 *
 * @return the record type or an error code
 */

ya_result dns_message_map_get_type(const dns_message_map_t *map, int index)
{
    if((index >= 0) && (index <= ptr_vector_last_index(&map->records)))
    {
        const uint8_t *p;
        if((p = dnsname_skip_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), ptr_vector_get(&map->records, index))) != NULL)
        {
            if(dns_message_get_buffer_limit_const(map->mesg) - p >= 2)
            {
                uint16_t rtype = GET_U16_AT_P(p);

                return rtype;
            }
        }
    }

    return ERROR;
}

/**
 * Gets the class of the record at index
 *
 * @param map
 * @param index
 *
 * @return the record class or an error code
 */

ya_result dns_message_map_get_class(const dns_message_map_t *map, int index)
{
    if((index >= 0) && (index <= ptr_vector_last_index(&map->records)))
    {
        const uint8_t *p;
        if((p = dnsname_skip_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), ptr_vector_get(&map->records, index))) != NULL)
        {
            if(dns_message_get_buffer_limit_const(map->mesg) - p >= 4)
            {
                uint16_t rclass = GET_U16_AT_P(p + 2);

                return rclass;
            }
        }
    }

    return ERROR;
}

/**
 *
 * @param map
 *
 * @return the number of records mapped
 */

int dns_message_map_record_count(const dns_message_map_t *map)
{
    int size = ptr_vector_size(&map->records);
    return size;
}

/**
 * Returns the index of the next record with the given type
 * from, and including, a given index.
 *
 * @param map
 * @param index
 * @param type
 * @return
 */

int dns_message_map_get_next_record_from(const dns_message_map_t *map, int index, uint16_t type)
{
    ya_result ret;

    for(;;)
    {
        ret = dns_message_map_get_type(map, index);

        if(ret == type)
        {
            return index;
        }

        if(FAIL(ret))
        {
            return ret;
        }

        ++index;
    }
}

/**
 * Returns the index of the next record with the given type
 * from, and including, a given index in a given section (0 to 3).
 *
 * @param map
 * @param index
 * @param type
 * @return
 */

int dns_message_map_get_next_record_from_section(const dns_message_map_t *map, int section, int index, uint16_t type)
{
    if(index < 0)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    uint16_t sc = dns_message_get_section_count(map->mesg, section);

    if(index >= sc)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    ya_result ret;

    do
    {
        ret = dns_message_map_get_type(map, map->section_base[section] + index);

        if(ret == type)
        {
            return index;
        }

        if(FAIL(ret))
        {
            return ret;
        }

        ++index;
    } while(index < sc);

    return ERROR;
}

/**
 * Releases the memory used by the map
 *
 * @param map
 */

void       dns_message_map_finalize(dns_message_map_t *map) { ptr_vector_finalise(&map->records); }

static int dns_message_map_reorder_remap_type(int t, int ct)
{
    int r;
    switch(t)
    {
        case TYPE_SOA:
            r = 0 << 1;
            break;
        case TYPE_NSEC:
            r = 0x7ffe << 1;
            break;
        case TYPE_NSEC3:
            r = 0x7fff << 1;
            break;
        case TYPE_RRSIG:
            r = dns_message_map_reorder_remap_type(ct, 0) + 1;
            break;
        default:
            r = (ntohs(t) + 0x1000) << 1;
            break;
    }
    return r;
}

static int dns_message_map_reorder_comparator(const void *rra, const void *rrb, void *ctx)
{
    const uint8_t                *pa = (const uint8_t *)rra;
    const uint8_t                *pb = (const uint8_t *)rrb;
    dns_message_map_t            *map = (dns_message_map_t *)ctx;
    struct type_class_ttl_rdlen_s tctra;
    struct type_class_ttl_rdlen_s tctrb;
    uint16_t                      ctypea;
    uint16_t                      ctypeb;
    uint8_t                       fqdna[256];
    uint8_t                       fqdnb[256];

    if(rra == rrb)
    {
        return 0;
    }

    pa = dnsname_expand_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), rra, fqdna, sizeof(fqdna));
    memcpy(&tctra, pa, 10);
    pa += 10;
    if(tctra.rtype == TYPE_RRSIG)
    {
        ctypea = GET_U16_AT_P(pa);
    }
    else
    {
        ctypea = 0;
    }

    pa += 10;

    pb = dnsname_expand_compressed(dns_message_get_buffer_const(map->mesg), dns_message_get_size(map->mesg), rrb, fqdnb, sizeof(fqdnb));
    memcpy(&tctrb, pb, 10);
    pb += 10;
    if(tctrb.rtype == TYPE_RRSIG)
    {
        ctypeb = GET_U16_AT_P(pb);
    }
    else
    {
        ctypeb = 0;
    }

    tctra.rdlen = ntohs(tctra.rdlen);
    tctrb.rdlen = ntohs(tctrb.rdlen);
    int rdata_size_d = tctra.rdlen;
    int rdata_size_min = MIN(tctra.rdlen, tctrb.rdlen);
    rdata_size_d -= tctrb.rdlen;
    int  d;

    bool n3a = (tctra.rtype == TYPE_NSEC3) || (ctypea == TYPE_NSEC3);
    bool n3b = (tctrb.rtype == TYPE_NSEC3) || (ctypeb == TYPE_NSEC3);

    if(n3a)
    {
        if(n3b)
        {
            // both are NSEC3 related: normal sort
        }
        else
        {
            // the NSEC3 one is after the normal one
            return 1;
        }
    }
    else // the first one is not NSEC3 related
    {
        if(n3b)
        {
            // the second one is: it comes after the normal one
            return -1;
        }
        else
        {
            // none are NSEC3 related: normal sort
        }
    }

    d = dnsname_compare(fqdna, fqdnb);

    if(d == 0)
    {
        // let's avoid lot's of if-then-else

        int ta = dns_message_map_reorder_remap_type(tctra.rtype, ctypea);
        int tb = dns_message_map_reorder_remap_type(tctrb.rtype, ctypeb);

        d = ta - tb;

        if(d == 0)
        {
            d = memcmp(pa, pb, rdata_size_min);

            if(d == 0)
            {
                d = rdata_size_d;
            }
        }
    }

    return d;
}

/**
 * Sorts records by section so that:
 * _ SOA is first,
 * _ NSEC is last,
 * _ NSEC3 labels are at the end,
 * _ RRSIG follows its RRSET
 *
 * @param map
 */

void dns_message_map_reorder(dns_message_map_t *map)
{
    // apply message_map_reorder_comparator to sections 1, 2 and 3.
    ptr_vector_t fakev;
    for(int_fast32_t section = 1; section < 4; ++section)
    {
        int sc = dns_message_map_get_section_count(map, section);
        if(sc > 1)
        {
            fakev.data = &map->records.data[map->section_base[section]];
            fakev.offset = sc - 1;
            fakev.size = fakev.offset + 1;
            ptr_vector_qsort_r(&fakev, dns_message_map_reorder_comparator, map);
        }
    }
}

void dns_message_map_print(const dns_message_map_t *map, output_stream_t *os)
{
    osformat(
        os, ";; opcode: %s, status: %s, id: %i, flags:", dns_message_opcode_get_name(dns_message_get_opcode(map->mesg) >> OPCODE_SHIFT), dns_message_rcode_get_name(dns_message_get_rcode(map->mesg)), ntohs(dns_message_get_id(map->mesg)));

    uint8_t h = dns_message_get_flags_hi(map->mesg);
    if(h & QR_BITS)
    {
        output_stream_write(os, "qr ", 3);
    }
    if(h & AA_BITS)
    {
        output_stream_write(os, "aa ", 3);
    }
    if(h & TC_BITS)
    {
        output_stream_write(os, "tc ", 3);
    }
    if(h & RD_BITS)
    {
        output_stream_write(os, "rd ", 3);
    }

    uint8_t l = dns_message_get_flags_hi(map->mesg);

    if(l & RA_BITS)
    {
        output_stream_write(os, "ra ", 3);
    }
    if(l & AD_BITS)
    {
        output_stream_write(os, "ad ", 3);
    }
    if(l & CD_BITS)
    {
        output_stream_write(os, "cd ", 3);
    }

    osformatln(os, "\n;; SECTION: [%i ,%i, %i, %i]", dns_message_get_section_count(map->mesg, 0), dns_message_get_section_count(map->mesg, 1), dns_message_get_section_count(map->mesg, 2), dns_message_get_section_count(map->mesg, 3));

    struct type_class_ttl_rdlen_s tctr;
    uint8_t                       tmp[1024];

    int                           i = 0;

    for(int_fast32_t section = 0; section < 4; ++section)
    {
        osformatln(os, ";; SECTION %i:", section);

        for(int_fast32_t n = dns_message_get_section_count(map->mesg, section); n > 0; --n)
        {
            if(ISOK(dns_message_map_get_fqdn(map, i, tmp, sizeof(tmp))))
            {
                if(section > 0)
                {
                    if(ISOK(dns_message_map_get_tctr(map, i, &tctr)))
                    {
                        osformat(os, "%{dnsname} %9i %{dnsclass} %{dnstype} ", tmp, ntohl(tctr.ttl), &tctr.rclass, &tctr.rtype);

                        if(section > 0)
                        {
                            int          rdata_size = dns_message_map_get_rdata(map, i, tmp, sizeof(tmp));

                            rdata_desc_t rd = {tctr.rtype, rdata_size, tmp};
                            osformat(os, "%{rdatadesc}", &rd);
                        }
                        osprintln(os, "");

                        ++i;
                        continue;
                    }
                }
                else
                {
                    tctr.rtype = dns_message_map_get_type(map, i);
                    tctr.rclass = dns_message_map_get_class(map, i);
                    osformatln(os, "%{dnsname} %{dnsclass} %{dnstype}", tmp, &tctr.rclass, &tctr.rtype);

                    ++i;
                    continue;
                }
            }

            osformatln(os, "%{dnsname} READ FAILURE\n", tmp);
            break;
        }

        osprintln(os, "");
    }
}

int32_t dns_message_send_udp_debug(const dns_message_t *mesg, int sockfd)
{
    log_info("dns_message_send_udp(%p, %i) through %{sockaddr}", mesg, sockfd, mesg->_msghdr.msg_name);

    int32_t n;
    void  **p = (void **)&mesg->_msghdr.msg_control;
    *p = NULL;
    while((n = sendmsg(sockfd, &mesg->_msghdr, 0)) < 0)
    {
        int err = errno;

        if(err != EINTR)
        {
            return MAKE_ERRNO_ERROR(err);
        }
    }

    return n;
}

ssize_t dns_message_send_tcp(const dns_message_t *mesg, int sockfd)
{
    ssize_t       ret;
    struct msghdr tcp_msghdr;
    struct iovec  tcp_data[2];
    uint16_t      tcp_len = dns_message_get_size_u16(mesg);
    uint16_t      tcp_native_len = htons(tcp_len);

    tcp_data[0].iov_base = &tcp_native_len;
    tcp_data[0].iov_len = 2;
    tcp_data[1].iov_base = mesg->_buffer;
    tcp_data[1].iov_len = tcp_len;
    tcp_msghdr.msg_name = mesg->_msghdr.msg_name;
    tcp_msghdr.msg_namelen = mesg->_msghdr.msg_namelen;
    tcp_msghdr.msg_iov = &tcp_data[0];
    tcp_msghdr.msg_iovlen = 2;
    tcp_msghdr.msg_control = mesg->_msghdr.msg_control;
#if __unix__
    tcp_msghdr.msg_controllen = mesg->_msghdr.msg_controllen;
#endif
    tcp_msghdr.msg_flags = 0;

    int32_t remain = tcp_len + 2;

#if DEBUG
    int32_t again = 0;
#endif

    for(;;)
    {
        ret = sendmsg(sockfd, &tcp_msghdr, 0);

        if(ret < 0)
        {
            int err = ERRNO_ERROR;
            if(err == MAKE_ERRNO_ERROR(EINTR))
            {
                continue;
            }

            if(err == MAKE_ERRNO_ERROR(EAGAIN))
            {
#if DEBUG
                ++again;
#endif
                usleep(100);
                continue;
            }

            ret = err;

            break;
        }

        remain -= ret;

        if(remain == 0)
        {
            break;
        }

        while(tcp_msghdr.msg_iovlen > 0)
        {
            if((size_t)ret < tcp_msghdr.msg_iov[0].iov_len)
            {
                uint8_t *p = (uint8_t *)tcp_msghdr.msg_iov[0].iov_base;
                p += ret;
                tcp_msghdr.msg_iov[0].iov_base = p;
                tcp_msghdr.msg_iov[0].iov_len -= (size_t)ret;
                break;
            }
            else
            {
                ret -= (size_t)tcp_msghdr.msg_iov[0].iov_len;

                ++tcp_msghdr.msg_iov;
                --tcp_msghdr.msg_iovlen;

                if(ret == 0)
                {
                    break;
                }
            }
        }
    }

#if DEBUG
    if(again > 0)
    {
        log_debug("dns_message_send_tcp: again=%i", again);
    }
#endif

    return ret;
}

/// @note 20230328 edf -- This is not FNV ... (explanation follows)
//
// This algorithm is based on:
// https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
// Instead of reading byte by byte, I get 8 bytes at once and shift them instead.
// It should be more efficient.
// I might consider reducing the shifts up to doing the 64 bits multiplication once.
//

#define FNV_basis 14695981039346656037ULL
#define FNV_prime 1099511628211ULL

/// @todo 20230328 edf -- needs to be refreshed every day

static uint64_t g_cookie_secret = ~1;

/// @todo 20240426 edf -- needs to be based on the client IP

static uint64_t g_client_cookie_secret = ~1;

int             dns_message_client_cookie_size(dns_message_t *mesg)
{
    if(dns_message_cookie_size_valid(mesg->_cookie.size))
    {
        return DNS_MESSAGE_COOKIE_CLIENT_SIZE;
    }
    else
    {
        return INVALID_STATE_ERROR;
    }
}

int dns_message_server_cookie_size(dns_message_t *mesg)
{
    if(dns_message_cookie_size_valid(mesg->_cookie.size))
    {
        return mesg->_cookie.size - DNS_MESSAGE_COOKIE_CLIENT_SIZE;
    }
    else
    {
        return INVALID_STATE_ERROR;
    }
}

/**
 * Sets the client cookie and enable cookies for the message.
 * Use of this function is not recommended.
 *
 * @param mesg the message
 * @param cookie the client cookie
 */

void dns_message_set_client_cookie(dns_message_t *mesg, uint64_t cookie)
{
    SET_U64_AT_P(dns_message_client_cookie_ptr(mesg), cookie);
    mesg->_cookie.size = DNS_MESSAGE_COOKIE_CLIENT_SIZE;
    dns_message_cookie_set(mesg);
}

/**
 * Sets the initial client_cookie for the given server address.
 *
 * @param mesg the message
 * @param address the address as a byte array
 * @param address_size the size of the address in bytes
 */

void dns_message_set_client_cookie_for_server_address(dns_message_t *mesg, const uint8_t *address, int address_size)
{
    uint64_t value = FNV_basis;
    value ^= g_client_cookie_secret;
    for(int_fast32_t i = 0; i < address_size; ++i)
    {
        uint8_t v = address[i];
        value ^= v;
        value *= FNV_prime;
    }
    SET_U64_AT_P(dns_message_client_cookie_ptr(mesg), value);
    mesg->_cookie.size = DNS_MESSAGE_COOKIE_CLIENT_SIZE;
    dns_message_cookie_set(mesg);
}

/**
 * Sets the initial client_cookie for the given server address.
 *
 * @param mesg the message
 * @param sa the struct sockaddr of the address
 */

void dns_message_set_client_cookie_for_server_sockaddr(dns_message_t *mesg, const socketaddress_t *sa)
{
    switch(sa->sa_family)
    {
        case AF_INET:
        {
            dns_message_set_client_cookie_for_server_address(mesg, (uint8_t *)&sa->sa4.sin_addr, 4);
            break;
        }
        case AF_INET6:
        {
            dns_message_set_client_cookie_for_server_address(mesg, (uint8_t *)&sa->sa6.sin6_addr, 16);
            break;
        }
        default:
        {
            dns_message_clear_cookie(mesg);
            break;
        }
    }
}

/**
 * Sets the initial client_cookie for the given server address.
 *
 * @param mesg the message
 * @param sa the host_address_t of the address
 */

void dns_message_set_client_cookie_for_server_host_address(dns_message_t *mesg, const host_address_t *ha)
{
    switch(ha->version)
    {
        case HOST_ADDRESS_IPV4:
        {
            dns_message_set_client_cookie_for_server_address(mesg, ha->ip.v4.bytes, 4);
            break;
        }
        case HOST_ADDRESS_IPV6:
        {
            dns_message_set_client_cookie_for_server_address(mesg, ha->ip.v6.bytes, 16);
            break;
        }
        default:
        {
            dns_message_clear_cookie(mesg);
            break;
        }
    }
}

/**
 * Computes a server cookie value based on the (assumed present) client cookie, client IP and the g_cookie_secret.
 */

uint64_t dns_message_cookie_server_compute(dns_message_t *mesg)
{
    uint64_t value = FNV_basis;
    if(dns_message_has_cookie(mesg))
    {
        // COOKIE
        uint64_t v = *(uint64_t *)dns_message_client_cookie_ptr(mesg);
        for(int_fast32_t i = DNS_MESSAGE_COOKIE_CLIENT_SIZE; i > 0; --i)
        {
            value ^= v;
            v >>= 8;
            value *= FNV_prime;
        }
        // IP
        switch(dns_message_get_sender_sa(mesg)->sa_family)
        {
            case AF_INET:
            {
                v = *(uint32_t *)&dns_message_get_sender_sa4(mesg)->sin_addr.s_addr;
                for(int_fast32_t i = 4; i > 0; --i)
                {
                    value ^= v;
                    v >>= 8;
                    value *= FNV_prime;
                }
                break;
            }
            case AF_INET6:
            {
                const void *address_bytes = &dns_message_get_sender_sa6(mesg)->sin6_addr;
                v = ((const uint64_t *)address_bytes)[0];
                for(int_fast32_t i = 8; i > 0; --i)
                {
                    value ^= v;
                    v >>= 8;
                    value *= FNV_prime;
                }
                v = ((uint64_t *)address_bytes)[1];
                for(int_fast32_t i = 8; i > 0; --i)
                {
                    value ^= v;
                    v >>= 8;
                    value *= FNV_prime;
                }
                break;
            }
        }
        // SECRET
        v = g_cookie_secret;
        for(int_fast32_t i = 8; i > 0; --i)
        {
            value ^= v;
            v >>= 8;
            value *= FNV_prime;
        }
    }

    return value;
}

/**
 * Takes a message with the client cookie set.
 * Note that the client cookie MUST be set.
 * Sets the server cookie in that message.
 */

void dns_message_cookie_server_set(dns_message_t *mesg)
{
    uint64_t value = dns_message_cookie_server_compute(mesg);
    SET_U64_AT_P(dns_message_server_cookie_ptr(mesg), value);
    mesg->_cookie.size = DNS_MESSAGE_COOKIE_CLIENT_SIZE + DNS_MESSAGE_COOKIE_SERVER_SIZE;
}

/**
 * Takes a message with the client cookie set (assumed)
 * Checks if the server cookie in that message matches the expected value.
 *
 * Returns true iff the value is matched.
 */

bool dns_message_cookie_server_check(dns_message_t *mesg)
{
    uint64_t value = dns_message_cookie_server_compute(mesg);
    return *(uint64_t *)dns_message_server_cookie_ptr(mesg) == value;
}

#if DNSCORE_HAS_QUERY_US_DEBUG
void dns_message_log_query_us(dns_message_t *mesg, int64_t from_us, int64_t to_us)
{
    int64_t dt = to_us - from_us;
    if(dt < 0)
    {
        dt = 0; // don't break if the clock changes
    }
    double d = dt;
    d /= 1000.0;
    log_notice("message-time: %02x %{dnsname} %{dnstype} %6.3fms (%llius)", dns_message_get_flags(mesg), dns_message_get_canonised_fqdn(mesg), dns_message_get_query_type_ptr(mesg), d, dt);
}
#endif

/** @} */
