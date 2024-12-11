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

#include <dnscore/logger.h>
#include <dnscore/thread_pool.h>
#include <dnscore/fdtools.h>
#include <dnscore/rfc.h>
#include <dnscore/dns_packet_reader.h>

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "process_class_ch.h"
#include "confs.h"
#include "dnscore/dns_message_opt.h"

#define CHVRSION_TAG 0x4e4f495352564843
#define CHHOSTNM_TAG 0x4d4e54534f484843
#define CHIDSVR_TAG  0x52565344494843

extern logger_handle_t *g_server_logger;

/*
 * The TXT CH record wire.  Only the first 10 bytes will be taken.
 */

static uint8_t  chaos_txt_stub[10] = {0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00};

static uint8_t *version_txt = NULL;
static uint8_t *hostname_txt = NULL;
static uint8_t *id_server_txt = NULL;

void            class_ch_set_hostname(const char *name)
{
    if(name != NULL)
    {
        size_t   name_len = MIN(strlen(name), 255);
        uint8_t *tmp;
        MALLOC_OR_DIE(uint8_t *, tmp, 13 + name_len, CHHOSTNM_TAG);
        memcpy(tmp, chaos_txt_stub, 10); // VS false positive (nonsense)
        SET_U16_AT(tmp[10], htons(name_len + 1));
        tmp[12] = (uint8_t)name_len;
        memcpy(&tmp[13], name, name_len);
        uint8_t *old = hostname_txt;
        hostname_txt = tmp;
        free(old);
    }
    else
    {
        uint8_t *old = hostname_txt;
        hostname_txt = NULL;
        free(old);
    }
}

void class_ch_set_version(const char *name)
{
    if(name != NULL)
    {
        size_t   name_len = MIN(strlen(name), 255);
        uint8_t *tmp;
        MALLOC_OR_DIE(uint8_t *, tmp, 13 + name_len, CHVRSION_TAG);
        memcpy(tmp, chaos_txt_stub, 10); // VS false positive (nonsense)
        SET_U16_AT(tmp[10], htons(name_len + 1));
        tmp[12] = (uint8_t)name_len;
        memcpy(&tmp[13], name, name_len);
        uint8_t *old = version_txt;
        version_txt = tmp;
        free(old);
    }
    else
    {
        uint8_t *old = version_txt;
        version_txt = NULL;
        free(old);
    }
}

void class_ch_set_id_server(const char *name)
{
    if(name != NULL)
    {
        size_t   name_len = MIN(strlen(name), 255);
        uint8_t *tmp;
        MALLOC_OR_DIE(uint8_t *, tmp, 13 + name_len, CHIDSVR_TAG);
        memcpy(tmp, chaos_txt_stub, 10); // VS false positive (nonsense)
        SET_U16_AT(tmp[10], htons(name_len + 1));
        tmp[12] = (uint8_t)name_len;
        memcpy(&tmp[13], name, name_len);
        uint8_t *old = id_server_txt;
        id_server_txt = tmp;
        free(old);
    }
    else
    {
        uint8_t *old = id_server_txt;
        id_server_txt = NULL;
        free(old);
    }
}

/*
 * The SOA CH record wire.
 */

static uint8_t chaos_soa[5 * 8 + 7] = {0xc0, 0x0c, 0x00, 0x06, 0x00, 0x03, 0x00, 0x01, 0x51, 0x80, 0x00, 0x23, 0xc0, 0x0c, 0x0a, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65,
                                       0x72, 0xc0, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x80, 0x00, 0x00, 0x1c, 0x20, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x01, 0x51, 0x80};

/*
 * The NS CH record wire.
 */

static uint8_t chaos_ns[1 * 8 + 6] = {0xc0, 0x0c, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xc0, 0x0c};

static void    chaos_make_message(dns_message_t *mesg, const uint8_t *record_wire, uint32_t record_wire_len)
{
    uint16_t t = dns_message_get_query_type(mesg);
    uint16_t an = 0;
    uint16_t au = 0;

    /* set the flags */

    dns_message_set_authoritative_answer(mesg);
    dns_message_apply_mask(mesg, QR_BITS | AA_BITS | RD_BITS, 0);

    uint8_t *p = dns_message_get_buffer_limit(mesg);

    if(t == TYPE_TXT || t == TYPE_ANY)
    {
        memcpy(p, record_wire, record_wire_len);

        p += record_wire_len;

        an++;
    }
    if(t == TYPE_SOA || t == TYPE_ANY)
    {
        memcpy(p, chaos_soa, sizeof(chaos_soa));
        p += sizeof(chaos_soa);

        dns_message_set_answer_count_ne(mesg, NETWORK_ONE_16);

        an++;
    }

    memcpy(p, chaos_ns, sizeof(chaos_ns));
    p += sizeof(chaos_ns);

    if(t == TYPE_ANY || t == TYPE_NS)
    {
        an++;
    }
    else
    {
        au++;
    }

    dns_message_set_answer_count(mesg, an);
    dns_message_set_authority_count(mesg, au);
    dns_message_set_size(mesg, p - dns_message_get_buffer_const(mesg));

    dns_message_edns0_append(mesg);
}

void class_ch_process(dns_message_t *mesg)
{
    ya_result return_value;

    uint8_t   qname[DOMAIN_LENGTH_MAX];

#if HAS_ACL_SUPPORT
    if(ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_query)))
    {
        dns_message_set_status(mesg, FP_ACCESS_REJECTED);
        dns_message_transform_to_error(mesg);

        return;
    }
#endif

    dns_packet_reader_t purd;
    dns_packet_reader_init_from_message(&purd, mesg);

    if(FAIL(return_value = dns_packet_reader_read_fqdn(&purd, qname, sizeof(qname))))
    {
        /* oops */

        log_err("chaos: error reading query: %r", return_value);

        return;
    }

    /* version */

    if((id_server_txt != NULL) && dnsname_equals_ignorecase((const uint8_t *)"\002id\006server", qname))
    {
        chaos_make_message(mesg, id_server_txt, 12 + ntohs(GET_U16_AT(id_server_txt[10])));
    }
    else if((hostname_txt != NULL) && dnslabel_equals_ignorecase_left((const uint8_t *)"\010hostname", qname))
    {
        chaos_make_message(mesg, hostname_txt, 12 + ntohs(GET_U16_AT(hostname_txt[10])));
    }
    else if((version_txt != NULL) && dnslabel_equals_ignorecase_left((const uint8_t *)"\007version", qname))
    {
        chaos_make_message(mesg, version_txt, 12 + ntohs(GET_U16_AT(version_txt[10])));
    }
    else
    {
        /* REFUSED */

        dns_message_set_status(mesg, FP_NOZONE_FOUND);
        dns_message_transform_to_error(mesg);
    }

#if DNSCORE_HAS_TSIG_SUPPORT

    if(dns_message_has_tsig(mesg)) /* NOTE: the TSIG information is in mesg */
    {
        tsig_sign_answer(mesg);
    }
#endif
}

/** @} */
