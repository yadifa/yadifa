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

#include <dnscore/logger.h>
#include <dnscore/thread_pool.h>
#include <dnscore/fdtools.h>
#include <dnscore/rfc.h>
#include <dnscore/packet_reader.h>

extern logger_handle *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#include "process_class_ch.h"
#include "confs.h"

#define CHVRSION_TAG 0x4e4f495352564843
#define CHHOSTNM_TAG 0x4d4e54534f484843
#define CHIDSVR_TAG 0x52565344494843

extern logger_handle* g_server_logger;

/*
 * The TXT CH record wire.  Only the first 10 bytes will be taken.
 */

static u8 chaos_txt_stub[10] =
{
    0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00
};

static u8 *version_txt = NULL;
static u8 *hostname_txt = NULL;
static u8 *id_server_txt = NULL;

void
class_ch_set_hostname(const char *name)
{
    if(name != NULL)
    {
        size_t name_len = MIN(strlen(name), 255);
        u8* tmp;
        MALLOC_OR_DIE(u8*, tmp, 13 + name_len, CHHOSTNM_TAG);
        memcpy(tmp, chaos_txt_stub, 10); // VS false positive (nonsense)
        SET_U16_AT(tmp[10], htons(name_len + 1));
        tmp[12] = (u8)name_len;
        memcpy(&tmp[13], name, name_len);
        u8 *old = hostname_txt;
        hostname_txt = tmp;
        free(old);
    }
    else
    {
        u8 *old = hostname_txt;
        hostname_txt = NULL;
        free(old);
    }
}

void
class_ch_set_version(const char *name)
{
    if(name != NULL)
    {
        size_t name_len = MIN(strlen(name), 255);
        u8* tmp;
        MALLOC_OR_DIE(u8*, tmp, 13 + name_len, CHVRSION_TAG);
        memcpy(tmp, chaos_txt_stub, 10); // VS false positive (nonsense)
        SET_U16_AT(tmp[10], htons(name_len + 1));
        tmp[12] = (u8)name_len;
        memcpy(&tmp[13], name, name_len);
        u8 *old = version_txt;
        version_txt = tmp;
        free(old);
    }
    else
    {
        u8 *old = version_txt;
        version_txt = NULL;
        free(old);
    }
}

void
class_ch_set_id_server(const char *name)
{
    if(name != NULL)
    {
        size_t name_len = MIN(strlen(name), 255);
        u8* tmp;
        MALLOC_OR_DIE(u8*, tmp, 13 + name_len, CHIDSVR_TAG);
        memcpy(tmp, chaos_txt_stub, 10); // VS false positive (nonsense)
        SET_U16_AT(tmp[10], htons(name_len + 1));
        tmp[12] = (u8)name_len;
        memcpy(&tmp[13], name, name_len);
        u8 *old = id_server_txt;
        id_server_txt = tmp;
        free(old);
    }
    else
    {
        u8 *old = id_server_txt;
        id_server_txt = NULL;
        free(old);
    }
}

/*
 * The SOA CH record wire.
 */

static u8 chaos_soa[5*8 + 7] = {
    0xc0, 0x0c, 0x00, 0x06, 0x00, 0x03, 0x00, 0x01, 0x51, 0x80,
    0x00, 0x23, 0xc0, 0x0c, 0x0a, 0x68, 0x6f, 0x73, 0x74, 0x6d,
    0x61, 0x73, 0x74, 0x65, 0x72, 0xc0, 0x0c, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x70, 0x80, 0x00, 0x00, 0x1c, 0x20, 0x00,
    0x09, 0x3a, 0x80, 0x00, 0x01, 0x51, 0x80 };

/*
 * The NS CH record wire.
 */

static u8 chaos_ns[1*8 + 6] = {
    0xc0, 0x0c, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0xc0, 0x0c };

static void
chaos_make_message(message_data *mesg, const u8* record_wire, u32 record_wire_len)
{
    u16 t = message_get_query_type(mesg);
    u16 an = 0;
    u16 au = 0;
    
    /* set the flags */

    message_set_authoritative_answer(mesg);
    message_apply_mask(mesg, QR_BITS|AA_BITS|RD_BITS, 0);

    u8 *p = message_get_buffer_limit(mesg);

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

        message_set_answer_count_ne(mesg, NETWORK_ONE_16);

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

    message_set_answer_count(mesg, an);
    message_set_authority_count(mesg, au);

    if(message_is_edns0(mesg))
    {
        u16 edns0_maxsize = g_config->edns0_max_size;
        u32 rcode_ext = message_get_rcode_ext(mesg);

        p[ 0] = 0;
        p[ 1] = 0;
        p[ 2] = 0x29;        
        p[ 3] = edns0_maxsize>>8;
        p[ 4] = edns0_maxsize;
        p[ 5] = (message_get_status(mesg) >> 4);
        p[ 6] = rcode_ext >> 16;
        p[ 7] = rcode_ext >> 8;
        p[ 8] = rcode_ext;

#if DNSCORE_HAS_NSID_SUPPORT
        if(!message_has_nsid(mesg))
        {
            p[ 9] = 0;
            p[10] = 0;

            p += EDNS0_RECORD_SIZE;
        }
        else
        {                
            p += EDNS0_RECORD_SIZE - 2;
            memcpy(p, edns0_rdatasize_nsid_option_wire, edns0_rdatasize_nsid_option_wire_size);
            p += edns0_rdatasize_nsid_option_wire_size;
        }
#else
        p[ 9] = 0;
        p[10] = 0;

        p += EDNS0_RECORD_SIZE;
#endif
        message_set_additional_count_ne(mesg, NETWORK_ONE_16);
    }

    message_set_size(mesg, p - message_get_buffer_const(mesg));
}

void
class_ch_process(message_data *mesg)
{
    ya_result return_value;

    u8 qname[MAX_DOMAIN_LENGTH];
    
#if HAS_ACL_SUPPORT
    if(ACL_REJECTED(acl_check_access_filter(mesg, &g_config->ac->allow_query)))
    {
        message_set_status(mesg, FP_ACCESS_REJECTED);
        message_transform_to_error(mesg);
        
        return;
    }
#endif

    packet_unpack_reader_data purd;
    packet_reader_init_from_message(&purd, mesg);

    if(FAIL(return_value = packet_reader_read_fqdn(&purd, qname, sizeof(qname))))
    {
        /* oops */

        log_err("chaos: error reading query: %r", return_value);

        return;
    }

    /* version */

    if((id_server_txt != NULL) && dnsname_equals_ignorecase((const u8*)"\002id\006server", qname))
    {
        chaos_make_message(mesg, id_server_txt, 12 + ntohs(GET_U16_AT(id_server_txt[10])));
    }
    else if((hostname_txt != NULL) && dnslabel_equals_ignorecase_left((const u8*)"\010hostname", qname))
    {
        chaos_make_message(mesg, hostname_txt, 12 + ntohs(GET_U16_AT(hostname_txt[10])));
    }
    else if((version_txt != NULL) && dnslabel_equals_ignorecase_left((const u8*)"\007version", qname))
    {
        chaos_make_message(mesg, version_txt, 12 + ntohs(GET_U16_AT(version_txt[10])));
    }
    else
    {
        /* REFUSED */

        message_set_status(mesg, FP_NOZONE_FOUND);
        message_transform_to_error(mesg);
    }

#if DNSCORE_HAS_TSIG_SUPPORT

    if(message_has_tsig(mesg))  /* NOTE: the TSIG information is in mesg */
    {
        tsig_sign_answer(mesg);
    }
#endif
}

/** @} */
