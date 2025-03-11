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
 * @defgroup ### #######
 * @ingroup dnsdb
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _DNSRDATA_H
#define _DNSRDATA_H

#error "This file is now obsolete."

#include <dnsdb/zdb_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#if OBSOLETE

/*
 * I need:
 *
 * NS,MD,MF,CNAME,SOA,MB,MG,MR,PTR,HINFO,MINFO,MX,RP,AFSDB,RT,SIG,PX,NXT,NAPTR,KX,SRV,DNAME,A6,RRSIG,NSEC
 * ++ ++ ++ +++++ +++ ++ ++ ++ +++ +++++ +++++ ++ ?? ????? ??                               ++ +++++ ++++
 */

typedef struct dnskey_rdata dnskey_rdata;
struct dnskey_rdata
{
    uint16_t flags;
    uint8_t  protocol;
    uint8_t  algorithm;
    uint8_t *public_key;
};

void rdata_to_dnskey(uint8_t *rdata, struct dnskey_rdata *dnskey);

struct rrsig_rdata
{
    uint16_t type_covered;
    uint8_t  algorithm;
    uint8_t  labels;
    uint32_t original_ttl;
    uint32_t signature_expiration;
    uint32_t signature_inception;
    uint8_t *signer_name;
    uint8_t *signature;
};

void rdata_to_rrsig(uint8_t *rdata, struct rrsig_rdata *rrsig);

#endif

#if OBSOLETE

/* rfc3845 */

typedef struct
{
    uint8_t  window_number;
    uint8_t  bitmap_length;
    uint8_t *bitmap; /* NOT A NAME */
} nsec_rdata_typebitmap;

/* rfc3845 */

struct nsec_rdata
{
    uint8_t               *domain_name;
    nsec_rdata_typebitmap *type_bitmap;
};

struct ns_rdata
{
    uint8_t *name;
};

struct cname_rdata
{
    uint8_t *name;
};

struct dname_rdata
{
    uint8_t *name;
};

struct ptr_rdata
{
    uint8_t *name;
};

struct mb_rdata
{
    uint8_t *madname;
};

struct md_rdata
{
    uint8_t *madname;
};

struct mf_rdata
{
    uint8_t *madname;
};

struct mg_rdata
{
    uint8_t *madname;
};

struct mr_rdata
{
    uint8_t *newname;
};

struct mx_rdata
{
    uint16_t preference;
    uint8_t *exchange;
};

struct hinfo_rdata
{
    uint8_t *cpu;
    uint8_t *os;
};

struct minfo_rdata
{
    uint8_t *rmailbx;
    uint8_t *emailbx;
};

/* rfc2782 */

struct srv_rdata
{
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    uint8_t *domain_name;
};

/* rfc2874 */

struct a6_rdata
{
    uint8_t  prefix_length;
    uint16_t address_suffix;
    uint8_t *prefix_name;
};

typedef uint64_t u48;

/* rfc2535 */

struct sig_rdata
{
    uint16_t type_covered;
    uint8_t  algorithm;
    uint8_t  labels;
    uint32_t original_ttl;
    uint32_t signature_expiration;
    uint32_t signature_inception;
    uint16_t key_tag;
    uint8_t *signer_name;
    uint8_t *signature; /* NOT A NAME */
};

/* rfc2845 */

struct tsig_rdata
{
    uint8_t *domain_name;
    u48      time_signed;
    uint16_t fudge;
    uint16_t mac_size;
    uint8_t *mac;
    uint16_t original_id;
    uint16_t error;
    uint16_t other_len;
    uint8_t *other_data;
};

/* No need to canonize */

struct txt_rdata
{
    char *txt;
};

struct a_rdata
{
    uint32_t address;
};

/** rfc1886 */

struct aaaa_rdata
{
    uint16_t address[8];
};

struct wks_rdata
{
    uint32_t address;
    uint8_t  protocol;
    uint8_t *bitmap; /* NOT A NAME */
};

#endif

#ifdef __cplusplus
}
#endif

#endif /* _DNSRECORDS_H */

/** @} */
