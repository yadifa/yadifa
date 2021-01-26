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
 *  @ingroup dnsdb
 *  @brief 
 *
 * @{
 */
#ifndef _DNSRDATA_H
#define	_DNSRDATA_H

#include <dnsdb/zdb_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * I need:
 *
 * NS,MD,MF,CNAME,SOA,MB,MG,MR,PTR,HINFO,MINFO,MX,RP,AFSDB,RT,SIG,PX,NXT,NAPTR,KX,SRV,DNAME,A6,RRSIG,NSEC
 * ++ ++ ++ +++++ +++ ++ ++ ++ +++ +++++ +++++ ++ ?? ????? ??                               ++ +++++ ++++
 */

typedef struct dnskey_rdata dnskey_rdata;
struct dnskey_rdata
{
    u16 flags;
    u8 protocol;
    u8 algorithm;
    u8* public_key;
};

void rdata_to_dnskey(u8* rdata,struct dnskey_rdata* dnskey);

struct rrsig_rdata
{
    u16 type_covered;
    u8 algorithm;
    u8 labels;
    u32 original_ttl;
    u32 signature_expiration;
    u32 signature_inception;
    u8* signer_name;
    u8* signature;
};

void rdata_to_rrsig(u8* rdata,struct rrsig_rdata* rrsig);

typedef struct soa_rdata soa_rdata;

struct soa_rdata
{
    const u8* mname;
    const u8* rname;
    u32 serial;
    u32 refresh;
    u32 retry;
    u32 expire;
    u32 minimum;    /* TTL / NTTL */
};

/* rfc3845 */

typedef struct
{
    u8 window_number;
    u8 bitmap_length;
    u8* bitmap;             /* NOT A NAME */
} nsec_rdata_typebitmap;

/* rfc3845 */

struct nsec_rdata
{
    u8* domain_name;
    nsec_rdata_typebitmap* type_bitmap;
};

struct ns_rdata
{
    u8* name;
};

struct cname_rdata
{
    u8* name;
};

struct dname_rdata
{
    u8* name;
};

struct ptr_rdata
{
    u8* name;
};

struct mb_rdata
{
    u8* madname;
};

struct md_rdata
{
    u8* madname;
};

struct mf_rdata
{
    u8* madname;
};

struct mg_rdata
{
    u8* madname;
};

struct mr_rdata
{
    u8* newname;
};

struct mx_rdata
{
    u16 preference;
    u8* exchange;
};

struct hinfo_rdata
{
    u8* cpu;
    u8* os;
};

struct minfo_rdata
{
    u8* rmailbx;
    u8* emailbx;
};

/* rfc2782 */

struct srv_rdata
{
    u16 priority;
    u16 weight;
    u16 port;
    u8* domain_name;
};

/* rfc2874 */

struct a6_rdata
{
    u8  prefix_length;
    u16 address_suffix;
    u8* prefix_name;
};

typedef u64 u48;

/* rfc2535 */

struct sig_rdata
{
    u16 type_covered;
    u8 algorithm;
    u8 labels;
    u32 original_ttl;
    u32 signature_expiration;
    u32 signature_inception;
    u16 key_tag;
    u8* signer_name;
    u8* signature;          /* NOT A NAME */
};

/* rfc2845 */

struct tsig_rdata
{
    u8* domain_name;
    u48 time_signed;
    u16 fudge;
    u16 mac_size;
    u8* mac;
    u16 original_id;
    u16 error;
    u16 other_len;
    u8* other_data;
};

/* No need to canonize */

struct txt_rdata
{
    char* txt;
};

struct a_rdata
{
    u32 address;
};

/** rfc1886 */

struct aaaa_rdata
{
    u16 address[8];
};

struct wks_rdata
{
    u32 address;
    u8 protocol;
    u8* bitmap; /* NOT A NAME */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _DNSRECORDS_H */

    /*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/
