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

/** @defgroup zone Functions used to sanitize a zone
 *  @ingroup dnsdb
 *  @brief Functions used to sanitize a zone
 *
 *  Functions used to sanitize a zone
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"

#include <stdarg.h>

#include <dnscore/dnscore.h>
#include <dnscore/logger.h>
#include <dnscore/format.h>
#include <dnscore/u32_set.h>
#include <dnscore/dnskey.h>

#include "dnsdb/zdb_sanitize.h"
#include "dnsdb/zdb_zone_load.h"
#include "dnsdb/rrsig.h"

#if HAS_DNSSEC_SUPPORT
#include "dnsdb/rrsig.h"
#endif

#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"

#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_error.h"

#define SANITIZE_OVERSHARE 0        // don't, this is dev/debugging
#define SANITIZE_LABEL_SUMMARY 0    // don't, this is dev/debugging

#define SANTIZE_DROP_LONELY_DS 0

#define SANITIZE_DETECT_MISSING_GLUES 1

extern logger_handle* g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

#define TYPES_INIT(b_)          u64 b_ = 0
#define TYPES_HAS(b_,t_)        (((b_) & (1ULL << NU16(t_))) != 0)
#define TYPES_ONLY_HAS(b_,t_)   ((b_) == (1ULL << NU16(t_)))
#define TYPES_SET(b_,t_)        ((b_) |= (1ULL << NU16(t_)))
#define TYPES_SET_OTHER(b_)     ((b_) |= (1ULL << 0)) // zero must never be used, so it's a perfect place holder
#define TYPES_CLEAR(b_,t_)      ((b_) &= ~(1ULL << (t)))
#define TYPES_AND_MASK(b_,m_)   ((b_) & (m_))

static u8 u64_count_bits(u64 value)
{
    static const u8 bitcount[256] =
    {
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
        4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
    };

    u8 total = 0;

    while(value != 0)
    {
        total += bitcount[value & 0xff];
        value >>= 8;
    }

    return total;
}

static void
zdb_sanitize_parms_init(zdb_sanitize_parms *parms, zdb_zone *zone, struct zdb_zone_load_parms *load_parms)
{
    memset(parms, 0, sizeof(*parms));
    parms->zone = zone;
    u32_set_init(&parms->dnskey_set);
    parms->load_parms = load_parms;
}

#if ZDB_HAS_DNSSEC_SUPPORT

static void
zdb_sanitize_parms_update_keys(zdb_sanitize_parms *parms)
{
    const zdb_packed_ttlrdata *dnskey_rrset = zdb_zone_get_dnskey_rrset(parms->zone);
    while(dnskey_rrset != NULL)
    {
        const u8 *dnskey_rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(dnskey_rrset);
        u32 dnskey_rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(dnskey_rrset);
        
        u16 keytag = dnskey_get_tag_from_rdata(dnskey_rdata, dnskey_rdata_size);

        u32_set_insert(&parms->dnskey_set, keytag);
        
        dnskey_rrset = dnskey_rrset->next;
    }
}



#endif

void
zdb_sanitize_parms_finalize(zdb_sanitize_parms *parms)
{
    u32_set_destroy(&parms->dnskey_set);
}

#if SANITIZE_LABEL_SUMMARY
static void
zdb_sanitize_log(dnsname_stack *dnsnamev, ya_result err)
{


    if(err & SANITY_UNEXPECTEDSOA)
    {
        log_warn("sanity: %{dnsnamestack} failed: unexpected SOA", dnsnamev);
    }
    if(err & SANITY_TOOMANYSOA)
    {
        log_err("sanity: %{dnsnamestack} failed: too many SOA", dnsnamev);
    }
    if(err & SANITY_CNAMENOTALONE)
    {
        log_warn("sanity: %{dnsnamestack} failed: CNAME must be alone", dnsnamev);
    }
    if(err & SANITY_UNEXPECTEDCNAME)
    {
        log_warn("sanity: %{dnsnamestack} failed: unexpected CNAME", dnsnamev);
    }
    if(err & SANITY_EXPECTEDNS)
    {
        log_warn("sanity: %{dnsnamestack} failed: expected NS", dnsnamev);
    }
    if(err & SANITY_UNEXPECTEDDS)
    {
        log_warn("sanity: %{dnsnamestack} failed: unexpected DS", dnsnamev);
    }
    if(err & SANITY_MUSTDROPZONE)
    {
        log_err("sanity: %{dnsnamestack} critical error : the zone will be dropped", dnsnamev);
    }
    if(err & SANITY_TRASHATDELEGATION)
    {
        log_warn("sanity: %{dnsnamestack} failed: delegation has unexpected records", dnsnamev);
    }
    if(err & SANITY_TRASHUNDERDELEGATION)
    {
        log_warn("sanity: %{dnsnamestack} failed: non-glue record(s) found under delegation", dnsnamev);
    }
    // SANITY_TOOMANYNSEC is not used
    if(err & SANITY_RRSIGWITHOUTKEYS)
    {
        log_warn("sanity: %{dnsnamestack} failed: RRSIG record(s) without matched DNSKEY", dnsnamev);
    }
    if(err & SANITY_RRSIGWITHOUTSET)
    {
        log_warn("sanity: %{dnsnamestack} failed: RRSIG record(s) over an absent RRSET", dnsnamev);
    }
    if(err & SANITY_RRSIGTTLDOESNTMATCH)
    {
        log_warn("sanity: %{dnsnamestack} failed: RRSIG record(s) TTL does not match the one of the covered RRSET", dnsnamev);
    }
}
#endif

/**
 * There must be an NS rrset on the path that matches the name
 */

static void
zdb_sanitize_rr_set_useless_glue(zdb_zone *zone, zdb_rr_label *label, dnsname_stack *name, zdb_rr_label** parent)
{
    zdb_rr_label** delegation = parent;

    // start from the parent
    // while there is a delegation

    while(*delegation != NULL)
    {
        zdb_packed_ttlrdata* delegation_ns_record_list_head = zdb_record_find(&(*delegation)->resource_record_set, TYPE_NS);

        // if there is an NS rrset

        if(delegation_ns_record_list_head != NULL)
        {
            do
            {
                if(dnsname_equals_dnsname_stack(ZDB_PACKEDRECORD_PTR_RDATAPTR(delegation_ns_record_list_head), name))
                {
                    // if the fqdn in the rdata matches the glue, there is nothing further

                    return;
                }

                delegation_ns_record_list_head = delegation_ns_record_list_head->next;
            }
            while(delegation_ns_record_list_head != NULL);
        }

        --delegation;
    }

    // the NS fqdn has not been found : warn about it

    static const u16 ip_types[2] = {TYPE_A, TYPE_AAAA};

    for(int i = 0; i < 2; ++i)
    {
        zdb_packed_ttlrdata* ip_record_list = zdb_record_find(&label->resource_record_set, ip_types[i]);

        if(ip_record_list != NULL)
        {
            rdata_desc rdatadesc;
            rdatadesc.type = ip_types[i];
            rdatadesc.len = ZDB_PACKEDRECORD_PTR_RDATASIZE(ip_record_list);
            rdatadesc.rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(ip_record_list);

            log_warn("sanity: %{dnsname}: consider removing wrong glue: %{dnsnamestack} %{typerdatadesc}", zone->origin, name, &rdatadesc);
        }
    }
}

static u32
zdb_sanitize_rr_set_ext(zdb_sanitize_parms *parms, zdb_rr_label *label, dnsname_stack *name, u16 flags, zdb_rr_label** parent)
{
    zdb_zone *zone = parms->zone;
    /*
     * CNAME : nothing else than RRSIG & NSEC
     */

    // record counts for ... (can overlap)

    const u64 not_cmake_nsec_rrsig_mask = ~((1ULL<<NU16(TYPE_CNAME))|(1ULL<<NU16(TYPE_NSEC))|(1ULL<<NU16(TYPE_RRSIG)));
    const u64 not_ns_ds_nsec_rrsig_mask = ~((1ULL<<NU16(TYPE_DS))|(1ULL<<NU16(TYPE_NS))|(1ULL<<NU16(TYPE_NSEC))|(1ULL<<NU16(TYPE_RRSIG)));
    const u64 not_a_aaaa_mask = ~((1ULL<<NU16(TYPE_A))|(1ULL<<NU16(TYPE_AAAA)));
    const u64 not_a_aaaa_ns_ds_mask = ~((1ULL<<NU16(TYPE_A))|(1ULL<<NU16(TYPE_AAAA))|(1ULL<<NU16(TYPE_NS))|(1ULL<<NU16(TYPE_DS)));
    const u64 ns_ds_mask = ((1ULL<<NU16(TYPE_NS))|(1ULL<<NU16(TYPE_DS)));
    const u64 ds_mask = (1ULL<<NU16(TYPE_DS));
    const u64 not_rrsig_mask = ~(1ULL<<NU16(TYPE_RRSIG));

    //const u64 others_mask = (1ULL<<63);     // this type is unassigned

    const u64 a_aaaa_mask = ((1ULL<<NU16(TYPE_A))|(1ULL<<NU16(TYPE_AAAA)));


    TYPES_INIT(dns_rrset_types);

    u32 rr_set_status = 0;

    bool ns_points_to_itself = FALSE;
    bool isapex = zone->apex == label;
    bool at_delegation = flags & ZDB_RR_LABEL_DELEGATION;
    bool under_delegation = flags & ZDB_RR_LABEL_UNDERDELEGATION;

    btree_iterator iter;
    btree_iterator_init(label->resource_record_set, &iter);

    while(btree_iterator_hasnext(&iter))
    {
        btree_node* node = btree_iterator_next_node(&iter);
        u16 type = node->hash;

        zdb_packed_ttlrdata* record_list = (zdb_packed_ttlrdata*)node->data;

        if(type != TYPE_RRSIG)
        {
            s32 ttl = record_list->ttl;
            while((record_list = record_list->next) != NULL)
            {
                record_list->ttl = ttl;
            }
        }
        else
        {
            u16 keytag = rrsig_get_key_tag_from_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(record_list), ZDB_PACKEDRECORD_PTR_RDATASIZE(record_list));

            u32_node *node = u32_set_find(&parms->dnskey_set, keytag);
            if(node != NULL)
            {
                // no key for this signature
                u16 rrsig_ctype = rrsig_get_type_covered_from_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(record_list), ZDB_PACKEDRECORD_PTR_RDATASIZE(record_list));
                s32 rrsig_ttl = rrsig_get_original_ttl_from_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(record_list), ZDB_PACKEDRECORD_PTR_RDATASIZE(record_list));
                record_list->ttl = rrsig_ttl;

                zdb_packed_ttlrdata *rrsig_ctype_rrset = zdb_record_find(&label->resource_record_set, rrsig_ctype);

                if(rrsig_ctype_rrset != NULL)
                {
                    s32 rrsig_ctype_ttl = rrsig_ctype_rrset->ttl;
                    if(rrsig_ctype_ttl != rrsig_ttl)
                    {
                        // signature TTL is wrong
                        rr_set_status |= SANITY_RRSIGTTLDOESNTMATCH;
                        parms->has_bogus_rrsig = TRUE;
                    }
                }
                else
                {
                    // signature covered type wrong
                    rr_set_status |= SANITY_RRSIGWITHOUTSET;
                    parms->has_bogus_rrsig = TRUE;

                    log_warn("zone: sanitize: %{dnsname}: %{dnsnamestack}: RRSIG covers a non-existing resource record set %{dnstype}",
                            zone->origin, name, &rrsig_ctype);
                }

                /// @note : maybe also verify RRSIG signature
            }
            else
            {
                rr_set_status |= SANITY_RRSIGWITHOUTKEYS;
                parms->has_bogus_rrsig = TRUE;

                log_warn("zone: sanitize: %{dnsname}: %{dnsnamestack}: RRSIG made with key with tag=%hu but there is no such key", zone->origin, name, keytag);
            }
        }

        if((type & NU16(0xffc0)) == 0) // only handle the 64 first types
        {
            if(type == TYPE_SOA)
            {
                if(TYPES_HAS(dns_rrset_types, TYPE_SOA))
                {
                    if(isapex)
                    {
                        rr_set_status |= SANITY_UNEXPECTEDSOA | SANITY_MUSTDROPZONE;
                        log_warn("zone: sanitize: %{dnsname}: too many SOA", zone->origin);
                    }
                    else
                    {
                        rr_set_status |= SANITY_UNEXPECTEDSOA;
                        log_warn("zone: sanitize: %{dnsname}: %{dnsnamestack}: unexpected SOA", zone->origin, name);
                    }
                }
            }

            TYPES_SET(dns_rrset_types, type); // types bitmap
        }
        else
        {
            TYPES_SET_OTHER(dns_rrset_types);
        }
    }

    parms->types_mask |= dns_rrset_types;

#if ZDB_HAS_DNSSEC_SUPPORT
    if(parms->load_parms != NULL) // gather information about signature status
    {
        if(TYPES_HAS(dns_rrset_types, TYPE_DNSKEY))
        {
            const zdb_packed_ttlrdata* dnskey_record_list = zdb_record_find(&label->resource_record_set, TYPE_DNSKEY);
            const zdb_packed_ttlrdata* dnskey = dnskey_record_list;
            while(dnskey != NULL)
            {
                zdb_zone_load_parms_dnskey_add(parms->load_parms, ZDB_PACKEDRECORD_PTR_RDATAPTR(dnskey), ZDB_PACKEDRECORD_PTR_RDATASIZE(dnskey));
                dnskey = dnskey->next;
            }
        }

        TYPES_INIT(rrsig_covered_types);

        if(TYPES_HAS(dns_rrset_types, TYPE_RRSIG))
        {
            // bool has_ds = TYPES_HAS(dns_rrset_types, TYPE_DS);

            const zdb_packed_ttlrdata* rrsig_record_list = zdb_record_find(&label->resource_record_set, TYPE_RRSIG);
            const zdb_packed_ttlrdata* rrsig = rrsig_record_list;
            // the signing key must be known
            while(rrsig != NULL)
            {
                u16 covered_type = rrsig_get_type_covered_from_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig));

                u16 flags = zdb_zone_load_parms_get_key_flags_from_rrsig_rdata(parms->load_parms, ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig));

                if(flags == 0)
                {
                    flags = DNSKEY_FLAGS_ZSK; // assume ZSK
                }

                if((covered_type & NU16(0xffc0)) == 0)
                {
                    TYPES_SET(rrsig_covered_types, covered_type); // types bitmap

                    if(covered_type != TYPE_RRSIG)
                    {
                        TYPES_SET(rrsig_covered_types, covered_type); // types bitmap

                        if(flags == DNSKEY_FLAGS_ZSK)
                        {
                            if(TYPES_HAS(dns_rrset_types, covered_type))
                            {
                                // signed ...

                                // should type signed for NSEC ?            // yes, always at or above delegations
                                // should type signed for NSEC3 OPTIN ?     // yes, always at or above delegations
                                // should type signed for NSEC3 OPTOUT ?    // everything but delegations without a DS and under delegations

                                if(at_delegation)
                                {
                                    // NS & DS for NSEC & NSEC3IN
                                    // if has_ds DS for NSEC3OUT

                                    switch(covered_type)
                                    {
                                        case TYPE_NS:
#if SANITIZE_OVERSHARE
                                            log_warn("sanity: %{dnsnamestack}: N3O: NS at delegation should not be signed", name);
#endif
                                            ++parms->nsec3out_extraneous_rrsig;
                                            break;
                                        case TYPE_DS:
                                            break;
                                        default:
#if SANITIZE_OVERSHARE
                                            log_warn("sanity: %{dnsnamestack}: ANY: %{dnstype} at delegation should not be signed", name, &covered_type);
#endif
                                            ++parms->nsec_extraneous_rrsig;
                                            ++parms->nsec3in_extraneous_rrsig;
                                            ++parms->nsec3out_extraneous_rrsig;
                                            break;
                                    }
                                }
                                else if(under_delegation)
                                {
                                    // nothing

                                    if((dns_rrset_types & ns_ds_mask) == 0)
                                    {
#if SANITIZE_OVERSHARE
                                        log_warn("sanity: %{dnsnamestack}: ANY: %{dnstype} under delegation should not be signed", name, &covered_type);
#endif

                                        ++parms->nsec_extraneous_rrsig;
                                        ++parms->nsec3in_extraneous_rrsig;
                                        ++parms->nsec3out_extraneous_rrsig;

                                        rr_set_status |= SANITY_RRSIGUNDERDELETATION;

                                        log_warn("zone: sanitize: %{dnsname}: %{dnsnamestack}: unexpected RRSIG under a delegation", zone->origin, name);
                                    }
                                }
                                else
                                {
                                    // should be signed so it's all right
                                }
                            }
                            else
                            {
                                // signature covers a type that's not present
#if SANITIZE_OVERSHARE
                                log_warn("sanity: %{dnsnamestack}: ANY: %{dnstype} is signed but not present", name, &covered_type);
#endif
                                rr_set_status |= SANITY_RRSIGWITHOUTSET;

                                log_warn("zone: sanitize: %{dnsname}: %{dnsnamestack}: RRSIG covers a non-existing resource record set %{dnstype}",
                                         zone->origin, name, &covered_type);
                            }
                        }
                        else if(flags == DNSKEY_FLAGS_KSK)
                        {
                            if(covered_type != TYPE_DNSKEY)
                            {
                                rr_set_status |= SANITY_RRSIGBYKSKOVERNONKEY;
#if SANITIZE_OVERSHARE
                                log_warn("sanity: %{dnsnamestack}: ANY: %{dnstype} is signed by a key signing key", name, &covered_type);
#endif
                                log_warn("zone: sanitize: %{dnsname}: key-signing-key used to sign a %{dnstype} rrset", zone->origin, &covered_type);

                                ++parms->nsec_extraneous_rrsig;
                                ++parms->nsec3in_extraneous_rrsig;
                                ++parms->nsec3out_extraneous_rrsig;
                            }
                            else if(!isapex)
                            {
#if SANITIZE_OVERSHARE
                                log_warn("sanity: %{dnsnamestack}: ANY: %{dnstype} is used out of the apex", name, &covered_type);
#endif
                                log_warn("zone: sanitize: %{dnsname}: key-signing-key used out of the apex", zone->origin);

                                ++parms->nsec_extraneous_rrsig;
                                ++parms->nsec3in_extraneous_rrsig;
                                ++parms->nsec3out_extraneous_rrsig;

                                rr_set_status |= SANITY_RRSIGBYKSKNOTINAPEX;
                            }
                        }
                        else
                        {
                            // ignored
                        }

                    }
                    else
                    {
                        rr_set_status |= SANITY_RRSIGOVERRRSIG;
                        log_warn("zone: sanitize: %{dnsname}: %{dnsnamestack}: unexpected RRSIG of an RRSIG", zone->origin, name);
                    }
                }
                else
                {
                    if(at_delegation)
                    {
                        // NS & DS for NSEC & NSEC3IN
                        // if has_ds DS for NSEC3OUT
#if SANITIZE_OVERSHARE
                        log_warn("sanity: %{dnsnamestack}: ANY: %{dnstype} at delegation should not be signed", name, &covered_type);
#endif
                        ++parms->nsec_extraneous_rrsig;
                        ++parms->nsec3in_extraneous_rrsig;
                        ++parms->nsec3out_extraneous_rrsig;
                    }
                    else if(under_delegation)
                    {
                        // nothing

                        if((dns_rrset_types & ns_ds_mask) == 0)
                        {
#if SANITIZE_OVERSHARE
                            log_warn("sanity: %{dnsnamestack}: ANY: %{dnstype} under delegation should not be signed", name, &covered_type);
#endif

                            ++parms->nsec_extraneous_rrsig;
                            ++parms->nsec3in_extraneous_rrsig;
                            ++parms->nsec3out_extraneous_rrsig;

                            rr_set_status |= SANITY_RRSIGUNDERDELETATION;

                            log_warn("zone: sanitize: %{dnsname}: %{dnsnamestack}: unexpected RRSIG under a delegation", zone->origin, name);
                        }
                        else
                        {
                            // we are in the delegation under a delegation case
                        }
                    }
                    else
                    {
                        // should be signed so it's all right
                    }

                    TYPES_SET_OTHER(rrsig_covered_types);
                }

                zdb_zone_load_parms_rrsig_add(parms->load_parms, ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig));

                rrsig = rrsig->next;
            }

            // dns_rrset_types
            // rrsig_covered_types

            u64 missing_types = dns_rrset_types & ~rrsig_covered_types & not_rrsig_mask;

            // missing type is the mask of missing signatures for types

            if(missing_types != 0)
            {
                if(at_delegation)
                {
                    // NS & DS for NSEC & NSEC3IN
                    // if has_ds DS for NSEC3OUT

                    if((missing_types & ns_ds_mask) != 0)
                    {
                        u8 count = u64_count_bits(missing_types & ns_ds_mask);
#if SANITIZE_OVERSHARE
                        log_warn("sanity: %{dnsnamestack}: NSEC,N3I: %i types at delegation are not covered by any signature", name, count);
#endif
                        parms->nsec_missing_rrsig += count;
                        parms->nsec3in_missing_rrsig += count;
                    }

                    if((missing_types & ds_mask) != 0)
                    {
                        u8 count = u64_count_bits(missing_types & ds_mask);
#if SANITIZE_OVERSHARE
                        log_warn("sanity: %{dnsnamestack}: N3O: %i types at delegation are not covered by any signature", name, count);
#endif
                        parms->nsec3out_missing_rrsig += count;
                    }
                }
                else if(under_delegation)
                {
                    // nothing
                }
                else
                {
                    // everything should be signed

                    u8 count = u64_count_bits(missing_types);
#if SANITIZE_OVERSHARE
                    log_warn("sanity: %{dnsnamestack}: ANY: %i types are not covered by any signature", name, count);
#endif
                    parms->nsec_missing_rrsig += count;
                    parms->nsec3in_missing_rrsig += count;
                    parms->nsec3out_missing_rrsig += count;
                }
            }
        }
        else // no signature found in this label
        {
            // dns_rrset_types
            // rrsig_covered_types

            u64 missing_types = dns_rrset_types & ~rrsig_covered_types;

            // missing type is the mask of missing signatures for types

            if(missing_types != 0)
            {
                if(at_delegation)
                {
                    // NS & DS for NSEC & NSEC3IN
                    // if has_ds DS for NSEC3OUT

                    if((missing_types & ns_ds_mask) != 0)
                    {
                        u8 count = u64_count_bits(missing_types & ns_ds_mask);
#if SANITIZE_OVERSHARE
                        log_warn("sanity: %{dnsnamestack}: NSEC,N3I: %i types at delegation are not covered by any signature (there are none)", name, count);
#endif
                        parms->nsec_missing_rrsig += count;
                        parms->nsec3in_missing_rrsig += count;
                    }

                    if((missing_types & ds_mask) != 0)
                    {
                        u8 count = u64_count_bits(missing_types & ds_mask);
#if SANITIZE_OVERSHARE
                        log_warn("sanity: %{dnsnamestack}: N3O: %i types at delegation are not covered by any signature (there are none)", name, count);
#endif
                        parms->nsec3out_missing_rrsig += count;
                    }
                }
                else if(under_delegation)
                {
                    // nothing
                }
                else
                {
                    // everything should be signed

                    u8 count = u64_count_bits(missing_types);
#if SANITIZE_OVERSHARE
                    log_warn("sanity: %{dnsnamestack}: ANY: %i types are not covered by any signature (there are none)", name, count);
#endif
                    parms->nsec_missing_rrsig += count;
                    parms->nsec3in_missing_rrsig += count;
                    parms->nsec3out_missing_rrsig += count;
                }
            }
        }
    }
#endif // ZDB_HAS_DNSSEC_SUPPORT

    if(isapex)
    {
        if(TYPES_HAS(dns_rrset_types, TYPE_CNAME))
        {
            /*
             * No CNAME at apex
             */

            rr_set_status |= SANITY_UNEXPECTEDCNAME;

            /*
             * Remove them all
             */

            log_warn("zone: sanitize: %{dnsname}: %{dnsnamestack}: CNAME record is not allowed at the apex", zone->origin, name);
        }

        /*
         * supposed to have one NS at apex
         */
        
        if(!TYPES_HAS(dns_rrset_types, TYPE_NS))
        {
            rr_set_status |= SANITY_EXPECTEDNS;

            /*
             * Just report it
             */

            log_warn("zone: sanitize: %{dnsname}: expected NS record at apex", zone->origin);
        }

        if(TYPES_HAS(dns_rrset_types, TYPE_DS))
        {
            /*
             * cannot have a DS at apex
             */

            rr_set_status |= SANITY_UNEXPECTEDDS;

            log_warn("zone: sanitize: %{dnsname}: unexpected DS record at apex", zone->origin);
        }
        
        zdb_rr_label_flag_or(label, ZDB_RR_LABEL_N3COVERED|ZDB_RR_LABEL_N3OCOVERED);
    }
    else // ! apex
    {
        if(TYPES_HAS(dns_rrset_types, TYPE_CNAME))
        {
            // Cannot accept anything else other than RRSIG & NSEC

            if((TYPES_AND_MASK(dns_rrset_types, not_cmake_nsec_rrsig_mask)) != 0)
            {
                rr_set_status |= SANITY_CNAMENOTALONE;

                log_warn("zone: sanitize: %{dnsname}: %{dnsnamestack}: CNAME record can only be next to NSEC and/or RRSIG records", zone->origin, name);
            }

            /*
             * Other DNS record types, such as NS, MX, PTR, SRV, etc. that point to other names should never point to a CNAME alias.
             * => insanely expensive to test
             */
        }

        if(TYPES_HAS(dns_rrset_types, TYPE_DS))
        {
            /*
             * MUST have an NS with a DS
             */

            if(TYPES_HAS(dns_rrset_types, TYPE_NS))
            {
                zdb_rr_label_flag_or(label, ZDB_RR_LABEL_N3COVERED|ZDB_RR_LABEL_N3OCOVERED);
            }
            else
            {
                rr_set_status |= SANITY_EXPECTEDNS;
                zdb_rr_label_flag_and(label, ~(ZDB_RR_LABEL_N3COVERED|ZDB_RR_LABEL_N3OCOVERED));
                log_warn("zone: sanitize: %{dnsname}: %{dnsnamestack}: expected NS record or unexpected DS record", zone->origin, name);
            }
        }

        if(at_delegation)
        {
#if SANITIZE_DETECT_MISSING_GLUES
            /// The 3 SANITIZE_DETECT_MISSING_GLUES blocs are for the detection of NS that should have a glue but do not have one.
            const zdb_packed_ttlrdata* ns_record_list = NULL;
#endif // SANITIZE_DETECT_MISSING_GLUES
            
            if(TYPES_HAS(dns_rrset_types, TYPE_NS))
            {
#if SANITIZE_DETECT_MISSING_GLUES
                ns_record_list = zdb_record_find(&label->resource_record_set, TYPE_NS);
                /* verify if the NS warrants a glue and if said glue exists */

                const zdb_packed_ttlrdata* record_list = ns_record_list;

                while(record_list != NULL)
                {
                    const u8* nameserver_name = ZDB_PACKEDRECORD_PTR_RDATAPTR(record_list);
                    
                    /*
                     * check if the nameserver ends with our name
                     * if it does then it needs a glue
                     * look if said glue exists
                     * _ any A/AAAA record at or under delegation that is not in this list needs to be removed
                     * _ any missing A/AAAA record at or under delegation that is in this list needs to be added
                     */
                    
                    if(dnsname_under_dnsname_stack(nameserver_name, name))
                    {
                        /**
                         * needs glue
                         * 
                         * @todo 20120123 edf -- check if the glue is present
                         * 
                         */                        
                    }

                    record_list = record_list->next;
                }
#endif // SANITIZE_DETECT_MISSING_GLUES
                
            }
            else
            {
                rr_set_status |= SANITY_EXPECTEDNS;
#if SANITIZE_DETECT_MISSING_GLUES
                ns_record_list = NULL;
#endif // SANITIZE_DETECT_MISSING_GLUES
            }
            
            if((TYPES_AND_MASK(dns_rrset_types, a_aaaa_mask) != 0) && (parent != NULL))
            {
                zdb_sanitize_rr_set_useless_glue(zone, label, name, parent);
            }
            
            /*
             *  If we have anything except NS DS NSEC RRSIG ...
             */
            if(TYPES_AND_MASK(dns_rrset_types, not_ns_ds_nsec_rrsig_mask) != 0)
            {
                // If A/AAAA is all we have (+ NS and + DS)

                if((TYPES_AND_MASK(dns_rrset_types, not_a_aaaa_ns_ds_mask) == 0) && (TYPES_AND_MASK(dns_rrset_types, a_aaaa_mask) != 0))
                {
                    //zdb_packed_ttlrdata* record_list = ns_record_list;
                    if(ns_record_list == NULL)
                    {
                        ns_record_list = zdb_record_find(&label->resource_record_set, TYPE_NS);
                    }

                    const zdb_packed_ttlrdata* record_list = ns_record_list; // sanitize

                    while(record_list != NULL)
                    {
                        if(dnsname_equals_dnsname_stack(ZDB_PACKEDRECORD_PTR_RDATAPTR(record_list), name))
                        {
                            ns_points_to_itself = TRUE;
                            break;
                        }

                        record_list = record_list->next;
                    }
                }

                if(!ns_points_to_itself)
                {
                    rr_set_status |= SANITY_TRASHATDELEGATION; // A or AAAA record at delegation
                }
            }
            
            zdb_rr_label_flag_or(label, ZDB_RR_LABEL_N3COVERED); // delegation case
        }
        else if(under_delegation)
        {
            if((TYPES_AND_MASK(dns_rrset_types, a_aaaa_mask) != 0) && (parent != NULL))
            {
                zdb_sanitize_rr_set_useless_glue(zone, label, name, parent);
            }

            if(TYPES_AND_MASK(dns_rrset_types & not_ns_ds_nsec_rrsig_mask, not_a_aaaa_mask) != 0)
            {
                rr_set_status |= SANITY_TRASHUNDERDELEGATION;

                log_warn("zone: sanitize: %{dnsname}: %{dnsnamestack}: unexpected types under a delegation", zone->origin, name);
            }

            // zdb_rr_label_flag_or(label, ZDB_RR_LABEL_N3COVERED);
        }
        else // not under delegation either
        {
#if SANTIZE_DROP_LONELY_DS
            if(!TYPES_ONLY_HAS(dns_rrset_types, TYPE_DS))
            {
                zdb_rr_label_flag_or(label, ZDB_RR_LABEL_N3COVERED|ZDB_RR_LABEL_N3OCOVERED);
            }
            else
            {
                // lonley DS record

                log_warn("zone: sanitize: %{dnsname}: %{dnsnamestack}: isolated DS record", zone->origin, name);

                u8 name_fqdn[MAX_DOMAIN_LENGTH];
                dnsname_vector name_vector;
                dnsname_stack_to_dnsname(name, name_fqdn);
                dnsname_to_dnsname_vector(name_fqdn, &name_vector);
                zdb_rr_label_delete_record(zone, name_vector.labels, (name_vector.size - zone->origin_vector.size) - 1, TYPE_ANY);

                rr_set_status |= SANITY_LABEL_DELETED;
            }
#else
            zdb_rr_label_flag_or(label, ZDB_RR_LABEL_N3COVERED|ZDB_RR_LABEL_N3OCOVERED);
#endif
        }
    }

    if(rr_set_status != 0)
    {
        rr_set_status |= SANITY_ERROR_BASE;
    }

    return rr_set_status;
}

static ya_result
zdb_sanitize_rr_label_ext(zdb_sanitize_parms *parms, zdb_rr_label *label, dnsname_stack *name, u16 flags, zdb_rr_label** parent)
{
    /**
     *
     * For all labels: check the label is right.
     *
     */

    ya_result return_value;

    if((flags & (ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION)) != 0)
    {
        zdb_rr_label_flag_or(label, ZDB_RR_LABEL_UNDERDELEGATION);
    }
    else
    {
        zdb_rr_label_flag_and(label, ~ZDB_RR_LABEL_UNDERDELEGATION);
    }
    
    if(parent != NULL)
    {
        parent++;
        *parent = label;
    }

    u32 rr_set_status;

    if((rr_set_status = zdb_sanitize_rr_set_ext(parms, label, name, zdb_rr_label_flag_get(label), parent)) != 0)
    {
#if SANITIZE_LABEL_SUMMARY
        zdb_sanitize_log(name, return_value);
#endif
        if((rr_set_status & SANITY_MUSTDROPZONE) != 0)
        {
            /**
             * Can stop here
             */

            return ERROR;
        }
    }

    if(rr_set_status & SANITY_LABEL_DELETED)
    {
        return SUCCESS;
    }
    
    u16 shutdown_test_countdown = 10000;
        
    dictionary_iterator iter;
    dictionary_iterator_init(&label->sub, &iter);
    while(dictionary_iterator_hasnext(&iter))
    {
        zdb_rr_label **sub_labelp = (zdb_rr_label**)dictionary_iterator_next(&iter);

        dnsname_stack_push_label(name, (*sub_labelp)->name);

        return_value = zdb_sanitize_rr_label_ext(parms, *sub_labelp, name, zdb_rr_label_flag_get(label), parent);
        
        /*
         * If this label is under (or at) delegation
         *   For each A/AAAA record
         *     Ensure there are NS at delegation linked to said records.
         */

        dnsname_stack_pop_label(name);

        if(FAIL(return_value))
        {
            return return_value;
        }
        
        if(--shutdown_test_countdown == 0)
        {
            if(dnscore_shuttingdown())
            {
                return STOPPED_BY_APPLICATION_SHUTDOWN;
            }
            
            shutdown_test_countdown = 1000;
        }
    }

    return SUCCESS;
}

#if HAS_NSEC3_SUPPORT

static ya_result
zdb_sanitize_zone_nsec3(zdb_sanitize_parms *parms)
{
    zdb_zone *zone = parms->zone;
    nsec3_zone* n3 = zone->nsec.nsec3;
    s32 soa_nttl = zone->min_ttl;

    while(n3 != NULL)
    {
#if DNSSEC_DEBUGLEVEL>2
        u32 nsec3_count = 0;
        log_debug("dnssec_process_zone_nsec3_body: processing NSEC3 collection");
#endif
        
        nsec3_iterator nsec3_items_iter;
        nsec3_iterator_init(&n3->items, &nsec3_items_iter);

        if(nsec3_iterator_hasnext(&nsec3_items_iter))
        {
            nsec3_zone_item* first = nsec3_iterator_next_node(&nsec3_items_iter);
            nsec3_zone_item* item = first;
            nsec3_zone_item* next;

            do
            {
                if(dnscore_shuttingdown())
                {
#if DNSSEC_DEBUGLEVEL>2
                    log_debug("dnssec_process_zone_nsec3_body: STOPPED_BY_APPLICATION_SHUTDOWN");
#endif
                    return STOPPED_BY_APPLICATION_SHUTDOWN;
                }
                
                if(nsec3_iterator_hasnext(&nsec3_items_iter))
                {
                    next = nsec3_iterator_next_node(&nsec3_items_iter);
                }
                else
                {
                    next = first;
                }

                zdb_packed_ttlrdata *rrsig = item->rrsig;
                
                // the signing key must be known
                while(rrsig != NULL)
                {

                    s32 rrsig_ttl = rrsig_get_original_ttl_from_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig));

                    if(rrsig_ttl != soa_nttl)
                    {
                        log_warn("%{digest32h}.%{dnsname} RRSIG's TTL does not match the NTTL (%i != %i)", item->digest, zone->origin, rrsig_ttl, soa_nttl);
                        // RRSIG TTL does not match NTTL
                        parms->has_bogus_rrsig = TRUE;
                    }

                    rrsig->ttl = soa_nttl;

                    zdb_zone_load_parms_rrsig_add(parms->load_parms, ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig));

                    rrsig = rrsig->next;
                }

                item = next;

#if DNSSEC_DEBUGLEVEL>2
                nsec3_count++;
#endif
            }
            while(next != first);

        } /* If there is a first item*/
        
#if DNSSEC_DEBUGLEVEL>2
        log_debug("dnssec_process_zone_nsec3_body: processed NSEC3 collection (%d items)", nsec3_count);
#endif

        n3 = n3->next;

    } /* while n3 != NULL */
    
    return SUCCESS;
}

#endif

ya_result
zdb_sanitize_zone_ex(zdb_zone *zone, struct zdb_zone_load_parms *load_parms)
{
    if(zone->apex == NULL)
    {
        return ERROR;
    }
    
    zdb_sanitize_parms *parmsp = &load_parms->sanitize_parms;
    
    zdb_sanitize_parms_init(parmsp, zone, load_parms);
    zdb_sanitize_parms_update_keys(parmsp);
    
    zdb_rr_label* label_stack[256];
    label_stack[0] = NULL;

    dnsname_stack name;
    dnsname_to_dnsname_stack(zone->origin, &name);

    ya_result return_code = zdb_sanitize_rr_label_ext(parmsp, zone->apex, &name, 0, label_stack);

    if(ISOK(return_code))
    {
#if HAS_NSEC3_SUPPORT 
        if((zone_get_maintain_mode(zone) & ZDB_ZONE_MAINTAIN_NSEC3) != 0)
        {
            if(zdb_zone_is_nsec3(zone))
            {
                return_code = zdb_sanitize_zone_nsec3(parmsp);
            }
        }
#endif
    }

    load_parms->state |= ZDB_ZONE_LOAD_STATE_SANITIZE_FIELD_AVAIABLE;
    
    // zdb_sanitize_parms_finalize(parmsp);
    
    return return_code;
}

ya_result
zdb_sanitize_zone(zdb_zone *zone)
{
    if(zone->apex == NULL)
    {
        return ERROR;
    }

    zdb_sanitize_parms parms;

    zdb_sanitize_parms_init(&parms, zone, NULL);
    zdb_sanitize_parms_update_keys(&parms);

    zdb_rr_label* label_stack[256];
    label_stack[0] = NULL;

    dnsname_stack name;
    dnsname_to_dnsname_stack(zone->origin, &name);

    ya_result return_code = zdb_sanitize_rr_label_ext(&parms, zone->apex, &name, 0, label_stack);

    if(ISOK(return_code))
    {
#if HAS_NSEC3_SUPPORT
        if((zone_get_maintain_mode(zone) & ZDB_ZONE_MAINTAIN_NSEC3) != 0)
        {
            if(zdb_zone_is_nsec3(zone))
            {
                return_code = zdb_sanitize_zone_nsec3(&parms);
            }
        }
#endif
    }

    zdb_sanitize_parms_finalize(&parms);

    return return_code;
}

bool
zdb_sanitize_is_good_for_chains(struct zdb_zone_load_parms *load_parms, u8 dnssec_mode)
{
    if((load_parms->state & ZDB_ZONE_LOAD_STATE_SANITIZE_FIELD_AVAIABLE) != 0)
    {
        switch(dnssec_mode)
        {
            case ZDB_ZONE_NOSEC:
            {
                return TRUE;
            }
            case ZDB_ZONE_NSEC:
            {
                return !(load_parms->sanitize_parms.has_bogus_rrsig) && (load_parms->sanitize_parms.nsec_missing_rrsig + load_parms->sanitize_parms.nsec_extraneous_rrsig) == 0;
            }
            case ZDB_ZONE_NSEC3:
            {
                return !(load_parms->sanitize_parms.has_bogus_rrsig) &&(load_parms->sanitize_parms.nsec3in_missing_rrsig + load_parms->sanitize_parms.nsec3in_extraneous_rrsig) == 0;
            }
            case ZDB_ZONE_NSEC3_OPTOUT:
            {
                return !(load_parms->sanitize_parms.has_bogus_rrsig) &&(load_parms->sanitize_parms.nsec3out_missing_rrsig + load_parms->sanitize_parms.nsec3out_extraneous_rrsig) == 0;
            }
            default:
            {
                return FALSE;   // unexpected state, assume sanitisaiton is useless
            }
        }
    }
    else
    {
        return dnssec_mode == ZDB_ZONE_NOSEC;   // no sanitisation results available, only consider it "good" if DNSSEC is not used for the zone
    }
}

bool
zdb_sanitize_is_good(struct zdb_zone_load_parms *load_parms, u8 dnssec_mode)
{
    if((load_parms->state & ZDB_ZONE_LOAD_STATE_SANITIZE_SUMMARY_AVAILABLE) == 0)
    {
        if(zdb_sanitize_is_good_for_chains(load_parms, dnssec_mode))
        {
            load_parms->state |= ZDB_ZONE_LOAD_STATE_SANITIZE_SUMMARY_AVAILABLE;
            return TRUE;
        }
        else
        {
            load_parms->state |= ZDB_ZONE_LOAD_STATE_SANITIZE_SUMMARY_AVAILABLE|ZDB_ZONE_LOAD_STATE_SANITIZE_SUMMARY_MAINTENANCE_REQUIRED;
            return FALSE;
        }
    }
    else
    {
        return (load_parms->state & ZDB_ZONE_LOAD_STATE_SANITIZE_SUMMARY_MAINTENANCE_REQUIRED) == 0;
    }
}

static void
zdb_sanitize_zone_rrset_flags_records(zdb_rr_label *label, dnsname_stack *name, u16 flags, zdb_rr_label** parent)
{
    (void)name;
    (void)parent;

    TYPES_INIT(dns_rrset_types);

    bool under_delegation = flags & ZDB_RR_LABEL_UNDERDELEGATION;

    if(under_delegation)
    {
        zdb_rr_label_flag_and(label, ~(ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_N3COVERED|ZDB_RR_LABEL_N3OCOVERED));
        return;
    }

    bool at_delegation = flags & ZDB_RR_LABEL_DELEGATION;

    if(at_delegation)
    {
        zdb_rr_label_flag_or(label, ZDB_RR_LABEL_N3COVERED); // delegation case

        btree_iterator iter;
        btree_iterator_init(label->resource_record_set, &iter);

        while(btree_iterator_hasnext(&iter))
        {
            btree_node* node = btree_iterator_next_node(&iter);
            u16 type = node->hash;

            zdb_packed_ttlrdata* record_list = (zdb_packed_ttlrdata*)node->data;

            if(type != TYPE_RRSIG)
            {
                s32 ttl = record_list->ttl;
                while((record_list = record_list->next) != NULL)
                {
                    record_list->ttl = ttl;
                }
            }

            if((type & NU16(0xffc0)) == 0) // only handle the 64 first types
            {
                TYPES_SET(dns_rrset_types, type); // types bitmap
            }
            else
            {
                TYPES_SET_OTHER(dns_rrset_types);
            }

            if(TYPES_HAS(dns_rrset_types, TYPE_DS))
            {
                /*
                 * MUST have an NS with a DS
                 */

                if(TYPES_HAS(dns_rrset_types, TYPE_NS))
                {
                    zdb_rr_label_flag_or(label, ZDB_RR_LABEL_N3COVERED|ZDB_RR_LABEL_N3OCOVERED);
                }
                else
                {
                    zdb_rr_label_flag_and(label, ~ZDB_RR_LABEL_N3OCOVERED);
                }
            }
        }

        return;
    }

    // not under delegation either

    zdb_rr_label_flag_or(label, ZDB_RR_LABEL_N3COVERED|ZDB_RR_LABEL_N3OCOVERED);
}

static ya_result
zdb_sanitize_zone_rrset_flags_label(zdb_rr_label *label, dnsname_stack *name, u16 flags, zdb_rr_label **parent)
{
    u16 shutdown_test_countdown = 10000;

    ya_result ret = SUCCESS;

    if((flags & (ZDB_RR_LABEL_DELEGATION|ZDB_RR_LABEL_UNDERDELEGATION)) != 0)
    {
        zdb_rr_label_flag_or(label, ZDB_RR_LABEL_UNDERDELEGATION);
    }
    else
    {
        zdb_rr_label_flag_and(label, ~ZDB_RR_LABEL_UNDERDELEGATION);
    }

    zdb_sanitize_zone_rrset_flags_records(label, name, zdb_rr_label_flag_get(label), parent);

    dictionary_iterator iter;
    dictionary_iterator_init(&label->sub, &iter);
    while(dictionary_iterator_hasnext(&iter))
    {
        zdb_rr_label **sub_labelp = (zdb_rr_label**)dictionary_iterator_next(&iter);

        dnsname_stack_push_label(name, (*sub_labelp)->name);

        ret = zdb_sanitize_zone_rrset_flags_label(*sub_labelp, name, zdb_rr_label_flag_get(label), parent);

        /*
         * If this label is under (or at) delegation
         *   For each A/AAAA record
         *     Ensure there are NS at delegation linked to said records.
         */

        dnsname_stack_pop_label(name);

        if(FAIL(ret))
        {
            return ret;
        }

        if(--shutdown_test_countdown == 0)
        {
            if(dnscore_shuttingdown())
            {
                return STOPPED_BY_APPLICATION_SHUTDOWN;
            }

            shutdown_test_countdown = 1000;
        }
    }

    return ret;
}

ya_result
zdb_sanitize_zone_rrset_flags(zdb_zone *zone)
{
    if(zone->apex == NULL)
    {
        return ERROR;
    }

    zdb_rr_label* label_stack[256];
    label_stack[0] = NULL;

    dnsname_stack name;
    dnsname_to_dnsname_stack(zone->origin, &name);

    ya_result ret = zdb_sanitize_zone_rrset_flags_label(zone->apex, &name, 0, label_stack);

    return ret;
}

/** @} */
