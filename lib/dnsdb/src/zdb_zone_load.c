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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#include "dnsdb/dnsdb-config.h"
#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/dnsname.h>
#include <dnscore/bytearray_output_stream.h>
#include <dnsdb/rrsig.h>
#include <dnscore/rfc.h>
#include <dnsdb/nsec3.h>

#if ZDB_HAS_DNSSEC_SUPPORT
#include <dnscore/dnskey.h>
#endif

#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_icmtl.h"
#include "dnsdb/zdb_sanitize.h"
#include "dnsdb/zdb_utils.h"
#include "dnsdb/zdb_zone_write.h"
#include "dnsdb/zdb_zone_label_iterator.h"
#include "dnsdb/zdb-zone-find.h"

#if ZDB_HAS_DNSSEC_SUPPORT
#include "dnsdb/dnssec-keystore.h"
#include "dnsdb/dnssec.h"
#endif

#if ZDB_HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3.h"
#endif

#if ZDB_HAS_NSEC_SUPPORT
#include "dnsdb/nsec.h"
#endif

#include "dnsdb/zdb_zone_load.h"

extern logger_handle *g_database_logger;
#define MODULE_MSG_HANDLE g_database_logger

void
zdb_zone_load_parms_init(struct zdb_zone_load_parms *parms, zone_reader *zr, const u8 *expected_origin, u16 flags)
{
    ZEROMEMORY(parms, sizeof(struct zdb_zone_load_parms));
    parms->zr = zr;
    parms->expected_origin = expected_origin;
    parms->dnskey_state = U32_SET_EMPTY;
    parms->out_zone = NULL;
    parms->flags = flags;
    parms->state = 0;
}

zdb_zone *
zdb_zone_load_parms_zone_detach(struct zdb_zone_load_parms *parms)
{
    zdb_zone *zone;
    zone = parms->out_zone;
    parms->out_zone = NULL;
    return zone;
}

zdb_zone *
zdb_zone_load_parms_zone_get(struct zdb_zone_load_parms *parms)
{
    return parms->out_zone;
}

ya_result
zdb_zone_load_parms_result_code(struct zdb_zone_load_parms *parms)
{
    return parms->result_code;
}

static void
zdb_zone_load_parms_finalize_dnskey_state_cb(u32_node *node)
{
    struct zdb_zone_load_dnskey_state_for_key *state = (struct zdb_zone_load_dnskey_state_for_key*)node->value;
#if DEBUG
    union zdb_zone_load_dnskey_id id;
    id.id = node->key;
    log_debug("destroying key state: tag=%i alg=%i sig: count=%i from=%T until=%T flags=%x", ntohs(id.fields.tag), id.fields.algorithm, state->rrsig_count, state->signed_from, state->signed_until, state->flags);
#endif
    ZFREE_OBJECT(state);
}

void
zdb_zone_load_parms_finalize(struct zdb_zone_load_parms *parms)
{
    if((parms->state & ZDB_ZONE_LOAD_STATE_SANITIZE_FIELD_AVAIABLE) != 0)
    {
        zdb_sanitize_parms_finalize(&parms->sanitize_parms);
        parms->state &= ~ZDB_ZONE_LOAD_STATE_SANITIZE_FIELD_AVAIABLE;
    }

    if(parms->dnskey_state != NULL)
    {
        // destroy the collection
        u32_set_callback_and_destroy(&parms->dnskey_state, zdb_zone_load_parms_finalize_dnskey_state_cb);
    }

    if(parms->out_zone != NULL)
    {
        // releases the zone
        zdb_zone_release(parms->out_zone);
        parms->out_zone = NULL;
    }
}

struct zdb_zone_load_dnskey_state_for_key*
zdb_zone_load_parms_dnskey_state(struct zdb_zone_load_parms *parms, union zdb_zone_load_dnskey_id id)
{
    u32_node *node = u32_set_insert(&parms->dnskey_state, id.id);
    struct zdb_zone_load_dnskey_state_for_key *state;

    if(node->value == NULL)
    {
        // new instance
        ZALLOC_OBJECT_OR_DIE(state, struct zdb_zone_load_dnskey_state_for_key, ZZLDSKEY_TAG);
        state->signed_from = MAX_U32;
        state->signed_until = 0;
        state->rrsig_count = 0;
        state->key_flags = 0;
        state->flags = 0;
        node->value = state;
    }
    else
    {
        state = (struct zdb_zone_load_dnskey_state_for_key*)node->value;
    }

    return state;
}

void
zdb_zone_load_parms_dnskey_add(struct zdb_zone_load_parms *parms, const u8 *dnskey_rdata, u16 dnskey_rdata_size)
{
    if(dnskey_rdata_size < 4)
    {
        return;
    }

    u16 tag = dnskey_get_tag_from_rdata(dnskey_rdata, dnskey_rdata_size);
    u8 alg = dnskey_get_algorithm_from_rdata(dnskey_rdata);

    // insert node

    union zdb_zone_load_dnskey_id id;
    id.fields.tag = tag;
    id.fields.algorithm = alg;
    id.fields.must_be_zero = 0;

    struct zdb_zone_load_dnskey_state_for_key *state = zdb_zone_load_parms_dnskey_state(parms, id);
    state->flags |= ZDB_ZONE_LOAD_DNSKEY_STATE_FLAG_HAS_PUBKEY;
    state->key_flags = dnskey_get_flags_from_rdata(dnskey_rdata);
}

u16
zdb_zone_load_parms_get_key_flags_from_rrsig_rdata(struct zdb_zone_load_parms *parms, const u8 *rrsig_rdata, u16 rrsig_rdata_size)
{
    u16 tag = rrsig_get_key_tag_from_rdata(rrsig_rdata, rrsig_rdata_size);
    u8 alg = rrsig_get_algorithm_from_rdata(rrsig_rdata, rrsig_rdata_size);

    union zdb_zone_load_dnskey_id id;
    id.fields.tag = tag;
    id.fields.algorithm = alg;
    id.fields.must_be_zero = 0;

    struct zdb_zone_load_dnskey_state_for_key *state = zdb_zone_load_parms_dnskey_state(parms, id);
    return state->key_flags;
}

void
zdb_zone_load_parms_rrsig_add(struct zdb_zone_load_parms *parms, const u8 *rrsig_rdata, u16 rrsig_rdata_size)
{
    if(rrsig_rdata_size < RRSIG_RDATA_HEADER_LEN)
    {
        return;
    }

    u16 tag = rrsig_get_key_tag_from_rdata(rrsig_rdata, rrsig_rdata_size);
    u8 alg = rrsig_get_algorithm_from_rdata(rrsig_rdata, rrsig_rdata_size);

    // insert node

    union zdb_zone_load_dnskey_id id;
    id.fields.tag = tag;
    id.fields.algorithm = alg;
    id.fields.must_be_zero = 0;

    struct zdb_zone_load_dnskey_state_for_key *state = zdb_zone_load_parms_dnskey_state(parms, id);
    state->flags |= ZDB_ZONE_LOAD_DNSKEY_STATE_FLAG_HAS_PUBKEY;

    s64 valid_until = rrsig_get_valid_until_from_rdata(rrsig_rdata, rrsig_rdata_size);
    s64 valid_from = rrsig_get_valid_from_from_rdata(rrsig_rdata, rrsig_rdata_size);

    if(state->signed_until < valid_until)
    {
        state->signed_until = valid_until;
    }

    if(state->signed_from > valid_from)
    {
        state->signed_from = valid_from;
    }

    ++state->rrsig_count;
}

ya_result
zdb_zone_load_ex(struct zdb_zone_load_parms *parms)
{
    u64 wire_size = 0;
    u8* rdata;
    size_t rdata_len;
    ya_result return_code;
    resource_record entry;
    s32 soa_min_ttl = 0;
    u32 soa_serial = 0;
    u32 earliest_signature_expiration = MAX_S32;
#if ZDB_HAS_DNSSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
    u32 has_optout = 0;
    u32 has_optin = 0;
#endif
    bool nsec3_keys = FALSE;
    bool nsec_keys = FALSE;
    bool has_dnskey = FALSE;
#endif
    bool has_nsec3 = FALSE;
    bool has_nsec = FALSE;
    bool has_rrsig = FALSE;
    bool dynupdate_forbidden = FALSE;
    //bool modified = FALSE;

#if ZDB_HAS_NSEC3_SUPPORT
    nsec3_load_context nsec3_context;
#endif

    char origin_ascii[MAX_DOMAIN_TEXT_LENGTH + 1];

    if((parms->zr == NULL) || (parms->out_zone != NULL))
    {
        parms->result_code = INVALID_ARGUMENT_ERROR;
        return INVALID_ARGUMENT_ERROR; // reader must be set, out_zone must be NULL
    }

    /*    ------------------------------------------------------------    */

    zone_reader *zr = parms->zr;
    const u8 *expected_origin = parms->expected_origin;
    const u16 flags = parms->flags;

    resource_record_init(&entry);

    if(FAIL(return_code = zone_reader_read_record(zr, &entry)))
    {
        resource_record_freecontent(&entry); /* destroys */

        const char *message = zone_reader_get_last_error_message(zr);

        if(expected_origin != NULL)
        {
            if(message == NULL)
            {
                log_err("zone load: %{dnsname}: reading zone: %r", expected_origin, return_code);
            }
            else
            {
                log_err("zone load: %{dnsname}: reading zone: %s: %r", expected_origin, message, return_code);
            }
        }
        else
        {
            if(message == NULL)
            {
                log_err("zone load: reading zone: %r", return_code);
            }
            else
            {
                log_err("zone load: reading zone: %s: %r", message, return_code);
            }
        }

        parms->result_code = return_code;

        return return_code;
    }

    if(entry.type != TYPE_SOA)
    {
        /* bad */

        resource_record_freecontent(&entry); /* destroys */

        if(expected_origin != NULL)
        {
            log_err("zone load: %{dnsname}: first record expected to be an SOA, got %{dnstype} instead", expected_origin, &entry.type);
        }
        else
        {
            log_err("zone load: first record expected to be an SOA, got %{dnstype} instead", &entry.type);
        }

        parms->result_code = ZDB_READER_FIRST_RECORD_NOT_SOA;

        return ZDB_READER_FIRST_RECORD_NOT_SOA;
    }

    if(expected_origin != NULL)
    {
        bool char_space_ok = TRUE;
        bool matched_origin = TRUE;
        if(!((char_space_ok = dnsname_locase_verify_charspace(entry.name)) && (matched_origin = dnsname_equals(entry.name, expected_origin))))
        {
            if(!char_space_ok)
            {
               log_err("zone load: %{dnsname}: invalid character space: %{dnsname}", expected_origin, entry.name);
            }

            if(!matched_origin)
            {
                log_err("zone load: %{dnsname}: found name outside of zone: %{dnsname}", expected_origin, entry.name);
            }

            resource_record_freecontent(&entry); /* destroys, actually no-operation in this version */

            parms->result_code = ZDB_READER_WRONGNAMEFORZONE;

            return ZDB_READER_WRONGNAMEFORZONE;
        }

        if(!matched_origin)
        {
            resource_record_freecontent(&entry); /* destroys */

            log_err("zone load: %{dnsname}: zone file domain do not match the expected one (%{dnsname})", expected_origin, entry.name);

            parms->result_code = ZDB_READER_ANOTHER_DOMAIN_WAS_EXPECTED;

            return ZDB_READER_ANOTHER_DOMAIN_WAS_EXPECTED;
        }
    }
    else
    {
        bool char_space_ok = dnsname_locase_verify_charspace(entry.name);

        if(!char_space_ok)
        {
            log_err("zone load: invalid character space: %{dnsname}", entry.name);

            resource_record_freecontent(&entry); /* destroys, actually no-operation in this version */

            parms->result_code = ZDB_READER_WRONGNAMEFORZONE;

            return ZDB_READER_WRONGNAMEFORZONE;
        }
    }

    dnsname_vector name;
    DEBUG_RESET_dnsname(name);
    u16 zclass = entry.class;

    dnsname_to_dnsname_vector(entry.name, &name);

    rr_soa_get_minimumttl(zone_reader_rdata(entry), zone_reader_rdata_size(entry), &soa_min_ttl);
    rr_soa_get_serial(zone_reader_rdata(entry), zone_reader_rdata_size(entry), &soa_serial);

    dnsname_to_cstr(origin_ascii, entry.name);

    dynupdate_forbidden = FALSE;

#if ZDB_HAS_DNSSEC_SUPPORT
    has_dnskey = FALSE;
    has_nsec3 = FALSE;
    has_nsec = FALSE;
    nsec3_keys = FALSE;
    nsec_keys = FALSE;
#if ZDB_HAS_NSEC3_SUPPORT
    has_optout = 0;
    has_optin = 0;
#endif
#endif

    zdb_zone* zone;

    zone = zdb_zone_create(entry.name); // comes with an RC = 1, not locked

    if(zone == NULL)
    {
        log_err("zone load: unable to load zone %{dnsname} %{dnsclass}", entry.name, &zclass);

        parms->result_code = ZDB_ERROR_NOSUCHCLASS;

        return ZDB_ERROR_NOSUCHCLASS;
    }

    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_LOAD);

    zone->min_ttl = soa_min_ttl;
    zone->text_serial = soa_serial;
    zone->axfr_serial = soa_serial - 1; /* ensure that the axfr on disk is not automatically taken in account later */

    if((parms->flags & ZDB_ZONE_NO_MAINTENANCE) == 0)
    {
        switch(parms->flags & ZDB_ZONE_DNSSEC_MASK)
        {
            case ZDB_ZONE_NSEC:
                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC);
                break;
            case ZDB_ZONE_NSEC3:
                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3);
                break;
            case ZDB_ZONE_NSEC3_OPTOUT:
                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT);
                break;
        }
    }

    dnsname_to_dnsname_vector(zone->origin, &name);
    //dnsname_vector_copy(&name, &zone->origin_vector);

#if ZDB_HAS_NSEC3_SUPPORT
    nsec3_load_init(&nsec3_context, zone);
    nsec3_load_allowed_to_fix(&nsec3_context, (parms->flags & ZDB_ZONE_IS_SLAVE) == 0);
#endif

    zdb_packed_ttlrdata* ttlrdata;

    u32 loop_count;

    for(loop_count = 1;; loop_count++)
    {
        /* Add the entry */

        if(dnscore_shuttingdown())
        {
            return_code = STOPPED_BY_APPLICATION_SHUTDOWN;
            break;
        }

        dnsname_vector entry_name;

        DEBUG_RESET_dnsname(entry_name);
        dnsname_to_dnsname_vector(entry.name, &entry_name);

        s32 a_i, b_i;

        if((a_i = name.size) > (b_i = entry_name.size))
        {
            // error

            return_code = ZDB_READER_WRONGNAMEFORZONE;

            log_err("zone load: domain name %{dnsnamevector} is too big", &entry_name);

            break;
        }

        /* ZONE ENTRY CHECK */

        while(a_i >= 0)
        {
            const u8* a = name.labels[a_i--];
            const u8* b = entry_name.labels[b_i--];

            if(!dnslabel_equals(a, b))
            {
                log_warn("zone load: bad domain name %{dnsnamevector} for zone %{dnsnamevector}", &entry_name, &name);

                goto zdb_zone_load_loop;
            }
        }

        if(FAIL(return_code))
        {
            break;
        }

        rdata_len = zone_reader_rdata_size(entry);
        rdata = zone_reader_rdata(entry);

#if ZDB_HAS_NSEC3_SUPPORT

        /*
         * SPECIAL NSEC3 support !!!
         *
         * If the record is an RRSIG(NSEC3), an NSEC3, or an NSEC3PARAM then
         * it cannot be handled the same way as the others.
         *
         */

        if(entry.type == TYPE_NSEC3PARAM)
        {
            if(FAIL(return_code = nsec3_load_add_nsec3param(&nsec3_context, rdata, rdata_len)))
            {
                break;
            }

            ZDB_RECORD_ZALLOC(ttlrdata, /*entry.ttl*/0, rdata_len, rdata);
            zdb_zone_record_add(zone, entry_name.labels, entry_name.size, entry.type, ttlrdata); // verified

            // has_nsec3 ?
        }
        else if(entry.type == TYPE_NSEC3CHAINSTATE)
        {
            if(FAIL(nsec3_load_add_nsec3chainstate(&nsec3_context, rdata, rdata_len)))
            {
                break;
            }
            ZDB_RECORD_ZALLOC(ttlrdata, /*entry.ttl*/0, rdata_len, rdata);
            zdb_zone_record_add(zone, entry_name.labels, entry_name.size, entry.type, ttlrdata); // verified
        }
        else if(entry.type == TYPE_NSEC3)
        {
            bool rdata_optout = NSEC3_RDATA_IS_OPTOUT(rdata);

            if(rdata_optout)
            {
                has_optout++;
            }
            else
            {
                has_optin++;
            }

            if(FAIL(return_code = nsec3_load_add_nsec3(&nsec3_context, entry.name, entry.ttl, rdata, rdata_len)))
            {
                break;
            }

            has_nsec3 = TRUE;
        }
        else if(entry.type == TYPE_RRSIG && ((GET_U16_AT(*rdata)) == TYPE_NSEC3)) /** @note : NATIVETYPE */
        {
            if(FAIL(return_code = nsec3_load_add_rrsig(&nsec3_context, entry.name, /*entry.ttl*/soa_min_ttl, rdata, rdata_len)))
            {
                break;
            }
        }
        else
        {
#endif
        /*
         * This is the general case
         * It happen with NSEC3 support if the type is neither NSEC3PARAM, NSEC3 nor RRSIG(NSEC3)
         */
        switch(entry.type)
        {
            case TYPE_DNSKEY:
            {
#if ZDB_HAS_DNSSEC_SUPPORT
                /*
                 * Check if we have access to the private part of the key
                 */

                u16 tag = dnskey_get_tag_from_rdata(rdata, rdata_len);
                u16 key_flags = GET_U16_AT(rdata[0]);
                u8 algorithm = rdata[3];

                switch(algorithm)
                {
                    case DNSKEY_ALGORITHM_DSASHA1:
                    case DNSKEY_ALGORITHM_RSASHA1:
                    {
                        nsec_keys = TRUE;
                        break;
                    }
                    case DNSKEY_ALGORITHM_DSASHA1_NSEC3:
                    case DNSKEY_ALGORITHM_RSASHA1_NSEC3:
                    {
                        nsec3_keys = TRUE;
                        break;
                    }
                    case DNSKEY_ALGORITHM_RSASHA256_NSEC3:
                    case DNSKEY_ALGORITHM_RSASHA512_NSEC3:
                    case DNSKEY_ALGORITHM_ECDSAP256SHA256:
                    case DNSKEY_ALGORITHM_ECDSAP384SHA384:
                    case DNSKEY_ALGORITHM_ED25519:
                    case DNSKEY_ALGORITHM_ED448:
#ifdef DNSKEY_ALGORITHM_DUMMY
                    case DNSKEY_ALGORITHM_DUMMY:
#endif
                    {
                        nsec_keys = TRUE;
                        nsec3_keys = TRUE;
                        break;
                    }
                    default:
                    {
                        log_info("zone load: unknown key algorithm for K%{dnsname}+%03d+%05hd", zone->origin, algorithm, tag);
                        break;
                    }
                }

                dnssec_key *key = NULL;

                if((flags & ZDB_ZONE_IS_SLAVE) == 0)
                {
                    if(ISOK(return_code = dnssec_keystore_load_private_key_from_parameters(algorithm, tag, key_flags, zone->origin, &key))) // converted, key properly released
                    {
                        if(return_code > 0)
                        {
                            log_info("zone load: loaded private key K%{dnsname}+%03d+%05hd", zone->origin, algorithm, tag);
                        }

                        // we are only interested on its existence so it can be released now (the fact the pointer is not NULL is all that matters)
                        dnskey_state_enable(key, DNSKEY_KEY_IS_IN_ZONE);
                        dnskey_release(key);
                        has_dnskey = TRUE;
                    }
                    else
                    {
                        int log_level =  zdb_zone_get_rrsig_push_allowed(zone)?MSG_INFO:MSG_WARNING;
                        log_to_level(log_level, "zone load: unable to load the private key K%{dnsname}+%03d+%05hd: %r", zone->origin, algorithm, tag, return_code);
                    }
                }

                if(key == NULL)
                {
                    /*
                     * Either:
                     *
                     * _ The private key is not available (error)
                     * _ The private key should not be loaded (slave)
                     *
                     * Get the public key for signature verifications.
                     */

                    if(ISOK(return_code = dnssec_keystore_load_public_key_from_rdata(rdata, rdata_len, zone->origin, &key))) // converted
                    {
                        log_info("zone load: loaded public key K%{dnsname}+%03d+%05hd", zone->origin, algorithm, tag);
                        dnskey_state_enable(key, DNSKEY_KEY_IS_IN_ZONE);
                        dnskey_release(key);

                        has_dnskey = TRUE;
                    }
                    else
                    {
                        /* the key is wrong */
                        log_warn("zone load: unable to load public key K%{dnsname}+%03d+%05hd: %r", zone->origin, algorithm, tag, return_code);
                    }
                }
#else
                /* DNSKEY not supported */
#endif
                ZDB_RECORD_ZALLOC(ttlrdata, entry.ttl, rdata_len, rdata);
                zdb_zone_record_add(zone, entry_name.labels, entry_name.size, entry.type, ttlrdata); // class is implicit, verified
                break;
            }
#if ZDB_HAS_NSEC_SUPPORT
            case TYPE_NSEC:
            {
                has_nsec = TRUE;
                ZDB_RECORD_ZALLOC(ttlrdata, entry.ttl, rdata_len, rdata);
                zdb_zone_record_add(zone, entry_name.labels, entry_name.size, entry.type, ttlrdata); /* class is implicit */
                break;
            }
#endif
            case TYPE_RRSIG:
            {
#if !ZDB_HAS_DNSSEC_SUPPORT
                if(!has_rrsig)
                {
                    log_warn("zone load: type %{dnstype} is not supported", &entry.type);
                }
#else
                has_rrsig = TRUE;
#endif
                if((GET_U16_AT(*rdata)) == TYPE_NSEC3PARAM) // RRSIG covered type
                {
                    entry.ttl = 0;
                }

                u32 rrsig_expiration = rrsig_get_valid_until_from_rdata(rdata, rdata_len);

                if(rrsig_expiration < earliest_signature_expiration)
                {
                    earliest_signature_expiration = rrsig_expiration;
                }
            }
            FALLTHROUGH // fall through
            default:
            {
                ZDB_RECORD_ZALLOC(ttlrdata, entry.ttl, rdata_len, rdata);
                zdb_zone_record_add(zone, entry_name.labels, entry_name.size, entry.type, ttlrdata); // class is implicit, name parameters verified
                break;
            }
#if !ZDB_HAS_NSEC3_SUPPORT
            case TYPE_NSEC3PARAM:
            {
                if(!has_nsec3param)
                {
                    log_warn("zone load: type %{dnstype} is not supported", &entry.type);
                }
                has_nsec3param = TRUE;
                break;
            }
            case TYPE_NSEC3:
            {
                if(!has_nsec3)
                {
                    log_warn("zone load: type %{dnstype} is not supported", &entry.type);
                }
                has_nsec3 = TRUE;
                break;
            }
#endif
#if !ZDB_HAS_NSEC_SUPPORT
            case TYPE_NSEC:
            {
                if(!has_nsec)
                {
                    log_warn("zone load: type %{dnstype} is not supported", &entry.type);
                }
                has_nsec = TRUE;
                break;
            }
#endif
        } // switch(entry.type)

#if ZDB_HAS_NSEC3_SUPPORT
        } // else
#endif

        zdb_zone_load_loop:

        wire_size += resource_record_size(&entry);

        resource_record_resetcontent(&entry); /* "next" */

        /**
         * Note : Return can be
         *
         * OK:		got a record
         * 1:		end of zone file
         * error code:	failure
         */

        if(OK != (return_code = zone_reader_read_record(zr, &entry)))
        {
            if(FAIL(return_code))
            {
                if(return_code == /**/ ERROR)
                {
                    return_code = UNEXPECTED_EOF;
                }

                const char *message = zone_reader_get_last_error_message(zr);

                if(message == NULL)
                {
                    log_err("zone load: reading record #%d of zone %{dnsname}: %r", loop_count, zone->origin, return_code);
                }
                else
                {
                    log_err("zone load: reading record #%d of zone %{dnsname}: %s: %r", loop_count, zone->origin, message, return_code);
                }
            }
            break;
        }

        if(!dnsname_locase_verify_charspace(entry.name))
        {
            log_warn("zone load: DNS character space error on '%{dnsname}'", entry.name);
        }
    }

    resource_record_freecontent(&entry); /* destroys, not "next" */

    if(ISOK(return_code))
    {
        zdb_sanitize_zone_rrset_flags(zone);
    }

#if ZDB_HAS_DNSSEC_SUPPORT
#if ZDB_HAS_NSEC3_SUPPORT
    if(has_nsec3 && (has_optout > 0))
    {
        zone->_flags |= ZDB_ZONE_HAS_OPTOUT_COVERAGE;
    }
#endif

    log_debug7("zone load: has_rrsig=%i has_dnskey=%i", has_rrsig, has_dnskey);
#endif

    if(dynupdate_forbidden)
    {
        log_info("zone load: freezing zone %{dnsname}", zone->origin);
        zdb_zone_set_frozen(zone);
    }

#if ZDB_HAS_DNSSEC_SUPPORT

    if(ISOK(return_code))
    {
        if(has_nsec && has_nsec3)
        {
            log_err("zone load: zone %{dnsname} has both NSEC and NSEC3 records!", zone->origin);

            // return_code = ZDB_READER_MIXED_DNSSEC_VERSIONS;
            has_nsec = FALSE;
        }
        if((flags & ZDB_ZONE_IS_SLAVE) == 0)
        {
            if(nsec_keys && nsec3_keys) // after algorithm 7, keys can be used both for NSEC and NSEC3
            {
                if(!(has_nsec3|has_nsec))
                {
                    log_warn("zone load: zone %{dnsname} has DNSKEY but there is no NSEC nor NSEC3 coverage", zone->origin);
                }
            }
            else if(nsec3_keys)
            {
                if(!has_nsec3)
                {
                    log_warn("zone load: zone %{dnsname} has NSEC3 DNSKEY but there is no NSEC3 coverage", zone->origin);
                }
            }
            else if(nsec_keys)
            {
                if(!has_nsec)
                {
                    log_warn("zone load: zone %{dnsname} has NSEC DNSKEY but there is no NSEC coverage", zone->origin);
                }
            }
            else
            {
                if(has_nsec3)
                {
                    log_warn("zone load: zone %{dnsname} is NSEC3 but there are no NSEC3 keys available", zone->origin);
                }

                if(has_nsec)
                {
                    log_warn("zone load: zone %{dnsname} is NSEC but there are no NSEC keys available", zone->origin);
                }
            }
        }
    }

    if(ISOK(return_code))
    {
        if(!(has_nsec || has_nsec3))
        {
            switch(flags & ZDB_ZONE_DNSSEC_MASK)
            {
                case ZDB_ZONE_NSEC:
                {
                    log_warn("zone load: zone is configured as NSEC but no NSEC records have been found");
                    if((flags & ZDB_ZONE_IS_SLAVE) == 0)
                    {
                        has_nsec = TRUE;
                    }
                    break;
                }
                case ZDB_ZONE_NSEC3:
                case ZDB_ZONE_NSEC3_OPTOUT:
                {
                    log_warn("zone load: zone is configured as NSEC3 but no NSEC3 records have been found");
                    if((flags & ZDB_ZONE_IS_SLAVE) == 0)
                    {
                        has_nsec3 = TRUE;
                    }
                    break;
                }
                default:
                {
                    break;
                }
            }
        }

        if(has_nsec3)
        {
            if((parms->flags & ZDB_ZONE_NO_MAINTENANCE) == 0)
            {
                zone->_flags |= ZDB_ZONE_MAINTAIN_NSEC3;

                if(has_optout > 0)
                {
                    zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT);
                }
                else
                {
                    zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3);
                }
            }

            zdb_rr_label_flag_or(zone->apex, ZDB_RR_LABEL_N3OCOVERED|ZDB_RR_LABEL_N3COVERED);

#if ZDB_HAS_NSEC3_SUPPORT
            /**
             * Check if there is both NSEC & NSEC3.  Reject if yes.
             *   compile NSEC if any
             *   compile NSEC3 if any
             *
             * I'm only doing NSEC3 here.
             */

            if((flags & ZDB_ZONE_DNSSEC_MASK) == ZDB_ZONE_NSEC)
            {
                log_warn("zone load: zone %{dnsname} was set to NSEC but is NSEC3", zone->origin);
            }

            if(has_optin > 0)
            {
                if(has_optout > 0)
                {
                    log_warn("zone load: zone %{dnsname} has got both OPT-OUT and OPT-IN records (%u and %u)", zone->origin, has_optout, has_optin);
                    nsec3_context.opt_out = TRUE;
                }
                else
                {
                    nsec3_context.opt_out = FALSE;
                }

                if((flags & ZDB_ZONE_DNSSEC_MASK) == ZDB_ZONE_NSEC3_OPTOUT)
                {
                    log_warn("zone load: zone %{dnsname} was set to OPT-OUT but appears to be OPT-IN", zone->origin);
                }
            }
            else if(has_optout > 0)
            {
                /* has_optin is false and has_optout is true */

                if((flags & ZDB_ZONE_DNSSEC_MASK) == ZDB_ZONE_NSEC3)
                {
                    log_warn("zone load: zone %{dnsname} was set to OPT-IN but appears to be OPT-OUT (%u)", zone->origin, has_optout);
                }

                nsec3_context.opt_out = TRUE;
            }
            else /* use the configuration */
            {
                nsec3_context.opt_out = ((flags & ZDB_ZONE_DNSSEC_MASK) == ZDB_ZONE_NSEC3_OPTOUT)?TRUE:FALSE;
            }

            log_info("zone load: zone %{dnsname} is %s", zone->origin, (nsec3_context.opt_out)?"OPT-OUT":"OPT-IN");

            /* If there is something in the NSEC3 context ... */

            if(!nsec3_load_is_context_empty(&nsec3_context))
            {
                /* ... do it. */

                log_debug("zone load: zone %{dnsname}: NSEC3 post-processing.", zone->origin);

                return_code = nsec3_load_generate(&nsec3_context);

                if(((flags & ZDB_ZONE_IS_SLAVE) != 0) && (nsec3_context.nsec3_rejected > 0))
                {
                    return_code = DNSSEC_ERROR_NSEC3_INVALIDZONESTATE; // the zone is corrupted and as a slave nothing can be done about it.
                }

                if(ISOK(return_code))
                {
                    /*
                    if(nsec3_context.opt_out)
                    {
                        zdb_rr_label_flag_or(zone->apex, ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT);
                    }
                    else
                    {
                        zdb_rr_label_flag_or(zone->apex, ZDB_RR_LABEL_NSEC3);
                    }
                    */

                    if(nsec3_context.fix_applied)
                    {
                        parms->state |= ZDB_ZONE_LOAD_STATE_SANITIZE_SUMMARY_NSEC3_CHAIN_FIXED;
                        zdb_zone_set_status(zone, ZDB_ZONE_STATUS_MODIFIED);
                    }


#if HAS_RRSIG_MANAGEMENT_SUPPORT
                    zdb_zone_set_maintained(zone, TRUE);
#endif

                    log_debug("zone load: zone %{dnsname}: NSEC3 post-processing done", zone->origin);
                }
                else
                {
                    log_err("zone load: zone %{dnsname}: error %r: NSEC3 post-processing failed", zone->origin, return_code);
                }
            }
            else
            {
                log_debug("zone load: zone %{dnsname}: NSEC3 context is empty", zone->origin);
                has_nsec3 = FALSE;
            }



#else // ZDB_HAS_NSEC3_SUPPORT is 0
            log_err("zone load: zone %{dnsname} has NSEC3* record(s) but the server has been compiled without NSEC support", zone->origin);
#endif
        }
        else if(has_nsec)
        {
            zone->_flags |= ZDB_ZONE_MAINTAIN_NSEC;

            if((flags & ZDB_ZONE_DNSSEC_MASK) >= ZDB_ZONE_NSEC3)
            {
                log_warn("zone load: zone %{dnsname} was set to NSEC3 but is NSEC", zone->origin);
            }

#if ZDB_HAS_NSEC_SUPPORT
            log_debug("zone load: zone %{dnsname}: NSEC post-processing.", zone->origin);

            if(ISOK(return_code = nsec_update_zone(zone, (flags & ZDB_ZONE_IS_SLAVE) != 0)))
            {//DNSSEC_ERROR_NSEC_INVALIDZONESTATE
                zdb_rr_label_flag_or(zone->apex, ZDB_RR_LABEL_NSEC);
                zdb_rr_label_flag_and(zone->apex, ~(ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT));
#if HAS_RRSIG_MANAGEMENT_SUPPORT
                zdb_zone_set_maintained(zone, (flags & ZDB_ZONE_IS_SLAVE) == 0);
#endif
            }

#else
            log_err("zone load: zone %{dnsname} has NSEC record(s) but the server has been compiled without NSEC support", zone->origin);
#endif
        }
    }
#endif

#if ZDB_HAS_NSEC3_SUPPORT
    nsec3_load_destroy(&nsec3_context);
#endif

    if(ISOK(return_code))
    {
        log_info("zone load: zone %{dnsname} has been loaded (%d record(s) parsed)", zone->origin, loop_count);

        log_debug("zone load: zone %{dnsname} wire size: %i", zone->origin, wire_size);
        zone->wire_size = wire_size;
        zone->progressive_signature_update.earliest_signature_expiration = earliest_signature_expiration;

        log_debug("zone load: zone %{dnsname} earliest signature expiration at %T in %d seconds", zone->origin, earliest_signature_expiration, (s32)(earliest_signature_expiration - time(NULL)));

        parms->out_zone = zone;

#if defined(ZDB_ZONE_MOUNT_ON_LOAD)
        if((flags & ZDB_ZONE_MOUNT_ON_LOAD) != 0)
        {
            log_info("zone load: zone %{dnsname} has been mounted", zone->origin);

            zdb_zone *old_zone = zdb_set_zone(db, zone);
            yassert(old_zone == NULL);
            (void)old_zone;
        }
#endif

    }
    else
    {
        log_err("zone load: zone %{dnsname}: error %r (%d record(s) parsed)", zone->origin, return_code, loop_count);
    }

    if(ISOK(return_code) && ((flags & ZDB_ZONE_REPLAY_JOURNAL) != 0))
    {
        /*
         * The zone file has been read.
         * NSEC structures have been created
         *
         * At this point, the incremental journal should be replayed.
         *
         */

#if DEBUG
        log_debug("zone load: replaying changes from journal");
#endif
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_LOAD);
        return_code = zdb_icmtl_replay(zone);
        zdb_zone_lock(zone, ZDB_ZONE_MUTEX_LOAD);

        if(ISOK(return_code))
        {
            if(return_code > 0)
            {
                log_info("zone load: replayed %d changes from journal", return_code);
            }

            if(!has_nsec3)
            {
                if((has_nsec3 = zdb_rr_label_flag_isset(zone->apex, ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT)))
                {
                    zone->_flags |= ZDB_ZONE_MAINTAIN_NSEC3;
                    if((zone->apex->nsec.nsec3 != NULL) && (has_optout = zone->apex->nsec.nsec3->_self != NULL))
                    {
                        has_optout = (zone->apex->nsec.nsec3->_self->flags != 0);
                    }
                }
            }

            if(has_nsec3 && (has_optout > 0))
            {
                zone->_flags |= ZDB_ZONE_HAS_OPTOUT_COVERAGE;

            }

            if(parms->state & ZDB_ZONE_LOAD_STATE_SANITIZE_SUMMARY_NSEC3_CHAIN_FIXED)
            {
                // the zone must look new to the slaves
                // increment serial
                // sign serial
                // delete journal before mount

                zdb_packed_ttlrdata *soa_rr = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);
                yassert(soa_rr != NULL);
                rr_soa_increase_serial(ZDB_PACKEDRECORD_PTR_RDATAPTR(soa_rr), ZDB_PACKEDRECORD_PTR_RDATASIZE(soa_rr), 1);
                rrsig_delete_covering(zone->apex, TYPE_SOA);

                zdb_zone_set_status(zone, ZDB_ZONE_STATUS_MODIFIED);
            }

            if((flags & ZDB_ZONE_IS_SLAVE) == 0)
            {
//#if DEBUG
                log_info("zone load: post-replay sanity check for %{dnsname}", zone->origin);
//#endif
                if(ISOK(return_code = zdb_sanitize_zone_ex(zone, parms)))
                {
                    log_info("zone load: post-replay sanity check for %{dnsname} done", zone->origin);
                }
                else
                {
                    log_err("zone load: impossible to sanitise %{dnsname}, dropping zone", zone->origin);
                }

                log_debug("zone load: post-replay sanity check for %{dnsname} done", zone->origin);
            }
            else
            {
                log_debug("zone load: no post-replay sanity check for %{dnsname} slave", zone->origin);
            }

            if(has_nsec3)
            {
                // the chain has just been created, but is probably missing internal links
                log_debug("journal: %{dnsname}: no journal, updating links", zone->origin);

                nsec3_zone_update_chain0_links(zone);
            }
        }
        else if(return_code == ZDB_ERROR_ICMTL_NOTFOUND)
        {
            if((flags & ZDB_ZONE_IS_SLAVE) == 0)
            {
                log_debug("zone load: post-replay sanity check for %{dnsname}", zone->origin);

                if(ISOK(return_code = zdb_sanitize_zone_ex(zone, parms)))
                {
                    log_info("zone load: post-replay sanity check for %{dnsname} done", zone->origin);

                    if(has_nsec3)
                    {
                        // the chain has just been created, but is probably missing internal links
                        log_debug("journal: %{dnsname}: no journal, updating links", zone->origin);

                        nsec3_zone_update_chain0_links(zone);
                    }
                }
                else
                {
                    log_err("zone load: impossible to sanitise %{dnsname}, dropping zone", zone->origin);
                }
            }
            else
            {
                log_debug("zone load: no post-replay sanity check for %{dnsname} slave", zone->origin);
            }
        }
        else
        {
            log_err("zone load: journal replay returned %r", return_code);
        }

        /*
         * End of the incremental replay
         */
    }

    if(zone != NULL)
    {
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_LOAD);

        if(FAIL(return_code))
        {
            zdb_zone_release(zone);
            parms->out_zone = NULL;
        }
    }

    parms->result_code = return_code;

    return return_code;
}

/**
 * @brief Load a zone in the database.
 *
 * Load a zone in the database.
 * 
 * @note It is not a good idea to scan the zone content in here. ie: getting the earliest signature expiration. (It's counter-productive and pointless)
 *
 * @param[in] db_UNUSED a pointer to the database, obsolete, can be set to NULL
 * @param[in] zr a pointer to an opened zone_reader
 * @param[in] zone_pointer_out a pointer to the pointer that will be set with the loaded zone
 * @param[in] expected_origin the expected origin for the loaded file, can be set to NULL
 * @param[in] flags various flags
 *
 * @return an error code.
 *
 */

ya_result
zdb_zone_load(zdb *db_UNUSED, zone_reader *zr, zdb_zone **zone_pointer_out, const u8 *expected_origin, u16 flags)
{
    (void)db_UNUSED;
    struct zdb_zone_load_parms parms;
    zdb_zone_load_parms_init(&parms, zr, expected_origin, flags);
    ya_result ret = zdb_zone_load_ex(&parms);
    if(ISOK(ret))
    {
        *zone_pointer_out = zdb_zone_load_parms_zone_detach(&parms);
    }
    else
    {
        *zone_pointer_out = NULL;
    }
    zdb_zone_load_parms_finalize(&parms);
    return ret;
}

/**
 * @brief Load the zone SOA.
 *
 * Load the zone SOA record
 * This is meant mainly for the slave that could choose between, ie: zone file or axfr zone file
 * The SOA MUST BE the first record
 *
 * @param[in] db a pointer to the database
 * @param[in] zone_data a pointer to an opened zone_reader at its start
 * @param[out] zone_pointer_out will contains a pointer to the loaded zone if the call is successful
 *
 * @return an error code.
 *
 */
ya_result
zdb_zone_get_soa(zone_reader *zone_data, u16 *rdata_size, u8 *rdata)
{
    ya_result return_value;
    resource_record entry;
    
    resource_record_init(&entry);

    if(ISOK(return_value = zone_reader_read_record(zone_data, &entry)))
    {
        if(entry.type == TYPE_SOA)
        {
            s32 soa_rdata_len = zone_reader_rdata_size(entry);
            u8 *soa_rdata = zone_reader_rdata(entry);
            
            if(soa_rdata_len < MAX_SOA_RDATA_LENGTH)
            {
                memcpy(rdata, soa_rdata, soa_rdata_len);
                *rdata_size = soa_rdata_len;
            }
            else
            {
                return_value = INVALID_RECORD; // too big
            }
        }
        else
        {
            return_value = INVALID_STATE_ERROR;
        }
    }
    
    return return_value;
}

/**
  @}
 */
