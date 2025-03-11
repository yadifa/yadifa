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
 * @defgroup yadifa
 * @ingroup ###
 * @brief
 *----------------------------------------------------------------------------*/

#define ZONESIGN_C_ 1

/** @note: here we define the variable that is holding the default logger handle for the current source file
 *         Such a handle should NEVER been set in an include file.
 */

#include "client_config.h"

#include <sys/time.h>
#include <unistd.h>
#include <strings.h>

#include "common_config.h"
#include "common.h"
#include "module.h"
#include "module/zonesign.h"
#include "dnscore/pool.h"
#include "dnscore/sys_get_cpu_count.h"

#include <dnscore/cmdline.h>
#include <dnscore/config_cmdline.h>
#include <dnscore/config_settings.h>
#include <dnscore/logger.h>
#include <dnscore/logger_handle.h>
#include <dnscore/output_stream.h> // needed because of an issue in cmdline
#include <dnscore/file_input_stream.h>
#include <dnscore/thread_pool.h>
#include <dnsdb/zdb_zone_load.h>
#include <dnscore/zone_reader_text.h>
#include <dnsdb/zdb_zone_write.h>
#include <dnsdb/zdb.h>
#include <dnsdb/zdb_zone_path_provider.h>
#include <dnsdb/zdb_zone_maintenance.h>
#include <dnsdb/dnssec_keystore.h>
#include <dnsdb/zdb_zone_label_iterator.h>
#include <dnscore/dnskey_signature.h>
#include <dnscore/random.h>
#include <dnsdb/zdb_packed_ttlrdata.h>
#include <dnscore/base64.h>
#include <dnscore/base16.h>

/*----------------------------------------------------------------------------*/
#pragma mark DEFINES

#define ZONESIGN_SECTION_NAME "yadifa-zonesign"

#define N3RDTTMP_TAG          0x504d54544452334e
#define ZSTMPBUF_TAG          0x465542504d54535a

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES

extern logger_handle_t *g_yadifa_logger;
#define MODULE_MSG_HANDLE g_yadifa_logger

// ********************************************************************************
// ***** module settings
// ********************************************************************************

static yadifa_zonesign_settings_s g_yadifa_zonesign_settings;

static random_ctx_t               rndctx = NULL;

static atomic_uint64_t            total_signatures_count = 0;

static const uint8_t              NSEC3_FLAGS_MARKED_UNUSED = 0x80;
static const uint8_t              NSEC3_FLAGS_MARKED_MODIFIED = 0x40;
static const uint8_t              NSEC3_FLAGS_MARKED_DELETED = 0x20;
static const uint8_t              NSEC3_FLAGS_MARKED_OPTOUT = 0x01;

static value_name_table_t         dnssec_enum[] = {{ZDB_ZONE_MAINTAIN_NSEC, "nsec"}, {ZDB_ZONE_MAINTAIN_NSEC3, "nsec3"}, {ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT, "nsec3-optout"}, {0, NULL}};

#define KEYS_PATH_DEFAULT LOCALSTATEDIR "/zones/keys/"
#define SIGN_FROM_DEFAULT "-1d"
#define SIGN_TO_DEFAULT   "+31d"

#define CONFIG_TYPE       yadifa_zonesign_settings_s

CONFIG_BEGIN(yadifa_zonesign_settings_desc)
CONFIG_PATH(keys_path, KEYS_PATH_DEFAULT)
CONFIG_FILE(input_file, NULL)
CONFIG_FILE(journal_file, NULL)
CONFIG_STRING(output_file, NULL)
CONFIG_FQDN(origin, NULL)
CONFIG_STRING(from_time_text, SIGN_FROM_DEFAULT)
CONFIG_STRING(to_time_text, SIGN_TO_DEFAULT)
CONFIG_STRING(now_text, "now")
CONFIG_STRING(nsec3_salt_text, NULL)
CONFIG_U32_RANGE(interval, "0", 0, INT32_MAX)
CONFIG_U32_RANGE(jitter, "0", 0, INT32_MAX)
CONFIG_U32_RANGE(dnskey_ttl, "86400", 0, INT32_MAX)
CONFIG_U32(new_serial, "0")
CONFIG_U32(workers, "0")
CONFIG_U16(nsec3_iterations, "1")
CONFIG_BOOL(nsec3_optout, "0")
CONFIG_BOOL(read_journal, "0")
CONFIG_BOOL(smart_signing, "0")
CONFIG_ENUM(dnssec_mode, "nsec3", dnssec_enum)
CONFIG_U8_INC(verbose)
CONFIG_END(yadifa_zonesign_settings_desc)

// ********************************************************************************
// ***** module command line struct
// ********************************************************************************

/**
 * The filter gets all words not taken by the rest of the CMDLINE struct
 */

static ya_result zonesign_cmdline_filter_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned)
{
    void *arg = CMDLINE_CALLBACK_ARG_GET(desc);
    (void)arg;
    (void)callback_owned;

    ya_result ret = cmdline_get_opt_long(desc, "input-file", arg_name);

    return ret;
}

CMDLINE_BEGIN(yadifa_cmdline)
CMDLINE_FILTER(zonesign_cmdline_filter_callback, NULL) // NULL is passed to the callback as a parameter (callback_owned)
// main hooks
CMDLINE_INDENT(4)
CMDLINE_IMSG("options:", "")
CMDLINE_INDENT(4)
CMDLINE_SECTION(ZONESIGN_SECTION_NAME)
CMDLINE_BOOL("smart-signing", 'S', "smart_signing")
CMDLINE_HELP("", "load keys found in the directory specified by keys-path and add the published ones to the zone")
CMDLINE_OPT("keys-path", 'K', "keys_path")
CMDLINE_HELP("<path>", "directory to find key files (default: " KEYS_PATH_DEFAULT ")")
CMDLINE_OPT("sign-start", 's', "from_time_text")
CMDLINE_HELP("<time>", "sets the signature start time (default: " SIGN_FROM_DEFAULT ")")
CMDLINE_IMSG("", "    can be: now, yesterday, tomorrow")
CMDLINE_IMSG("", "    can be: YYYYMMDDHHmmss for year month day 24h-hour minutes seconds")
CMDLINE_IMSG("",
             "    can be: +integer[units] | -integer[units] where units can be years, months, days, hours, seconds or "
             "their first letters")
CMDLINE_IMSG("", "    ex: yesterday, -1day, -1d, -24hours, -24h : one day ago")
CMDLINE_IMSG("", "    ex: tomorrow, +1day, +1d, +24hours, +24h : in one day")
CMDLINE_OPT("sign-end", 'e', "to_time_text")
CMDLINE_HELP("<time>", "sets the signature end time (default: " SIGN_TO_DEFAULT ")")
CMDLINE_IMSG("", "    see sign-start option for format")
CMDLINE_OPT("interval", 'i', "interval")
CMDLINE_HELP("<seconds>", "sets the interval (default: sign-end - sign-start) / 4")
CMDLINE_OPT("jitter", 'j', "interval")
CMDLINE_HELP("<seconds>", "randomize the signature end time by up that time (default: 0)")
CMDLINE_OPT("now", 0, "now")
CMDLINE_HELP("<time>", "sets the current reference time to use for the verification of signatures (default: now)")
CMDLINE_IMSG("", "    see sign-start option for format")
CMDLINE_OPT("origin", 'o', "origin")
CMDLINE_HELP("<fqdn>", "sets the zone origin (default: guess from zone file)")
CMDLINE_OPT("new-serial", 0, "new_serial")
CMDLINE_HELP("<serial>", "sets the serial of the zone")
CMDLINE_OPT("input-file", 0, "input_file")
// DO NOT DOCUMENT THIS ONE
CMDLINE_OPT("output", 'f', "output_file")
CMDLINE_HELP("<file>", "the name of the signed zone file (default: zone file + \".signed\")")
CMDLINE_BOOL("journal", 'J', "read_journal")
CMDLINE_HELP("", "read the yadifad journal file next to the zone file, named: origin. + \".cjf\" (default: no)")
CMDLINE_OPT("dnssec-mode", 'M', "dnssec_mode")
CMDLINE_HELP("<mode>", "sets the DNSSEC mode to use for the zone (default: guess from the zone file, nsec3 if unsigned zone)")
CMDLINE_IMSG("", "    can be: nsec, nsec3, nsec3-optout")
CMDLINE_OPT("nsec3-salt", '3', "nsec3_salt_text")
CMDLINE_HELP("<hex>", "NSEC3 salt")
CMDLINE_OPT("nsec3-iterations", 'H', "nsec3_iterations")
CMDLINE_HELP("<n>", "NSEC3 iterations value (default: guess from the zone file, 1 if unsigned zone with new mode)")
CMDLINE_BOOL("nsec3-optout", 'A', "nsec3_optout")
CMDLINE_HELP("", "NSEC3 optout (default: guess from the zone file, optin if unsigned zone with new mode)")
CMDLINE_BOOL("verbose", 'v', "verbose")
CMDLINE_HELP("", "increases verbosity")

// command line
CMDLINE_VERSION_HELP(yadifa_cmdline)
CMDLINE_SECTION(ZONESIGN_SECTION_NAME) // CMDLINE_VERSION_HELP changes the section
CMDLINE_BLANK()
CMDLINE_END(yadifa_cmdline)

// ********************************************************************************
// zone reader filter
// ********************************************************************************

static ya_result nosec_zone_reader_read_record(zone_reader_t *zr, resource_record_t *rr)
{
    zone_reader_t *fzr = zr->data;
    ya_result      ret;
    for(;;)
    {
        ret = fzr->vtbl->read_record(fzr, rr);
        if(ret == 1)
        {
            if(rr->type == TYPE_RRSIG)
            {
                continue;
            }
        }
        return ret;
    }
}

static ya_result nosec_zone_reader_unread_record(zone_reader_t *zr, resource_record_t *rr)
{
    zone_reader_t *fzr = zr->data;
    return fzr->vtbl->unread_record(fzr, rr);
}

static ya_result nosec_zone_reader_free_record(zone_reader_t *zr, resource_record_t *rr)
{
    zone_reader_t *fzr = zr->data;
    return fzr->vtbl->free_record(fzr, rr);
}

static void nosec_zone_reader_close(zone_reader_t *zr)
{
    zone_reader_t *fzr = zr->data;
    fzr->vtbl->close(fzr);
}

static void nosec_zone_reader_handle_error(zone_reader_t *zr,
                                           ya_result      error_code) // used for cleaning up after an error (AXFR feedback)
{
    zone_reader_t *fzr = zr->data;
    fzr->vtbl->handle_error(fzr, error_code);
}

static const char *nosec_zone_reader_get_last_error_message(zone_reader_t *zr)
{
    zone_reader_t *fzr = zr->data;
    return fzr->vtbl->get_last_error_message(fzr);
}

static bool nosec_zone_reader_canwriteback(zone_reader_t *zr)
{
    zone_reader_t *fzr = zr->data;
    return fzr->vtbl->can_write_back(fzr);
}

static const zone_reader_vtbl nosec_zone_reader_vtbl = {nosec_zone_reader_read_record,
                                                        nosec_zone_reader_unread_record,
                                                        nosec_zone_reader_free_record,
                                                        nosec_zone_reader_close,
                                                        nosec_zone_reader_handle_error,
                                                        nosec_zone_reader_canwriteback,
                                                        nosec_zone_reader_get_last_error_message,
                                                        "nosec_zone_reader"};

static void                   nosec_zone_reader_init(zone_reader_t *zr, zone_reader_t *fzr)
{
    zr->data = fzr;
    zr->vtbl = &nosec_zone_reader_vtbl;
}

// ********************************************************************************
// ***** module register
// ********************************************************************************

static int zonesign_config_register(int priority)
{
    // register all config blocs required by the server

    ZEROMEMORY(&g_yadifa_zonesign_settings, sizeof(g_yadifa_zonesign_settings));

    ya_result ret;

    if(FAIL(ret = config_register_struct(ZONESIGN_SECTION_NAME, yadifa_zonesign_settings_desc, &g_yadifa_zonesign_settings, priority)))
    {
        return ret; // internal error
    }

    return ret;
}

// ********************************************************************************
// ***** module run
// ********************************************************************************

static ya_result database_zone_path_provider(const uint8_t *domain_fqdn, char *path_buffer, uint32_t path_buffer_size, uint32_t flags)
{
    (void)domain_fqdn;
    ya_result ret = ZDB_ERROR_ZONE_NOT_IN_DATABASE;

    switch(flags & ~ZDB_ZONE_PATH_PROVIDER_MKDIR)
    {
        case ZDB_ZONE_PATH_PROVIDER_ZONE_PATH:
        {
            ret = file_get_absolute_path(g_yadifa_zonesign_settings.input_file, path_buffer, path_buffer_size);
            while((--ret > 0) && path_buffer[ret] != '/')
                ;
            path_buffer[ret] = '\0';
            break;
        }
        case ZDB_ZONE_PATH_PROVIDER_ZONE_FILE:
        {
            ret = snformat(path_buffer, path_buffer_size, "%s", g_yadifa_zonesign_settings.input_file);
            break;
        }
        case ZDB_ZONE_PATH_PROVIDER_DNSKEY_PATH:
        {
            ret = snformat(path_buffer, path_buffer_size, "%s", g_yadifa_zonesign_settings.keys_path);
            break;
        }
        default:
        {
            ret = INVALID_STATE_ERROR;
            break;
        }
    }

    return ret;
}

static void zonesign_nsec3_flags_and_or(nsec3_zone_t *n3, uint8_t mask_and, uint8_t mask_or)
{
    nsec3_iterator_t iter;
    nsec3_iterator_init(&n3->items, &iter);

    while(nsec3_iterator_hasnext(&iter))
    {
        nsec3_zone_item_t *item = nsec3_iterator_next_node(&iter);
        item->flags &= mask_and;
        item->flags |= mask_or;
    }
}

static inline void bitarray_set(uint8_t *bytes, uint32_t index, uint8_t value)
{
    if(value & 1)
    {
        bytes[index >> 3] |= 1 << (index & 7);
    }
    else
    {
        bytes[index >> 3] &= ~(1 << (index & 7));
    }
}

static inline uint8_t bitarray_get(uint8_t *bytes, uint32_t index) { return (bytes[index >> 3] >> (index & 7)) & 1; }

static void           zonesign_signature_from_to_get(int32_t *from_epochp, int32_t *to_epochp)
{
    int32_t from_epoch = g_yadifa_zonesign_settings.from_time;
    int32_t to_epoch = g_yadifa_zonesign_settings.to_time;
    if(g_yadifa_zonesign_settings.jitter > 0)
    {
        int32_t r = random_next(rndctx);
        to_epoch += r % g_yadifa_zonesign_settings.jitter;
    }

    *from_epochp = from_epoch;
    *to_epochp = to_epoch;
}

static bool zonesign_signature_should_be_replaced(int32_t to_epoch) { return to_epoch < MAX((int32_t)(g_yadifa_zonesign_settings.to_time - g_yadifa_zonesign_settings.interval), 0); }

struct zonesign_nsec3_chain_item_sign_parms_s
{
    zdb_zone_t   *zone;
    nsec3_zone_t *n3;
    ptr_vector_t *zsks;
    int32_t       min_ttl;
};

struct zonesign_nsec3_chain_item_sign_parms_s zonesign_nsec3_chain_item_sign_parms;

static void                                   zonesign_nsec3_chain_item_sign(void *parms_)
{
    nsec3_zone_item_t      *item = parms_;
    zdb_zone_t             *zone = zonesign_nsec3_chain_item_sign_parms.zone;
    nsec3_zone_t           *n3 = zonesign_nsec3_chain_item_sign_parms.n3;
    ptr_vector_t           *zsks = zonesign_nsec3_chain_item_sign_parms.zsks;

    resource_record_view_t  rrv_;
    resource_record_view_t *rrv = &rrv_;

    nsec3_item_resource_record_view_init(rrv);
    nsec3_item_resource_record_view_origin_set(rrv, zone->origin);
    nsec3_item_resource_record_view_nsec3_zone_set(rrv, n3);
    nsec3_item_resource_record_view_ttl_set(rrv, zonesign_nsec3_chain_item_sign_parms.min_ttl);

    item->flags &= NSEC3_FLAGS_MARKED_OPTOUT;

    nsec3_zone_item_rrsig_delete_all(item);

    for(int_fast32_t i = 0; i <= ptr_vector_last_index(zsks); ++i)
    {
        dnskey_t *key = (dnskey_t *)ptr_vector_get(zsks, i);
        // uint16_t tag = dnskey_get_tag(key);

        zdb_resource_record_data_t *nsec3_rrsig = NULL;

        dnskey_signature_t          ds;
        dnskey_signature_init(&ds);
        ptr_vector_t rrset_dummy = {{(void **)&item}, 0, 1};

        int32_t      from_epoch;
        int32_t      to_epoch;

        zonesign_signature_from_to_get(&from_epoch, &to_epoch);

        dnskey_signature_set_validity(&ds, from_epoch, to_epoch);
        dnskey_signature_set_view(&ds, rrv);
        dnskey_signature_set_rrset_reference(&ds, &rrset_dummy);
        dnskey_signature_set_canonised(&ds, true);
        ya_result ret = dnskey_signature_sign(&ds, key, (void **)&nsec3_rrsig);
        dnskey_signature_finalize(&ds);

        if(ISOK(ret))
        {
            ++total_signatures_count;
            if(g_yadifa_zonesign_settings.verbose >= 2)
            {
                rdata_desc_t rrsig_rdata_desc = {TYPE_RRSIG, zdb_resource_record_data_rdata_size(nsec3_rrsig), zdb_resource_record_data_rdata_const(nsec3_rrsig)};
                formatln("%{dnsname} add  %{digest32h} RRSIG %{rdatadesc}", zone->origin, item->digest, &rrsig_rdata_desc);
                flushout();
            }

            nsec3_zone_item_rrsig_add(item, nsec3_rrsig);
        }
        else
        {
            break;
        }
    }

    nsec3_item_resource_record_finalize(rrv);
}

static ya_result zonesign_nsec3_chain_update(zdb_zone_t *zone, nsec3_zone_t *n3, ptr_vector_t *zsks, bool opt_out, int workers)
{
    nsec3_load_is_label_covered_function *is_covered;
    nsec3_hash_function_t                *hash_function;
    uint8_t                              *nsec3_rdata;
    uint8_t                              *loaded_nsec3_rdata;
    uint8_t                              *salt;
#if NSEC3_MIN_TTL_ERRATA
    int32_t min_ttl = zone->min_ttl_soa;
#else
    int32_t min_ttl = zone->min_ttl;
#endif
    ya_result                 ret = SUCCESS;
    uint16_t                  hash_iterations;
    uint16_t                  nsec3param_rdata_size;
    uint8_t                   salt_len;
    uint8_t                   digest_len;
    uint8_t                   optout_byte;
    zdb_zone_label_iterator_t iter;
    // btree_iterator type_iter;
    type_bit_maps_context_t type_bitmap;
    uint8_t                 digest[64];
    uint8_t                 fqdn[256];

    MALLOC_OBJECT_ARRAY_OR_DIE(nsec3_rdata, uint8_t, 65536 * 2, N3RDTTMP_TAG);
    loaded_nsec3_rdata = &nsec3_rdata[65536];

    if(opt_out)
    {
        is_covered = nsec3_load_is_label_covered_optout;
        optout_byte = NSEC3_FLAGS_MARKED_OPTOUT;
    }
    else
    {
        is_covered = nsec3_load_is_label_covered;
        optout_byte = 0;
    }

    zonesign_nsec3_flags_and_or(n3, 0xff, NSEC3_FLAGS_MARKED_UNUSED);

    digest_len = digest[0] = nsec3_hash_len(NSEC3PARAM_RDATA_ALGORITHM(n3->rdata));
    hash_function = nsec3_hash_get_function(NSEC3PARAM_RDATA_ALGORITHM(n3->rdata));
    salt = NSEC3PARAM_RDATA_SALT(n3->rdata);
    salt_len = NSEC3PARAM_RDATA_SALT_LEN(n3->rdata);
    hash_iterations = NSEC3PARAM_RDATA_ITERATIONS(n3->rdata);
    nsec3param_rdata_size = NSEC3PARAM_LENGTH_MIN + salt_len;

    bool nsec3_chain_is_new = n3->items == NULL;

    zdb_zone_label_iterator_init(zone, &iter);
    while(zdb_zone_label_iterator_hasnext(&iter))
    {
        uint32_t        fqdn_len = zdb_zone_label_iterator_nextname(&iter, fqdn);
        zdb_rr_label_t *label = zdb_zone_label_iterator_next(&iter);

        if(!is_covered(label))
        {
            continue;
        }

        hash_function(fqdn, fqdn_len, salt, salt_len, hash_iterations, &digest[1], false);

        // uint16_t bitmap_size = zdb_record_bitmap_type_init(&label->resource_record_set, &type_bitmap);

        uint16_t bitmap_size;
        bitmap_size = zdb_rr_label_bitmap_type_init(label, &type_bitmap);
        uint16_t nsec3_rdata_size_pre_bitmap = nsec3param_rdata_size + 1 + digest_len;
        uint16_t nsec3_rdata_size = nsec3_rdata_size_pre_bitmap + bitmap_size;

        memcpy(nsec3_rdata, n3->rdata, nsec3param_rdata_size);
        nsec3_rdata[1] = optout_byte;
        nsec3_rdata[nsec3param_rdata_size] = SHA_DIGEST_LENGTH;
        uint8_t *bitmap_bytes = &nsec3_rdata[nsec3param_rdata_size + 1 + digest_len];
        type_bit_maps_write(&type_bitmap, bitmap_bytes);

        // find the record in the chain

        if(nsec3_chain_is_new)
        {
            nsec3_zone_item_t *item = nsec3_insert(&n3->items, digest);
            item->flags = NSEC3_FLAGS_MARKED_MODIFIED | optout_byte;
            nsec3_zone_item_update_bitmap(item, nsec3_rdata, nsec3_rdata_size);
            item->rrsig_rrset = NULL;

            if(g_yadifa_zonesign_settings.verbose >= 2)
            {
                nsec3_zone_item_t *prev_item;

                if((prev_item = nsec3_find_interval_prev_mod(&n3->items, digest)) == NULL)
                {
                    prev_item = item;
                }

                nsec3_zone_item_t *item_next = nsec3_node_mod_next(prev_item);
                memcpy(&nsec3_rdata[nsec3param_rdata_size], item_next->digest, NSEC3_NODE_DIGEST_SIZE(item_next) + 1);
                rdata_desc_t zone_rdata_desc = {TYPE_NSEC3, nsec3_rdata_size, nsec3_rdata};
                formatln("%{dnsname} add %{digest32h} NSEC3 %{rdatadesc}", fqdn, digest, &zone_rdata_desc);
                flushout();
            }
        }
        else
        {
            nsec3_zone_item_t *item = nsec3_find(&n3->items, digest);
            if(item == NULL) // the expected record doesn't exist
            {
                // create it
                // Its predecessor's signature must be marked as next-changed

                if(g_yadifa_zonesign_settings.verbose >= 1)
                {
                    formatln("%{dnsname} covering NSEC3 record %{digest32h} missing", fqdn, digest);
                }

                nsec3_zone_item_t *prev_item;

                if((prev_item = nsec3_find_interval_prev_mod(&n3->items, digest)) != NULL)
                {
                    prev_item->flags |= NSEC3_FLAGS_MARKED_MODIFIED;
                    nsec3_zone_item_rrsig_delete_all(prev_item);
                    if(g_yadifa_zonesign_settings.verbose >= 1)
                    {
                        formatln("%{dnsname} previous NSEC3 record %{digest32h} marked as modified", fqdn, prev_item->digest);

                        if(g_yadifa_zonesign_settings.verbose >= 2)
                        {
                            nsec3_zone_item_t *item_next = nsec3_node_mod_next(prev_item);
                            memcpy(&nsec3_rdata[nsec3param_rdata_size], item_next->digest, NSEC3_NODE_DIGEST_SIZE(item_next) + 1);
                            rdata_desc_t zone_rdata_desc = {TYPE_NSEC3, nsec3_rdata_size, nsec3_rdata};
                            formatln("%{dnsname} add %{digest32h} NSEC3 %{rdatadesc}", fqdn, digest, &zone_rdata_desc);
                            flushout();
                        }
                    }
                }

                item = nsec3_insert(&n3->items, digest);
                item->flags = NSEC3_FLAGS_MARKED_MODIFIED | optout_byte;
                nsec3_zone_item_update_bitmap(item, nsec3_rdata, nsec3_rdata_size);
                item->rrsig_rrset = NULL;
            }
            else // the record exists
            {
                item->flags &= ~NSEC3_FLAGS_MARKED_UNUSED;
                item->flags &= optout_byte | ~NSEC3_FLAGS_MARKED_OPTOUT;

                // check it's a full match
                if(((item->flags & NSEC3_FLAGS_MARKED_OPTOUT) == optout_byte) && (item->type_bit_maps_size == bitmap_size) && (memcmp(item->type_bit_maps, bitmap_bytes, bitmap_size) == 0))
                {
                    // full match
                    // formatln("%{dnsname} covering NSEC3 record %{digest32h} is OK", fqdn, digest);
                }
                else // if it's not a full match, its signature must be re-made
                {
                    if(g_yadifa_zonesign_settings.verbose >= 1)
                    {
                        formatln("%{dnsname} covering NSEC3 record %{digest32h} differs from expectations", fqdn, digest);

                        if(g_yadifa_zonesign_settings.verbose >= 2)
                        {
                            uint16_t           loaded_nsec3_rdata_size = nsec3_zone_item_to_rdata(n3, item, loaded_nsec3_rdata, 65535);
                            nsec3_zone_item_t *item_next = nsec3_node_mod_next(item);
                            memcpy(&nsec3_rdata[nsec3param_rdata_size], item_next->digest, NSEC3_NODE_DIGEST_SIZE(item_next) + 1);
                            rdata_desc_t loaded_rdata_desc = {TYPE_NSEC3, loaded_nsec3_rdata_size, loaded_nsec3_rdata};
                            rdata_desc_t zone_rdata_desc = {TYPE_NSEC3, nsec3_rdata_size, nsec3_rdata};

                            formatln("%{dnsname} del %{digest32h} NSEC3 %{rdatadesc}", fqdn, digest, &loaded_rdata_desc);
                            flushout();
                            formatln("%{dnsname} add %{digest32h} NSEC3 %{rdatadesc}", fqdn, digest, &zone_rdata_desc);
                            flushout();
                        }
                    }

                    item->flags |= NSEC3_FLAGS_MARKED_MODIFIED | optout_byte;
                    if(item->type_bit_maps_size != bitmap_size)
                    {
                        nsec3_item_type_bitmap_free(item);
                        ZALLOC_OBJECT_ARRAY_OR_DIE(item->type_bit_maps, uint8_t, bitmap_size, NSEC3_TYPEBITMAPS_TAG);
                        item->type_bit_maps_size = bitmap_size;
                    }
                    memcpy(item->type_bit_maps, bitmap_bytes, bitmap_size);
                    nsec3_zone_item_rrsig_delete_all(item);
                }
            }
        }
    } // for all labels

    // cleanup

    if(!nsec3_chain_is_new)
    {
        ptr_vector_t nsec3_items_to_delete;
        ptr_vector_init_empty(&nsec3_items_to_delete);
        nsec3_iterator_t iter;
        nsec3_iterator_init(&n3->items, &iter);

        while(nsec3_iterator_hasnext(&iter))
        {
            nsec3_zone_item_t *item = nsec3_iterator_next_node(&iter);
            if((item->flags & NSEC3_FLAGS_MARKED_UNUSED) != 0)
            {
                // remove the node

                if(g_yadifa_zonesign_settings.verbose >= 2)
                {
                    uint16_t           loaded_nsec3_rdata_size = nsec3_zone_item_to_rdata(n3, item, loaded_nsec3_rdata, 65535);
                    nsec3_zone_item_t *item_next = nsec3_node_mod_next(item);
                    memcpy(&nsec3_rdata[nsec3param_rdata_size], item_next->digest, NSEC3_NODE_DIGEST_SIZE(item_next) + 1);
                    rdata_desc_t loaded_rdata_desc = {TYPE_NSEC3, loaded_nsec3_rdata_size, loaded_nsec3_rdata};

                    formatln("%{dnsname} del %{digest32h} NSEC3 %{rdatadesc}", zone->origin, item->digest, &loaded_rdata_desc);
                    flushout();
                }

                item->flags |= NSEC3_FLAGS_MARKED_DELETED;
                nsec3_zone_item_rrsig_delete_all(item);
                ptr_vector_append(&nsec3_items_to_delete, item);
                nsec3_zone_item_t *prev_item = item;

                do
                {
                    prev_item = nsec3_node_mod_prev(prev_item);
                } while(((prev_item->flags & NSEC3_FLAGS_MARKED_DELETED) != 0) && prev_item != item);

                if(item == prev_item)
                {
                    // the whole chain has been deleted.
                    ptr_vector_clear(&nsec3_items_to_delete);
                    nsec3_destroy(&n3->items);
                    break;
                }

                prev_item->flags |= NSEC3_FLAGS_MARKED_MODIFIED;
                nsec3_zone_item_rrsig_delete_all(prev_item);
            }
        }

        for(int_fast32_t i = 0; i <= ptr_vector_last_index(&nsec3_items_to_delete); ++i)
        {
            nsec3_zone_item_t *item = (nsec3_zone_item_t *)ptr_vector_get(&nsec3_items_to_delete, i);
            nsec3_item_remove_all_owners(item);
            nsec3_item_remove_all_star(item);
            nsec3_delete(&n3->items, item->digest);
        }

        type_bit_maps_finalize(&type_bitmap);
    }

    // sign what must

    zonesign_nsec3_chain_item_sign_parms.zone = zone;
    zonesign_nsec3_chain_item_sign_parms.n3 = n3;
    zonesign_nsec3_chain_item_sign_parms.zsks = zsks;
    zonesign_nsec3_chain_item_sign_parms.min_ttl = min_ttl;

    if(workers <= 1)
    {
        nsec3_iterator_t iter;
        nsec3_iterator_init(&n3->items, &iter);

        while(nsec3_iterator_hasnext(&iter))
        {
            nsec3_zone_item_t *item = nsec3_iterator_next_node(&iter);
            zonesign_nsec3_chain_item_sign(item);
        }
    }
    else
    {
        // use the list of signing keys for signing

        struct thread_pool_s *tp = thread_pool_init_ex(workers, workers * 1024, "nsec3sig");

        nsec3_iterator_t      iter;
        nsec3_iterator_init(&n3->items, &iter);

        while(nsec3_iterator_hasnext(&iter))
        {
            nsec3_zone_item_t *item = nsec3_iterator_next_node(&iter);
            thread_pool_enqueue_call(tp, zonesign_nsec3_chain_item_sign, item, NULL, "nsec3sig");
        }

        thread_pool_wait_queue_empty(tp);
        thread_pool_destroy(tp);
    }

    free(nsec3_rdata);

    return ret;
}

static ya_result zonesign_update_nsec3_chain(zdb_zone_t *zone, ptr_vector_t *zsks, bool opt_out)
{
    ya_result ret = SUCCESS;
    for(int_fast32_t chain_index = 0;; ++chain_index)
    {
        nsec3_zone_t *n3 = zdb_zone_get_nsec3chain(zone, chain_index);
        if(n3 == NULL)
        {
            break;
        }

        if(FAIL(ret = zonesign_nsec3_chain_update(zone, n3, zsks, opt_out, g_yadifa_zonesign_settings.workers)))
        {
            break;
        }
    }

    return ret;
}

struct zonesign_update_label_signature_parms_s
{
    zdb_zone_t                           *zone;
    zdb_rr_label_t                       *label;
    ptr_vector_t                         *ksks;
    ptr_vector_t                         *zsks;
    nsec3_load_is_label_covered_function *is_covered;
    uint8_t                              *buffer_72K;
    pool_t                               *pool;
    ptr_vector_t                          rrset;
    resource_record_view_t                rrv;
    uint8_t                               fqdn[DOMAIN_LENGTH_MAX];
};

static void *zonesign_update_label_signature_parms_allocate(void *args)
{
    (void)args;
    static const size_t                             buffer_size = 8704 + 65536;
    struct zonesign_update_label_signature_parms_s *parms;
    ZALLOC_OBJECT_OR_DIE(parms, struct zonesign_update_label_signature_parms_s, GENERIC_TAG);
    parms->zone = NULL;
    parms->label = NULL;
    parms->ksks = NULL;
    parms->zsks = NULL;
    parms->is_covered = NULL;
    MALLOC_OBJECT_ARRAY_OR_DIE(parms->buffer_72K, uint8_t, 8704 + 65536, ZSTMPBUF_TAG);
    ZEROMEMORY(parms->buffer_72K, buffer_size);
    ptr_vector_init_empty(&parms->rrset);
    zdb_resource_record_data_resource_record_view_init(&parms->rrv);
    zdb_resource_record_data_resource_record_view_set_class(&parms->rrv, CLASS_IN);
    return parms;
}

static void zonesign_update_label_signature_parms_reset(void *ptr, void *args)
{
    (void)ptr;
    (void)args;
}

static void zonesign_update_label_signature_parms_free(void *ptr, void *args)
{
    (void)args;
    struct zonesign_update_label_signature_parms_s *parms = ptr;
    ptr_vector_finalise(&parms->rrset);
    free(parms->buffer_72K);
    ZFREE_OBJECT(parms);
}

static void zonesign_update_label_signatures(void *parms_)
{
    struct zonesign_update_label_signature_parms_s *parms = parms_;
    zdb_rr_label_t                                 *label = parms->label;
    bool                                            delegation = ZDB_LABEL_ATORUNDERDELEGATION(label);
    zdb_resource_record_set_t                      *rrsig_rrset = zdb_rr_label_get_rrset(label, TYPE_RRSIG);
    uint8_t                                        *tags_bitmap = &parms->buffer_72K[0];
    uint8_t                                        *rdata_buffer = &parms->buffer_72K[8192];
    resource_record_view_t                         *rrv = &parms->rrv;

    if(rrsig_rrset != NULL)
    {
        if(parms->is_covered(label))
        {
            // remove expired or invalid signatures

            ptr_vector_t                     to_delete = PTR_VECTOR_EMPTY;

            zdb_resource_record_set_iterator rrsig_rrset_iter;
            zdb_resource_record_set_iterator_init(rrsig_rrset, &rrsig_rrset_iter);
            while(zdb_resource_record_set_iterator_has_next(&rrsig_rrset_iter))
            {
                zdb_resource_record_data_t *rrsig_record = zdb_resource_record_set_iterator_next(&rrsig_rrset_iter);

                uint8_t                    *rrsig_rdata = zdb_resource_record_data_rdata(rrsig_record);
                uint16_t                    rrsig_rdata_size = zdb_resource_record_data_rdata_size(rrsig_record);

                uint16_t                    tag = rrsig_get_key_tag_from_rdata(rrsig_rdata, rrsig_rdata_size);
                uint16_t                    type_covered = rrsig_get_type_covered_from_rdata(rrsig_rdata, rrsig_rdata_size);

                ptr_vector_t               *keys = (type_covered != TYPE_DNSKEY) ? parms->zsks : parms->ksks;
                dnskey_t                   *signing_key = NULL;

                for(int_fast32_t i = 0; i <= ptr_vector_last_index(keys); ++i)
                {
                    dnskey_t *key = (dnskey_t *)ptr_vector_get(keys, i);

                    if(dnskey_get_tag(key) == tag)
                    {
                        signing_key = key;
                    }
                }

                bool expect_signed = !delegation | (delegation && ((type_covered == TYPE_DS) || (type_covered == TYPE_NSEC)));

                // if there is no such key or the signature is invalid

                if(!expect_signed || (signing_key == NULL) || (dnskey_is_private(signing_key) && zonesign_signature_should_be_replaced(rrsig_get_valid_until_from_rdata(rrsig_rdata, rrsig_rdata_size))))
                {
                    ptr_vector_append(&to_delete, rrsig_record);

                    struct zdb_ttlrdata rrsig_to_delete;
                    rrsig_to_delete.next = NULL;
                    rrsig_to_delete.rdata_size = rrsig_rdata_size;
                    memcpy(rdata_buffer, rrsig_rdata, rrsig_rdata_size);
                    rrsig_to_delete.rdata_pointer = rdata_buffer;

                    zdb_resource_record_sets_delete_exact_record(&label->resource_record_set, TYPE_RRSIG, &rrsig_to_delete);
                }
            }

            for(int_fast32_t i = 0; i <= ptr_vector_last_index(&to_delete); ++i)
            {
                zdb_resource_record_data_t *rrsig_record = (zdb_resource_record_data_t *)ptr_vector_get(&to_delete, i);
                zdb_resource_record_data_delete(rrsig_record);
            }

            rrsig_rrset = zdb_rr_label_get_rrset(label, TYPE_RRSIG);
        }
        else
        {
            // remove all signatures
            zdb_resource_record_sets_delete_type(&label->resource_record_set, TYPE_RRSIG);
        }
    }

    // there is no irrelevant signatures present

    if(parms->is_covered(label))
    {
        zdb_resource_record_data_resource_record_view_set_fqdn(rrv, parms->fqdn);

        // if it's not a delegation nor we have a DS or an NSEC, then we will have an RRSIG record
        bool expect_some_signature = !zdb_resource_record_sets_isempty(&label->resource_record_set) &&
                                     (!delegation || (delegation && ((zdb_resource_record_sets_find(&label->resource_record_set, TYPE_DS) != NULL) || (zdb_resource_record_sets_find(&label->resource_record_set, TYPE_NSEC) != NULL))));

        if(expect_some_signature)
        {
            if(rrsig_rrset == NULL)
            {
                /*zdb_resource_record_sets_node *rrset_node = */ zdb_resource_record_sets_insert_empty_set(&label->resource_record_set, TYPE_RRSIG);
            }

            zdb_resource_record_sets_set_iterator_t iter;
            zdb_resource_record_sets_set_iterator_init(&label->resource_record_set, &iter);
            while(zdb_resource_record_sets_set_iterator_hasnext(&iter))
            {
                zdb_resource_record_sets_node_t *rrset_node = zdb_resource_record_sets_set_iterator_next_node(&iter);
                uint16_t                         rtype = zdb_resource_record_set_type(&rrset_node->value);

                if(rtype == TYPE_RRSIG)
                {
                    continue;
                }

                bool expect_signed = !delegation | (delegation && ((rtype == TYPE_DS) || (rtype == TYPE_NSEC)));

                if(!expect_signed)
                {
                    continue;
                }

                int32_t rttl = zdb_resource_record_set_ttl(&rrset_node->value);

                ptr_vector_clear(&parms->rrset);

                zdb_resource_record_set_const_iterator iter;
                zdb_resource_record_set_const_iterator_init(&rrset_node->value, &iter);
                while(zdb_resource_record_set_const_iterator_has_next(&iter))
                {
                    const zdb_resource_record_data_t *record = zdb_resource_record_set_const_iterator_next(&iter);

                    ptr_vector_append(&parms->rrset, (zdb_resource_record_data_t *)record);

                    if(g_yadifa_zonesign_settings.verbose >= 2)
                    {
                        rdata_desc_t rrsig_rdata_desc = {rtype, zdb_resource_record_data_rdata_size(record), zdb_resource_record_data_rdata_const(record)};
                        formatln("%{dnsname} %{typerdatadesc}", parms->fqdn, &rrsig_rdata_desc);
                    }
                }

                zdb_resource_record_data_resource_record_view_set_type(rrv, rtype);
                zdb_resource_record_data_resource_record_view_set_ttl(rrv, rttl);

                ptr_vector_t *keys = (rtype != TYPE_DNSKEY) ? parms->zsks : parms->ksks;

                // sets the tags of all the signing keys

                for(int_fast32_t i = 0; i <= ptr_vector_last_index(keys); ++i)
                {
                    dnskey_t *key = (dnskey_t *)ptr_vector_get(keys, i);
                    bitarray_set(tags_bitmap, dnskey_get_tag(key), 1);
                }

                // clears the tags that have already a signature

                if(rrsig_rrset != NULL)
                {
                    zdb_resource_record_set_const_iterator iter;
                    zdb_resource_record_set_const_iterator_init(&rrset_node->value, &iter);
                    while(zdb_resource_record_set_const_iterator_has_next(&iter))
                    {
                        const zdb_resource_record_data_t *rrsig_record = zdb_resource_record_set_const_iterator_next(&iter);

                        const uint8_t                    *rrsig_rdata = zdb_resource_record_data_rdata_const(rrsig_record);
                        uint16_t                          rrsig_rdata_size = zdb_resource_record_data_rdata_size(rrsig_record);

                        uint16_t                          type_covered = rrsig_get_type_covered_from_rdata(rrsig_rdata, rrsig_rdata_size);

                        if(type_covered == rtype)
                        {
                            uint16_t tag = rrsig_get_key_tag_from_rdata(rrsig_rdata, rrsig_rdata_size);
                            bitarray_set(tags_bitmap, tag, 0);
                        }
                    }
                }

                // process the signing keys whose tags are still enabled

                bool has_one_signature = false;

                for(int_fast32_t i = 0; i <= ptr_vector_last_index(keys); ++i)
                {
                    dnskey_t *key = (dnskey_t *)ptr_vector_get(keys, i);
                    uint16_t  tag = dnskey_get_tag(key);

                    if(bitarray_get(tags_bitmap, tag) == 1)
                    {
                        bitarray_set(tags_bitmap, tag, 0);

                        zdb_resource_record_data_t *type_rrsig = NULL;

                        dnskey_signature_t          ds;
                        dnskey_signature_init(&ds);

                        int32_t from_epoch;
                        int32_t to_epoch;

                        zonesign_signature_from_to_get(&from_epoch, &to_epoch);

                        dnskey_signature_set_validity(&ds, from_epoch, to_epoch);
                        dnskey_signature_set_view(&ds, rrv);
                        dnskey_signature_set_rrset_reference(&ds, &parms->rrset);
                        dnskey_signature_set_canonised(&ds, false);
                        ya_result ret = dnskey_signature_sign(&ds, key, (void **)&type_rrsig);
                        dnskey_signature_finalize(&ds);

                        if(ISOK(ret))
                        {
                            ++total_signatures_count;
                            has_one_signature = true;

                            zdb_resource_record_sets_insert_record(&label->resource_record_set, TYPE_RRSIG, rttl, type_rrsig);

                            if(g_yadifa_zonesign_settings.verbose >= 1)
                            {
                                rdata_desc_t rrsig_rdata_desc = {TYPE_RRSIG, zdb_resource_record_data_rdata_size(type_rrsig), zdb_resource_record_data_rdata_const(type_rrsig)};
                                formatln("%{dnsname} add  %{dnsname} RRSIG %{rdatadesc}", parms->zone->origin, parms->fqdn, &rrsig_rdata_desc);
                                flushout();
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
                    else
                    {
                        has_one_signature = true;
                    }
                }

                if(!has_one_signature)
                {
                    formatln("error: could not sign %{dnsname} %{dnstype}", parms->fqdn, &rtype);
                    break;
                }
            } // while
        }
        else // !if(expect_some_signature)
        {
            // purge the signatures and skip
            zdb_resource_record_sets_delete_type(&label->resource_record_set, TYPE_RRSIG);
        }
    } // if(parms->is_covered(label))

    pool_release(parms->pool, parms);
}

static ya_result zonesign_update_signatures(zdb_zone_t *zone, ptr_vector_t *ksks, ptr_vector_t *zsks, int workers)
{
    ya_result                             ret = SUCCESS;

    nsec3_load_is_label_covered_function *is_covered;

    const size_t                          queue_size = workers * 1024;

    zdb_zone_label_iterator_t             iter;

    if(g_yadifa_zonesign_settings.dnssec_mode == ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT)
    {
        is_covered = nsec3_load_is_label_covered_optout;
    }
    else
    {
        is_covered = nsec3_load_is_label_covered; // NSEC too
    }

    zdb_zone_label_iterator_init(zone, &iter);

    if(workers <= 1)
    {
        struct zonesign_update_label_signature_parms_s *parms = zonesign_update_label_signature_parms_allocate(NULL);

        while(zdb_zone_label_iterator_hasnext(&iter))
        {
            zdb_zone_label_iterator_nextname(&iter, &parms->fqdn[0]);
            zdb_rr_label_t *label = zdb_zone_label_iterator_next(&iter);
            parms->label = label;
            zonesign_update_label_signatures(parms);
        }

        zonesign_update_label_signature_parms_free(parms, NULL);
    }
    else
    {
        struct thread_pool_s *tp = thread_pool_init_ex(workers, queue_size, "signer");
        if(tp == NULL)
        {
            return INVALID_STATE_ERROR;
        }

        pool_t pool;

        pool_init_ex(&pool, zonesign_update_label_signature_parms_allocate, zonesign_update_label_signature_parms_free, zonesign_update_label_signature_parms_reset, NULL, "zonesign_parms");

        pool_set_size(&pool, 1024); // 72MB

        while(zdb_zone_label_iterator_hasnext(&iter))
        {
            struct zonesign_update_label_signature_parms_s *parms = pool_alloc_wait(&pool);
            parms->zone = zone;
            parms->ksks = ksks;
            parms->zsks = zsks;
            parms->is_covered = is_covered;
            parms->pool = &pool;

            zdb_zone_label_iterator_nextname(&iter, &parms->fqdn[0]);
            zdb_rr_label_t *label = zdb_zone_label_iterator_next(&iter);
            parms->label = label;

            thread_pool_enqueue_call(tp, zonesign_update_label_signatures, parms, NULL, "sign");
        }

        thread_pool_wait_queue_empty(tp);
        thread_pool_destroy(tp);
        tp = NULL;

        pool_finalize(&pool);
    }

    return ret;
}

static bool zonesign_remove_signatures_covering_type_matching(const zdb_resource_record_data_t *record, const void *data)
{
    uint16_t *rtypep = (uint16_t *)data;
    return rrsig_get_type_covered_from_rdata(zdb_resource_record_data_rdata_const(record), zdb_resource_record_data_rdata_size(record)) == *rtypep;
}

static void zonesign_remove_signatures_covering_type(zdb_resource_record_sets_set_t *rrsets, uint16_t covered_type)
{
    zdb_resource_record_set_t *rrsig_rrset = zdb_resource_record_sets_find(rrsets, TYPE_RRSIG);
    if(rrsig_rrset != NULL)
    {
        zdb_resource_record_set_delete_matching(rrsig_rrset, zonesign_remove_signatures_covering_type_matching, &covered_type);
    }
}

static ya_result zonesign_load_keys_from_dir(const uint8_t *origin, time_t epoch)
{
    ya_result ret;

    int       ksk_count = 0;
    int       zsk_count = 0;

    if(g_yadifa_zonesign_settings.smart_signing)
    {
        dnssec_keystore_add_domain(origin, g_yadifa_zonesign_settings.keys_path);

        if(FAIL(ret = dnssec_keystore_reload_domain(origin)))
        {
            formatln("error: failed to load keys for domain %{dnsname}: %r", origin, ret);
            return ret;
        }

        for(int_fast32_t i = 0;; ++i)
        {
            dnskey_t *key = dnssec_keystore_acquire_key_from_fqdn_at_index(origin, i);
            if(key == NULL)
            {
                break;
            }

            if(dnskey_is_published(key, epoch))
            {
                uint16_t key_flags = dnskey_get_flags(key);
                if(key_flags == DNSKEY_FLAGS_KSK)
                {
                    formatln("will use K%{dnsname}+%03i+%05i (KSK)", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));
                    ++ksk_count;
                }
                else if(key_flags == DNSKEY_FLAGS_ZSK)
                {
                    formatln("will use K%{dnsname}+%03i+%05i (ZSK)", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));
                    ++zsk_count;
                }
                /*
                                dns_resource_record_t rr;
                                dnskey_init_dns_resource_record(key, g_yadifa_zonesign_settings.dnskey_ttl, &rr); //
                   note: static allocation zdb_resource_record_data_t *dnskey;

                                dnskey = zdb_resource_record_data_new_instance_copy(rr.rdata_size, rr.rdata); // this
                   bit could be optimised by avoiding one memcopy

                                if(zdb_resource_record_sets_insert_record_checked(&zone->apex->resource_record_set,
                   TYPE_DNSKEY, g_yadifa_zonesign_settings.dnskey_ttl, dnskey))
                                {
                                    formatln("added K%{dnsname}+%03u+%05u key record (%s)", zone->origin,
                   dnskey_get_algorithm(key), dnskey_get_tag(key), ((dnskey_get_flags(key) ==
                   DNSKEY_FLAGS_KSK)?"KSK":"ZSK")); remove_dnskey_rrsig = true;
                                }
                */
            }
            else
            {
                // unload the key
                formatln("ignoring K%{dnsname}+%03i+%05i (not published)", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));
                dnssec_keystore_remove_key(key);
            }
            dnskey_release(key);
        }
        /*
                if(remove_dnskey_rrsig)
                {
                    zonesign_remove_signatures_covering_type(&zone->apex->resource_record_set, TYPE_DNSKEY);
                }
        */
    }

    return ((ksk_count > 0) ? 1 : 0) | ((zsk_count > 0) ? 2 : 0);
}

// for all keys in the zone, remove the ones not in the keystore, or load them if we are not using smart signing

static ya_result zonezign_remove_dnskey_not_in_keystore(zdb_zone_t *zone)
{
    ya_result                  ret = SUCCESS;
    zdb_resource_record_set_t *dnskey_rrset = (zdb_resource_record_set_t *)zdb_zone_get_dnskey_rrset(zone);

    struct rr_rdata_size_s
    {
        const uint8_t *rdata;
        uint16_t       rdata_size;
    };

    int                    rdata_and_size_count = 0;
    struct rr_rdata_size_s rdata_and_size[64];

    if(dnskey_rrset != NULL)
    {
        zdb_resource_record_set_const_iterator iter;
        zdb_resource_record_set_const_iterator_init(dnskey_rrset, &iter);
        while(zdb_resource_record_set_const_iterator_has_next(&iter))
        {
            const zdb_resource_record_data_t *dnskey_record = zdb_resource_record_set_const_iterator_next(&iter);

            dnskey_t                         *key;
            const uint8_t                    *rdata = zdb_resource_record_data_rdata_const(dnskey_record);
            uint16_t                          rdata_size = zdb_resource_record_data_rdata_size(dnskey_record);

            uint16_t                          flags = dnskey_get_flags_from_rdata(rdata);
            const char                       *flags_name;

            switch(flags)
            {
                case DNSKEY_FLAGS_KSK:
                    flags_name = "KSK";
                    break;
                case DNSKEY_FLAGS_ZSK:
                    flags_name = "ZSK";
                    break;
                default:
                    flags_name = "???";
                    break;
            }

            if(g_yadifa_zonesign_settings.smart_signing)
            {
                ret = dnskey_new_from_rdata(rdata, rdata_size, zone->origin, &key);

                if(FAIL(ret))
                {
                    formatln("%s key K%{dnsname}+%03i+%05i : failed to load public key: %r", flags_name, zone->origin, dnskey_get_algorithm_from_rdata(rdata), dnskey_get_tag_from_rdata(rdata, rdata_size), ret);
                    flushout();
                    return INVALID_STATE_ERROR;
                }

                if(!dnssec_keystore_contains_key(key))
                {
                    // remove the key from the zone
                    formatln("removing key K%{dnsname}+%03i+%05i from the zone", zone->origin, dnskey_get_algorithm(key), dnskey_get_tag(key));
                    flushout();

                    rdata_and_size[rdata_and_size_count].rdata = rdata;
                    rdata_and_size[rdata_and_size_count].rdata_size = rdata_size;
                    ++rdata_and_size_count;
                }
                else
                {
                    formatln("keeping key K%{dnsname}+%03i+%05i in the zone", zone->origin, dnskey_get_algorithm(key), dnskey_get_tag(key));
                    flushout();
                }
            }
            else
            {
                ret = dnssec_keystore_load_private_key_from_rdata(rdata, rdata_size, zone->origin, &key);

                if(FAIL(ret))
                {
                    formatln("%s key K%{dnsname}+%03i+%05i : failed to load private key: %r", flags_name, zone->origin, dnskey_get_algorithm_from_rdata(rdata), dnskey_get_tag_from_rdata(rdata, rdata_size), ret);
                    return ret;
                }
                else
                {
                    formatln("%s key K%{dnsname}+%03i+%05i : loaded", flags_name, dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));
                }
            }
        }
    }

    for(int i = 0; i < rdata_and_size_count; ++i)
    {
        if(!zdb_resource_record_set_delete_by_rdata(dnskey_rrset, rdata_and_size[i].rdata, rdata_and_size[i].rdata_size))
        {
            formatln("operation failed");
            return INVALID_STATE_ERROR;
        }
    }

    return ret;
}

static ya_result zonesign_setup_dnskey_records(zdb_zone_t *zone, time_t epoch)
{
    ya_result ret;

    // load smart_signing keys if required

    if(g_yadifa_zonesign_settings.smart_signing)
    {
        bool smart_keys_loaded = dnssec_keystore_acquire_key_from_fqdn_at_index(zone->origin, 0) != NULL;

        if(!smart_keys_loaded)
        {
            ret = zonesign_load_keys_from_dir(zone->origin, epoch);
            if(FAIL(ret))
            {
                return ret;
            }
        }
    }

    // for all keys in the zone, remove the ones not in the keystore, or load them if we are not using smart signing

    if((ret = zonezign_remove_dnskey_not_in_keystore(zone)) < 0)
    {
        exit(1);
    }

    if(g_yadifa_zonesign_settings.smart_signing)
    {
        // add the keys from the keystore to the zone

        for(int i = 0; i < 64; ++i)
        {
            dnskey_t *key;
            key = dnssec_keystore_acquire_key_from_fqdn_at_index(zone->origin, i);
            if(key == NULL)
            {
                break;
            }
            formatln("adding key K%{dnsname}+%03i+%05i to the zone", dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));
            zdb_zone_lock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
            zdb_zone_add_dnskey_from_key(zone, key);
            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
            dnskey_release(key);
        }
    }

    if(!dnssec_keystore_has_activated_ksk(zone->origin, epoch))
    {
        println("error: no active KSK private key available");
        return INVALID_STATE_ERROR;
    }

    if(!dnssec_keystore_has_activated_zsk(zone->origin, epoch))
    {
        println("error: no active ZSK private key available");
        return INVALID_STATE_ERROR;
    }

    return SUCCESS;
}

static ya_result zonesign_run()
{
    ya_result ret = SUCCESS;

    int64_t   signature_begin = 0;
    int64_t   signature_end = 0;
    int64_t   nsec3_signature_begin = 0;
    int64_t   nsec3_signature_end = 0;

    zdb_init();

    zdb_zone_path_set_provider(database_zone_path_provider);

    if(g_yadifa_zonesign_settings.input_file == NULL)
    {
        return COMMAND_ARGUMENT_EXPECTED;
    }

    bool auto_now = (config_value_get_source(ZONESIGN_SECTION_NAME, "now") <= CONFIG_SOURCE_DEFAULT);

    if(auto_now)
    {
        g_yadifa_zonesign_settings.now = ((timeus()) / ONE_SECOND_US) * ONE_SECOND_US;
    }
    else
    {
        int64_t t = timeus_from_smarttime_ex(g_yadifa_zonesign_settings.now_text, g_yadifa_zonesign_settings.now);

        if(t < 0)
        {
            formatln("error: could not parse '%s' as a date time: %r", g_yadifa_zonesign_settings.now_text, (ya_result)t);
            return (ya_result)t;
        }

        g_yadifa_zonesign_settings.now = (uint32_t)(t / ONE_SECOND_US);
    }

    bool auto_from_time = (config_value_get_source(ZONESIGN_SECTION_NAME, "from_time_text") <= CONFIG_SOURCE_DEFAULT);
    bool auto_to_time = (config_value_get_source(ZONESIGN_SECTION_NAME, "to_time_text") <= CONFIG_SOURCE_DEFAULT);
    bool auto_interval = (config_value_get_source(ZONESIGN_SECTION_NAME, "interval") == CONFIG_SOURCE_DEFAULT);

    if(auto_from_time)
    {
        g_yadifa_zonesign_settings.from_time = (g_yadifa_zonesign_settings.now / ONE_SECOND_US) - 86400;
    }
    else
    {
        int64_t t = timeus_from_smarttime_ex(g_yadifa_zonesign_settings.from_time_text, g_yadifa_zonesign_settings.now);

        if(t < 0)
        {
            formatln("error: could not parse '%s' as a date time: %r", g_yadifa_zonesign_settings.from_time_text, (ya_result)t);
            return (ya_result)t;
        }

        g_yadifa_zonesign_settings.from_time = (uint32_t)(t / ONE_SECOND_US);
    }

    if(auto_to_time)
    {
        g_yadifa_zonesign_settings.to_time = (g_yadifa_zonesign_settings.now / ONE_SECOND_US) + 86400 * 31;
    }
    else
    {
        int64_t t = timeus_from_smarttime_ex(g_yadifa_zonesign_settings.to_time_text, g_yadifa_zonesign_settings.now);

        if(t < 0)
        {
            formatln("error: could not parse '%s' as a date time: %r", g_yadifa_zonesign_settings.to_time_text, (ya_result)t);
            return (ya_result)t;
        }

        g_yadifa_zonesign_settings.to_time = (uint32_t)(t / ONE_SECOND_US);
    }

    if(g_yadifa_zonesign_settings.to_time < g_yadifa_zonesign_settings.from_time)
    {
        formatln("error: %T happens after %T", g_yadifa_zonesign_settings.from_time, g_yadifa_zonesign_settings.to_time);
        return INVALID_ARGUMENT_ERROR;
    }

    if(auto_interval)
    {
        g_yadifa_zonesign_settings.interval = (g_yadifa_zonesign_settings.to_time - g_yadifa_zonesign_settings.from_time) / 4;
    }

    bool auto_origin = (config_value_get_source(ZONESIGN_SECTION_NAME, "origin") <= CONFIG_SOURCE_DEFAULT);
    bool auto_serial = (config_value_get_source(ZONESIGN_SECTION_NAME, "new_serial") <= CONFIG_SOURCE_DEFAULT);
    bool auto_output_file = (config_value_get_source(ZONESIGN_SECTION_NAME, "output_file") == CONFIG_SOURCE_DEFAULT);

    if(auto_output_file)
    {
        ret = asnformat(&g_yadifa_zonesign_settings.output_file, PATH_MAX, "%s.signed", g_yadifa_zonesign_settings.input_file);
        if(FAIL(ret))
        {
            formatln(
                "error: automatically appending '.signed' to '%s' would result in a path too big for the limit of %i "
                "bytes.",
                g_yadifa_zonesign_settings.input_file,
                PATH_MAX);
            return INVALID_PATH;
        }
    }

    bool auto_nsec3_salt = (config_value_get_source(ZONESIGN_SECTION_NAME, "nsec3_salt_text") <= CONFIG_SOURCE_DEFAULT);
    bool auto_nsec3_iterations = (config_value_get_source(ZONESIGN_SECTION_NAME, "nsec3_iterations") == CONFIG_SOURCE_DEFAULT);
    bool auto_nsec3_optout = (config_value_get_source(ZONESIGN_SECTION_NAME, "nsec3_optout") == CONFIG_SOURCE_DEFAULT);
    bool auto_dnssec_mode = (config_value_get_source(ZONESIGN_SECTION_NAME, "dnssec_mode") <= CONFIG_SOURCE_DEFAULT);
    bool auto_dnssec = false; // auto_dnssec_mode & auto_nsec3_salt & auto_nsec3_iterations & auto_nsec3_optout;
    bool required_nsec3 = (!auto_nsec3_salt | !auto_nsec3_iterations | !auto_nsec3_optout);

    if(auto_dnssec_mode)
    {
        if(required_nsec3)
        {
            g_yadifa_zonesign_settings.dnssec_mode = g_yadifa_zonesign_settings.nsec3_optout ? ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT : ZDB_ZONE_MAINTAIN_NSEC3;
        }
        else
        {
            g_yadifa_zonesign_settings.dnssec_mode = ZDB_ZONE_MAINTAIN_NSEC;
        }
    }
    else
    {
        if(!auto_nsec3_optout)
        {
            if((g_yadifa_zonesign_settings.dnssec_mode < ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT) && g_yadifa_zonesign_settings.nsec3_optout)
            {
                println("requested dnssec-mode is contradicting requested optout mode");
                return INVALID_ARGUMENT_ERROR;
            }
        }
    }

    if(g_yadifa_zonesign_settings.nsec3_salt_text != NULL)
    {
        int32_t nsec3_salt_text_size = strlen(g_yadifa_zonesign_settings.nsec3_salt_text);
        if(nsec3_salt_text_size > 255 * 2)
        {
            println("error: salt maximum size is 255 bytes");
            return INVALID_ARGUMENT_ERROR;
        }

        if(FAIL(ret = base16_decode(g_yadifa_zonesign_settings.nsec3_salt_text, nsec3_salt_text_size, &g_yadifa_zonesign_settings.nsec3_salt[0])))
        {
            println("error:  cannot decode salt hexadecimal string");
            return ret;
        }

        g_yadifa_zonesign_settings.nsec3_salt_size = ret;
    }
    else
    {
        g_yadifa_zonesign_settings.nsec3_salt_size = 0;
    }

    // int64_t timeus_from_smarttime_ex(const char *text, int64_t now)

    struct zdb_zone_load_parms parms;
    zone_reader_t              zr;
    zone_reader_t              fzr;
    zdb_zone_t                *zone;
    uint16_t                   flags = ZDB_ZONE_NO_MAINTENANCE; // could replay the journal too ...
    flags |= ZDB_ZONE_NOKEYSTOREUPDATE;
    if(g_yadifa_zonesign_settings.read_journal)
    {
        flags |= ZDB_ZONE_REPLAY_JOURNAL;
    }

    uint32_t cpu_count = sys_get_cpu_count();

    if(g_yadifa_zonesign_settings.workers == 0)
    {
        g_yadifa_zonesign_settings.workers = cpu_count;
    }
    else if(g_yadifa_zonesign_settings.workers > cpu_count)
    {
        g_yadifa_zonesign_settings.workers = cpu_count;
    }

    if(FAIL(ret = zone_reader_text_open(&fzr, g_yadifa_zonesign_settings.input_file)))
    {
        formatln("error: could not read '%s' zone file: %r", g_yadifa_zonesign_settings.input_file, ret);
        return ret;
    }

    nosec_zone_reader_init(&zr, &fzr);

    formatln("zone-file: %s", g_yadifa_zonesign_settings.input_file);
    formatln("output-file: %s", g_yadifa_zonesign_settings.output_file);
    formatln("keys-path: %s", g_yadifa_zonesign_settings.keys_path);
    formatln("sign-start: %T", g_yadifa_zonesign_settings.from_time);
    formatln("sign-end: %T", g_yadifa_zonesign_settings.to_time);
    formatln("jitter: %u seconds", g_yadifa_zonesign_settings.jitter);
    formatln("interval: %u seconds", g_yadifa_zonesign_settings.interval);
    formatln("workers: %i", g_yadifa_zonesign_settings.workers);

    if(auto_origin)
    {
        println("origin: auto");
    }
    else
    {
        formatln("origin: %{dnsname}", g_yadifa_zonesign_settings.origin);
    }

    if(auto_serial)
    {
        println("serial: unchanged");
    }
    else
    {
        formatln("serial: %u", g_yadifa_zonesign_settings.new_serial);
    }

    formatln("read-journal: %s", g_yadifa_zonesign_settings.read_journal ? "yes" : "no");
    if(auto_dnssec_mode)
    {
        if(required_nsec3)
        {
            println("dnssec-mode: nsec3");
        }
        else
        {
            println("dnssec-mode: auto");
        }
    }
    else
    {
        const char *dnssec_mode_name = "?";
        value_name_table_get_name_from_value(dnssec_enum, g_yadifa_zonesign_settings.dnssec_mode, &dnssec_mode_name);
        formatln("dnssec-mode: %s", dnssec_mode_name);
    }

    println("");
    flushout();

    rndctx = random_init_auto();

    dnssec_keystore_setpath(g_yadifa_zonesign_settings.keys_path);
    ptr_vector_t ksks = PTR_VECTOR_EMPTY;
    ptr_vector_t zsks = PTR_VECTOR_EMPTY;

    time_t       epoch = g_yadifa_zonesign_settings.now / ONE_SECOND_US;

    int          keystore_count = 0;

    // if smart signing, look for the keys

    if(g_yadifa_zonesign_settings.smart_signing && g_yadifa_zonesign_settings.origin != NULL)
    {
        ret = zonesign_load_keys_from_dir(g_yadifa_zonesign_settings.origin, epoch);
        if(FAIL(ret))
        {
            formatln("failed to load smart keys: %r", ret);
            return ret;
        }
        if(ret != 3)
        {
            formatln("requires a KSK and a ZSK");
            return INVALID_STATE_ERROR;
        }
        for(int i = 0; i < 64; ++i)
        {
            dnskey_t *key = dnssec_keystore_acquire_key_from_fqdn_at_index(g_yadifa_zonesign_settings.origin, i);
            if(key == NULL)
            {
                break;
            }
            dnskey_release(key);
            ++keystore_count;
        }
    }

    println("loading zone file");
    zdb_zone_load_parms_init(&parms, &zr, g_yadifa_zonesign_settings.origin, flags);
    if(FAIL(ret = zdb_zone_load_ex(&parms)))
    {
        formatln("failed to load zone file: %r", ret);
        return ret;
    }

    for(int i = keystore_count; i < 64; ++i)
    {
        dnskey_t *key = dnssec_keystore_acquire_key_from_fqdn_at_index(g_yadifa_zonesign_settings.origin, i);
        if(key == NULL)
        {
            break;
        }
        dnssec_keystore_remove_key(key);
        dnskey_release(key);
    }

    zone = parms.out_zone;
    formatln("%{dnsname} zone file loaded", zone->origin);

    // if smart signing, remove keys not in the keystore
    ret = zonesign_setup_dnskey_records(zone, epoch);

    if(FAIL(ret))
    {
        formatln("failed to setup a DNSKEY records configuration: %r", ret);
        return ret;
    }

    // put the private keys in the relevant collection

    for(int i = 0; i < 64; ++i)
    {
        dnskey_t *key = dnssec_keystore_acquire_key_from_fqdn_at_index(zone->origin, i);
        if(key == NULL)
        {
            break;
        }
        if(!dnskey_is_private(key))
        {
            dnskey_release(key);
            continue;
        }
        if(dnskey_get_flags(key) == DNSKEY_FLAGS_KSK)
        {
            ptr_vector_append(&ksks, key);
        }
        else if(dnskey_get_flags(key) == DNSKEY_FLAGS_ZSK)
        {
            ptr_vector_append(&zsks, key);
        }
    }

    if(!auto_serial)
    {
        // update the serial value
        zdb_resource_record_data_t *soa = zdb_resource_record_sets_find_soa(&zone->apex->resource_record_set);
        rr_soa_set_serial(zdb_resource_record_data_rdata(soa), zdb_resource_record_data_rdata_size(soa), g_yadifa_zonesign_settings.new_serial);

        // remove RRSIGs over the SOA
        zonesign_remove_signatures_covering_type(&zone->apex->resource_record_set, TYPE_SOA);
        formatln("serial value set to %u", g_yadifa_zonesign_settings.new_serial);
    }

    uint16_t mode = zone->apex->_flags & ZDB_RR_LABEL_DNSSEC_MASK;
    char    *zone_dnssec_mode;

    switch(mode)
    {
        case 0:
            formatln("zone doesn't appear to be DNSSEC");
            zone_dnssec_mode = "none";
            zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC);
            g_yadifa_zonesign_settings.dnssec_mode = ZDB_ZONE_MAINTAIN_NSEC;
            break;
        case ZDB_RR_LABEL_NSEC:
            formatln("zone appears to be NSEC");
            zone_dnssec_mode = "nsec";
            zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC);
            g_yadifa_zonesign_settings.dnssec_mode = ZDB_ZONE_MAINTAIN_NSEC;
            break;
        case ZDB_RR_LABEL_NSEC3:
            formatln("zone appears to be NSEC3");
            zone_dnssec_mode = "nsec3";
            zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3);
            g_yadifa_zonesign_settings.dnssec_mode = ZDB_ZONE_MAINTAIN_NSEC3;
            break;
        case ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT:
            formatln("zone appears to be NSEC3 optout");

            zone_dnssec_mode = "nsec3 optout";
            zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT);
            g_yadifa_zonesign_settings.dnssec_mode = ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT;
            break;
        default:
            zone_dnssec_mode = "???";
            formatln("zone has an unexpected DNSSEC state");
            break;
    }

    if(auto_dnssec)
    {
        // automatic, an unsigned zone will be signed as nsec
        formatln("detected %s dnssec-mode will be used", zone_dnssec_mode);

        if(mode == ZDB_RR_LABEL_NSEC)
        {
            zdb_zone_lock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
            nsec_update_zone(zone, false);
            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
        }

        ret = zdb_zone_sign(zone);
    }
    else
    {
        ret = ERROR;

        const char *dnssec_mode_name = "?";
        // zone_set_maintain_mode(zone, g_yadifa_zonesign_settings.dnssec_mode);
        g_yadifa_zonesign_settings.nsec3_optout = (g_yadifa_zonesign_settings.dnssec_mode == ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT);
        value_name_table_get_name_from_value(dnssec_enum, g_yadifa_zonesign_settings.dnssec_mode, &dnssec_mode_name);
        formatln("%s mode will be used", dnssec_mode_name);

        bool optout = g_yadifa_zonesign_settings.nsec3_optout;
        // the update assumes its previous state was correct so it will ignore incorrect records
        // nsec3_zone_update_chain0_links(zone);

        bool nsec3_chains_must_be_deleted = g_yadifa_zonesign_settings.dnssec_mode < ZDB_ZONE_MAINTAIN_NSEC3;

        if(!nsec3_chains_must_be_deleted)
        {
            if((g_yadifa_zonesign_settings.dnssec_mode >= ZDB_ZONE_MAINTAIN_NSEC3) && (mode >= ZDB_RR_LABEL_NSEC3))
            {
                bool one_match = false;
                for(nsec3_zone_t *n3 = zone->nsec.nsec3; n3 != NULL; n3 = n3->next)
                {
                    if(!auto_nsec3_salt)
                    {
                        if(!((g_yadifa_zonesign_settings.nsec3_salt_size == NSEC3PARAM_RDATA_SALT_LEN(n3->rdata)) &&
                             (memcmp(g_yadifa_zonesign_settings.nsec3_salt, NSEC3PARAM_RDATA_SALT(n3->rdata), g_yadifa_zonesign_settings.nsec3_salt_size) == 0)))
                        {
                            continue;
                        }
                    }

                    if(!auto_nsec3_iterations)
                    {
                        if(g_yadifa_zonesign_settings.nsec3_iterations != NSEC3PARAM_RDATA_ITERATIONS(n3->rdata))
                        {
                            continue;
                        }
                    }

                    one_match = true;
                    break;
                }

                if(!one_match)
                {
                    nsec3_chains_must_be_deleted = true;
                }
            }
        }

        if(nsec3_chains_must_be_deleted)
        {
            // remove all current NSEC3 chains
            zdb_resource_record_sets_delete_type(&zone->apex->resource_record_set, TYPE_NSEC3PARAM);
            nsec3_destroy_zone(zone);
        }

        if(!(auto_nsec3_salt || auto_nsec3_iterations))
        {
            uint8_t nsec3param_rdata[NSEC3PARAM_RDATA_SIZE_FROM_SALT(255)];
            nsec3param_rdata[0] = NSEC3_DIGEST_ALGORITHM_SHA1;
            nsec3param_rdata[1] = g_yadifa_zonesign_settings.nsec3_optout ? 1 : 0;
            SET_U16_AT(nsec3param_rdata[2], htons(g_yadifa_zonesign_settings.nsec3_iterations));
            nsec3param_rdata[4] = g_yadifa_zonesign_settings.nsec3_salt_size;
            memcpy(&nsec3param_rdata[5], g_yadifa_zonesign_settings.nsec3_salt, g_yadifa_zonesign_settings.nsec3_salt_size);
            nsec3_zone_add_from_rdata(zone, NSEC3PARAM_RDATA_SIZE_FROM_SALT(g_yadifa_zonesign_settings.nsec3_salt_size), nsec3param_rdata);

            zdb_resource_record_data_t *nsec3param = zdb_resource_record_data_new_instance_copy(NSEC3PARAM_RDATA_SIZE_FROM_SALT(g_yadifa_zonesign_settings.nsec3_salt_size),
                                                                                                nsec3param_rdata); // this bit could be optimised by avoiding one memcopy

            zdb_resource_record_sets_insert_record(&zone->apex->resource_record_set, TYPE_NSEC3PARAM, 0, nsec3param); // TTL = 0
            zone_set_maintain_mode(zone, g_yadifa_zonesign_settings.nsec3_optout ? ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT : ZDB_ZONE_MAINTAIN_NSEC3);
        }

        if(zone_get_maintain_mode(zone) == ZDB_ZONE_MAINTAIN_NSEC)
        {
            zdb_zone_lock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
            nsec_update_zone(zone, false);
            zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
        }

        flushout();

        signature_begin = timeus();
        formatln("signatures update: %llT (%lli)", signature_begin, signature_begin);

        ret = zonesign_update_signatures(zone, &ksks, &zsks, g_yadifa_zonesign_settings.workers);

        if(FAIL(ret))
        {
            formatln("failed to update signatures: %r", ret);
            goto zonesign_run_exit;
        }

        signature_end = timeus();
        formatln("signatures update ended: %llT (%lli)", signature_end, signature_end);

        if(zone_get_maintain_mode(zone) >= ZDB_ZONE_MAINTAIN_NSEC3)
        {
            nsec3_signature_begin = timeus();
            formatln("NSEC3 signatures update: %llT (%lli)", nsec3_signature_begin, nsec3_signature_begin);
            ret = zonesign_update_nsec3_chain(zone, &zsks, optout);
            nsec3_signature_end = timeus();
            formatln("NSEC3 signatures update ended: %llT (%lli)", nsec3_signature_end, nsec3_signature_end);

            nsec3_zone_update_chain0_links(zone);

            if(FAIL(ret))
            {
                formatln("failed to update nsec3 chains: %r", ret);
                goto zonesign_run_exit;
            }
        }

        // ret = zdb_zone_sign(zone);
    }

    formatln("zone sign returned: %r", ret); // @note absurd maybe not initialized
    formatln("zone sign did %li signatures", total_signatures_count);

    double signature_time_total = (signature_end - signature_begin) + (nsec3_signature_end - nsec3_signature_begin);
    signature_time_total /= 1000000.0;

    formatln("zone sign took %f seconds", signature_time_total);
    formatln("zone sign signature rate: %f signatures/s", total_signatures_count / signature_time_total);

    flushout();

    println("storing zone file");
    zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    ret = zdb_zone_write_text_file(zone, g_yadifa_zonesign_settings.output_file, 0);
    zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
    if(ISOK(ret))
    {
        println("zone file stored");
    }
    else
    {
        formatln("failed to store zone file: %r", ret);
    }

zonesign_run_exit:
    zdb_zone_load_parms_finalize(&parms);
    zone_reader_close(&zr);

    return ret;
}

// ********************************************************************************
// ***** module virtual table
// ********************************************************************************

const module_s zonesign_program = {
    module_default_init,               // module initializer
    module_default_finalize,           // module finalizer
    zonesign_config_register,          // module register
    module_default_setup,              // module setup
    zonesign_run,                      // module run
    module_default_cmdline_help_print, //

    yadifa_cmdline, // module command line struct
    NULL,           // module command line callback
    NULL,           // module filter arguments

    "zone signer",                  // module public name
    "yzonesign",                    // module command (name as executable match)
    "zonesign",                     // module parameter (name as first parameter)
    /*zonesign_cmdline_help*/ NULL, // module text to be printed upon help request
    ".yadifa.rc"                    // module rc file (ie: ".module.rc"
};
