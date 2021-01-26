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

/** @defgroup yadifa
 *  @ingroup ###
 *  @brief
 */

#define ZONESIGN_C_ 1

/** @note: here we define the variable that is holding the default logger handle for the current source file
 *         Such a handle should NEVER been set in an include file.
 */

#include "client-config.h"

#include <sys/time.h>
#include <unistd.h>
#include <strings.h>

#include "common-config.h"
#include "common.h"
#include "module.h"
#include "module/zonesign.h"

#include <dnscore/cmdline.h>
#include <dnscore/config-cmdline.h>
#include <dnscore/config_settings.h>
#include <dnscore/logger.h>
#include <dnscore/logger_handle.h>
#include <dnscore/output_stream.h>  // needed because of an issue in cmdline
#include <dnscore/file_input_stream.h>
#include <dnsdb/zdb_zone_load.h>
#include <dnscore/zone_reader_text.h>
#include <dnsdb/zdb_zone_write.h>
#include <dnsdb/zdb.h>
#include <dnsdb/zdb-zone-path-provider.h>
#include <dnsdb/zdb-zone-maintenance.h>
#include <dnsdb/dnssec-keystore.h>
#include <dnsdb/zdb_zone_label_iterator.h>
#include <dnscore/dnskey-signature.h>
#include <dnscore/random.h>
#include <dnsdb/zdb-packed-ttlrdata.h>
#include <dnscore/base64.h>
#include <dnscore/base16.h>

/*----------------------------------------------------------------------------*/
#pragma mark DEFINES

#define ZONESIGN_SECTION_NAME "yadifa-zonesign"

/*----------------------------------------------------------------------------*/
#pragma mark GLOBAL VARIABLES


extern logger_handle *g_yadifa_logger;
#define MODULE_MSG_HANDLE g_yadifa_logger

// ********************************************************************************
// ***** module settings
// ********************************************************************************

static yadifa_zonesign_settings_s g_yadifa_zonesign_settings;

static random_ctx rndctx = NULL;

static value_name_table dnssec_enum[]=
{
    {ZDB_ZONE_MAINTAIN_NSEC        , "nsec"        },
    {ZDB_ZONE_MAINTAIN_NSEC3       , "nsec3"       },
    {ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT, "nsec3-optout"},
    {0, NULL}
};

#define KEYS_PATH_DEFAULT LOCALSTATEDIR "/zones/keys/"
#define SIGN_FROM_DEFAULT "-1d"
#define SIGN_TO_DEFAULT "+31d"

#define CONFIG_TYPE yadifa_zonesign_settings_s

CONFIG_BEGIN(yadifa_zonesign_settings_desc)
CONFIG_PATH(keys_path, KEYS_PATH_DEFAULT)
CONFIG_FILE(input_file, NULL)
CONFIG_FILE(journal_file, NULL)
CONFIG_FILE(output_file, NULL)
CONFIG_FQDN(origin, NULL)
CONFIG_STRING(from_time_text, SIGN_FROM_DEFAULT)
CONFIG_STRING(to_time_text, SIGN_TO_DEFAULT)
CONFIG_STRING(now_text, "now")
CONFIG_STRING(nsec3_salt_text, NULL)
CONFIG_U32_RANGE(interval, "0", 0, MAX_S32)
CONFIG_U32_RANGE(jitter, "0", 0, MAX_S32)
CONFIG_U32_RANGE(dnskey_ttl, "86400", 0, MAX_S32)
CONFIG_U32(new_serial, "0")
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

static ya_result
zonesign_cmdline_filter_callback(const struct cmdline_desc_s *desc, const char *arg_name, void *callback_owned)
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
CMDLINE_OPT("keys-path", 'K', "keys_path" )
CMDLINE_HELP("<path>", "directory to find key files (default: " KEYS_PATH_DEFAULT ")")
CMDLINE_OPT("sign-start", 's', "from_time_text")
CMDLINE_HELP("<time>", "sets the signature start time (default: " SIGN_FROM_DEFAULT ")")
CMDLINE_IMSG("", "    can be: now, yesterday, tomorrow")
CMDLINE_IMSG("", "    can be: YYYYMMDDHHmmss for year month day 24h-hour minutes seconds")
CMDLINE_IMSG("", "    can be: +integer[units] | -integer[units] where units can be years, months, days, hours, seconds or their first letters")
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
CMDLINE_SECTION(ZONESIGN_SECTION_NAME)  // CMDLINE_VERSION_HELP changes the section
CMDLINE_BLANK()
CMDLINE_END(yadifa_cmdline)

// ********************************************************************************
// ***** module register
// ********************************************************************************

static int
zonesign_config_register(int priority)
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

static ya_result
database_zone_path_provider(const u8* domain_fqdn, char *path_buffer, u32 path_buffer_size, u32 flags)
{
    (void)domain_fqdn;
    ya_result ret = ZDB_ERROR_ZONE_NOT_IN_DATABASE;

    switch(flags & ~ZDB_ZONE_PATH_PROVIDER_MKDIR)
    {
        case ZDB_ZONE_PATH_PROVIDER_ZONE_PATH:
        {
            ret = file_get_absolute_path(g_yadifa_zonesign_settings.input_file, path_buffer, path_buffer_size);
            while((--ret > 0) && path_buffer[ret] != '/');
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

static void
zonesign_nsec3_flags_and_or(nsec3_zone* n3, u8 mask_and, u8 mask_or)
{
    nsec3_iterator iter;
    nsec3_iterator_init(&n3->items, &iter);

    while(nsec3_iterator_hasnext(&iter))
    {
        nsec3_zone_item *item = nsec3_iterator_next_node(&iter);
        item->flags &= mask_and;
        item->flags |= mask_or;
    }
}

static inline void bitarray_set(u8 *bytes, u32 index, u8 value)
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

static inline u8 bitarray_get(u8 *bytes, u32 index)
{
    return (bytes[index >> 3] >> (index & 7)) & 1;
}

static void
zonesign_signature_from_to_get(s32 *from_epochp, s32 *to_epochp)
{
    s32 from_epoch = g_yadifa_zonesign_settings.from_time;
    s32 to_epoch = g_yadifa_zonesign_settings.to_time;
    if(g_yadifa_zonesign_settings.jitter > 0)
    {
        s32 r = random_next(rndctx);
        to_epoch += r % g_yadifa_zonesign_settings.jitter;
    }

    *from_epochp = from_epoch;
    *to_epochp = to_epoch;
}

static bool
zonesign_signature_should_be_replaced(s32 to_epoch)
{
    return to_epoch < MAX((s32)(g_yadifa_zonesign_settings.to_time - g_yadifa_zonesign_settings.interval),0);
}

static ya_result
zonesign_nsec3_chain_update(zdb_zone *zone, nsec3_zone* n3, ptr_vector *zsks, bool opt_out)
{
    static const u8 NSEC3_FLAGS_MARKED_UNUSED = 0x80;
    static const u8 NSEC3_FLAGS_MARKED_MODIFIED = 0x40;
    static const u8 NSEC3_FLAGS_MARKED_DELETED = 0x20;
    static const u8 NSEC3_FLAGS_MARKED_OPTOUT = 0x01;
    nsec3_load_is_label_covered_function *is_covered;
    nsec3_hash_function *hash_function;
    u8 *nsec3_rdata;
    u8 *loaded_nsec3_rdata;
    u8 *salt;
    s32 min_ttl = zone->min_ttl;
    ya_result ret = SUCCESS;
    u16 hash_iterations;
    u16 nsec3param_rdata_size;
    u8 salt_len;
    u8 digest_len;
    u8 optout_byte;
    zdb_zone_label_iterator iter;
    //btree_iterator type_iter;
    type_bit_maps_context type_bitmap;
    u8 digest[64];
    u8 fqdn[256];

    MALLOC_OBJECT_ARRAY_OR_DIE(nsec3_rdata, u8, 65536 * 2, GENERIC_TAG);
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
    nsec3param_rdata_size = NSEC3PARAM_MINIMUM_LENGTH + salt_len;

    bool nsec3_chain_is_new = n3->items == NULL;

    zdb_zone_label_iterator_init(&iter, zone);
    while(zdb_zone_label_iterator_hasnext(&iter))
    {
        u32 fqdn_len = zdb_zone_label_iterator_nextname(&iter, fqdn);
        zdb_rr_label *label = zdb_zone_label_iterator_next(&iter);

        if(!is_covered(label))
        {
            continue;
        }

        hash_function(
            fqdn,
            fqdn_len,
            salt,
            salt_len,
            hash_iterations,
            &digest[1],
            FALSE);

        // u16 bitmap_size = zdb_record_bitmap_type_init(&label->resource_record_set, &type_bitmap);

        u16 bitmap_size;
        bitmap_size = zdb_rr_label_bitmap_type_init(label, &type_bitmap);
        u16 nsec3_rdata_size_pre_bitmap = nsec3param_rdata_size + 1 + digest_len;
        u16 nsec3_rdata_size = nsec3_rdata_size_pre_bitmap + bitmap_size;

        memcpy(nsec3_rdata, n3->rdata, nsec3param_rdata_size);
        nsec3_rdata[1] = optout_byte;
        nsec3_rdata[nsec3param_rdata_size] = SHA_DIGEST_LENGTH;
        u8 *bitmap_bytes = &nsec3_rdata[nsec3param_rdata_size + 1 + digest_len];
        type_bit_maps_write(&type_bitmap, bitmap_bytes);

        // find the record in the chain

        if(nsec3_chain_is_new)
        {
            nsec3_node *item = nsec3_insert(&n3->items, digest);
            item->flags = NSEC3_FLAGS_MARKED_MODIFIED | optout_byte;
            nsec3_zone_item_update_bitmap(item, nsec3_rdata, nsec3_rdata_size);
            item->rrsig = NULL;

            if(g_yadifa_zonesign_settings.verbose >= 2)
            {
                nsec3_node *prev_item;

                if((prev_item = nsec3_find_interval_prev_mod(&n3->items, digest)) == NULL)
                {
                    prev_item = item;
                }

                nsec3_node *item_next = nsec3_node_mod_next(prev_item);
                memcpy(&nsec3_rdata[nsec3param_rdata_size], item_next->digest, NSEC3_NODE_DIGEST_SIZE(item_next) + 1);
                rdata_desc zone_rdata_desc = { TYPE_NSEC3, nsec3_rdata_size, nsec3_rdata };
                formatln("%{dnsname} add %{digest32h} NSEC3 %{rdatadesc}", fqdn, digest, &zone_rdata_desc);
                flushout();
            }
        }
        else
        {
            nsec3_node *item = nsec3_find(&n3->items, digest);
            if(item == NULL) // the expected record doesn't exist
            {
                // create it
                // it's predecessor's signature must be marked as next-changed

                if(g_yadifa_zonesign_settings.verbose >= 1)
                {
                    formatln("%{dnsname} covering NSEC3 record %{digest32h} missing", fqdn, digest);
                }

                nsec3_node *prev_item;

                if((prev_item = nsec3_find_interval_prev_mod(&n3->items, digest)) != NULL)
                {
                    prev_item->flags |= NSEC3_FLAGS_MARKED_MODIFIED;
                    nsec3_zone_item_rrsig_delete_all(prev_item);
                    if(g_yadifa_zonesign_settings.verbose >= 1)
                    {
                        formatln("%{dnsname} previous NSEC3 record %{digest32h} marked as modified", fqdn, prev_item->digest);

                        if(g_yadifa_zonesign_settings.verbose >= 2)
                        {
                            nsec3_node *item_next = nsec3_node_mod_next(prev_item);
                            memcpy(&nsec3_rdata[nsec3param_rdata_size], item_next->digest, NSEC3_NODE_DIGEST_SIZE(item_next) + 1);
                            rdata_desc zone_rdata_desc = { TYPE_NSEC3, nsec3_rdata_size, nsec3_rdata };
                            formatln("%{dnsname} add %{digest32h} NSEC3 %{rdatadesc}", fqdn, digest, &zone_rdata_desc);
                            flushout();
                        }
                    }
                }

                item = nsec3_insert(&n3->items, digest);
                item->flags = NSEC3_FLAGS_MARKED_MODIFIED | optout_byte;
                nsec3_zone_item_update_bitmap(item, nsec3_rdata, nsec3_rdata_size);
                item->rrsig = NULL;
            }
            else // the record exists
            {
                item->flags &= ~NSEC3_FLAGS_MARKED_UNUSED;
                item->flags &= optout_byte | ~NSEC3_FLAGS_MARKED_OPTOUT;

                // check it's a full match
                if(
                    ((item->flags & NSEC3_FLAGS_MARKED_OPTOUT) == optout_byte) &&
                    (item->type_bit_maps_size == bitmap_size) &&
                    (memcmp(item->type_bit_maps, bitmap_bytes, bitmap_size) == 0)
                )
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
                            u16 loaded_nsec3_rdata_size = nsec3_zone_item_to_rdata(n3, item, loaded_nsec3_rdata, 65535);
                            nsec3_node *item_next = nsec3_node_mod_next(item);
                            memcpy(&nsec3_rdata[nsec3param_rdata_size], item_next->digest, NSEC3_NODE_DIGEST_SIZE(item_next) + 1);
                            rdata_desc loaded_rdata_desc = { TYPE_NSEC3, loaded_nsec3_rdata_size, loaded_nsec3_rdata };
                            rdata_desc zone_rdata_desc = { TYPE_NSEC3, nsec3_rdata_size, nsec3_rdata };

                            formatln("%{dnsname} del %{digest32h} NSEC3 %{rdatadesc}", fqdn, digest, &loaded_rdata_desc);
                            flushout();
                            formatln("%{dnsname} add %{digest32h} NSEC3 %{rdatadesc}", fqdn, digest, &zone_rdata_desc);
                            flushout();
                        }
                    }

                    item->flags |= NSEC3_FLAGS_MARKED_MODIFIED | optout_byte;
                    if(item->type_bit_maps_size != bitmap_size)
                    {
                        ZFREE_ARRAY(item->type_bit_maps, item->type_bit_maps_size);
                        ZALLOC_OBJECT_ARRAY_OR_DIE(item->type_bit_maps, u8, bitmap_size, NSEC3_TYPEBITMAPS_TAG);
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
        ptr_vector nsec3_items_to_delete;
        ptr_vector_init_empty(&nsec3_items_to_delete);
        nsec3_iterator iter;
        nsec3_iterator_init(&n3->items, &iter);

        while(nsec3_iterator_hasnext(&iter))
        {
            nsec3_zone_item *item = nsec3_iterator_next_node(&iter);
            if((item->flags & NSEC3_FLAGS_MARKED_UNUSED) != 0)
            {
                // remove the node

                if(g_yadifa_zonesign_settings.verbose >= 2)
                {
                    u16 loaded_nsec3_rdata_size = nsec3_zone_item_to_rdata(n3, item, loaded_nsec3_rdata, 65535);
                    nsec3_node *item_next = nsec3_node_mod_next(item);
                    memcpy(&nsec3_rdata[nsec3param_rdata_size], item_next->digest, NSEC3_NODE_DIGEST_SIZE(item_next) + 1);
                    rdata_desc loaded_rdata_desc = { TYPE_NSEC3, loaded_nsec3_rdata_size, loaded_nsec3_rdata };

                    formatln("%{dnsname} del %{digest32h} NSEC3 %{rdatadesc}", zone->origin, item->digest, &loaded_rdata_desc);
                    flushout();
                }

                item->flags |= NSEC3_FLAGS_MARKED_DELETED;
                nsec3_zone_item_rrsig_delete_all(item);
                ptr_vector_append(&nsec3_items_to_delete, item);
                nsec3_node *prev_item = item;

                do
                {
                    prev_item = nsec3_node_mod_prev(prev_item);
                }
                while(((prev_item->flags & NSEC3_FLAGS_MARKED_DELETED) != 0) && prev_item != item);

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

        for(int i = 0; i <= ptr_vector_last_index(&nsec3_items_to_delete); ++i)
        {
            nsec3_node *item = (nsec3_node*)ptr_vector_get(&nsec3_items_to_delete, i);
            nsec3_item_remove_all_owners(item);
            nsec3_item_remove_all_star(item);
            nsec3_delete(&n3->items, item->digest);
        }

        type_bit_maps_finalize(&type_bitmap);
    }

    // sign what must

    {
        // use the list of signing keys for signing

        u8 *tags_bitmap = loaded_nsec3_rdata; // repurpose that 64KB buffer
        ZEROMEMORY(tags_bitmap, 65536);

        resource_record_view rrv;

        nsec3_item_resource_record_view_init(&rrv);
        nsec3_item_resource_record_view_origin_set(&rrv, zone->origin);
        nsec3_item_resource_record_view_nsec3_zone_set(&rrv, n3);
        nsec3_item_resource_record_view_ttl_set(&rrv, min_ttl);

        nsec3_iterator iter;
        nsec3_iterator_init(&n3->items, &iter);

        for(int i = 0; i <= ptr_vector_last_index(zsks); ++i)
        {
            dnssec_key *key = (dnssec_key*)ptr_vector_get(zsks, i);
            if(dnskey_is_private(key))
            {
                u16 tag = dnskey_get_tag(key);
                bitarray_set(tags_bitmap, tag, 1);
            }
        }

        while(nsec3_iterator_hasnext(&iter))
        {
            nsec3_zone_item *item = nsec3_iterator_next_node(&iter);
            item->flags &= NSEC3_FLAGS_MARKED_OPTOUT;
            zdb_packed_ttlrdata *rrsig_rrset = item->rrsig;
            while(rrsig_rrset != NULL)
            {
                // verify
                u8 *rrsig_rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig_rrset);
                u16 rrsig_rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig_rrset);

                u16 rrsig_tag = rrsig_get_key_tag_from_rdata(rrsig_rdata, rrsig_rdata_size);
                if(bitarray_get(tags_bitmap, rrsig_tag) == 1)
                {
                    // expected signing key

                    if(!zonesign_signature_should_be_replaced(rrsig_get_valid_until_from_rdata(rrsig_rdata, rrsig_rdata_size)))
                    {
                        if(g_yadifa_zonesign_settings.verbose >= 3)
                        {
                            rdata_desc rrsig_rdata_desc = { TYPE_RRSIG, rrsig_rdata_size, rrsig_rdata };
                            formatln("%{dnsname} GOOD %{digest32h} RRSIG %{rdatadesc}", zone->origin, item->digest, &rrsig_rdata_desc);
                            flushout();
                        }

                        // TODO: check for validity
                        bitarray_set(tags_bitmap, rrsig_tag, 0); // the signature is good

                        // redo
                        rrsig_rrset = rrsig_rrset->next;
                    }
                    else
                    {
                        if(g_yadifa_zonesign_settings.verbose >= 3)
                        {
                            rdata_desc rrsig_rdata_desc = { TYPE_RRSIG, rrsig_rdata_size, rrsig_rdata };
                            formatln("%{dnsname} UPDT %{digest32h} RRSIG %{rdatadesc}", zone->origin, item->digest, &rrsig_rdata_desc);
                            flushout();
                        }

                        struct zdb_ttlrdata rrsig_to_delete;
                        rrsig_to_delete.next = NULL;
                        rrsig_to_delete.ttl = rrsig_rrset->ttl;
                        rrsig_to_delete.rdata_size = rrsig_rdata_size;
                        memcpy(loaded_nsec3_rdata, rrsig_rdata, rrsig_rdata_size);
                        rrsig_to_delete.rdata_pointer = loaded_nsec3_rdata;
                        rrsig_rrset = rrsig_rrset->next;

                        nsec3_zone_item_rrsig_del(item, &rrsig_to_delete);
                    }
                }
                else
                {
                    // unexpected signing key

                    if(g_yadifa_zonesign_settings.verbose >= 3)
                    {
                        rdata_desc rrsig_rdata_desc = { TYPE_RRSIG, rrsig_rdata_size, rrsig_rdata };
                        formatln("%{dnsname} ???? %{digest32h} RRSIG %{rdatadesc}", zone->origin, item->digest, &rrsig_rdata_desc);
                        flushout();
                    }

                    struct zdb_ttlrdata rrsig_to_delete;
                    rrsig_to_delete.next = NULL;
                    rrsig_to_delete.ttl = rrsig_rrset->ttl;
                    rrsig_to_delete.rdata_size = rrsig_rdata_size;
                    memcpy(loaded_nsec3_rdata, rrsig_rdata, rrsig_rdata_size);
                    rrsig_to_delete.rdata_pointer = loaded_nsec3_rdata;
                    rrsig_rrset = rrsig_rrset->next;

                    nsec3_zone_item_rrsig_del(item, &rrsig_to_delete);
                }
            }

            for(int i = 0; i <= ptr_vector_last_index(zsks); ++i)
            {
                dnssec_key *key = (dnssec_key*)ptr_vector_get(zsks, i);
                u16 tag = dnskey_get_tag(key);

                if(!dnskey_is_private(key))
                {
                    continue;
                }

                if(bitarray_get(tags_bitmap, tag) == 1)
                {
                    dnssec_key *key = (dnssec_key*)ptr_vector_get(zsks, i);
                    // the bit wasn't cleared so the signature must be made

                    struct zdb_packed_ttlrdata *nsec3_rrsig = NULL;

                    dnskey_signature ds;
                    dnskey_signature_init(&ds);
                    ptr_vector rrset_dummy = {(void**)&item, 0, 1};

                    s32 from_epoch;
                    s32 to_epoch;

                    zonesign_signature_from_to_get(&from_epoch, &to_epoch);

                    dnskey_signature_set_validity(&ds, from_epoch, to_epoch);
                    dnskey_signature_set_view(&ds, &rrv);
                    dnskey_signature_set_rrset_reference(&ds, &rrset_dummy);
                    dnskey_signature_set_canonised(&ds, TRUE);
                    ya_result ret = dnskey_signature_sign(&ds, key, (void **) &nsec3_rrsig);
                    dnskey_signature_finalize(&ds);

                    if(ISOK(ret))
                    {
                        nsec3_rrsig->next = NULL;

                        if(g_yadifa_zonesign_settings.verbose >= 2)
                        {
                            rdata_desc rrsig_rdata_desc = { TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(nsec3_rrsig), ZDB_PACKEDRECORD_PTR_RDATAPTR(nsec3_rrsig) };
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
                else
                {
                    bitarray_set(tags_bitmap, tag, 1);
                }
            }
        }

        nsec3_item_resource_record_finalize(&rrv);
    }

    free(nsec3_rdata);

    return ret;
}

static ya_result
zonesign_update_nsec3_chain(zdb_zone *zone, ptr_vector *zsks, bool opt_out)
{
    ya_result ret;
    for(int chain_index = 0; ; ++chain_index)
    {
        nsec3_zone* n3 = zdb_zone_get_nsec3chain(zone, chain_index);
        if(n3 == NULL)
        {
            break;
        }

        if(FAIL(ret = zonesign_nsec3_chain_update(zone, n3, zsks, opt_out)))
        {
            break;
        }
    }

    return ret;
}

static ya_result
zonesign_update_signatures(zdb_zone *zone, ptr_vector *ksks, ptr_vector *zsks)
{
    ya_result ret = SUCCESS;
    ptr_vector rrset = PTR_VECTOR_EMPTY;
    nsec3_load_is_label_covered_function *is_covered;
    u8 *buffer;
    MALLOC_OBJECT_ARRAY_OR_DIE(buffer, u8, 8192 + 65536, GENERIC_TAG);
    u8* tags_bitmap = &buffer[0];
    u8* rdata_buffer = &buffer[8192];
    resource_record_view rrv;
    zdb_zone_label_iterator iter;
    btree_iterator type_iter;
    u8 fqdn[256];

    ZEROMEMORY(tags_bitmap, 8192);

    if(g_yadifa_zonesign_settings.dnssec_mode == ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT)
    {
        is_covered = nsec3_load_is_label_covered_optout;
    }
    else
    {
        is_covered = nsec3_load_is_label_covered; // NSEC too
    }

    zdb_packed_ttlrdata_resource_record_view_init(&rrv);
    zdb_packed_ttlrdata_resource_record_view_set_class(&rrv, CLASS_IN);

    zdb_zone_label_iterator_init(&iter, zone);
    while(zdb_zone_label_iterator_hasnext(&iter))
    {
        /*u32 fqdn_len = */zdb_zone_label_iterator_nextname(&iter, fqdn);
        zdb_rr_label *label = zdb_zone_label_iterator_next(&iter);

        bool delegation = ZDB_LABEL_ATORUNDERDELEGATION(label);
        zdb_packed_ttlrdata *rrsig_rrset = zdb_rr_label_get_rrset(label, TYPE_RRSIG);

        if(rrsig_rrset != NULL)
        {
            if(is_covered(label))
            {
                // remove expired or invalid signatures

                zdb_packed_ttlrdata *rrsig = rrsig_rrset;

                do
                {
                    u8 *rrsig_rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig);
                    u16 rrsig_rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig);

                    u16 tag = rrsig_get_key_tag_from_rdata(rrsig_rdata, rrsig_rdata_size);
                    u16 type_covered = rrsig_get_type_covered_from_rdata(rrsig_rdata, rrsig_rdata_size);

                    ptr_vector *keys = (type_covered != TYPE_DNSKEY)?zsks:ksks;
                    dnssec_key *signing_key = NULL;

                    for(int i = 0; i <= ptr_vector_last_index(keys); ++i)
                    {
                        dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, i);

                        if(dnskey_get_tag(key) == tag)
                        {
                            signing_key = key;
                        }
                    }

                    bool expect_signed = !delegation | (delegation && ((type_covered == TYPE_DS) || (type_covered == TYPE_NSEC)));

                    // if there is no such key or the signature is invalid

                    if(!expect_signed || (signing_key == NULL) || (dnskey_is_private(signing_key) && zonesign_signature_should_be_replaced(rrsig_get_valid_until_from_rdata(rrsig_rdata, rrsig_rdata_size))))
                    {
                        struct zdb_ttlrdata rrsig_to_delete;
                        rrsig_to_delete.next = NULL;
                        rrsig_to_delete.ttl = rrsig->ttl;
                        rrsig_to_delete.rdata_size = rrsig_rdata_size;
                        memcpy(rdata_buffer, rrsig_rdata, rrsig_rdata_size);
                        rrsig_to_delete.rdata_pointer = rdata_buffer;

                        rrsig = rrsig->next;

                        zdb_record_delete_exact(&label->resource_record_set, TYPE_RRSIG, &rrsig_to_delete);
                    }
                    else
                    {
                        rrsig = rrsig->next;
                    }
                }
                while(rrsig != NULL);

                rrsig_rrset = zdb_rr_label_get_rrset(label, TYPE_RRSIG);
            }
            else
            {
                // remove all signatures
                zdb_record_delete(&label->resource_record_set, TYPE_RRSIG);
            }
        }

        // there is no irrelevant signatures present

        if(is_covered(label))
        {
            zdb_packed_ttlrdata_resource_record_view_set_fqdn(&rrv, fqdn);

            {
                // if it's not a delegation or we have a DS or an NSEC, then we will have an RRSIG record
                bool expect_some_signature = !zdb_record_isempty(&label->resource_record_set) && (!delegation || (delegation && ((zdb_record_find(&label->resource_record_set, TYPE_DS) != NULL) || (zdb_record_find(&label->resource_record_set, TYPE_NSEC) != NULL))));

                if(expect_some_signature)
                {
                    if(zdb_record_find(&label->resource_record_set, TYPE_RRSIG) == NULL)
                    {
                        zdb_packed_ttlrdata **rrsigp = zdb_record_find_insert(&label->resource_record_set, TYPE_RRSIG);
                        *rrsigp = NULL;
                    }
                    btree_iterator_init(label->resource_record_set, &type_iter);
                    while(btree_iterator_hasnext(&type_iter))
                    {
                        btree_node* type_node = btree_iterator_next_node(&type_iter);

                        u16 rtype = (u16)type_node->hash;

                        zdb_packed_ttlrdata* rrset_sll = (zdb_packed_ttlrdata*)type_node->data;

                        if(rtype == TYPE_RRSIG)
                        {
                            continue;
                        }

                        s32 rttl = rrset_sll->ttl;

                        bool expect_signed = !delegation | (delegation && ((rtype == TYPE_DS) || (rtype == TYPE_NSEC)));

                        if(!expect_signed)
                        {
                            continue;
                        }

                        ptr_vector_clear(&rrset);
                        do
                        {
                            ptr_vector_append(&rrset, rrset_sll);

                            if(g_yadifa_zonesign_settings.verbose >= 2)
                            {
                                rdata_desc rrsig_rdata_desc = { rtype, ZDB_PACKEDRECORD_PTR_RDATASIZE(rrset_sll), ZDB_PACKEDRECORD_PTR_RDATAPTR(rrset_sll) };
                                formatln("%{dnsname} %{typerdatadesc}", fqdn, &rrsig_rdata_desc);
                            }

                            rrset_sll = rrset_sll->next;
                        }
                        while(rrset_sll != NULL);

                        zdb_packed_ttlrdata_resource_record_view_set_type(&rrv, rtype);
                        zdb_packed_ttlrdata_resource_record_view_set_ttl(&rrv, rttl);

                        ptr_vector *keys = (rtype != TYPE_DNSKEY)?zsks:ksks;

                        for(int i = 0; i <= ptr_vector_last_index(keys); ++i)
                        {
                            dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, i);
                            bitarray_set(tags_bitmap, dnskey_get_tag(key), 1);
                        }

                        zdb_packed_ttlrdata *rrsig = rrsig_rrset;
                        while(rrsig != NULL)
                        {
                            u8 *rrsig_rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig);
                            u16 rrsig_rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig);

                            u16 type_covered = rrsig_get_type_covered_from_rdata(rrsig_rdata, rrsig_rdata_size);

                            if(type_covered == rtype)
                            {
                                u16 tag = rrsig_get_key_tag_from_rdata(rrsig_rdata, rrsig_rdata_size);
                                bitarray_set(tags_bitmap, tag, 0);
                            }

                            rrsig = rrsig->next;
                        }

                        bool has_one_signature = FALSE;

                        for(int i = 0; i <= ptr_vector_last_index(keys); ++i)
                        {
                            dnssec_key *key = (dnssec_key*)ptr_vector_get(keys, i);
                            u16 tag = dnskey_get_tag(key);
                            if(bitarray_get(tags_bitmap, tag) == 1)
                            {
                                bitarray_set(tags_bitmap, tag, 0);

                                struct zdb_packed_ttlrdata *type_rrsig = NULL;

                                dnskey_signature ds;
                                dnskey_signature_init(&ds);

                                s32 from_epoch;
                                s32 to_epoch;

                                zonesign_signature_from_to_get(&from_epoch, &to_epoch);

                                dnskey_signature_set_validity(&ds, from_epoch, to_epoch);
                                dnskey_signature_set_view(&ds, &rrv);
                                dnskey_signature_set_rrset_reference(&ds, &rrset);
                                dnskey_signature_set_canonised(&ds, FALSE);
                                ya_result ret = dnskey_signature_sign(&ds, key, (void **) &type_rrsig);
                                dnskey_signature_finalize(&ds);

                                if(ISOK(ret))
                                {
                                    has_one_signature = TRUE;

                                    type_rrsig->next = NULL;
                                    zdb_record_insert(&label->resource_record_set, TYPE_RRSIG, type_rrsig);

                                    if(g_yadifa_zonesign_settings.verbose >= 1)
                                    {
                                        rdata_desc rrsig_rdata_desc = { TYPE_RRSIG, ZDB_PACKEDRECORD_PTR_RDATASIZE(type_rrsig), ZDB_PACKEDRECORD_PTR_RDATAPTR(type_rrsig) };
                                        formatln("%{dnsname} add  %{dnsname} RRSIG %{rdatadesc}", zone->origin, fqdn, &rrsig_rdata_desc);
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
                                has_one_signature = TRUE;
                            }
                        }

                        if(!has_one_signature)
                        {
                            formatln("error: could not sign %{dnsname} %{dnstype}", fqdn, &rtype);
                            ret = INVALID_STATE_ERROR;
                            goto zonesign_update_signatures_exit;
                        }
                    }
                }
                else
                {
                    // purge the signatures and skip
                    zdb_record_delete(&label->resource_record_set, TYPE_RRSIG);
                }
            }
        }
    }

zonesign_update_signatures_exit:

    free(buffer);
    zdb_packed_ttlrdata_resource_record_view_finalize(&rrv);
    ptr_vector_destroy(&rrset);

    return ret;
}

static void
zonesign_remove_signatures_covering_type(zdb_rr_collection *rrsets, u16 covered_type)
{
    zdb_packed_ttlrdata *rrsig = zdb_record_find(rrsets, TYPE_RRSIG);
    while(rrsig != NULL)
    {
        if(rrsig_get_type_covered_from_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig)) == covered_type)
        {
            zdb_ttlrdata rrsig_to_delete;
            rrsig_to_delete.next = NULL;
            rrsig_to_delete.ttl = rrsig->ttl;
            rrsig_to_delete.rdata_pointer = ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig);
            rrsig_to_delete.rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig);
            rrsig = rrsig->next;
            zdb_record_delete_self_exact(rrsets, TYPE_RRSIG, &rrsig_to_delete);
        }
        else
        {
            rrsig = rrsig->next;
        }
    }
}


static ya_result
zonesign_run()
{
    ya_result ret = SUCCESS;

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
        s64 t = timeus_from_smarttime_ex(g_yadifa_zonesign_settings.now_text, g_yadifa_zonesign_settings.now);

        if(t < 0)
        {
            formatln("error: could not parse '%s' as a date time: %r", g_yadifa_zonesign_settings.now_text);
            return (ya_result)t;
        }

        g_yadifa_zonesign_settings.now = (u32)(t / ONE_SECOND_US);
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
        s64 t = timeus_from_smarttime_ex(g_yadifa_zonesign_settings.from_time_text, g_yadifa_zonesign_settings.now);

        if(t < 0)
        {
            formatln("error: could not parse '%s' as a date time: %r", g_yadifa_zonesign_settings.from_time_text);
            return (ya_result)t;
        }

        g_yadifa_zonesign_settings.from_time = (u32)(t / ONE_SECOND_US);
    }

    if(auto_to_time)
    {
        g_yadifa_zonesign_settings.to_time = (g_yadifa_zonesign_settings.now / ONE_SECOND_US) + 86400 * 31;
    }
    else
    {
        s64 t = timeus_from_smarttime_ex(g_yadifa_zonesign_settings.to_time_text, g_yadifa_zonesign_settings.now);

        if(t < 0)
        {
            formatln("error: could not parse '%s' as a date time: %r", g_yadifa_zonesign_settings.to_time_text);
            return (ya_result)t;
        }

        g_yadifa_zonesign_settings.to_time = (u32)(t / ONE_SECOND_US);
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

    if(!auto_output_file)
    {
        ret = asnformat(&g_yadifa_zonesign_settings.output_file, PATH_MAX, "%s.signed", g_yadifa_zonesign_settings.input_file);
        if(FAIL(ret))
        {
            formatln("error: automatically appending '.signed' to '%s' would result in a path too big for the limit of %i bytes.", g_yadifa_zonesign_settings.input_file, PATH_MAX);
            return INVALID_PATH;
        }
    }

    bool auto_nsec3_salt = (config_value_get_source(ZONESIGN_SECTION_NAME, "nsec3_salt_text") <= CONFIG_SOURCE_DEFAULT);
    bool auto_nsec3_iterations = (config_value_get_source(ZONESIGN_SECTION_NAME, "nsec3_iterations") == CONFIG_SOURCE_DEFAULT);
    bool auto_nsec3_optout = (config_value_get_source(ZONESIGN_SECTION_NAME, "nsec3_optout") == CONFIG_SOURCE_DEFAULT);
    bool auto_dnssec_mode = (config_value_get_source(ZONESIGN_SECTION_NAME, "dnssec_mode") <= CONFIG_SOURCE_DEFAULT);
    bool auto_dnssec = auto_dnssec_mode & auto_nsec3_salt & auto_nsec3_iterations & auto_nsec3_optout;
    bool required_nsec3 = (!auto_nsec3_salt | !auto_nsec3_iterations | !auto_nsec3_optout);

    if(auto_dnssec_mode)
    {
        if(required_nsec3)
        {
            g_yadifa_zonesign_settings.dnssec_mode = g_yadifa_zonesign_settings.nsec3_optout?ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT:ZDB_ZONE_MAINTAIN_NSEC3;
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
        s32 nsec3_salt_text_size = strlen(g_yadifa_zonesign_settings.nsec3_salt_text);
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

    // s64 timeus_from_smarttime_ex(const char *text, s64 now)

    struct zdb_zone_load_parms parms;
    zone_reader zr;
    zdb_zone *zone;
    u16 flags = ZDB_ZONE_NO_MAINTENANCE; // could replay the journal too ...
    if(g_yadifa_zonesign_settings.read_journal)
    {
        flags |= ZDB_ZONE_REPLAY_JOURNAL;
    }

    if(FAIL(ret = zone_reader_text_open(g_yadifa_zonesign_settings.input_file, &zr)))
    {
        formatln("error: could not read '%s' zone file: %r", ret);
        return ret;
    }

    formatln("zone-file: %s", g_yadifa_zonesign_settings.input_file);
    formatln("output-file: %s", g_yadifa_zonesign_settings.output_file);
    formatln("keys-path: %s", g_yadifa_zonesign_settings.keys_path);
    formatln("sign-start: %T", g_yadifa_zonesign_settings.from_time);
    formatln("sign-end: %T", g_yadifa_zonesign_settings.to_time);
    formatln("jitter: %u seconds", g_yadifa_zonesign_settings.jitter);
    formatln("interval: %u seconds", g_yadifa_zonesign_settings.interval);

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

    formatln("read-journal: %s", g_yadifa_zonesign_settings.read_journal?"yes":"no");
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
    ptr_vector ksks = PTR_VECTOR_EMPTY;
    ptr_vector zsks = PTR_VECTOR_EMPTY;

    bool has_one_ksk = FALSE;
    bool has_one_zsk = FALSE;

    time_t epoch = g_yadifa_zonesign_settings.now / ONE_SECOND_US;

    println("loading zone file");
    zdb_zone_load_parms_init(&parms, &zr, g_yadifa_zonesign_settings.origin, flags);
    if(ISOK(ret = zdb_zone_load_ex(&parms)))
    {
        zone = parms.out_zone;

        formatln("%{dnsname} zone file loaded", zone->origin);

        if(g_yadifa_zonesign_settings.smart_signing)
        {
            dnssec_keystore_add_domain(zone->origin, g_yadifa_zonesign_settings.keys_path);

            if(FAIL(ret = dnssec_keystore_reload_domain(zone->origin)))
            {
                formatln("error: failed to load keys for domain %{dnsname}: %r", zone->origin, ret);
                return ret;
            }

            bool remove_dnskey_rrsig = FALSE;

            for(int i = 0; ; ++i)
            {
                dnssec_key *key = dnssec_keystore_acquire_key_from_fqdn_at_index(zone->origin, i);
                if(key == NULL)
                {
                    break;
                }

                if(dnskey_is_published(key, epoch))
                {
                    dns_resource_record rr;
                    dnskey_init_dns_resource_record(key, g_yadifa_zonesign_settings.dnskey_ttl, &rr);
                    zdb_packed_ttlrdata *dnskey;
                    ZDB_RECORD_ZALLOC(dnskey, g_yadifa_zonesign_settings.dnskey_ttl, rr.rdata_size, rr.rdata);
                    if(zdb_record_insert_checked(&zone->apex->resource_record_set, TYPE_DNSKEY, dnskey))
                    {
                        formatln("added K%{dnsname}+%03u+%05u key record (%s)", zone->origin, dnskey_get_algorithm(key), dnskey_get_tag(key), ((dnskey_get_flags(key) == DNSKEY_FLAGS_KSK)?"KSK":"ZSK"));
                        remove_dnskey_rrsig = TRUE;
                    }
                }
            }

            if(remove_dnskey_rrsig)
            {
                zonesign_remove_signatures_covering_type(&zone->apex->resource_record_set, TYPE_DNSKEY);
            }
        }

        const struct zdb_packed_ttlrdata *dnskey_rrset = zdb_zone_get_dnskey_rrset(zone);
        while(dnskey_rrset != NULL)
        {
            dnssec_key *key;
            const u8 *rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(dnskey_rrset);
            u16 rdata_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(dnskey_rrset);

            u16 flags = dnskey_get_flags_from_rdata(rdata);
            const char *flags_name;

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

            ret = dnssec_keystore_load_private_key_from_rdata(
                rdata,
                rdata_size,
                zone->origin, &key);

            if(FAIL(ret))
            {
                formatln("%s key K%{dnsname}+%03i+%05i : failed to load private key: %r", flags_name, zone->origin, dnskey_get_algorithm_from_rdata(rdata), dnskey_get_tag_from_rdata(rdata, rdata_size), ret);

                ret = dnssec_keystore_load_public_key_from_rdata(
                    rdata,
                    rdata_size,
                    zone->origin, &key);

                if(FAIL(ret))
                {
                    formatln("%s key K%{dnsname}+%03i+%05i : failed to load public key: %r", flags_name, zone->origin, dnskey_get_algorithm_from_rdata(rdata), dnskey_get_tag_from_rdata(rdata, rdata_size), ret);
                    return ret;
                }
            }
            else
            {
                formatln("%s key K%{dnsname}+%03i+%05i : loaded", flags_name, dnskey_get_domain(key), dnskey_get_algorithm(key), dnskey_get_tag(key));
            }

            if(dnskey_get_flags(key) == DNSKEY_FLAGS_KSK)
            {
                dnskey_acquire(key);
                ptr_vector_append(&ksks, key);
                has_one_ksk |= dnskey_is_private(key);
            }
            else if(dnskey_get_flags(key) == DNSKEY_FLAGS_ZSK)
            {
                dnskey_acquire(key);
                ptr_vector_append(&zsks, key);
                has_one_zsk |= dnskey_is_private(key);
            }
            else
            {
                // flags not supported
            }

            dnskey_rrset = dnskey_rrset->next;
        }

        if(!has_one_ksk)
        {
            bool signed_by_one_known_ksk = FALSE;

            zdb_packed_ttlrdata *rrsig = zdb_record_find(&zone->apex->resource_record_set, TYPE_RRSIG);
            while(rrsig != NULL)
            {
                if(rrsig_get_type_covered_from_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig)) == TYPE_DNSKEY)
                {
                    u16 tag = rrsig_get_key_tag_from_rdata(ZDB_PACKEDRECORD_PTR_RDATAPTR(rrsig), ZDB_PACKEDRECORD_PTR_RDATASIZE(rrsig));

                    for(int i = 0; i <= ptr_vector_last_index(&ksks); ++i)
                    {
                        if(dnskey_get_tag((dnssec_key*)ptr_vector_get(&ksks, i)) == tag)
                        {
                            signed_by_one_known_ksk = TRUE;
                            break;
                        }
                    }

                    if(signed_by_one_known_ksk)
                    {
                        break;
                    }
                }

                rrsig = rrsig->next;
            }

            if(signed_by_one_known_ksk)
            {
                println("warning: no KSK private key available, will try to keep the signatures");
            }
            else
            {
                println("error: no KSK private key available");
                return INVALID_STATE_ERROR;
            }
        }

        if(!has_one_zsk)
        {
            println("error: no ZSK private key available");
            return INVALID_STATE_ERROR;
        }

        if(!auto_serial)
        {
            // update the serial value

            zdb_packed_ttlrdata *soa = zdb_record_find(&zone->apex->resource_record_set, TYPE_SOA);
            rr_soa_set_serial(ZDB_PACKEDRECORD_PTR_RDATAPTR(soa), ZDB_PACKEDRECORD_PTR_RDATASIZE(soa), g_yadifa_zonesign_settings.new_serial);

            // remove RRSIGs over the SOA

            zonesign_remove_signatures_covering_type(&zone->apex->resource_record_set, TYPE_SOA);

            formatln("serial value set to %u", g_yadifa_zonesign_settings.new_serial);
        }

        u16 mode = zone->apex->_flags & ZDB_RR_LABEL_DNSSEC_MASK;
        char *zone_dnssec_mode;

        switch(mode)
        {
            case 0:
                formatln("zone doesn't appear to be DNSSEC");
                break;
            case ZDB_RR_LABEL_NSEC:
                formatln("zone appears to be NSEC");
                zone_dnssec_mode = "nsec";
                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC);
                break;
            case ZDB_RR_LABEL_NSEC3:
                formatln("zone appears to be NSEC3");
                zone_dnssec_mode = "nsec3";
                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3);
                break;
            case ZDB_RR_LABEL_NSEC3|ZDB_RR_LABEL_NSEC3_OPTOUT:
                formatln("zone appears to be NSEC3 optout");

                zone_dnssec_mode = "nsec3 optout";
                zone_set_maintain_mode(zone, ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT);
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
                nsec_update_zone(zone, FALSE);
                zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
            }

            ret = zdb_zone_sign(zone);
        }
        else
        {
            ret = ERROR;

            const char *dnssec_mode_name = "?";
            zone_set_maintain_mode(zone, g_yadifa_zonesign_settings.dnssec_mode);
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
                    bool one_match = FALSE;
                    for(nsec3_zone *n3 = zone->nsec.nsec3; n3 != NULL; n3 = n3->next)
                    {
                        if(!auto_nsec3_salt)
                        {
                            if(!((g_yadifa_zonesign_settings.nsec3_salt_size == NSEC3PARAM_RDATA_SALT_LEN(n3->rdata)) && (memcmp(g_yadifa_zonesign_settings.nsec3_salt, NSEC3PARAM_RDATA_SALT(n3->rdata), g_yadifa_zonesign_settings.nsec3_salt_size) == 0)) )
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

                        one_match = TRUE;
                        break;
                    }

                    if(!one_match)
                    {
                        nsec3_chains_must_be_deleted = TRUE;
                    }
                }
            }

            if(nsec3_chains_must_be_deleted)
            {
                // remove all current NSEC3 chains
                zdb_record_delete(&zone->apex->resource_record_set, TYPE_NSEC3PARAM);
                nsec3_destroy_zone(zone);
            }

            if(!(auto_nsec3_salt || auto_nsec3_iterations))
            {
                u8 nsec3param_rdata[NSEC3PARAM_RDATA_SIZE_FROM_SALT(255)];
                nsec3param_rdata[0] = NSEC3_DIGEST_ALGORITHM_SHA1;
                nsec3param_rdata[1] = g_yadifa_zonesign_settings.nsec3_optout?1:0;
                SET_U16_AT(nsec3param_rdata[2], htons(g_yadifa_zonesign_settings.nsec3_iterations));
                nsec3param_rdata[4] = g_yadifa_zonesign_settings.nsec3_salt_size;
                memcpy(&nsec3param_rdata[5], g_yadifa_zonesign_settings.nsec3_salt, g_yadifa_zonesign_settings.nsec3_salt_size);
                nsec3_zone_add_from_rdata(zone, NSEC3PARAM_RDATA_SIZE_FROM_SALT(g_yadifa_zonesign_settings.nsec3_salt_size), nsec3param_rdata);
                zdb_packed_ttlrdata *nsec3param;
                ZDB_RECORD_ZALLOC(nsec3param, 0, NSEC3PARAM_RDATA_SIZE_FROM_SALT(g_yadifa_zonesign_settings.nsec3_salt_size), nsec3param_rdata);
                zdb_record_insert(&zone->apex->resource_record_set, TYPE_NSEC3PARAM, nsec3param);
                zone_set_maintain_mode(zone, g_yadifa_zonesign_settings.nsec3_optout?ZDB_ZONE_MAINTAIN_NSEC3_OPTOUT:ZDB_ZONE_MAINTAIN_NSEC3);
            }

            if(g_yadifa_zonesign_settings.dnssec_mode == ZDB_ZONE_MAINTAIN_NSEC)
            {
                zdb_zone_lock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
                nsec_update_zone(zone, FALSE);
                zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_RRSIG_UPDATER);
            }

            flushout();

            ret = zonesign_update_signatures(zone, &ksks, &zsks);

            if(g_yadifa_zonesign_settings.dnssec_mode >= ZDB_ZONE_MAINTAIN_NSEC3)
            {
                ret = zonesign_update_nsec3_chain(zone, &zsks, optout);
                nsec3_zone_update_chain0_links(zone);
            }

            //ret = zdb_zone_sign(zone);
        }

        formatln("zone sign returned: %r", ret);

        flushout();
/*
        zdb_zone_lock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
        ret = zdb_zone_write_text_ex(zone, termout, TRUE, TRUE);
        zdb_zone_unlock(zone, ZDB_ZONE_MUTEX_SIMPLEREADER);
*/
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
    }
    else
    {
        formatln("failed to load zone file: %r", ret);
    }

    zdb_zone_load_parms_finalize(&parms);
    zone_reader_close(&zr);

    return ret;
}

// ********************************************************************************
// ***** module virtual table
// ********************************************************************************

const module_s zonesign_program =
{
    module_default_init,            // module initializer
    module_default_finalize,        // module finalizer
    zonesign_config_register,         // module register
    module_default_setup,           // module setup
    zonesign_run,                     // module run
    module_default_cmdline_help_print,      //

    yadifa_cmdline,                 // module command line struct
    NULL,                           // module command line callback
    NULL,                           // module filter arguments
    
    "zone signer",           // module public name
    "yzonesign",                        // module command (name as executable match)
    "zonesign",                         // module parameter (name as first parameter)
    /*zonesign_cmdline_help*/ NULL,          // module text to be printed upon help request
    ".yadifa.rc"                    // module rc file (ie: ".module.rc"
};
