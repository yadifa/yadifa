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

#pragma once

#include <dnscore/host_address.h>
#include <dnscore/dnskey-keyring.h>
#include <dnscore/ptr_set.h>
#include <dnscore/u64_set.h>

#ifndef PACKAGE_VERSION
#include "keyroll-config.h"
#endif

#define YKEYROLL_NAME "yakeyrolld"
#define YKEYROLL_VERSION PACKAGE_VERSION

#define YKEYROLL_KSK_SUFFIX "_SECRET_KEYSIGNINGKEY"

#define DNSKEY_TTL_DEFAULT 86400

#define KEYROLL_QUERY_TIMEOUT_S 10 // seconds

#define KEYROLL_ERROR_BASE 0x80100000
#define	KEYROLL_ERROR_CODE(code_)		    ((s32)(KEYROLL_ERROR_BASE+(code_)))
#define KEYROLL_EXPECTED_IDENTICAL_RECORDS KEYROLL_ERROR_CODE(1)
#define KEYROLL_EXPECTED_IDENTICAL_SIZE_RRSETS KEYROLL_ERROR_CODE(2)
#define KEYROLL_EXPECTED_DNSKEY_OR_RRSIG KEYROLL_ERROR_CODE(3)
#define KEYROLL_UPDATE_SUBCOMMAND_ERROR KEYROLL_ERROR_CODE(4)
#define KEYROLL_HOLE_IN_TIMELINE KEYROLL_ERROR_CODE(5)
#define KEYROLL_MUST_REINITIALIZE KEYROLL_ERROR_CODE(6)

enum KeyrollAction
{
    Publish = 1,
    Activate = 2,
    Deactivate = 4,
    Unpublish = 8
};

struct keyroll_s;

typedef struct keyroll_step_s
{
    struct keyroll_s* keyroll;      // link back to the keyroll
    s64 epochus;
    ptr_vector dnskey_del;          // keys added at this instant
    ptr_vector dnskey_add;          // keys demoved at this instant
    ptr_vector rrsig_add;           // signatures added at this instant
    ptr_vector expect;              // dns_resource_record vector
    ptr_vector endresult;           // dns_resource_record vector
    ptr_set    file_add;            // list of the files to be added + content
    ptr_vector file_del;            // list of the files to be deleted

    u64 fingerprint;                // number generated from dnskey_set, based on currently present tags
    u8  keyroll_action;

    bool dirty;
    bool from_merge;
} keyroll_step_t;

typedef struct keyroll_key_parameters_s
{
    u32 activate_after;     // publish +
    u32 deactivate_after;   // publish +
    u32 delete_after;       // publish +
    u32 estimated_signing_time;
    u16 size;
    u8 algorithm;
} keyroll_key_parameters_t;

typedef struct keyroll_s
{
    u8 *domain;

    host_address *server;
    dnskey_keyring *keyring;
    char *plan_path;
    char *keys_path;
    char *private_keys_path;

    u64_set steps;

    keyroll_key_parameters_t ksk_parameters;
    keyroll_key_parameters_t zsk_parameters;

    s64 ksk_next_deactivation;

    s64 zsk_next_deactivation;

    u32 update_apply_verify_retries;        // if an update wasn't applied successfully, retry CHECKING this amount of times
    u32 update_apply_verify_retries_delay;  // time between the above retries

    u32 match_verify_retries;               // if there is not match, retry checking this amount of times
    u32 match_verify_retries_delay;         // time between the above retries

    bool generation_mode;

    // current key records
} keyroll_t;

void keyroll_errors_register();

s64 keyroll_set_timing_steps(keyroll_t *keyroll, dnssec_key *key, bool dirty);

/**
 * Keyroll initialisation for a domain
 *
 * @param domain the domain
 * @param plan_path the directory containing the plan files (the sequence of steps)
 * @param keys_path the directory where to put the keys
 * @param server the server address
 */

ya_result keyroll_init(keyroll_t* keyroll, const u8 *domain, const char *plan_path, const char *keys_path, const host_address *server, bool generation_mode);

/**
 * Connects to the server, fetches the public keys and add them to the keyring.
 */

ya_result keyroll_fetch_public_keys_from_server(keyroll_t* keyroll);

/**
 * Does an keyroll_init followed by a keyroll_fetch_public_keys_from_server.
 */

ya_result keyroll_init_from_server(keyroll_t* keyroll, const u8 *domain, const char *plan_path, const char *keys_path, const host_address *server);

ya_result keyroll_update_apply_verify_retries_set(keyroll_t* keyroll, u32 retries, u32 delay);
ya_result keyroll_match_verify_retries_set(keyroll_t* keyroll, u32 retries, u32 delay);

void keyroll_finalize(keyroll_t *keyroll);

/**
 * Generates a DNSKEY to be published at the given epoch.
 * The DNSKEY can be set as a KSK or ZSK using the ksk parameter.
 * This function creates steps at the various time fields of the key.
 */

ya_result keyroll_generate_dnskey(keyroll_t *keyroll, s64 publication_epochus, bool ksk);

/**
 * Generates a DNSKEY to be published at the given epoch.
 * The DNSKEY can be set as a KSK or ZSK using the ksk parameter.
 * This functions requires the time fields to be set manually.
 * This function creates steps at the various time fields of the key.
 */

ya_result keyroll_generate_dnskey_ex(keyroll_t *keyroll, u32 size, u8 algorithm,
                                     s64 creation_epochus, s64 publication_epochus, s64 activate_epochus,
                                     s64 deactivate_epochus, s64 unpublish_epochus, bool ksk, dnssec_key **out_keyp);

/**
 * Returns the step at the given epoch, or create an empty one
 */

keyroll_step_t* keyroll_get_step(keyroll_t *keyroll, s64 epochus);

/**
 * Queries the server for its current state (DNSKEY + RRSIG DNSKEY records)
 *
 * Appends found dns_resource_record* to the ptr_vector
 *
 * The ptr_vector is expected to be initialised and empty, or at the very least only filled with
 * dns_resource_record*
 *
 */

ya_result keyroll_dnskey_state_query(const keyroll_t *keyroll, ptr_vector *current_dnskey_rrsig_rr);

/**
 * Releases the memory used by dns_resource_record* in the ptr_vector
 */

void keyroll_dnskey_state_destroy(ptr_vector *current_dnskey_rrsig_rr);

/**
 * Compares the expected state at a given step with the state on the server
 * (queried with keyroll_dnskey_state_query)
 *
 * Returns SUCCESS iff it's a match.
 */

ya_result keyroll_step_expects_matched(const keyroll_step_t *step, const ptr_vector *dnskey_rrsig_rr);

/**
 * Scans the plan for the step matching the given state
 *
 * Returns the matching step or NULL
 */

keyroll_step_t* keyroll_step_scan_matching_expectations(const keyroll_t *keyroll, ptr_vector *current_dnskey_rrsig_rr);

/**
 * Plays a step on the server
 *
 * @param step the step to play
 * @param delete_all_dnskey delete all keys on the server.
 */

ya_result keyroll_step_play(const keyroll_step_t *step, bool delete_all_dnskey);

/**
 * Plays all the steps in a given epoch range.
 */

ya_result keyroll_step_play_range_ex(const keyroll_t *keyroll, s64 seek_from , s64 now, bool delete_all_dnskey, keyroll_step_t **first_stepp);

/**
 * Plays all the steps in a given epoch range.
 */

ya_result keyroll_step_play_range(const keyroll_t *keyroll, s64 seek_from , s64 now);

/**
 * Plays the first step of a plan if it's before a given epoch.
 * If the first step is in the future, it's not played.
 * Returns the first step in the parameter.
 * Returns an error code.
 */

ya_result keyroll_play_first_step(const keyroll_t *keyroll, s64 now, keyroll_step_t **first_stepp);

/**
 * Returns the step being active at the given epoch or NULL if there is no such step.
 * If a step starts at the given epoch, it's the one returned.
 */

keyroll_step_t* keyroll_get_current_step_at(const keyroll_t *keyroll, s64 epochus);

/**
 * Returns the next step to be active from the given epoch or NULL if there is no such step.
 * If a step starts at the given epoch, it's the one returned.
 */

keyroll_step_t* keyroll_get_next_step_from(const keyroll_t *keyroll, s64 epochus);

/**
 * Destroys all the .keyroll, .key and .private files of a plan (obviously dangerous)
 */

ya_result keyroll_plan_purge(keyroll_t *keyroll);

/**
 * Loads a plan from disk (all the steps).
 * Loads KSK private keys if they are available.
 */

ya_result keyroll_plan_load(keyroll_t *keyroll);

/**
 * Generates a plan using a DNSSEC policy.
 */

ya_result keyroll_plan_with_policy(keyroll_t *keyroll, s64 generate_from, s64 generate_until, const char* policy_name);

/**
 * Generates a simple plan.
 * Do not use this.
 * Use the DNSSEC policy one instead.
 */

ya_result keyroll_plan(keyroll_t *keyroll, s64 generate_until);

/**
 * Prints a step.
 */

void keyroll_step_print(keyroll_step_t *step);

/**
 * Prints a plan.
 */

ya_result keyroll_print(keyroll_t *keyroll, output_stream *os);

/**
 * Prints a plan to the given output stream in a JSON format.
 */

ya_result keyroll_print_json(keyroll_t *keyroll, output_stream *os);

/**
 * Stores the plan on disk (several files, private KSK files, ...)
 */

ya_result keyroll_store(keyroll_t *keyroll);

ya_result keyroll_get_state_find_match_and_play(const keyroll_t *keyrollp, s64 now, const keyroll_step_t *current_step, const keyroll_step_t ** matched_stepp);

/**
 * Enables or disables dryrun mode (no updates is ever sent)
 */

void keyroll_set_dryrun_mode(bool enabled);

u32 keyroll_deactivation_margin(u32 activate_epoch, u32 deactivate_epoch, u32 delete_epoch);
