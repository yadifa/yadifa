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

#pragma once

#include <dnscore/host_address.h>
#include <dnscore/dnskey_keyring.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/ptr_treemap.h>
#include <dnscore/u64_treemap.h>

#ifndef PACKAGE_VERSION
#include "keyroll_config.h"
#endif

#define YKEYROLL_NAME                          "yakeyrolld"
#define YKEYROLL_VERSION                       PACKAGE_VERSION

#define YKEYROLL_KSK_SUFFIX                    "_SECRET_KEYSIGNINGKEY"

#define DNSKEY_TTL_DEFAULT                     86400

#define KEYROLL_STEPS_MAX                      1000 // Typically: 13 keys a year, ready for two years. More is kind of counter-productive. So 1000 is plenty.
// exceptions requiring a bigger limit are corner-cases tests

#define KEYROLL_QUERY_TIMEOUT_S                10 // seconds

#define KEYROLL_ERROR_BASE                     0x80100000
#define KEYROLL_ERROR_CODE(code_)              ((int32_t)(KEYROLL_ERROR_BASE + (code_)))
#define KEYROLL_EXPECTED_IDENTICAL_RECORDS     KEYROLL_ERROR_CODE(1)
#define KEYROLL_EXPECTED_IDENTICAL_SIZE_RRSETS KEYROLL_ERROR_CODE(2)
#define KEYROLL_EXPECTED_DNSKEY_OR_RRSIG       KEYROLL_ERROR_CODE(3)
#define KEYROLL_UPDATE_SUBCOMMAND_ERROR        KEYROLL_ERROR_CODE(4)
#define KEYROLL_HOLE_IN_TIMELINE               KEYROLL_ERROR_CODE(5)
#define KEYROLL_MUST_REINITIALIZE              KEYROLL_ERROR_CODE(6)

enum KeyrollAction
{
    Publish = 1,
    Activate = 2,
    Deactivate = 4,
    Unpublish = 8
};

struct keyroll_s;

#define KROLLSTP_TAG 0x5054534c4c4f524b

typedef struct keyroll_step_s
{
    struct keyroll_s *keyroll; // link back to the keyroll
    int64_t           epochus;
    ptr_vector_t      dnskey_del; // keys added at this instant
    ptr_vector_t      dnskey_add; // keys demoved at this instant
    ptr_vector_t      rrsig_add;  // signatures added at this instant
    ptr_vector_t      expect;     // dns_resource_record vector
    ptr_vector_t      endresult;  // dns_resource_record vector
    ptr_treemap_t     file_add;   // list of the files to be added + content
    ptr_vector_t      file_del;   // list of the files to be deleted

    uint64_t          fingerprint; // number generated from dnskey_set, based on currently present tags
    uint8_t           keyroll_action;

    bool              dirty;
    bool              from_merge;
} keyroll_step_t;

typedef struct keyroll_key_parameters_s
{
    uint32_t activate_after;   // publish +
    uint32_t deactivate_after; // publish +
    uint32_t delete_after;     // publish +
    uint32_t estimated_signing_time;
    uint16_t size;
    uint8_t  algorithm;
} keyroll_key_parameters_t;

typedef struct keyroll_s
{
    uint8_t                 *domain;

    host_address_t          *server;
    dnskey_keyring_t        *keyring;
    char                    *plan_path;
    char                    *keys_path;
    char                    *private_keys_path;

    u64_treemap_t            steps;

    keyroll_key_parameters_t ksk_parameters;
    keyroll_key_parameters_t zsk_parameters;

    int64_t                  ksk_next_deactivation;

    int64_t                  zsk_next_deactivation;

    uint32_t                 update_apply_verify_retries;       // if an update wasn't applied successfully, retry CHECKING this amount of times
    uint32_t                 update_apply_verify_retries_delay; // time between the above retries

    uint32_t                 match_verify_retries;       // if there is not match, retry checking this amount of times
    uint32_t                 match_verify_retries_delay; // time between the above retries

    uint32_t                 steps_count;

    bool                     generation_mode;

    // current key records
} keyroll_t;

void    keyroll_errors_register();

int64_t keyroll_set_timing_steps(keyroll_t *keyroll, dnskey_t *key, bool dirty);

// global value

void keyroll_set_roll_step_limit_override(int32_t roll_step_limit_override);

/**
 * Keyroll initialisation for a domain
 *
 * @param domain the domain
 * @param plan_path the directory containing the plan files (the sequence of steps)
 * @param keys_path the directory where to put the keys
 * @param server the server address
 */

ya_result keyroll_init(keyroll_t *keyroll, const uint8_t *domain, const char *plan_path, const char *keys_path, const host_address_t *server, bool generation_mode);

/**
 * Connects to the server, fetches the public keys and add them to the keyring.
 */

ya_result keyroll_fetch_public_keys_from_server(keyroll_t *keyroll);

/**
 * Does an keyroll_init followed by a keyroll_fetch_public_keys_from_server.
 */

ya_result keyroll_init_from_server(keyroll_t *keyroll, const uint8_t *domain, const char *plan_path, const char *keys_path, const host_address_t *server);

ya_result keyroll_update_apply_verify_retries_set(keyroll_t *keyroll, uint32_t retries, uint32_t delay);
ya_result keyroll_match_verify_retries_set(keyroll_t *keyroll, uint32_t retries, uint32_t delay);

void      keyroll_finalize(keyroll_t *keyroll);

/**
 * Generates a DNSKEY to be published at the given epoch.
 * The DNSKEY can be set as a KSK or ZSK using the ksk parameter.
 * This function creates steps at the various time fields of the key.
 */

ya_result keyroll_generate_dnskey(keyroll_t *keyroll, int64_t publication_epochus, bool ksk);

/**
 * Generates a DNSKEY to be published at the given epoch.
 * The DNSKEY can be set as a KSK or ZSK using the ksk parameter.
 * This functions requires the time fields to be set manually.
 * This function creates steps at the various time fields of the key.
 */

ya_result keyroll_generate_dnskey_ex(keyroll_t *keyroll, uint32_t size, uint8_t algorithm, int64_t creation_epochus, int64_t publication_epochus, int64_t activate_epochus, int64_t deactivate_epochus, int64_t unpublish_epochus, bool ksk,
                                     dnskey_t **out_keyp);

/**
 * Returns the step at the given epoch, or create an empty one
 */

keyroll_step_t *keyroll_get_step(keyroll_t *keyroll, int64_t epochus);

/**
 * Queries the server for its current state (DNSKEY + RRSIG DNSKEY records)
 *
 * Appends found dns_resource_record* to the ptr_vector_t
 *
 * The ptr_vector_t is expected to be initialised and empty, or at the very least only filled with
 * dns_resource_record*
 *
 */

ya_result keyroll_dnskey_state_query(const keyroll_t *keyroll, ptr_vector_t *current_dnskey_rrsig_rr);

/**
 * Releases the memory used by dns_resource_record* in the ptr_vector_t
 */

void keyroll_dnskey_state_destroy(ptr_vector_t *current_dnskey_rrsig_rr);

/**
 * Compares the expected state at a given step with the state on the server
 * (queried with keyroll_dnskey_state_query)
 *
 * Returns SUCCESS iff it's a match.
 */

ya_result keyroll_step_expects_matched(const keyroll_step_t *step, const ptr_vector_t *dnskey_rrsig_rr);

/**
 * Scans the plan for the step matching the given state
 *
 * Returns the matching step or NULL
 */

keyroll_step_t *keyroll_step_scan_matching_expectations(const keyroll_t *keyroll, ptr_vector_t *current_dnskey_rrsig_rr);

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

ya_result keyroll_step_play_range_ex(const keyroll_t *keyroll, int64_t seek_from, int64_t now, bool delete_all_dnskey, keyroll_step_t **first_stepp);

/**
 * Plays all the steps in a given epoch range.
 */

ya_result keyroll_step_play_range(const keyroll_t *keyroll, int64_t seek_from, int64_t now);

/**
 * Plays the first step of a plan if it's before a given epoch.
 * If the first step is in the future, it's not played.
 * Returns the first step in the parameter.
 * Returns an error code.
 */

ya_result keyroll_play_first_step(const keyroll_t *keyroll, int64_t now, keyroll_step_t **first_stepp);

/**
 * Returns the step being active at the given epoch or NULL if there is no such step.
 * If a step starts at the given epoch, it's the one returned.
 */

keyroll_step_t *keyroll_get_current_step_at(const keyroll_t *keyroll, int64_t epochus);

/**
 * Returns the next step to be active from the given epoch or NULL if there is no such step.
 * If a step starts at the given epoch, it's the one returned.
 */

keyroll_step_t *keyroll_get_next_step_from(const keyroll_t *keyroll, int64_t epochus);

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

ya_result keyroll_plan_with_policy(keyroll_t *keyroll, int64_t generate_from, int64_t generate_until, const char *policy_name);

/**
 * Generates a simple plan.
 * Do not use this.
 * Use the DNSSEC policy one instead.
 */

ya_result keyroll_plan(keyroll_t *keyroll, int64_t generate_until);

/**
 * Prints a step.
 */

void keyroll_step_print(keyroll_step_t *step);

/**
 * Prints a plan.
 */

ya_result keyroll_print(keyroll_t *keyroll, output_stream_t *os);

/**
 * Prints a plan to the given output stream in a JSON format.
 */

ya_result keyroll_print_json(keyroll_t *keyroll, output_stream_t *os);

/**
 * Stores the plan on disk (several files, private KSK files, ...)
 */

ya_result keyroll_store(keyroll_t *keyroll);

ya_result keyroll_get_state_find_match_and_play(const keyroll_t *keyrollp, int64_t now, const keyroll_step_t *current_step, const keyroll_step_t **matched_stepp);

/**
 * Enables or disables dryrun mode (no updates is ever sent)
 */

void     keyroll_set_dryrun_mode(bool enabled);

uint32_t keyroll_deactivation_margin(uint32_t activate_epoch, uint32_t deactivate_epoch, uint32_t delete_epoch);
