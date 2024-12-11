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

#include <dnscore/ptr_vector.h>

struct config_s
{
    ptr_vector_t    domains;
    ptr_vector_t    fqdns;
    char           *configuration_file_path;
    char           *log_path;
    char           *keys_path;
    char           *plan_path;
    char           *pid_path;
    char           *pid_file;
    char           *generate_from;
    char           *generate_until;
    char           *policy_name;
    host_address_t *server;

    uid_t           uid;
    gid_t           gid;
    uint32_t        timeout;
    uint32_t        ttl;

    uint32_t        update_apply_verify_retries;       // if an update wasn't applied successfully, retry CHECKING this amount of times
    uint32_t        update_apply_verify_retries_delay; // time between the above retries

    uint32_t        match_verify_retries;       // if there is not match, retry checking this amount of times
    uint32_t        match_verify_retries_delay; // time between the above retries

    uint32_t        roll_step_limit_override;

    int             program_mode;
    bool            reset;
    bool            purge;
    bool            dryrun;
    bool            wait_for_yadifad;
    bool            daemonise;
    bool            print_plan;
    bool            user_confirmation;
#if DEBUG
    bool with_secret_keys;
#endif
};

typedef struct config_s config_t;

enum keyroll_status_t
{
    KEYROLL_STATUS_OK = 0,
    KEYROLL_STATUS_ERROR = 1,
    KEYROLL_STATUS_RESET = 2
};

struct keyroll_state_s
{
    uint8_t              *domain;
    int64_t               next_operation;
    int64_t               errors;
    int64_t               retry_countdown;
    int64_t               last_error_epoch;
    int64_t               reinitialisations;
    int64_t               last_reinitialisation_epoch;
    enum keyroll_status_t status;
};

typedef struct keyroll_state_s keyroll_state_t;
