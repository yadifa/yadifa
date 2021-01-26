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

/** @defgroup 
 *  @ingroup 
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/

#pragma once

#include<dnscore/dnskey.h>

#include <dynamic-module-interface.h>

struct dynamic_module_interface_chain;
struct dynamic_module_dnskey_interface_chain;
struct dynamic_module_statistics_interface_chain;
struct server_statistics_t;

#if !DYNAMIC_MODULE_HANDLER_C
extern struct dynamic_module_interface_chain *g_dynamic_module_interface_chain;
extern struct dynamic_module_dnskey_interface_chain *g_dynamic_module_dnskey_interface_chain;
extern struct dynamic_module_statistics_interface_chain *g_dynamic_module_statistics_interface_chain;
#endif

/**
 * Trivial.
 */

ya_result dynamic_module_handler_init();

/**
 * Trivial.
 */

ya_result dynamic_module_handler_finalize();

/**
 * Loads a module given its full path name (with luck relative may work too ... so yes: full path)
 * Don't forget to take into account the choot.
 * 
 * Modules should only be loaded AFTER the last fork.
 */

ya_result dynamic_module_handler_load(int argc, const char **argv);

ya_result dynamic_module_handler_load_from_command(const char *command);

static inline bool dynamic_module_interface_chain_available()
{
    return g_dynamic_module_interface_chain != NULL;
}

static inline bool dynamic_module_dnskey_interface_chain_available()
{
    return g_dynamic_module_dnskey_interface_chain != NULL;
}

static inline bool dynamic_module_statistics_interface_chain_available()
{
    return g_dynamic_module_statistics_interface_chain != NULL;
}

// interface

void dynamic_module_startup();
void dynamic_module_settings();
void dynamic_module_shutdown();

// dnskey_interface

void dynamic_module_on_dnskey_created(const dnssec_key *key);
void dynamic_module_on_dnskey_publish(const dnssec_key *key);
void dynamic_module_on_dnskey_activate(const dnssec_key *key);
void dynamic_module_on_dnskey_revoke(const dnssec_key *key);
void dynamic_module_on_dnskey_inactive(const dnssec_key *key);
void dynamic_module_on_dnskey_delete(const dnssec_key *key);

#define DYNAMIC_MODULE_STATISTICS_RCODE_COUNT 32
#define DYNAMIC_MODULE_STATISTICS_TSIG_RCODE_COUNT 4

struct dynamic_module_statistics_args_buffers
{
    uint64_t udp_rcode_buffer[DYNAMIC_MODULE_STATISTICS_RCODE_COUNT];    
    uint64_t tcp_rcode_buffer[DYNAMIC_MODULE_STATISTICS_RCODE_COUNT];
    uint64_t udp_tsig_rcode_buffer[DYNAMIC_MODULE_STATISTICS_TSIG_RCODE_COUNT];    
    uint64_t tcp_tsig_rcode_buffer[DYNAMIC_MODULE_STATISTICS_TSIG_RCODE_COUNT];
};

void dynamic_module_on_statistics_update(struct server_statistics_t *st, u64 epoch);

/**
 * @}
 */
