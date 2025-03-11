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
 * @defgroup server
 * @ingroup yadifad
 * @brief server
 *
 *  Handles queries made in the CH class (ie: version.*)
 *
 * @{
 *----------------------------------------------------------------------------*/

#ifndef __CTRL__H__
#define __CTRL__H__

#include <dnscore/host_address.h>
#include <dnscore/tsig.h>
#include <dnscore/dns_message.h>

#include "server_config.h"

#if !HAS_CTRL
#error "CTRL has not been enabled : do not include this"
#endif

#define CTRL_PORT_DEFAULT             1021 // highest prime under 1023

#define HAS_CTRL_DYNAMIC_PROVISIONING 0

/**
 * CTRL handling
 */

struct config_control_s
{
#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING
    host_address_t *primaries; /* all the recognised primaries are listed here */

    /* So that the zone contains more than an SOA : */

    uint8_t      *dynamic_mname;              /* current name server */
    uint8_t      *dynamic_rname;              /* admin email (rname form) */
    host_address *dynamic_mname_ip_addresses; /* list of IPs for the current name server (IPv4 & IPv6) */
#endif
    host_address_t *listen;
    bool            enabled;
};

typedef struct config_control_s config_control_t;

void                            ctrl_set_listen(host_address_t *hosts);
void                            ctrl_exclude_listen(host_address_t *address_list);
host_address_t                 *ctrl_get_listen();

static inline bool              ctrl_has_dedicated_listen() { return ctrl_get_listen() != NULL; }

void                            ctrl_set_enabled(bool b);
bool                            ctrl_get_enabled();

ya_result                       ctrl_config_reload();

ya_result                       ctrl_message_process(dns_message_t *mesg);

#if DNSCORE_HAS_CTRL_DYNAMIC_PROVISIONING

host_address         *ctrl_get_primaries();
void                  ctrl_set_primaries(host_address *hosts);

const uint8_t        *ctrl_get_dynamic_mname();
void                  ctrl_set_dynamic_mname(const uint8_t *fqdn);

const uint8_t        *ctrl_get_dynamic_rname();
void                  ctrl_set_dynamic_rname(const uint8_t *fqdn);

host_address         *ctrl_get_dynamic_mname_ip_addresses();
void                  ctrl_set_dynamic_mname_ip_addresses(host_address *hosts);

const config_control *ctrl_get_config();

bool                  ctrl_is_host_primary(const host_address *host);

bool                  ctrl_is_ip_tsig_primary(const socketaddress *sa, const tsig_key_t *tsig);

ya_result             ctrl_store_dynamic_config();

ya_result             ctrl_drop_dynamic_config();

/**
 * all secondaries of the dynamic provisioning space will be notified of all zones they are supposed to handle
 */

void ctrl_notify_all_secondaries();

/**
 * all primaries of the dynamic provisioning space will be notified that this secondary just came up
 */

void ctrl_notify_all_primaries();

void ctrl_notify_secondary(host_address *secondary);

#endif

/** @} */

#endif
