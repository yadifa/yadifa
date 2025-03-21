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
 * @defgroup
 * @ingroup yadifad
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _NOTIFY_H
#define _NOTIFY_H

#include "server_config.h"

#if HAS_CTRL
#include "ctrl.h"
#endif

#include <dnscore/dns_message.h>
#include <dnscore/host_address.h>
#include "database.h"

/**
 *  @brief Handle a notify from the primary (or another secondary)
 *
 *  @param database : the database
 *  @param mesg     : the input message
 *
 *  @retval OK
 *  @retval NOK
 */

ya_result notify_process(dns_message_t *msg);

/**
 * Sends a notify to all the secondary for a given domain name
 *
 * @param origin
 */

void notify_secondaries(const uint8_t *origin);

/**
 * Stops all notification for zone with origin
 *
 * @param origin
 */

void      notify_clear(const uint8_t *origin);

ya_result notify_service_init();

/**
 * Starts the notify service thread
 */

ya_result notify_service_start();

void      notify_wait_servicing();

/**
 * Stops the notify service thread
 */

ya_result notify_service_stop();

ya_result notify_service_finalize();

bool      notify_has_candidates_for_zone(zone_desc_t *zone_desc);

#endif /* _NOTIFY_H */

/** @} */
