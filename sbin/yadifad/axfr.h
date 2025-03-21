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
 * @defgroup ### #######
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#ifndef _AXFR_H
#define _AXFR_H

#include <dnscore/dns_message.h>
#include <dnscore/host_address.h>
#include <dnscore/tcp_manager2.h>

ya_result axfr_process_init();
ya_result axfr_process_finalise();

/**
 *
 * Handle an AXFR query from a secondary.
 *
 * If we don't do this many secondaries could call with a small interval asking a just-dynupdated snapshot.
 * If we do it the secondaries will be only a few steps behind and the next notification/ixfr will bring them up to
 * date.
 *
 */

ya_result axfr_process(dns_message_t *mesg, tcp_manager_channel_t *tmc);

/**
 *
 * Send an AXFR query to a primary and handle the answer (loads the zone)
 *
 */

ya_result axfr_query(const host_address_t *servers, const uint8_t *origin, uint32_t *out_loaded_serial);
ya_result axfr_query_ex(const host_address_t *servers, const uint8_t *origin, uint32_t *out_loaded_serial, uint32_t *out_loaded_refresh);

#endif /* _AXFR_H */

/** @} */
