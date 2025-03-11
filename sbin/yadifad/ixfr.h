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

#ifndef _IXFR_H
#define _IXFR_H

#include <dnscore/dns_message.h>
#include <dnscore/host_address.h>
#include <dnscore/tcp_manager2.h>

#include "database.h"

#ifdef __cplusplus
extern "C"
{
#endif

ya_result ixfr_process(dns_message_t *mesg, tcp_manager_channel_t *tmc);

/**
 *
 * Send an IXFR query to a primary and handle the answer (loads the zone).
 *
 */

ya_result ixfr_query(const host_address_t *servers, zdb_zone_t *zone, uint32_t *output_loaded_serial);

/**
 * Connects to the server and sends an IXFR query with the given parameters.
 * In case of success the input and output streams are tcp streams to the server, ready to read the answer
 * In case of error the streams are undefined
 *
 * @param servers
 * @param origin
 * @param ttl
 * @param rdata
 * @param rdata_size
 * @param is
 * @param os
 * @return
 */

ya_result ixfr_start_query(const host_address_t *servers, const uint8_t *origin, int32_t ttl, const uint8_t *rdata, uint16_t rdata_size, input_stream_t *is, output_stream_t *os, dns_message_t *ixfr_queryp);

#ifdef __cplusplus
}
#endif

#endif /* _IXFR_H */

/** @} */
