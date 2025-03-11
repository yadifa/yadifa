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
 * @defgroup query_ex Database top-level query function
 * @ingroup dnsdb
 * @brief Database top-level query function
 *
 *  Database top-level query function
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnsdb/zdb_query_to_wire_context.h>

/**
 * @brief Queries the database given a message
 *
 * @param db the database
 * @param mesg the message
 * @param ans_auth_add the structure that will contain the sections of the answer
 * @param pool_buffer a big enough buffer used for the memory pool
 *
 * @return the status of the message (probably useless)
 */

static inline void zdb_query_to_wire_context_init(zdb_query_to_wire_context_t *context, dns_message_t *mesg)
{
    dns_packet_writer_init_append_to_message(&context->pw, mesg);
    context->mesg = mesg;
    context->fqdn = dns_message_get_canonised_fqdn(mesg);
    context->flags = ~0;
    context->record_type = dns_message_get_query_type(mesg);
    memset(&context->answer_count, 0, (const uint8_t *)&context->ns_rrsets[0] - (const uint8_t *)&context->answer_count);
}

finger_print zdb_query_to_wire(zdb_t *db, zdb_query_to_wire_context_t *context);

void         zdb_query_to_wire_finalize(zdb_query_to_wire_context_t *context);

/** @} */
