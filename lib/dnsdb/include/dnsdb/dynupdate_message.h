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

/**-----------------------------------------------------------------------------
 * @defgroup
 * @ingroup
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnscore/dnskey.h>
#include <dnscore/dns_packet_reader.h>
#include <dnscore/dns_packet_writer.h>

struct dynupdate_message
{
    uint8_t            *packet;
    uint32_t            size;
    uint16_t            rclass;
    dns_packet_writer_t pw;
};

typedef struct dynupdate_message dynupdate_message;

/**
 * Initialises a simple update buffer
 *
 * @param dmsg
 */

void dynupdate_message_init(dynupdate_message *dmsg, const uint8_t *origin, uint16_t rclass);

/**
 * Clears a simple update buffer
 *
 * @param dmsg
 */

void dynupdate_message_reset(dynupdate_message *dmsg, const uint8_t *origin, uint16_t rclass);

/**
 * Releases resources.
 *
 * @param dmsg
 */

void dynupdate_message_finalize(dynupdate_message *dmsg);

/**
 * Sets a reader up for the buffer.
 *
 * @param dmsg
 * @param purd
 */

void dynupdate_message_set_reader(dynupdate_message *dmsg, dns_packet_reader_t *purd);

/**
 * Return the number of update records.
 *
 * @param dmsg
 * @return
 */

uint16_t dynupdate_message_get_count(dynupdate_message *dmsg);

/**
 * Adds a dnskey record to the buffer
 *
 * @param dmsg
 * @param ttl
 * @param key
 * @return
 */

ya_result dynupdate_message_add_dnskey(dynupdate_message *dmsg, int32_t ttl, const dnskey_t *key);

/**
 * Deletes a dnskey record to the buffer
 *
 * @param dmsg
 * @param ttl
 * @param key
 * @return
 */

ya_result dynupdate_message_del_dnskey(dynupdate_message *dmsg, const dnskey_t *key);

/**
 * Appends a "add RR" command to the buffer.
 *
 * @param dmsg
 * @param fqdn
 * @param rtype
 * @param ttl
 * @param rdata_size
 * @param rdata
 * @return
 */

ya_result dynupdate_message_add_record(dynupdate_message *dmsg, const uint8_t *fqdn, uint16_t rtype, int32_t ttl, uint16_t rdata_size, const void *rdata);

/**
 * Appends a "delete RR" command to the buffer.
 *
 * @param dmsg
 * @param fqdn
 * @param rtype
 * @param ttl
 * @param rdata_size
 * @param rdata
 * @return
 */

ya_result dynupdate_message_del_record(dynupdate_message *dmsg, const uint8_t *fqdn, uint16_t rtype, int32_t ttl, uint16_t rdata_size, const void *rdata);

/**
 *
 * Appends a "delete RRSET" command to the buffer.
 *
 * @param dmsg
 * @param fqdn
 * @param rtype
 * @return
 */

ya_result dynupdate_message_del_record_set(dynupdate_message *dmsg, const uint8_t *fqdn, uint16_t rtype);

/**
 * Appends a "delete fqdn" command to the buffer.
 *
 * @param dmsg
 * @param fqdn
 * @return
 */

ya_result dynupdate_message_del_fqdn(dynupdate_message *dmsg, const uint8_t *fqdn);

/** @} */
