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

#ifndef __CTRL_QUERY__H__
#define __CTRL_QUERY__H__

#include "server_config.h"

#if !HAS_CTRL
#error "CTRL has not been enabled : do not include this"
#endif

#include <dnscore/dns_message.h>
#include <dnscore/host_address.h>
#include <dnscore/dns_packet_writer.h>

#include "zone_desc.h"

ya_result ctrl_query_message_add_soa(dns_packet_writer_t *pw, zone_desc_t *zone_desc);

/* Adds record using the TXT type */

ya_result ctrl_query_message_add_u32_txt(dns_packet_writer_t *pw, const char *name, uint32_t value);
ya_result ctrl_query_message_add_type_txt(dns_packet_writer_t *pw, const char *name, uint16_t value);
ya_result ctrl_query_message_add_class_txt(dns_packet_writer_t *pw, const char *name, uint16_t value);
ya_result ctrl_query_message_add_hosts_txt(dns_packet_writer_t *pw, const char *name, host_address_t *hosts);
ya_result ctrl_query_message_add_time_txt(dns_packet_writer_t *pw, const char *name, uint32_t value);
ya_result ctrl_query_message_add_text_txt(dns_packet_writer_t *pw, const char *name, const char *value);
ya_result ctrl_query_message_add_aml_txt(dns_packet_writer_t *pw, const char *name, const address_match_list_t *aml);
ya_result ctrl_query_message_add_ams_txt(dns_packet_writer_t *pw, const char *name, const address_match_set_t *ams);

ya_result ctrl_query_message_add_u8(dns_packet_writer_t *pw, const uint8_t *origin, uint16_t rtype, uint8_t value);
ya_result ctrl_query_message_add_u32(dns_packet_writer_t *pw, const uint8_t *origin, uint16_t rtype, uint32_t value);
ya_result ctrl_query_message_add_utf8(dns_packet_writer_t *pw, const uint8_t *origin, uint16_t rtype, const char *value);
ya_result ctrl_query_message_add_hosts(dns_packet_writer_t *pw, const uint8_t *origin, uint16_t rtype, const host_address_t *value);

/** @} */

#endif
