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

/** @defgroup server
 *  @ingroup yadifad
 *  @brief server
 *
 *  Handles queries made in the CH class (ie: version.*)
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#ifndef __CTRL_QUERY__H__
#define __CTRL_QUERY__H__

#include "server-config.h"

#if !HAS_CTRL
#error "CTRL has not been enabled : do not include this"
#endif

#include <dnscore/message.h>
#include <dnscore/host_address.h>
#include <dnscore/packet_writer.h>
#include <dnscore/host_address.h>

#include "zone_desc.h"

ya_result ctrl_query_message_add_soa(packet_writer *pw, zone_desc_s *zone_desc);

/* Adds record using the TXT type */

ya_result ctrl_query_message_add_u32_txt(packet_writer *pw, const char* name, u32 value);
ya_result ctrl_query_message_add_type_txt(packet_writer *pw, const char* name, u16 value);
ya_result ctrl_query_message_add_class_txt(packet_writer *pw, const char* name, u16 value);
ya_result ctrl_query_message_add_hosts_txt(packet_writer *pw, const char* name, host_address *hosts);
ya_result ctrl_query_message_add_time_txt(packet_writer *pw, const char* name, u32 value);
ya_result ctrl_query_message_add_text_txt(packet_writer *pw, const char* name, const char* value);
ya_result ctrl_query_message_add_aml_txt(packet_writer *pw, const char* name, const address_match_list *aml);
ya_result ctrl_query_message_add_ams_txt(packet_writer *pw, const char* name, const address_match_set *ams);

ya_result ctrl_query_message_add_u8(packet_writer *pw, const u8 *origin, u16 rtype, u8 value);
ya_result ctrl_query_message_add_u32(packet_writer *pw, const u8 *origin, u16 rtype, u32 value);
ya_result ctrl_query_message_add_utf8(packet_writer *pw, const u8 *origin, u16 rtype, const char *value);
ya_result ctrl_query_message_add_hosts(packet_writer *pw, const u8 *origin, u16 rtype, const host_address *value);

/** @} */

#endif
