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

#ifndef __CTRL_ZONE__H__
#define __CTRL_ZONE__H__

#include "server_config.h"

#if !HAS_CTRL
#error "CTRL has not been enabled : do not include this"
#endif

#include <dnscore/dns_message.h>

/**
 * CTRL handling
 */

ya_result ctrl_zone_freeze(zone_desc_t *zone_desc, bool dolock);
ya_result ctrl_zone_unfreeze(zone_desc_t *zone_desc, bool dolock);

ya_result ctrl_zone_sync_doclean(zone_desc_t *zone_desc, bool dolock);
ya_result ctrl_zone_sync_noclean(zone_desc_t *zone_desc, bool dolock);
ya_result ctrl_zone_sync(zone_desc_t *zone_desc, bool dolock, bool clear_journal);
ya_result ctrl_zone_notify(zone_desc_t *zone_desc, bool dolock);
ya_result ctrl_zone_refresh(zone_desc_t *zone_desc, bool dolock);
ya_result ctrl_zone_reload(zone_desc_t *zone_desc, bool dolock);

#if HAS_DYNAMIC_PROVISIONING
ya_result ctrl_zone_generate_from_message(dns_message_t *mesg); /* generate but let on the unactivated side */
ya_result ctrl_zone_config_merge(zone_desc_s *zone_desc, bool dolock);
ya_result ctrl_zone_config_merge_all();
ya_result ctrl_zone_config_delete(zone_desc_s *zone_desc, bool dolock);
#endif

/** @} */

#endif
