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
 * @defgroup dnsdbdnssec DNSSEC functions
 * @ingroup dnsdb
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * USE INCLUDES
 *
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnscore/thread_pool.h>
#include <dnscore/dns_message.h>

#include <dnsdb/zdb_types.h>
#include "dnscore/tcp_manager2.h"

/**
 * If the zone is relatively small, there is no need to prepare an image on the disk.
 * Instead, snapshot to memory.
 * The default treshold is set to 64KB (way more than the needs of 99% of use-cases)
 * TLDs are still expected use the through-storage branch of the code.
 */

/**
 * Returns the current value of the threshold.
 * Setting it to 0 will effectively disable the feature.
 *
 * @return The current value of the threshold, in bytes.
 *
 */

uint32_t zdb_zone_answer_axfr_memfile_size_threshold();

/**
 * Set the new value of the threshold.
 * Setting it to 0 will effectively disable the feature.
 * Returns the previous value of the threshold.
 *
 * @param new_threshold the new value of the threshold, in bytes.
 * @return The previous value of the threshold, in bytes.
 */

uint32_t zdb_zone_answer_axfr_memfile_size_threshold_set(uint32_t new_threshold);

/**
 *
 * @param zone
 * @param mesg
 * @param tp
 * @param max_packet_size
 * @param max_record_by_packet
 * @param compress_packets
 */

void zdb_zone_answer_axfr(zdb_zone_t *zone, dns_message_t *mesg, tcp_manager_channel_t *tmc, struct thread_pool_s *network_tp, struct thread_pool_s *disk_tp, uint16_t max_packet_size, uint16_t max_record_by_packet, bool compress_packets);

/** @} */
