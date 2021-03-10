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

/** @defgroup dnsdbdnssec DNSSEC functions
 *  @ingroup dnsdb
 *  @brief 
 *
 *  
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#pragma once

#include <dnscore/thread_pool.h>
#include <dnscore/message.h>
#if DNSCORE_HAS_TCP_MANAGER
#include <dnscore/tcp_manager.h>
#endif

#include <dnsdb/zdb_types.h>

/**
 * 
 * Replies an (I)XFR stream to a slave.
 * 
 * @param zone The zone 
 * @param mesg The original query
 * @param network_tp The network thread pool to use
 * @param disk_tp The disk thread pool to use
 * @param max_packet_size the maximum size of a packet/message in the stream
 * @param max_record_by_packet The maximum number of records in a single message (1 for very old servers)
 * @param compress_packets Allow fqdn compression
 * 
 */

#if DNSCORE_HAS_TCP_MANAGER
void zdb_zone_answer_ixfr(zdb_zone *zone, message_data *mesg, tcp_manager_socket_context_t *sctx, struct thread_pool_s *network_tp, struct thread_pool_s *disk_tp, u16 max_packet_size, u16 max_record_by_packet, bool compress_packets);
#else
void zdb_zone_answer_ixfr(zdb_zone *zone, message_data *mesg, int sockfd, struct thread_pool_s *network_tp, struct thread_pool_s *disk_tp, u16 max_packet_size, u16 max_record_by_packet, bool compress_packets);
#endif

/** @} */
