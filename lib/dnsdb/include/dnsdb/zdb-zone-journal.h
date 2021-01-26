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

/** @defgroup
 *  @ingroup dnsdb
 *  @brief
 *
 * Journal API
 *
 *
 * @{
 */

#pragma once

#define ZDB_ZONE_JOURNAL_AVAILABLE 1

#include <dnscore/dns_resource_record.h>
#include <dnsdb/zdb_types.h>

/**
 * Returns the first and last serial in the journal of a loaded zone.
 * If the journal has not been opened yet (and bound to the zone) then it will be.
 * 
 * @param zone the zone
 * @param out_serial_from, can be NULL
 * @param out_serial_to, can be NULL
 * 
 * @return an error code
 */

ya_result zdb_zone_journal_get_serial_range(zdb_zone *zone, u32 *out_serial_from, u32 *out_serial_to);

/**
 * Opens a stream from the journal for reading an IXFR starting at a given serial.
 * 
 * @param zone the zone
 * @param serial the serial to start from
 * @param out_is the stream to be initialised for reading the IXFR
 * @param out_last_soa_rr the last SOA record, can be NULL
 * 
 * @return an error code
 */

ya_result zdb_zone_journal_get_ixfr_stream_at_serial(zdb_zone *zone, u32 serial, input_stream *out_is, dns_resource_record *out_last_soa_rr);

/**
 * Appends an IXFR stream to the journal.
 * The expected stream lacks the repeated last SOA record at the first and last position.
 * 
 * @param zone
 * @param is stream of uncompressed wire records : (SOA DEL DEL DEL ... SOA ADD ADD ADD ...)+
 * @return an error code
 */

ya_result zdb_zone_journal_append_ixfr_stream(zdb_zone *zone, input_stream *is);

/**
 * Deletes the file of the journal of a zone
 * 
 * @param zone
 * @return an error code
 */

ya_result zdb_zone_journal_delete(const zdb_zone *zone);

/**
 * @}
 */

