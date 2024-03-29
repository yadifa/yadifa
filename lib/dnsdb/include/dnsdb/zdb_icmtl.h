/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2023, EURid vzw. All rights reserved.
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

/** @defgroup dnsdb
 *  @ingroup dnsdb
 *  @brief journal file & incremental changes
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnsdb/dynupdate.h>

#ifndef HAS_DYNUPDATE_DIFF_ENABLED
#error "HAS_DYNUPDATE_DIFF_ENABLED not defined"
#endif

#include <dnsdb/zdb_types.h>
#include <dnscore/output_stream.h>
#include <dnscore/input_stream.h>
#include <dnscore/counter_output_stream.h>
#include <dnscore/ptr_vector.h>

#ifdef	__cplusplus
extern "C"
{
#endif


#define ZDB_ICMTL_REPLAY_SERIAL_OFFSET 1 // avoids scanning
#define ZDB_ICMTL_REPLAY_SERIAL_LIMIT  2 // don't try to go beyond the set serial


struct zdb_icmtl_replay_commit_state
{
    u32 dnskey_removed;
    u32 dnskey_added;
    u32 end_serial;
#if __SIZEOF_POINTER__ ==  8
    u32 reserved0;
#endif
#if HAS_EVENT_DYNAMIC_MODULE
    ptr_vector dnskey_added_list;
    ptr_vector dnskey_removed_list;
#endif
};

typedef struct zdb_icmtl_replay_commit_state zdb_icmtl_replay_commit_state;

ya_result zdb_icmtl_replay_commit_ex(zdb_zone *zone, input_stream *is, zdb_icmtl_replay_commit_state *out_state);

ya_result zdb_icmtl_replay_commit(zdb_zone *zone, input_stream *is, u32 *out_serial_after_replayp);


/**
 * Replays incremental changes for the zone, looking in the directory for the files (.ix)
 */

ya_result zdb_icmtl_replay(zdb_zone *zone);

#ifdef	__cplusplus
}
#endif


/** @} */

/*----------------------------------------------------------------------------*/

