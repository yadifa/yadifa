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

/** @defgroup dnsdbupdate Dynamic update functions
 *  @ingroup dnsdb
 *  @brief 
 *
 * @{
 */
/*----------------------------------------------------------------------------*/
#ifndef _ZDB_DYNUPDATE_H
#define	_ZDB_DYNUPDATE_H
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include <dnscore/output_stream.h>
#include <dnscore/packet_reader.h>

#include <dnsdb/zdb_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif

#define HAS_DYNUPDATE_DIFF_ENABLED 1


/*
 * HOWTO :
 *
 * Get the query, and determine it's a dynupdate
 * Call dynupdate_check_prerequisites to verify the update is allowed
 * If OK Call dynupdate_update on dryrun mode to verify the update should run
 * smoothly
 *   if OK Save the query on a permanent storage to recover it in case of crash
 * Answer to the querier
 * Call dynupdate_update on run mode (dryrun = FALSE)
 *
 * The result is
 * 
 * either the number of bytes read from the buffer
 * either an encapsulated server error code retrievable with SERVER_ERROR_GETCODE(error)
 *
 */

ya_result dynupdate_check_prerequisites(zdb_zone* zone, packet_unpack_reader_data *reader, u16 count);

#ifdef	__cplusplus
}
#endif

#endif	/* _ZDB_DYNUPDATE_H */

/** @} */
