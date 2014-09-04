/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
/** @defgroup dnspacket DNS Messages
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef _PACKET_READER_H
#define	_PACKET_READER_H

#include <dnscore/sys_types.h>
#include <dnscore/host_address.h>

#ifdef	__cplusplus
extern "C"
{
#endif

/* dynupdate */

/* reads and unpack */

typedef struct packet_unpack_reader_data packet_unpack_reader_data;


struct packet_unpack_reader_data
{
    const u8* packet;
    u32 packet_size;
    u32 offset;
};

ya_result packet_reader_read_record(packet_unpack_reader_data* reader, u8 *output_buffer, u32 len);

ya_result packet_reader_read_fqdn(packet_unpack_reader_data* reader, u8 *output_buffer, u32 len);

ya_result packet_reader_read(packet_unpack_reader_data* reader, void *output_buffer, u32 len);

ya_result packet_reader_read_u16(packet_unpack_reader_data* reader, u16 *val);
ya_result packet_reader_read_u32(packet_unpack_reader_data* reader, u32 *val);

static inline ya_result packet_reader_skip(packet_unpack_reader_data* reader, u32 len)
{
    if((reader->offset += len) > reader->packet_size)
    {
        reader->offset = reader->packet_size;
	
        return UNEXPECTED_EOF;	/* unexpected EOF */
    }

    return len;
}

/* fqdn + type + class */
ya_result packet_reader_read_zone_record(packet_unpack_reader_data* reader, u8* output_buffer, u32 len);

/* fqdn + type + class + ttl + size + rdata */


void packet_reader_rewind(packet_unpack_reader_data* reader);

ya_result packet_reader_skip_fqdn(packet_unpack_reader_data* reader);
ya_result packet_reader_skip_record(packet_unpack_reader_data* reader);

void packet_reader_init(packet_unpack_reader_data* reader, const u8* buffer, u32 buffer_size);

/* two tools functions for the controller */

ya_result packet_reader_read_utf8(packet_unpack_reader_data *reader, u16 rdatasize, u16 rclass, char **txt, bool dryrun);

ya_result packet_reader_read_remote_server(packet_unpack_reader_data *reader, u16 rdatasize, u16 rclass, host_address **ha, bool dryrun);

#ifdef	__cplusplus
}
#endif

#endif	/* _PACKET_READER_H */
/** @} */

/*----------------------------------------------------------------------------*/

