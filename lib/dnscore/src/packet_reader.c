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
* DOCUMENTATION */
/** @defgroup dnspacket DNS Messages
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "dnscore/packet_reader.h"
#include "dnscore/rfc.h"

ya_result
packet_reader_read_fqdn(packet_unpack_reader_data* reader, u8* output_buffer, u32 len_)
{
    const u8* p_limit = &reader->packet[reader->packet_size];

    u8* buffer = output_buffer;
    u8* buffer_limit = &buffer[len_];
    const u8* p = &reader->packet[reader->offset];

    if(p >= p_limit)
    {
        return UNEXPECTED_EOF; /* EOF */
    }

    for(;;)
    {
        u8 len = *p++;

        if((len & 0xc0) == 0xc0)
        {
            reader->offset = p - reader->packet;

            /* reposition the pointer */
            u32 new_offset = len & 0x3f;
            new_offset <<= 8;
            new_offset |= *p;

            p = &reader->packet[new_offset];

            reader->offset++;

            break;
        }

        *buffer++ = len;

        if(len == 0)
        {
            reader->offset = p - reader->packet;
            return buffer - output_buffer;
        }

        if((p + len > p_limit) || (buffer + len > buffer_limit))
        {
            return UNEXPECTED_EOF;
        }
        /*
        MEMCOPY(buffer, p, len);
        buffer += len;
        p += len;
        */
        u8* buffer_limit = &buffer[len];
        do
        {
            *buffer++ = tolower(*p++);
        }
        while(buffer < buffer_limit);
    }

    for(;;)
    {
        u8 len = *p++;

        if((len & 0xc0) == 0xc0) /* EDF: better yet: cmp len, 192; jge  */
        {
            /* reposition the pointer */
            u32 new_offset = len & 0x3f;
            new_offset <<= 8;
            new_offset |= *p;

            p = &reader->packet[new_offset];

            continue;
        }

        *buffer++ = len;

        if(len == 0)
        {
            return buffer - output_buffer;
        }

        if((p + len > p_limit) || (buffer + len > buffer_limit))
        {
            return UNEXPECTED_EOF;
        }

        u8* buffer_limit = &buffer[len];
        do
        {
            *buffer++ = tolower(*p++);
        }
        while(buffer < buffer_limit);
    }
}

ya_result
packet_reader_read(packet_unpack_reader_data* reader, u8* output_buffer, u32 len)
{
    u32 remaining = reader->packet_size - reader->offset;

    if(remaining < len)
    {
        len = remaining;
    }

    MEMCOPY(output_buffer, &reader->packet[reader->offset], len);

    reader->offset += len;

    return len;
}

ya_result
packet_reader_read_u16(packet_unpack_reader_data* reader, u16 *val)
{
    zassert(val != NULL);

    u32 remaining = reader->packet_size - reader->offset;

    if(remaining < 2)
    {
        return UNEXPECTED_EOF;
    }

    *val = GET_U16_AT(reader->packet[reader->offset]);
    reader->offset += 2;

    return 2;
}

ya_result
packet_reader_read_u32(packet_unpack_reader_data* reader, u32 *val)
{
    zassert(val != NULL);
    
    u32 remaining = reader->packet_size - reader->offset;

    if(remaining < 4)
    {
        return UNEXPECTED_EOF;
    }

    *val = GET_U32_AT(reader->packet[reader->offset]);
    reader->offset += 4;

    return 4;
}

ya_result
packet_reader_read_zone_record(packet_unpack_reader_data* reader, u8* output_buffer, u32 len)
{
    ya_result err;

    u8* buffer = output_buffer;

    /* Read the name */

    if(FAIL(err = packet_reader_read_fqdn(reader, buffer, len)))
    {
        return err;
    }

    buffer += err;
    len -= err;

    if(len < 4)
    {
        return UNEXPECTED_EOF;
    }

    /* read the TYPE CLASS TTL RDATASIZE (4 bytes) */

    if(FAIL(err = packet_reader_read(reader, buffer, 4)))
    {
        return err;
    }

    zassert(err == 4);

    buffer += 4;

    return buffer - output_buffer;
}

/**
 * @note DOES NOT AND SHOULD NOT WORK FOR CTRL TYPES !
 */

ya_result
packet_reader_read_record(packet_unpack_reader_data* reader, u8* output_buffer, u32 len)
{
    ya_result err;

    u8* buffer = output_buffer;

    /* Read the name */

    if(FAIL(err = packet_reader_read_fqdn(reader, buffer, len)))
    {
        return err;
    }

    buffer += err;
    len -= err;

    if(len < 10)
    {
        return UNEXPECTED_EOF;
    }

    /* read the TYPE CLASS TTL RDATASIZE (10 bytes) */

    if(FAIL(err = packet_reader_read(reader, buffer, 10)))
    {
        return err;
    }

    zassert(err == 10);

    u16 size = ntohs(GET_U16_AT(buffer[8]));

    if(len < size)
    {
        return UNEXPECTED_EOF;
    }

    if(size == 0)   /* Can occur for dynupdate record set delete */
    {
        return (buffer - output_buffer) + 10;
    }

    u16 type = (GET_U16_AT(buffer[0])); /** @note : NATIVETYPE */

    buffer += 10;

    /*
     * EDF: No need to cut the len short, especially since what is returned
     * by the fqdn readers is the output side, not the input one (unpack)
     */

    u8* rdata_start = buffer;
    u32 rdata_limit = reader->offset + size;

    switch(type)
    {
        /******************************************************************************
         * The types that requires special handling (dname compression)
         ******************************************************************************/

        case TYPE_MX:
        {
            if((err = packet_reader_read(reader, buffer, 2)) != 2)
            {
                return INVALID_RECORD;
            }

            buffer += err;
            len -= err;
            size -= err;
            
            if(len == 0 || size > MAX_DOMAIN_LENGTH)
            {
                return INVALID_RECORD;      /* wrong size */
            }

            if(FAIL(err = packet_reader_read_fqdn(reader, buffer, len)))
            {
                return err;
            }

            buffer += err;

            break;
        }
        case TYPE_NS:
        case TYPE_CNAME:
        case TYPE_DNAME:
        case TYPE_PTR:
        case TYPE_MB:
        case TYPE_MD:
        case TYPE_MF:
        case TYPE_MG:
        case TYPE_MR:
        {
            /* ONE NAME record */
            
            if(size == 0 || size > MAX_DOMAIN_LENGTH)
            {
                return INVALID_RECORD;      /* wrong size */
            }

            if(FAIL(err = packet_reader_read_fqdn(reader, buffer, len)))
            {
                return err;
            }

            buffer += err;

            break;
        }
        case TYPE_SOA:
        {
            /* NOTE: NO NEED TO SORT (There is only one) */
            if(FAIL(err = packet_reader_read_fqdn(reader, buffer, len)))
            {
                return err;
            }

            buffer += err;
            len -= err;

            if(FAIL(err = packet_reader_read_fqdn(reader, buffer, len)))
            {
                return err;
            }

            if(rdata_limit - reader->offset != 20)
            {
                err = UNEXPECTED_EOF;
                break;
            }

            buffer += err;
            len -= err;

            if(FAIL(err = packet_reader_read(reader, buffer, 20)))
            {
                return err;
            }

            buffer += err;

            break;
        }
        case TYPE_RRSIG:    /* not supposed to be compressed */
        {
            if(size > 2+1+1+4+4+4+2+256+1024+4)
            {
                return UNSUPPORTED_RECORD;    /* too big */
            }

            if(size < 18)
            {
                err = UNEXPECTED_EOF;
                break;
            }

            if(FAIL(err = packet_reader_read(reader, buffer, 18)))
            {
                return err;
            }

            buffer += err;
            len -= err;

            if(FAIL(err = packet_reader_read_fqdn(reader, buffer, len)))
            {
                return err;
            }

            buffer += err;
            len -= err;

            if(FAIL(err = packet_reader_read(reader, buffer, rdata_limit - reader->offset)))
            {
                return err;
            }

            buffer += err;

            break;
        }
        case TYPE_NSEC: /* not supposed to be compressed */
        {
            if(FAIL(err = packet_reader_read_fqdn(reader, buffer, len)))
            {
                return err;
            }

            buffer += err;
            len -= err;

            if(FAIL(err = packet_reader_read(reader, buffer, rdata_limit - reader->offset)))
            {
                return err;
            }

            buffer += err;

            break;
        }
        
        /******************************************************************************
         * The types we reject
         ******************************************************************************/

        case TYPE_SIG:
        {
            if(size > 1024)
            {
                return UNSUPPORTED_RECORD;    /* key is too big */
            }
            
            if(FAIL(err = packet_reader_skip(reader, size)))
            {
                return err;
            }

            buffer += err;

            return UNSUPPORTED_TYPE;
        }
        case TYPE_A6:
        {
            if(size > 1+16+256)
            {
                return UNSUPPORTED_RECORD;    /* key is too big */
            }
            
            if(FAIL(err = packet_reader_skip(reader, size)))
            {
                return err;
            }

            buffer += err;

            return UNSUPPORTED_TYPE;
        }
        case TYPE_ASFDB:
        {
            if(size > 260)
            {
                return UNSUPPORTED_RECORD;    /* key is too big */
            }

            if(FAIL(err = packet_reader_skip(reader, size)))
            {
                return err;
            }

            buffer += err;

            return UNSUPPORTED_TYPE;

            /******************************************************************************
             * The other types
             ******************************************************************************/
        }
        case TYPE_A:
        {
            if(size != 4)
            {
                return INCORRECT_IPADDRESS;
            }

            if(FAIL(err = packet_reader_read(reader, buffer, size)))
            {
                return err;
            }

            buffer += err;
            break;
        }
        case TYPE_AAAA:
        {
            if(size != 16)
            {
                return INCORRECT_IPADDRESS;
            }

            if(FAIL(err = packet_reader_read(reader, buffer, size)))
            {
                return err;
            }

            buffer += err;
            break;
        }
            /*
        case TYPE_HINFO:
        case TYPE_MINFO:
        case TYPE_DS:
        case TYPE_TXT:
        case TYPE_WKS:
        case TYPE_DNSKEY:
        case TYPE_NSEC3:
        case TYPE_NSEC3PARAM:
        case TYPE_LOC:
            */
        default:
        {
            if(FAIL(err = packet_reader_read(reader, buffer, size)))
            {
                return err;
            }

            buffer += err;
            break;
        }
    }
    
    if(rdata_limit != reader->offset)
    {
        return UNEXPECTED_EOF;
    }

    SET_U16_AT(rdata_start[-2], htons(buffer - rdata_start)); /* rdata size */

    /*
     * This len was the rdata_size but this was the packed size.
     * So I cannot compare without a relatively expensive test
     * zassert(len == 0);
     *
     */

    return buffer - output_buffer;
}

void
packet_reader_rewind(packet_unpack_reader_data* reader)
{
    reader->offset = 0;
}

/*
 * Skip a compressed fqdn
 */

ya_result
packet_reader_skip_fqdn(packet_unpack_reader_data* reader)
{
    /* Testing for a minimum len size is pointless */

    u32 from = reader->offset;

    const u8* p_limit = &reader->packet[reader->packet_size];

    const u8* p = &reader->packet[reader->offset];

    if(p >= p_limit)
    {
        return UNEXPECTED_EOF; /* EOF */
    }

    for(;;)
    {
        u8 len = *p++;

        if((len & 0xc0) == 0xc0)
        {
            p++;
            reader->offset = p - reader->packet;
            return reader->offset - from;
        }

        if(len == 0)
        {
            reader->offset = p - reader->packet;
            return reader->offset - from;
        }

        if(p + len > p_limit)
        {
            return UNEXPECTED_EOF;
        }

        p += len;
    }
}

/*
 * Skip a record
 */

ya_result
packet_reader_skip_record(packet_unpack_reader_data* reader)
{
    ya_result err;
    ya_result from = reader->offset;

    /* Read the name */

    if(FAIL(err = packet_reader_skip_fqdn(reader)))
    {
        return err;
    }

    /* read the TYPE CLASS TTL RDATASIZE (10 bytes) */

    u16 size = ntohs(GET_U16_AT(reader->packet[reader->offset + 8]));

    reader->offset += 10;
    reader->offset += size;

    if(reader->offset > reader->packet_size)
    {
        return UNEXPECTED_EOF;
    }

    /*
     * This len was the rdata_size but this was the packed size.
     * So I cannot compare without a relatively expensive test
     * zassert(len == 0);
     *
     */

    return reader->offset - from;
}

void
packet_reader_init(u8* buffer, u32 buffer_size, packet_unpack_reader_data* reader)
{
    reader->packet = buffer;
    reader->packet_size = buffer_size;

    reader->offset = 0;
}

/** @} */

/*----------------------------------------------------------------------------*/

