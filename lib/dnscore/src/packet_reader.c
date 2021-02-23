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

/** @defgroup dnspacket DNS Messages
 *  @ingroup dnscore
 *  @brief
 *
 *
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "dnscore/dnscore-config.h"
#include "dnscore/packet_reader.h"
//#include "dnscore/rfc.h"
#include "dnscore/tsig.h"

#if HAS_CTRL
#include "dnscore/ctrl-rfc.h"
#endif

#define TMP00003_TAG 0x3330303030504d54

ya_result
packet_reader_read_fqdn(packet_unpack_reader_data* reader, u8 *output_buffer, u32 len_)
{
    const u8                *p_limit = &reader->packet[reader->packet_size];

    u8                                              *buffer = output_buffer;
    u8                                        *buffer_limit = &buffer[len_];
    const u8                           *p = &reader->packet[reader->offset];

    /*    ------------------------------------------------------------    */ 

    if(p >= p_limit)
    {
        return UNEXPECTED_EOF; /* EOF */
    }

    for(;;)
    {
        u8 len = *p++;

        if((len & 0xc0) == 0xc0)
        {
            if(p >= p_limit)
            {
                return UNEXPECTED_EOF; /* EOF */
            }

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

        if(p + len >= p_limit)
        {
            return UNEXPECTED_EOF;
        }

        if(buffer + len >= buffer_limit)
        {
            return BUFFER_WOULD_OVERFLOW;
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
        u8 len = *p;

        if((len & 0xc0) == 0xc0) /* EDF: better yet: cmp len, 192; jge  */
        {
            /* reposition the pointer */
            u32 new_offset = len & 0x3f;
            new_offset <<= 8;
            new_offset |= p[1];

            const u8* q = &reader->packet[new_offset];
            
            if(q < p)
            {
                p = q;
                continue;
            }
            
            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }

        *buffer++ = len;

        if(len == 0)
        {
            return buffer - output_buffer;
        }
        
        ++p;

        if(p + len >= p_limit)
        {
            return UNEXPECTED_EOF;
        }

        if(buffer + len >= buffer_limit)
        {
            return BUFFER_WOULD_OVERFLOW;
        }

        u8* buffer_limit = &buffer[len];
        
        do
        {
            *buffer++ = tolower(*p++);
        }
        while(buffer < buffer_limit);
    }
    
    // never reached
}

ya_result
packet_reader_read(packet_unpack_reader_data* reader, void *output_buffer, u32 len)
{
    u32 remaining = reader->packet_size - reader->offset;

    if(remaining >= len)
    {
        MEMCOPY(output_buffer, &reader->packet[reader->offset], len);
        reader->offset += len;

        return len;
    }
    else
    {
        return UNEXPECTED_EOF;
    }
}

ya_result
packet_reader_read_u16(packet_unpack_reader_data* reader, u16 *val)
{
    yassert(val != NULL);

    u32 remaining = reader->packet_size - reader->offset;

    if(remaining >= 2)
    {
        *val = GET_U16_AT(reader->packet[reader->offset]);
        reader->offset += 2;
        return 2;
    }
    else
    {
        return UNEXPECTED_EOF;
    }
}

ya_result
packet_reader_read_dnstype(packet_unpack_reader_data* reader)
{
    u32 remaining = reader->packet_size - reader->offset;

    if(remaining >= 2)
    {
        u16 dnstype = GET_U16_AT(reader->packet[reader->offset]);
        reader->offset += 2;
        return dnstype;
    }
    else
    {
        return UNEXPECTED_EOF;
    }
}

ya_result
packet_reader_read_dnsclass(packet_unpack_reader_data* reader)
{
    u32 remaining = reader->packet_size - reader->offset;

    if(remaining >= 2)
    {
        u16 dnsclass = GET_U16_AT(reader->packet[reader->offset]);
        reader->offset += 2;
        return dnsclass;
    }
    else
    {
        return UNEXPECTED_EOF;
    }
}

ya_result
packet_reader_skip_query(packet_unpack_reader_data* reader, const u8 *domain, u16 dnstype, u16 dnsclass)
{
    ya_result ret;
    u8 fqdn[MAX_DOMAIN_LENGTH];
    if(ISOK(ret = packet_reader_read_fqdn(reader, fqdn, sizeof(fqdn))))
    {
        if(dnsname_equals_ignorecase(domain, fqdn))
        {
            if(FAIL(ret = packet_reader_read_dnstype(reader)))
            {
                return ret;
            }

            if(ret != dnstype)
            {
                return MESSAGE_UNEXPECTED_ANSWER_TYPE_CLASS;
            }

            if(FAIL(ret = packet_reader_read_dnsclass(reader)))
            {
                return ret;
            }

            if(ret != dnsclass)
            {
                return MESSAGE_UNEXPECTED_ANSWER_TYPE_CLASS;
            }
        }
        else
        {
            return MESSAGE_UNEXPECTED_ANSWER_DOMAIN;
        }
    }

    return ret;
}

ya_result
packet_reader_read_u32(packet_unpack_reader_data* reader, u32 *val)
{
    yassert(val != NULL);
    
    u32 remaining = reader->packet_size - reader->offset;

    if(remaining >= 4)
    {
        *val = GET_U32_AT(reader->packet[reader->offset]);
        reader->offset += 4;
        return 4;
    }
    else
    {
        return UNEXPECTED_EOF;
    }
}

ya_result
packet_reader_read_zone_record(packet_unpack_reader_data* reader, u8* output_buffer, u32 buffer_size)
{
    ya_result ret;

    u8* buffer = output_buffer;

    /* Read the name */

    if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, buffer_size)))
    {
        return ret;
    }

    buffer += ret;
    buffer_size -= ret;

    if(buffer_size >= 4)
    {
        /* read the TYPE CLASS (4 bytes) */

        if(FAIL(ret = packet_reader_read(reader, buffer, 4))) // exact
        {
            return ret;
        }

        yassert(ret == 4);

        buffer += 4;

        return buffer - output_buffer;
    }
    else
    {
        return UNEXPECTED_EOF;
    }
}

ya_result
packet_reader_skip_zone_record(packet_unpack_reader_data* reader)
{
    u32 from = reader->offset;
    ya_result  ret;

    /* Read the name */

    if(FAIL(ret = packet_reader_skip_fqdn(reader)))
    {
        return ret;
    }

    /* read the TYPE CLASS TTL RDATASIZE (4 bytes) */

    if(FAIL(ret = packet_reader_skip(reader, 4)))
    {
        return ret;
    }

    return reader->offset - from;
}

ya_result
packet_reader_skip_query_section(packet_unpack_reader_data* reader)
{
    u32 from = reader->offset;
    u16 records = ntohs(MESSAGE_SECTION_COUNT(reader->packet, 0));

    while(records > 0)
    {
        ya_result ret = packet_reader_skip_zone_record(reader);
        if(FAIL(ret))
        {
            return ret;
        }

        --records;
    }

    return reader->offset - from;
}

ya_result
packet_reader_skip_section(packet_unpack_reader_data* reader, int section)
{
    switch(section)
    {
        case 0:
        {
            ya_result ret = packet_reader_skip_query_section(reader);
            return ret;
        }
        case 1:
        case 2:
        case 3:
        {
            s32 from = reader->offset;
            u16 records = MESSAGE_SECTION_COUNT(reader->packet, section);

            while(records > 0)
            {
                ya_result ret = packet_reader_skip_record(reader);
                if(FAIL(ret))
                {
                    return ret;
                }

                --records;
            }

            return reader->offset - from;
        }
        default:
            return INVALID_ARGUMENT_ERROR;
    }
}


ya_result
packet_reader_read_rdata(packet_unpack_reader_data* reader, u16 type, u32 rdata_size, u8 *buffer, u32 buffer_size)
{
    u8* rdata_start = buffer;
    const u32 rdata_limit = reader->offset + rdata_size; // without compression, this is where the rdata ends + 1 byte
    ya_result ret;

    if(packet_reader_available(reader) < rdata_size)
    {
        return UNEXPECTED_EOF;
    }

    switch(type)
    {
        /******************************************************************************
         * The types that requires special handling (dname compression)
         ******************************************************************************/

        case TYPE_MX:
        case TYPE_AFSDB:
        {
            packet_reader_read_unchecked(reader, buffer, 2); // exact
            buffer += 2;
            buffer_size -= 2;
            rdata_size -= 2;
            
            if(buffer_size == 0 || rdata_size > MAX_DOMAIN_LENGTH)
            {
                return INVALID_RECORD;      /* wrong size */
            }

            if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, buffer_size))) /* err = error code or bytes filled, not bytes read (compression) */
            {
                return ret;
            }

            buffer += ret;

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
            
            if(rdata_size == 0 || rdata_size > MAX_DOMAIN_LENGTH)
            {
                return INVALID_RECORD;      /* wrong size */
            }

            if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, buffer_size)))
            {
                return ret;
            }

            buffer += ret;

            break;
        }
        case TYPE_SOA:
        {
            /* NOTE: NO NEED TO SORT (There is only one) */
            if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, buffer_size)))
            {
                return ret;
            }

            buffer += ret;
            buffer_size -= ret;

            if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, buffer_size)))
            {
                return ret;
            }

            if(rdata_limit - reader->offset != 20)
            {
                return INVALID_RECORD;
            }

            buffer_size -= ret;
            if(buffer_size < 20)
            {
                return BUFFER_WOULD_OVERFLOW;
            }

            buffer += ret;
            //len -= err;

            packet_reader_read_unchecked(reader, buffer, 20); // exact

            buffer += 20;

            break;
        }
        case TYPE_RRSIG:    /* not supposed to be compressed */
        {
            if(rdata_size > 2+1+1+4+4+4+2+256+1024+4)
            {
                return UNSUPPORTED_RECORD;    /* too big */
            }

            if(rdata_size < RRSIG_RDATA_HEADER_LEN)
            {
                return INVALID_RECORD;
            }

            packet_reader_read_unchecked(reader, buffer, RRSIG_RDATA_HEADER_LEN); // exact

            buffer += RRSIG_RDATA_HEADER_LEN;
            buffer_size -= RRSIG_RDATA_HEADER_LEN;

            if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, buffer_size)))
            {
                return ret;
            }

            buffer += ret;

            if(FAIL(ret = packet_reader_read(reader, buffer, rdata_limit - reader->offset))) // exact
            {
                return ret;
            }

            buffer += ret;

            break;
        }
        case TYPE_NSEC: /* not supposed to be compressed */
        {
            if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, buffer_size)))
            {
                return ret;
            }

            buffer += ret;
            //len -= err;
            
            if(rdata_limit - reader->offset == 0)
            {
                return INVALID_RECORD; // record is broken
            }

            if(FAIL(ret = packet_reader_read(reader, buffer, rdata_limit - reader->offset))) // exact
            {
                return ret;
            }

            buffer += ret;

            break;
        }
        
        /******************************************************************************
         * The types we reject
         ******************************************************************************/

        case TYPE_SIG:
        {
            if(rdata_size > 1024)
            {
                return UNSUPPORTED_RECORD;    /* key is too big */
            }
            
            packet_reader_skip_unchecked(reader, rdata_size);

            return UNSUPPORTED_TYPE;
        }
        case TYPE_A6:
        {
            if(rdata_size > 1+16+256)
            {
                return UNSUPPORTED_RECORD;    /* key is too big */
            }
            
            packet_reader_skip_unchecked(reader, rdata_size);

            return UNSUPPORTED_TYPE;
        }
        
        /******************************************************************************
         * The other types
         ******************************************************************************/

        case TYPE_A:
        {
            if(rdata_size != 4)
            {
                return INCORRECT_IPADDRESS;
            }

            packet_reader_read_unchecked(reader, buffer, 4); // exact

            buffer += 4;
            break;
        }
        case TYPE_AAAA:
        {
            if(rdata_size != 16)
            {
                return INCORRECT_IPADDRESS;
            }

            packet_reader_read_unchecked(reader, buffer, 16); // exact

            buffer += 16;
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
            packet_reader_read_unchecked(reader, buffer, rdata_size); // exact
            buffer += rdata_size;
            break;
        }
    }
    
    if(rdata_limit != reader->offset)
    {
        return UNEXPECTED_EOF;
    }
    
    return buffer - rdata_start;
}

/**
 * @note DOES NOT AND SHOULD NOT WORK FOR CTRL TYPES !
 */

ya_result
packet_reader_read_record(packet_unpack_reader_data* reader, u8* output_buffer, u32 len)
{
    ya_result ret;

    u8* buffer = output_buffer;

    /* Read the name */

    if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, len)))
    {
        return ret;
    }

    buffer += ret;
    len -= ret;

    if(len < 10)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    /* read the TYPE CLASS TTL RDATASIZE (10 bytes) */

    ret = packet_reader_read(reader, buffer, 10); // exact
    
    if(FAIL(ret))
    {
        return ret;
    }
/*
 *  ret always return either what was asked, either unexpected eof
 *  if(ret != 10)
 *  {
 *       return UNEXPECTED_EOF;
 *  }
 */
    u16 rdata_size = ntohs(GET_U16_AT(buffer[8]));

    if(rdata_size == 0)   /* Can occur for dynupdate record set delete */
    {
        return (buffer - output_buffer) + 10;
    }

    if(len < rdata_size)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    if(packet_reader_available(reader) < rdata_size)
    {
        return UNEXPECTED_EOF;
    }

    u16 rtype = (GET_U16_AT(buffer[0])); /** @note : NATIVETYPE */

    buffer += 10;

    /*
     * EDF: No need to cut the len short, especially since what is returned
     * by the fqdn readers is the output side, not the input one (unpack)
     */

    u8* rdata_start = buffer;
    u32 rdata_limit = reader->offset + rdata_size;

    switch(rtype)
    {
        /******************************************************************************
         * The types that requires special handling (dname compression)
         ******************************************************************************/

        case TYPE_MX:
        case TYPE_AFSDB:
        {
            packet_reader_read_unchecked(reader, buffer, 2); // exact

            buffer += 2;
            len -= 2;
            rdata_size -= 2;
            
            if(len == 0 || rdata_size > MAX_DOMAIN_LENGTH)
            {
                return INVALID_RECORD;      /* wrong rdata_size */
            }

            if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, len))) /* err = error code or bytes filled, not bytes read (compression) */
            {
                return ret;
            }

            buffer += ret;

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
            
            if((rdata_size == 0) || (rdata_size > MAX_DOMAIN_LENGTH))
            {
                return INVALID_RECORD;      /* wrong rdata_size */
            }

            if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, len)))
            {
                return ret;
            }

            buffer += ret;

            break;
        }
        case TYPE_SOA:
        {
            /* NOTE: NO NEED TO SORT (There is only one) */
            if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, len)))
            {
                return ret;
            }

            buffer += ret;
            len -= ret;

            if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, len)))
            {
                return ret;
            }

            if(rdata_limit - reader->offset != 20)
            {
                return INVALID_RECORD;
            }

            len -= ret;
            if(len < 20)
            {
                return BUFFER_WOULD_OVERFLOW;
            }

            buffer += ret;
            //len -= err;

            packet_reader_read_unchecked(reader, buffer, 20); // exact

            buffer += 20;

            break;
        }
        case TYPE_RRSIG:    /* not supposed to be compressed */
        {
            if(rdata_size > 2+1+1+4+4+4+2+256+1024+4)
            {
                return UNSUPPORTED_RECORD;    /* too big */
            }

            if(rdata_size < RRSIG_RDATA_HEADER_LEN)
            {
                return UNEXPECTED_EOF;
            }

            packet_reader_read_unchecked(reader, buffer, RRSIG_RDATA_HEADER_LEN); // exact

            buffer += RRSIG_RDATA_HEADER_LEN;
            len -= RRSIG_RDATA_HEADER_LEN;

            if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, len)))
            {
                return ret;
            }

            buffer += ret;

            if(FAIL(ret = packet_reader_read(reader, buffer, rdata_limit - reader->offset))) // exact
            {
                return ret;
            }

            buffer += ret;

            break;
        }
        case TYPE_NSEC: /* not supposed to be compressed */
        {
            if(FAIL(ret = packet_reader_read_fqdn(reader, buffer, len)))
            {
                return ret;
            }

            buffer += ret;
            //len -= err;
            
            if(rdata_limit - reader->offset == 0)
            {
                return INVALID_RECORD; // record is broken
            }

            if(FAIL(ret = packet_reader_read(reader, buffer, rdata_limit - reader->offset))) // exact
            {
                return ret;
            }

            buffer += ret;

            break;
        }
        
        /******************************************************************************
         * The types we reject
         ******************************************************************************/

        case TYPE_SIG:
        {
            if(rdata_size > 1024)
            {
                return UNSUPPORTED_RECORD;    /* key is too big */
            }
            
            packet_reader_skip_unchecked(reader, rdata_size);

            //buffer += err;

            return UNSUPPORTED_TYPE;
        }
        case TYPE_A6:
        {
            if(rdata_size > 1+16+256)
            {
                return UNSUPPORTED_RECORD;    /* key is too big */
            }
            
            packet_reader_skip_unchecked(reader, rdata_size);

            return UNSUPPORTED_TYPE;
        }
        
        /******************************************************************************
         * The other types
         ******************************************************************************/

        case TYPE_A:
        {
            if(rdata_size != 4)
            {
                return INCORRECT_IPADDRESS;
            }

            packet_reader_read_unchecked(reader, buffer, 4); // exact
            buffer += 4;

            break;
        }
        case TYPE_AAAA:
        {
            if(rdata_size != 16)
            {
                return INCORRECT_IPADDRESS;
            }

            packet_reader_read_unchecked(reader, buffer, 16); // exact

            buffer += 16;
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
            packet_reader_read_unchecked(reader, buffer, rdata_size); // exact
            buffer += rdata_size;
            break;
        }
    }
    
    if(rdata_limit != reader->offset)
    {
        return UNEXPECTED_EOF;
    }

    SET_U16_AT(rdata_start[-2], htons(buffer - rdata_start)); /* rdata rdata_size */

    /*
     * This len was the rdata_size but this was the packed rdata_size.
     * So I cannot compare without a relatively expensive test
     * yassert(len == 0);
     *
     */

    return buffer - output_buffer;
}

ya_result
packet_reader_read_dns_resource_record(packet_unpack_reader_data* reader, dns_resource_record *rr)
{

    ya_result ret;

    if(ISOK(ret = packet_reader_read_fqdn(reader, rr->name, sizeof(rr->name))))
    {
        rr->name_len = ret;
        if(ISOK(ret = packet_reader_read(reader, &rr->tctr, 10)))
        {
            u16 rdata_size = ntohs(rr->tctr.rdlen);
            dns_resource_record_ensure_size(rr, rdata_size);
            rr->rdata_size = rdata_size;
            u32 offset = reader->offset;
            while((ret = packet_reader_read_rdata(reader, rr->tctr.qtype, rdata_size, rr->rdata, rr->rdata_buffer_size)) == BUFFER_WOULD_OVERFLOW)
            {
                dns_resource_record_ensure_size(rr, MIN((MAX_DOMAIN_LENGTH + 7) & ~7, MAX(rr->rdata_buffer_size * 2, 65535)));
                reader->offset = offset;
            }
        }
    }

    return ret;
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

        if(p + len >= p_limit)
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
     * yassert(len == 0);
     *
     */

    return reader->offset - from;
}

#if HAS_CTRL

/**
 * 
 * Returns true iff the string txt is utf-8
 * The current implementation checks it's ASCII7 (which is a valid subset of utf-8)
 * 
 * @param txt
 * @param len
 * @return 
 */

static bool
is_utf8(const char *txt, u16 len)
{
    for(u16 i = 0; i < len; i++)
    {
        if((txt[i] & 0x80) != 0)
        {
            return FALSE;
        }
    }
    
    return TRUE;
}

/**
 * 
 * @note Yes, this COULD go in the message.* files, once they are finalised
 * 
 * @param reader
 * @param rdatasize
 * @param rclass
 * @param txt
 * @param dryrun
 * @return 
 */

ya_result
packet_reader_read_utf8(packet_unpack_reader_data *reader, u16 rdatasize, u16 rclass, char **txt, bool dryrun)
{
    char *tmp = NULL;
    ya_result return_value;
    
    if(rclass == CLASS_ANY)
    {
        if(rdatasize != 0)
        {
            return RCODE_ERROR_CODE(RCODE_FORMERR); /* formerr */
        }
        
        if(!dryrun)
        {
            free(*txt);
            *txt = NULL;
        }

        return_value = SUCCESS;
    }
    else
    {
        MALLOC_OR_DIE(char *, tmp, rdatasize + 1, TMP00003_TAG);
        packet_reader_read(reader, (u8*)tmp, rdatasize);
        tmp[rdatasize] = '\0';

        if(is_utf8(tmp, rdatasize))
        {
            return_value = SUCCESS;

            if(!dryrun)
            {
                if(rclass != CLASS_NONE)
                {
                    if(*txt != NULL)
                    {
                        free(*txt);
                    }

                    *txt = tmp;
                    tmp = NULL;
                }
                else
                {
                    if(*txt != NULL)
                    {
                        if(strcmp(*txt, tmp) == 0)
                        {
                            free(*txt);
                            *txt = NULL;
                        }
                    }
                }
            }
        }
        else
        {
            return_value = MAKE_DNSMSG_ERROR(RCODE_FORMERR);
        }

        if(tmp != NULL)
        {                    
            free(tmp);
        }
    }
    
    return return_value;
}

/**
 * 
 * @note Yes, this COULD go in the message.* files, once they are finalised
 * 
 * @param reader
 * @param rdatasize
 * @param rclass
 * @param ha
 * @param dryrun
 * @return 
 */

ya_result
packet_reader_read_remote_server(packet_unpack_reader_data *reader, u16 rdatasize, u16 rclass, host_address **ha, bool dryrun)
{
    u16 ip_port = 0;
    u8 ipver;
    u8 flags;
    
    u8 ip_buffer[16];
    u8 tsig_name[MAX_DOMAIN_LENGTH];
    
    if(rclass == CLASS_ANY)
    {
        if(rdatasize != 0)
        {
            return RCODE_ERROR_CODE(RCODE_FORMERR); /* formerr */
        }
        
        if(!dryrun)
        {
            if(*ha != NULL)
            {
                host_address_delete_list(*ha);
                *ha = NULL;
            }
        }
        
        return SUCCESS;
    }
    
    ya_result return_value;
            
    if(ISOK(return_value = packet_reader_read(reader, &flags, 1)))
    {
        return_value = INVALID_STATE_ERROR;

        ipver = flags & REMOTE_SERVER_FLAGS_IP_MASK;

        if((ipver == HOST_ADDRESS_IPV4) || (ipver == HOST_ADDRESS_IPV6))
        {
            tsig_item *tsig = NULL;

            if(ipver == HOST_ADDRESS_IPV4)
            {
                return_value = packet_reader_read(reader, ip_buffer, 4);
            }
            else
            {
                return_value = packet_reader_read(reader, ip_buffer, 16);
            }
            
            if(FAIL(return_value))
            {
                return return_value;
            }

            if((flags & REMOTE_SERVER_FLAGS_PORT_MASK) != 0)
            {
                if(FAIL(return_value = packet_reader_read_u16(reader, &ip_port)))
                {
                    return return_value;
                }
            }

            if((flags & REMOTE_SERVER_FLAGS_KEY_MASK) != 0)
            {
                if(FAIL(return_value = packet_reader_read_fqdn(reader, tsig_name, sizeof(tsig_name))))
                {
                    return return_value;
                }

                if((tsig = tsig_get(tsig_name)) == NULL)
                {
                    return RCODE_ERROR_CODE(RCODE_BADKEY);
                }                
            }

            if(!dryrun)
            {
                host_address *address;

                MALLOC_OBJECT_OR_DIE(address, host_address, HOSTADDR_TAG);

                address->next = NULL;
                address->tsig = tsig;

                if(ipver == HOST_ADDRESS_IPV4)
                {
                    memcpy(address->ip.v4.bytes, ip_buffer, 4);
                    address->port = ip_port;
                    address->version = HOST_ADDRESS_IPV4;
                }
                else // HOST_ADDRESS_IPV6:
                {
                    memcpy(address->ip.v6.bytes, ip_buffer, 16);
                    address->port = ip_port;
                    address->version = HOST_ADDRESS_IPV6;
                }
                
                /*
                 * Here the rclass changes the behaviour
                 */

                if(rclass != CLASS_NONE)
                {
                    if(*ha == NULL)
                    {
                        *ha = address;
                    }
                    else
                    {
                        host_address_append_host_address(*ha, address); // copy made, or may fail is address is not supported
                        free(address);
                    }
                }
                else
                {
                    host_address_remove_host_address(ha, address); /* not freed */
                    free(address);
                }

                return_value = SUCCESS;
            }
        }
    }
    
    return return_value;
}

#endif

/** @} */
