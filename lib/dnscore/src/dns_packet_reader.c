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
 * @defgroup dnspacket DNS Messages
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#include "dnscore/dnscore_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "dnscore/dnscore_config.h"
#include <dnscore/dns_packet_reader.h>
// #include "dnscore/rfc.h"
#include "dnscore/tsig.h"

#if DNSCORE_HAS_CTRL
#include "dnscore/ctrl_rfc.h"
#endif

#define TMP00003_TAG 0x3330303030504d54

ya_result dns_packet_reader_read_fqdn(dns_packet_reader_t *reader, uint8_t *output_buffer, uint32_t len)
{
    const uint8_t *p_limit = &reader->packet[reader->packet_size];

    uint8_t       *buffer = output_buffer;
    uint8_t       *buffer_limit = &buffer[len];
    const uint8_t *p = &reader->packet[reader->packet_offset];

    /*    ------------------------------------------------------------    */

    if(p >= p_limit)
    {
        reader->packet_offset = reader->packet_size;
        return UNEXPECTED_EOF; /* EOF */
    }

    for(;;)
    {
        uint8_t len = *p++;

        if((len & 0xc0) == 0xc0)
        {
            if(p >= p_limit)
            {
                reader->packet_offset = reader->packet_size;
                return UNEXPECTED_EOF; /* EOF */
            }

            reader->packet_offset = p - reader->packet;

            /* reposition the pointer */
            uint32_t new_offset = len & 0x3f;
            new_offset <<= 8;
            new_offset |= *p;

            const uint8_t *q = &reader->packet[new_offset];

            if(q >= p)
            {
                return RCODE_ERROR_CODE(RCODE_FORMERR);
            }

            p = q;

            reader->packet_offset++;

            break;
        }

        *buffer++ = len;

        if(len == 0)
        {
            reader->packet_offset = p - reader->packet;
            return buffer - output_buffer;
        }

        if(p + len >= p_limit)
        {
            reader->packet_offset = reader->packet_size;
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
        uint8_t *buffer_limit = &buffer[len];
        do
        {
            *buffer++ = tolower(*p++);
        } while(buffer < buffer_limit);
    }

    for(;;)
    {
        uint8_t len = *p;

        if((len & 0xc0) == 0xc0) /* EDF: better yet: cmp len, 192; jge  */
        {
            /* reposition the pointer */
            uint32_t new_offset = len & 0x3f;
            new_offset <<= 8;
            new_offset |= p[1];

            const uint8_t *q = &reader->packet[new_offset];

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
            reader->packet_offset = reader->packet_size;
            return UNEXPECTED_EOF;
        }

        if(buffer + len >= buffer_limit)
        {
            return BUFFER_WOULD_OVERFLOW;
        }

        uint8_t *buffer_limit = &buffer[len];

        do
        {
            *buffer++ = tolower(*p++);
        } while(buffer < buffer_limit);
    }

    // never reached
}

ya_result dns_packet_reader_read(dns_packet_reader_t *reader, void *output_buffer, uint32_t len)
{
    uint32_t remaining = reader->packet_size - reader->packet_offset;

    if(remaining >= len)
    {
        MEMCOPY(output_buffer, &reader->packet[reader->packet_offset], len);
        reader->packet_offset += len;

        return len;
    }
    else
    {
        reader->packet_offset = reader->packet_size;
        return UNEXPECTED_EOF;
    }
}

ya_result dns_packet_reader_read_u16(dns_packet_reader_t *reader, uint16_t *val)
{
    yassert(val != NULL);

    uint32_t remaining = reader->packet_size - reader->packet_offset;

    if(remaining >= 2)
    {
        *val = GET_U16_AT(reader->packet[reader->packet_offset]);
        reader->packet_offset += 2;
        return 2;
    }
    else
    {
        reader->packet_offset = reader->packet_size;
        return UNEXPECTED_EOF;
    }
}

ya_result dns_packet_reader_skip_bytes(dns_packet_reader_t *reader, uint16_t count)
{
    uint32_t remaining = reader->packet_size - reader->packet_offset;

    if(remaining >= count)
    {
        reader->packet_offset += count;
        return count;
    }
    else
    {
        reader->packet_offset = reader->packet_size;
        return UNEXPECTED_EOF;
    }
}

ya_result dns_packet_reader_read_dnstype(dns_packet_reader_t *reader)
{
    uint32_t remaining = reader->packet_size - reader->packet_offset;

    if(remaining >= 2)
    {
        uint16_t dnstype = GET_U16_AT(reader->packet[reader->packet_offset]);
        reader->packet_offset += 2;
        return dnstype;
    }
    else
    {
        reader->packet_offset = reader->packet_size;
        return UNEXPECTED_EOF;
    }
}

ya_result dns_packet_reader_read_dnsclass(dns_packet_reader_t *reader)
{
    uint32_t remaining = reader->packet_size - reader->packet_offset;

    if(remaining >= 2)
    {
        uint16_t dnsclass = GET_U16_AT(reader->packet[reader->packet_offset]);
        reader->packet_offset += 2;
        return dnsclass;
    }
    else
    {
        reader->packet_offset = reader->packet_size;
        return UNEXPECTED_EOF;
    }
}

ya_result dns_packet_reader_skip_query(dns_packet_reader_t *reader, const uint8_t *domain, uint16_t dnstype, uint16_t dnsclass)
{
    ya_result ret;
    uint8_t   fqdn[DOMAIN_LENGTH_MAX];
    if(ISOK(ret = dns_packet_reader_read_fqdn(reader, fqdn, sizeof(fqdn))))
    {
        if(dnsname_equals_ignorecase(domain, fqdn))
        {
            if(FAIL(ret = dns_packet_reader_read_dnstype(reader)))
            {
                return ret;
            }

            if(ret != dnstype)
            {
                return MESSAGE_UNEXPECTED_ANSWER_TYPE_CLASS;
            }

            if(FAIL(ret = dns_packet_reader_read_dnsclass(reader)))
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

ya_result dns_packet_reader_read_u32(dns_packet_reader_t *reader, uint32_t *val)
{
    yassert(val != NULL);

    uint32_t remaining = reader->packet_size - reader->packet_offset;

    if(remaining >= 4)
    {
        *val = GET_U32_AT(reader->packet[reader->packet_offset]);
        reader->packet_offset += 4;
        return 4;
    }
    else
    {
        reader->packet_offset = reader->packet_size;
        return UNEXPECTED_EOF;
    }
}

ya_result dns_packet_reader_read_zone_record(dns_packet_reader_t *reader, uint8_t *output_buffer, uint32_t len)
{
    ya_result ret;

    uint8_t  *buffer = output_buffer;

    /* Read the name */

    if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, len)))
    {
        return ret;
    }

    buffer += ret;
    len -= ret;

    if(len >= 4)
    {
        /* read the TYPE CLASS (4 bytes) */

        if(FAIL(ret = dns_packet_reader_read(reader, buffer, 4))) // exact
        {
            return ret;
        }

        yassert(ret == 4);

        buffer += 4;

        return buffer - output_buffer;
    }
    else
    {
        reader->packet_offset = reader->packet_size;
        return UNEXPECTED_EOF;
    }
}

ya_result dns_packet_reader_skip_zone_record(dns_packet_reader_t *reader)
{
    uint32_t  from = reader->packet_offset;
    ya_result ret;

    /* Read the name */

    if(FAIL(ret = dns_packet_reader_skip_fqdn(reader)))
    {
        return ret;
    }

    /* read the TYPE CLASS TTL RDATASIZE (4 bytes) */

    if(FAIL(ret = dns_packet_reader_skip(reader, 4)))
    {
        return ret;
    }

    return reader->packet_offset - from;
}

ya_result dns_packet_reader_skip_query_section(dns_packet_reader_t *reader)
{
    uint32_t from = reader->packet_offset;
    uint16_t query_record_count = ntohs(MESSAGE_SECTION_COUNT(reader->packet, 0));

    while(query_record_count > 0)
    {
        ya_result ret = dns_packet_reader_skip_zone_record(reader);
        if(FAIL(ret))
        {
            return ret;
        }

        --query_record_count;
    }

    return reader->packet_offset - from;
}

ya_result dns_packet_reader_skip_section(dns_packet_reader_t *reader, int section)
{
    switch(section)
    {
        case 0:
        {
            ya_result ret = dns_packet_reader_skip_query_section(reader);
            return ret;
        }
        case 1:
        case 2:
        case 3:
        {
            int32_t  from = reader->packet_offset;
            uint16_t records = ntohs(MESSAGE_SECTION_COUNT(reader->packet, section));

            while(records > 0)
            {
                ya_result ret = dns_packet_reader_skip_record(reader);
                if(FAIL(ret))
                {
                    return ret;
                }

                --records;
            }

            return reader->packet_offset - from;
        }
        default:
            return INVALID_ARGUMENT_ERROR;
    }
}

ya_result dns_packet_reader_read_rdata(dns_packet_reader_t *reader, uint16_t type, int32_t rdata_size, uint8_t *buffer, int32_t buffer_size)
{
    uint8_t       *rdata_start = buffer;
    const uint32_t rdata_limit = reader->packet_offset + rdata_size; // without compression, this is where the rdata ends + 1 byte
    ya_result      ret;

    if(dns_packet_reader_available(reader) < rdata_size)
    {
        reader->packet_offset = reader->packet_size;
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
            uint8_t *p = buffer;
            buffer += 2;
            buffer_size -= 2;
            rdata_size -= 2;

            if(buffer_size == 0 || rdata_size > DOMAIN_LENGTH_MAX)
            {
                return INVALID_RECORD; /* wrong size */
            }

            dns_packet_reader_read_unchecked(reader, p, 2); // exact

            if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, buffer_size))) /* err = error code or bytes filled, not bytes read (compression) */
            {
                return ret;
            }

            if(dnsname_is_wildcard(buffer))
            {
                return INVALID_RECORD;
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

            if(rdata_size == 0 || rdata_size > DOMAIN_LENGTH_MAX)
            {
                return INVALID_RECORD; /* wrong size */
            }

            if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, buffer_size)))
            {
                return ret;
            }

            if(dnsname_is_wildcard(buffer))
            {
                return INVALID_RECORD;
            }

            buffer += ret;

            break;
        }
        case TYPE_SOA:
        {
            /* NOTE: NO NEED TO SORT (There is only one) */
            if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, buffer_size)))
            {
                return ret;
            }

            if(dnsname_is_wildcard(buffer))
            {
                return INVALID_RECORD;
            }

            buffer += ret;
            buffer_size -= ret;

            if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, buffer_size)))
            {
                return ret;
            }

            if(dnsname_is_wildcard(buffer))
            {
                return INVALID_RECORD;
            }

            if(rdata_limit - reader->packet_offset != 20)
            {
                return INVALID_RECORD;
            }

            buffer_size -= ret;
            if(buffer_size < 20)
            {
                return BUFFER_WOULD_OVERFLOW;
            }

            buffer += ret;
            // len -= err;

            dns_packet_reader_read_unchecked(reader, buffer, 20); // exact

            buffer += 20;

            break;
        }
        case TYPE_SIG:
        case TYPE_RRSIG: /* not supposed to be compressed */
        {
            if(rdata_size > 2 + 1 + 1 + 4 + 4 + 4 + 2 + 256 + 1024 + 4)
            {
                return UNSUPPORTED_RECORD; /* too big */
            }

            if(rdata_size < RRSIG_RDATA_HEADER_LEN)
            {
                return INVALID_RECORD;
            }

            dns_packet_reader_read_unchecked(reader, buffer, RRSIG_RDATA_HEADER_LEN); // exact

            buffer += RRSIG_RDATA_HEADER_LEN;
            buffer_size -= RRSIG_RDATA_HEADER_LEN;

            if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, buffer_size)))
            {
                return ret;
            }

            buffer += ret;

            if(FAIL(ret = dns_packet_reader_read(reader, buffer, rdata_limit - reader->packet_offset))) // exact
            {
                return ret;
            }

            buffer += ret;

            break;
        }
        case TYPE_NSEC: /* not supposed to be compressed */
        {
            if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, buffer_size)))
            {
                return ret;
            }

            buffer += ret;
            // len -= err;

            if(rdata_limit - reader->packet_offset == 0)
            {
                return INVALID_RECORD; // record is broken
            }

            if(FAIL(ret = dns_packet_reader_read(reader, buffer, rdata_limit - reader->packet_offset))) // exact
            {
                return ret;
            }

            buffer += ret;

            break;
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

            dns_packet_reader_read_unchecked(reader, buffer, 4); // exact

            buffer += 4;
            break;
        }
        case TYPE_AAAA:
        {
            if(rdata_size != 16)
            {
                return INCORRECT_IPADDRESS;
            }

            dns_packet_reader_read_unchecked(reader, buffer, 16); // exact

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
            dns_packet_reader_read_unchecked(reader, buffer, rdata_size); // exact // rdata_size has been checked for overflow already
            buffer += rdata_size;
            break;
        }
    }

    if(rdata_limit != reader->packet_offset)
    {
        reader->packet_offset = reader->packet_size;
        return UNEXPECTED_EOF;
    }

    return buffer - rdata_start;
}

/**
 * @note DOES NOT AND SHOULD NOT WORK FOR CTRL TYPES !
 */

ya_result dns_packet_reader_read_record(dns_packet_reader_t *reader, uint8_t *output_buffer, uint32_t len)
{
    ya_result ret;

    uint8_t  *buffer = output_buffer;

    /* Read the name */

    if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, len)))
    {
        return ret;
    }

    buffer += ret;
    len -= ret;

    if(len < TYPE_CLASS_TTL_RDLEN_SIZE)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    /* read the TYPE CLASS TTL RDATASIZE (10 bytes) */

    ret = dns_packet_reader_read(reader, buffer, TYPE_CLASS_TTL_RDLEN_SIZE); // exact

    if(FAIL(ret))
    {
        return ret;
    }
    /*
     *  ret always return either what was asked, either unexpected eof
     *  if(ret != 10)
     *  {
     *       reader->offset = reader->packet_size;
     *       return UNEXPECTED_EOF;
     *  }
     */
    uint16_t rdata_size = ntohs(GET_U16_AT(buffer[8]));

    if(rdata_size == 0) /* Can occur for dynupdate record set delete */
    {
        return (buffer - output_buffer) + TYPE_CLASS_TTL_RDLEN_SIZE;
    }

    if(len < rdata_size)
    {
        return BUFFER_WOULD_OVERFLOW;
    }

    if(dns_packet_reader_available(reader) < rdata_size)
    {
        reader->packet_offset = reader->packet_size;
        return UNEXPECTED_EOF;
    }

    uint16_t rtype = (GET_U16_AT(buffer[0])); /** @note : NATIVETYPE */

    buffer += 10;

    /*
     * EDF: No need to cut the len short, especially since what is returned
     * by the fqdn readers is the output side, not the input one (unpack)
     */

    uint8_t *rdata_start = buffer;
    uint32_t rdata_limit = reader->packet_offset + rdata_size;

    switch(rtype)
    {
            /******************************************************************************
             * The types that requires special handling (dname compression)
             ******************************************************************************/

        case TYPE_MX:
        case TYPE_AFSDB:
        {
            uint8_t *p = buffer;
            buffer += 2;
            len -= 2;
            rdata_size -= 2;

            if(len == 0 || rdata_size > DOMAIN_LENGTH_MAX)
            {
                return INVALID_RECORD; /* wrong rdata_size */
            }

            dns_packet_reader_read_unchecked(reader, p, 2); // exact

            if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, len))) /* err = error code or bytes filled, not bytes read (compression) */
            {
                return ret;
            }

            if(dnsname_is_wildcard(buffer))
            {
                return INVALID_RECORD;
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

            if((rdata_size == 0) || (rdata_size > DOMAIN_LENGTH_MAX))
            {
                return INVALID_RECORD; /* wrong rdata_size */
            }

            if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, len)))
            {
                return ret;
            }

            if(dnsname_is_wildcard(buffer))
            {
                return INVALID_RECORD;
            }

            buffer += ret;

            break;
        }
        case TYPE_SOA:
        {
            /* NOTE: NO NEED TO SORT (There is only one) */
            if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, len)))
            {
                return ret;
            }

            if(dnsname_is_wildcard(buffer))
            {
                return INVALID_RECORD;
            }

            buffer += ret;
            len -= ret;

            if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, len)))
            {
                return ret;
            }

            if(dnsname_is_wildcard(buffer))
            {
                return INVALID_RECORD;
            }

            if(rdata_limit - reader->packet_offset != 20)
            {
                return INVALID_RECORD;
            }

            len -= ret;
            if(len < 20)
            {
                return BUFFER_WOULD_OVERFLOW;
            }

            buffer += ret;
            // len -= err;

            dns_packet_reader_read_unchecked(reader, buffer, 20); // exact

            buffer += 20;

            break;
        }
        case TYPE_SIG:
        case TYPE_RRSIG: /* not supposed to be compressed */
        {
            if(rdata_size > 2 + 1 + 1 + 4 + 4 + 4 + 2 + 256 + 1024 + 4)
            {
                return UNSUPPORTED_RECORD; /* too big */
            }

            if(rdata_size < RRSIG_RDATA_HEADER_LEN)
            {
                reader->packet_offset = reader->packet_size;
                return UNEXPECTED_EOF;
            }

            dns_packet_reader_read_unchecked(reader, buffer, RRSIG_RDATA_HEADER_LEN); // exact

            buffer += RRSIG_RDATA_HEADER_LEN;
            len -= RRSIG_RDATA_HEADER_LEN;

            if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, len)))
            {
                return ret;
            }

            buffer += ret;

            if(FAIL(ret = dns_packet_reader_read(reader, buffer, rdata_limit - reader->packet_offset))) // exact
            {
                return ret;
            }

            buffer += ret;

            break;
        }
        case TYPE_NSEC: /* not supposed to be compressed */
        {
            if(FAIL(ret = dns_packet_reader_read_fqdn(reader, buffer, len)))
            {
                return ret;
            }

            buffer += ret;

            if(rdata_limit - reader->packet_offset == 0)
            {
                return INVALID_RECORD; // record is broken
            }

            if(FAIL(ret = dns_packet_reader_read(reader, buffer, rdata_limit - reader->packet_offset))) // exact
            {
                return ret;
            }

            buffer += ret;

            break;
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

            dns_packet_reader_read_unchecked(reader, buffer, 4); // exact
            buffer += 4;

            break;
        }
        case TYPE_AAAA:
        {
            if(rdata_size != 16)
            {
                return INCORRECT_IPADDRESS;
            }

            dns_packet_reader_read_unchecked(reader, buffer, 16); // exact

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
            dns_packet_reader_read_unchecked(reader, buffer, rdata_size); // exact
            buffer += rdata_size;
            break;
        }
    }

    if(rdata_limit != reader->packet_offset)
    {
        reader->packet_offset = reader->packet_size;
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

ya_result dns_packet_reader_read_dns_resource_record(dns_packet_reader_t *reader, dns_resource_record_t *rr)
{
    ya_result ret;

    if(ISOK(ret = dns_packet_reader_read_fqdn(reader, rr->name, sizeof(rr->name))))
    {
        rr->name_len = ret;
        if(ISOK(ret = dns_packet_reader_read(reader, &rr->tctr, 10)))
        {
            uint16_t rdata_size = ntohs(rr->tctr.rdlen);
            dns_resource_record_ensure_size(rr, rdata_size);
            // rr->rdata_size = rdata_size;
            uint32_t offset = reader->packet_offset;

            // dns_packet_reader_read_rdata returns the number of bytes written or BUFFER_WOULD_OVERFLOW if the buffer
            // is too small

            while((ret = dns_packet_reader_read_rdata(reader, rr->tctr.rtype, rdata_size, rr->rdata, rr->rdata_buffer_size)) == BUFFER_WOULD_OVERFLOW)
            {
                dns_resource_record_ensure_size(rr, MIN((DOMAIN_LENGTH_MAX + 7) & ~7, MAX(rr->rdata_buffer_size * 2, 65535)));
                reader->packet_offset = offset;
            }

            rr->rdata_size = ret;
        }
    }

    return ret;
}

void dns_packet_reader_rewind(dns_packet_reader_t *reader) { reader->packet_offset = 0; }

/*
 * Skip a compressed fqdn
 */

ya_result dns_packet_reader_skip_fqdn(dns_packet_reader_t *reader)
{
    /* Testing for a minimum len size is pointless */

    uint32_t       from = reader->packet_offset;
    const uint8_t *p_limit = &reader->packet[reader->packet_size];
    const uint8_t *p = &reader->packet[reader->packet_offset];

    if(p >= p_limit)
    {
        return UNEXPECTED_EOF; /* EOF */
    }

    for(;;)
    {
        uint8_t len = *p++;

        if((len & 0xc0) == 0xc0)
        {
            p++;
            reader->packet_offset = p - reader->packet;
            return reader->packet_offset - from;
        }

        if(len == 0)
        {
            reader->packet_offset = p - reader->packet;
            return reader->packet_offset - from;
        }

        if(p + len >= p_limit)
        {
            reader->packet_offset = reader->packet_size;
            return UNEXPECTED_EOF;
        }

        p += len;
    }
}

/*
 * Skip a record
 */

ya_result dns_packet_reader_skip_record(dns_packet_reader_t *reader)
{
    ya_result err;
    ya_result from = reader->packet_offset;

    /* Read the name */

    if(FAIL(err = dns_packet_reader_skip_fqdn(reader)))
    {
        return err;
    }

    /* read the TYPE CLASS TTL RDATASIZE (10 bytes) */

    uint16_t size = ntohs(GET_U16_AT(reader->packet[reader->packet_offset + 8]));
    uint32_t next_offset = reader->packet_offset + 10 + size;

    if(next_offset > reader->packet_size)
    {
        reader->packet_offset = reader->packet_size;
        return UNEXPECTED_EOF;
    }

    reader->packet_offset = next_offset;

    /*
     * This len was the rdata_size but this was the packed size.
     * So I cannot compare without a relatively expensive test
     * yassert(len == 0);
     *
     */

    return reader->packet_offset - from;
}

#if DNSCORE_HAS_CTRL

/**
 *
 * Returns true iff the string txt is utf-8
 * The current implementation checks it's ASCII7 (which is a valid subset of utf-8)
 *
 * @param txt
 * @param len
 * @return
 */

static bool is_utf8(const char *txt, uint16_t len)
{
    for(uint_fast16_t i = 0; i < len; i++)
    {
        if((txt[i] & 0x80) != 0)
        {
            return false;
        }
    }

    return true;
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

ya_result dns_packet_reader_read_utf8(dns_packet_reader_t *reader, uint16_t rdatasize, uint16_t rclass, char **txt, bool dryrun)
{
    char     *tmp = NULL;
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
        if(ISOK(dns_packet_reader_read(reader, (uint8_t *)tmp, rdatasize)))
        {
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
                return_value = MAKE_RCODE_ERROR(RCODE_FORMERR);
            }
        }
        else
        {
            return_value = MAKE_RCODE_ERROR(RCODE_FORMERR);
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

ya_result dns_packet_reader_read_remote_server(dns_packet_reader_t *reader, uint16_t rdatasize, uint16_t rclass, host_address_t **ha, bool dryrun)
{
    uint16_t ip_port = 0;
    uint8_t  ipver;
    uint8_t  flags;

    uint8_t  ip_buffer[16];
    uint8_t  tsig_name[DOMAIN_LENGTH_MAX];

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

    if(ISOK(return_value = dns_packet_reader_read(reader, &flags, 1)))
    {
        return_value = INVALID_STATE_ERROR;

        ipver = flags & REMOTE_SERVER_FLAGS_IP_MASK;

        if((ipver == HOST_ADDRESS_IPV4) || (ipver == HOST_ADDRESS_IPV6))
        {
            tsig_key_t *tsig = NULL;

            if(ipver == HOST_ADDRESS_IPV4)
            {
                return_value = dns_packet_reader_read(reader, ip_buffer, 4);
            }
            else
            {
                return_value = dns_packet_reader_read(reader, ip_buffer, 16);
            }

            if(FAIL(return_value))
            {
                return return_value;
            }

            if((flags & REMOTE_SERVER_FLAGS_PORT_MASK) != 0)
            {
                if(FAIL(return_value = dns_packet_reader_read_u16(reader, &ip_port)))
                {
                    return return_value;
                }
            }

            if((flags & REMOTE_SERVER_FLAGS_KEY_MASK) != 0)
            {
                if(FAIL(return_value = dns_packet_reader_read_fqdn(reader, tsig_name, sizeof(tsig_name))))
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
                host_address_t *address = host_address_new_instance();
                address->next = NULL;
                address->tsig = tsig;

                if(ipver == HOST_ADDRESS_IPV4)
                {
                    memcpy(address->ip.v4.bytes, ip_buffer, 4);
                    address->port = ip_port;
                    address->version = HOST_ADDRESS_IPV4;
                    address->tls = HOST_ADDRESS_TLS_NOT_SET;
                }
                else // HOST_ADDRESS_IPV6:
                {
                    memcpy(address->ip.v6.bytes, ip_buffer, 16);
                    address->port = ip_port;
                    address->version = HOST_ADDRESS_IPV6;
                    address->tls = HOST_ADDRESS_TLS_NOT_SET;
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
                        host_address_append_host_address(*ha,
                                                         address); // copy made, or may fail is address is not supported
                        host_address_delete(address);
                    }
                }
                else
                {
                    host_address_remove_host_address(ha, address); /* not freed */
                    host_address_delete(address);
                }

                return_value = SUCCESS;
            }
        }
    }

    return return_value;
}

#endif

/** @} */
