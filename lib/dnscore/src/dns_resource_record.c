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
/** @defgroup dnscore
 *  @ingroup dnscore
 *  @brief Wire resource record reader
 *
 * Wire resource record reader
 *
 * @{
 */

#include "dnscore-config.h"

#include <arpa/inet.h>
#include "dnscore/dns_resource_record.h"

void
dns_resource_record_init(dns_resource_record *rr)
{
#ifdef DEBUG
    memset(rr, 0xff, sizeof(dns_resource_record));
#endif

    rr->rdata = NULL;
    rr->rdata_size = 0;
    rr->rdata_buffer_size = 0;
}

void
dns_resource_record_clear(dns_resource_record *rr)
{
    if(rr->rdata != NULL)
    {
        free(rr->rdata);
        rr->rdata = NULL;
        rr->rdata_size = 0;
        rr->rdata_buffer_size = 0;
    }
}

/**
 * 
 * This utility function reads an uncompressed record from a stream.
 * Compression has to be handled by the underlying input_stream
 * If an error code is returned, then most likely the stream is broken.
 *  
 * @param is
 * @param rr
 * 
 * @return an error code or the number of bytes read
 */

ya_result
dns_resource_record_read(dns_resource_record *rr, input_stream *is)
{
    ya_result return_value;
    
    if(FAIL(return_value = input_stream_read_dnsname(is, &rr->name[0])))
    {
        return return_value;
    }
    
    if(return_value == 0)
    {
        return 0;
    }
    
    rr->name_len = return_value;
    
    if(FAIL(return_value = input_stream_read_fully(is, &rr->tctr, 10))) /* cannot use sizeof(tctr) */
    {
        return return_value;
    }
    
    rr->rdata_size = htons(rr->tctr.rdlen);
    
    if(rr->rdata_buffer_size < rr->rdata_size)
    {
        u8 *tmp;
        
        // do the computations into 32 bits words
        
        u32 rdata_size = rr->rdata_size;
        u32 buffer_size = MIN((rdata_size + 255) & 0xff00, 0xffff);
        
        rr->rdata_buffer_size = buffer_size;
        
        MALLOC_OR_DIE(u8*, tmp, rr->rdata_buffer_size, GENERIC_TAG);
        free(rr->rdata);
        rr->rdata = tmp;
    }
    
    if(FAIL(return_value = input_stream_read_fully(is, rr->rdata, rr->rdata_size)))
    {
        return return_value;
    }
    
    return rr->name_len + 10 + rr->rdata_size; /* total bytes read */
}

/**
 * 
 * This utility function writes an uncompressed record to a stream.
 * Compression has to be handled by the underlying output_stream
 * If an error code is returned, then most likely the stream is broken.
 *  
 * @param os
 * @param rr
 * 
 * @return an error code or the number of bytes written
 */

ya_result
dns_resource_record_write(dns_resource_record *rr, output_stream *os)
{
    ya_result return_value;
    
    if(FAIL(return_value = output_stream_write(os, rr->name, rr->name_len)))
    {
        return return_value;
    }
    
    if(FAIL(return_value = output_stream_write(os, (u8*)&rr->tctr, 10)))
    {
        return return_value;
    }
    
    if(FAIL(return_value = output_stream_write(os, rr->rdata, rr->rdata_size)))
    {
        return return_value;
    }
    
    return rr->name_len + 10 + rr->rdata_size; /* total bytes read */
}

bool
dns_resource_record_equals(dns_resource_record *a, dns_resource_record *b)
{
    if((a->rdata_size == b->rdata_size) && (a->name_len == b->name_len))
    {
        if(memcmp(&a->tctr, &b->tctr, sizeof(a->tctr)) == 0)
        {
            if(dnsname_equals(a->name, b->name))
            {
                if(memcmp(a->rdata, b->rdata, a->rdata_size) == 0)
                {
                    return TRUE;
                }
            }
        }
    }
    
    return FALSE;
}

bool
dns_resource_record_match(dns_resource_record *a, dns_resource_record *b)
{
    if((a->rdata_size == b->rdata_size) && (a->name_len == b->name_len))
    {
        if((a->tctr.qtype == b->tctr.qtype) && (a->tctr.qclass == b->tctr.qclass) && (a->tctr.rdlen == b->tctr.rdlen))
        {
            if(dnsname_equals(a->name, b->name))
            {
                if(memcmp(a->rdata, b->rdata, a->rdata_size) == 0)
                {
                    return TRUE;
                }
            }
        }
    }
    
    return FALSE;
}

/** @} */
