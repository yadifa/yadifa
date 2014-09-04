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

#ifndef _DNS_RESOURCE_RECORD_H_
#define _DNS_RESOURCE_RECORD_H_

#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>
#include <dnscore/rfc.h>

typedef struct dns_resource_record dns_resource_record;

struct dns_resource_record
{
    u8 *rdata;                          /* allocated */
    struct type_class_ttl_rdlen tctr;   /* I used this already known structure to make passing theses values easier */
    u16 rdata_size;
    u16 rdata_buffer_size;
    u8 name_len;                        /* dnsname_len(name) */
    u8 name[MAX_DOMAIN_LENGTH];
};

void dns_resource_record_init(dns_resource_record *rr);

void dns_resource_record_clear(dns_resource_record *rr);

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

ya_result dns_resource_record_read(dns_resource_record *rr, input_stream *is);

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

ya_result dns_resource_record_write(dns_resource_record *rr, output_stream *os);

bool dns_resource_record_equals(dns_resource_record *a, dns_resource_record *b);

bool dns_resource_record_match(dns_resource_record *a, dns_resource_record *b);

#endif // _DNS_RESOURCE_RECORD_H_

/** @} */
