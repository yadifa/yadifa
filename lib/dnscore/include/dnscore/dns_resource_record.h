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

/** @defgroup dnscore
 *  @ingroup dnscore
 *  @brief Wire resource record reader
 *
 * Wire resource record reader
 *
 * @{
 */

#pragma once

#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>
#include <dnscore/rfc.h>
#include <dnscore/zalloc.h>

#define DNSRREC_TAG  0x5f43455252534e44
#define DNSRRDAT_TAG 0x5441445252534e44

typedef struct dns_resource_record dns_resource_record;

struct dns_resource_record
{
    u8 *rdata;                          /* allocated, grows */
    struct type_class_ttl_rdlen tctr;   /* I used this already known structure to make passing theses values easier */
    u16 rdata_size;
    u16 rdata_buffer_size;
    u8 name_len;                        /* dnsname_len(name) */
    u8 name[MAX_DOMAIN_LENGTH];
};

void dns_resource_record_init(dns_resource_record *rr);

ya_result dns_resource_record_init_record(dns_resource_record *rr, const u8* fqdn, u16 rtype, u16 rclass, s32 ttl, u16 rdata_size, const u8 *rdata);

ya_result dns_resource_init_from_record(dns_resource_record *rr, const dns_resource_record *src);

ya_result dns_resource_set_from_record(dns_resource_record *rr, const dns_resource_record *src);

void dns_resource_record_clear(dns_resource_record *rr);

static inline void dns_resource_record_finalize(dns_resource_record *rr)
{
    dns_resource_record_clear(rr);
}

ya_result dns_resource_record_set_fqdn(dns_resource_record *rr, const u8* fqdn);

ya_result dns_resource_record_set_record(dns_resource_record *rr, const u8* fqdn, u16 rtype, u16 rclass, s32 ttl, u16 rdata_size, const u8 *rdata);

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

ya_result dns_resource_record_write(const dns_resource_record *rr, output_stream *os);

bool dns_resource_record_equals(const dns_resource_record *a, const dns_resource_record *b);

bool dns_resource_record_match(const dns_resource_record *a, const dns_resource_record *b);

int dns_resource_record_compare(const dns_resource_record *a, const dns_resource_record *b);

int ptr_set_dns_resource_record_node_compare(const void *node_a, const void *node_b);

/**
 * WARNING, this function does not preserve the content of the buffer.
 */

static inline void dns_resource_record_ensure_size(dns_resource_record *a, u16 size) // does not preserve buffer content
{
    if(a->rdata_buffer_size < size)
    {
        free(a->rdata);
        a->rdata_buffer_size = (size + 7) & ~7;
        MALLOC_OBJECT_ARRAY_OR_DIE(a->rdata, u8, a->rdata_buffer_size, DNSRRDAT_TAG);
        //a->rdata = (u8*)malloc(a->rdata_buffer_size);
    }
}

static inline dns_resource_record *dns_resource_record_new_instance()
{
    dns_resource_record *rr;
    ZALLOC_OBJECT_OR_DIE(rr, dns_resource_record, DNSRREC_TAG);
    dns_resource_record_init(rr);
    return rr;
}

static inline void dns_resource_record_free(dns_resource_record *rr)
{
    dns_resource_record_finalize(rr);
    ZFREE_OBJECT(rr);
}

struct resource_record_view;

void dns_resource_record_resource_record_view_init(struct resource_record_view *rrv);

void dns_resource_record_resource_record_view_finalise(struct resource_record_view *rrv);

/** @} */
