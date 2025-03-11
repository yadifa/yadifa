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
 * @defgroup dnscore
 * @ingroup dnscore
 * @brief Wire resource record reader
 *
 * Wire resource record reader
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnscore/input_stream.h>
#include <dnscore/output_stream.h>
#include <dnscore/rfc.h>
#include <dnscore/zalloc.h>

#define DNSRREC_TAG  0x5f43455252534e44
#define DNSRRDAT_TAG 0x5441445252534e44

typedef struct dns_resource_record_s dns_resource_record_t;

struct dns_resource_record_s
{
    uint8_t                      *rdata; /* allocated, grows */
    struct type_class_ttl_rdlen_s tctr;  /* I used this already known structure to make passing theses values easier */
    uint16_t                      rdata_size;
    uint16_t                      rdata_buffer_size;
    uint8_t                       name_len; /* dnsname_len(name) */
    uint8_t                       name[DOMAIN_LENGTH_MAX];
};

void               dns_resource_record_init(dns_resource_record_t *rr);

ya_result          dns_resource_record_init_record(dns_resource_record_t *rr, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, uint16_t rdata_size, const uint8_t *rdata);

ya_result          dns_resource_init_from_record(dns_resource_record_t *rr, const dns_resource_record_t *src);

ya_result          dns_resource_set_from_record(dns_resource_record_t *rr, const dns_resource_record_t *src);

void               dns_resource_record_clear(dns_resource_record_t *rr);

static inline void dns_resource_record_finalize(dns_resource_record_t *rr) { dns_resource_record_clear(rr); }

ya_result          dns_resource_record_set_fqdn(dns_resource_record_t *rr, const uint8_t *fqdn);

ya_result          dns_resource_record_set_record(dns_resource_record_t *rr, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, uint16_t rdata_size, const uint8_t *rdata);

/**
 *
 * This utility function reads an uncompressed record from a stream.
 * Compression has to be handled by the underlying input_stream_t
 * If an error code is returned, then most likely the stream is broken.
 *
 * @param is
 * @param rr
 *
 * @return an error code or the number of bytes read
 */

ya_result dns_resource_record_read(dns_resource_record_t *rr, input_stream_t *is);

/**
 *
 * This utility function writes an uncompressed record to a stream.
 * Compression has to be handled by the underlying output_stream_t
 * If an error code is returned, then most likely the stream is broken.
 *
 * @param os
 * @param rr
 *
 * @return an error code or the number of bytes written
 */

ya_result dns_resource_record_write(const dns_resource_record_t *rr, output_stream_t *os);

/**
 * Compare all the fields of two dns_resource_record_t
 */

bool dns_resource_record_equals(const dns_resource_record_t *a, const dns_resource_record_t *b);

/**
 * Compare all the fields minus the TTL of two dns_resource_record_t
 */

bool dns_resource_record_match(const dns_resource_record_t *a, const dns_resource_record_t *b);

int  dns_resource_record_compare(const dns_resource_record_t *a, const dns_resource_record_t *b);

int  ptr_treemap_dns_resource_record_node_compare(const void *key_a, const void *key_b);

/**
 * WARNING, this function does not preserve the content of the buffer.
 */

static inline void dns_resource_record_ensure_size(dns_resource_record_t *a,
                                                   uint16_t               size) // does not preserve buffer content
{
    if(a->rdata_buffer_size < size)
    {
        free(a->rdata);
        a->rdata_buffer_size = (size + 7) & ~7;
        MALLOC_OBJECT_ARRAY_OR_DIE(a->rdata, uint8_t, a->rdata_buffer_size, DNSRRDAT_TAG);
        // a->rdata = (uint8_t*)malloc(a->rdata_buffer_size);
    }
}

static inline dns_resource_record_t *dns_resource_record_new_instance()
{
    dns_resource_record_t *rr;
    ZALLOC_OBJECT_OR_DIE(rr, dns_resource_record_t, DNSRREC_TAG);
    dns_resource_record_init(rr);
    return rr;
}

static inline void dns_resource_record_delete(dns_resource_record_t *rr)
{
    dns_resource_record_finalize(rr);
    ZFREE_OBJECT(rr);
}

static inline void dns_resource_record_free(dns_resource_record_t *rr) { dns_resource_record_delete(rr); }

struct resource_record_view_s;

void dns_resource_record_resource_record_view_init(struct resource_record_view_s *rrv);

void dns_resource_record_resource_record_view_finalise(struct resource_record_view_s *rrv);

/** @} */
