/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

#include "dnscore/dnscore_config.h"
#include "dnscore/dnscore_config.h"

#include <arpa/inet.h>
#include <dnscore/dns_resource_record.h>
#include <dnscore/dnskey_signature.h>

#define RRRDATA_TAG 0x0041544144525252

void dns_resource_record_init(dns_resource_record_t *rr)
{
#if DEBUG
    memset(rr, 0xf1, sizeof(dns_resource_record_t));
#endif

    rr->rdata = NULL;
    rr->rdata_size = 0;
    rr->rdata_buffer_size = 0;
}

void dns_resource_record_clear(dns_resource_record_t *rr)
{
    if(rr->rdata != NULL)
    {
#if DEBUG
        memset(rr->rdata, 0xfe, rr->rdata_size);
#endif
        yassert(rr->rdata_buffer_size > 0);
        free(rr->rdata);
        rr->rdata = NULL;
        rr->rdata_size = 0;
        rr->rdata_buffer_size = 0;
    }
}

ya_result dns_resource_record_set_fqdn(dns_resource_record_t *rr, const uint8_t *fqdn)
{
    uint32_t len = dnsname_len(fqdn);
    if(len <= sizeof(rr->name))
    {
        memcpy(rr->name, fqdn, len);
        rr->name_len = len;
        return len;
    }
    else
    {
        return DOMAIN_TOO_LONG;
    }
}

ya_result dns_resource_record_set_record(dns_resource_record_t *rr, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, uint16_t rdata_size, const uint8_t *rdata)
{
    ya_result ret;
    if(ISOK(ret = dns_resource_record_set_fqdn(rr, fqdn)))
    {
        rr->tctr.rtype = rtype;
        rr->tctr.rclass = rclass;
        rr->tctr.rdlen = htons(rdata_size);
        rr->tctr.ttl = htonl(ttl);
        rr->rdata_size = rdata_size;

        if(rr->rdata_size > 0)
        {
            if(rr->rdata_buffer_size < rdata_size)
            {
                uint8_t *tmp;

                // do the computations into 32 bits words

                uint32_t rdata_size_32 = rr->rdata_size;
                uint32_t buffer_size_32 = MIN(((rdata_size_32 + 15) & ~15), 0xffff);
#if DEBUG
                if(rr->rdata != NULL)
                {
                    memset(rr->rdata, 0xfe, rr->rdata_buffer_size);
                }
#endif
                rr->rdata_buffer_size = buffer_size_32;

                MALLOC_OR_DIE(uint8_t *, tmp, rr->rdata_buffer_size, RRRDATA_TAG);
                free(rr->rdata);
                rr->rdata = tmp;
            }

            memcpy(rr->rdata, rdata,
                   rdata_size); // rdata_size != 0 => rdata != 0 && rr->rdata != NULL ; also: VS false positive (nonsense)
        }
    }

    return ret;
}

ya_result dns_resource_record_init_record(dns_resource_record_t *rr, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, uint16_t rdata_size, const uint8_t *rdata)
{
    yassert((rdata != NULL) && (rdata_size > 0));
    ya_result ret;
    dns_resource_record_init(rr);
    ret = dns_resource_record_set_record(rr, fqdn, rtype, rclass, ttl, rdata_size, rdata);
    return ret;
}

ya_result dns_resource_init_from_record(dns_resource_record_t *rr, const dns_resource_record_t *src)
{
    yassert((src != NULL) && (src->rdata != NULL) && (src->rdata_size > 0));
    ya_result ret;
    ret = dns_resource_record_init_record(rr, src->name, src->tctr.rtype, src->tctr.rclass, ntohl(src->tctr.ttl), src->rdata_size, src->rdata);
    return ret;
}

ya_result dns_resource_set_from_record(dns_resource_record_t *rr, const dns_resource_record_t *src)
{
    ya_result ret;
    ret = dns_resource_record_set_record(rr, src->name, src->tctr.rtype, src->tctr.rclass, ntohl(src->tctr.ttl), src->rdata_size, src->rdata);
    return ret;
}

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

ya_result dns_resource_record_read(dns_resource_record_t *rr, input_stream_t *is)
{
    ya_result ret;

    if(FAIL(ret = input_stream_read_dnsname(is, &rr->name[0])))
    {
        return ret;
    }

    if(ret == 0)
    {
        return 0;
    }

    rr->name_len = ret;

    if(FAIL(ret = input_stream_read_fully(is, &rr->tctr, 10))) /* cannot use sizeof(tctr) */
    {
        return ret;
    }

    rr->rdata_size = htons(rr->tctr.rdlen);

    if(rr->rdata_buffer_size < rr->rdata_size)
    {
        uint8_t *tmp;

        // do the computations into 32 bits words

        uint32_t rdata_size = rr->rdata_size;
        uint32_t buffer_size = MIN((rdata_size + 255) & 0xff00, 0xffff);

#if DEBUG
        memset(rr->rdata, 0xfe, rr->rdata_buffer_size);
#endif

        rr->rdata_buffer_size = buffer_size;

        MALLOC_OR_DIE(uint8_t *, tmp, rr->rdata_buffer_size, RRRDATA_TAG);
        free(rr->rdata);
        rr->rdata = tmp;
    }

    if(FAIL(ret = input_stream_read_fully(is, rr->rdata, rr->rdata_size)))
    {
        return ret;
    }

#if DEBUG
    memset(&rr->rdata[rr->rdata_size], 0xee, rr->rdata_buffer_size - rr->rdata_size);
#endif

    return rr->name_len + 10 + rr->rdata_size; /* total bytes read */
}

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

ya_result dns_resource_record_write(const dns_resource_record_t *rr, output_stream_t *os)
{
    ya_result return_value;

    if(FAIL(return_value = output_stream_write(os, rr->name, rr->name_len)))
    {
        return return_value;
    }

    if(FAIL(return_value = output_stream_write(os, (uint8_t *)&rr->tctr, 10)))
    {
        return return_value;
    }

    if(FAIL(return_value = output_stream_write(os, rr->rdata, rr->rdata_size)))
    {
        return return_value;
    }

    return rr->name_len + 10 + rr->rdata_size; /* total bytes read */
}

bool dns_resource_record_equals(const dns_resource_record_t *a, const dns_resource_record_t *b)
{
    if((a->rdata_size == b->rdata_size) && (a->name_len == b->name_len))
    {
        if(memcmp(&a->tctr, &b->tctr, sizeof(a->tctr)) == 0)
        {
            if(dnsname_equals(a->name, b->name))
            {
                if(memcmp(a->rdata, b->rdata, a->rdata_size) == 0)
                {
                    return true;
                }
            }
        }
    }

    return false;
}

bool dns_resource_record_match(const dns_resource_record_t *a, const dns_resource_record_t *b)
{
    if((a->rdata_size == b->rdata_size) && (a->name_len == b->name_len))
    {
        if((a->tctr.rtype == b->tctr.rtype) && (a->tctr.rclass == b->tctr.rclass) && (a->tctr.rdlen == b->tctr.rdlen))
        {
            if(dnsname_equals(a->name, b->name))
            {
                if(memcmp(a->rdata, b->rdata, a->rdata_size) == 0)
                {
                    return true;
                }
            }
        }
    }

    return false;
}

int dns_resource_record_compare(const dns_resource_record_t *a, const dns_resource_record_t *b)
{
    int d;

    d = dnsname_compare(a->name, b->name);

    if(d == 0)
    {
        d = a->tctr.rclass;
        d -= b->tctr.rclass;

        if(d == 0)
        {
            d = a->tctr.rtype;
            d -= b->tctr.rtype;

            if(d == 0)
            {
                d = a->tctr.ttl;
                d -= b->tctr.ttl;

                if(d == 0)
                {
                    d = a->rdata_size;
                    d -= b->rdata_size;

                    if(d == 0)
                    {
                        d = memcmp(a->rdata, b->rdata, a->rdata_size);
                    }
                }
            }
        }
    }

    return d;
}

int ptr_treemap_dns_resource_record_node_compare(const void *node_a, const void *node_b)
{
    if(node_a != NULL)
    {
        if(node_b != NULL)
        {
            return dns_resource_record_compare((const dns_resource_record_t *)node_a, (const dns_resource_record_t *)node_b);
        }
        else
        {
            return -1;
        }
    }
    else
    {
        return (node_b == NULL) ? 0 : 1;
    }
}

static const uint8_t *dns_resource_record_view_get_fqdn(void *data, const void *rr_)
{
    (void)data;
    const dns_resource_record_t *rr = (const dns_resource_record_t *)rr_;
    return rr->name;
}

static uint16_t dns_resource_record_view_get_type(void *data, const void *rr_)
{
    (void)data;
    const dns_resource_record_t *rr = (const dns_resource_record_t *)rr_;
    return rr->tctr.rtype;
}

static uint16_t dns_resource_record_view_get_class(void *data, const void *rr_)
{
    (void)data;
    const dns_resource_record_t *rr = (const dns_resource_record_t *)rr_;
    return rr->tctr.rclass;
}

static int32_t dns_resource_record_view_get_ttl(void *data, const void *rr_)
{
    (void)data;
    const dns_resource_record_t *rr = (const dns_resource_record_t *)rr_;
    return ntohl(rr->tctr.ttl);
}

static uint16_t dns_resource_record_view_get_rdata_size(void *data, const void *rr_)
{
    (void)data;
    const dns_resource_record_t *rr = (const dns_resource_record_t *)rr_;
    return rr->rdata_size;
}

static const uint8_t *dns_resource_record_view_get_rdata(void *data, const void *rr_)
{
    (void)data;
    const dns_resource_record_t *rr = (const dns_resource_record_t *)rr_;
    return rr->rdata;
}

static void *dns_resource_record_view_new_instance(void *data, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, uint16_t rdata_size, const uint8_t *rdata)
{
    (void)data;
    dns_resource_record_t *rr;
    ZALLOC_OBJECT_OR_DIE(rr, dns_resource_record_t, DNSRREC_TAG);
    dns_resource_record_init_record(rr, fqdn, rtype, rclass, ttl, rdata_size, rdata);
    return rr;
}

static resource_record_view_vtbl dns_resource_record_view_vtbl = {dns_resource_record_view_get_fqdn,
                                                                  dns_resource_record_view_get_type,
                                                                  dns_resource_record_view_get_class,
                                                                  dns_resource_record_view_get_ttl,
                                                                  dns_resource_record_view_get_rdata_size,
                                                                  dns_resource_record_view_get_rdata,
                                                                  dns_resource_record_view_new_instance};

void                             dns_resource_record_resource_record_view_init(resource_record_view_t *rrv)
{
    rrv->data = NULL;
    rrv->vtbl = &dns_resource_record_view_vtbl;
}

void dns_resource_record_resource_record_view_finalise(resource_record_view_t *rrv) { rrv->vtbl = NULL; }

/** @} */
