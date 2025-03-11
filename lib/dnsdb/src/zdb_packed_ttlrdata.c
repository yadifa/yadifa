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

#include "dnsdb/zdb_packed_ttlrdata.h"

static const uint8_t *zdb_resource_record_data_record_view_get_fqdn(void *data, const void *rr)
{
    zdb_resource_record_data_record_view_data_t *rrv = (zdb_resource_record_data_record_view_data_t *)data;
    (void)rr;
    return rrv->fqdn;
}

static uint16_t zdb_resource_record_data_record_view_get_type(void *data, const void *rr)
{
    zdb_resource_record_data_record_view_data_t *rrv = (zdb_resource_record_data_record_view_data_t *)data;
    (void)rr;
    return rrv->rtype;
}

static uint16_t zdb_resource_record_data_record_view_get_class(void *data, const void *rr)
{
    zdb_resource_record_data_record_view_data_t *rrv = (zdb_resource_record_data_record_view_data_t *)data;
    (void)rr;
    return rrv->rclass;
}

static int32_t zdb_resource_record_data_record_view_get_ttl(void *data, const void *rr)
{
    zdb_resource_record_data_record_view_data_t *rrv = (zdb_resource_record_data_record_view_data_t *)data;
    (void)rr;
    return rrv->rttl;
}

static uint16_t zdb_resource_record_data_record_view_get_rdata_size(void *data, const void *rr)
{
    (void)data;
    zdb_resource_record_data_t *ttlrdata = (zdb_resource_record_data_t *)rr;
    return zdb_resource_record_data_rdata_size(ttlrdata);
}

static const uint8_t *zdb_resource_record_data_record_view_get_rdata(void *data, const void *rr)
{
    (void)data;
    zdb_resource_record_data_t *ttlrdata = (zdb_resource_record_data_t *)rr;
    return zdb_resource_record_data_rdata(ttlrdata);
}

static void *zdb_resource_record_data_record_view_new_instance(void *data, const uint8_t *fqdn, uint16_t rtype, uint16_t rclass, int32_t ttl, uint16_t rdata_size, const uint8_t *rdata)
{
    (void)data;
    (void)fqdn;
    (void)rtype;
    (void)rclass;
    (void)ttl;
    zdb_resource_record_data_t *rr = zdb_resource_record_data_new_instance_copy(rdata_size, rdata);
    return rr;
}

static const struct resource_record_view_vtbl zdb_resource_record_data_record_view_vtbl = {zdb_resource_record_data_record_view_get_fqdn,
                                                                                           zdb_resource_record_data_record_view_get_type,
                                                                                           zdb_resource_record_data_record_view_get_class,
                                                                                           zdb_resource_record_data_record_view_get_ttl,
                                                                                           zdb_resource_record_data_record_view_get_rdata_size,
                                                                                           zdb_resource_record_data_record_view_get_rdata,
                                                                                           zdb_resource_record_data_record_view_new_instance};

void                                          zdb_resource_record_data_resource_record_view_init(struct resource_record_view_s *rrv)
{
    zdb_resource_record_data_record_view_data_t *data;
    ZALLOC_OBJECT_OR_DIE(data, zdb_resource_record_data_record_view_data_t, ZDBPTRVD_TAG);
    rrv->data = data;
    rrv->vtbl = &zdb_resource_record_data_record_view_vtbl;
}

void zdb_resource_record_data_resource_record_view_set_fqdn(struct resource_record_view_s *rrv, const uint8_t *fqdn)
{
    zdb_resource_record_data_record_view_data_t *data = (zdb_resource_record_data_record_view_data_t *)rrv->data;
    data->fqdn = fqdn;
}

void zdb_resource_record_data_resource_record_view_set_type(struct resource_record_view_s *rrv, uint16_t rtype)
{
    zdb_resource_record_data_record_view_data_t *data = (zdb_resource_record_data_record_view_data_t *)rrv->data;
    data->rtype = rtype;
}

void zdb_resource_record_data_resource_record_view_set_class(struct resource_record_view_s *rrv, uint16_t rclass)
{
    zdb_resource_record_data_record_view_data_t *data = (zdb_resource_record_data_record_view_data_t *)rrv->data;
    data->rclass = rclass;
}

void zdb_resource_record_data_resource_record_view_set_ttl(struct resource_record_view_s *rrv, int32_t rttl)
{
    zdb_resource_record_data_record_view_data_t *data = (zdb_resource_record_data_record_view_data_t *)rrv->data;
    data->rttl = rttl;
}

void zdb_resource_record_data_resource_record_view_finalize(struct resource_record_view_s *rrv)
{
    zdb_resource_record_data_record_view_data_t *data = (zdb_resource_record_data_record_view_data_t *)rrv->data;
    ZFREE_OBJECT(data);
    rrv->data = NULL;
}

zdb_resource_record_data_t *zdb_resource_record_data_clone(zdb_resource_record_data_t *record)
{
    zdb_resource_record_data_t *clone;
    clone = zdb_resource_record_data_new_instance_copy(zdb_resource_record_data_rdata_size(record), zdb_resource_record_data_rdata(record));
    return clone;
}
#if OBSOLETE
void zdb_resource_record_data_insert_clone(zdb_resource_record_data_t **list_head, zdb_resource_record_data_t *record)
{
    zdb_resource_record_data_t *new_head = zdb_resource_record_data_clone(record);
    *list_head = new_head;
}

void zdb_resource_record_data_insert(zdb_resource_record_data_t **list_head, zdb_resource_record_data_t *new_head)
{
    assert(new_head->_next == NULL);
    new_head->_next = *list_head;
    *list_head = new_head;
}
#endif
