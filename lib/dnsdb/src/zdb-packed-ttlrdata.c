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

#include "dnsdb/zdb-packed-ttlrdata.h"

static const u8 *
zdb_packed_ttlrdata_record_view_get_fqdn(void *data, const void *rr)
{
    zdb_packed_ttlrdata_record_view_data *rrv = (zdb_packed_ttlrdata_record_view_data*)data;
    (void)rr;
    return rrv->fqdn;
}

static u16
zdb_packed_ttlrdata_record_view_get_type(void *data, const void *rr)
{
    zdb_packed_ttlrdata_record_view_data *rrv = (zdb_packed_ttlrdata_record_view_data*)data;
    (void)rr;
    return rrv->rtype;
}

static u16
zdb_packed_ttlrdata_record_view_get_class(void *data, const void *rr)
{
    zdb_packed_ttlrdata_record_view_data *rrv = (zdb_packed_ttlrdata_record_view_data*)data;
    (void)rr;
    return rrv->rclass;
}

static s32
zdb_packed_ttlrdata_record_view_get_ttl(void *data, const void *rr)
{
    zdb_packed_ttlrdata_record_view_data *rrv = (zdb_packed_ttlrdata_record_view_data*)data;
    (void)rr;
    return rrv->rttl;
}

static u16
zdb_packed_ttlrdata_record_view_get_rdata_size(void *data, const void *rr)
{
    (void)data;
    zdb_packed_ttlrdata *ttlrdata = (zdb_packed_ttlrdata*)rr;
    return ZDB_PACKEDRECORD_PTR_RDATASIZE(ttlrdata);
}

static const u8 *
zdb_packed_ttlrdata_record_view_get_rdata(void *data, const void *rr)
{
    (void)data;
    zdb_packed_ttlrdata *ttlrdata = (zdb_packed_ttlrdata*)rr;
    return ZDB_PACKEDRECORD_PTR_RDATAPTR(ttlrdata);
}

static void *
zdb_packed_ttlrdata_record_view_new_instance(void *data, const u8 *fqdn, u16 rtype, u16 rclass, s32 ttl, u16 rdata_size, const u8 *rdata)
{
    (void)data;
    (void)fqdn;
    (void)rtype;
    (void)rclass;
    zdb_packed_ttlrdata *ttlrdata;
    ZDB_RECORD_ZALLOC(ttlrdata, ttl, rdata_size, rdata);
    ttlrdata->next = NULL;
    return ttlrdata;
}

static const struct resource_record_view_vtbl zdb_packed_ttlrdata_record_view_vtbl =
{
    zdb_packed_ttlrdata_record_view_get_fqdn,
    zdb_packed_ttlrdata_record_view_get_type,
    zdb_packed_ttlrdata_record_view_get_class,
    zdb_packed_ttlrdata_record_view_get_ttl,
    zdb_packed_ttlrdata_record_view_get_rdata_size,
    zdb_packed_ttlrdata_record_view_get_rdata,
    zdb_packed_ttlrdata_record_view_new_instance
};

void
zdb_packed_ttlrdata_resource_record_view_init(struct resource_record_view *rrv)
{
    zdb_packed_ttlrdata_record_view_data *data;
    ZALLOC_OBJECT_OR_DIE(data, zdb_packed_ttlrdata_record_view_data, ZDBPTRVD_TAG);
    rrv->data = data;
    rrv->vtbl = &zdb_packed_ttlrdata_record_view_vtbl;
}

void
zdb_packed_ttlrdata_resource_record_view_set_fqdn(struct resource_record_view *rrv, const u8 *fqdn)
{
    zdb_packed_ttlrdata_record_view_data *data = (zdb_packed_ttlrdata_record_view_data*)rrv->data;
    data->fqdn = fqdn;
}

void
zdb_packed_ttlrdata_resource_record_view_set_type(struct resource_record_view *rrv, u16 rtype)
{
    zdb_packed_ttlrdata_record_view_data *data = (zdb_packed_ttlrdata_record_view_data*)rrv->data;
    data->rtype = rtype;
}

void
zdb_packed_ttlrdata_resource_record_view_set_class(struct resource_record_view *rrv, u16 rclass)
{
    zdb_packed_ttlrdata_record_view_data *data = (zdb_packed_ttlrdata_record_view_data*)rrv->data;
    data->rclass = rclass;
}

void
zdb_packed_ttlrdata_resource_record_view_set_ttl(struct resource_record_view *rrv, s32 rttl)
{
    zdb_packed_ttlrdata_record_view_data *data = (zdb_packed_ttlrdata_record_view_data*)rrv->data;
    data->rttl = rttl;
}

void
zdb_packed_ttlrdata_resource_record_view_finalize(struct resource_record_view *rrv)
{
    zdb_packed_ttlrdata_record_view_data *data = (zdb_packed_ttlrdata_record_view_data*)rrv->data;
    ZFREE_OBJECT(data);
    rrv->data = NULL;
}


zdb_packed_ttlrdata*
zdb_packed_ttlrdata_clone(zdb_packed_ttlrdata *record)
{
    zdb_packed_ttlrdata* clone;
    ZDB_RECORD_ZALLOC(clone, record->ttl, ZDB_PACKEDRECORD_PTR_RDATASIZE(record), ZDB_PACKEDRECORD_PTR_RDATAPTR(record));
    clone->next = NULL;
    return clone;
}

void zdb_packed_ttlrdata_insert_clone(zdb_packed_ttlrdata **list_head, zdb_packed_ttlrdata *record)
{
    zdb_packed_ttlrdata *new_head = zdb_packed_ttlrdata_clone(record);
    new_head->next = *list_head;
    *list_head = new_head;
}

void zdb_packed_ttlrdata_insert(zdb_packed_ttlrdata **list_head, zdb_packed_ttlrdata *new_head)
{
    assert(new_head->next == NULL);
    new_head->next = *list_head;
    *list_head = new_head;
}
