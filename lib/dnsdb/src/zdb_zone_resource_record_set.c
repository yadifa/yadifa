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
 * @defgroup records Internal functions for the database: resource records.
 * @ingroup dnsdb
 * @brief Internal functions for the database: resource records.
 *
 *  Internal functions for the database: resource records.
 *
 *  Handling of the class->type->ttl+rdata list.
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnsdb/dnsdb_config.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <dnscore/format.h>
#include <dnscore/dnscore.h>
#include <dnscore/rfc.h>

#include <arpa/inet.h>
#include <dnscore/permut.h>

#include "dnsdb/zdb_record.h"

#include "dnsdb/zdb_error.h"

#include "dnsdb/btree.h"

#if HAS_NSEC3_SUPPORT
#include "dnsdb/nsec3_types.h"
#endif

#define PERMUTATION_STATIC_ARRAY_SIZE 16

pcg32_random_t dns_packet_writer_add_rrset_rng;

void           zdb_resource_record_set_init(zdb_resource_record_set_t *rrset, uint16_t type, int32_t ttl)
{
    rrset->_ttl = ttl;
    rrset->_type = type;
    rrset->_record_count = 0;
#if DEBUG
    rrset->_record = NULL;
#endif
}

void zdb_resource_record_set_init_with_one_record(zdb_resource_record_set_t *rrset, uint16_t type, int32_t ttl, zdb_resource_record_data_t *rr)
{
    rrset->_ttl = ttl;
    rrset->_type = type;
    rrset->_record_count = 1;
    rrset->_record = rr;
}

zdb_resource_record_set_t *zdb_resource_record_set_new_instance(uint16_t type, int32_t ttl)
{
    zdb_resource_record_set_t *rrset;
    ZALLOC_OBJECT_OR_DIE(rrset, zdb_resource_record_set_t, ZDBRRSET_TAG);
    rrset->_ttl = ttl;
    rrset->_type = type;
    rrset->_record_count = 0;
#if DEBUG
    rrset->_record = NULL;
#endif
    return rrset;
}

void zdb_resource_record_set_insert_record(zdb_resource_record_set_t *rrset, zdb_resource_record_data_t *record)
{
#if DEBUG
    switch(rrset->_type)
    {
        case TYPE_A:
            if(zdb_resource_record_data_rdata_size(record) != 4)
            {
                abort();
            }
            break;
        case TYPE_AAAA:
            if(zdb_resource_record_data_rdata_size(record) != 16)
            {
                abort();
            }
            break;
#if ZDB_HAS_NSEC3_SUPPORT
        case TYPE_NSEC3PARAM:
            if(zdb_resource_record_data_rdata_size(record) != NSEC3PARAM_RDATA_SIZE_FROM_RDATA(zdb_resource_record_data_rdata_const(record)))
            {
                abort();
            }
            break;
#endif
        default:
            break;
    }
#endif

    if(rrset->_record_count == 0)
    {
        rrset->_record_count = 1;
        rrset->_record = record;
    }
    else if(rrset->_record_count == 1)
    {
        zdb_resource_record_data_t **records;
        ZALLOC_OBJECT_ARRAY_OR_DIE(records, zdb_resource_record_data_t *, 2, ZDB_RECORD_TAG);
        records[0] = rrset->_record;
        records[1] = record;
        rrset->_record_count = 2;
        rrset->_records = records;
    }
    else
    {
        zdb_resource_record_data_t **records;
        int                          new_count = rrset->_record_count + 1;
        int                          array_size = sizeof(zdb_resource_record_data_t *) * rrset->_record_count;
        ZALLOC_OBJECT_ARRAY_OR_DIE(records, zdb_resource_record_data_t *, new_count, ZDB_RECORD_TAG);
        memcpy(records, rrset->_records, array_size);
        records[rrset->_record_count] = record;
        ZFREE_ARRAY(rrset->_records, array_size);
        rrset->_record_count = new_count;
        rrset->_records = records;
    }
}

void zdb_resource_record_set_insert_record_with_ttl(zdb_resource_record_set_t *rrset, zdb_resource_record_data_t *record, int32_t ttl)
{
#if DEBUG
    switch(rrset->_type)
    {
        case TYPE_A:
            if(zdb_resource_record_data_rdata_size(record) != 4)
            {
                abort();
            }
            break;
        case TYPE_AAAA:
            if(zdb_resource_record_data_rdata_size(record) != 16)
            {
                abort();
            }
            break;
#if ZDB_HAS_NSEC3_SUPPORT
        case TYPE_NSEC3PARAM:
            if(zdb_resource_record_data_rdata_size(record) != NSEC3PARAM_RDATA_SIZE_FROM_RDATA(zdb_resource_record_data_rdata_const(record)))
            {
                abort();
            }
            break;
#endif
        default:
            break;
    }
#endif

    rrset->_ttl = ttl;

    if(rrset->_record_count == 0)
    {
        rrset->_record_count = 1;
        rrset->_record = record;
    }
    else if(rrset->_record_count == 1)
    {
        zdb_resource_record_data_t **records;
        ZALLOC_OBJECT_ARRAY_OR_DIE(records, zdb_resource_record_data_t *, 2, ZDB_RECORD_TAG);
        records[0] = rrset->_record;
        records[1] = record;
        rrset->_record_count = 2;
        rrset->_records = records;
    }
    else
    {
        zdb_resource_record_data_t **records;
        int                          new_count = rrset->_record_count + 1;
        int                          array_size = sizeof(zdb_resource_record_data_t *) * rrset->_record_count;
        ZALLOC_OBJECT_ARRAY_OR_DIE(records, zdb_resource_record_data_t *, new_count, ZDB_RECORD_TAG);
        memcpy(records, rrset->_records, array_size);
        records[rrset->_record_count] = record;
        ZFREE_ARRAY(rrset->_records, array_size);
        rrset->_record_count = new_count;
        rrset->_records = records;
    }
}

bool zdb_resource_record_set_insert_record_with_ttl_checked(zdb_resource_record_set_t *rrset, zdb_resource_record_data_t *record, int32_t ttl)
{
    rrset->_ttl = ttl;

    if(rrset->_record_count == 0)
    {
        rrset->_record_count = 1;
        rrset->_record = record;
        return true;
    }
    else if(rrset->_record_count == 1)
    {
        if(zdb_resource_record_data_compare_records(rrset->_record, record) != 0)
        {
            zdb_resource_record_data_t **records;
            ZALLOC_OBJECT_ARRAY_OR_DIE(records, zdb_resource_record_data_t *, 2, ZDB_RECORD_TAG);
            records[0] = rrset->_record;
            records[1] = record;
            rrset->_record_count = 2;
            rrset->_records = records;
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        for(int_fast32_t i = 0; i < rrset->_record_count; ++i)
        {
            if(zdb_resource_record_data_compare_records(rrset->_records[i], record) == 0)
            {
                return false;
            }
        }

        zdb_resource_record_data_t **records;
        int                          new_count = rrset->_record_count + 1;
        int                          array_size = sizeof(zdb_resource_record_data_t *) * rrset->_record_count;
        ZALLOC_OBJECT_ARRAY_OR_DIE(records, zdb_resource_record_data_t *, new_count, ZDB_RECORD_TAG);
        memcpy(records, rrset->_records, array_size);
        records[rrset->_record_count] = record;
        ZFREE_ARRAY(rrset->_records, array_size);
        rrset->_record_count = new_count;
        rrset->_records = records;

        return true;
    }
}

bool zdb_resource_record_set_insert_record_with_ttl_checked_with_mp(zdb_resource_record_set_t *rrset, zdb_resource_record_data_t *record, int32_t ttl, memory_pool_t *mp)
{
    rrset->_ttl = ttl;

    if(rrset->_record_count == 0)
    {
        rrset->_record_count = 1;
        rrset->_record = record;
        return true;
    }
    else if(rrset->_record_count == 1)
    {
        if(zdb_resource_record_data_compare_records(rrset->_record, record) != 0)
        {
            zdb_resource_record_data_t **records;
            // ZALLOC_OBJECT_ARRAY_OR_DIE(records, zdb_resource_record_data_t*, 2, ZDB_RECORD_TAG);
            records = (zdb_resource_record_data_t **)memory_pool_alloc(mp, sizeof(zdb_resource_record_data_t *) * 2);

            records[0] = rrset->_record;
            records[1] = record;
            rrset->_record_count = 2;
            rrset->_records = records;
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        for(int_fast32_t i = 0; i < rrset->_record_count; ++i)
        {
            if(zdb_resource_record_data_compare_records(rrset->_records[i], record) == 0)
            {
                return false;
            }
        }

        zdb_resource_record_data_t **records;
        int                          new_count = rrset->_record_count + 1;
        int                          array_size = sizeof(zdb_resource_record_data_t *) * rrset->_record_count;
        // ZALLOC_OBJECT_ARRAY_OR_DIE(records, zdb_resource_record_data_t*, new_count, ZDB_RECORD_TAG);
        records = (zdb_resource_record_data_t **)memory_pool_alloc(mp, sizeof(zdb_resource_record_data_t *) * new_count);
        memcpy(records, rrset->_records, array_size);
        records[rrset->_record_count] = record;
        // ZFREE_ARRAY(rrset->_records, array_size);
        memory_pool_free(mp, rrset->_records, array_size);
        rrset->_record_count = new_count;
        rrset->_records = records;

        return true;
    }
}

void zdb_resource_record_set_clear(zdb_resource_record_set_t *rrset)
{
    if(rrset->_record_count == 0)
    {
    }
    else if(rrset->_record_count == 1)
    {
        zdb_resource_record_data_delete(rrset->_record);
#if DEBUG
        rrset->_record = NULL;
#endif
        rrset->_record_count = 0;
    }
    else
    {
        for(int_fast32_t i = 0; i < rrset->_record_count; ++i)
        {
            zdb_resource_record_data_delete(rrset->_records[i]);
        }

        int array_size = sizeof(zdb_resource_record_data_t *) * rrset->_record_count;
        ZFREE_ARRAY(rrset->_records, array_size);
#if DEBUG
        rrset->_records = NULL;
#endif
        rrset->_record_count = 0;
    }
}

void zdb_resource_record_set_delete(zdb_resource_record_set_t *rrset)
{
    zdb_resource_record_set_clear(rrset); // in zdb_resource_record_set_delete
    ZFREE_OBJECT(rrset);
}

bool zdb_resource_record_set_delete_matching(zdb_resource_record_set_t *rrset, bool (*matching)(const zdb_resource_record_data_t *record, const void *data), const void *data)
{
    if(rrset->_record_count == 0)
    {
        return false;
    }
    else if(rrset->_record_count == 1)
    {
        if(matching(rrset->_record, data))
        {
            zdb_resource_record_data_delete(rrset->_record);
#if DEBUG
            rrset->_record = NULL;
#endif
            rrset->_record_count = 0;
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        int16_t removed_count = 0;
        for(int_fast32_t i = 0; i < rrset->_record_count; ++i)
        {
            if(matching(rrset->_records[i], data))
            {
                zdb_resource_record_data_delete(rrset->_records[i]);
                rrset->_records[i] = NULL;
                ++removed_count;
            }
        }
        if(removed_count > 0)
        {
            int new_count = rrset->_record_count - removed_count;

            if(new_count == 0)
            {
                int array_size = sizeof(zdb_resource_record_data_t *) * rrset->_record_count;
                ZFREE_ARRAY(rrset->_records, array_size);

                rrset->_record_count = 0;
                rrset->_records = NULL;
            }
            else if(new_count == 1)
            {
                zdb_resource_record_data_t *rr;

                for(int_fast32_t i = 0; i < rrset->_record_count; ++i)
                {
                    if((rr = rrset->_records[i]) != NULL)
                    {
                        break;
                    }
                }

                int array_size = sizeof(zdb_resource_record_data_t *) * rrset->_record_count;
                ZFREE_ARRAY(rrset->_records, array_size);

                rrset->_record = rr;
                rrset->_record_count = 1;
            }
            else
            {
                zdb_resource_record_data_t **records;
                zdb_resource_record_data_t **p;
                ZALLOC_OBJECT_ARRAY_OR_DIE(records, zdb_resource_record_data_t *, new_count, ZDB_RECORD_TAG);
                p = records;
                for(int_fast32_t i = 0; i < rrset->_record_count; ++i)
                {
                    zdb_resource_record_data_t *rr;
                    if((rr = rrset->_records[i]) != NULL)
                    {
                        *p++ = rr;
                    }
                }

                int array_size = sizeof(zdb_resource_record_data_t *) * rrset->_record_count;
                ZFREE_ARRAY(rrset->_records, array_size);

                rrset->_record_count = new_count;
                rrset->_records = records;
            }
        }

        return removed_count > 0;
    }
}

struct zdb_resource_record_set_delete_by_rdata_s
{
    const void *rdata;
    uint16_t    rdata_size;
};

static bool zdb_resource_record_set_delete_by_rdata_matching(const zdb_resource_record_data_t *record, const void *data)
{
    const struct zdb_resource_record_set_delete_by_rdata_s *rdata = data;
    uint16_t                                                rr_rdata_size = zdb_resource_record_data_rdata_size(record);
    if(rr_rdata_size == rdata->rdata_size)
    {
        const uint8_t *rr_rdata = zdb_resource_record_data_rdata_const(record);
        return memcmp(rdata->rdata, rr_rdata, rr_rdata_size) == 0;
    }
    else
    {
        return false;
    }
}

bool zdb_resource_record_set_delete_by_rdata(zdb_resource_record_set_t *rrset, const void *rdata_, uint16_t rdata_size)
{
    const struct zdb_resource_record_set_delete_by_rdata_s rdata = {rdata_, rdata_size};
    bool                                                   ret = zdb_resource_record_set_delete_matching(rrset, zdb_resource_record_set_delete_by_rdata_matching, &rdata);
    return ret;
}

zdb_resource_record_data_t *zdb_resource_record_set_record_get(zdb_resource_record_set_t *rrset, int index)
{
    if(rrset->_record_count == 0)
    {
        return NULL;
    }
    else if(rrset->_record_count == 1)
    {
        return rrset->_record;
    }
    else
    {
        assert(index < rrset->_record_count);
        return rrset->_records[index];
    }
}

const zdb_resource_record_data_t *zdb_resource_record_set_record_get_const(const zdb_resource_record_set_t *rrset, int index)
{
    if(rrset->_record_count == 0)
    {
        return NULL;
    }
    else if(rrset->_record_count == 1)
    {
        return rrset->_record;
    }
    else
    {
        assert(index < rrset->_record_count);
        return rrset->_records[index];
    }
}

void zdb_resource_record_set_record_set(zdb_resource_record_set_t *rrset, int index, zdb_resource_record_data_t *rr)
{
    if(rrset->_record_count == 0)
    {
    }
    else if(rrset->_record_count == 1)
    {
        rrset->_record = rr;
    }
    else
    {
        assert(index < rrset->_record_count);
        rrset->_records[index] = rr;
    }
}

ya_result dns_packet_writer_add_rrset(dns_packet_writer_t *pw, const uint8_t *fqdn, const zdb_resource_record_set_t *rrset)
{
    yassert(rrset != NULL);

    uint16_t  last_good_offset = pw->packet_offset;
    uint16_t  code = last_good_offset;
    uint8_t  *p = &pw->packet[last_good_offset];

    ya_result ret = dns_packet_writer_add_fqdn(pw, fqdn);

    if(ISOK(ret))
    {
        if((*p & 0xc0) == 0xc0)
        {
            // already compressed
            code = GET_U16_AT_P(p);
        }
        else
        {
            // make a compression code
            code = htons(code | 0xc000);
        }

        // now write each rrset using the above compressed code

        int32_t  ne_ttl = htonl(zdb_resource_record_set_ttl(rrset));
        uint16_t rtype = zdb_resource_record_set_type(rrset);
        switch(rtype)
        {
            case TYPE_MX:
            {
                zdb_resource_record_set_const_iterator iter;
                zdb_resource_record_set_const_iterator_init(rrset, &iter);
                if(zdb_resource_record_set_const_iterator_has_next(&iter))
                {
                    const zdb_resource_record_data_t *rr = zdb_resource_record_set_const_iterator_next(&iter);

                    if(dns_packet_writer_get_remaining_capacity(pw) < 10 + 2 + 1) // + 1 because that's the minimum fqdn size
                    {
                        ret = BUFFER_WOULD_OVERFLOW;
                        dns_packet_writer_set_truncated(pw);
                        break;
                    }

                    dns_packet_writer_add_u16(pw, TYPE_MX);
                    dns_packet_writer_add_u16(pw, CLASS_IN);
                    dns_packet_writer_add_u32(pw, ne_ttl);
                    // dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                    pw->packet_offset += 2;
                    uint16_t offset = pw->packet_offset;
                    dns_packet_writer_add_bytes(pw, zdb_resource_record_data_rdata_const(rr), 2);
                    if(FAIL(ret = dns_packet_writer_add_fqdn(pw, zdb_resource_record_data_rdata_const(rr) + 2)))
                    {
                        pw->packet_offset = last_good_offset;
                        dns_packet_writer_set_truncated(pw);
                        break;
                    }
                    dns_packet_writer_set_u16(pw, ntohs(pw->packet_offset - offset), offset - 2);

                    while(zdb_resource_record_set_const_iterator_has_next(&iter))
                    {
                        rr = zdb_resource_record_set_const_iterator_next(&iter);

                        if(dns_packet_writer_get_remaining_capacity(pw) < 12 + 2 + 1) // + 1 because that's the minimum fqdn size
                        {
                            pw->packet_offset = last_good_offset;
                            ret = BUFFER_WOULD_OVERFLOW;
                            dns_packet_writer_set_truncated(pw);
                            break;
                        }

                        dns_packet_writer_add_u16(pw, TYPE_MX);
                        dns_packet_writer_add_u16(pw, CLASS_IN);
                        dns_packet_writer_add_u32(pw, ne_ttl);
                        // dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                        pw->packet_offset += 2;
                        uint16_t offset = pw->packet_offset;
                        dns_packet_writer_add_bytes(pw, zdb_resource_record_data_rdata_const(rr), 2);
                        if(FAIL(ret = dns_packet_writer_add_fqdn(pw, zdb_resource_record_data_rdata_const(rr) + 2)))
                        {
                            pw->packet_offset = last_good_offset;
                            dns_packet_writer_set_truncated(pw);
                            break;
                        }
                        dns_packet_writer_set_u16(pw, ntohs(pw->packet_offset - offset), offset - 2);

                        last_good_offset = pw->packet_offset;
                    }
                }
                break;
            }
            case TYPE_NS:
            {
                /* ONE NAME record, in random order */

                if(rrset->_record_count == 1)
                {
                    const zdb_resource_record_data_t *rr = rrset->_record;

                    if(dns_packet_writer_get_remaining_capacity(pw) < 10 + 1) // + 1 because that's the minimum fqdn size
                    {
                        pw->packet_offset = last_good_offset;
                        ret = BUFFER_WOULD_OVERFLOW;
                        dns_packet_writer_set_truncated(pw);
                        break;
                    }

                    dns_packet_writer_add_u16(pw, rtype);
                    dns_packet_writer_add_u16(pw, CLASS_IN);
                    dns_packet_writer_add_u32(pw, ne_ttl);
                    // dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                    pw->packet_offset += 2;
                    uint16_t offset = pw->packet_offset;
                    if(FAIL(ret = dns_packet_writer_add_fqdn(pw, zdb_resource_record_data_rdata_const(rr))))
                    {
                        pw->packet_offset = last_good_offset;
                        dns_packet_writer_set_truncated(pw);
                        break;
                    }
                    dns_packet_writer_set_u16(pw, htons(pw->packet_offset - offset), offset - 2);
                }
                else
                {
                    // permutation needed
                    void  *tmp_ptrs[PERMUTATION_STATIC_ARRAY_SIZE * 2];
                    void **p;
                    void **b;

                    if(rrset->_record_count < PERMUTATION_STATIC_ARRAY_SIZE)
                    {
                        p = tmp_ptrs;
                        b = &tmp_ptrs[PERMUTATION_STATIC_ARRAY_SIZE];
                        memcpy(b, rrset->_records, rrset->_record_count * sizeof(void *));

                        permut_pointers_randomly(p, b, rrset->_record_count, &dns_packet_writer_add_rrset_rng);

                        if(dns_packet_writer_get_remaining_capacity(pw) < 10 + 1) // + 1 because that's the minimum fqdn size
                        {
                            pw->packet_offset = last_good_offset;
                            ret = BUFFER_WOULD_OVERFLOW;
                            dns_packet_writer_set_truncated(pw);
                            break;
                        }

                        const zdb_resource_record_data_t *rr = p[0];

                        dns_packet_writer_add_u16(pw, rtype);
                        dns_packet_writer_add_u16(pw, CLASS_IN);
                        dns_packet_writer_add_u32(pw, ne_ttl);
                        // dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                        pw->packet_offset += 2;
                        uint16_t offset = pw->packet_offset;
                        if(FAIL(ret = dns_packet_writer_add_fqdn(pw, zdb_resource_record_data_rdata_const(rr))))
                        {
                            pw->packet_offset = last_good_offset;
                            dns_packet_writer_set_truncated(pw);
                            break;
                        }

                        dns_packet_writer_set_u16(pw, htons(pw->packet_offset - offset), offset - 2);

                        last_good_offset = pw->packet_offset;

                        for(int_fast32_t i = 1; i < rrset->_record_count; ++i)
                        {
                            rr = p[i];

                            if(dns_packet_writer_get_remaining_capacity(pw) < 12 + 1) // + 1 because that's the minimum fqdn size
                            {
                                pw->packet_offset = last_good_offset;
                                ret = BUFFER_WOULD_OVERFLOW;
                                dns_packet_writer_set_truncated(pw);
                                break;
                            }

                            dns_packet_writer_add_u16(pw, code);
                            dns_packet_writer_add_u16(pw, rtype);
                            dns_packet_writer_add_u16(pw, CLASS_IN);
                            dns_packet_writer_add_u32(pw, ne_ttl);
                            // dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                            pw->packet_offset += 2;
                            uint16_t offset = pw->packet_offset;
                            if(FAIL(ret = dns_packet_writer_add_fqdn(pw, zdb_resource_record_data_rdata_const(rr))))
                            {
                                pw->packet_offset = last_good_offset;
                                dns_packet_writer_set_truncated(pw);
                                break;
                            }
                            dns_packet_writer_set_u16(pw, htons(pw->packet_offset - offset), offset - 2);

                            last_good_offset = pw->packet_offset;
                        }
                    }
                    else
                    {
                        p = (void **)malloc(sizeof(void *) * 2 * rrset->_record_count);
                        b = &tmp_ptrs[rrset->_record_count];
                        memcpy(b, rrset->_records, rrset->_record_count * sizeof(void *));

                        permut_pointers_randomly(p, b, rrset->_record_count, &dns_packet_writer_add_rrset_rng);

                        const zdb_resource_record_data_t *rr = p[0];

                        if(dns_packet_writer_get_remaining_capacity(pw) < 10 + 1) // + 1 because that's the minimum fqdn size
                        {
                            pw->packet_offset = last_good_offset;
                            ret = BUFFER_WOULD_OVERFLOW;
                            dns_packet_writer_set_truncated(pw);
                            break;
                        }

                        dns_packet_writer_add_u16(pw, rtype);
                        dns_packet_writer_add_u16(pw, CLASS_IN);
                        dns_packet_writer_add_u32(pw, ne_ttl);
                        // dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                        pw->packet_offset += 2;
                        uint16_t offset = pw->packet_offset;
                        if(FAIL(ret = dns_packet_writer_add_fqdn(pw, zdb_resource_record_data_rdata_const(rr))))
                        {
                            pw->packet_offset = last_good_offset;
                            dns_packet_writer_set_truncated(pw);
                            break;
                        }
                        dns_packet_writer_set_u16(pw, htons(pw->packet_offset - offset), offset - 2);

                        last_good_offset = pw->packet_offset;

                        for(int_fast32_t i = 1; i < rrset->_record_count; ++i)
                        {
                            rr = p[i];

                            if(dns_packet_writer_get_remaining_capacity(pw) < 12 + 1) // + 1 because that's the minimum fqdn size
                            {
                                pw->packet_offset = last_good_offset;
                                ret = BUFFER_WOULD_OVERFLOW;
                                dns_packet_writer_set_truncated(pw);
                                break;
                            }

                            dns_packet_writer_add_u16(pw, code);
                            dns_packet_writer_add_u16(pw, rtype);
                            dns_packet_writer_add_u16(pw, CLASS_IN);
                            dns_packet_writer_add_u32(pw, ne_ttl);
                            // dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                            pw->packet_offset += 2;
                            uint16_t offset = pw->packet_offset;
                            if(FAIL(ret = dns_packet_writer_add_fqdn(pw, zdb_resource_record_data_rdata_const(rr))))
                            {
                                pw->packet_offset = last_good_offset;
                                dns_packet_writer_set_truncated(pw);
                                break;
                            }
                            dns_packet_writer_set_u16(pw, htons(pw->packet_offset - offset), offset - 2);
                            last_good_offset = pw->packet_offset;
                        }

                        free(p);
                    }
                }

                break;
            }
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

                zdb_resource_record_set_const_iterator iter;
                zdb_resource_record_set_const_iterator_init(rrset, &iter);
                if(zdb_resource_record_set_const_iterator_has_next(&iter))
                {
                    const zdb_resource_record_data_t *rr = zdb_resource_record_set_const_iterator_next(&iter);

                    if(dns_packet_writer_get_remaining_capacity(pw) < 10 + 1) // + 1 because that's the minimum fqdn size
                    {
                        pw->packet_offset = last_good_offset;
                        ret = BUFFER_WOULD_OVERFLOW;
                        dns_packet_writer_set_truncated(pw);
                        break;
                    }

                    dns_packet_writer_add_u16(pw, rtype);
                    dns_packet_writer_add_u16(pw, CLASS_IN);
                    dns_packet_writer_add_u32(pw, ne_ttl);
                    // dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                    pw->packet_offset += 2;
                    uint16_t offset = pw->packet_offset;
                    if(FAIL(ret = dns_packet_writer_add_fqdn(pw, zdb_resource_record_data_rdata_const(rr))))
                    {
                        pw->packet_offset = last_good_offset;
                        dns_packet_writer_set_truncated(pw);
                        break;
                    }
                    dns_packet_writer_set_u16(pw, htons(pw->packet_offset - offset), offset - 2);

                    last_good_offset = pw->packet_offset;

                    while(zdb_resource_record_set_const_iterator_has_next(&iter))
                    {
                        rr = zdb_resource_record_set_const_iterator_next(&iter);

                        if(dns_packet_writer_get_remaining_capacity(pw) < 12 + 1) // + 1 because that's the minimum fqdn size
                        {
                            pw->packet_offset = last_good_offset;
                            dns_packet_writer_set_truncated(pw);
                            break;
                        }

                        dns_packet_writer_add_u16(pw, code);
                        dns_packet_writer_add_u16(pw, rtype);
                        dns_packet_writer_add_u16(pw, CLASS_IN);
                        dns_packet_writer_add_u32(pw, ne_ttl);
                        // dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                        pw->packet_offset += 2;
                        uint16_t offset = pw->packet_offset;

                        if(FAIL(ret = dns_packet_writer_add_fqdn(pw, zdb_resource_record_data_rdata_const(rr))))
                        {
                            pw->packet_offset = last_good_offset;
                            dns_packet_writer_set_truncated(pw);
                            break;
                        }
                        dns_packet_writer_set_u16(pw, htons(pw->packet_offset - offset), offset - 2);

                        last_good_offset = pw->packet_offset;
                    }
                }
                break;
            }
            case TYPE_SOA:
            {
                if(dns_packet_writer_get_remaining_capacity(pw) < 10 + 1 + 1 + 20) // + 1 because that's the minimum fqdn size
                {
                    pw->packet_offset = last_good_offset;
                    ret = BUFFER_WOULD_OVERFLOW;
                    dns_packet_writer_set_truncated(pw);
                    break;
                }

                dns_packet_writer_add_u16(pw, rtype);
                dns_packet_writer_add_u16(pw, CLASS_IN);
                dns_packet_writer_add_u32(pw, ne_ttl);

                pw->packet_offset += 2;
                uint16_t                          offset = pw->packet_offset;

                const zdb_resource_record_data_t *rr = zdb_resource_record_set_record_get_const(rrset, 0);
                const uint8_t                    *rdata = zdb_resource_record_data_rdata_const(rr); // rdata is not NULL
                uint32_t                          len1 = dnsname_len(rdata);
                if(FAIL(ret = dns_packet_writer_add_fqdn(pw, rdata)))
                {
                    pw->packet_offset = last_good_offset;
                    dns_packet_writer_set_truncated(pw);
                    break;
                }
                rdata += len1;

                uint32_t len2 = dnsname_len(rdata);
                if(FAIL(ret = dns_packet_writer_add_fqdn(pw, rdata)))
                {
                    pw->packet_offset = last_good_offset;
                    dns_packet_writer_set_truncated(pw);
                    break;
                }
                rdata += len2; // scan-build false positive : for some reason, scan-build says this sets rdata to NULL

                if(dns_packet_writer_get_remaining_capacity(pw) < 20) // + 1 because that's the minimum fqdn size
                {
                    pw->packet_offset = last_good_offset;
                    ret = BUFFER_WOULD_OVERFLOW;
                    dns_packet_writer_set_truncated(pw);
                    break;
                }

                dns_packet_writer_add_bytes(pw, rdata, 20);
                dns_packet_writer_set_u16(pw, htons(pw->packet_offset - offset), offset - 2);

                break;
            }
            default:
            {
                zdb_resource_record_set_const_iterator iter;
                zdb_resource_record_set_const_iterator_init(rrset, &iter);
                if(zdb_resource_record_set_const_iterator_has_next(&iter))
                {
                    const zdb_resource_record_data_t *rr = zdb_resource_record_set_const_iterator_next(&iter);

                    if(dns_packet_writer_get_remaining_capacity(pw) < 10 + zdb_resource_record_data_rdata_size(rr))
                    {
                        pw->packet_offset = last_good_offset;
                        ret = BUFFER_WOULD_OVERFLOW;
                        dns_packet_writer_set_truncated(pw);
                        break;
                    }

                    dns_packet_writer_add_u16(pw, rtype);
                    dns_packet_writer_add_u16(pw, CLASS_IN);
                    dns_packet_writer_add_u32(pw, ne_ttl);
                    dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                    dns_packet_writer_add_bytes(pw, zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr));

                    last_good_offset = pw->packet_offset;

                    while(zdb_resource_record_set_const_iterator_has_next(&iter))
                    {
                        rr = zdb_resource_record_set_const_iterator_next(&iter);

                        if(dns_packet_writer_get_remaining_capacity(pw) < 12 + zdb_resource_record_data_rdata_size(rr))
                        {
                            pw->packet_offset = last_good_offset;
                            ret = BUFFER_WOULD_OVERFLOW;
                            dns_packet_writer_set_truncated(pw);
                            break;
                        }

                        dns_packet_writer_add_u16(pw, code); // compression code

                        dns_packet_writer_add_u16(pw, rtype);
                        dns_packet_writer_add_u16(pw, CLASS_IN);
                        dns_packet_writer_add_u32(pw, ne_ttl);
                        dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                        dns_packet_writer_add_bytes(pw, zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr));

                        last_good_offset = pw->packet_offset;
                    }
                }

                break;
            }
        } /* switch(type) */
    } // message may be truncated

    return ret;
}

ya_result dns_packet_writer_add_rrset_rrsig(dns_packet_writer_t *pw, const uint8_t *fqdn, const zdb_resource_record_set_t *rrsig_rrset, uint16_t rtype, int32_t ne_ttl)
{
    yassert(rrsig_rrset != NULL);

    uint16_t                               last_good_offset = pw->packet_offset;
    uint16_t                               code = last_good_offset;
    uint8_t                               *p = &pw->packet[last_good_offset];

    zdb_resource_record_set_const_iterator iter;
    zdb_resource_record_set_const_iterator_init(rrsig_rrset, &iter);
    while(zdb_resource_record_set_const_iterator_has_next(&iter))
    {
        const zdb_resource_record_data_t *rr = zdb_resource_record_set_const_iterator_next(&iter);

        if(rrsig_get_type_covered_from_rdata(zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr)) == rtype)
        {
            ya_result ret = dns_packet_writer_add_fqdn(pw, fqdn);

            if(ISOK(ret))
            {
                ret = 1;

                if((*p & 0xc0) == 0xc0)
                {
                    // already compressed
                    code = GET_U16_AT_P(p);
                }
                else
                {
                    // use it
                    code = htons(code | 0xc000);
                }

                if(dns_packet_writer_get_remaining_capacity(pw) < 10 + zdb_resource_record_data_rdata_size(rr))
                {
                    pw->packet_offset = last_good_offset;
                    // ret = BUFFER_WOULD_OVERFLOW;
                    dns_packet_writer_set_truncated(pw);
                    break;
                }

                dns_packet_writer_add_u16(pw, TYPE_RRSIG);
                dns_packet_writer_add_u16(pw, CLASS_IN);
                dns_packet_writer_add_u32(pw, ne_ttl);
                dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                dns_packet_writer_add_bytes(pw, zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr));

                last_good_offset = pw->packet_offset;

                // now write each rrset using the above compressed code

                while(zdb_resource_record_set_const_iterator_has_next(&iter))
                {
                    rr = zdb_resource_record_set_const_iterator_next(&iter);

                    if(rrsig_get_type_covered_from_rdata(zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr)) == rtype)
                    {
                        if(dns_packet_writer_get_remaining_capacity(pw) < 12 + zdb_resource_record_data_rdata_size(rr))
                        {
                            pw->packet_offset = last_good_offset;
                            ret = BUFFER_WOULD_OVERFLOW;
                            dns_packet_writer_set_truncated(pw);
                            break;
                        }

                        dns_packet_writer_add_u16(pw, code);
                        dns_packet_writer_add_u16(pw, TYPE_RRSIG);
                        dns_packet_writer_add_u16(pw, CLASS_IN);
                        dns_packet_writer_add_u32(pw, ne_ttl);
                        dns_packet_writer_add_u16(pw, ntohs(zdb_resource_record_data_rdata_size(rr)));
                        dns_packet_writer_add_bytes(pw, zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr));

                        last_good_offset = pw->packet_offset;

                        ++ret;
                    }
                }
            }

            return ret;
        }
    }

    return 0;
}

ya_result dns_packet_writer_add_rrsig_rrset(dns_packet_writer_t *pw, const uint8_t *fqdn, const zdb_resource_record_set_t *rrsig_rrset)
{
    yassert(rrsig_rrset != NULL);

    uint16_t                               last_good_offset = pw->packet_offset;
    uint16_t                               code = last_good_offset;
    uint8_t                               *p = &pw->packet[last_good_offset];

    zdb_resource_record_set_const_iterator iter;
    zdb_resource_record_set_const_iterator_init(rrsig_rrset, &iter);
    if(zdb_resource_record_set_const_iterator_has_next(&iter))
    {
        const zdb_resource_record_data_t *rr = zdb_resource_record_set_const_iterator_next(&iter);

        ya_result                         ret = dns_packet_writer_add_fqdn(pw, fqdn);

        if(ISOK(ret))
        {
            if((*p & 0xc0) == 0xc0)
            {
                // already compressed
                code = GET_U16_AT_P(p);
            }
            else
            {
                // use it
                code = htons(code | 0xc000);
            }

            if(dns_packet_writer_get_remaining_capacity(pw) < 10 + zdb_resource_record_data_rdata_size(rr))
            {
                pw->packet_offset = last_good_offset;
                // ret = BUFFER_WOULD_OVERFLOW;
                dns_packet_writer_set_truncated(pw);
                return 0;
            }

            dns_packet_writer_add_u16(pw, TYPE_RRSIG);
            dns_packet_writer_add_u16(pw, CLASS_IN);
            dns_packet_writer_add_u32(pw, rrsig_get_original_ttl_from_rdata_ne(zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr)));
            dns_packet_writer_add_u16(pw, htons(zdb_resource_record_data_rdata_size(rr)));
            dns_packet_writer_add_bytes(pw, zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr));

            last_good_offset = pw->packet_offset;

            // now write each rrset using the above compressed code

            uint16_t count = 1;

            while(zdb_resource_record_set_const_iterator_has_next(&iter))
            {
                rr = zdb_resource_record_set_const_iterator_next(&iter);

                if(dns_packet_writer_get_remaining_capacity(pw) < 12 + zdb_resource_record_data_rdata_size(rr))
                {
                    pw->packet_offset = last_good_offset;
                    // ret = BUFFER_WOULD_OVERFLOW;
                    dns_packet_writer_set_truncated(pw);
                    break;
                }

                dns_packet_writer_add_u16(pw, code);
                dns_packet_writer_add_u16(pw, TYPE_RRSIG);
                dns_packet_writer_add_u16(pw, CLASS_IN);
                dns_packet_writer_add_u32(pw, rrsig_get_original_ttl_from_rdata_ne(zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr)));
                dns_packet_writer_add_u16(pw, htons(zdb_resource_record_data_rdata_size(rr)));
                dns_packet_writer_add_bytes(pw, zdb_resource_record_data_rdata_const(rr), zdb_resource_record_data_rdata_size(rr));

                last_good_offset = pw->packet_offset;
                ++count;
            }

            return count;
        }
    }

    return 0;
}

/** @} */
