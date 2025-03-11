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
 * @defgroup types The types used in the database
 * @ingroup dnsdb
 * @brief The types used in the database
 *
 * The types used in the database
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnscore/dns_packet_writer.h>
#include <dnsdb/zdb_zone_resource_record.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct zdb_resource_record_set_s
{
    int32_t  _ttl;
    uint16_t _type;
    int16_t  _record_count;
    union
    {
        zdb_resource_record_data_t  *_record;
        zdb_resource_record_data_t **_records;
    };
};

typedef struct zdb_resource_record_set_s       zdb_resource_record_set_t;

typedef zdb_resource_record_data_t             zdb_resource_record_data;

typedef const struct zdb_resource_record_set_s zdb_resource_record_set_const_t;

struct zdb_resource_record_set_iterator_s
{
    zdb_resource_record_data_t **rr;
    zdb_resource_record_data_t **rr_limit;
};

typedef struct zdb_resource_record_set_iterator_s zdb_resource_record_set_iterator_t;

typedef zdb_resource_record_set_iterator_t        zdb_resource_record_set_iterator;

struct zdb_resource_record_set_const_iterator_s
{
    const zdb_resource_record_data_t **rr;
    const zdb_resource_record_data_t **rr_limit;
};

typedef struct zdb_resource_record_set_const_iterator_s zdb_resource_record_set_const_iterator_t;

typedef zdb_resource_record_set_const_iterator_t        zdb_resource_record_set_const_iterator;

void                                                    zdb_resource_record_set_insert_record(zdb_resource_record_set_t *rrset, zdb_resource_record_data_t *record);

void                                                    zdb_resource_record_set_insert_record_with_ttl(zdb_resource_record_set_t *rrset, zdb_resource_record_data_t *record, int32_t ttl);

bool                                                    zdb_resource_record_set_insert_record_with_ttl_checked(zdb_resource_record_set_t *rrset, zdb_resource_record_data_t *record, int32_t ttl);

bool                                                    zdb_resource_record_set_insert_record_with_ttl_checked_with_mp(zdb_resource_record_set_t *rrset, zdb_resource_record_data_t *record, int32_t ttl, memory_pool_t *mp);

static inline bool                                      zdb_resource_record_set_of_one(const zdb_resource_record_set_t *rrset) { return rrset->_record_count == 1; }

static inline bool                                      zdb_resource_record_set_isempty(const zdb_resource_record_set_t *rrset) { return rrset->_record_count == 0; }

static inline int                                       zdb_resource_record_set_size(const zdb_resource_record_set_t *rrset) { return rrset->_record_count; }

static inline int32_t                                   zdb_resource_record_set_ttl(const zdb_resource_record_set_t *rrset) { return rrset->_ttl; }

static inline uint16_t                                  zdb_resource_record_set_type(const zdb_resource_record_set_t *rrset) { return rrset->_type; }

static inline const uint16_t                           *zdb_resource_record_set_typep(const zdb_resource_record_set_t *rrset) { return &rrset->_type; }

void                                                    zdb_resource_record_set_init(zdb_resource_record_set_t *rr, uint16_t type, int32_t ttl);

void                                                    zdb_resource_record_set_init_with_one_record(zdb_resource_record_set_t *rrset, uint16_t type, int32_t ttl, zdb_resource_record_data_t *rr);

zdb_resource_record_set_t                              *zdb_resource_record_set_new_instance(uint16_t type, int32_t ttl);

void                                                    zdb_resource_record_set_delete(zdb_resource_record_set_t *rrset);

void                                                    zdb_resource_record_set_clear(zdb_resource_record_set_t *rrset);

bool                                                    zdb_resource_record_set_delete_matching(zdb_resource_record_set_t *rrset, bool (*matching)(const zdb_resource_record_data_t *record, const void *data), const void *data);

bool                                                    zdb_resource_record_set_delete_by_rdata(zdb_resource_record_set_t *rrset, const void *data, uint16_t rdata_size);

static inline void                                      zdb_resource_record_set_iterator_init(zdb_resource_record_set_t *rrset, zdb_resource_record_set_iterator_t *iter)
{
    if(rrset->_record_count > 1)
    {
        iter->rr = &rrset->_records[0];
        iter->rr_limit = &rrset->_records[rrset->_record_count];
    }
    else if(rrset->_record_count == 1)
    {
        iter->rr = &rrset->_record;
        iter->rr_limit = iter->rr + 1;
    }
    else
    {
        iter->rr = NULL;
        iter->rr_limit = NULL;
    }
}

static inline bool                        zdb_resource_record_set_iterator_has_next(zdb_resource_record_set_iterator_t *iter) { return iter->rr < iter->rr_limit; }

static inline zdb_resource_record_data_t *zdb_resource_record_set_iterator_next(zdb_resource_record_set_iterator_t *iter)
{
    zdb_resource_record_data_t *ret = *iter->rr;
    ++iter->rr;
    return ret;
}

static inline void zdb_resource_record_set_const_iterator_init(zdb_resource_record_set_const_t *rrset, zdb_resource_record_set_const_iterator *iter)
{
    if(rrset->_record_count > 1)
    {
        iter->rr = (const zdb_resource_record_data_t **)&rrset->_records[0];
        iter->rr_limit = (const zdb_resource_record_data_t **)&rrset->_records[rrset->_record_count];
    }
    else if(rrset->_record_count == 1)
    {
        iter->rr = (const zdb_resource_record_data_t **)&rrset->_record;
        iter->rr_limit = iter->rr + 1;
    }
    else
    {
        iter->rr = NULL;
        iter->rr_limit = NULL;
    }
}

static inline bool                              zdb_resource_record_set_const_iterator_has_next(zdb_resource_record_set_const_iterator *iter) { return iter->rr < iter->rr_limit; }

static inline const zdb_resource_record_data_t *zdb_resource_record_set_const_iterator_next(zdb_resource_record_set_const_iterator *iter)
{
    const zdb_resource_record_data_t *ret = *iter->rr;
    ++iter->rr;
    return ret;
}

void                              zdb_resource_record_set_add_records_delete_duplicates_from_source(zdb_resource_record_set_t *to_rrset, zdb_resource_record_set_t *from_rrset);

zdb_resource_record_data_t       *zdb_resource_record_set_record_get(zdb_resource_record_set_t *rrset, int index);

const zdb_resource_record_data_t *zdb_resource_record_set_record_get_const(const zdb_resource_record_set_t *rrset, int index);

ya_result                         dns_packet_writer_add_rrset(dns_packet_writer_t *pw, const uint8_t *fqdn, const zdb_resource_record_set_t *rrset);

ya_result                         dns_packet_writer_add_rrset_rrsig(dns_packet_writer_t *pw, const uint8_t *fqdn, const zdb_resource_record_set_t *rrsig_rrset, uint16_t rtype, int32_t ne_ttl);

ya_result                         dns_packet_writer_add_rrsig_rrset(dns_packet_writer_t *pw, const uint8_t *fqdn, const zdb_resource_record_set_t *rrsig_rrset);

ya_result                         dns_packet_writer_add_rrset_with_rrsig(dns_packet_writer_t *pw, const uint8_t *fqdn, const zdb_resource_record_set_t *rrset, const zdb_resource_record_set_t *rrsig_rrset);

/*
static int zdb_record_permut_2[2][2] =
{
    {0, 1},
    {1, 0}
};

static int zdb_record_permut_3[2][3] =
{
    {1, 2, 0},
    {2, 1, 0}
};

// for value 4
int permut_4[2][4] =
{
    {  1, 2, 3, 0, },
    {  3, 2, 1, 0, },
};

// for value 5
int permut_5[4][5] =
{
    {  1, 2, 3, 4, 0, },
    {  2, 4, 1, 3, 0, },
    {  3, 1, 4, 2, 0, },
    {  4, 3, 2, 1, 0, },
};

// for value 6
int permut_6[2][6] =
{
    {  1, 2, 3, 4, 5, 0, },
    {  5, 4, 3, 2, 1, 0, },
};

// for value 7
int permut_7[6][7] =
{
    {  1, 2, 3, 4, 5, 6, 0, },
    {  2, 4, 6, 1, 3, 5, 0, },
    {  3, 6, 2, 5, 1, 4, 0, },
    {  4, 1, 5, 2, 6, 3, 0, },
    {  5, 3, 1, 6, 4, 2, 0, },
    {  6, 5, 4, 3, 2, 1, 0, },
};

// for value 8
int permut_8[4][8] =
{
    {  1, 2, 3, 4, 5, 6, 7, 0, },
    {  3, 6, 1, 4, 7, 2, 5, 0, },
    {  5, 2, 7, 4, 1, 6, 3, 0, },
    {  7, 6, 5, 4, 3, 2, 1, 0, },
};

static inline int zdb_resource_record_set_permutate(zdb_resource_record_set_const_t *rrset, zdb_resource_record_data_t
**record_array, int record_array_size)
{
    int n = zdb_resource_record_data_count(rrset);
    zdb_resource_record_data_t *record = rrset;
    if(n <= record_array_size)
    {
        switch(n)
        {
            case 1:
            {
                record_array[0] = record;
                return 1;
            }
            case 2:
            {
                record_array[zdb_record_permut_2[0]] = record;
                record_array[zdb_record_permut_2[1]] = record;
                return 1;
            }
        }
    }
}
*/

#ifdef __cplusplus
}
#endif

/** @} */
