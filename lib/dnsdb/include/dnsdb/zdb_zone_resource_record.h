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
 * @defgroup types The types used in the database
 * @ingroup dnsdb
 * @brief The types used in the database
 *
 * The types used in the database
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

#include <dnsdb/zdb_config_features.h>

#include <dnscore/zalloc.h>
#include <dnsdb/zdb_error.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define ZDB_RDATABUF_TAG 0x4655424154414452
#define ZDB_RECORD_TAG   0x4443455242445a /** "ZDBRECD" */

#define TTLRDATA_TAG     0x41544144524c5454
#define ZDBRDATA_TAG     0x415441445242445a
#define TMPRDATA_TAG     0x4154414452504d54
#define ZDBRRSET_TAG     0x544553525242445a

struct zdb_resource_record_data_s
{
    uint16_t _rdata_size; /*  2  2 */
    uint8_t  _rdata_start[1];
};

typedef struct zdb_resource_record_data_s zdb_resource_record_data_t;

// a zdb_resource_record_data ready to store a valid SOA

struct zdb_resource_record_data_soa
{                         /* DO NOT CHANGE THE ORDER OF THE FIELDS !!! */
    uint16_t _rdata_size; /*  2  2 */
    uint8_t  _rdata_start[SOA_RDATA_LENGTH_MAX];
};

static inline uint16_t       zdb_resource_record_data_rdata_size(const zdb_resource_record_data_t *record) { return record->_rdata_size; }

static inline uint8_t       *zdb_resource_record_data_rdata(zdb_resource_record_data_t *record) { return record->_rdata_start; }

static inline const uint8_t *zdb_resource_record_data_rdata_const(const zdb_resource_record_data_t *record) { return record->_rdata_start; }

/*
 * These macros existed when 2 different ways for storing the record were
 * available at compile time.
 *
 * The zdb_resource_record_data having proved to be the best (by far),
 * the other one has been removed.
 *
 */

int                  zdb_resource_record_data_compare_records(const zdb_resource_record_data_t *rr0, const zdb_resource_record_data_t *rr1);

static inline size_t zdb_resource_record_data_storage_size_from_rdata_size(uint16_t rdata_size) { return sizeof(zdb_resource_record_data_t) - 1 + rdata_size; }

static inline size_t zdb_resource_record_data_storage_size(const zdb_resource_record_data_t *record) { return zdb_resource_record_data_storage_size_from_rdata_size(zdb_resource_record_data_rdata_size(record)); }

#define zdb_resource_record_data_storage_size_from_rdata_size(rdata_size_) (sizeof(zdb_resource_record_data_t) - 1 + (rdata_size_))

static inline void                        zdb_resource_record_data_init(zdb_resource_record_data_t *rr, uint16_t rdata_size) { rr->_rdata_size = rdata_size; }

static inline zdb_resource_record_data_t *zdb_resource_record_data_new_instance(uint16_t rdata_size)
{
    zdb_resource_record_data_t *ret;
    uint32_t                    size = zdb_resource_record_data_storage_size_from_rdata_size(rdata_size);
    ret = (zdb_resource_record_data_t *)ZALLOC_BYTES(size, ZDB_RECORD_TAG);
    ret->_rdata_size = rdata_size;
    return ret;
}

static inline zdb_resource_record_data_t *zdb_resource_record_data_new_instance_copy(uint16_t rdata_size, const uint8_t *rdata)
{
    zdb_resource_record_data_t *ret;
    uint32_t                    size = zdb_resource_record_data_storage_size_from_rdata_size(rdata_size);
    ret = (zdb_resource_record_data_t *)ZALLOC_BYTES(size, ZDB_RECORD_TAG);
    ret->_rdata_size = rdata_size;
    MEMCOPY(&ret->_rdata_start[0], rdata, rdata_size);
    return ret;
}

static inline zdb_resource_record_data_t *zdb_resource_record_data_new_instance_clone(zdb_resource_record_data_t *record)
{
    zdb_resource_record_data_t *ret;
    uint32_t                    size = sizeof(zdb_resource_record_data_t) - 1 + record->_rdata_size;
    ret = (zdb_resource_record_data_t *)ZALLOC_BYTES(size, ZDB_RECORD_TAG);
    ret->_rdata_size = record->_rdata_size;
    MEMCOPY(&ret->_rdata_start[0], record->_rdata_start, record->_rdata_size);
    return ret;
}

static inline void zdb_resource_record_data_delete(zdb_resource_record_data_t *record)
{
    uint32_t size = zdb_resource_record_data_storage_size_from_rdata_size(record->_rdata_size);
    ZFREE_BYTES(record, size);
}

static inline void zdb_resource_record_data_delete_check(zdb_resource_record_data_t *record)
{
#if DNSCORE_HAS_ZALLOC
    if(record != NULL)
    {
        uint32_t size = zdb_resource_record_data_storage_size_from_rdata_size(record->_rdata_size);

        if(size <= ZALLOC_PG_PAGEABLE_MAXSIZE)
        {
            zfree_line(record, (size - 1) >> 3);
        }
        else
        {
            free(record);
        }
    }
#else
    free(record);
#endif
}

#ifdef __cplusplus
}
#endif

/** @} */
