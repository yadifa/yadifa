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
 * @defgroup nsec3 NSEC3 functions
 * @ingroup dnsdbdnssec
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#ifndef _NSEC3_TYPES_H
#define _NSEC3_TYPES_H

#include <arpa/inet.h>

#include <dnscore/ptr_vector.h>
#include <dnscore/typebitmap.h>

#include <dnsdb/zdb_types.h>
#include <dnsdb/nsec3_collection.h>

#if !ZDB_HAS_NSEC3_SUPPORT
#error "Please do not include nsec3.h if ZDB_HAS_NSEC3_SUPPORT is 0"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * There is no sense in using more than one.
 * Two can be a transition state
 *
 * This limit is actually used for ICMTL generation
 * The NSEC3 structure is cheap on memory (every bit count on a TLD) but
 * there is a price for this.  It is mostly irrelevant, but for ICMTL and
 * anything trying to get specific NSEC3 rdata bits without knowing the
 * NSEC3PARAM as well.
 *
 */

#define NSEC3PARAM_SUPPORTED_COUNT_MAX   4

#define NSEC3_DIGEST_TAG                 0x474944334e       /* N3DIG */
#define NSEC3_ZONE_TAG                   0x454e4f5a334e     /* N3ZONE */
#define NSEC3_CONTEXT_RECORD_TAG         0x585443334e       /* N3CTX */
#define NSEC3_RDATA_TAG                  0x4154414452334e   /* N3RDATA */
#define NSEC3_LABELEXT_TAG               0x54584542414c334e /* N3LABEXT */
#define NSEC3_TYPEBITMAPS_TAG            0x5350414d4254334e /* N3TBMAPS */
#define NSEC3_LABELPTRARRAY_TAG          0x595252412a4c334e /* N3L*ARRY */

/** The NSEC3 node with this flag on is scheduled for a processing (ie: signature)
 *  It is thus FORBIDDEN to delete it (but it MUST be removed from the NSEC3 collection)
 *
 *  So instead of a delete the NSEC3_PROPRIETARY_FLAG_DELETED flag should be used and the NSEC3 record has to be put in
 * a "scheduled for delete" list.  The schedule being done after the signature the nsec3 record will be effectively
 * removed.
 *
 */

#define NSEC3_PROPRIETARY_FLAG_SCHEDULED 0x80
#define NSEC3_PROPRIETARY_FLAG_DELETED   0x40

/**
 * @note 20161011 edf -- to sum it up :
 *
 * 1 byte for the hash
 * 1 bytes for the flags
 * 1 byte for the opt-out flag
 * 2 bytes for the iterations
 * 1 byte for the salt length
 * 255 bytes for the salt
 * 1 byte for the hash len
 * 255 bytes for the hash
 * 256 * (1 + 1 +32) bytes for the type bitmap encoding
 */

#define TMP_NSEC3_TTLRDATA_SIZE          (1 + 1 + 1 + 2 + 1 + DOMAIN_LENGTH_MAX + 1 + DOMAIN_LENGTH_MAX + TYPE_BIT_MAPS_RDATA_SIZE_MAX)

struct nsec3_node_s;
typedef struct nsec3_node_s nsec3_zone_item_t;

/*
 * Index instead of a pointer.
 * The relevant information are:
 *
 * index
 * (index+1) MOD count
 */

struct nsec3_label_extension_s
{
    nsec3_zone_item_t              *_self;
    nsec3_zone_item_t              *_star;

    struct nsec3_label_extension_s *_next;
};

typedef struct nsec3_label_extension_s  nsec3_label_extension_t;
typedef nsec3_label_extension_t       **nsec3_label_extension_array;

static inline nsec3_zone_item_t        *nsec3_label_extension_self(const nsec3_label_extension_t *n3le) { return n3le->_self; }

static inline nsec3_zone_item_t        *nsec3_label_extension_star(const nsec3_label_extension_t *n3le) { return n3le->_star; }

static inline nsec3_label_extension_t  *nsec3_label_extension_next(const nsec3_label_extension_t *n3le) { return n3le->_next; }

static inline void                      nsec3_label_extension_set_self(nsec3_label_extension_t *n3le, nsec3_zone_item_t *self) { n3le->_self = self; }

static inline void                      nsec3_label_extension_set_star(nsec3_label_extension_t *n3le, nsec3_zone_item_t *star) { n3le->_star = star; }

static inline void                      nsec3_label_extension_set_next(nsec3_label_extension_t *n3le, nsec3_label_extension_t *next) { n3le->_next = next; }

static inline nsec3_label_extension_t **nsec3_label_extension_next_ptr(nsec3_label_extension_t *n3le) { return &n3le->_next; }

static inline nsec3_label_extension_t  *nsec3_label_extension_get_from_label(zdb_rr_label_t *label, int index)
{
    yassert(label != NULL);

    // yassert(index > 0);
    nsec3_label_extension_t *n3e = label->nsec.nsec3;
    while(index > 0)
    {
        yassert(n3e != NULL);
        n3e = nsec3_label_extension_next(n3e);
        index--;
    }
    return n3e;
}

struct nsec3_zone_s
{
    nsec3_zone_t      *next;               // next chain
    nsec3_zone_item_t *items;              // collection
    uint32_t           nsec3param_size;    // size of both nsec3_rdata_prefix and rdata
    uint8_t           *nsec3_rdata_prefix; // with the flags byte set
    uint8_t            rdata[];            // NSEC3PARAM head
};

#define NSEC3PARAM_LENGTH_MIN                          5
#define NSEC3PARAM_LENGTH_MAX                          260

#define NSEC3PARAM_RDATA_ALGORITHM(n3prd)              (((const uint8_t *)(n3prd))[0])
#define NSEC3PARAM_RDATA_FLAGS(n3prd)                  (((const uint8_t *)(n3prd))[1])
#define NSEC3PARAM_RDATA_ITERATIONS_NE(n3prd)          GET_U16_AT(((const uint8_t *)(n3prd))[2])       // network order
#define NSEC3PARAM_RDATA_ITERATIONS(n3prd)             NU16(GET_U16_AT(((const uint8_t *)(n3prd))[2])) // network order
#define NSEC3PARAM_RDATA_SALT_LEN(n3prd)               (((const uint8_t *)(n3prd))[4])
#define NSEC3PARAM_RDATA_SALT(n3prd)                   (&((uint8_t *)(n3prd))[NSEC3PARAM_LENGTH_MIN])
#define NSEC3PARAM_RDATA_SIZE_FROM_SALT(salt_len)      (NSEC3PARAM_LENGTH_MIN + (salt_len))
#define NSEC3PARAM_RDATA_SIZE_FROM_RDATA(rdata_bytes_) (NSEC3PARAM_RDATA_SIZE_FROM_SALT(NSEC3PARAM_RDATA_SALT_LEN(rdata_bytes_)))
#define NSEC3_RDATA_HASLEN(n3prd)                      (((const uint8_t *)(n3prd))[5 + NSEC3PARAM_RDATA_SALT_LEN(n3prd)])
#define NSEC3_RDATA_BITMAP(n3prd)                      (&((const uint8_t *)(n3prd))[5 + NSEC3PARAM_RDATA_SALT_LEN(n3prd) + 1 + NSEC3_RDATA_HASLEN(n3prd)])

#define NSEC3_ZONE_ALGORITHM(n3_)                      NSEC3PARAM_RDATA_ALGORITHM((n3_)->rdata)
#define NSEC3_ZONE_FLAGS(n3_)                          NSEC3PARAM_RDATA_FLAGS((n3_)->rdata)
#define NSEC3_ZONE_ITERATIONS(n3_)                     NSEC3PARAM_RDATA_ITERATIONS((n3_)->rdata)
#define NSEC3_ZONE_SALT_LEN(n3_)                       NSEC3PARAM_RDATA_SALT_LEN((n3_)->rdata)
#define NSEC3_ZONE_SALT(n3_)                           NSEC3PARAM_RDATA_SALT((n3_)->rdata)

#define NSEC3PARAM_DEFAULT_TTL                         0

/// @note: defined in rfc.h : NSEC3_FLAGS_OPTOUT 0x01

#define NSEC3_FLAGS_MARKED_FOR_ICMTL_ADD                                                                                                                                                                                                       \
    0x80 /* DO NOT PUT THIS IN THE RFC                                                                                                                                                                                                         \
          * IT'S PROPRIETARY                                                                                                                                                                                                                   \
          */
#define NSEC3_FLAGS_MARKED_FOR_ICMTL_DEL                                                                                                                                                                                                       \
    0x40 /* DO NOT PUT THIS IN THE RFC                                                                                                                                                                                                         \
          * IT'S PROPRIETARY                                                                                                                                                                                                                   \
          */

#define NSEC3_ZONE_STRUCT_SIZE_FROM_SALT(salt_len) (sizeof(nsec3_zone) + NSEC3PARAM_RDATA_SIZE_FROM_SALT(salt_len) - 1)

// #define NSEC3PARAM_RDATA_SIZE_FROM_CHAIN(n3_) NSEC3PARAM_RDATA_SIZE_FROM_SALT(NSEC3_ZONE_SALT_LEN(n3_))
#define NSEC3PARAM_RDATA_SIZE_FROM_CHAIN(n3_)      ((n3_)->nsec3param_size)
#define NSEC3_ZONE_RDATA_SIZE(n3_)                 NSEC3PARAM_RDATA_SIZE_FROM_SALT(NSEC3_ZONE_SALT_LEN(n3_))
#define NSEC3_ZONE_STRUCT_SIZE(n3_)                NSEC3_ZONE_STRUCT_SIZE_FROM_SALT(NSEC3_ZONE_SALT_LEN(n3_))

#define nsec3_zone_get_iterations(n3_)             (ntohs(GET_U16_AT((n3_)->rdata[2])))
#define nsec3_zone_set_iterations(n3_, iter_)      (GET_U16_AT((n3_)->rdata[2]) = htons(iter_))

#define nsec3_zone_get_item_next(n3_, idx_)        ((nsec3_zone_item_t *)((n3_)->items.data[(idx_ + 1) % nsec3_zone_get_item_count(n3_)]))

#define ZONE_HAS_NSEC3PARAM(zone_)                 (((zone_)->nsec.nsec3 != NULL) && (zdb_resource_record_sets_find(&(zone_)->apex->resource_record_set, TYPE_NSEC3PARAM) != NULL))
#define ZONE_NSEC3_AVAILABLE(zone_)                (zdb_rr_label_flag_isset(((zone_)->apex), ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT))

static inline bool                     zdb_rr_label_nsec_linked(const zdb_rr_label_t *label) { return (label->_flags & ZDB_RR_LABEL_NSEC) != 0; }

static inline bool                     zdb_rr_label_nsec3_linked(const zdb_rr_label_t *label) { return (label->_flags & ZDB_RR_LABEL_NSEC3) != 0; }

static inline bool                     zdb_rr_label_nsec3optout_linked(const zdb_rr_label_t *label) { return (label->_flags & ZDB_RR_LABEL_NSEC3_OPTOUT) != 0; }

static inline bool                     zdb_rr_label_nsec3any_linked(const zdb_rr_label_t *label) { return (label->_flags & (ZDB_RR_LABEL_NSEC3 | ZDB_RR_LABEL_NSEC3_OPTOUT)) != 0; }

static inline nsec3_label_extension_t *nsec3_label_extension_alloc()
{
    nsec3_label_extension_t *n3le;
    ZALLOC_OBJECT_OR_DIE(n3le, nsec3_label_extension_t, NSEC3_LABELEXT_TAG); // in nsec3_label_link
#if DEBUG
    memset(n3le, 0xac, sizeof(nsec3_label_extension_t));
#endif
    return n3le;
}

static inline nsec3_label_extension_t *nsec3_label_extension_alloc_list(int count)
{
    nsec3_label_extension_t *n3le = nsec3_label_extension_alloc();
    n3le->_self = NULL;
    n3le->_star = NULL;
    nsec3_label_extension_t *prev = n3le;
    while(--count > 0)
    {
        prev->_next = nsec3_label_extension_alloc();
        prev = prev->_next;
        prev->_self = NULL;
        prev->_star = NULL;
    }
    prev->_next = NULL;

    return n3le;
}

static inline void nsec3_label_extension_free(nsec3_label_extension_t *n3le)
{
#if DEBUG
    memset(n3le, 0xfe, sizeof(nsec3_label_extension_t));
#endif
    ZFREE(n3le, nsec3_label_extension_t);
}

static inline uint8_t nsec3param_get_flags(void *rdata_)
{
    uint8_t *rdata = (uint8_t *)rdata_;
    return rdata[1];
}

static inline void nsec3param_set_flags(void *rdata_, uint8_t flags)
{
    uint8_t *rdata = (uint8_t *)rdata_;
    rdata[1] = flags;
}

static inline const uint8_t *nsec3_type_bitmaps_get(const void *rdata_, uint16_t rdata_size, uint16_t *bitmaps_sizep)
{
    if(rdata_size >= 26)
    {
        const uint8_t *rdata = (const uint8_t *)rdata_;
        int            salt_len = rdata[4];
        int            hash_pos = 5 + salt_len;
        if(hash_pos < rdata_size)
        {
            int hash_len = rdata[hash_pos];
            int bitmaps_pos = hash_pos + 1 + hash_len;
            if(bitmaps_pos < rdata_size)
            {
                if(bitmaps_sizep != NULL)
                {
                    *bitmaps_sizep = rdata_size - bitmaps_pos;
                }
                return &rdata[bitmaps_pos];
            }
        }
    }
    return NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* _NSEC3_TYPES_H */
/** @} */
