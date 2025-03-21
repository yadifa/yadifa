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
 * @defgroup ### #######
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#define ZONE_SOURCE_MISSING  0
#define ZONE_SOURCE_EXISTS   1
#define ZONE_SOURCE_OBSOLETE 2
#define ZONE_SOURCE_RELEVANT 4
#define ZONE_SOURCE_TEMPLATE 8
#define ZONE_SOURCE_LOCALE   16 // on disk
#define ZONE_SOURCE_REMOTE   32 // on the primary
#define ZONE_SOURCE_LOADED   64 // in DB

struct zone_source_s
{
    uint32_t    serial;
    uint32_t    base_serial;
    uint32_t    flags;
    const char *type_name;
    uint16_t    rdata_size;
    uint8_t     rdata[SOA_RDATA_LENGTH_MAX];
};

typedef struct zone_source_s zone_source_t;

#define ZONE_SOURCE_EMPTY {0, 0, 0, "UNDEFINED"}
#define ZONE_SOURCE_INIT(__type_name)                                                                                                                                                                                                          \
    {                                                                                                                                                                                                                                          \
        0, 0, 0, (__type_name), 0, { 0 }                                                                                                                                                                                                       \
    }

static inline void zone_source_init(zone_source_t *zs, const char *type_name)
{
    zs->serial = 0;
    zs->flags = 0;
    zs->type_name = type_name;
}

static inline void zone_source_set(zone_source_t *zs, uint32_t flags) { zs->flags |= flags; }

static inline void zone_source_unset(zone_source_t *zs, uint32_t flags) { zs->flags &= ~flags; }

static inline bool zone_source_has_flags(zone_source_t *zs, uint32_t flags) { return (zs->flags & flags) == flags; }

static inline bool zone_source_exists(zone_source_t *zs)
{
    yassert(zs != NULL);

    bool ret = zone_source_has_flags(zs, ZONE_SOURCE_EXISTS);

    return ret;
}

static inline bool zone_source_is_relevant(zone_source_t *zs)
{
    yassert(zs != NULL);

    bool ret = zone_source_has_flags(zs, ZONE_SOURCE_RELEVANT | ZONE_SOURCE_EXISTS);

    return ret;
}

static inline void zone_source_disable(zone_source_t *zs)
{
    yassert(zs != NULL);

    zs->flags |= ZONE_SOURCE_OBSOLETE;
    zs->flags &= ~ZONE_SOURCE_RELEVANT;
}

static inline void zone_source_set_serial(zone_source_t *zs, uint32_t serial)
{
    yassert(zs != NULL);

    zs->serial = serial;
    zs->base_serial = serial;
}

static inline ya_result zone_source_update_serial_from_soa(zone_source_t *zs)
{
    ya_result ret;
    uint32_t  serial;
    if(ISOK(ret = rr_soa_get_serial(zs->rdata, zs->rdata_size, &serial)))
    {
        zone_source_set_serial(zs, serial);
    }
    return ret;
}

static inline void zone_source_set_journal_serial(zone_source_t *zs, uint32_t serial)
{
    yassert(zs != NULL);

    zs->serial = serial;
}

static inline int zone_source_compare(zone_source_t *zsa, zone_source_t *zsb)
{
    yassert(zsa != NULL);
    yassert(zsb != NULL);

    if(zone_source_exists(zsa))
    {
        if(zone_source_exists(zsb))
        {
            if(zsa->serial != zsb->serial)
            {
                return serial_gt(zsa->serial, zsb->serial) ? 1 : -1; // B or A
            }
            else
            {
                return 0; // equal
            }
        }
        else
        {
            return -1; // A
        }
    }
    else
    {
        if(zone_source_exists(zsb))
        {
            return 1; // B
        }
        else
        {
            return 0; // equaly lame
        }
    }
}

static inline zone_source_t *zone_source_get_best(zone_source_t *zsa, zone_source_t *zsb)
{
    yassert(zsa != NULL);
    yassert(zsb != NULL);

    if(zone_source_exists(zsa))
    {
        if(zone_source_exists(zsb))
        {
            if(zsa->serial != zsb->serial)
            {
                return serial_gt(zsa->serial, zsb->serial) ? zsa : zsb; // B or A
            }
            else
            {
                return zsa; // equal
            }
        }
        else
        {
            return zsa; // A
        }
    }
    else
    {
        if(zone_source_exists(zsb))
        {
            return zsb; // B
        }
        else
        {
            return zsa; // equaly lame
        }
    }
}

/** @} */
