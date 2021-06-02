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

/** @defgroup dnsdbzone Zone related functions
 *  @ingroup dnsdb
 *  @brief Functions used to manipulate a zone
 *
 *  Functions used to manipulate a zone
 *
 * @{
 */

#pragma once

#include <dnscore/sys_types.h>
#include <dnscore/rfc.h>

#ifdef	__cplusplus
extern "C"
{
#endif

#define ZONEFILE_ERROR_BASE                       0x800a0000
#define ZONEFILE_ERROR_CODE(code_)                ((s32)(ZONEFILE_ERROR_BASE+(code_)))

#define ZONEFILE_FEATURE_NOT_SUPPORTED            ZONEFILE_ERROR_CODE(0x0001)
#define ZONEFILE_EXPECTED_FILE_PATH               ZONEFILE_ERROR_CODE(0x0002)
#define ZONEFILE_SOA_WITHOUT_CLASS                ZONEFILE_ERROR_CODE(0x0003)
#define ZONEFILE_SALT_TOO_BIG                     ZONEFILE_ERROR_CODE(0x0011)
#define ZONEFILE_TEXT_TOO_BIG                     ZONEFILE_ERROR_CODE(0x0012)
#define ZONEFILE_FLAGS_TOO_BIG                    ZONEFILE_ERROR_CODE(0x0013)
#define ZONEFILE_SERVICE_TOO_BIG                  ZONEFILE_ERROR_CODE(0x0014)
#define ZONEFILE_REGEX_TOO_BIG                    ZONEFILE_ERROR_CODE(0x0015)
#define ZONEFILE_RDATA_PARSE_ERROR                ZONEFILE_ERROR_CODE(0x0016)
#define ZONEFILE_RDATA_BUFFER_TOO_SMALL           ZONEFILE_ERROR_CODE(0x0017)
#define ZONEFILE_RDATA_SIZE_MISMATCH              ZONEFILE_ERROR_CODE(0x0018)

/**
 * Structure used to describe a resource record from a zone.
 * 
 * Meant to be used by the zone reader modules :
 * 
 * TEXT FILE
 * AXFR FILE
 * 
 */
    
#define DNSRR_TAG 0x5252534e44
    
typedef struct resource_record resource_record;
struct resource_record
{
    /* Next resource record */
    resource_record                                                  *next;

    s32                                                                ttl;
    /* Contains one of the RR TYPE codes */
    u16                                                               type;
    /* Contains one of the RR CLASS codes */
    u16                                                              class; /* should be renamed to something else */
    
    u16                                                         rdata_size;
    
    /* The name of the node to which this resource record pertains */
    u8                                              name[MAX_DOMAIN_LENGTH];

    u8                                              rdata[RDATA_MAX_LENGTH];
};

#if MAX_DOMAIN_LENGTH < 255
#error "MAX_DOMAIN_LENGTH must be 255 at least"
#endif


static inline void resource_record_init(resource_record* entry)
{
    memset(entry, 0, (offsetof(resource_record, name) + 7) & ~7);
    /*
    entry->next    = NULL;
    entry->ttl     = 0;
    entry->type    = 0;
    entry->class   = 0;

    entry->rdata_size = 0;

    entry->name[0] = 0;
    entry->name[1] = 0;
     */
}

static inline void resource_record_copy(resource_record* entry, const resource_record* source)
{
    memcpy(entry, source, offsetof(resource_record, name));
    dnsname_copy(entry->name, source->name);
    memcpy(entry->rdata, source->rdata, source->rdata_size);
}

static inline bool resource_record_equals(resource_record* entry, const resource_record* source)
{
    if(memcmp(entry, source, offsetof(resource_record, name)) == 0)
    {
        if(dnsname_equals(entry->name, source->name))
        {
            if(memcmp(entry->rdata, source->rdata, source->rdata_size) == 0)
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static inline void resource_record_init_from(resource_record* entry, const resource_record* source)
{
    resource_record_copy(entry, source);
    entry->next = NULL;
}

static inline void resource_record_freecontent(resource_record* entry)
{
    yassert(entry != NULL);
    (void)entry;
}

static inline void resource_record_resetcontent(resource_record* entry)
{
    yassert(entry != NULL);

    /* Resets the RDATA output stream so we can fill it again */

    entry->rdata_size = 0;
}

static inline s32 resource_record_size(resource_record* entry)
{
    return entry->rdata_size + 10 + dnsname_len(entry->name);
}

struct zone_reader_vtbl;

typedef struct zone_reader zone_reader;
struct zone_reader
{
    void *data;
    const struct zone_reader_vtbl *vtbl;
};

typedef ya_result zone_reader_read_record_method(zone_reader *, resource_record *);
typedef ya_result zone_reader_unread_record_method(zone_reader *, resource_record *);
typedef ya_result zone_reader_free_record_method(zone_reader *, resource_record *);
typedef void zone_reader_close_method(zone_reader *);
typedef void zone_reader_handle_error_method(zone_reader *zr, ya_result error_code); // used for cleaning up after an error (AXFR feedback)
typedef const char* zone_reader_get_last_error_message_method(zone_reader *zr);
typedef bool zone_reader_canwriteback_method(zone_reader *);

typedef struct zone_reader_vtbl zone_reader_vtbl;
struct zone_reader_vtbl
{
    zone_reader_read_record_method *read_record;
    zone_reader_unread_record_method *unread_record;
    zone_reader_free_record_method *free_record;
    zone_reader_close_method *close;
    zone_reader_handle_error_method *handle_error;
    zone_reader_canwriteback_method *can_write_back;
    zone_reader_get_last_error_message_method *get_last_error_message;
    const char* __class__;
};

#define zone_reader_read_record(zr__,rr__) (zr__)->vtbl->read_record((zr__),(rr__))
#define zone_reader_free_record(zr__,rr__) (zr__)->vtbl->free_record((zr__),(rr__))
#define zone_reader_handle_error(zr__,rr__) (zr__)->vtbl->handle_error((zr__),(rr__))
#define zone_reader_close(zr__) (zr__)->vtbl->close((zr__))
#define zone_reader_canwriteback(zr__) (zr__)->vtbl->can_write_back((zr__))
#define zone_reader_get_last_error_message(zr__) (zr__)->vtbl->get_last_error_message((zr__))
#define zone_reader_unread_record(zr__,rr__) (zr__)->vtbl->unread_record((zr__),(rr__))

#define zone_reader_rdata(zr__)      ((zr__).rdata)
#define zone_reader_rdata_size(zr__) ((zr__).rdata_size)

#ifdef	__cplusplus
}
#endif

/** @} */
