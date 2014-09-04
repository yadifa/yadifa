/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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

#ifndef __ZDB_ZONE_LOAD_INTERFACE__H__
#define	__ZDB_ZONE_LOAD_INTERFACE__H__

#include <dnsdb/zdb_types.h>
#include <dnscore/bytearray_output_stream.h>

#ifdef	__cplusplus
extern "C"
{
#endif

/**
 * Structure used to describe a resource record from a zone.
 * 
 * Meant to be used by the zone reader modules :
 * 
 * TEXT FILE
 * AXFR FILE
 * 
 */
    
//#define RR_OS_RDATA

typedef struct resource_record resource_record;
struct resource_record
{
#ifdef RR_OS_RDATA
    output_stream                                                      os_rdata;
#endif

    /* Next resource record */
    resource_record                                                       *next;

    u32                                                                     ttl;
    /* Contains one of the RR TYPE codes */
    u16                                                                    type;
    /* Contains one of the RR CLASS codes */
    u16                                                                   class; /* should be renamed to something else */
    
#ifndef RR_OS_RDATA
    u16                                                              rdata_size;
#endif
    
    /* The name of the node to which this resource record pertains */
    u8                                                  name[MAX_DOMAIN_LENGTH];

    u8                                              rdata[RDATA_MAX_LENGTH + 1];
};

void resource_record_init(resource_record* entry);
void resource_record_freecontent(resource_record* entry);
void resource_record_resetcontent(resource_record* entry);

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
typedef void zone_reader_handle_error_method(zone_reader *zr, ya_result error_code);
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
    const char* __class__;
};

#define zone_reader_read_record(zr__,rr__) (zr__)->vtbl->read_record((zr__),(rr__))
#define zone_reader_free_record(zr__,rr__) (zr__)->vtbl->free_record((zr__),(rr__))
#define zone_reader_handle_error(zr__,rr__) (zr__)->vtbl->handle_error((zr__),(rr__))
#define zone_reader_close(zr__) (zr__)->vtbl->close((zr__))
#define zone_reader_canwriteback(zr__) (zr__)->vtbl->can_write_back((zr__))

#define zone_reader_unread_record(zr__,rr__) (zr__)->vtbl->unread_record((zr__),(rr__))

#ifdef RR_OS_RDATA
#define zone_reader_rdata(zr__)      bytearray_output_stream_buffer(&((zr__)->os_rdata))
#define zone_reader_rdata_size(zr__) bytearray_output_stream_size(&((zr__)->os_rdata))
#else
#define zone_reader_rdata(zr__)      ((zr__).rdata)
#define zone_reader_rdata_size(zr__) ((zr__).rdata_size)
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* __ZDB_ZONE_LOAD_INTERFACE__H__ */

/** @} */
