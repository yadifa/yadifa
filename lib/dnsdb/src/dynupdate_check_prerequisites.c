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

/** @defgroup dnsdbupdate Dynamic update functions
 *  @ingroup dnsdb
 *  @brief
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include "dnsdb/dnsdb-config.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <dnscore/rfc.h>
#include <dnscore/ptr_vector.h>
#include <dnscore/dnsname.h>

#include "dnsdb/dynupdate.h"
#include "dnsdb/zdb_rr_label.h"
#include "dnsdb/zdb_record.h"
#include "dnsdb/zdb_zone.h"

/*
 *
 */

#define ZDB_DYNUPDATE_TAG 0x1111111111111111

typedef struct name_type_rdata name_type_rdata;

struct name_type_rdata
{
    u8* rname;
    u8* rdata;
    u16 rtype;
    u16 rdata_size;
};

static int
name_type_rdata_compare(const void* a, const void* b)
{
    int cmp;

    name_type_rdata* ia = (name_type_rdata*)a;
    name_type_rdata* ib = (name_type_rdata*)b;

    /* strcmp is adequate for this test */

    if((cmp = strcmp((char*)ia->rname, (char*)ib->rname)) != 0)
    {
        return cmp;
    }

    cmp = ia->rtype;
    cmp -= ib->rtype;

    return cmp;
}

static void
name_type_rdata_free(void* a)
{
    free(a);
}

static void
free_rrsets(ptr_vector* rrsetsp)
{
    ptr_vector_callback_and_clear(rrsetsp, name_type_rdata_free);
    ptr_vector_destroy(rrsetsp);
}

/*
 * Input stream here is not a good idea because
 *
 * A) Like Gery said, the buffer is 64K max.
 * B) Using an input stream would require me to copy & allocate memory,
 *    this way only requires it for the last case, and only a "token",
 *    never a string.
 */

ya_result
dynupdate_check_prerequisites(zdb_zone* zone, packet_unpack_reader_data *reader, u16 count)
{
    if(zdb_zone_invalid(zone))
    {
        return ZDB_ERROR_ZONE_INVALID;
    }
    
    if(count == 0)
    {
        return SUCCESS;
    }
    
    dnsname_vector *origin_path;
    dnsname_vector name_path;

    ptr_vector rrsets;

    u8* rname;
    u8* rdata;
    u32 rname_size;
    u16 rtype;
    u16 rclass;
    u16 rdata_size;
    u8 wire[MAX_DOMAIN_LENGTH + 10 + 65536];

    origin_path = &zone->origin_vector;

    ptr_vector_init(&rrsets);

    while(count-- > 0)
    {
        ya_result return_value;
        
        if(FAIL(return_value = packet_reader_read_record(reader, wire, sizeof(wire))))
        {
            free_rrsets(&rrsets);
            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }
        
        rname = wire;
        rname_size = dnsname_len(wire);
        rtype = GET_U16_AT(wire[rname_size]);
        rclass = GET_U16_AT(wire[rname_size + 2]);
        rdata_size = ntohs(GET_U16_AT(wire[rname_size + 8]));        
        rdata = &wire[rname_size + 10];

        dnsname_to_dnsname_vector(rname, &name_path);

        s32 idx;

        for(idx = 0; idx < origin_path->size; idx++)
        {
            if(!dnslabel_equals(origin_path->labels[origin_path->size - idx], name_path.labels[name_path.size - idx]))
            {
                free_rrsets(&rrsets);
                return RCODE_ERROR_CODE(RCODE_NOTZONE);
            }
        }

        if(rclass == CLASS_ANY)
        {
            if(rdata_size != 0)
            {
                free_rrsets(&rrsets);
                return RCODE_ERROR_CODE(RCODE_FORMERR);
            }

            zdb_rr_label* label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - origin_path->size) - 1);

            if(rtype == TYPE_ANY)
            {
                if(label == NULL)
                {
                    free_rrsets(&rrsets);
                    return RCODE_ERROR_CODE(RCODE_NXDOMAIN);
                }
            }
            else
            {
                if(label == NULL)
                {
                    free_rrsets(&rrsets);
                    return RCODE_ERROR_CODE(RCODE_NXRRSET);
                }

                if(zdb_record_find(&label->resource_record_set, rtype) == NULL)
                {
                    free_rrsets(&rrsets);
                    return RCODE_ERROR_CODE(RCODE_NXRRSET);
                }
            }
        }
        else if(rclass == CLASS_NONE)
        {
            if(rdata_size != 0)
            {
                free_rrsets(&rrsets);
                return RCODE_ERROR_CODE(RCODE_FORMERR);
            }

            zdb_rr_label* label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - origin_path->size) - 1);

            if(rtype == TYPE_ANY)
            {
                if(label != NULL)
                {
                    free_rrsets(&rrsets);
                    return RCODE_ERROR_CODE(RCODE_YXDOMAIN);
                }
            }
            else
            {
                if(label != NULL)
                {
                    if(zdb_record_find(&label->resource_record_set, rtype) != NULL)
                    {
                        free_rrsets(&rrsets);
                        return RCODE_ERROR_CODE(RCODE_YXRRSET);
                    }
                } // else label is NULL
            }
        }
        else if(rclass == zdb_zone_getclass(zone))
        {
            name_type_rdata* item;
            MALLOC_OBJECT_OR_DIE(item, name_type_rdata, ZDB_DYNUPDATE_TAG);
            item->rname = rname;
            item->rdata = rdata;
            item->rtype = rtype;
            item->rdata_size = rdata_size;
            ptr_vector_append(&rrsets, item);
        }
        else
        {
            free_rrsets(&rrsets);
            return RCODE_ERROR_CODE(RCODE_FORMERR);
        }
    }
    
    ptr_vector_qsort(&rrsets, name_type_rdata_compare);

    /*
     * Get the first name.
     * While the next records have this name ...
     *   Get the first type
     *   while the next records have this type ...
     *      Test that the record has a match
     *      Decrement the match count (dual record queries are an error)
     *
     */

    if(ptr_vector_size(&rrsets) > 0)
    {
        zdb_rr_label* label = NULL;
        zdb_packed_ttlrdata* rr_sll = NULL;

        u8* last_name = (u8*)"\0377";
        u16 last_type = 0;
        s32 required_matches = 0;

        name_type_rdata** itemp;
        s32 record_count = ptr_vector_last_index(&rrsets); // record_count >= 0

        itemp = (name_type_rdata**)rrsets.data;

        while(record_count-- >= 0)
        {
            name_type_rdata* item = *itemp++;

            if(!dnsname_equals(item->rname, last_name))
            {
                if(required_matches != 0)
                {
                    free_rrsets(&rrsets);
                    return RCODE_ERROR_CODE(RCODE_NXRRSET);
                }

                last_name = item->rname;

                /*
                 * It's a new name: get the rr_label
                 */

                dnsname_to_dnsname_vector(item->rname, &name_path);

                label = zdb_rr_label_find_exact(zone->apex, name_path.labels, (name_path.size - origin_path->size) - 1);

                if(label == NULL)
                {
                    free_rrsets(&rrsets);
                    return RCODE_ERROR_CODE(RCODE_NXRRSET);
                }

                last_type = 0; // forces the next test
            }

            if(last_type != item->rtype)
            {
                if(required_matches != 0)
                {
                    free_rrsets(&rrsets);
                    return RCODE_ERROR_CODE(RCODE_NXRRSET);
                }

                last_type = item->rtype;

                /*
                 * get the type's rr list
                 * compute the size of the list
                 */

                if(label != NULL)
                {
                    rr_sll = zdb_record_find(&label->resource_record_set, last_type);
                }
                else
                {
                    rr_sll = NULL;
                }

                required_matches = 0;

                zdb_packed_ttlrdata* rr = rr_sll;

                while(rr != NULL)
                {
                    required_matches++;

                    rr = rr->next;
                }
            }

            /*
             * check that the rdata exists
             *
             * if not: break
             *
             * if yes: decrement the counter
             */

            zdb_packed_ttlrdata* rr = rr_sll;

            while(rr != NULL)
            {
                if(rr->rdata_size == item->rdata_size)
                {
                    /*
                     * the records are read canonised to lower-case 
                     */

                    if(memcmp(&rr->rdata_start[0], item->rdata, item->rdata_size) == 0)
                    {
                        /*
                         * match
                         */

                        required_matches--;
                        break;
                    }
                }

                rr = rr->next;
            }

            if(rr == NULL)
            {
                /*
                 * no match
                 */

                free_rrsets(&rrsets);
                return RCODE_ERROR_CODE(RCODE_NXRRSET);
            }
        }
    }

    free_rrsets(&rrsets);

    return reader->offset;
}

/** @} */
