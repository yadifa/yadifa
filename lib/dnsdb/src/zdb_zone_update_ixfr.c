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
 *  @brief
 *
 *
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <dnscore/sys_types.h>
#include <dnscore/dnssec_errors.h>

#include "dnsdb/zdb_types.h"
#include "dnsdb/zdb_zone.h"
#include "dnsdb/zdb_zone_label.h"
#include "dnsdb/zdb_utils.h"

#include <dnscore/input_stream.h>

#if ZDB_HAS_NSEC3_SUPPORT!=0
#include "dnsdb/nsec3_icmtl.h"
#include "dnsdb/nsec3_load.h"
#endif

#include <dnscore/rfc.h>

#define DUMP_ICMTL_UPDATE    0

#if DUMP_ICMTL_UPDATE != 0
#include <dnscore/format.h>
#endif

/**
 * @brief Updates a zone from an IXFR input stream
 *
 * Updates a zone from an IXFR input stream
 *
 * The function does not closes the input stream
 *
 * If the IXFR is wrong, the zone will be messed up.
 * Please check that the general structure of the stream is right
 * before calling this.
 *
 * SOA x+n
 *	SOA x+0
 *	...
 *	SOA x+1
 *	...
 *
 *	SOA x+1
 *	...
 *	SOA x+2
 *	...
 * SOA x+n
 *
 *
 *
 * @param[in] db a pointer to the database
 * @param[in] is a pointer to an input stream containing the IXFR
 *
 * @return an error code
 */

ya_result
zdb_zone_update_ixfr(zdb *db, input_stream *is) // mutex checked
{
    u8 rname[MAX_DOMAIN_LENGTH];
    u16 rtype;
    u16 rclass;
    u32 rttl;
    u16 rdata_size;
    u8* rdata;

    zdb_packed_ttlrdata* soa_ttlrdata;
    zdb_packed_ttlrdata* tmp_ttlrdata;
    zdb_packed_ttlrdata* ttlrdata;

    dnsname_vector name;
    dnsname_vector entry_name;

    ya_result err;

    /* Get the first SOA */

    if(FAIL(err = input_stream_read_rr_header(is, rname, sizeof (rname), &rtype, &rclass, &rttl, &rdata_size)))
    {
        return err;
    }

    if(rtype != TYPE_SOA)
    {
        return ZDB_ERROR_GENERAL;
    }

    DEBUG_RESET_dnsname(name);
    dnsname_to_dnsname_vector(rname, &name);

    ZDB_RECORD_ZALLOC_EMPTY(soa_ttlrdata, rttl, rdata_size);
    if(FAIL(err = input_stream_read_fully(is, ZDB_PACKEDRECORD_PTR_RDATAPTR(soa_ttlrdata), rdata_size)))
    {
        ZDB_RECORD_ZFREE(soa_ttlrdata);
        return err;
    }

#ifdef DEBUG
#if DUMP_ICMTL_UPDATE != 0
    if(err != 0)
    {
        format("zdb_zone_update_ixfr H: %{dnsname} %d %{dnsclass} %{dnstype} ", rname, rttl, &rclass, &rtype);
        print_rdata(rtype, ZDB_PACKEDRECORD_PTR_RDATAPTR(soa_ttlrdata), rdata_size);
        println("");
    }
#endif
#endif

    u32 serial_first;

    if(FAIL(err = rr_soa_get_serial(soa_ttlrdata->rdata_start, soa_ttlrdata->rdata_size, &serial_first)))
    {
        ZDB_RECORD_ZFREE(soa_ttlrdata);
        return err;
    }

    zdb_zone_label* zone_label = zdb_zone_label_find(db, &name, rclass);

    if((zone_label == NULL) || (zone_label->zone == NULL))
    {
        /* Not loaded */
        ZDB_RECORD_ZFREE(soa_ttlrdata);
        
        return ZDB_ERROR_GENERAL;
    }

    zdb_zone* zone = zone_label->zone;

    u32 serial_current;

    if(FAIL(err = zdb_zone_getserial(zone, &serial_current)))
    {
        ZDB_RECORD_ZFREE(soa_ttlrdata);
        
        return err;
    }

#if ZDB_HAS_NSEC3_SUPPORT != 0
    nsec3_load_context nsec3_context;
    nsec3_load_init(&nsec3_context, zone);
#endif

    MALLOC_OR_DIE(zdb_packed_ttlrdata*, tmp_ttlrdata, sizeof (zdb_ttlrdata) + RDATA_MAX_LENGTH, ZDB_RDATABUF_TAG);

    /* We do not need tmp_ttlrdata and rdata at the same time, let's spare memory */

    rdata = ZDB_PACKEDRECORD_PTR_RDATAPTR(tmp_ttlrdata);

    /* Read the next SOA (sub or end) */

    if(FAIL(err = input_stream_read_rr_header(is, rname, sizeof (rname), &rtype, &rclass, &rttl, &rdata_size)))
    {
        ZDB_RECORD_ZFREE(soa_ttlrdata);
        free(tmp_ttlrdata);
        return err;
    }

    if(rtype != TYPE_SOA)
    {
        ZDB_RECORD_ZFREE(soa_ttlrdata);
        free(tmp_ttlrdata);
        return ZDB_ERROR_GENERAL;
    }

    for(;;)
    {
        if(FAIL(err = input_stream_read_fully(is, rdata, rdata_size)))
        {
            break;
        }

#ifdef DEBUG
#if DUMP_ICMTL_UPDATE != 0
        if(err != 0)
        {
            format("zdb_zone_update_ixfr F: %{dnsname} %d %{dnsclass} %{dnstype} ", rname, rttl, &rclass, &rtype);
            print_rdata(rtype, rdata, rdata_size);
            println("");
        }
#endif
#endif

        /* The SOA serial is supposed to match our current one or the first one
         *
         * If it's the first one, then the task is done
         *
         * If it's the current one, we are moving forward
         *
         * If it's something else, there is an error
         *
         */

        u32 serial_from;

        if(FAIL(err = rr_soa_get_serial(rdata, rdata_size, &serial_from)))
        {
            break;
        }

        /* Check the serial */

        if(serial_from != serial_current)
        {
            if(serial_from == serial_first)
            {
                /* IXFR done */

                err = SUCCESS;

                break;
            }

            /* Serial sequence is not right */

            err = ZDB_ERROR_GENERAL;

            break;
        }

        tmp_ttlrdata->ttl = rttl;
        tmp_ttlrdata->rdata_size = rdata_size;
        zdb_zone_record_delete(zone, NULL, -1, TYPE_SOA, tmp_ttlrdata);

        for(;;)
        {
            /* Load the next record without the data (sub) */

            if(FAIL(err = input_stream_read_rr_header(is, rname, sizeof (rname), &rtype, &rclass, &rttl, &rdata_size)))
            {
                break;
            }

            /* If we got an SOA, it's the one that starts the "add" sequence */

            if(rtype == TYPE_SOA)
            {
                break;
            }

            /* Load the data */

            if(FAIL(err = input_stream_read_fully(is, rdata, rdata_size)))
            {
                break;
            }

#ifdef DEBUG
#if DUMP_ICMTL_UPDATE != 0
            if(err != 0)
            {
                format("zdb_zone_update_ixfr R: %{dnsname} %d %{dnsclass} %{dnstype} ", rname, rttl, &rclass, &rtype);
                print_rdata(rtype, rdata, rdata_size);
                println("");
            }
#endif
#endif
            tmp_ttlrdata->ttl = rttl;
            tmp_ttlrdata->rdata_size = rdata_size;

            /* The vector is not always required, but it's so much easier to
             * read putting it here
             */

            DEBUG_RESET_dnsname(entry_name);
            dnsname_to_dnsname_vector(rname, &entry_name);

#if ZDB_HAS_NSEC3_SUPPORT != 0

            if(rtype == TYPE_NSEC3PARAM)
            {
                /* Remove it from the zone */

                zdb_zone_record_delete(zone, name.labels, (entry_name.size - name.size) - 1, rtype, tmp_ttlrdata);

                /* Destroy the whole NSEC3 collection associated to the NSEC3PARAM  */

                nsec3_remove_nsec3param_by_record(zone, tmp_ttlrdata);

                continue;
            }

            if(rtype == TYPE_NSEC3)
            {
                /* Remove the NSEC3 label (and its signature)
                 *
                 * The previous record will have its signature changed, no doubt.
                 * But I cannot edit the previous one about this.
                 * Since we are in an IXFR, the previous NSEC3 is supposed to be
                 * removed too, until one of the previous is also added in the
                 * next section (soa add)
                 *
                 * zdb_zone_record_delete is not the right call, it's
                 *
                 * nsec3_...
                 *
                 */

                nsec3_remove_nsec3(zone, tmp_ttlrdata);

                continue;
            }

            if(rtype == TYPE_RRSIG)
            {
                if((GET_U16_AT(*rdata)) == TYPE_NSEC3) /** @note : NATIVETYPE */
                {
                    /* Remove the RRSIG from the NSEC3 label
                     *
                     * zdb_zone_record_delete is not the right call, it's
                     *
                     * nsec3_...
                     *
                     */

                    nsec3_remove_rrsig(zone, tmp_ttlrdata);

                    continue;
                }
            }

#endif

            /* Remove from the zone */

            zdb_zone_record_delete(zone, name.labels, (entry_name.size - name.size) - 1, rtype, tmp_ttlrdata);

        } /* Remove records */

        /* The current header is the "ADD" SOA */

        if(FAIL(err = input_stream_read_fully(is, rdata, rdata_size)))
        {
            break;
        }

#ifdef DEBUG
#if DUMP_ICMTL_UPDATE != 0
        if(err != 0)
        {
            format("zdb_zone_update_ixfr T: %{dnsname} %d %{dnsclass} %{dnstype} ", rname, rttl, &rclass, &rtype);
            print_rdata(rtype, rdata, rdata_size);
            println("");
        }
#endif
#endif

        /* The SOA serial is supposed to be bigger than the previous one */

        u32 serial_to;

        if(FAIL(err = rr_soa_get_serial(rdata, rdata_size, &serial_to)))
        {
            break;
        }

        /*
         * After the "add" sequence is done, serial_current will be serial_to
         */

        do
        {
            /* Load the record without the data (add) */

            if(FAIL(err = input_stream_read_rr_header(is, rname, sizeof (rname), &rtype, &rclass, &rttl, &rdata_size)))
            {
                break;
            }

#if ZDB_HAS_NSEC3_SUPPORT != 0

            if(rtype == TYPE_NSEC3PARAM)
            {
                /* Load the data */

                if(FAIL(err = input_stream_read_fully(is, rdata, rdata_size)))
                {
                    break;
                }

#ifdef DEBUG
#if DUMP_ICMTL_UPDATE != 0
                if(err != 0)
                {
                    format("zdb_zone_update_ixfr A: %{dnsname} %d %{dnsclass} %{dnstype} ", rname, rttl, &rclass, &rtype);
                    print_rdata(rtype, rdata, rdata_size);
                    println("");
                }
#endif
#endif
                /* Add it to the nsec3 context */

                nsec3_load_add_nsec3param(&nsec3_context, rdata, rdata_size);

                /* Add it to the zone */

                DEBUG_RESET_dnsname(entry_name);
                dnsname_to_dnsname_vector(rname, &entry_name);

                ZDB_RECORD_ZALLOC(ttlrdata, rttl, rdata_size, rdata);
                zdb_zone_record_add(zone, entry_name.labels, (entry_name.size - name.size) - 1, rtype, ttlrdata);
            }
            else if(rtype == TYPE_NSEC3)
            {
                /* Load the data */

                if(FAIL(err = input_stream_read_fully(is, rdata, rdata_size)))
                {
                    break;
                }

#ifdef DEBUG
#if DUMP_ICMTL_UPDATE != 0
                if(err != 0)
                {
                    format("zdb_zone_update_ixfr A: %{dnsname} %d %{dnsclass} %{dnstype} ", rname, rttl, &rclass, &rtype);
                    print_rdata(rtype, rdata, rdata_size);
                    println("");
                }
#endif
#endif
                /* Add it to the nsec3 context */

                if(FAIL(err = nsec3_load_add_nsec3(&nsec3_context, rname, rttl, rdata, rdata_size)))
                {
                    break;
                }
            }
            else if(rtype == TYPE_RRSIG)
            {
                /* Load the data */

                if(FAIL(err = input_stream_read_fully(is, rdata, rdata_size)))
                {
                    break;
                }

#if DUMP_ICMTL_UPDATE != 0
                if(err != 0)
                {
                    format("zdb_zone_update_ixfr A: %{dnsname} %d %{dnsclass} %{dnstype} ", rname, rttl, &rclass, &rtype);
                    print_rdata(rtype, rdata, rdata_size);
                    println("");
                }
#endif

                if((GET_U16_AT(*rdata)) == TYPE_NSEC3) /** @note : NATIVETYPE */
                {
                    /* Add it to the nsec3 context */

                    if(FAIL(err = nsec3_load_add_rrsig(&nsec3_context, rname, rttl, rdata, rdata_size)))
                    {
                        break;
                    }
                }
                else
                {
                    /* Add it to the zone */

                    DEBUG_RESET_dnsname(entry_name);
                    dnsname_to_dnsname_vector(rname, &entry_name);

                    ZDB_RECORD_ZALLOC(ttlrdata, rttl, rdata_size, rdata);
                    zdb_zone_record_add(zone, entry_name.labels, (entry_name.size - name.size) - 1, rtype, ttlrdata);
                }
            }
            else
            {
#endif
                /* Add it to the zone */

                ZDB_RECORD_ZALLOC_EMPTY(ttlrdata, rttl, rdata_size);

                if(FAIL(err = input_stream_read_fully(is, ZDB_PACKEDRECORD_PTR_RDATAPTR(ttlrdata), rdata_size)))
                {
                    break;
                }

#ifdef DEBUG
#if DUMP_ICMTL_UPDATE != 0
                if(err != 0)
                {
                    format("zdb_zone_update_ixfr A: %{dnsname} %d %{dnsclass} %{dnstype} ", rname, rttl, &rclass, &rtype);
                    print_rdata(rtype, ttlrdata->rdata_start, rdata_size);
                    println(termout, "");
                }
#endif
#endif
                DEBUG_RESET_dnsname(entry_name);
                dnsname_to_dnsname_vector(rname, &entry_name);

                zdb_zone_record_add(zone, entry_name.labels, (entry_name.size - name.size) - 1, rtype, ttlrdata); /* class is implicit */

#if ZDB_HAS_NSEC3_SUPPORT != 0
            }
#endif
        }
        while(rtype != TYPE_SOA);

        /*
         * The record is either the first of another SOA pair (sub, add)
         * Either the final one.
         */

        /* Update the current serial */

        serial_current = serial_to;

        break;
    }

    free(tmp_ttlrdata);

    if(ISOK(err))
    {
        /*
         * soa_ttlrdata is the new SOA
         */

        zdb_zone_record_add(zone, NULL, -1, TYPE_SOA, soa_ttlrdata);

#if ZDB_HAS_NSEC3_SUPPORT != 0
        /**
         * Check if there is both NSEC & NSEC3.  Reject if yes.
         *       compile NSEC if any
         *	 compile NSEC3 if any
         *
         * @todo: I'm only doing NSEC3 here. Do NSEC as well.
         */
        
        err = nsec3_load_compile(&nsec3_context);
        
        if((nsec3_context.nsec3_rejected > 0)||(nsec3_context.nsec3_discarded > 0))
        {
            err = DNSSEC_ERROR_NSEC3_INVALIDZONESTATE;
        }

        if(ISOK(err))
        {
            nsec3_load_destroy(&nsec3_context);
#endif
            zone_label->zone = zone;

            return err;
#if ZDB_HAS_NSEC3_SUPPORT != 0
        }
#endif
    }

#if ZDB_HAS_NSEC3_SUPPORT != 0
    nsec3_load_destroy(&nsec3_context);
#endif

    /**
     * @note : do NOT use these to unload a zone.
     *         zdb_zone_label_delete(db, &name, zone->zclass);
     *         zdb_zone_destroy(zone);
     */

    zdb_zone_unload(db, &name, zdb_zone_getclass(zone));

    return err;
}

/** @} */

/*----------------------------------------------------------------------------*/

