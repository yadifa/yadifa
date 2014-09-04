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
/** @defgroup rrsig RRSIG functions
 *  @ingroup dnsdbdnssec
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
#include <dnscore/format.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/rrsig.h"
#include "dnsdb/rr_canonize.h"

#define ZDB_GUARANTEED_LOWCASE_RDATA 1	/* The zone loader guarantees that dnames in the rdata are stored lo-case */

#define RR_CANONIZE_TWONAMES_TAG    0x4e324e4f4e4143	/* CANON2N  */
#define RR_CANONIZE_ONENAME_TAG	    0x4e314e4f4e4143    /* CANON1N  */
#define RR_CANONIZE_MX_TAG          0x584d4e4f4e4143	/* CANONMX  */
#define RR_CANONIZE_SOA_TAG         0x414f534e4f4e4143	/* CANONSOA */
#define RR_CANONIZE_NSEC1_TAG	    0x31534e4e4f4e4143  /* CANONNS1 */
#define RR_CANONIZE_NOP_TAG         0x504f4e4e4f4e4143	/* CANONNOP */

/*
 *
 */

static int
rr_canonize_sort_rdata_compare(const void* a, const void* b)
{
    zdb_canonized_packed_ttlrdata* rr_a = *(zdb_canonized_packed_ttlrdata**)a;
    zdb_canonized_packed_ttlrdata* rr_b = *(zdb_canonized_packed_ttlrdata**)b;

    u16 rr_a_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(rr_a);
    u16 rr_b_size = ZDB_PACKEDRECORD_PTR_RDATASIZE(rr_b);

    int ret;

    u8* ptr_a = &rr_a->rdata_start[0];
    u8* ptr_b = &rr_b->rdata_start[0];

    int diff_len = rr_a_size - rr_b_size;

    if(diff_len != 0)
    {
        u16 len = MIN(rr_a_size, rr_b_size);

        ret = memcmp(ptr_a, ptr_b, len);

        if(ret == 0)
        {
            ret = diff_len;
        }
    }
    else
    {
        ret = memcmp(ptr_a, ptr_b, rr_a_size);
    }


    return ret;

}

#if ZDB_GUARANTEED_LOWCASE_RDATA == 0

static void
rr_canonize_twonames(zdb_packed_ttlrdata* rr, ptr_vector* v)
{
    while(rr != NULL)
    {
        zdb_canonized_packed_ttlrdata* c_rr;

        u32 c_rr_size = sizeof (zdb_canonized_packed_ttlrdata) - 1 + ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);
        MALLOC_OR_DIE(zdb_canonized_packed_ttlrdata*, c_rr, c_rr_size, RR_CANONIZE_TWONAMES_TAG);

        ZDB_PACKEDRECORD_PTR_RDATASIZE(c_rr) = ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);
        c_rr->rdata_canonized_size = htons(ZDB_PACKEDRECORD_PTR_RDATASIZE(rr));

        u8* src = &rr->rdata_start[0];
        u8* dst = &c_rr->rdata_start[0];

        u32 n;

        n = dnsname_canonize(src, dst);
        src += n;
        dst += n;

        dnsname_canonize(src, dst);

        ptr_vector_append(v, c_rr);

        rr = rr->next;
    }
}

static void
rr_canonize_onename(zdb_packed_ttlrdata* rr, ptr_vector* v)
{
    while(rr != NULL)
    {
        zdb_canonized_packed_ttlrdata* c_rr;

        u32 c_rr_size = sizeof (zdb_canonized_packed_ttlrdata) - 1 + ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);

        MALLOC_OR_DIE(zdb_canonized_packed_ttlrdata*, c_rr, c_rr_size, RR_CANONIZE_ONENAME_TAG);

        ZDB_PACKEDRECORD_PTR_RDATASIZE(c_rr) = ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);
        c_rr->rdata_canonized_size = htons(ZDB_PACKEDRECORD_PTR_RDATASIZE(rr));

        u8* src = &rr->rdata_start[0];
        u8* dst = &c_rr->rdata_start[0];

        dnsname_canonize(src, dst);

        ptr_vector_append(v, c_rr);

        rr = rr->next;
    }
}

static void
rr_canonize_mx(zdb_packed_ttlrdata* rr, ptr_vector* v)
{
    while(rr != NULL)
    {
        zdb_canonized_packed_ttlrdata* c_rr;

        u32 c_rr_size = sizeof (zdb_canonized_packed_ttlrdata) - 1 + ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);

        MALLOC_OR_DIE(zdb_canonized_packed_ttlrdata*, c_rr, c_rr_size, RR_CANONIZE_MX_TAG);

        ZDB_PACKEDRECORD_PTR_RDATASIZE(c_rr) = ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);
        c_rr->rdata_canonized_size = htons(ZDB_PACKEDRECORD_PTR_RDATASIZE(rr));

        c_rr->rdata_start[0] = rr->rdata_start[0];
        c_rr->rdata_start[1] = rr->rdata_start[1];

        u8* src = &rr->rdata_start[2];
        u8* dst = &c_rr->rdata_start[2];

        dnsname_canonize(src, dst);

        ptr_vector_append(v, c_rr);

        rr = rr->next;
    }
}

static void
rr_canonize_soa(zdb_packed_ttlrdata* rr, ptr_vector* v)
{
    yassert(rr != NULL && rr->next == NULL);

    zdb_canonized_packed_ttlrdata* c_rr;

    u32 c_rr_size = sizeof (zdb_canonized_packed_ttlrdata) - 1 + ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);

    MALLOC_OR_DIE(zdb_canonized_packed_ttlrdata*, c_rr, c_rr_size, RR_CANONIZE_SOA_TAG);

    ZDB_PACKEDRECORD_PTR_RDATASIZE(c_rr) = ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);
    c_rr->rdata_canonized_size = htons(ZDB_PACKEDRECORD_PTR_RDATASIZE(rr));

    u8* src = &rr->rdata_start[0];
    u8* dst = &c_rr->rdata_start[0];

    u32 n;

    n = dnsname_canonize(src, dst);
    src += n;
    dst += n;
    n = dnsname_canonize(src, dst);
    src += n;
    dst += n;

    MEMCOPY(dst, src, 4 + 4 + 4 + 4 + 4);

    ptr_vector_append(v, c_rr);
}

static void
rr_canonize_nsec(zdb_packed_ttlrdata* rr, ptr_vector* v)
{
    while(rr != NULL)
    {
        zdb_canonized_packed_ttlrdata* c_rr;

        u32 c_rr_size = sizeof (zdb_canonized_packed_ttlrdata) - 1 + ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);
        MALLOC_OR_DIE(zdb_canonized_packed_ttlrdata*, c_rr, c_rr_size, RR_CANONIZE_NSEC1_TAG);

        ZDB_PACKEDRECORD_PTR_RDATASIZE(c_rr) = ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);
        c_rr->rdata_canonized_size = htons(ZDB_PACKEDRECORD_PTR_RDATASIZE(rr));

        u8* src = &rr->rdata_start[0];
        u8* dst = &c_rr->rdata_start[0];

        dnsname_canonize(src, dst);

        ptr_vector_append(v, c_rr);

        rr = rr->next;
    }
}

#endif /* ZDB_GUARANTEED_LOWCASE_RDATA */

static void
rr_canonize_nsec3param(zdb_packed_ttlrdata* rr, ptr_vector* v)
{
    while(rr != NULL)
    {
        zdb_canonized_packed_ttlrdata* c_rr;

        u32 c_rr_size = sizeof (zdb_canonized_packed_ttlrdata) - 1 + ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);
        MALLOC_OR_DIE(zdb_canonized_packed_ttlrdata*, c_rr, c_rr_size, RR_CANONIZE_NOP_TAG);

        ZDB_PACKEDRECORD_PTR_RDATASIZE(c_rr) = ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);
        c_rr->rdata_canonized_size = htons(ZDB_PACKEDRECORD_PTR_RDATASIZE(rr));
        MEMCOPY(&c_rr->rdata_start[0], ZDB_PACKEDRECORD_PTR_RDATAPTR(rr), ZDB_PACKEDRECORD_PTR_RDATASIZE(rr));
        c_rr->rdata_start[1] = 0; /* The signed NSEC3PARAM has its flags to 0 */
        ptr_vector_append(v, c_rr);

        rr = rr->next;
    }
}

static void
rr_canonize_nop(zdb_packed_ttlrdata* rr, ptr_vector* v)
{
    while(rr != NULL)
    {
        zdb_canonized_packed_ttlrdata* c_rr;

        u32 c_rr_size = sizeof (zdb_canonized_packed_ttlrdata) - 1 + ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);
        MALLOC_OR_DIE(zdb_canonized_packed_ttlrdata*, c_rr, c_rr_size, RR_CANONIZE_NOP_TAG);

        ZDB_PACKEDRECORD_PTR_RDATASIZE(c_rr) = ZDB_PACKEDRECORD_PTR_RDATASIZE(rr);
        c_rr->rdata_canonized_size = htons(ZDB_PACKEDRECORD_PTR_RDATASIZE(rr));
        /** @todo CHECK: If we don't lo-case anymore maybe I could grab some
         *        more cycles here.  Not for the A-records on a 64bits arch,
         *        but for any case where the rdata is (much) bigger than 8 bytes
         */
        MEMCOPY(&c_rr->rdata_start[0], ZDB_PACKEDRECORD_PTR_RDATAPTR(rr), ZDB_PACKEDRECORD_PTR_RDATASIZE(rr));
        ptr_vector_append(v, c_rr);

        rr = rr->next;
    }
}



void
rr_canonize_rrset(u16 type, zdb_packed_ttlrdata* rr_sll, ptr_vector* rrsp)
{
    switch(type)
    {
#if ZDB_GUARANTEED_LOWCASE_RDATA == 0
        case TYPE_NS:
        case TYPE_CNAME:
        case TYPE_DNAME:
        case TYPE_PTR:
        case TYPE_MB:
        case TYPE_MD:
        case TYPE_MF:
        case TYPE_MG:
        case TYPE_MR:
            /* ONE NAME record */

            rr_canonize_onename(rr_sll, rrsp);
            break;
        case TYPE_MX:

            rr_canonize_mx(rr_sll, rrsp);
            break;
        case TYPE_SOA:
            /* NOTE: NO NEED TO SORT (There is only one) */
            rr_canonize_soa(rr_sll, rrsp);
            break;
        case TYPE_SIG:
            rr_canonize_notsupported(rr_sll, rrsp, TYPE_SIG);
            break;
        case TYPE_RRSIG:
            /*
             * A signature must not be signed ...
             */
            rr_canonize_notsupported(rr_sll, rrsp, TYPE_RRSIG);
            break;
        case TYPE_A6:
            rr_canonize_notsupported(rr_sll, rrsp, TYPE_A6);
            break;
        case TYPE_NSEC:
            rr_canonize_nsec(rr_sll, rrsp);
            break;
        case TYPE_ASFDB:
            rr_canonize_notsupported(rr_sll, rrsp, TYPE_ASFDB);
            break;
        case TYPE_SRV:
            rr_canonize_notsupported(rr_sll, rrsp, TYPE_SRV);
            break;
        case TYPE_A:
        case TYPE_HINFO:
        case TYPE_MINFO:
        case TYPE_AAAA:
        case TYPE_DS:
        case TYPE_TXT:
        case TYPE_WKS:
        case TYPE_DNSKEY:
        case TYPE_NSEC3:
        case TYPE_LOC:
            /* NO CANONIZATION record : copy */
            rr_canonize_nop(rr_sll, rrsp);
            break;
        default:
            rr_canonize_notsupported(rr_sll, rrsp, type);
            break;
#else
        default:
            rr_canonize_nop(rr_sll, rrsp);
            break;
#endif
        case TYPE_NSEC3PARAM:
            rr_canonize_nsec3param(rr_sll, rrsp);
            break;

    }

    /* */

    ptr_vector_qsort(rrsp, rr_canonize_sort_rdata_compare);
}

/*
 * MUST wrap the free function because free could be a macro.
 */

static void
rr_free_canonized_free(void* ptr)
{
    free(ptr);
}

void
rr_canonize_free(ptr_vector* rrsp)
{
    ptr_vector_free_empties(rrsp, rr_free_canonized_free);
    /* DO NOT DO NOT DO NOT : ptr_vector_destroy(rrsp); */
}

/** @} */

/*----------------------------------------------------------------------------*/

