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

/** @defgroup nsec3 NSEC3 functions
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
#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/dnssec_errors.h"
#include "dnscore/nsec3-hash.h"
#include "dnscore/digest.h"

/******************************************************************************
 *
 * Digest - related methods.
 *
 *****************************************************************************/

static u8 WILDCARD_PREFIX[2] = {1, '*'};

static ya_result
nsec3_hash_unsupported_function(const u8* name, u32 name_len, const u8* salt, u32 salt_len, u32 iterations, u8* digest, bool wild)
{
    (void)name;
    (void)name_len;
    (void)salt;
    (void)salt_len;
    (void)iterations;
    (void)digest;
    (void)wild;

    return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM;
}

static ya_result
nsec3_hash_sha1_function(const u8* name, u32 name_len, const u8* salt, u32 salt_len, u32 iterations, u8* digest, bool wild)
{
    digest_s sha1;
    digest_sha1_init(&sha1);
    
    if(wild)
    {
        digest_update(&sha1, WILDCARD_PREFIX, 2);
    }

    digest_update(&sha1, name, name_len);
    digest_update(&sha1, salt, salt_len);

    digest_final_copy_bytes(&sha1, digest, SHA_DIGEST_LENGTH); // generates NSEC3 hash : safe use

    for(; iterations > 0; iterations--)
    {
        digest_sha1_init(&sha1);
        digest_update(&sha1, digest, SHA_DIGEST_LENGTH);
        digest_update(&sha1, salt, salt_len);
        digest_final_copy_bytes(&sha1, digest, SHA_DIGEST_LENGTH); // generates NSEC3 hash : safe use
    }

    return SUCCESS;
}

/** 
 *
 * Returns the (NSEC3) hashing function for an algorithm
 * 
 * If the algorithm is not supported, the returned function will
 * always return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM.
 * 
 * A typical usage for this is :
 *
 * get_nsec3_hash_function(NSEC3_ZONE_ALGORITHM(n3))(name, ...... )
 * |_______________________________________________||_____________|
 *  Get the digest function pointer		    Call the returned function
 * 
 * @param algorithm the algorithm id
 * @return the hashing function
 * 
 */

nsec3_hash_function*
nsec3_hash_get_function(u8 algorithm)
{
    switch(algorithm)
    {
        case 1:
            return &nsec3_hash_sha1_function;

        default:
            return &nsec3_hash_unsupported_function;
    }
}


/**
 * Returns the size in bytes of the hash computed by hashing function algorithm
 * 
 * @param algorithm the algorithm id
 * @return size in bytes of the computed hash or 0 if the function is not supported
 */

u8
nsec3_hash_len(u8 algorithm)
{
    switch(algorithm)
    {
        case 1:
            return SHA_DIGEST_LENGTH;
        default:
            return 0;
    }
}

/** @} */
