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
#include <stdio.h>
#include <stdlib.h>

#include <openssl/sha.h>
#include <dnscore/dnssec_errors.h>

#include "dnsdb/zdb_error.h"
#include "dnsdb/nsec3_hash.h"

/******************************************************************************
 *
 * Digest - related methods.
 *
 *****************************************************************************/

static u8 WILDCARD_PREFIX[2] = {1, '*'};

static ya_result
unsupported_hash_function(const u8* name, u32 name_len, const u8* salt, u32 salt_len, u32 iterations, u8* digest, bool wild)
{
    return DNSSEC_ERROR_UNSUPPORTEDDIGESTALGORITHM;
}

static ya_result
sha1_hash_function(const u8* name, u32 name_len, const u8* salt, u32 salt_len, u32 iterations, u8* digest, bool wild)
{
    SHA_CTX sha1;
    SHA1_Init(&sha1);

    if(wild)
    {
        SHA1_Update(&sha1, WILDCARD_PREFIX, 2);
    }

    SHA1_Update(&sha1, name, name_len);
    SHA1_Update(&sha1, salt, salt_len);

    SHA1_Final(digest, &sha1);

    for(; iterations > 0; iterations--)
    {
        SHA1_Init(&sha1);
        SHA1_Update(&sha1, digest, SHA_DIGEST_LENGTH);
        SHA1_Update(&sha1, salt, salt_len);

        SHA1_Final(digest, &sha1);
    }

    return SUCCESS;
}

/*
 * Returns the function associated with the algorithm
 *
 * A typical usage for this would be :
 *
 * get_nsec3_hash_function(NSEC3_ZONE_ALGORITHM(n3))(name, ...... )
 * |_______________________________________________||_____________|
 *  Get the digest function pointer		    Call the returned function
 *
 * I'd do a macro for this but ...
 *
 */

nsec3_hash_function*
nsec3_hash_get_function(u8 algorithm)
{
    switch(algorithm)
    {
        case 1:
            return &sha1_hash_function;

        default:
            return &unsupported_hash_function;
    }
}

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

    return 0;
}

/** @} */

/*----------------------------------------------------------------------------*/

