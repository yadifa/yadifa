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
/** @defgroup ### #######
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#include <stdio.h>
#include <stdlib.h>

#include "dnscore-config.h"

#include "dnscore/sys_types.h"

#include "dnscore/dnsname.h"

#include "dnscore/rfc.h"
#include "dnscore/string_set.h"
#include "dnscore/tsig.h"


/*
 *
 */

static string_node *hmac_algorithms = NULL;

static void
string_set_insert(const char *name, u32 value)
{
    string_node *node;
    u8 fqdn[MAX_DOMAIN_LENGTH];

    cstr_to_dnsname(fqdn, name);

    node = string_set_avl_insert(&hmac_algorithms, (char*)dnsname_dup(fqdn));
    node->value = value;
}

void
tsig_register_algorithms()
{
    string_set_insert("hmac-md5.sig-alg.reg.int", HMAC_MD5);
    string_set_insert("hmac-sha1.sig-alg.reg.int", HMAC_SHA1);
    string_set_insert("hmac-sha224.sig-alg.reg.int", HMAC_SHA224);
    string_set_insert("hmac-sha256.sig-alg.reg.int", HMAC_SHA256);
    string_set_insert("hmac-sha384.sig-alg.reg.int", HMAC_SHA384);
    string_set_insert("hmac-sha512.sig-alg.reg.int", HMAC_SHA512);
}

void
tsig_finalize_algorithms()
{
    string_set_avl_iterator iter;
    string_set_avl_iterator_init(&hmac_algorithms, &iter);
    
    while(string_set_avl_iterator_hasnext(&iter))
    {
        string_node* node = string_set_avl_iterator_next_node(&iter);
        free((void*)node->key);
    }
    
    string_set_avl_destroy(&hmac_algorithms);
}

u8
tsig_get_algorithm(const u8 *name)
{
#if 1
    string_node *node = string_set_avl_find(&hmac_algorithms, (char*)name);

    return (node != NULL) ? node->value : HMAC_UNKNOWN;
#else
    /* Here is an example of an hard-coded one: I should complete it and bench ... */
    u32 len = dnsname_len(name);
    if(len >= 24)
    {
        if(memcmp(name, "hmac-", 5) == 0)
        {
            if(memcmp(&name[5], "md5.sig-alg.reg.int", 20) == 0)
            {
                return HMAC_MD5;
            }
            if(memcmp(&name[5], "sha", 3) == 0)
            {
                if(memcmp(&name[8], "1.sig-alg.reg.int", 18) == 0)
                {
                    return HMAC_SHA1;
                }
                if(memcmp(&name[8], "224.sig-alg.reg.int", 20) == 0)
                {
                    return HMAC_SHA224;
                }
                ...
            }
        }
    }

    return HMAC_UNKNOWN;
#endif
}

const u8*
tsig_get_algorithm_name(u8 algorithm)
{
    switch(algorithm)
    {
        case HMAC_MD5:
            return (u8*)"\010hmac-md5\007sig-alg\003reg\003int";
        case HMAC_SHA1:
            return (u8*)"\011hmac-sha1\007sig-alg\003reg\003int";
        case HMAC_SHA224:
            return (u8*)"\013hmac-sha224\007sig-alg\003reg\003int";
        case HMAC_SHA256:
            return (u8*)"\013hmac-sha256\007sig-alg\003reg\003int";
        case HMAC_SHA384:
            return (u8*)"\013hmac-sha384\007sig-alg\003reg\003int";
        case HMAC_SHA512:
            return (u8*)"\013hmac-sha512\007sig-alg\003reg\003int";
        default:
            return (u8*)"\004null"; /* UNKNOWN */
    }
}

const EVP_MD *
tsig_get_EVP_MD(u8 algorithm)
{
    switch(algorithm)
    {
#ifndef OPENSSL_NO_MD5
        case HMAC_MD5:
            return EVP_md5();
#endif
#ifndef OPENSSL_NO_SHA
        case HMAC_SHA1:
            return EVP_sha1();
#endif
#ifndef OPENSSL_NO_SHA256
        case HMAC_SHA224:
            return EVP_sha224();
        case HMAC_SHA256:
            return EVP_sha256();
#endif
#ifndef OPENSSL_NO_SHA512
        case HMAC_SHA384:
            return EVP_sha384();
        case HMAC_SHA512:
            return EVP_sha512();
#endif
        default:
            return EVP_md_null();
    }
}

/** @} */
