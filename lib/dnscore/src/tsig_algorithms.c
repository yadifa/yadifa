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

/** @defgroup ### #######
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#include "dnscore/dnscore-config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/dnscore-config.h"

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
tsig_string_set_insert(const char *name, u32 value)
{
    string_node *node;
    u8 fqdn[MAX_DOMAIN_LENGTH];

    cstr_to_dnsname(fqdn, name);

    node = string_set_insert(&hmac_algorithms, (char*)dnsname_dup(fqdn));
    node->value = value;
}

void
tsig_register_algorithms()
{
    tsig_string_set_insert("hmac-md5.sig-alg.reg.int", HMAC_MD5);
    tsig_string_set_insert("hmac-sha1", HMAC_SHA1);
    tsig_string_set_insert("hmac-sha224", HMAC_SHA224);
    tsig_string_set_insert("hmac-sha256", HMAC_SHA256);
    tsig_string_set_insert("hmac-sha384", HMAC_SHA384);
    tsig_string_set_insert("hmac-sha512", HMAC_SHA512);
}

void
tsig_finalize_algorithms()
{
    string_set_iterator iter;
    string_set_iterator_init(&hmac_algorithms, &iter);
    
    while(string_set_iterator_hasnext(&iter))
    {
        string_node* node = string_set_iterator_next_node(&iter);
        free((void*)node->key);
    }
    
    string_set_destroy(&hmac_algorithms);
}

u8
tsig_get_algorithm(const u8 *name)
{
    string_node *node = string_set_find(&hmac_algorithms, (char*)name);

    return (node != NULL) ? node->value : HMAC_UNKNOWN;
}

const u8*
tsig_get_algorithm_name(u8 algorithm)
{
    switch(algorithm)
    {
        case HMAC_MD5:
            return (u8*)"\010hmac-md5\007sig-alg\003reg\003int";
        case HMAC_SHA1:
            return (u8*)"\011hmac-sha1";
        case HMAC_SHA224:
            return (u8*)"\013hmac-sha224";
        case HMAC_SHA256:
            return (u8*)"\013hmac-sha256";
        case HMAC_SHA384:
            return (u8*)"\013hmac-sha384";
        case HMAC_SHA512:
            return (u8*)"\013hmac-sha512";
        default:
            return (u8*)"\004null"; /* UNKNOWN */
    }
}

/** @} */
