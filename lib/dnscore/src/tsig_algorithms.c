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
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include <stdio.h>
#include <stdlib.h>

#include "dnscore/dnscore_config.h"

#include "dnscore/sys_types.h"

#include "dnscore/dnsname.h"

#include "dnscore/rfc.h"
#include "dnscore/string_set.h"
#include "dnscore/tsig.h"

/*
 *
 */

static string_treemap_node_t *hmac_algorithms = NULL;

static void                   tsig_string_set_insert(const char *name, uint32_t value)
{
    string_treemap_node_t *node;
    uint8_t                fqdn[DOMAIN_LENGTH_MAX];

    dnsname_init_with_cstr(fqdn, name);

    node = string_treemap_insert(&hmac_algorithms, (char *)dnsname_dup(fqdn));
    node->value = value;
}

void tsig_register_algorithms()
{
    tsig_string_set_insert("hmac-md5.sig-alg.reg.int", HMAC_MD5);
    tsig_string_set_insert("hmac-sha1", HMAC_SHA1);
    tsig_string_set_insert("hmac-sha224", HMAC_SHA224);
    tsig_string_set_insert("hmac-sha256", HMAC_SHA256);
    tsig_string_set_insert("hmac-sha384", HMAC_SHA384);
    tsig_string_set_insert("hmac-sha512", HMAC_SHA512);
}

void tsig_finalize_algorithms()
{
    string_treemap_iterator_t iter;
    string_treemap_iterator_init(&hmac_algorithms, &iter);

    while(string_treemap_iterator_hasnext(&iter))
    {
        string_treemap_node_t *node = string_treemap_iterator_next_node(&iter);
        free((void *)node->key);
    }

    string_treemap_finalise(&hmac_algorithms);
}

uint8_t tsig_get_algorithm(const uint8_t *name)
{
    string_treemap_node_t *node = string_treemap_find(&hmac_algorithms, (char *)name);

    return (node != NULL) ? node->value : HMAC_UNKNOWN;
}

const uint8_t *tsig_get_algorithm_name(uint8_t algorithm)
{
    switch(algorithm)
    {
        case HMAC_MD5:
            return (uint8_t *)"\010hmac-md5\007sig-alg\003reg\003int";
        case HMAC_SHA1:
            return (uint8_t *)"\011hmac-sha1";
        case HMAC_SHA224:
            return (uint8_t *)"\013hmac-sha224";
        case HMAC_SHA256:
            return (uint8_t *)"\013hmac-sha256";
        case HMAC_SHA384:
            return (uint8_t *)"\013hmac-sha384";
        case HMAC_SHA512:
            return (uint8_t *)"\013hmac-sha512";
        default:
            return (uint8_t *)"\004null"; /* UNKNOWN */
    }
}

/** @} */
