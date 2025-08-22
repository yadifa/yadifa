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
 * @defgroup query_ex Collections used by the query
 * @ingroup dnsdb
 * @brief A fqdn -> zone dict used to handle additionals
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

/**
 * A dictionary made specifically for zdb_query_to_wire to insert FQDNs and their zone
 *
 */

#define FQDN_ZONE_DICT_SIZE_MAX 64

struct dnsname_zone_dict_node_s
{
    const uint8_t *fqdn;
    const zdb_zone_t *zone;
    struct dnsname_zone_dict_node_s *children[2];
};

struct dnsname_zone_dict_s
{
    struct dnsname_zone_dict_node_s nodes[FQDN_ZONE_DICT_SIZE_MAX];
    int count;
};

/**
 * Initialises the dictionary.
 *
 * @param dict the dictionary to initialise
 */

static inline void dnsname_zone_dict_init(struct dnsname_zone_dict_s *dict)
{
    dict->count = 0;
}

/**
 * Insert a fqdn + zone in the dictionary
 *
 * Duplicates are ignored.
 *
 * @param dict the dictionary to insert into
 * @param fqdn the fqdn
 * @param zone the zone
 */

static inline void dnsname_zone_dict_insert(struct dnsname_zone_dict_s *dict, const uint8_t *fqdn, const zdb_zone_t *zone)
{
    if(dict->count > 0)
    {
        if(dict->count < FQDN_ZONE_DICT_SIZE_MAX)
        {
            struct dnsname_zone_dict_node_s *node = &dict->nodes[0];

            for(;;)
            {
                int d = dnsname_compare(fqdn, node->fqdn);
                if(d == 0) // equals -> nothing to do
                {
                    return;
                }

                struct dnsname_zone_dict_node_s **nodep = &node->children[d > 0];

                if(*nodep == NULL) // no children -> add it
                {
                    node = &dict->nodes[dict->count++];
                    *nodep = node;
                    node->fqdn = fqdn;
                    node->zone = zone;
                    node->children[0] = NULL;
                    node->children[1] = NULL;
                    return;
                }

                node = *nodep;
            }
        }
    }
    else
    {
        dict->nodes[0].fqdn = fqdn;
        dict->nodes[0].zone = zone;
        dict->nodes[0].children[0] = NULL;
        dict->nodes[0].children[1] = NULL;
        dict->count = 1;
    }
}


/** @} */