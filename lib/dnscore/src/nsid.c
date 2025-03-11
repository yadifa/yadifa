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
 * @defgroup
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include <stdlib.h>
// #include <arpa/inet.h>
// #include <ctype.h>

// #include "dnscore/dnscore_config.h"

#define DNSCORE_NSID_C

#include "dnscore/nsid.h"
#include "dnscore/rfc.h"

static uint8_t edns0_nsid_option_wire_default[4] = {(uint8_t)OPT_NSID, (uint8_t)(OPT_NSID >> 8), 0, 0};
static uint8_t edns0_rdatasize_nsid_option_wire_default[2] = {0, 0};         // rdatasize = 0, empty everything else
static uint8_t edns0_rdatasize_nsid_cookie_option_wire_default[2] = {0, 20}; // rdatasize = 20 (the size of a cookie)

uint32_t       edns0_record_size = EDNS0_RECORD_SIZE;
uint8_t       *edns0_nsid_option_wire = edns0_nsid_option_wire_default;
uint8_t       *edns0_rdatasize_nsid_option_wire = edns0_rdatasize_nsid_option_wire_default;
uint8_t       *edns0_rdatasize_nsid_cookie_option_wire = edns0_rdatasize_nsid_cookie_option_wire_default;
uint32_t       edns0_nsid_option_wire_size = sizeof(edns0_nsid_option_wire_default);
uint32_t       edns0_rdatasize_nsid_option_wire_size = 2;

/**
 * Sets the NSID fields.
 * If called with NULL, resets the value to default.
 *
 * @param bytes the NSID or NULL
 * @param size the size of the NSID, ignored if bytes is NULL
 * @return an error code
 */

ya_result edns0_set_nsid(const uint8_t *bytes, uint16_t size)
{
    if(bytes != NULL)
    {
        if(size > EDNS0_NSID_SIZE_MAX)
        {
            return BUFFER_WOULD_OVERFLOW;
        }

        size_t   tmp_size = 2 + 2 + 2 + size;
        uint8_t *tmp = malloc(tmp_size * 2);

        if(tmp == NULL)
        {
            return ERROR;
        }

        tmp[0] = (size + 4) >> 8;          // rdatasize, Big Endian
        tmp[1] = (size + 4) & 255;         // VS false positive (nonsense)
        tmp[2] = (uint8_t)OPT_NSID;        // option 0003 (NSID)
        tmp[3] = (uint8_t)(OPT_NSID >> 8); // size of the NSID
        tmp[4] = size >> 8;
        tmp[5] = size & 255;
        memcpy(&tmp[6], bytes, size); // bytes of the NSID

        memcpy(&tmp[tmp_size], tmp, tmp_size);

        if(edns0_rdatasize_nsid_option_wire != edns0_rdatasize_nsid_option_wire_default)
        {
            free(edns0_rdatasize_nsid_option_wire);
        }

        edns0_rdatasize_nsid_option_wire = tmp;
        edns0_nsid_option_wire = tmp + 2;
        edns0_nsid_option_wire_size = tmp_size - 2;
        edns0_rdatasize_nsid_cookie_option_wire = &tmp[tmp_size];
        SET_U16_AT_P(edns0_rdatasize_nsid_cookie_option_wire, htons(ntohs(GET_U16_AT_P(edns0_rdatasize_nsid_cookie_option_wire)) + 20));
        edns0_rdatasize_nsid_option_wire_size = 6 + size;

        edns0_record_size = EDNS0_RECORD_SIZE - 2 + edns0_rdatasize_nsid_option_wire_size;
    }
    else
    {
        if(edns0_rdatasize_nsid_option_wire != edns0_rdatasize_nsid_option_wire_default)
        {
            free(edns0_rdatasize_nsid_option_wire);
            edns0_rdatasize_nsid_option_wire = edns0_rdatasize_nsid_option_wire_default;
            edns0_rdatasize_nsid_cookie_option_wire = edns0_rdatasize_nsid_cookie_option_wire_default;
            edns0_rdatasize_nsid_option_wire_size = 2;
            edns0_record_size = EDNS0_RECORD_SIZE;
        }
    }

    return SUCCESS;
}

/** @} */
