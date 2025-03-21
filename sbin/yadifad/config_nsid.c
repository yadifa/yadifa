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
 * @defgroup config Configuration handling
 * @ingroup yadifad
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#include "server_config.h"
#include <stdio.h>
#include <stdlib.h>

#include <dnscore/format.h>
#include <dnscore/config_settings.h>
#include <dnscore/base16.h>
#include <dnscore/nsid.h>
#include <dnscore/logger.h>

#include "server_config.h"

extern logger_handle_t *g_server_logger;
#define MODULE_MSG_HANDLE g_server_logger

#define NSIDNAME_TAG      0x454d414e4449534e

#if DNSCORE_HAS_NSID_SUPPORT

struct byte_array_s
{
    uint8_t *bytes;
    uint32_t size;
};

struct config_nsid_s
{
    struct byte_array_s nsid;
};

typedef struct config_nsid_s config_nsid_t;

static ya_result             config_set_byte_array(struct byte_array_s *dest, const uint8_t *bytes, uint32_t size)
{
    if(dest->bytes != NULL)
    {
        log_warn("config: NSID has already been set, previous value overwritten");

        if(dest->size != size)
        {
            free(dest->bytes);
            dest->bytes = NULL;
            dest->size = 0;
        }
        else // equal sizes
        {
            if(memcmp(dest->bytes, bytes, size) != 0)
            {
                memcpy(dest->bytes, bytes, size);
            }

            return SUCCESS;
        }
    }

    MALLOC_OR_DIE(uint8_t *, dest->bytes, size, NSIDNAME_TAG);
    memcpy(dest->bytes, bytes, size);
    dest->size = size;

    return SUCCESS;
}

ya_result config_set_byte_array_from_ascii(const char *value, struct byte_array_s *dest, anytype settings)
{
    (void)settings;

    ya_result return_code;

    return_code = config_set_byte_array(dest, (const uint8_t *)value, strlen(value));

    return return_code;
}

ya_result config_set_byte_array_from_hex(const char *value, struct byte_array_s *dest, anytype settings)
{
    (void)settings;

    ya_result return_code;

    uint32_t  value_len = strlen(value);

    uint8_t   tmp[EDNS0_NSID_SIZE_MAX];

    if(value_len > EDNS0_NSID_SIZE_MAX * 2)
    {
        return INVALID_ARGUMENT_ERROR;
    }

    return_code = base16_decode(value, value_len, tmp);

    if(ISOK(return_code))
    {
        return_code = config_set_byte_array(dest, tmp, (uint32_t)return_code);
    }

    return return_code;
}

#define CONFIG_TYPE config_nsid_t

CONFIG_BEGIN(config_nsid_desc){"ascii",
                               offsetof(CONFIG_TYPE, nsid),
                               (config_set_field_function *)config_set_byte_array_from_ascii,
                               NULL,
                               {._intptr = 0},
                               sizeof(((CONFIG_TYPE *)0)->nsid),
                               sizeof(((CONFIG_TYPE *)0)->nsid),
                               CONFIG_TABLE_SOURCE_NONE,
                               CONFIG_FIELD_ALLOCATION_DIRECT},
    {"hex",
     offsetof(CONFIG_TYPE, nsid),
     (config_set_field_function *)config_set_byte_array_from_hex,
     NULL,
     {._intptr = 0},
     sizeof(((CONFIG_TYPE *)0)->nsid),
     sizeof(((CONFIG_TYPE *)0)->nsid),
     CONFIG_TABLE_SOURCE_NONE,
     CONFIG_FIELD_ALLOCATION_DIRECT},
    //{"hostname", offsetof(CONFIG_TYPE, fieldname), (config_set_field_function*)config_set_search_or_domain,
    // NULL,{._u8=RO_DOMAIN}, CONFIG_TABLE_SOURCE_NONE},
    CONFIG_END(config_nsid_desc)
#undef CONFIG_TYPE

        static config_nsid_t tmp_config_nsid = {{NULL, 0}};

static ya_result config_nsid_section_postprocess(struct config_section_descriptor_s *csd, config_error_t *cfgerr)
{
    (void)csd;
    (void)cfgerr;
    ya_result ret;

    /* here check that the settings are right */

    if(FAIL(ret = edns0_set_nsid(tmp_config_nsid.nsid.bytes, tmp_config_nsid.nsid.size)))
    {
#if CONFIG_SECTION_DESCRIPTOR_TRACK
        config_section_descriptor_config_error_update(cfgerr, csd, &tmp_config_nsid.nsid.bytes);
#endif
    }

    return ret;
}

ya_result config_register_nsid(int32_t priority)
{
    const char *section_name = "nsid";

    ya_result   return_code = config_register_struct(section_name, config_nsid_desc, &tmp_config_nsid, priority);

    if(ISOK(return_code))
    {
        // hook a new finaliser before the standard one

        config_section_descriptor_t      *section_desc = config_section_get_descriptor(section_name);
        config_section_descriptor_vtbl_s *vtbl = (config_section_descriptor_vtbl_s *)section_desc->vtbl;
        vtbl->postprocess = config_nsid_section_postprocess;
    }

    return return_code;
}

#endif

/** @} */
