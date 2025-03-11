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
 * @defgroup DNS extension
 * @ingroup dnscore
 * @brief This API allows the definition of custom types and classes.
 *----------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
 *
 * Just register a dnscore_dns_extension_t before calling dnscore_init() or dnscore_init_ex()
 * and the types & classes will be handled.
 *
 * Used by a internal projects.
 *
 * This API allows to have all the sources of YADIFA opensource.
 *
 *----------------------------------------------------------------------------*/

#include "dnscore/dnscore_config.h"
#include "dnscore/dnscore_extension.h"
#include "dnscore/ptr_vector.h"

static ptr_vector_t dnscore_dns_extension_vector = EMPTY_PTR_VECTOR;

ya_result           dnscore_dns_extension_register(const dnscore_dns_extension_t *dnscore_dns_extension)
{
    for(int i = 0; i < ptr_vector_size(&dnscore_dns_extension_vector); ++i)
    {
        if(ptr_vector_get(&dnscore_dns_extension_vector, i) == dnscore_dns_extension)
        {
            return INVALID_STATE_ERROR; // duplicate entry
        }
    }

    ptr_vector_append(&dnscore_dns_extension_vector, (void *)dnscore_dns_extension);

    return SUCCESS;
}

bool dnscore_dns_extension_dnsclass_format_handler(uint16_t rclass, char const **txtp, int32_t *lenp)
{
    for(int i = 0; i < ptr_vector_size(&dnscore_dns_extension_vector); ++i)
    {
        const dnscore_dns_extension_t *dnscore_dns_extension = (const dnscore_dns_extension_t *)ptr_vector_get(&dnscore_dns_extension_vector, i);
        if(dnscore_dns_extension->dnsclass_format_handler(rclass, txtp, lenp))
        {
            return true;
        }
    }
    return false;
}

bool dnscore_dns_extension_dnstype_format_handler(uint16_t rtype, char const **txtp, int32_t *lenp)
{
    for(int i = 0; i < ptr_vector_size(&dnscore_dns_extension_vector); ++i)
    {
        const dnscore_dns_extension_t *dnscore_dns_extension = (const dnscore_dns_extension_t *)ptr_vector_get(&dnscore_dns_extension_vector, i);
        if(dnscore_dns_extension->dnstype_format_handler(rtype, txtp, lenp))
        {
            return true;
        }
    }
    return false;
}

bool dnscore_dns_extension_osprint_data(output_stream_t *os, uint16_t rtype, const uint8_t *rdata_pointer, uint16_t rdata_size)
{
    for(int i = 0; i < ptr_vector_size(&dnscore_dns_extension_vector); ++i)
    {
        const dnscore_dns_extension_t *dnscore_dns_extension = (const dnscore_dns_extension_t *)ptr_vector_get(&dnscore_dns_extension_vector, i);
        if(dnscore_dns_extension->osprint_data(os, rtype, rdata_pointer, rdata_size))
        {
            return true;
        }
    }
    return false;
}

ya_result dnscore_dns_extension_zone_reader_text_copy_rdata(parser_t *p, uint16_t rtype, uint8_t *rdata, uint32_t rdata_size, const uint8_t *origin, const char **textp, uint32_t *text_lenp)
{
    ya_result ret;
    for(int i = 0; i < ptr_vector_size(&dnscore_dns_extension_vector); ++i)
    {
        const dnscore_dns_extension_t *dnscore_dns_extension = (const dnscore_dns_extension_t *)ptr_vector_get(&dnscore_dns_extension_vector, i);
        if((ret = dnscore_dns_extension->zone_reader_text_copy_rdata(p, rtype, rdata, rdata_size, origin, textp, text_lenp)) != UNSUPPORTED_RECORD)
        {
            return ret;
        }
    }
    return UNSUPPORTED_RECORD;
}

bool dnscore_dns_extension_get_class(int index, uint16_t *rclassp, const char *const *rclass_namep)
{
    for(int i = 0; i < ptr_vector_size(&dnscore_dns_extension_vector); ++i)
    {
        const dnscore_dns_extension_t *dnscore_dns_extension = (const dnscore_dns_extension_t *)ptr_vector_get(&dnscore_dns_extension_vector, i);
        int                            n = dnscore_dns_extension->additional_class_count();
        if(index >= n)
        {
            index -= n;
            continue;
        }

        bool ret = dnscore_dns_extension->additional_class_get(index, rclassp, (const char **)rclass_namep);
        return ret;
    }

    return false;
}

bool dnscore_dns_extension_get_type(int index, uint16_t *rtypep, const char *const *rtype_namep)
{
    for(int i = 0; i < ptr_vector_size(&dnscore_dns_extension_vector); ++i)
    {
        const dnscore_dns_extension_t *dnscore_dns_extension = (const dnscore_dns_extension_t *)ptr_vector_get(&dnscore_dns_extension_vector, i);
        int                            n = dnscore_dns_extension->additional_type_count();
        if(index >= n)
        {
            index -= n;
            continue;
        }

        bool ret = dnscore_dns_extension->additional_type_get(index, rtypep, (const char **)rtype_namep);
        return ret;
    }

    return false;
}

/** @} */
