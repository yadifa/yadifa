/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

#pragma once

#include <dnscore/output_stream.h>
#include <dnscore/parser.h>

/**
 * Gives the class name and length
 * @param txtp will point to the name
 * @param lenp will be set to the len of the name
 * @return true iff the class was known
 */

typedef bool dnscore_dns_extension_dnsclass_format_handler_t(uint16_t rclass, char const **txtp, int32_t *lenp);

/**
 * Gives the type name and length
 * @param txtp will point to the name
 * @param lenp will be set to the len of the name
 * @return true iff the type was known
 */

typedef bool dnscore_dns_extension_dnstype_format_handler_t(uint16_t rtype, char const **txtp, int32_t *lenp);

/**
 * Prints a text representation of the rdata of the given type on the output stream
 *
 * @param os the output stream
 * @param rtype the type of the rdata
 * @param rdata_pointer the rdata
 * @param rdata_size the size of the rdata
 * @return true iff the type was known
 */

typedef bool dnscore_dns_extension_osprint_data_t(output_stream_t *os, uint16_t rtype, const uint8_t *rdata_pointer, uint16_t rdata_size);

/**
 * Parses a type into an rdata, returns the size of the rdata
 *
 * MUST return UNSUPPORTED_RECORD if the record is unknown by the call
 *
 * @param p the parser
 * @param rtype the type to parse
 * @param rdata the rdata to fill
 * @param rdata_size the maximum size of the rdata
 * @param origin the origin of the zone being parsed
 * @param textp a pointer of pointer to the current parser token
 * @param text_lenp a pointer to the size of the current parser token
 *
 * @return parsed rdata size, an error code, UNSUPPORTED_RECORD if the record is unknown by that call
 */

typedef ya_result dnscore_dns_extension_zone_reader_text_copy_rdata_t(parser_t *p, uint16_t rtype, uint8_t *rdata, uint32_t rdata_size, const uint8_t *origin, const char **textp, uint32_t *text_lenp);

/**
 * @return the number of classes known by the extension
 */

typedef uint16_t dnscore_dns_extension_additional_class_count_t();

/**
 * @return the number of types known by the extension
 */

typedef uint16_t dnscore_dns_extension_additional_type_count_t();

/**
 * Retrieves the class at index in the extension
 *
 * @param index the class index
 * @param rclassp will be set to the class
 * @param rclassnamep will point to the class name
 * @return true iff the class was known
 */

typedef bool dnscore_dns_extension_additional_class_get_t(int index, uint16_t *rclassp, const char **rclassnamep);

/**
 * Retrieves the type at index in the extension
 *
 * @param index the type index
 * @param rclassp will be set to the type
 * @param rclassnamep will point to the type name
 * @return true iff the type was known
 */

typedef bool dnscore_dns_extension_additional_type_get_t(int index, uint16_t *rypep, const char **rtypenamep);

struct dnscore_dns_extension_s
{
    dnscore_dns_extension_dnsclass_format_handler_t     *dnsclass_format_handler;
    dnscore_dns_extension_dnstype_format_handler_t      *dnstype_format_handler;
    dnscore_dns_extension_osprint_data_t                *osprint_data;
    dnscore_dns_extension_zone_reader_text_copy_rdata_t *zone_reader_text_copy_rdata;
    dnscore_dns_extension_additional_class_count_t      *additional_class_count;
    dnscore_dns_extension_additional_type_count_t       *additional_type_count;
    dnscore_dns_extension_additional_class_get_t        *additional_class_get;
    dnscore_dns_extension_additional_type_get_t         *additional_type_get;
};

typedef struct dnscore_dns_extension_s dnscore_dns_extension_t;

/**
 * Extensions MUST be registered before calling dnscore_init()
 */

ya_result dnscore_dns_extension_register(const dnscore_dns_extension_t *dnscore_dns_extension);
// not necessary at the moment:
// ya_result dnscore_dns_extension_unregister(dnscore_dns_extension_t *dnscore_dns_extension);

bool      dnscore_dns_extension_dnsclass_format_handler(uint16_t rclass, char const **txtp, int32_t *lenp);
bool      dnscore_dns_extension_dnstype_format_handler(uint16_t rtype, char const **txtp, int32_t *lenp);
bool      dnscore_dns_extension_osprint_data(output_stream_t *os, uint16_t rtype, const uint8_t *rdata_pointer, uint16_t rdata_size);
ya_result dnscore_dns_extension_zone_reader_text_copy_rdata(parser_t *p, uint16_t rtype, uint8_t *rdata, uint32_t rdata_size, const uint8_t *origin, const char **textp, uint32_t *text_lenp);
bool      dnscore_dns_extension_get_class(int index, uint16_t *rclassp, const char *const *rclass_namep);
bool      dnscore_dns_extension_get_type(int index, uint16_t *rtypep, const char *const *rtype_namep);

/** @} */
