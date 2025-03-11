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
 * @defgroup dnscore
 * @ingroup dnscore
 * @brief Functions used to manipulate dns formatted names and labels
 *
 * DNS names are stored in many ways:
 * _ C string : ASCII with a '\0' sentinel
 * _ DNS wire : label_length_byte + label_bytes) ending with a label_length_byte with a value of 0
 * _ simple array of pointers to labels
 * _ simple stack of pointers to labels (so the same as above, but with the order reversed)
 * _ sized array of pointers to labels
 * _ sized stack of pointers to labels (so the same as above, but with the order reversed)
 *
 * @{
 *----------------------------------------------------------------------------*/

#define DNSNAME_C_ 1

#include "dnscore/dnscore_config.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "dnscore/dnscore_config.h"
#include "dnscore/sys_types.h"

const uint8_t __LOCASE_TABLE__[256] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                                       0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,

                                       0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                                       0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,

                                       0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
                                       0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,

                                       0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
                                       0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

#include "dnscore/dnsname.h"
#include "dnscore/rfc.h"
#include "dnscore/zalloc.h"

#define DNSNAMED_TAG 0x44454d414e534e44

/*****************************************************************************
 *
 * BUFFER
 *
 *****************************************************************************/

/** @brief Converts a C string to a dns name.
 *
 *  Converts a C string to a dns name.
 *
 *  @param[in] str a pointer to the source c-string
 *  @param[in] name a pointer to a buffer that will get the full dns name
 *
 *  @return Returns the length of the string
 */

/*
 * This table contains true for both expected name terminators
 */
#if NOTUSED
static bool cstr_to_dnsname_terminators[256] = {
    true,  false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,                                                                                                                 /* '\0' */
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true,  false, /* '.' */
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
};
#endif

/**
 *  0: out of space
 *  1: in space
 * -1: terminator
 *
 * =>
 *
 * test the map
 * signed -> terminator
 *   zero -> out of space
 *
 */

#if !DNSCORE_HAS_FULL_ASCII7

/*
 * The list of characters that are valid in a zone: * - _ 0..9 A..Z a..z
 *
 */

static int8_t cstr_to_dnsname_map[256] = {
    // 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 00 (HEX) */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 10 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, -1, 0, /* 20 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,  0, /* 30 */
    0,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 40 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0,  1, /* 50 */
    0,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 60 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0,  0, /* 70 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 80 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 90 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * The list of characters that are valid in a zone: - _ 0..9 A..Z a..z
 */

static int8_t cstr_to_dnsname_map_nostar[256] = {
    // 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 00 (HEX) */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 10 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, -1, 0, /* 20 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,  0, /* 30 */
    0,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 40 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0,  1, /* 50 */
    0,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 60 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0,  0, /* 70 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 80 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 90 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static int8_t cstr_to_rname_map[256] = {
    // 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 00 (HEX) */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 10 */
    0,  1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, /* 20 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, /* 30 */
    0,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 40 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, /* 50 */
    0,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 60 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, /* 70 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 80 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 90 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

#else

static int8_t cstr_to_dnsname_map[256] = {
    // 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 00 (HEX) */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 10 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, /* 20 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 30 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 40 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 50 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 60 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 70 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 80 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 90 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static int8_t cstr_to_dnsname_map_nostar[256] = {
    // 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 00 (HEX) */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 10 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, -1, 1, /* 20 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 30 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 40 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 50 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 60 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  0, /* 70 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 80 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 90 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static int8_t cstr_to_rname_map[256] = {
    // 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 00 (HEX) */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 10 */
    0,  1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, /* 20 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 30 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 40 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 50 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 60 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, /* 70 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 80 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 90 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

#endif // ASCII7 charset instead of strict DNS

/**
 * This is a set for rname in the SOA TYPE
 *
 *  0: out of space
 *  1: in space
 * -1: terminator
 *
 * =>
 *
 * test the map
 * signed -> terminator
 *   zero -> out of space
 *
 */

#if !DNSCORE_HAS_FULL_ASCII7

static const int8_t cstr_to_dnsrname_map[256] = {
    // 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 00 (HEX) */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 10 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, -1, 0, /* 20 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,  0, /* 30 */
    0,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 40 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 2, 0, 0,  1, /* 50 */
    0,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 60 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0,  0, /* 70 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 80 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 90 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

#else

static const int8_t cstr_to_dnsrname_map[256] = {
    // 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 00 (HEX) */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 10 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, -1, 1, /* 20 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 30 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 40 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1,  1, /* 50 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 60 */
    1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, /* 70 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 80 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, /* 90 */
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

#endif

/**
 * char DNS charset test
 *
 * @param c
 * @return true iff c in in the DNS charset
 *
 */

bool    dnsname_is_charspace(uint8_t c) { return cstr_to_dnsname_map[c] == 1; }

int32_t dnslabel_compare(const uint8_t *a, const uint8_t *b)
{
    int len = MIN(*a, *b);
    int d = memcmp(a + 1, b + 1, len);
    if(d == 0)
    {
        d = *a;
        d -= *b;
    }
    return d;
}

/**
 * label DNS charset test
 *
 * @param label
 * @return true iff each char in the label in in the DNS charset
 *
 */

bool dnslabel_verify_charspace(const uint8_t *label)
{
    uint8_t n = *label;

    if(n > LABEL_LENGTH_MAX)
    {
        return false;
    }

    const uint8_t *const limit = &label[n];

    while(++label <= limit)
    {
        uint8_t c = *label;

        if(cstr_to_dnsname_map[c] != 1)
        {
            return false;
        }
    }

    return true;
}

/**
 * dns name DNS charset test
 *
 * @param name_wire
 * @return true if each char in the name is in the DNS charset
 *
 */

bool dnsname_verify_charspace(const uint8_t *name_wire)
{
    uint8_t n;

    for(;;)
    {
        n = *name_wire;

        if(n == 0)
        {
            return true;
        }

        if(n > LABEL_LENGTH_MAX)
        {
            return false;
        }

        const uint8_t *const limit = &name_wire[n];

        while(++name_wire <= limit)
        {
            uint8_t c = *name_wire;

            if(cstr_to_dnsname_map[c] != 1)
            {
                return false;
            }
        }
    }
}

/**
 * char DNS rchar charset test
 *
 * @param c
 * @return true iff c in in the DNS rchar charset
 *
 */

bool dnsname_is_rname_charspace(uint8_t c) { return cstr_to_rname_map[c] == 1; }

/**
 * dns name RNAME charset test
 *
 * @param name_wire
 * @return true if each char in the name is in the DNS charset
 *
 */

bool dnsname_verify_rname_charspace(const uint8_t *name_wire)
{
    uint8_t n;

    for(;;)
    {
        n = *name_wire;

        if(n == 0)
        {
            return true;
        }

        if(n > LABEL_LENGTH_MAX)
        {
            return false;
        }

        const uint8_t *const limit = &name_wire[n];

        while(++name_wire <= limit)
        {
            uint8_t c = *name_wire;

            if(cstr_to_rname_map[c] != 1)
            {
                return false;
            }
        }
    }
}

/**
 * label DNS charset test and set to lower case
 *
 * @param label
 * @return true iff each char in the label in in the DNS charset
 *
 */

bool dnslabel_locase_verify_charspace(uint8_t *label)
{
    uint8_t n = *label;

    if(n > LABEL_LENGTH_MAX)
    {
        return false;
    }

    uint8_t *const limit = &label[n];

    while(++label <= limit)
    {
        uint8_t c = *label;

        if(cstr_to_dnsname_map[c] != 1)
        {
            return false;
        }

        *label = LOCASE(c);
    }

    return true;
}

/**
 * dns name DNS charset test and set to lower case
 *
 * @param name_wire
 * @return true iff each char in the name is in the DNS charset
 *
 */

bool dnsname_locase_verify_charspace(uint8_t *name_wire)
{
    uint8_t n;

    for(;;)
    {
        n = *name_wire;

        if(n == 0)
        {
            return true;
        }

        if(n > LABEL_LENGTH_MAX)
        {
            return false;
        }

        uint8_t *const limit = &name_wire[n];

        while(++name_wire <= limit)
        {
            uint8_t c = *name_wire;

            if(cstr_to_dnsname_map[c] != 1)
            {
                return false;
            }

            *name_wire = LOCASE(c);
        }
    }
}

/**
 *  Converts a C string to a DNS name.
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source c-string
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_with_cstr(uint8_t *name_parm, const char *str) { return dnsname_init_with_charp(name_parm, str, strlen(str)); }

/**
 *  Converts a C string to a lower-case DNS name.
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source c-string
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_with_cstr_locase(uint8_t *name_parm, const char *str) { return dnsname_init_with_charp_locase(name_parm, str, strlen(str)); }

/**
 *  Converts a text buffer to a DNS name.
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source buffer
 *  @param str_len the length of the source buffer
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_with_charp(uint8_t *name_parm, const char *str, uint32_t str_len)
{
    uint8_t *const    limit = &name_parm[DOMAIN_LENGTH_MAX];
    const char *const str_limit = &str[str_len];
    uint8_t          *s = name_parm;
    uint8_t          *p = &name_parm[1];

    uint8_t           c;

    if(str_len == 0)
    {
        return DOMAINNAME_INVALID;
    }

    if(str_len >= DOMAIN_LENGTH_MAX)
    {
        return DOMAIN_TOO_LONG;
    }

    for(; str < str_limit;)
    {
        c = *str++;

        if(c != '.')
        {
            *p = c;
            if(++p >= limit)
            {
                // no place for a zero
                return DOMAIN_TOO_LONG;
            }
        }
        else // '.'
        {
            uint8_t l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                if(str == str_limit)
                {
                    if(s - name_parm == 1)
                    {
                        return 1;
                    }
                }
                return DOMAINNAME_INVALID;
            }

            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            p++;
        }
    }

    {
        uint8_t l = p - s - 1;
        *s = l;
        s = p;

        if(l > 0)
        {
            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            // p in [0; 254] so no need to: if(p >= limit) { return DOMAIN_TOO_LONG; }

            *s++ = '\0';
        }
    }

    return s - name_parm;
}

/**
 *  Converts a text buffer to a lower-case DNS name.
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source buffer
 *  @param str_len the length of the source buffer
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_with_charp_locase(uint8_t *name_parm, const char *str, uint32_t str_len)
{
    uint8_t *const    limit = &name_parm[DOMAIN_LENGTH_MAX];
    const char *const str_limit = &str[str_len];
    uint8_t          *s = name_parm;
    uint8_t          *p = &name_parm[1];

    uint8_t           c;

    if(str_len == 0)
    {
        return DOMAINNAME_INVALID;
    }

    if(str_len >= DOMAIN_LENGTH_MAX)
    {
        return DOMAIN_TOO_LONG;
    }

    for(; str < str_limit;)
    {
        c = *str++;

        if(c != '.')
        {
            *p = LOCASE(c);
            if(++p >= limit)
            {
                // no place for a zero
                return DOMAIN_TOO_LONG;
            }
        }
        else // '.'
        {
            uint8_t l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                if(str == str_limit)
                {
                    if(s - name_parm == 1)
                    {
                        return 1;
                    }
                }
                return DOMAINNAME_INVALID;
            }

            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            p++;
        }
    }

    {
        uint8_t l = p - s - 1;
        *s = l;
        s = p;

        if(l > 0)
        {
            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            // p in [0; 254] so no need to: if(p >= limit) { return DOMAIN_TOO_LONG; }

            *s++ = '\0';
        }
    }

    return s - name_parm;
}

/**
 *  Converts a text buffer to a lower-case dns name and checks for charset validity.
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source buffer
 *  @param str_len the length of the source buffer
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_check_with_charp_locase(uint8_t *name_parm, const char *str, uint32_t str_len)
{
    uint8_t *const    limit = &name_parm[DOMAIN_LENGTH_MAX];
    const char *const str_limit = &str[str_len];
    uint8_t          *s = name_parm;
    uint8_t          *p = &name_parm[1];

    uint8_t           c;

    if(str_len == 0)
    {
        return DOMAINNAME_INVALID;
    }

    if(str_len >= DOMAIN_LENGTH_MAX)
    {
        return DOMAIN_TOO_LONG;
    }

    for(; str < str_limit;)
    {
        c = *str++;

        if(c != '.')
        {
            if(cstr_to_dnsname_map[c] == 0)
            {
                return INVALID_CHARSET;
            }

            *p = LOCASE(c);
            if(++p >= limit)
            {
                // no place for a zero
                return DOMAIN_TOO_LONG;
            }
        }
        else // '.'
        {
            uint8_t l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                if(str == str_limit)
                {
                    if(s - name_parm == 1)
                    {
                        return 1;
                    }
                }
                return DOMAINNAME_INVALID;
            }

            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            p++;
        }
    }

    {
        uint8_t l = p - s - 1;
        *s = l;
        s = p;

        if(l > 0)
        {
            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            // p in [0; 254] so no need to: if(p >= limit) { return DOMAIN_TOO_LONG; }

            *s++ = '\0';
        }
    }

    return s - name_parm;
}

/**
 *  Converts a C string to a dns name and checks for charset validity.
 *  Checks the DNS name charset is being respected.
 *  Allows for '*.fqdn' but rejects '*' in the middle of a name
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source c-string
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_check_star_with_cstr(uint8_t *name_parm, const char *str) { return dnsname_init_check_star_with_charp(name_parm, str, strlen(str)); }

/**
 *  Converts text buffer to a DNS name and checks for charset validity.
 *  Checks the DNS name charset is being respected.
 *  Allows for '*.fqdn' but rejects '*' in the middle of a name
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the text
 *  @param str_len the length of the text
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_check_star_with_charp(uint8_t *name_parm, const char *str, uint32_t str_len)
{
    uint8_t *const    limit = &name_parm[DOMAIN_LENGTH_MAX];
    const char *const str_limit = &str[str_len];
    uint8_t          *s = name_parm;
    uint8_t          *p = &name_parm[1];

    uint8_t           c;

    if(str_len == 0)
    {
        return DOMAINNAME_INVALID;
    }

    if(str_len >= DOMAIN_LENGTH_MAX)
    {
        return DOMAIN_TOO_LONG;
    }

    if(*str == '*')
    {
        str++;
        if(*str == '.') // *.fqdn
        {
            str++;
            *s++ = 1;
            *s++ = '*';
            p = s + 1;
        }
        else if(str_len == 1) // '*'
        {
            *s++ = 1;
            *s++ = '*';
            *s++ = 0;
            return 3;
        }
        else // *xxx
        {
            return DOMAINNAME_INVALID;
        }
    }

    for(; str < str_limit;)
    {
        c = *str++;

        if(c != '.')
        {
            if(cstr_to_dnsname_map_nostar[c] == 0)
            {
                return INVALID_CHARSET;
            }

            *p = c;
            if(++p >= limit)
            {
                // no place for a zero
                return DOMAIN_TOO_LONG;
            }
        }
        else // '.'
        {
            uint8_t l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                if(str == str_limit)
                {
                    if(s - name_parm == 1)
                    {
                        return 1;
                    }
                }
                return DOMAINNAME_INVALID;
            }

            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            p++;
        }
    }

    {
        uint8_t l = p - s - 1;
        *s = l;
        s = p;

        if(l > 0)
        {
            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            // p in [0; 254] so no need to: if(p >= limit) { return DOMAIN_TOO_LONG; }

            *s++ = '\0';
        }
    }

    return s - name_parm;
}

/**
 *  Converts text buffer to a DNS name and checks for charset validity.
 *  Checks the DNS name charset is being respected.
 *  Rejects the '*' character.
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the text
 *  @param str_len the length of the text
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_check_nostar_with_charp(uint8_t *name_parm, const char *str, uint32_t str_len)
{
    uint8_t *const    limit = &name_parm[DOMAIN_LENGTH_MAX];
    const char *const str_limit = &str[str_len];
    uint8_t          *s = name_parm;
    uint8_t          *p = &name_parm[1];

    uint8_t           c;

    if(str_len == 0)
    {
        return DOMAINNAME_INVALID;
    }

    if(str_len >= DOMAIN_LENGTH_MAX)
    {
        return DOMAIN_TOO_LONG;
    }

    for(; str < str_limit;)
    {
        c = *str++;

        if(c != '.')
        {
            if(cstr_to_dnsname_map_nostar[c] == 0)
            {
                return INVALID_CHARSET;
            }

            *p = c;
            if(++p >= limit)
            {
                // no place for a zero
                return DOMAIN_TOO_LONG;
            }
        }
        else // '.'
        {
            uint8_t l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                if(str == str_limit)
                {
                    if(s - name_parm == 1)
                    {
                        return 1;
                    }
                }
                return DOMAINNAME_INVALID;
            }

            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            p++;
        }
    }

    {
        uint8_t l = p - s - 1;
        *s = l;
        s = p;

        if(l > 0)
        {
            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            // p in [0; 254] so no need to: if(p >= limit) { return DOMAIN_TOO_LONG; }

            *s++ = '\0';
        }
    }

    return s - name_parm;
}

/**
 *  Converts text buffer to a DNS name and checks for charset validity.
 *  Checks the DNS name charset is being respected.
 *  Rejects the '*' character.
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the text
 *  @param str_len the length of the text
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_check_nostar_with_charp_locase(uint8_t *name_parm, const char *str, uint32_t str_len)
{
    uint8_t *const    limit = &name_parm[DOMAIN_LENGTH_MAX];
    const char *const str_limit = &str[str_len];
    uint8_t          *s = name_parm;
    uint8_t          *p = &name_parm[1];

    uint8_t           c;

    if(str_len == 0)
    {
        return DOMAINNAME_INVALID;
    }

    if(str_len >= DOMAIN_LENGTH_MAX)
    {
        return DOMAIN_TOO_LONG;
    }

    for(; str < str_limit;)
    {
        c = *str++;

        if(c != '.')
        {
            if(cstr_to_dnsname_map_nostar[c] == 0)
            {
                return INVALID_CHARSET;
            }

            *p = LOCASE(c);
            if(++p >= limit)
            {
                // no place for a zero
                return DOMAIN_TOO_LONG;
            }
        }
        else // '.'
        {
            uint8_t l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                if(str == str_limit)
                {
                    if(s - name_parm == 1)
                    {
                        return 1;
                    }
                }
                return DOMAINNAME_INVALID;
            }

            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            p++;
        }
    }

    {
        uint8_t l = p - s - 1;
        *s = l;
        s = p;

        if(l > 0)
        {
            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            // p in [0; 254] so no need to: if(p >= limit) { return DOMAIN_TOO_LONG; }

            *s++ = '\0';
        }
    }

    return s - name_parm;
}

/**
 *  Converts text buffer to a DNS name and checks for charset validity.
 *  Checks the DNS name charset is being respected.
 *  Appends an FQDN to the name.
 *  Allows for '*.fqdn' but rejects '*' in the middle of a name
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the text
 *  @param str_len the length of the text
 *  @param origin the FQDN to append to the result
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_check_star_with_charp_and_origin(uint8_t *name_parm, const char *str, uint32_t str_len, const uint8_t *origin)
{
    uint8_t *const    limit = &name_parm[DOMAIN_LENGTH_MAX];
    const char *const str_limit = &str[str_len];
    uint8_t          *s = name_parm;
    uint8_t          *p = &name_parm[1];

    uint8_t           c;

    if(str_len == 0)
    {
        return DOMAINNAME_INVALID;
    }

    if(*str == '*')
    {
        str++;
        if(*str == '.') // *.fqdn
        {
            str++;
            *s++ = 1;
            *s++ = '*';
            p = s + 1;
        }
        else if(str_len == 1) // '*'
        {
            *s++ = 1;
            *s++ = '*';

            uint32_t origin_len = dnsname_len(origin);
            if(origin_len + 2 <= DOMAIN_LENGTH_MAX)
            {
                memcpy(s, origin, origin_len);
                return origin_len + 2;
            }
            else
            {
                return DOMAIN_TOO_LONG;
            }
        }
        else // *xxx
        {
            return DOMAINNAME_INVALID;
        }
    }

    for(; str < str_limit;)
    {
        c = *str++;

        if(c != '.')
        {
            if(cstr_to_dnsname_map_nostar[c] == 0)
            {
                return INVALID_CHARSET;
            }

            *p = c;
            if(++p >= limit)
            {
                // no place for a zero
                return DOMAIN_TOO_LONG;
            }
        }
        else // '.' ; note: p in [0; 254]
        {
            uint8_t l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                if(str == str_limit)
                {
                    if(s - name_parm == 1)
                    {
                        return 1;
                    }
                }
                return DOMAINNAME_INVALID;
            }

            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            p++; // note: p in [1; 255], s = p - 1
        }
    }

    {
        uint8_t l = p - s - 1;
        *s = l; // write the last label length
        s = p;
        if(l > 0) // didn't end with a '.', p in [0; 254]
        {
            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            // p in [0; 254] so no need to: if(p >= limit) { return DOMAIN_TOO_LONG; }

            uint32_t prefix_len = s - name_parm;
            uint32_t origin_len = dnsname_len(origin);
            if(origin_len + prefix_len <= DOMAIN_LENGTH_MAX)
            {
                memcpy(s, origin, origin_len);
                return origin_len + prefix_len;
            }
            else
            {
                return DOMAIN_TOO_LONG;
            }
        }
        else // ended with a '.', p in [1; 255]
        {
            return s - name_parm;
        }
    }
}

/**
 *  Converts text buffer to a lower-case DNS name and checks for charset validity.
 *  Checks the DNS name charset is being respected.
 *  Appends an FQDN to the name.
 *  Allows for '*.fqdn' but rejects '*' in the middle of a name
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the text
 *  @param str_len the length of the text
 *  @param origin the FQDN to append to the result
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_check_star_with_charp_and_origin_locase(uint8_t *name_parm, const char *str, uint32_t str_len, const uint8_t *origin)
{
    uint8_t *const    limit = &name_parm[DOMAIN_LENGTH_MAX];
    const char *const str_limit = &str[str_len];
    uint8_t          *s = name_parm;
    uint8_t          *p = &name_parm[1];

    uint8_t           c;

    if(str_len == 0)
    {
        return DOMAINNAME_INVALID;
    }

    if(*str == '*')
    {
        str++;
        if(*str == '.') // *.fqdn
        {
            str++;
            *s++ = 1;
            *s++ = '*';
            p = s + 1;
        }
        else if(str_len == 1) // '*'
        {
            *s++ = 1;
            *s++ = '*';

            uint32_t origin_len = dnsname_len(origin);
            if(origin_len + 2 <= DOMAIN_LENGTH_MAX)
            {
                memcpy(s, origin, origin_len);
                return origin_len + 2;
            }
            else
            {
                return DOMAIN_TOO_LONG;
            }
        }
        else // *xxx
        {
            return DOMAINNAME_INVALID;
        }
    }

    for(; str < str_limit;)
    {
        c = *str++;

        if(c != '.')
        {
            if(cstr_to_dnsname_map_nostar[c] == 0)
            {
                return INVALID_CHARSET;
            }

            *p = LOCASE(c);
            if(++p >= limit)
            {
                // no place for a zero
                return DOMAIN_TOO_LONG;
            }
        }
        else // '.' ; note: p in [0; 254]
        {
            uint8_t l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                if(str == str_limit)
                {
                    if(s - name_parm == 1)
                    {
                        return 1;
                    }
                }
                return DOMAINNAME_INVALID;
            }

            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            p++; // note: p in [1; 255], s = p - 1
        }
    }

    {
        uint8_t l = p - s - 1;
        *s = l; // write the last label length
        s = p;
        if(l > 0) // didn't end with a '.', p in [0; 254]
        {
            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            // p in [0; 254] so no need to: if(p >= limit) { return DOMAIN_TOO_LONG; }

            uint32_t prefix_len = s - name_parm;
            uint32_t origin_len = dnsname_len(origin);
            if(origin_len + prefix_len <= DOMAIN_LENGTH_MAX)
            {
                memcpy(s, origin, origin_len);
                return origin_len + prefix_len;
            }
            else
            {
                return DOMAIN_TOO_LONG;
            }
        }
        else // ended with a '.', p in [1; 255]
        {
            return s - name_parm;
        }
    }
}

/**
 *  Converts a text buffer to a DNS RNAME.
 *  Handles escape codes
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source buffer
 *  @param str_len the length of the source buffer
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsrname_init_check_with_charp(uint8_t *name_parm, const char *str, uint32_t str_len)
{
    uint8_t *const    limit = &name_parm[DOMAIN_LENGTH_MAX];
    const char *const str_limit = &str[str_len];
    uint8_t          *s = name_parm;
    uint8_t          *p = &name_parm[1];

    uint8_t           c;

    if(str_len == 0)
    {
        return DOMAINNAME_INVALID;
    }

    if(str_len >= DOMAIN_LENGTH_MAX)
    {
        return DOMAIN_TOO_LONG;
    }

    for(; str < str_limit;)
    {
        c = *str++;

        if(c != '.')
        {
            if(c != '\\')
            {
                if(cstr_to_dnsrname_map[c] == 0)
                {
                    return INVALID_CHARSET;
                }

                *p = c;
                if(++p >= limit)
                {
                    // no place for a zero
                    return DOMAIN_TOO_LONG;
                }
            }
            else // escaping next character
            {
                if(str >= str_limit)
                {
                    return DOMAINNAME_INVALID;
                }

                c = *str++;
                *p = c;
                if(++p >= limit)
                {
                    // no place for a zero
                    return DOMAIN_TOO_LONG;
                }
            }
        }
        else // '.'
        {
            uint8_t l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                if(str == str_limit)
                {
                    if(s - name_parm == 1)
                    {
                        return 1;
                    }
                }
                return DOMAINNAME_INVALID;
            }

            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            p++;
        }
    }

    {
        uint8_t l = p - s - 1;
        *s = l;
        s = p;

        if(l > 0)
        {
            if(l > LABEL_LENGTH_MAX)
            {
                return LABEL_TOO_LONG;
            }

            // p in [0; 254] so no need to: if(p >= limit) { return DOMAIN_TOO_LONG; }

            *s++ = '\0';
        }
    }

    return s - name_parm;
}

/**
 *  Converts a C string to a dns RNAME and checks for validity
 *  Handles escape codes
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source c-string
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsrname_init_check_with_cstr(uint8_t *name_parm, const char *str) { return dnsrname_init_check_with_charp(name_parm, str, strlen(str)); }

/* ONE use */

ya_result cstr_get_dnsname_len(const char *str)
{
    ya_result   total = 0;
    const char *start;

    if(*str == '.')
    {
        str++;
    }

    int32_t label_len;

    do
    {
        char c;

        start = str;

        do
        {
            c = *str++;
        } while(c != '.' && c != '\0');

        label_len = (str - start) - 1;

        if(label_len > LABEL_LENGTH_MAX)
        {
            return LABEL_TOO_LONG;
        }

        total += label_len + 1;

        if(c == '\0')
        {
            if(label_len != 0)
            {
                total++;
            }

            break;
        }
    } while(label_len != 0);

    if(total <= DOMAIN_LENGTH_MAX)
    {
        return total;
    }
    else
    {
        return DOMAIN_TOO_LONG;
    }
}

/** @brief Converts a dns name to a C string
 *
 *  Converts a dns name to a C string
 *
 *  @param[in] name a pointer to the source dns name
 *  @param[in] str a pointer to a buffer that will get the c-string
 *
 *  @return Returns the length of the string
 */

/* FOUR uses */

uint32_t cstr_init_with_dnsname(char *str, const uint8_t *name)
{
#if DEBUG
    yassert(name != NULL);
#endif

    char   *start = str;

    uint8_t len;

    len = *name++;

    if(len != 0)
    {
        do
        {
            MEMCOPY(str, name, len);
            str += len;
            *str++ = '.';
            name += len;
            len = *name++;
        } while(len != 0);
    }
    else
    {
        *str++ = '.';
    }

    *str = '\0';

    return (uint32_t)(str - start);
}

/** @brief Tests if two DNS labels are equals
 *
 *  Tests if two DNS labels are equals
 *
 *  @param[in] name_a a pointer to a dnsname to compare
 *  @param[in] name_b a pointer to a dnsname to compare
 *
 *  @return Returns true if names are equal, else false.
 */

/* ELEVEN uses */

#if !DNSCORE_HAS_MEMALIGN_ISSUES

bool dnslabel_equals(const uint8_t *name_a, const uint8_t *name_b)
{
    uint8_t len = *name_a;

    if(len != *name_b)
    {
        return false;
    }

    len++;

    /* Hopefully the compiler just does register renaming */

    const uint32_t *name_a_32 = (const uint32_t *)name_a;
    const uint32_t *name_b_32 = (const uint32_t *)name_b;
    int             idx;
    int             len4 = len & ~3;
    for(idx = 0; idx < len4; idx += 4)
    {
        if(GET_U32_AT(name_a[idx]) != GET_U32_AT(name_b[idx]))
        {
            return false;
        }
    }

    /* Hopefully the compiler just does register renaming */

    name_a = (const uint8_t *)name_a_32;
    name_b = (const uint8_t *)name_b_32;

    switch(len & 3)
    {
        case 0:
            return true;
        case 1:
            return name_a[idx] == name_b[idx];
        case 2:
            return GET_U16_AT(name_a[idx]) == GET_U16_AT(name_b[idx]);
        case 3:
            return (GET_U16_AT(name_a[idx]) == GET_U16_AT(name_b[idx])) && (name_a[idx + 2] == name_b[idx + 2]);
    }

    // icc complains here but is wrong.
    // this line cannot EVER be reached

    assert(false); /* NOT zassert */

    return false;
}

#else

bool dnslabel_equals(const uint8_t *name_a, const uint8_t *name_b)
{
    uint8_t len = *name_a;

    if(*name_b == len)
    {
        return memcmp(name_a + 1, name_b + 1, len) == 0;
    }

    return false;
}

#endif

/** @brief Tests if two DNS labels are (case-insensitive) equals
 *
 *  Tests if two DNS labels are (case-insensitive) equals
 *
 *  @param[in] name_a a pointer to a dnsname to compare
 *  @param[in] name_b a pointer to a dnsname to compare
 *
 *  @return Returns true if names are equal, else false.
 */

#if !DNSCORE_HAS_MEMALIGN_ISSUES

bool dnslabel_equals_ignorecase_left1(const uint8_t *name_a, const uint8_t *name_b)
{
    int len = (int)*name_a;

    if(len != (int)*name_b)
    {
        return false;
    }

    len++;

    /*
     * Label size must match
     */

    int idx;
    int len4 = len & ~3;
    for(idx = 0; idx < len4; idx += 4)
    {
        if(!LOCASEEQUALSBY4(&name_a[idx], &name_b[idx])) /* can be used because left is locase */
        {
            return false;
        }
    }

    /* Hopefully the compiler just does register renaming */

    switch(len & 3)
    {
        case 0:
            return true;
        case 1:
            return LOCASEEQUALS(name_a[idx], name_b[idx]); /* can be used because left is locase */
        case 2:
            return LOCASEEQUALSBY2(&name_a[idx], &name_b[idx]); /* can be used because left is locase */
        case 3:
            return LOCASEEQUALSBY3(&name_a[idx], &name_b[idx]); /* can be used because left is locase */
    }

    assert(false); /* NOT zassert */

    return false;
}

#if DNSCORE_HAS_EXPERIMENTAL
bool dnslabel_equals_ignorecase_left2(const uint8_t *name_a, const uint8_t *name_b)
{
    int len = (int)*name_a;

    if(len != (int)*name_b)
    {
        return false;
    }

    for(int_fast32_t i = 1; i < len; ++i)
    {
        // if(__LOCASE_TABLE__[name_a[i]] != __LOCASE_TABLE__[name_b[i]])
        if(name_a[i] != __LOCASE_TABLE__[name_b[i]])
        {
            return false;
        }
    }

    return true;
}

bool dnslabel_equals_ignorecase_left3(const uint8_t *name_a, const uint8_t *name_b)
{
    int len = (int)*name_a;

    if(len != (int)*name_b)
    {
        return false;
    }

    for(name_a++, name_b++; len > 4; len -= 4, name_a += 4, name_b += 4)
    {
        // if(__LOCASE_TABLE__[name_a[i]] != __LOCASE_TABLE__[name_b[i]])
        uint32_t w = GET_U32_AT_P(name_a);
        uint32_t x = GET_U32_AT_P(name_b);

        if((w & 0xff) != __LOCASE_TABLE__[x & 0xff])
        {
            return false;
        }

        w >>= 8;
        x >>= 8;

        if((w & 0xff) != __LOCASE_TABLE__[x & 0xff])
        {
            return false;
        }

        w >>= 8;
        x >>= 8;

        if((w & 0xff) != __LOCASE_TABLE__[x & 0xff])
        {
            return false;
        }

        w >>= 8;
        x >>= 8;

        if((w) != __LOCASE_TABLE__[x])
        {
            return false;
        }
    }

    for(int_fast32_t i = 0; i < len; ++i)
    {
        // if(__LOCASE_TABLE__[name_a[i]] != __LOCASE_TABLE__[name_b[i]])
        if(name_a[i] != __LOCASE_TABLE__[name_b[i]])
        {
            return false;
        }
    }

    return true;
}
#endif

bool dnslabel_equals_ignorecase_left4(const uint8_t *name_a, const uint8_t *name_b)
{
    int len = (int)*name_a;

    if(len != (int)*name_b)
    {
        return false;
    }

    for(name_a++, name_b++; len > 4; len -= 4, name_a += 4, name_b += 4)
    {
        // if(__LOCASE_TABLE__[name_a[i]] != __LOCASE_TABLE__[name_b[i]])
        uint32_t w = GET_U32_AT_P(name_a);
        uint32_t x = GET_U32_AT_P(name_b);

        uint32_t z = (uint32_t)__LOCASE_TABLE__[x & 0xff] | ((uint32_t)__LOCASE_TABLE__[(x >> 8) & 0xff] << 8) | ((uint32_t)__LOCASE_TABLE__[(x >> 16) & 0xff] << 16) | ((uint32_t)__LOCASE_TABLE__[(x >> 24) & 0xff] << 24);

        if(w != z)
        {
            return false;
        }
    }

    for(int_fast32_t i = 0; i < len; ++i)
    {
        // if(__LOCASE_TABLE__[name_a[i]] != __LOCASE_TABLE__[name_b[i]])
        if(name_a[i] != __LOCASE_TABLE__[name_b[i]])
        {
            return false;
        }
    }

    return true;
}

#if DNSCORE_HAS_EXPERIMENTAL
bool dnslabel_equals_ignorecase_left5(const uint8_t *name_a, const uint8_t *name_b) { return strcasecmp((const char *)name_a, (const char *)name_b) == 0; }
#endif

#else

/**
 * This WILL work with label size too since a label size is 0->63
 * which is well outside the [A-Za-z] space.
 */

bool dnslabel_equals_ignorecase_left(const uint8_t *name_a, const uint8_t *name_b) { return strcasecmp((const char *)name_a, (const char *)name_b) == 0; }

#endif

/** @brief Tests if two DNS names are equals
 *
 *  Tests if two DNS labels are equals
 *
 *  @param[in] name_a a pointer to a dnsname to compare
 *  @param[in] name_b a pointer to a dnsname to compare
 *
 *  @return Returns true if names are equal, else false.
 */

/* TWO uses */

bool dnsname_equals(const uint8_t *name_a, const uint8_t *name_b)
{
    int la = dnsname_len(name_a);
    int lb = dnsname_len(name_b);

    if(la == lb)
    {
        return memcmp(name_a, name_b, la) == 0;
    }

    return false;
}

/*
 * Comparison of a name by label
 */

int dnsname_compare(const uint8_t *name_a, const uint8_t *name_b)
{
    for(;;)
    {
        int8_t la = (int8_t)name_a[0];
        int8_t lb = (int8_t)name_b[0];

        name_a++;
        name_b++;

        if(la == lb)
        {
            if(la > 0)
            {
                int c = memcmp(name_a, name_b, la);

                if(c != 0)
                {
                    return c;
                }
            }
            else
            {
                return 0;
            }
        }
        else
        {
            int c = memcmp(name_a, name_b, MIN(la, lb));

            if(c == 0)
            {
                c = la - lb;
            }

            return c;
        }

        name_a += la;
        name_b += lb;
    }
}

bool dnsname_is_subdomain(const uint8_t *subdomain, const uint8_t *domain)
{
#if !DNSCORE_HAS_FULL_ASCII7
    uint32_t len = dnsname_len(domain);
    uint32_t sub_len = dnsname_len(subdomain);

    if(sub_len >= len)
    {
        subdomain += sub_len - len;

        if(domain[0] == subdomain[0])
        {
            int ret = memcmp(subdomain, domain, len);
            return ret == 0;
        }
    }
#else
    dnsname_stack_t subdomain_stack;
    dnsname_stack_t domain_stack;
    int32_t         subdomain_top = dnsname_to_dnsname_stack(subdomain, &subdomain_stack);
    int32_t         domain_top = dnsname_to_dnsname_stack(domain, &domain_stack);

    if(subdomain_top >= domain_top)
    {
        for(int_fast32_t i = 0; i <= domain_top; ++i)
        {
            const uint8_t *sublabel = subdomain_stack.labels[i];
            const uint8_t *label = domain_stack.labels[i];

            if(!dnslabel_equals(sublabel, label))
            {
                return false;
            }
        }

        return true;
    }
#endif

    return false;
}

/** @brief Tests if two DNS names are (ignore case) equals
 *
 *  Tests if two DNS labels are (ignore case) equals
 *
 *  @param[in] name_a a pointer to a LO-CASE dnsname to compare
 *  @param[in] name_b a pointer to a dnsname to compare
 *
 *  @return Returns true if names are equal, else false.
 */

/* TWO uses */
#if DNSCORE_HAS_EXPERIMENTAL
bool dnsname_equals_ignorecase1(const uint8_t *name_a, const uint8_t *name_b)
{
    int len;

    do
    {
        len = (int)*name_a++;

        if(len != (int)*name_b++)
        {
            return false;
        }

        if(len == 0)
        {
            return true;
        }

        while(len > 4 && (LOCASEEQUALSBY4(name_a++, name_b++)))
        {
            len--;
        }

        while(len > 0 && (LOCASEEQUALS(*name_a++, *name_b++)))
        {
            len--;
        }
    } while(len == 0);

    return false;
}

bool dnsname_equals_ignorecase2(const uint8_t *name_a, const uint8_t *name_b)
{
    int len;

    for(int_fast32_t i = 0;; ++i)
    {
        len = (int)name_a[i];

        if(len != (int)name_b[i])
        {
            return false;
        }

        if(len == 0)
        {
            return true;
        }

        len += i;

        for(; i < len; ++i)
        {
            if(__LOCASE_TABLE__[name_a[i]] != __LOCASE_TABLE__[name_b[i]])
            {
                return false;
            }
        }
    }
}
#endif
bool dnsname_equals_ignorecase3(const uint8_t *name_a, const uint8_t *name_b)
{
    int len_a = dnsname_len(name_a);
    int len_b = dnsname_len(name_b);
    return ((len_a == len_b) && (strncasecmp((const char *)name_a, (const char *)name_b, len_a) == 0));
}

/** @brief Returns the full length of a dns name
 *
 *  Returns the full length of a dns name
 *
 *  @param[in] name a pointer to the dnsname
 *
 *  @return The length of the dnsname, "." ( zero ) included
 */

/* SEVENTEEN uses (more or less) */

uint32_t dnsname_len(const uint8_t *name)
{
    yassert(name != NULL);

    const uint8_t *start = name;

    uint8_t        c;

    while((c = *name++) > 0)
    {
        name += c;
    }

    return name - start;
}

int32_t dnsname_len_with_size(const uint8_t *name, size_t name_buffer_size)
{
    yassert(name != NULL);
    if(name_buffer_size > 0)
    {
        const uint8_t *start = name;
        const uint8_t *limit = name + name_buffer_size;
        uint8_t        c;
        while((c = *name++) > 0)
        {
            name += c;
            if(name >= limit)
            {
                return BUFFER_WOULD_OVERFLOW;
            }
        }

        return name - start;
    }
    else
    {
        return BUFFER_WOULD_OVERFLOW;
    }
}

int32_t dnsname_len_checked_with_size(const uint8_t *name, size_t name_buffer_size)
{
    yassert(name != NULL);

    if(name_buffer_size > 0)
    {
        const uint8_t *start = name;
        const uint8_t *limit = name + name_buffer_size;
        uint8_t        c;
        while((c = *name++) > 0)
        {
            name += c;
            if(name >= limit)
            {
                return BUFFER_WOULD_OVERFLOW;
            }
        }

        int32_t len = name - start;

        if(len > DOMAIN_LENGTH_MAX)
        {
            return DOMAIN_TOO_LONG;
        }

        return len;
    }
    else
    {
        return BUFFER_WOULD_OVERFLOW;
    }
}

ya_result dnsname_len_checked(const uint8_t *name)
{
    yassert(name != NULL);

    const uint8_t *name_base = name;

    uint8_t        c;

    while((c = *name++) > 0)
    {
        name += c;
        if(name - name_base > DOMAIN_LENGTH_MAX)
        {
            return DOMAIN_TOO_LONG;
        }
    }

    ya_result ret = (ya_result)(name - name_base);
    if(ret <= DOMAIN_LENGTH_MAX)
    {
        return ret;
    }
    else
    {
        return DOMAIN_TOO_LONG;
    }
}

/* ONE use */

uint32_t dnsname_getdepth(const uint8_t *name)
{
    yassert(name != NULL);

    uint32_t d = 0;

    uint8_t  c;

    while((c = *name) > 0)
    {
        name += c + 1;
        d++;
    }

    return d;
}

uint8_t *dnsname_dup(const uint8_t *src)
{
    uint8_t *dst;
    uint32_t len = dnsname_len(src);
    MALLOC_OR_DIE(uint8_t *, dst, len, DNSNAMED_TAG);
    MEMCOPY(dst, src, len);

    return dst;
}

void dnsname_free(uint8_t *ptr)
{
#if DEBUG
    uint32_t len = dnsname_len(ptr);
    memset(ptr, 0xfe, len);
#endif
    free(ptr);
}

/* ONE use */

uint32_t dnsname_copy(uint8_t *dst, const uint8_t *src)
{
    uint32_t len = dnsname_len(src);

    MEMCOPY(dst, src, len);

    return len;
}

ya_result dnsname_copy_checked(uint8_t *dst, const uint8_t *src)
{
    ya_result len = dnsname_len_checked(src);
    if(ISOK(len))
    {
        MEMCOPY(dst, src, len);
    }
    return len;
}

/** @brief Canonizes a dns name.
 *
 *  Canonizes a dns name. (A.K.A : lo-cases it)
 *
 *  @param[in] src a pointer to the dns name
 *  @param[out] dst a pointer to a buffer that will hold the canonized dns name
 *
 *  @return The length of the dns name
 */

/* TWELVE uses */

uint32_t dnsname_canonize(const uint8_t *src, uint8_t *dst)
{
    const uint8_t *org = src;

    uint32_t       len;

    for(;;)
    {
        len = *src++;
        *dst++ = len;

        if(len == 0)
        {
            break;
        }

        while(len > 0)
        {
            *dst++ = LOCASE(*src++); /* Works with the dns character set */
            len--;
        }
    }

    return (uint32_t)(src - org);
}

/*****************************************************************************
 *
 * VECTOR
 *
 *****************************************************************************/

/**
 * Converts a vector of DNS labels into a DNS name
 * note: top is the last offset in the vector, not its length
 *
 * @param name an array of pointers to DNS labels
 * @param top the last valid index of the array
 * @param str_start a buffer that will contain the DNS name
 * @return the size of the DNS name
 */

uint32_t dnslabel_vector_to_dnsname(const_dnslabel_vector_reference_t name, int32_t top, uint8_t *str_start)
{
    uint8_t                          *str = str_start;

    const_dnslabel_vector_reference_t limit = &name[top];

    while(name <= limit)
    {
        const uint8_t *label = *name++;
        uint8_t        len = label[0] + 1;
        MEMCOPY(str, label, len);
        str += len;
    }

    *str++ = 0;

    return str - str_start;
}

/**
 * Converts a vector of DNS labels into a domain name C string
 * note: top is the last offset in the vector, not its length
 *
 * @param name an array of pointers to DNS labels
 * @param top the last valid index of the array
 * @param str_start a buffer that will contain the domain name C string
 * @return strlen(domain name)
 */

uint32_t dnslabel_vector_to_cstr(const_dnslabel_vector_reference_t name, int32_t top, char *str)
{
    const_dnslabel_vector_reference_t limit = &name[top];

    char                             *start = str;

    while(name <= limit)
    {
        const uint8_t *label = *name++;
        uint8_t        len = *label++;

        MEMCOPY(str, label, len);
        str += len;

        *str++ = '.';
    }

    *str = '\0';

    return (uint32_t)(str - start);
}

/**
 * Computes the DNS name length of a vector of DNS labels
 * note: top is the last offset in the vector, not its length
 *
 * @param name an array of pointers to DNS labels
 * @param top the last valid index of the array
 * @return the length of the DNS name
 */

uint32_t dnslabel_vector_len(const_dnslabel_vector_reference_t name, int32_t top)
{
    uint32_t ret = 1;

    for(int_fast32_t i = 0; i <= top; i++)
    {
        ret += name[i][0] + 1;
    }

    return ret;
}

/* ONE use */

uint32_t dnsname_vector_sub_to_dnsname(const dnsname_vector_t *name, int32_t from, uint8_t *name_start)
{
    uint8_t                          *str = name_start;

    const_dnslabel_vector_reference_t limit = &name->labels[name->size];
    const_dnslabel_vector_reference_t labelp = &name->labels[from];

    while(labelp <= limit)
    {
        uint32_t len = *labelp[0] + 1;
        MEMCOPY(str, *labelp, len);
        str += len;
        labelp++;
    }

    *str++ = 0;

    return str - name_start;
}

/** @brief Divides a name into sections
 *
 *  Divides a name into sections.
 *  Writes a pointer to each label of the dnsname into an array
 *  "." is never put in there.
 *
 *  @param[in] name a pointer to the dnsname
 *  @param[out] sections a pointer to the target array of pointers
 *
 *  @return The index of the top-level label ("." is never put in there)
 */

/* TWO uses */

int32_t dnsname_to_dnslabel_vector(const uint8_t *dns_name, dnslabel_vector_reference_t labels)
{
    yassert(dns_name != NULL && labels != NULL);

    int32_t idx = -1;
    int     offset = 0;

    for(;;)
    {
        uint32_t len = dns_name[offset];

        if(len == 0)
        {
            break;
        }

        labels[++idx] = &dns_name[offset];
        offset += len + 1;
    }

    return idx;
}

/** @brief Divides a name into sections
 *
 *  Divides a name into sections.
 *  Writes a pointer to each label of the dnsname into an array
 *  "." is never put in there.
 *
 *  @param[in] name a pointer to the dnsname
 *  @param[out] sections a pointer to the target array of pointers
 *
 *  @return The index of the top-level label ("." is never put in there)
 */

/* TWENTY-ONE uses */

int32_t dnsname_to_dnsname_vector(const uint8_t *dns_name, dnsname_vector_t *name)
{
    yassert(dns_name != NULL && name != NULL);

    int32_t size = dnsname_to_dnslabel_vector(dns_name, name->labels);
    name->size = size;

    return size;
}

uint32_t dnsname_vector_copy(dnsname_vector_t *dst, const dnsname_vector_t *src)
{
    dst->size = src->size;
    if(dst->size > 0)
    {
        memcpy((void *)&dst->labels[0], &src->labels[0], sizeof(uint8_t *) * (dst->size + 1));
    }
    return dst->size;
}

uint32_t dnsname_vector_len(const dnsname_vector_t *name_vector)
{
    uint32_t len = 1;

    for(int_fast32_t size = 0; size <= name_vector->size; size++)
    {
        len += name_vector->labels[size][0] + 1;
    }

    return len;
}

/*****************************************************************************
 *
 * STACK
 *
 *****************************************************************************/

/** @brief Converts a stack of dns labels to a C string
 *
 *  Converts a stack of dns labels to a C string
 *
 *  @param[in] name a pointer to the dnslabel stack
 *  @param[in] top the index of the top of the stack
 *  @param[in] str a pointer to a buffer that will get the c-string
 *
 *  @return Returns the length of the string
 */

/* ONE use */

uint32_t dnslabel_stack_to_cstr(const_dnslabel_stack_reference_t name, int32_t top, char *str)
{
    char *start = str;
    if(top >= 0)
    {
        do
        {
            const uint8_t *label = name[top];
            uint8_t        len = *label++;

            MEMCOPY(str, label, len);
            str += len;

            *str++ = '.';
            top--;
        } while(top >= 0);
    }
    else
    {
        *str++ = '.';
    }
    *str = '\0';

    return (uint32_t)(str - start);
}

/* ONE use */

uint32_t dnslabel_stack_to_dnsname(const_dnslabel_stack_reference_t name, int32_t top, uint8_t *str_start)
{

    uint8_t                         *str = str_start;
    const_dnslabel_stack_reference_t base = name;

    name += top;

    while(name >= base)
    {
        const uint8_t *label = *name--;
        uint32_t       len = *label;

        MEMCOPY(str, label, len + 1);
        str += len + 1;
    }

    *str++ = '\0';

    return (uint32_t)(str - str_start);
}

int32_t dnsname_to_dnslabel_stack(const uint8_t *dns_name, dnslabel_stack_reference_t labels)
{
    int32_t        label_pointers_top = -1;
    const uint8_t *label_pointers[LABEL_COUNT_MAX];

    for(;;)
    {
        uint8_t len = *dns_name;

        if(len == 0)
        {
            break;
        }

        label_pointers[++label_pointers_top] = dns_name;

        dns_name += len + 1;
    }

    int32_t         size = label_pointers_top;

    const uint8_t **labelp = labels;
    while(label_pointers_top >= 0)
    {
        *labelp++ = (uint8_t *)label_pointers[label_pointers_top--];
    }

    return size;
}

/* ONE use */

uint32_t dnsname_stack_to_dnsname(const dnsname_stack_t *name_stack, uint8_t *name_start)
{
    uint8_t *name = name_start;

    for(int_fast32_t size = name_stack->size; size >= 0; size--)
    {
        uint32_t len = name_stack->labels[size][0] + 1;
        MEMCOPY(name, name_stack->labels[size], len);
        name += len;
    }

    *name++ = '\0';

    return name - name_start;
}

uint32_t dnsname_stack_len(const dnsname_stack_t *name_stack)
{
    uint32_t len = 1;

    for(int_fast32_t size = 0; size <= name_stack->size; size++)
    {
        len += name_stack->labels[size][0] + 1;
    }

    return len;
}

/* TWO uses (debug) */

uint32_t dnsname_stack_to_cstr(const dnsname_stack_t *name, char *str) { return dnslabel_stack_to_cstr(name->labels, name->size, str); }

/* ONE use */

bool dnsname_equals_dnsname_stack(const uint8_t *str, const dnsname_stack_t *name)
{
    int32_t size = name->size;

    while(size >= 0)
    {
        const uint8_t *label = name->labels[size];
        uint8_t        len = *label;

        if(len != *str)
        {
            return false;
        }

        label++;
        str++;

        if(memcmp(str, label, len) != 0)
        {
            return false;
        }

        str += len;

        size--;
    }

    return *str == 0;
}

bool dnsname_under_dnsname_stack(const uint8_t *str, const dnsname_stack_t *name)
{
    int32_t size = name->size;

    while(size >= 0)
    {
        const uint8_t *label = name->labels[size];
        uint8_t        len = *label;

        if(len != *str)
        {
            return (len != 0);
        }

        label++;
        str++;

        if(memcmp(str, label, len) != 0)
        {
            return false;
        }

        str += len;

        size--;
    }

    return *str == 0;
}

/* FOUR uses */

int32_t dnsname_stack_push_label(dnsname_stack_t *dns_name, const uint8_t *dns_label)
{
    yassert(dns_name != NULL && dns_label != NULL);

    dns_name->labels[++dns_name->size] = dns_label;

    return dns_name->size;
}

/* FOUR uses */

int32_t dnsname_stack_pop_label(dnsname_stack_t *name)
{
    yassert(name != NULL);

#if DEBUG
    name->labels[name->size] = (uint8_t *)~0;
#endif

    return name->size--;
}

const uint8_t *dnsname_stack_peek_label(dnsname_stack_t *name) { return name->labels[name->size]; }

int32_t        dnsname_to_dnsname_stack(const uint8_t *dns_name, dnsname_stack_t *name)
{
    int32_t  label_pointers_top = -1;
    uint8_t *label_pointers[LABEL_COUNT_MAX];

    for(;;)
    {
        uint8_t len = *dns_name;

        if(len == 0)
        {
            break;
        }

        label_pointers[++label_pointers_top] = (uint8_t *)dns_name;

        dns_name += len + 1;
    }

    name->size = label_pointers_top;

    const uint8_t **labelp = name->labels;
    while(label_pointers_top >= 0)
    {
        *labelp++ = label_pointers[label_pointers_top--];
    }

    return name->size;
}

/** @brief Allocates and duplicates a name with ZALLOC.
 *
 *  Allocates and duplicates a dns name with ZALLOC.
 *
 *  @param[in] name a pointer to the dnsname
 *
 *  @return A new instance of the dnsname.
 */

uint8_t *dnsname_zdup(const uint8_t *name)
{
    yassert(name != NULL);

    uint32_t len = dnsname_len(name);

    uint8_t *dup;

    ZALLOC_OBJECT_ARRAY_OR_DIE(dup, uint8_t, len, ZDB_NAME_TAG);
    MEMCOPY(dup, name, len); // nothing wrong here

    return dup;
}

/** @brief Converts a name to a newly allocated dns name with ZALLOC.
 *
 *  Converts a name to a newly allocated dns name with ZALLOC.
 *
 *  @param domainname a pointer to the name
 *
 *  @return a new instance of the name converted to a dnsname
 */

uint8_t *dnsname_zdup_from_name(const char *domainname)
{
    yassert(domainname != NULL);

    uint32_t  len = cstr_get_dnsname_len(domainname);
    ya_result ret;
    uint8_t  *dup;

    ZALLOC_OBJECT_ARRAY_OR_DIE(dup, uint8_t, len, ZDB_NAME_TAG);
    if(ISOK(ret = dnsname_init_check_star_with_cstr(dup, domainname)))
    {
    }
    else
    {
        ZFREE_ARRAY(dup, len);
        dup = NULL;
    }

    return dup;
}

void dnsname_zfree(uint8_t *name) { ZFREE_ARRAY(name, dnsname_len(name)); }

/** @brief Allocates and duplicates a label with ZALLOC.
 *
 *  Allocates and duplicates a label with ZALLOC.
 *
 *  @param[in] name a pointer to the label
 *
 *  @return A new instance of the label
 */

uint8_t *dnslabel_zdup(const uint8_t *name)
{
    yassert(name != NULL);

    uint32_t len = name[0] + 1;

    uint8_t *dup;
    ZALLOC_OBJECT_ARRAY_OR_DIE(dup, uint8_t, len, ZDB_LABEL_TAG);
    MEMCOPY(dup, name, len);

    return dup;
}

void dnslabel_zfree(uint8_t *name)
{
    uint32_t len = name[0] + 1;
    ZFREE_ARRAY(name, len);
    (void)len; // silences warning  on some build settings
}

/**
 *
 * Expands a compressed FQDN from a wire.
 *
 * @param wire_base_ the address of the wire buffer
 * @param wire_size the size of the wire buffer
 * @param compressed_fqdn the address, in the wire buffer, of the FQDN to expand
 * @param output_fqdn the address of the buffer that will get a copy of the expanded FQDN
 * @param output_fqdn_size the size of the buffer that will get a a copy of the expanded FQDN
 *
 * @return a pointer to the next byte after the expanded FQDN (ie: points to a type) or NULL if an error occurred
 */

const uint8_t *dnsname_expand_compressed(const void *wire_base_, size_t wire_size, const void *compressed_fqdn, uint8_t *output_fqdn, uint32_t output_fqdn_size)
{
    const uint8_t *base = (const uint8_t *)wire_base_;
    const uint8_t *p_limit = &base[wire_size];

    yassert(output_fqdn_size >= DOMAIN_LENGTH_MAX);

    uint8_t       *buffer = output_fqdn;
    uint8_t *const buffer_limit = &buffer[output_fqdn_size]; // pointer to the byte that must never be reached
    const uint8_t *p = (const uint8_t *)compressed_fqdn;
    const uint8_t *ret_ptr;

    if((p < base) || (p >= p_limit))
    {
        return NULL; /* EOF */
    }

    for(;;)
    {
        uint8_t len = *p++; // get the next byte (length)

        if((len & 0xc0) == 0xc0) // test if it's a compressed code
        {
            ret_ptr = p + 1;

            /* reposition the pointer */
            uint32_t new_offset = len & 0x3f;
            new_offset <<= 8;
            new_offset |= *p;

            p = &base[new_offset];

            if(p < p_limit) // ensure we are not outside the message
            {
                break;
            }

            return NULL;
        }

        if((p + len >= p_limit) || (buffer + len + 1 >= buffer_limit))
        {
            return NULL;
        }

        *buffer++ = len;

        if(len == 0)
        {
            return p;
        }

        uint8_t *label_limit = &buffer[len];
        do
        {
            *buffer++ = tolower(*p++);
        } while(buffer < label_limit);
    }

    for(;;)
    {
        uint8_t len = *p;

        if((len & 0xc0) == 0xc0) /* EDF: better yet: cmp len, 192; jge  */
        {
            /* reposition the pointer */
            uint32_t new_offset = len & 0x3f;
            new_offset <<= 8;
            new_offset |= p[1];

            const uint8_t *q = &base[new_offset];

            if(q < p)
            {
                p = q;
                continue;
            }

            return NULL;
        }

        if((p + len >= p_limit) || (buffer + len + 1 >= buffer_limit))
        {
            return NULL;
        }

        *buffer++ = len;

        if(len == 0)
        {
            return ret_ptr;
        }

        ++p;

        uint8_t *label_limit = &buffer[len];
        do
        {
            *buffer++ = tolower(*p++);
        } while(buffer < label_limit);
    }

    // never reached
}

/**
 *
 * Skip a compressed FQDN from a wire to position right after the FQDN.
 *
 * @param wire_base_ the address of the wire buffer
 * @param wire_size the size of the wire buffer
 * @param compressed_fqdn the address, in the wire buffer, of the FQDN to expand
 *
 * @return a pointer to the next byte after the FQDN (ie: points to a type) or NULL if an error occurred
 */

const uint8_t *dnsname_skip_compressed(const void *wire_base_, size_t wire_size, const void *compressed_fqdn)
{
    const uint8_t *base = (const uint8_t *)wire_base_;

    const uint8_t *p_limit = &base[wire_size];

    const uint8_t *p = (const uint8_t *)compressed_fqdn;

    if((p < base) || (p >= p_limit))
    {
        return NULL; /* EOF */
    }

    for(;;)
    {
        uint8_t len = *p++;

        if((len & 0xc0) == 0xc0)
        {
            return p + 1; // yes, read the purpose of the function
        }

        if(len == 0)
        {
            return p;
        }

        p += len;

        if(p >= p_limit)
        {
            return NULL;
        }
    }

    // never reached
}

/** @} */
