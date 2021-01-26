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

/** @defgroup dnscore
 *  @ingroup dnscore
 *  @brief Functions used to manipulate dns formatted names and labels
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
 */

#define DNSNAME_C_ 1

#include "dnscore/dnscore-config.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "dnscore/dnscore-config.h"
#include "dnscore/sys_types.h"


const u8 __LOCASE_TABLE__[256] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,

    0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,

    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,

    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};


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

/* TWO uses */

/*
 * This table contains TRUE for both expected name terminators
 */

static bool cstr_to_dnsname_terminators[256] =
{
    TRUE,  FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, /* '\0' */
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, TRUE,  FALSE, /* '.' */
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
    FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
};

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

#if !HAS_FULL_ASCII7

/*
 * The list of characters that are valid in a zone: * - _ 0..9 A..Z a..z
 *
 */

static s8 cstr_to_dnsname_map[256] =
{// 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
   -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 00 (HEX) */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 10 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1,-1, 0, /* 20 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /* 30 */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 40 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, /* 50 */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 60 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, /* 70 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 80 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 90 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * The list of characters that are valid in a zone: - _ 0..9 A..Z a..z 
 */

static s8 cstr_to_dnsname_map_nostar[256] =
{// 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
   -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 00 (HEX) */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 10 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,-1, 0, /* 20 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /* 30 */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 40 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, /* 50 */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 60 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, /* 70 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 80 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 90 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

#else

static s8 cstr_to_dnsname_map[256] =
{
   -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 00 (HEX) */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 10 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,-1, 1, /* 20 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 30 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 40 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 50 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 60 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 70 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 80 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 90 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static s8 cstr_to_dnsname_map_nostar[256] =
{
   -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 00 (HEX) */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 10 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,-1, 1, /* 20 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 30 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 40 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 50 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 60 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 70 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 80 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 90 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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

#if !HAS_FULL_ASCII7

static const s8 cstr_to_dnsrname_map[256] =
{
   -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 00 (HEX) */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 10 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,-1, 0, /* 20 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /* 30 */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 40 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 2, 0, 0, 1, /* 50 */
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 60 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, /* 70 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 80 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 90 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

#else

static const s8 cstr_to_dnsrname_map[256] =
{
   -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 00 (HEX) */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 10 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,-1, 1, /* 20 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 30 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 40 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, /* 50 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 60 */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 70 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 80 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 90 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

#endif

/**
 * char DNS charset test
 * 
 * @param c
 * @return TRUE iff c in in the DNS charset
 * 
 */

bool
dnsname_is_charspace(u8 c)
{
    return cstr_to_dnsname_map[c] == 1;
}

s32
dnslabel_compare(const u8 *a, const u8 *b)
{
    int len = MIN(*a, *b);
    int d = memcmp(a+1, b+1, len);
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
 * @return TRUE iff each char in the label in in the DNS charset
 * 
 */

bool
dnslabel_verify_charspace(const u8 *label)
{
    u8 n = *label;    

    if(n > MAX_LABEL_LENGTH)
    {
        return FALSE;
    }

    const u8 *const limit = &label[n];

    while(++label < limit)
    {
        u8 c = *label;

        if(cstr_to_dnsname_map[c] != 1)
        {
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * dns name DNS charset test
 *
 * @param name_wire
 * @return TRUE if each char in the name is in the DNS charset
 *
 */

bool
dnsname_verify_charspace(const u8 *name_wire)
{
    u8 n;

    for(;;)
    {
        n = *name_wire;

        if(n == 0)
        {
            return TRUE;
        }

        if(n > MAX_LABEL_LENGTH)
        {
            return FALSE;
        }

        const u8 *const limit = &name_wire[n];

        while(++name_wire <= limit)
        {
            u8 c = *name_wire;

            if(cstr_to_dnsname_map[c] != 1)
            {
                return FALSE;
            }
        }
    }
}


/**
 * label DNS charset test and set to lower case
 * 
 * @param label
 * @return TRUE iff each char in the label in in the DNS charset
 * 
 */

bool
dnslabel_locase_verify_charspace(u8 *label)
{
    u8 n = *label;

    if(n > MAX_LABEL_LENGTH)
    {
        return FALSE;
    }

    u8 * const limit = &label[n];

    while(++label <= limit)
    {
        u8 c = *label;

        if(cstr_to_dnsname_map[c] != 1)
        {
            return FALSE;
        }

        *label = LOCASE(c);
    }

    return TRUE;
}

/**
 * dns name DNS charset test and set to lower case
 * 
 * @param name_wire
 * @return TRUE iff each char in the name is in the DNS charset
 * 
 */

bool
dnsname_locase_verify_charspace(u8 *name_wire)
{
    u8 n;
    
    for(;;)
    {
        n = *name_wire;
        
        if(n == 0)
        {
            return TRUE;
        }

        if(n > MAX_LABEL_LENGTH)
        {
            return FALSE;
        }

        u8 * const limit = &name_wire[n];

        while(++name_wire <= limit)
        {
            u8 c = *name_wire;

            if(cstr_to_dnsname_map[c] != 1)
            {
                return FALSE;
            }

            *name_wire = LOCASE(c);
        }
    }
}

/**
 * dns name DNS charset test and set to lower case
 * 
 * LOCASE is done using tolower(c)
 * 
 * @param name_wire
 * @return TRUE iff each char in the name in in the DNS charset
 * 
 */

bool
dnsname_locase_verify_extended_charspace(u8 *name_wire)
{
    u8 n;
    
    for(;;)
    {
        n = *name_wire;
        
        if(n == 0)
        {
            return TRUE;
        }

        if(n > MAX_LABEL_LENGTH)
        {
            return FALSE;
        }

        u8 * const limit = &name_wire[n];

        while(++name_wire <= limit)
        {
            u8 c = *name_wire;

            if(cstr_to_dnsname_map[c] != 1)
            {
                return FALSE;
            }

            *name_wire = tolower(c);
        }
    }
}

/**
 *  @brief Converts a C string to a dns name.
 *
 *  Converts a C string to a dns name.
 *
 *  @param[in] name_parm a pointer to a buffer that will get the full dns name
 *  @param[in] str a pointer to the source c-string
 *
 *  @return Returns the length of the string up to the last '\0'
 */

ya_result
cstr_to_dnsname(u8* name_parm, const char* str)
{
    u8 * const limit = &name_parm[MAX_DOMAIN_LENGTH];
    u8 *s = name_parm;
    u8 *p = &name_parm[1];

    u8 c;

    for(c = *str++;; c = *str++)
    {
        if(!cstr_to_dnsname_terminators[c] /*(c != '.') && (c != '\0')*/)
        {
            *p = c;
        }
        else
        {
            u8 l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                break;
            }

            if(l > MAX_LABEL_LENGTH)
            {
                return LABEL_TOO_LONG;
            }

            if(c == '\0')
            {
                if(p >= limit)
                {
                    return DOMAIN_TOO_LONG;
                }

                *s++ = '\0';
                break;
            }
        }

        if(++p > limit)
        {
            return DOMAIN_TOO_LONG;
        }
    }

    return s - name_parm;
}

ya_result
cstr_to_locase_dnsname(u8* name_parm, const char* str)
{
    u8 * const limit = &name_parm[MAX_DOMAIN_LENGTH];
    u8 *s = name_parm;
    u8 *p = &name_parm[1];

    u8 c;

    for(c = *str++;; c = *str++)
    {
        if(!cstr_to_dnsname_terminators[c] /*(c != '.') && (c != '\0')*/)
        {
            *p = LOCASE(c);
        }
        else
        {
            u8 l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                break;
            }

            if(l > MAX_LABEL_LENGTH)
            {
                return LABEL_TOO_LONG;
            }

            if(c == '\0')
            {
                if(p >= limit)
                {
                    return DOMAIN_TOO_LONG;
                }

                *s++ = '\0';
                break;
            }
        }

        if(++p > limit)
        {
            return DOMAIN_TOO_LONG;
        }
    }

    return s - name_parm;
}

ya_result
charp_to_dnsname(u8* name_parm, const char* str, u32 str_len)
{
    const char * const limit = &str[str_len];
    u8 *s = name_parm;
    u8 *p = &name_parm[1];

    u8 c;
    
    if(str_len >= MAX_DOMAIN_LENGTH)
    {
        return DOMAIN_TOO_LONG;
    }

    for(c = *str++; ; c = *str++)
    {
        if((str <= limit) && !cstr_to_dnsname_terminators[c] /*(c != '.') && (c != '\0')*/)
        {
            *p = c;
        }
        else
        {
            u8 l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                break;
            }

            if(l > MAX_LABEL_LENGTH)
            {
                return LABEL_TOO_LONG;
            }

            if(str >= limit)
            {
                *s++ = '\0';
                break;
            }
        }

        ++p;
    }

    return s - name_parm;
}

ya_result
charp_to_locase_dnsname(u8* name_parm, const char* str, u32 str_len)
{
    const char * const limit = &str[str_len];
    u8 *s = name_parm;
    u8 *p = &name_parm[1];

    u8 c;
    
    if(str_len >= MAX_DOMAIN_LENGTH)
    {
        return DOMAIN_TOO_LONG;
    }

    for(c = *str++; ; c = *str++)
    {
        if((str <= limit) && !cstr_to_dnsname_terminators[c] /*(c != '.') && (c != '\0')*/)
        {
            *p = LOCASE(c);
        }
        else
        {
            u8 l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                break;
            }

            if(l > MAX_LABEL_LENGTH)
            {
                return LABEL_TOO_LONG;
            }

            if(str >= limit)
            {
                *s++ = '\0';
                break;
            }
        }

        ++p;
    }

    return s - name_parm;
}

/**
 * Allows for '*'
 */

ya_result
charp_to_locase_dnsname_with_check(u8* name_parm, const char* str, u32 str_len)
{
    const char * const limit = &str[str_len];
    u8 *s = name_parm;
    u8 *p = &name_parm[1];

    u8 c;
    
    if(str_len >= MAX_DOMAIN_LENGTH)
    {
        return DOMAIN_TOO_LONG;
    }

    for(c = *str++; ; c = *str++)
    {       
        if((str <= limit) && !cstr_to_dnsname_terminators[c] /*(c != '.') && (c != '\0')*/)
        {
            if(cstr_to_dnsname_map[c] == 0)
            {
                return INVALID_CHARSET;
            }
            
            *p = LOCASE(c);
        }
        else
        {
            u8 l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                break;
            }

            if(l > MAX_LABEL_LENGTH)
            {
                return LABEL_TOO_LONG;
            }

            if(str >= limit)
            {
                *s++ = '\0';
                break;
            }
        }

        ++p;
    }

    return s - name_parm;
}

/**
 *  @brief Converts a C string to a dns name and checks for validity
 *
 *  Converts a C string to a dns name.
 *
 *  @param[in] name_parm a pointer to a buffer that will get the full dns name
 *  @param[in] str a pointer to the source c-string
 *
 *  @return Returns the length of the string up to the last '\0'
 */

ya_result
cstr_to_dnsname_with_check(u8* name_parm, const char* str)
{
    u8 * const limit = &name_parm[MAX_DOMAIN_LENGTH];
    u8 *s = name_parm;
    u8 *p = &name_parm[1];

    u8 c;

    /*
     * I cannot check this in one go actually.
     *
     * It would work 99.9999999% of the time but if the string is "" and is at the end of a page it would overlap to a non-mapped
     * memory and crash.
     *
     */

    if((str[0] == '.') && (str[1] == '\0'))
    {
        *name_parm = 0;
        return 1;
    }

    if(str[0] == '*')
    {
        if(str[1] == '\0')
        {
            name_parm[0] = 1;
            name_parm[1] = '*';
            name_parm[2] = '\0';
            return 3;
        }
        else if(str[1] == '.')
        {
            name_parm[0] = 1;
            name_parm[1] = '*';
            str += 2;
            s += 2;
            p += 2;
        }
        else
        {
            return DOMAINNAME_INVALID;
        }
    }

    for(c = *str++;; c = *str++)
    { /* test if a switch/case is better (break mix issues for this switch in this particular loop)
	   *
	   * in theory this is test/jb/jz
	   * a switch would be jmp [v]
	   *
	   */
        
        if(cstr_to_dnsname_map_nostar[c] >= 0 /*(c != '.') && (c != '\0')*/)
        {
            if(cstr_to_dnsname_map_nostar[c] == 0)
            {
                return INVALID_CHARSET;
            }

            *p = c;
        }
        else
        {
            u8 l = p - s - 1;
            *s = l;
            s = p;

            if(l == 0)
            {
                if(c != '\0')
                {
                    return DOMAINNAME_INVALID;
                }

                break;
            }

            if(l > MAX_LABEL_LENGTH)
            {
                return LABEL_TOO_LONG;
            }

            if(c == '\0')
            {
                if(p >= limit)
                {
                    return DOMAIN_TOO_LONG;
                }

                *s++ = '\0';
                break;
            }
        }

        if(++p > limit)
        {
            return DOMAIN_TOO_LONG;
        }
    }

    return s - name_parm;
}

ya_result
cstr_to_dnsname_with_check_len(u8* name_parm, const char* text, u32 text_len)
{
    /*
     * .        => 1 => 00 => 1
     * 
     * a        => 1 => 01 'A' 00 => 3
     * a.b      => 3 => 01 'A' 01 'B' 00 => 5
     * a.b.     => 4 => 01 'A' 01 'B' 00 => 5
     * 
     */

    u8 *label_start = name_parm;
    u8 *p = &name_parm[1];
    
    u8 c;

    /*
     * I cannot check this in one go actually.
     *
     * It would work 99.9999999% of the time but if the string is "" and is at the end of a page it would overlap to a non-mapped
     * memory and crash.
     *
     */
    
    if(text_len == 0)
    {
        return DOMAINNAME_INVALID;
    }
    
    if(text[0] == '.')
    {
        if(text_len == 1)
        {
            *name_parm = 0;
            return 1;
        }
        else
        {
            return DOMAINNAME_INVALID;
        }
    }

    if(text[0] != '*')
    {
        // ensure the length is acceptable
        
        u32 output_len = text_len + 1;
        
        if(text[text_len - 1] != '.')
        {
            output_len += 1;
        }
        
        if(output_len > MAX_DOMAIN_LENGTH)
        {
            return DOMAIN_TOO_LONG;
        }
    }
    else
    {
        if(text_len == 1)      // '*'
        {
            name_parm[0] = 1;
            name_parm[1] = '*';
            name_parm[2] = '\0';
            return 3;
        }
        else if(text[1] == '.')  //  '*.????' note: at this point str_len is 2 or more
        {
            // ensure the length is acceptable
            
            u32 output_len = text_len + 1;
        
            if(text[text_len - 1] != '.')
            {
                output_len += 1;
            }

            if(output_len > MAX_DOMAIN_LENGTH)
            {
                return DOMAIN_TOO_LONG;
            }
            
            name_parm[0] = 1;
            name_parm[1] = '*';
            
            if(text_len == 2)   
            {
                name_parm[2] = '\0';
                return 3;
            }
            
            text += 2;
            label_start += 2;
            p += 2;
        }
        else                    // '*????'
        {
            return DOMAINNAME_INVALID;
        }
    }
    
    const char * const text_limit = &text[text_len];

    for(c = *text++; ; c = *text++)
    {
        /* test if a switch/case is better (break mix issues for this switch in this particular loop)
         *
         * in theory this is test/jb/jz
         * a switch would be jmp [v]
         *
         */
        
        if(cstr_to_dnsname_map_nostar[c] >= 0)          // (c != '.') && (c != '\0')
        {
            if(cstr_to_dnsname_map_nostar[c] == 0)
            {
                return INVALID_CHARSET;
            }

            *p++ = c;
            
            if(text == text_limit)
            {
                // close the label
                
                u8 label_length = p - label_start - 1;      // size of the label
            
                if(label_length > MAX_LABEL_LENGTH)
                {
                    return LABEL_TOO_LONG;
                }
                
                *label_start = label_length;
                
                // close the fqdn
                
                *p++ = 0;
                
                return p - name_parm;
            }
        }
        else    // reached '.' or end of cstr (which should not occur in this algorithm)
        {
            u8 label_length = p - label_start - 1;      // size of the label
            /*
            if(label_length == 0)                       // .. case
            {
                if(c != '\0')
                {
                    return DOMAINNAME_INVALID;
                }

                break;
            }
            */
            if(label_length > MAX_LABEL_LENGTH)
            {
                return LABEL_TOO_LONG;
            }
            
            *label_start = label_length;
            
            if(text == text_limit)
            {
                *p++ = '\0';
                return p - name_parm;
            }
            
            label_start = p;
            p++;
        }
    }
}

ya_result
cstr_to_locase_dnsname_with_check_len(u8* name_parm, const char* text, u32 text_len)
{
    /*
     * .        => 1 => 00 => 1
     * 
     * a        => 1 => 01 'A' 00 => 3
     * a.b      => 3 => 01 'A' 01 'B' 00 => 5
     * a.b.     => 4 => 01 'A' 01 'B' 00 => 5
     * 
     */

    u8 *label_start = name_parm;
    u8 *p = &name_parm[1];
    
    u8 c;

    /*
     * I cannot check this in one go actually.
     *
     * It would work 99.9999999% of the time but if the string is "" and is at the end of a page it would overlap to a non-mapped
     * memory and crash.
     *
     */
    
    if(text_len == 0)
    {
        return DOMAINNAME_INVALID;
    }
    
    if(text[0] == '.')
    {
        if(text_len == 1)
        {
            *name_parm = 0;
            return 1;
        }
        else
        {
            return DOMAINNAME_INVALID;
        }
    }

    if(text[0] != '*')
    {
        // ensure the length is acceptable
        
        u32 output_len = text_len + 1;
        
        if(text[text_len - 1] != '.')
        {
            output_len += 1;
        }
        
        if(output_len > MAX_DOMAIN_LENGTH)
        {
            return DOMAIN_TOO_LONG;
        }
    }
    else
    {
        if(text_len == 1)      // '*'
        {
            name_parm[0] = 1;
            name_parm[1] = '*';
            name_parm[2] = '\0';
            return 3;
        }
        else if(text[1] == '.')  //  '*.????' note: at this point str_len is 2 or more
        {
            // ensure the length is acceptable
            
            u32 output_len = text_len + 1;
        
            if(text[text_len - 1] != '.')
            {
                output_len += 1;
            }

            if(output_len > MAX_DOMAIN_LENGTH)
            {
                return DOMAIN_TOO_LONG;
            }
            
            name_parm[0] = 1;
            name_parm[1] = '*';
            
            if(text_len == 2)   
            {
                name_parm[2] = '\0';
                return 3;
            }
            
            text += 2;
            label_start += 2;
            p += 2;
        }
        else                    // '*????'
        {
            return DOMAINNAME_INVALID;
        }
    }
    
    const char * const text_limit = &text[text_len];

    for(c = *text++; ; c = *text++)
    {
        /* test if a switch/case is better (break mix issues for this switch in this particular loop)
         *
         * in theory this is test/jb/jz
         * a switch would be jmp [v]
         *
         */
        
        if(cstr_to_dnsname_map_nostar[c] >= 0)          // (c != '.') && (c != '\0')
        {
            if(cstr_to_dnsname_map_nostar[c] == 0)
            {
                return INVALID_CHARSET;
            }

            *p++ = LOCASE(c);
            
            if(text == text_limit)
            {
                // close the label
                
                u8 label_length = p - label_start - 1;      // size of the label
            
                if(label_length > MAX_LABEL_LENGTH)
                {
                    return LABEL_TOO_LONG;
                }
                
                *label_start = label_length;
                
                // close the fqdn
                
                *p++ = 0;
                
                return p - name_parm;
            }
        }
        else    // reached '.' or end of cstr (which should not occur in this algorithm)
        {
            u8 label_length = p - label_start - 1;      // size of the label
            /*
            if(label_length == 0)                       // .. case
            {
                if(c != '\0')
                {
                    return DOMAINNAME_INVALID;
                }

                break;
            }
            */
            if(label_length > MAX_LABEL_LENGTH)
            {
                return LABEL_TOO_LONG;
            }
            
            *label_start = label_length;
            
            if(text == text_limit)
            {
                *p++ = '\0';
                return p - name_parm;
            }
            
            label_start = p;
            p++;
        }
    }
}

ya_result
cstr_to_dnsname_with_check_len_with_origin(u8* name_parm, const char* text, u32 text_len, const u8 *origin)
{
    /*
     * .        => 1 => 00 => 1
     * 
     * a        => 1 => 01 'A' 00 => 3
     * a.b      => 3 => 01 'A' 01 'B' 00 => 5
     * a.b.     => 4 => 01 'A' 01 'B' 00 => 5
     * 
     */

    u8 *label_start = name_parm;
    u8 *p = &name_parm[1];
    
    u8 c;

    /*
     * I cannot check this in one go actually.
     *
     * It would work 99.9999999% of the time but if the string is "" and is at the end of a page it would overlap to a non-mapped
     * memory and crash.
     *
     */
    
    if(text_len == 0)
    {
        return DOMAINNAME_INVALID;
    }
    
    if(text[0] == '.')
    {
        if(text_len == 1)
        {
            *name_parm = 0;
            return 1;
        }
        else
        {
            return DOMAINNAME_INVALID;
        }
    }

    if(text[0] != '*')
    {
        // ensure the length is acceptable
        
        u32 output_len = text_len + 1;
        
        if(text[text_len - 1] != '.')
        {
            output_len += 1;
        }
        
        if(output_len > MAX_DOMAIN_LENGTH)
        {
            return DOMAIN_TOO_LONG;
        }
    }
    else
    {
        if(text_len == 1)      // '*'
        {
            name_parm[0] = 1;
            name_parm[1] = '*';

            ya_result return_value = dnsname_copy(&name_parm[2], origin) + 2;
            
            return return_value;
        }
        else if(text[1] == '.')  //  '*.????' note: at this point str_len is 2 or more
        {
            // ensure the length is acceptable
            
            u32 output_len = text_len + 1;
        
            if(text[text_len - 1] != '.')
            {
                output_len += 1;
            }

            if(output_len > MAX_DOMAIN_LENGTH)
            {
                return DOMAIN_TOO_LONG;
            }
            
            name_parm[0] = 1;
            name_parm[1] = '*';
            
            if(text_len == 2)   
            {
                name_parm[2] = '\0';
                return 3;
            }
            
            text += 2;
            label_start += 2;
            p += 2;
        }
        else                    // '*????'
        {
            return DOMAINNAME_INVALID;
        }
    }
    
    const char * const text_limit = &text[text_len];

    for(c = *text++; ; c = *text++)
    {
        /* test if a switch/case is better (break mix issues for this switch in this particular loop)
         *
         * in theory this is test/jb/jz
         * a switch would be jmp [v]
         *
         */
        
        if(cstr_to_dnsname_map_nostar[c] >= 0)          // (c != '.') && (c != '\0')
        {
            if(cstr_to_dnsname_map_nostar[c] == 0)
            {
                return INVALID_CHARSET;
            }

            *p++ = c;
            
            if(text == text_limit)
            {
                // close the label
                
                u8 label_length = p - label_start - 1;      // size of the label
            
                if(label_length > MAX_LABEL_LENGTH)
                {
                    return LABEL_TOO_LONG;
                }
                
                *label_start = label_length;
                
                // close the fqdn
                
                ya_result return_value = dnsname_copy(p, origin) + p - name_parm;
            
                return return_value;
            }
        }
        else    // reached '.' or end of cstr (which should not occur in this algorithm)
        {
            u8 label_length = p - label_start - 1;      // size of the label

            if(label_length > MAX_LABEL_LENGTH)
            {
                return LABEL_TOO_LONG;
            }
            
            *label_start = label_length;
            
            if(text == text_limit)
            {
                *p++ = '\0';
                return p - name_parm;
            }
            
            label_start = p;
            p++;
        }
    }
}

ya_result
cstr_to_locase_dnsname_with_check_len_with_origin(u8* name_parm, const char* text, u32 text_len, const u8 *origin)
{
    /*
     * .        => 1 => 00 => 1
     * 
     * a        => 1 => 01 'A' 00 => 3
     * a.b      => 3 => 01 'A' 01 'B' 00 => 5
     * a.b.     => 4 => 01 'A' 01 'B' 00 => 5
     * 
     */

    u8 *label_start = name_parm;
    u8 *p = &name_parm[1];
    
    u8 c;

    /*
     * I cannot check this in one go actually.
     *
     * It would work 99.9999999% of the time but if the string is "" and is at the end of a page it would overlap to a non-mapped
     * memory and crash.
     *
     */
    
    if(text_len == 0)
    {
        return DOMAINNAME_INVALID;
    }
    
    if(text[0] == '.')
    {
        if(text_len == 1)
        {
            *name_parm = 0;
            return 1;
        }
        else
        {
            return DOMAINNAME_INVALID;
        }
    }

    if(text[0] != '*')
    {
        // ensure the length is acceptable
        
        u32 output_len = text_len + 1;
        
        if(text[text_len - 1] != '.')
        {
            output_len += 1;
        }
        
        if(output_len > MAX_DOMAIN_LENGTH)
        {
            return DOMAIN_TOO_LONG;
        }
    }
    else
    {
        if(text_len == 1)      // '*'
        {
            name_parm[0] = 1;
            name_parm[1] = '*';

            //ya_result return_value = dnsname_copy(&name_parm[2], origin) + 2;
            ya_result return_value = dnsname_canonize(origin, &name_parm[2]) + 2;
            
            return return_value;
        }
        else if(text[1] == '.')  //  '*.????' note: at this point str_len is 2 or more
        {
            // ensure the length is acceptable
            
            u32 output_len = text_len + 1;
        
            if(text[text_len - 1] != '.')
            {
                output_len += 1;
            }

            if(output_len > MAX_DOMAIN_LENGTH)
            {
                return DOMAIN_TOO_LONG;
            }
            
            name_parm[0] = 1;
            name_parm[1] = '*';
            
            if(text_len == 2)   
            {
                name_parm[2] = '\0';
                return 3;
            }
            
            text += 2;
            label_start += 2;
            text_len -= 2;
            p += 2;
        }
        else                    // '*????'
        {
            return DOMAINNAME_INVALID;
        }
    }
    
    const char * const text_limit = &text[text_len];

    for(c = *text++; ; c = *text++)
    {
        /* test if a switch/case is better (break mix issues for this switch in this particular loop)
         *
         * in theory this is test/jb/jz
         * a switch would be jmp [v]
         *
         */
        
        if(cstr_to_dnsname_map_nostar[c] >= 0)          // (c != '.') && (c != '\0')
        {
            if(cstr_to_dnsname_map_nostar[c] == 0)
            {
                return INVALID_CHARSET;
            }

            *p++ = LOCASE(c);
            
            if(text == text_limit)
            {
                // close the label
                
                u8 label_length = p - label_start - 1;      // size of the label
            
                if(label_length > MAX_LABEL_LENGTH)
                {
                    return LABEL_TOO_LONG;
                }
                
                *label_start = label_length;
                
                // close the fqdn
                
                ya_result return_value = dnsname_copy(p, origin) + p - name_parm;
            
                return return_value;
            }
        }
        else    // reached '.' or end of cstr (which should not occur in this algorithm)
        {
            u8 label_length = p - label_start - 1;      // size of the label

            if(label_length > MAX_LABEL_LENGTH)
            {
                return LABEL_TOO_LONG;
            }
            
            *label_start = label_length;
            
            if(text == text_limit)
            {
                if(label_length > 0)
                {
                    *p++ = '\0';
                }
                return p - name_parm;
            }
            
            label_start = p;
            p++;
        }
    }
}

/**
 *  @brief Converts a C string to a dns rname and checks for validity
 *
 *  Converts a C string to a dns rname.
 *
 *  @param[in] name_parm a pointer to a buffer that will get the full dns name
 *  @param[in] str a pointer to the source c-string
 *
 *  @return the length of the string up to the last '\0'
 */

ya_result
cstr_to_dnsrname_with_check(u8* name_parm, const char* str)
{
    u8 * const limit = &name_parm[MAX_DOMAIN_LENGTH];
    u8 *s = name_parm;
    u8 *p = &name_parm[1];

    u8 c;

    bool escaped = FALSE;

    /*
     * I cannot check this in one go actually.
     *
     * It would work 99.9999999% of the time but if the string is "" and is at the end of a page it would overlap to a non-mapped
     * memory and crash.
     *
     */

    for(c = *str++;; c = *str++)
    { /* test if a switch/case is better (break mix issues for this switch in this particular loop)
	 *
	 * in theory this is test/jb/jz
	 * a switch would be jmp [v]
	 * mmhh ...
	 *
	 */
        if((cstr_to_dnsrname_map[c] >= 0)  /*(c != '.') && (c != '\0')*/ || escaped)
        {
            if(!escaped)
            {            
                if(cstr_to_dnsrname_map[c] == 0)
                {
                    return INVALID_CHARSET;
                }

                /* escape character */
                /* AFAIK there is only one escape : '\', so why use an indexed memory to test it ?  if (cstr_to_dnsrname_map[c] == 2) */
                if(c == '\\')
                {  
                    escaped = TRUE;
                    /* reading the next char here is wrong is the record is corrupt and ends with my-wrong-rname\. */
                    continue;
                }
            }

            *p = c;
            escaped = FALSE;
        }
        else
        {
            u8 l = p - s - 1;
            *s = l;

            s = p;

            if(l == 0)
            {
                if(c != '\0')
                {
                    return DOMAINNAME_INVALID;
                }

                break;
            }

            if(l > MAX_LABEL_LENGTH)
            {
                return LABEL_TOO_LONG;
            }

            if(c == '\0')
            {
                if(p >= limit)
                {
                    return DOMAIN_TOO_LONG;
                }

                *s++ = '\0';
                break;
            }
        }

        if(++p > limit)
        {
            return DOMAIN_TOO_LONG;
        }
    }
    
    if(escaped)
    {
        return DOMAINNAME_INVALID;
    }

    return s - name_parm;
}

/* ONE use */

ya_result
cstr_get_dnsname_len(const char* str)
{
    ya_result total = 0;
    const char* start;

    if(*str == '.')
    {
        str++;
    }

    s32 label_len;

    do
    {
        char c;

        start = str;

        do
        {
            c = *str++;
        }
        while(c != '.' && c != '\0');

        label_len = (str - start) - 1;

        if(label_len > MAX_LABEL_LENGTH)
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
    }
    while(label_len != 0);

    return total;
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

u32
dnsname_to_cstr(char* dest_cstr, const u8* name)
{
#if DEBUG
    yassert(name != NULL);
#endif
    
    char* start = dest_cstr;

    u8 len;

    len = *name++;

    if(len != 0)
    {
        do
        {
            MEMCOPY(dest_cstr, name, len);
            dest_cstr += len;
            *dest_cstr++ = '.';
            name += len;
            len = *name++;
        }
        while(len != 0);
    }
    else
    {
        *dest_cstr++ = '.';
    }

    *dest_cstr = '\0';

    return (u32)(dest_cstr - start);
}

/** @brief Tests if two DNS labels are equals
 *
 *  Tests if two DNS labels are equals
 *
 *  @param[in] name_a a pointer to a dnsname to compare
 *  @param[in] name_b a pointer to a dnsname to compare
 *
 *  @return Returns TRUE if names are equal, else FALSE.
 */

/* ELEVEN uses */

#if !DNSCORE_HAS_MEMALIGN_ISSUES

bool
dnslabel_equals(const u8* name_a, const u8* name_b)
{
    u8 len = *name_a;

    if(len != *name_b)
    {
        return FALSE;
    }

    len++;

    /* Hopefully the compiler just does register renaming */

    const u32* name_a_32 = (const u32*)name_a;
    const u32* name_b_32 = (const u32*)name_b;
    int idx;
    int len4 = len & ~3;
    for(idx = 0; idx < len4; idx += 4)
    {
        if(GET_U32_AT(name_a[idx]) != GET_U32_AT(name_b[idx]))
        {
            return FALSE;
        }
    }

    /* Hopefully the compiler just does register renaming */

    name_a = (const u8*)name_a_32;
    name_b = (const u8*)name_b_32;

    switch(len & 3)
    {
        case 0:
            return TRUE;
        case 1:
            return name_a[idx] == name_b[idx];
        case 2:
            return GET_U16_AT(name_a[idx]) == GET_U16_AT(name_b[idx]);
        case 3:
            return (GET_U16_AT(name_a[idx]) == GET_U16_AT(name_b[idx])) && (name_a[idx+2] == name_b[idx+2]);
    }

    // icc complains here but is wrong.
    // this line cannot EVER be reached
    
    assert(FALSE); /* NOT zassert */
    
    return FALSE;
}

#else

bool
dnslabel_equals(const u8* name_a, const u8* name_b)
{
    u8 len = *name_a;

    if(*name_b == len)
    {
        return memcmp(name_a + 1, name_b + 1, len) == 0;
    }

    return FALSE;
}

#endif

/** @brief Tests if two DNS labels are (case-insensitive) equals
 *
 *  Tests if two DNS labels are (case-insensitive) equals
 *
 *  @param[in] name_a a pointer to a dnsname to compare
 *  @param[in] name_b a pointer to a dnsname to compare
 *
 *  @return Returns TRUE if names are equal, else FALSE.
 */

#if !DNSCORE_HAS_MEMALIGN_ISSUES

bool
dnslabel_equals_ignorecase_left1(const u8* name_a, const u8* name_b)
{
    int len = (int)* name_a;

    if(len != (int)* name_b)
    {
        return FALSE;
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
            return FALSE;
        }
    }

    /* Hopefully the compiler just does register renaming */

    switch(len & 3)
    {
        case 0:
            return TRUE;
        case 1:
            return LOCASEEQUALS(name_a[idx], name_b[idx]); /* can be used because left is locase */
        case 2:
            return LOCASEEQUALSBY2(&name_a[idx], &name_b[idx]); /* can be used because left is locase */
        case 3:
            return LOCASEEQUALSBY3(&name_a[idx], &name_b[idx]); /* can be used because left is locase */
    }

    assert(FALSE); /* NOT zassert */
    
    return FALSE;
}

bool
dnslabel_equals_ignorecase_left2(const u8* name_a, const u8* name_b)
{
    int len = (int)* name_a;

    if(len != (int)* name_b)
    {
        return FALSE;
    }

    for(int i = 1; i < len; ++i)
    {
        //if(__LOCASE_TABLE__[name_a[i]] != __LOCASE_TABLE__[name_b[i]])
        if(name_a[i] != __LOCASE_TABLE__[name_b[i]])
        {
            return FALSE;
        }
    }

    return TRUE;
}

bool
dnslabel_equals_ignorecase_left3(const u8* name_a, const u8* name_b)
{
    int len = (int)* name_a;

    if(len != (int)* name_b)
    {
        return FALSE;
    }

    for(name_a++, name_b++; len > 4; len -= 4, name_a += 4, name_b += 4)
    {
        //if(__LOCASE_TABLE__[name_a[i]] != __LOCASE_TABLE__[name_b[i]])
        u32 w = GET_U32_AT_P(name_a);
        u32 x = GET_U32_AT_P(name_b);

        if((w & 0xff) != __LOCASE_TABLE__[x & 0xff])
        {
            return FALSE;
        }

        w >>= 8;
        x >>= 8;

        if((w & 0xff) != __LOCASE_TABLE__[x & 0xff])
        {
            return FALSE;
        }

        w >>= 8;
        x >>= 8;

        if((w & 0xff) != __LOCASE_TABLE__[x & 0xff])
        {
            return FALSE;
        }

        w >>= 8;
        x >>= 8;

        if((w) != __LOCASE_TABLE__[x])
        {
            return FALSE;
        }
    }

    for(int i = 0; i < len; ++i)
    {
        //if(__LOCASE_TABLE__[name_a[i]] != __LOCASE_TABLE__[name_b[i]])
        if(name_a[i] != __LOCASE_TABLE__[name_b[i]])
        {
            return FALSE;
        }
    }

    return TRUE;
}

bool
dnslabel_equals_ignorecase_left4(const u8* name_a, const u8* name_b)
{
    int len = (int)* name_a;

    if(len != (int)* name_b)
    {
        return FALSE;
    }

    for(name_a++, name_b++; len > 4; len -= 4, name_a += 4, name_b += 4)
    {
        //if(__LOCASE_TABLE__[name_a[i]] != __LOCASE_TABLE__[name_b[i]])
        u32 w = GET_U32_AT_P(name_a);
        u32 x = GET_U32_AT_P(name_b);

        u32 z = (u32)__LOCASE_TABLE__[x & 0xff] |
                ((u32)__LOCASE_TABLE__[(x >> 8) & 0xff] << 8) |
                ((u32)__LOCASE_TABLE__[(x >> 16) & 0xff] << 16) |
                ((u32)__LOCASE_TABLE__[(x >> 24) & 0xff] << 24);

        if(w != z)
        {
            return FALSE;
        }
    }

    for(int i = 0; i < len; ++i)
    {
        //if(__LOCASE_TABLE__[name_a[i]] != __LOCASE_TABLE__[name_b[i]])
        if(name_a[i] != __LOCASE_TABLE__[name_b[i]])
        {
            return FALSE;
        }
    }

    return TRUE;
}

bool
dnslabel_equals_ignorecase_left5(const u8* name_a, const u8* name_b)
{
    return strcasecmp((const char*)name_a, (const char*)name_b) == 0;
}

#else

/**
 * This WILL work with label size too since a label size is 0->63
 * which is well outside the [A-Za-z] space.
 */

bool
dnslabel_equals_ignorecase_left(const u8* name_a, const u8* name_b)
{
    return strcasecmp((const char*)name_a, (const char*)name_b) == 0;
}

#endif

/** @brief Tests if two DNS names are equals
 *
 *  Tests if two DNS labels are equals
 *
 *  @param[in] name_a a pointer to a dnsname to compare
 *  @param[in] name_b a pointer to a dnsname to compare
 *
 *  @return Returns TRUE if names are equal, else FALSE.
 */

/* TWO uses */

bool
dnsname_equals(const u8* name_a, const u8* name_b)
{
    int la = dnsname_len(name_a);
    int lb = dnsname_len(name_b);

    if(la == lb)
    {
        return memcmp(name_a, name_b, la) == 0;
    }

    return FALSE;
}

/*
 * Comparison of a name by label
 */

int
dnsname_compare(const u8* name_a, const u8* name_b)
{
    for(;;)
    {
        s8 la = (s8)name_a[0];
        s8 lb = (s8)name_b[0];
        
        name_a++;
        name_b++;
        
        if(la == lb)
        {   
            if( la > 0)
            {
                int c =  memcmp(name_a, name_b, la);

                if( c != 0)
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
            int c =  memcmp(name_a, name_b, MIN(la,lb));
            
            if( c == 0)
            {
                c = la - lb;
            }
            
            return c;
        }
        
        name_a += la;
        name_b += lb;
    }
}

bool
dnsname_is_subdomain(const u8* subdomain, const u8* domain)
{
#if !HAS_FULL_ASCII7
    u32 len = dnsname_len(domain);
    u32 sub_len = dnsname_len(subdomain);
    
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
    dnsname_stack subdomain_stack;
    dnsname_stack domain_stack;
    s32 subdomain_top = dnsname_to_dnsname_stack(subdomain, &subdomain_stack);
    s32 domain_top = dnsname_to_dnsname_stack(domain, &domain_stack);

    if(subdomain_top >= domain_top)
    {
        for(int i = 0; i <= domain_top; ++i)
        {
            const u8 *sublabel = subdomain_stack.labels[i];
            const u8 *label = domain_stack.labels[i];

            if(!dnslabel_equals(sublabel, label))
            {
                return FALSE;
            }
        }

        return TRUE;
    }
#endif
    
    return FALSE;
}

/** @brief Tests if two DNS names are (ignore case) equals
 *
 *  Tests if two DNS labels are (ignore case) equals
 *
 *  @param[in] name_a a pointer to a LO-CASE dnsname to compare
 *  @param[in] name_b a pointer to a dnsname to compare
 *
 *  @return Returns TRUE if names are equal, else FALSE.
 */

/* TWO uses */

bool
dnsname_equals_ignorecase1(const u8* name_a, const u8* name_b)
{
    int len;

    do
    {
        len = (int)*name_a++;

        if(len != (int)*name_b++)
        {
            return FALSE;
        }

        if(len == 0)
        {
            return TRUE;
        }

        while(len > 4 && (LOCASEEQUALSBY4(name_a++,name_b++)))
        {
            len--;
        }
        
        while(len > 0 && (LOCASEEQUALS(*name_a++,*name_b++)))
        {
            len--;
        }
    }
    while(len == 0);

    return FALSE;
}

bool
dnsname_equals_ignorecase2(const u8* name_a, const u8* name_b)
{
    int len;

    for(int i = 0;; ++i)
    {
        len = (int)name_a[i];

        if(len != (int)name_b[i])
        {
            return FALSE;
        }

        if(len == 0)
        {
            return TRUE;
        }

        len += i;

        for(; i < len; ++i)
        {
            if(__LOCASE_TABLE__[name_a[i]] != __LOCASE_TABLE__[name_b[i]])
            {
                return FALSE;
            }
        }
    }
}

bool
dnsname_equals_ignorecase3(const u8* name_a, const u8* name_b)
{
    int len_a = dnsname_len(name_a);
    int len_b = dnsname_len(name_b);
    return ((len_a == len_b) && (strncasecmp((const char*)name_a, (const char*)name_b, len_a) == 0));
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

u32
dnsname_len(const u8 *name)
{
    yassert(name != NULL);
    
    const u8 *start = name;

    u8 c;

    while((c = *name++) > 0)
    {
        name += c;
    }

    return name - start;
}

s32
dnsname_len_with_limit(const u8 *name, const u8 *name_limit)
{
    yassert(name != NULL);
    
    const u8 *start = name;

    u8 c;

    for(;;)
    {
        if(name >= name_limit)
        {
            return DOMAINNAME_INVALID;
        }
        
        c = *name;
        
        name += c;
        
        if(c == 0)
        {
            break;
        }
        
        ++name;
    }

    return name - start;
}

/* ONE use */

u32
dnsname_getdepth(const u8 *name)
{
    yassert(name != NULL);
    
    u32 d = 0;

    u8 c;

    while((c = *name) > 0)
    {
        name += c + 1;
        d++;
    }

    return d;
}

u8*
dnsname_dup(const u8* src)
{
    u8 *dst;
    u32 len = dnsname_len(src);
    MALLOC_OR_DIE(u8*, dst, len, DNSNAMED_TAG);
    MEMCOPY(dst, src, len);

    return dst;
}

void
dnsname_free(u8* ptr)
{
#if DEBUG
    u32 len = dnsname_len(ptr);
    memset(ptr, 0xfe, len);
#endif
    free(ptr);
}

/* ONE use */

u32
dnsname_copy(u8* dst, const u8* src)
{
    u32 len = dnsname_len(src);

    MEMCOPY(dst, src, len);

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

u32
dnsname_canonize(const u8* src, u8* dst)
{
    const u8* org = src;

    u32 len;

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

    return (u32)(src - org);
}

/*****************************************************************************
 *
 * VECTOR
 *
 *****************************************************************************/

/* NO use (test) */

u32
dnslabel_vector_to_dnsname(const_dnslabel_vector_reference name, s32 top, u8* str_start)
{
    u8* str = str_start;

    const_dnslabel_vector_reference limit = &name[top];

    while(name <= limit)
    {
        const u8* label = *name++;
        u8 len = label[0] + 1;
        MEMCOPY(str, label, len);
        str += len;
    }

    *str++ = 0;

    return str - str_start;
}

/* NO use (test) */

u32
dnslabel_vector_to_cstr(const_dnslabel_vector_reference name, s32 top, char* str)
{
    const_dnslabel_vector_reference limit = &name[top];

    char* start = str;

    while(name < limit)
    {
        const u8* label = *name++;
        u8 len = *label++;

        MEMCOPY(str, label, len);
        str += len;

        *str++ = '.';
    }

    *str++ = '\0';

    return (u32)(str - start);
}

/* ONE use */

u32
dnslabel_vector_dnslabel_to_dnsname(const u8 *prefix, const dnsname_vector *namestack, s32 bottom, u8 *str)
{
    u8* start = str;

    u32 len = *prefix;
    MEMCOPY(str, prefix, len + 1);
    str += len + 1;

    const_dnslabel_vector_reference name = &namestack->labels[bottom];
    u32 top = (u32)namestack->size;

    while(bottom <= (s32)top)
    {
        const u8* label = *name++;
        u32 len = *label;

        MEMCOPY(str, label, len + 1);
        str += len + 1;

        bottom--;
    }

    *str++ = '\0';

    return (u32)(str - start);
}

u32
dnslabel_vector_len(const_dnslabel_vector_reference name, s32 top)
{
    u32 ret = 1;
    
    for(s32 i = 0; i <= top; i++)
    {
        ret += name[i][0];
    }
    
    return ret;
}

/* ONE use */

u32
dnsname_vector_sub_to_dnsname(const dnsname_vector *name, s32 from, u8 *name_start)
{
    u8* str = name_start;

    const_dnslabel_vector_reference limit = &name->labels[name->size];
    const_dnslabel_vector_reference labelp = &name->labels[from];

    while(labelp <= limit)
    {
        u32 len = *labelp[0] + 1;
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

s32
dnsname_to_dnslabel_vector(const u8 *dns_name, dnslabel_vector_reference labels)
{
    yassert(dns_name != NULL && labels != NULL);
    
    s32 idx = -1;
    int offset = 0;

    for(;;)
    {
        u32 len = dns_name[offset];

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

s32
dnsname_to_dnsname_vector(const u8* dns_name, dnsname_vector* name)
{
    yassert(dns_name != NULL && name != NULL);
    
    s32 size = dnsname_to_dnslabel_vector(dns_name, name->labels);
    name->size = size;

    return size;
}

u32 dnsname_vector_copy(dnsname_vector* dst, const dnsname_vector* src)
{
    dst->size = src->size;
    if(dst->size > 0)
    {
        memcpy(&dst->labels[0], &src->labels[0], sizeof(u8*) * dst->size);
    }
    return dst->size;
}

u32
dnsname_vector_len(dnsname_vector *name_vector)
{
    u32 len = 1;

    for(s32 size = 0; size <= name_vector->size; size++)
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

u32
dnslabel_stack_to_cstr(const_dnslabel_stack_reference name, s32 top, char* str)
{
    char* start = str;
    if(top >= 0)
    {
        do
        {
            const u8* label = name[top];
            u8 len = *label++;

            MEMCOPY(str, label, len);
            str += len;

            *str++ = '.';
            top--;
        }
        while(top >= 0);
    }
    else
    {
        *str++ = '.';
    }
    *str++ = '\0';

    return (u32)(str - start);
}

/* ONE use */

u32
dnslabel_stack_to_dnsname(const_dnslabel_stack_reference name, s32 top, u8* str_start)
{

    u8* str = str_start;
    const_dnslabel_stack_reference base = name;

    name += top;

    while(name >= base)
    {
        const u8* label = *name--;
        u32 len = *label;

        MEMCOPY(str, label, len + 1);
        str += len + 1;
    }

    *str++ = '\0';

    return (u32)(str - str_start);
}

s32
dnsname_to_dnslabel_stack(const u8* dns_name, dnslabel_stack_reference labels)
{
    s32 label_pointers_top = -1;
    const u8 * label_pointers[MAX_LABEL_COUNT];

    for(;;)
    {
        u8 len = *dns_name;

        if(len == 0)
        {
            break;
        }

        label_pointers[++label_pointers_top] = dns_name;

        dns_name += len + 1;
    }

    s32 size = label_pointers_top;

    const u8** labelp = labels;
    while(label_pointers_top >= 0)
    {
        *labelp++ = (u8*)label_pointers[label_pointers_top--];
    }

    return size;
}

/* ONE use */

u32
dnsname_stack_to_dnsname(const dnsname_stack *name_stack, u8 *name_start)
{
    u8* name = name_start;

    for(s32 size = name_stack->size; size >= 0; size--)
    {
        u32 len = name_stack->labels[size][0] + 1;
        MEMCOPY(name, name_stack->labels[size], len);
        name += len;
    }

    *name++ = '\0';

    return name - name_start;
}

u32
dnsname_stack_len(const dnsname_stack* name_stack)
{
    u32 len = 1;

    for(s32 size = 0; size <= name_stack->size; size++)
    {
        len += name_stack->labels[size][0] + 1;
    }

    return len;
}

/* TWO uses (debug) */

u32
dnsname_stack_to_cstr(const dnsname_stack* name, char* str)
{
    return dnslabel_stack_to_cstr(name->labels, name->size, str);
}

/* ONE use */

bool
dnsname_equals_dnsname_stack(const u8* str, const dnsname_stack* name)
{
    s32 size = name->size;

    while(size >= 0)
    {
        const u8* label = name->labels[size];
        u8 len = *label;

        if(len != *str)
        {
            return FALSE;
        }

        label++;
        str++;

        if(memcmp(str, label, len) != 0)
        {
            return FALSE;
        }

        str += len;

        size--;
    }

    return *str == 0;
}

bool
dnsname_under_dnsname_stack(const u8* str, const dnsname_stack* name)
{
    s32 size = name->size;

    while(size >= 0)
    {
        const u8* label = name->labels[size];
        u8 len = *label;

        if(len != *str)
        {
            return (len != 0);
        }

        label++;
        str++;

        if(memcmp(str, label, len) != 0)
        {
            return FALSE;
        }

        str += len;

        size--;
    }

    return *str == 0;
}

/* FOUR uses */

s32
dnsname_stack_push_label(dnsname_stack* dns_name, const u8* dns_label)
{
    yassert(dns_name != NULL && dns_label != NULL);
   
    dns_name->labels[++dns_name->size] = dns_label;

    return dns_name->size;
}

/* FOUR uses */

s32
dnsname_stack_pop_label(dnsname_stack* name)
{
    yassert(name != NULL);
    
#if DEBUG
    name->labels[name->size] = (u8*)~0;
#endif

    return name->size--;
}

s32
dnsname_to_dnsname_stack(const u8* dns_name, dnsname_stack* name)
{
    s32 label_pointers_top = -1;
    u8 * label_pointers[MAX_LABEL_COUNT];

    for(;;)
    {
        u8 len = *dns_name;

        if(len == 0)
        {
            break;
        }

        label_pointers[++label_pointers_top] = (u8*)dns_name;

        dns_name += len + 1;
    }

    name->size = label_pointers_top;

    const u8** labelp = name->labels;
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

u8*
dnsname_zdup(const u8* name)
{
    yassert(name != NULL);

    u32 len = dnsname_len(name);

    u8* dup;

    ZALLOC_OBJECT_ARRAY_OR_DIE(dup, u8, len, ZDB_NAME_TAG);
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

u8*
dnsname_zdup_from_name(const char* domainname)
{
    yassert(domainname != NULL);

    u32 len = cstr_get_dnsname_len(domainname);
    ya_result ret;
    u8* dup;

    ZALLOC_OBJECT_ARRAY_OR_DIE(dup, u8, len, ZDB_NAME_TAG);
    if(ISOK(ret = cstr_to_dnsname_with_check(dup, domainname)))
    {
    }
    else
    {
        ZFREE_ARRAY(dup, len);
        dup = NULL;
    }
    
    return dup;
}

void
dnsname_zfree(u8 *name)
{
    ZFREE_ARRAY(name, dnsname_len(name));
}

/** @brief Allocates and duplicates a label with ZALLOC.
 *
 *  Allocates and duplicates a label with ZALLOC.
 *
 *  @param[in] name a pointer to the label
 *
 *  @return A new instance of the label
 */

u8*
dnslabel_zdup(const u8* name)
{
    yassert(name != NULL);

    u32 len = name[0] + 1;

    u8* dup;
    ZALLOC_OBJECT_ARRAY_OR_DIE(dup, u8, len, ZDB_LABEL_TAG);
    MEMCOPY(dup, name, len);

    return dup;
}

void
dnslabel_zfree(u8 *name)
{
    u32 len = name[0] + 1;
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

const u8*
dnsname_expand_compressed(const void *wire_base_, size_t wire_size, const void *compressed_fqdn, u8 *output_fqdn, u32 output_fqdn_size)
{
    const u8 *base = (const u8*)wire_base_;
    const u8 *p_limit = &base[wire_size];

    yassert(output_fqdn_size >= MAX_DOMAIN_LENGTH);

    u8 *buffer = output_fqdn;
    u8 * const buffer_limit = &buffer[output_fqdn_size];  // pointer to the byte that must never be reached
    const u8 *p = (const u8*)compressed_fqdn;
    const u8 *ret_ptr;

    if((p < base) || (p >= p_limit))
    {
        return NULL; /* EOF */
    }

    for(;;)
    {
        u8 len = *p++;  // get the next byte (length)

        if((len & 0xc0) == 0xc0)    // test if it's a compressed code
        {
            ret_ptr = p + 1;

            /* reposition the pointer */
            u32 new_offset = len & 0x3f;
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

        u8 *label_limit = &buffer[len];
        do
        {
            *buffer++ = tolower(*p++);
        }
        while(buffer < label_limit);
    }

    for(;;)
    {
        u8 len = *p;

        if((len & 0xc0) == 0xc0) /* EDF: better yet: cmp len, 192; jge  */
        {
            /* reposition the pointer */
            u32 new_offset = len & 0x3f;
            new_offset <<= 8;
            new_offset |= p[1];

            const u8* q = &base[new_offset];
            
            if(q < p)
            {
                p = q;
                continue;
            }
            
            return NULL;
        }

        if((p + len >= p_limit) || (buffer + len + 1>= buffer_limit))
        {
            return NULL;
        }

        *buffer++ = len;

        if(len == 0)
        {
            return ret_ptr;
        }
        
        ++p;

        u8 *label_limit = &buffer[len];
        do
        {
            *buffer++ = tolower(*p++);
        }
        while(buffer < label_limit);
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

const u8*
dnsname_skip_compressed(const void *wire_base_, size_t wire_size, const void *compressed_fqdn)
{
    const u8 *base = (const u8*)wire_base_;
    
    const u8 *p_limit = &base[wire_size];

    const u8 *p = (const u8*)compressed_fqdn;

    if((p < base) || (p >= p_limit))
    {
        return NULL; /* EOF */
    }

    for(;;)
    {
        u8 len = *p++;

        if((len & 0xc0) == 0xc0)
        {
            return p + 1;   // yes, read the purpose of the function
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
