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
#pragma once

#include <dnscore/sys_types.h>
#include <dnscore/rfc.h>

#if DNSCORE_HAS_FULL_ASCII7
#include <ctype.h>
#endif

/**
 * The maximum number of domains-subdomains handled by the database.
 * This should not be set to a value greater than 128 (128 covers (\001 'a') * 255 )
 *
 * Recommended value: 128
 *
 */

#define SRV_UNDERSCORE_SUPPORT 1

#define DNSNAME_SECTIONS_MAX   ((DOMAIN_LENGTH_MAX + 1) / 2)

#if !DNSNAME_C_
extern const uint8_t __LOCASE_TABLE__[256];
#endif

// dns equal chars comparison should give 0x00 or 0x20
// the '_' breaks this so there is a slightly different (slightly slower) way to handle it

// IMPORTANT NOTE 1 : MACROS ARE WRITTEN TO USE THEIR PARAMETERS EXACTLY ONCE

// IMPORTANT NOTE 2 : LOCASEEQUAL only works on the DNS chars AND with the first parameter being a lo-case string (like
// in the database)

#if !DNSCORE_HAS_FULL_ASCII7

#define dnsname_equals_ignorecase       dnsname_equals_ignorecase3
#define dnslabel_equals_ignorecase_left dnslabel_equals_ignorecase_left1

#if !SRV_UNDERSCORE_SUPPORT
#define LOCASE(c__) ((char)(c__) | (char)0x20)

static inline bool LOCASEEQUALS(char ca__, char cb__) { return ((((char)(ca__) - (char)(cb__)) & 0xdf) == 0); }

static inline bool LOCASEEQUALSBY2(const uint8_t *name_a, const uint8_t *name_b) { return (((GET_U16_AT(name_a[0]) - GET_U16_AT(name_b[0])) & ((uint16_t)0xdfdf)) == 0); }

static inline bool LOCASEEQUALSBY3(const uint8_t *name_a, const uint8_t *name_b) { return LOCASEEQUALSBY2(name_a, name_b) && LOCASEEQUALS(name_a[2], name_b[2]); }

static inline bool LOCASEEQUALSBY4(const uint8_t *name_a, const uint8_t *name_b) { return (((GET_U32_AT(name_a[0]) - GET_U32_AT(name_b[0])) & ((uint16_t)0xdfdfdfdf)) == 0); }
#else // slightly modified to take '_' into account

#define LOCASE(c__) (((((char)(c__) + (char)0x01) | (char)0x20)) - (char)0x01)

static inline bool LOCASEEQUALS(uint8_t a, uint8_t b) { return ((((uint8_t)(a + 0x01) - (uint8_t)(b + 0x01)) & 0xdf) == 0); }

static inline bool LOCASEEQUALSBY2(const uint8_t *name_a, const uint8_t *name_b) { return ((((GET_U16_AT(name_a[0]) + 0x0101) - (GET_U16_AT(name_b[0]) + 0x0101)) & ((uint16_t)0xdfdf)) == 0); }

static inline bool LOCASEEQUALSBY3(const uint8_t *name_a, const uint8_t *name_b) { return LOCASEEQUALSBY2(name_a, name_b) && LOCASEEQUALS(name_a[2], name_b[2]); }

static inline bool LOCASEEQUALSBY4(const uint8_t *name_a, const uint8_t *name_b) { return ((((GET_U32_AT(name_a[0]) + 0x01010101) - (GET_U32_AT(name_b[0]) + 0x01010101)) & ((uint32_t)0xdfdfdfdf)) == 0); }
#endif

#else // DNSCORE_HAS_FULL_ASCII7

#define dnsname_equals_ignorecase       dnsname_equals_ignorecase3
#define dnslabel_equals_ignorecase_left dnslabel_equals_ignorecase_left4

#define LOCASE(c__)                     __LOCASE_TABLE__[(c__)]

static inline bool LOCASEEQUALS(uint8_t a, uint8_t b) { return LOCASE(a) == LOCASE(b); }

static inline bool LOCASEEQUALSBY2(const uint8_t *name_a, const uint8_t *name_b) { return LOCASEEQUALS(name_a[0], name_b[0]) && LOCASEEQUALS(name_a[1], name_b[1]); }

static inline bool LOCASEEQUALSBY3(const uint8_t *name_a, const uint8_t *name_b) { return LOCASEEQUALSBY2(name_a, name_b) && LOCASEEQUALS(name_a[2], name_b[2]); }

static inline bool LOCASEEQUALSBY4(const uint8_t *name_a, const uint8_t *name_b) { return LOCASEEQUALSBY3(name_a, name_b) && LOCASEEQUALS(name_a[3], name_b[3]); }

#endif

#define ZDB_NAME_TAG  0x454d414e42445a /* "ZDBNAME" */
#define ZDB_LABEL_TAG 0x4c424c42445a   /* "ZDBLBL" */

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * A dnslabel_array is basically a dnslabel*[]
 * There are two kind of arrays :
 *
 * dnslabel_stack:
 *
 * [0000] "."	    label
 * [0001] "tdl"	    label
 * [0002] "domain"  label <- top
 *
 * dnslabel_vector:
 *
 * [0000] "domain"  label
 * [0001] "tdl"	    label
 * [0002] "."	    label <- top
 *
 */

/*
 * The plan was to typedef an array into a stack or a vector.
 * But in order to help the compiler complaining about mixing both,
 * I have to define them separatly
 *
 */

typedef const uint8_t *dnslabel_stack_t[DNSNAME_SECTIONS_MAX];

/* This + 1 is just to make sure both are different to the compiler's eyes */

typedef const uint8_t        *dnslabel_vector_t[DNSNAME_SECTIONS_MAX + 1];

typedef const uint8_t       **dnslabel_stack_reference_t;
typedef const uint8_t       **dnslabel_vector_reference_t;

typedef const uint8_t *const *const_dnslabel_stack_reference_t;
typedef const uint8_t *const *const_dnslabel_vector_reference_t;

#if DEBUG
#define DEBUG_RESET_dnsname(name) memset(&(name), 0x5b, sizeof(dnsname_stack_t))
#else
#define DEBUG_RESET_dnsname(name)
#endif

struct dnsname_stack_s
{
    int32_t          size;
    dnslabel_stack_t labels;
};

typedef struct dnsname_stack_s dnsname_stack_t;

struct dnsname_vector_s
{
    int32_t           size;
    dnslabel_vector_t labels;
};

typedef struct dnsname_vector_s dnsname_vector_t;

/**
 *  Converts a C string to a DNS name.
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source c-string
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_with_cstr(uint8_t *name_parm, const char *str);
// backward compatibility
static inline ya_result cstr_to_dnsname(uint8_t *name_parm, const char *str) { return dnsname_init_with_cstr(name_parm, str); }

/**
 *  Converts a C string to a lower-case DNS name.
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source c-string
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_with_cstr_locase(uint8_t *name_parm, const char *str);
// backward compatibility
static inline ya_result cstr_to_locase_dnsname(uint8_t *name_parm, const char *str) { return dnsname_init_with_cstr_locase(name_parm, str); }

/**
 *  Converts a text buffer to a DNS name.
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source buffer
 *  @param str_len the length of the source buffer
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_with_charp(uint8_t *name_parm, const char *str, uint32_t str_len);
// backward compatibility
static inline ya_result charp_to_dnsname(uint8_t *name_parm, const char *str, uint32_t str_len) { return dnsname_init_with_charp(name_parm, str, str_len); }

/**
 *  Converts a text buffer to a lower-case DNS name.
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source buffer
 *  @param str_len the length of the source buffer
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_with_charp_locase(uint8_t *name_parm, const char *str, uint32_t str_len);
// backward compatibility
static inline ya_result charp_to_locase_dnsname(uint8_t *name_parm, const char *str, uint32_t str_len) { return dnsname_init_with_charp_locase(name_parm, str, str_len); }

/**
 *  Converts a text buffer to a lower-case dns name and checks for charset validity.
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source buffer
 *  @param str_len the length of the source buffer
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsname_init_check_with_charp_locase(uint8_t *name_parm, const char *str, uint32_t str_len);
// backward compatibility
static inline ya_result charp_to_locase_dnsname_with_check(uint8_t *name_parm, const char *str, uint32_t str_len) { return dnsname_init_check_with_charp_locase(name_parm, str, str_len); }

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

ya_result dnsname_init_check_star_with_cstr(uint8_t *name_parm, const char *str);
// backward compatibility
static inline ya_result cstr_to_dnsname_with_check(uint8_t *name_parm, const char *str) { return dnsname_init_check_star_with_cstr(name_parm, str); }

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

ya_result dnsname_init_check_star_with_charp(uint8_t *name_parm, const char *str, uint32_t str_len);

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

ya_result dnsname_init_check_nostar_with_charp(uint8_t *name_parm, const char *str, uint32_t str_len);
// backward compatibility
static inline ya_result cstr_to_dnsname_with_check_len(uint8_t *name_parm, const char *text, uint32_t text_len) { return dnsname_init_check_nostar_with_charp(name_parm, text, text_len); }

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

ya_result dnsname_init_check_nostar_with_charp_locase(uint8_t *name_parm, const char *str, uint32_t str_len);

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

ya_result dnsname_init_check_star_with_charp_and_origin(uint8_t *name_parm, const char *str, uint32_t str_len, const uint8_t *origin);
// backward compatibility
// static inline ya_result cstr_to_dnsname_with_check_len_with_origin(uint8_t* name_parm, const char* text, uint32_t
// text_len, const uint8_t *origin) { return cstr_to_dnsname_with_check_len(name_parm, text, text_len, origin); }

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

ya_result dnsname_init_check_star_with_charp_and_origin_locase(uint8_t *name_parm, const char *str, uint32_t str_len, const uint8_t *origin);
// backward compatibility
// static inline ya_result cstr_to_locase_dnsname_with_check_len_with_origin(uint8_t* name_parm, const char* text,
// uint32_t text_len, const uint8_t *origin) { return cstr_to_dnsname_with_check_len(name_parm, text, text_len, origin);
// }

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

ya_result dnsrname_init_check_with_charp(uint8_t *name_parm, const char *str, uint32_t str_len);

/**
 *  Converts a C string to a dns RNAME and checks for validity
 *  Handles escape codes
 *
 *  @param name_parm a pointer to a buffer that will get the full dns name
 *  @param str a pointer to the source c-string
 *
 *  @return Returns the length of the FQDN
 */

ya_result dnsrname_init_check_with_cstr(uint8_t *name_parm, const char *str);
// backward compatibility
static inline ya_result cstr_to_dnsrname_with_check(uint8_t *name_parm, const char *str) { return dnsrname_init_check_with_cstr(name_parm, str); }

/**
 * Gets the DNS name length of a C string if it was converted.
 */

ya_result cstr_get_dnsname_len(const char *str);

/** @brief Converts a dns name to a C string
 *
 *  Converts a dns name to a C string
 *
 *  @param name a pointer to the source dns name
 *  @param str a pointer to a buffer that will get the c-string
 *
 *  @return Returns the length of the string
 */

/* SIX uses */

uint32_t cstr_init_with_dnsname(char *str, const uint8_t *name);

/** @brief Tests if two DNS labels are equals
 *
 *  Tests if two DNS labels are equals
 *
 *  @param name_a a pointer to a dnsname to compare
 *  @param name_b a pointer to a dnsname to compare
 *
 *  @return Returns true if names are equal, else false.
 */

/* ELEVEN uses */

bool dnslabel_equals(const uint8_t *name_a, const uint8_t *name_b);

int  dnsname_compare(const uint8_t *name_a, const uint8_t *name_b);

bool dnsname_is_subdomain(const uint8_t *subdomain, const uint8_t *domain);

/** @brief Tests if two DNS labels are (case-insensitive) equals
 *
 *  Tests if two DNS labels are (case-insensitive) equals
 *
 *  @param name_a a pointer to a lo-case dnsname to compare
 *  @param name_b a pointer to a any-case dnsname to compare
 *
 *  @return Returns true if names are equal, else false.
 */

bool dnslabel_equals_ignorecase_left1(const uint8_t *name_a, const uint8_t *name_b);

#if DNSCORE_HAS_EXPERIMENTAL
bool dnslabel_equals_ignorecase_left2(const uint8_t *name_a, const uint8_t *name_b);

bool dnslabel_equals_ignorecase_left3(const uint8_t *name_a, const uint8_t *name_b);
#endif
bool dnslabel_equals_ignorecase_left4(const uint8_t *name_a, const uint8_t *name_b);
#if DNSCORE_HAS_EXPERIMENTAL
bool dnslabel_equals_ignorecase_left5(const uint8_t *name_a, const uint8_t *name_b);
#endif

/** @brief Tests if two DNS names are equals
 *
 *  Tests if two DNS labels are equals
 *
 *  @param name_a a pointer to a dnsname to compare
 *  @param name_b a pointer to a dnsname to compare
 *
 *  @return Returns true if names are equal, else false.
 */

/* TWO uses */

bool dnsname_equals(const uint8_t *name_a, const uint8_t *name_b);

/** @brief Tests if two DNS names are (ignore case) equals
 *
 *  Tests if two DNS labels are (ignore case) equals
 *
 *  @param name_a a pointer to a dnsname to compare
 *  @param name_b a pointer to a dnsname to compare
 *
 *  @return Returns true if names are equal, else false.
 */

/* TWO uses */

#if DNSCORE_HAS_EXPERIMENTAL
bool dnsname_equals_ignorecase1(const uint8_t *name_a, const uint8_t *name_b);

bool dnsname_equals_ignorecase2(const uint8_t *name_a, const uint8_t *name_b);
#endif

bool dnsname_equals_ignorecase3(const uint8_t *name_a, const uint8_t *name_b);

/** @brief Returns the full length of a dns name
 *
 *  Returns the full length of a dns name
 *
 *  @param name a pointer to the dnsname
 *
 *  @return The length of the dnsname, "." ( zero ) included
 */

/* SEVENTEEN uses (more or less) */

uint32_t  dnsname_len(const uint8_t *name);

int32_t   dnsname_len_with_size(const uint8_t *name, size_t name_buffer_size);
int32_t   dnsname_len_checked_with_size(const uint8_t *name, size_t name_buffer_size);

ya_result dnsname_len_checked(const uint8_t *name);

/* ONE use */

uint32_t dnsname_getdepth(const uint8_t *name);

/* ONE use */

uint32_t  dnsname_copy(uint8_t *dst, const uint8_t *src);

ya_result dnsname_copy_checked(uint8_t *dst, const uint8_t *src);

/* malloc & copies a dnsname */

uint8_t *dnsname_dup(const uint8_t *src);

void     dnsname_free(uint8_t *ptr);

/** @brief Canonizes a dns name.
 *
 *  Canonizes a dns name. (Lo-case)
 *
 *  @param src a pointer to the dns name
 *  @param[out] dst a pointer to a buffer that will hold the canonized dns name
 *
 *  @return The length of the dns name
 */

/* TWELVE uses */

uint32_t dnsname_canonize(const uint8_t *src, uint8_t *dst);

/**
 * char DNS charset test
 *
 * @param c
 * @return true iff c in in the DNS charset
 *
 */

bool               dnsname_is_charspace(uint8_t c);

static inline bool dnsname_is_wildcard(const uint8_t *fqdn) { return (fqdn[0] == 1) && (fqdn[1] == '*'); }

int32_t            dnslabel_compare(const uint8_t *a, const uint8_t *b);

/**
 * label DNS charset test
 *
 * @param label
 * @return true iff each char in the label in in the DNS charset
 *
 */

bool dnslabel_verify_charspace(const uint8_t *label);

/**
 * dns name DNS charset test
 *
 * @param name_wire
 * @return true if each char in the name is in the DNS charset
 *
 */

bool dnsname_verify_charspace(const uint8_t *name_wire);

/**
 * label DNS charset test and set to lower case
 *
 * @param label
 * @return true iff each char in the label in in the DNS charset
 *
 */

bool dnslabel_locase_verify_charspace(uint8_t *label);

/**
 * dns name DNS charset test and set to lower case
 *
 * LOCASE is done using |32
 *
 * @param name_wire
 * @return true iff each char in the name in in the DNS charset
 *
 */

bool dnsname_locase_verify_charspace(uint8_t *name_wire);

/**
 * char DNS rchar charset test
 *
 * @param c
 * @return true iff c in in the DNS rchar charset
 *
 */

bool dnsname_is_rname_charspace(uint8_t c);

/**
 * dns name RNAME charset test
 *
 * @param name_wire
 * @return true if each char in the name is in the DNS charset
 *
 */

bool dnsname_verify_rname_charspace(const uint8_t *name_wire);

/*****************************************************************************
 *
 * VECTOR
 *
 *****************************************************************************/

/**
 * Converts a vector of DNS labels into a domain name C string
 * note: top is the last offset in the vector, not its length
 *
 * @param name an array of pointers to DNS labels
 * @param top the last valid index of the array
 * @param str_start a buffer that will contain the domain name C string
 * @return strlen(domain name)
 */

uint32_t dnslabel_vector_to_cstr(const_dnslabel_vector_reference_t name, int32_t top, char *str);

/**
 * Converts a vector of DNS labels into a DNS name
 * note: top is the last offset in the vector, not its length
 *
 * @param name an array of pointers to DNS labels
 * @param top the last valid index of the array
 * @param str_start a buffer that will contain the DNS name
 * @return the size of the DNS name
 */

uint32_t               dnslabel_vector_to_dnsname(const_dnslabel_vector_reference_t name, int32_t top, uint8_t *str_start);

static inline uint32_t dnslabel_copy(uint8_t *target, const uint8_t *src)
{
    uint32_t len = src[0] + 1;
    memcpy(target, src, len);
    return len;
}

/**
 * Computes the DNS name length of a vector of DNS labels
 * note: top is the last offset in the vector, not its length
 *
 * @param name an array of pointers to DNS labels
 * @param top the last valid index of the array
 * @return the length of the DNS name
 */

uint32_t dnslabel_vector_len(const_dnslabel_vector_reference_t name, int32_t top);

/* ONE use */

uint32_t dnsname_vector_sub_to_dnsname(const dnsname_vector_t *name, int32_t from, uint8_t *name_start);

/** @brief Divides a name into sections
 *
 *  Divides a name into sections.
 *  Writes a pointer to each label of the dnsname into an array
 *  "." is never put in there.
 *
 *  @param name a pointer to the dnsname
 *  @param[out] sections a pointer to the target array of pointers
 *
 *  @return The index of the top-level label ("." is never put in there)
 */

/* TWO uses */

int32_t dnsname_to_dnslabel_vector(const uint8_t *dns_name, dnslabel_vector_reference_t labels);

int32_t dnsname_to_dnslabel_stack(const uint8_t *dns_name, dnslabel_stack_reference_t labels);

/** @brief Divides a name into sections
 *
 *  Divides a name into sections.
 *  Writes a pointer to each label of the dnsname into an array
 *  "." is never put in there.
 *
 *  @param name a pointer to the dnsname
 *  @param[out] sections a pointer to the target array of pointers
 *
 *  @return The index of the top-level label ("." is never put in there)
 */

/* TWENTY-ONE uses */

int32_t  dnsname_to_dnsname_vector(const uint8_t *dns_name, dnsname_vector_t *name);

uint32_t dnsname_vector_copy(dnsname_vector_t *dst, const dnsname_vector_t *src);

uint32_t dnsname_vector_len(const dnsname_vector_t *name_vector);

/*****************************************************************************
 *
 * STACK
 *
 *****************************************************************************/

/** @brief Converts a stack of dns labels to a C string
 *
 *  Converts a stack of dns labels to a C string
 *
 *  @param name a pointer to the dnslabel stack
 *  @param top the index of the top of the stack
 *  @param str a pointer to a buffer that will get the c-string
 *
 *  @return Returns the length of the string
 *
 *  @note The value returned should be checked to see if it's expected to be strlen(str) or strlen(str)+1
 */

/* ONE use */

uint32_t dnslabel_stack_to_cstr(const const_dnslabel_stack_reference_t name, int32_t top, char *str);

/* ONE use */

uint32_t dnslabel_stack_to_dnsname(const const_dnslabel_stack_reference_t name, int32_t top, uint8_t *str_start);

/* ONE use */

uint32_t dnsname_stack_to_dnsname(const dnsname_stack_t *name_stack, uint8_t *name_start);

/* ONE use, returns the fqdn len */

uint32_t              dnsname_stack_len(const dnsname_stack_t *name_stack);

static inline int32_t dnsname_stack_depth(const dnsname_stack_t *name_stack) { return name_stack->size + 1; }

/* TWO uses (debug) */

uint32_t dnsname_stack_to_cstr(const dnsname_stack_t *name, char *str);

/* ONE use */

bool dnsname_equals_dnsname_stack(const uint8_t *str, const dnsname_stack_t *name);

bool dnsname_under_dnsname_stack(const uint8_t *str, const dnsname_stack_t *name);

/* FOUR uses */

int32_t dnsname_stack_push_label(dnsname_stack_t *dns_name, const uint8_t *dns_label);

/* FOUR uses */

int32_t dnsname_stack_pop_label(dnsname_stack_t *name);

/**
 * The label that would be popped.
 */

const uint8_t *dnsname_stack_peek_label(dnsname_stack_t *name);

int32_t        dnsname_to_dnsname_stack(const uint8_t *dns_name, dnsname_stack_t *name);

/** @brief Allocates and duplicates a name with ZALLOC.
 *
 *  Allocates and duplicates a name ZALLOC.
 *
 *  @param name a pointer to the dnsname
 *
 *  @return A new instance of the dnsname.
 */

uint8_t *dnsname_zdup(const uint8_t *name);

/** @brief Converts a name to a newly allocated dns name with ZALLOC.
 *
 *  Converts a name to a newly allocated dns name with ZALLOC.
 *
 *  @param domainname a pointer to the name
 *
 *  @return a new instance of the name converted to a dnsname
 */

uint8_t *dnsname_zdup_from_name(const char *domainname);

void     dnsname_zfree(uint8_t *name);

/** @brief Allocates and duplicates a label with ZALLOC.
 *
 *  Allocates and duplicates a label with ZALLOC.
 *
 *  @param name a pointer to the label
 *
 *  @return A new instance of the label
 */

uint8_t *dnslabel_zdup(const uint8_t *name);

void     dnslabel_zfree(uint8_t *name);

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

const uint8_t *dnsname_expand_compressed(const void *wire_base_, size_t wire_size, const void *compressed_fqdn, uint8_t *output_fqdn, uint32_t output_fqdn_size);

/**
 *
 * Skip a compressed FQDN from a wire.
 *
 * @param wire_base_ the address of the wire buffer
 * @param wire_size the size of the wire buffer
 * @param compressed_fqdn the address, in the wire buffer, of the FQDN to expand
 *
 * @return a pointer to the next byte after the FQDN (ie: points to a type) or NULL if an error occurred
 */

const uint8_t *dnsname_skip_compressed(const void *wire_base_, size_t wire_size, const void *compressed_fqdn);

#ifdef __cplusplus
}
#endif

/** @} */
