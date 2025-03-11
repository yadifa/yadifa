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
 * @defgroup systemtypes Definition of types in order to ensure architecture-independence
 * @ingroup dnscore
 * @brief Definition of types in order to ensure architecture-independence
 *
 * @{
 *----------------------------------------------------------------------------*/

#ifndef _SYSTYPES_H
#define _SYSTYPES_H

#include <dnscore/dnscore_config_features.h>

#ifdef __cplusplus
#error "C++ compiler mode not supported"
#endif

#if !DEBUG
#ifndef NDEBUG
#define NDEBUG 1
#endif
#endif

#include <stdlib.h>

#include <string.h>
#include <stdint.h>
#include <inttypes.h> // for SCN* macros
#include <stdbool.h>
#include <unistd.h>
#include <stddef.h>
#include <stdatomic.h>

#ifdef _MSC_VER
#include <malloc.h>
#define C11_VLA_AVAILABLE   0

// VS wants to use _malloca instead which allocates on the heap if size > _ALLOCA_S_THRESHOLD (1024)
// I'd rather have a bigger stack
// It needs to be a macro

#define stack_alloc(size__) _alloca((size__))

#else
#define C11_VLA_AVAILABLE 1
#endif

#ifdef WIN32
#define __windows__ 1
#else
#define __unix__ 1
#endif

#ifndef __has_c_attribute      // Optional of course.
#define __has_c_attribute(x) 0 // Compatibility with non-clang compilers.
#endif
#if __has_c_attribute(fallthrough) || (defined(__GNUC__) && (__GNUC__ >= 7)) || (defined(__clang__) && (__clang_major__ >= 10))
// __attribute__ ((fallthrough));   // C and C++03
// [[fallthrough]];                 // C++17 and above
#define FALLTHROUGH __attribute__((fallthrough));
#else
#define FALLTHROUGH
#endif

#if defined __FreeBSD__
#include <sys/endian.h>

#ifndef __BYTE_ORDER
#if defined(_BYTE_ORDER)
#define __BIG_ENDIAN    _BIG_ENDIAN
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#define __BYTE_ORDER    _BYTE_ORDER
#elif defined(WORDS_BIGENDIAN)
#define __BIG_ENDIAN    4321
#define __LITTLE_ENDIAN 1234
#define __BYTE_ORDER    __BIG_ENDIAN
#else
#error "endianness detection code will most likely fail"
#endif
#endif

#include <sys/types.h>
#define bswap_16 bswap16
#define bswap_32 bswap32
#define bswap_64 bswap64

#elif defined __APPLE__
#include <machine/endian.h>
#ifndef __unix__
#define __unix__ 1
#endif
#include <libkern/OSByteOrder.h>
#define bswap_16(x) OSSwapInt16(x)
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)
#ifndef __BYTE_ORDER
#if defined(BYTE_ORDER)
#define __BIG_ENDIAN    BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __BYTE_ORDER    BYTE_ORDER
#elif defined(WORDS_BIGENDIAN)
#define __BIG_ENDIAN    4321
#define __LITTLE_ENDIAN 1234
#define __BYTE_ORDER    __BIG_ENDIAN
#else
#error "endianness detection code will most likely fail"
#endif
#endif
#elif defined __sun
#include <sys/byteorder.h>
#ifndef __BYTE_ORDER
#if defined(__BYTE_ORDER__)
#define __BIG_ENDIAN    __ORDER_BIG_ENDIAN__
#define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define __BYTE_ORDER    __BYTE_ORDER__
#else
// assume big endian
#define __BIG_ENDIAN    4321
#define __LITTLE_ENDIAN 1234
#define __BYTE_ORDER    __BIG_ENDIAN
#endif
#endif
#elif defined __OpenBSD__ || defined __NetBSD__
#include <endian.h>
#ifndef __BYTE_ORDER
#if defined(BYTE_ORDER)
#define __BIG_ENDIAN    BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#define __BYTE_ORDER    BYTE_ORDER
#else
// assume big endian
#define __BIG_ENDIAN    4321
#define __LITTLE_ENDIAN 1234
#define __BYTE_ORDER    __BIG_ENDIAN
#endif
#endif

#define bswap_16 swap16
#define bswap_32 swap32
#define bswap_64 swap64

#elif __windows__
#define WIN32_LEAN_AND_MEAN
#define WINVER       0x0600
#define _WIN32_WINNT 0x0600

#include <Windows.h>
#include <BaseTsd.h>
#include <windef.h>

#pragma warning(disable : 4068) // unknown pragma
#pragma warning(disable : 4133) // incompatible types
#pragma warning(disable : 4146) // unary minus operator applied to unsigned type, result still unsigned
#pragma warning(disable : 4244) // conversion from 'X' to 'Y', possible loss of data
#pragma warning(disable : 4267) // 'function': conversion from 'X' to 'Y', possible loss of data
#pragma warning(disable : 4996) // This function or variable may be unsafe. Consider using ...
#pragma warning(error : 4013)   // 'X' undefined; assuming extern returning int
#pragma warning(error : 4047)   // 'function': 'X' differs in levels of indirection from 'Y'
#pragma warning(error : 4645)   // function declared with 'noreturn' has a return statement
#pragma warning(error : 4646)   // function declared with 'noreturn' has non-void return type
#pragma warning(error : 4715)   // not all control paths return a value

#define bswap_16        _byteswap_ushort
#define bswap_32        _byteswap_ulong
#define bswap_64        _byteswap_uint64

#define __BIG_ENDIAN    4321
#define __LITTLE_ENDIAN 1234
#if REG_DWORD == REG_DWORD_LITTLE_ENDIAN
#define __BYTE_ORDER    __LITTLE_ENDIAN
#define WORDS_BIGENDIAN 0
#else
#define __BYTE_ORDER    __BIG_ENDIAN
#define WORDS_BIGENDIAN 1
#endif
// #include <minwindef.h>
// #include <minwinbase.h>
#undef inline
#define inline
// typedef int uid_t;
// typedef int gid_t;
// typedef HANDLE pid_t;

char                *strtok_r(char *str, const char *delim, char **saveptr);

typedef unsigned int mode_t;

#define restrict

#define S_ISREG(mode__) ((mode__ & _S_IFREG) != 0)
#define S_ISLNK(mode__) (0)
#define S_ISDIR(mode__) ((mode__ & _S_IFDIR) != 0)

#else
#include <endian.h>
#include <byteswap.h>
#endif

#define VERSION_2_0_0 0x020000000000LL
#define VERSION_2_1_0 0x020100000000LL
#define VERSION_2_2_0 0x020200000000LL
#define VERSION_2_3_0 0x020300000000LL
#define VERSION_2_4_0 0x020400000000LL
#define VERSION_2_4_1 0x020400100000LL
#define VERSION_2_4_2 0x020400200000LL
#define VERSION_2_5_0 0x020500000000LL
#define VERSION_2_5_1 0x020500100000LL
#define VERSION_2_5_2 0x020500200000LL
#define VERSION_2_5_3 0x020500300000LL
#define VERSION_2_6_0 0x020600000000LL
#define VERSION_2_6_1 0x020600100000LL
#define VERSION_2_6_2 0x020600200000LL
#define VERSION_2_6_3 0x020600300000LL
#define VERSION_2_6_4 0x020600400000LL
#define VERSION_2_6_5 0x020600500000LL
#define VERSION_3_0_0 0x030000000000LL
#define VERSION_3_0_1 0x030001000000LL

#include <dnscore/dnscore_config_features.h>
#include <dnscore/sys_error.h>

#include <sys/types.h> /** @note must be used for u_char on Mac OS X */

#ifdef __cplusplus
extern "C"
{
#endif

#define SIZEOF_TIMEVAL 16

#ifndef HAS_DYNAMIC_PROVISIONING
#define HAS_DYNAMIC_PROVISIONING 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if defined(__bool_true_false_are_defined) && __bool_true_false_are_defined != 0

#ifndef TRUE
#define TRUE true
#endif

#ifndef FALSE
#define FALSE false
#endif

#else

typedef int bool;

#ifndef TRUE
#define TRUE (0 == 0)
#endif

#ifndef FALSE
#define FALSE (0 == 1)
#endif

#endif

#define UNSIGNED_TYPE_VALUE_MAX(__type__)  ((__type__)~0)
#define SIGNED_TYPE_VALUE_MAX(__type__)    (((__type__)~0) >> 1)
#define SIGNED_TYPE_VALUE_MIN(__type__)    (((__type__)~0) - (((__type__)~0) >> 1))

#define UNSIGNED_VAR_VALUE_MAX(__var__)    ((~0ULL) >> ((sizeof(~0ULL) - sizeof(__var__)) * 8LL))
#define SIGNED_VAR_VALUE_MAX(__var__)      (UNSIGNED_VAR_VALUE_MAX(__var__) >> 1)
#define SIGNED_VAR_VALUE_MIN(__var__)      (UNSIGNED_VAR_VALUE_MAX(__var__) - SIGNED_VAR_VALUE_MAX(__var__))

#define UNSIGNED_VAR_VALUE_IS_MAX(__var__) (__var__ == UNSIGNED_VAR_VALUE_MAX(__var__))
#define SIGNED_VAR_VALUE_IS_MAX(__var__)   (__var__ == SIGNED_VAR_VALUE_MAX(__var__))

/* This is the basic type definition set                        */
/* Tweaks will be added for each setup (using the preprocessor) */

#if OBSOLETE
typedef unsigned char  u8; // <- likely to be a problem in future versions of C
typedef signed char    s8;
typedef unsigned short u16;
typedef short          s16;
typedef unsigned int   u32;
typedef int            s32;
#endif

#if defined(HAVE_UINT64_T) && defined(HAVE_INT64_T)
typedef uint64_t      u64;
typedef int64_t       s64;
typedef atomic_ullong atomic_uint64_t;
#elif defined(HAVE_LONG_LONG)
typedef unsigned long long u64;
typedef signed long long   s64;
typedef atomic_ullong      atomic_uint64_t;
#elif defined(_LONGLONG) && (_LONGLONG == 1) // FreeBSD 9.1 gcc 4.2.1
typedef unsigned long long u64;
typedef signed long long   s64;
typedef atomic_ullong      atomic_uint64_t;
#elif defined(__SIZEOF_LONG_LONG__) && (__SIZEOF_LONG_LONG__ == 8)
typedef unsigned long long u64;
typedef atomic_ullong      atomic_uint64_t;
typedef signed long long   s64;
#elif defined(__LONG_LONG_MAX__) && (__LONG_LONG_MAX__ == 9223372036854775807LL)
typedef unsigned long long u64;
typedef signed long long   s64;
#elif defined(_LONGLONG_TYPE)
typedef unsigned long long u64;
typedef signed long long   s64;
#elif __windows__
typedef __int8                    s8;
typedef unsigned __int8           u8;
typedef __int16                   s16;
typedef unsigned __int16          u16;
typedef __int32                   s32;
typedef unsigned __int32          u32;
typedef __int64                   s64;
typedef unsigned __int64          u64;
typedef volatile unsigned __int64 atomic_uint64_t;
#else
#error NO UNSIGNED 64 BITS TYPE KNOWN ON THIS 64 BITS ARCHITECTURE (uint64_t + s64)
#endif

typedef void      callback_function_t(void *);
typedef ya_result result_callback_function_t(void *, void *);

/*
AIX : __64BIT__
HP: __LP64__
SUN: __sparcv9, _LP64
SGI: _MIPS_SZLONG==64
NT: _M_IA64
*/

#ifndef __SIZEOF_POINTER__
#if defined(__LP64__) || defined(__LP64) || defined(_LP64) || defined(__64BIT__) || defined(MIPS_SZLONG) || defined(_M_IA64) || defined(_WIN64)
#define __SIZEOF_POINTER__ 8
#else
#define __SIZEOF_POINTER__ 4
#endif
#endif

#if __SIZEOF_POINTER__ == 4

typedef unsigned int intptr; // an integer with the same size as a data pointer

typedef float        realptr; // a float with the same size as a data pointer

#elif __SIZEOF_POINTER__ == 8

#if defined(HAVE_UINT64_T)
typedef uint64_t intptr;
#elif defined(HAVE_LONG_LONG)
typedef unsigned long long intptr;
#elif defined(__LONG_LONG_MAX__) && (__LONG_LONG_MAX__ == 9223372036854775807LL)
typedef unsigned long long intptr;
#elif defined(__SIZEOF_LONG_LONG__) && (__SIZEOF_LONG_LONG__ == 8)
typedef unsigned long long intptr;
#elif defined(_LONGLONG) && (_LONGLONG == 1) // FreeBSD 9.1 gcc 4.2.1
typedef unsigned long long intptr;
#elif defined(_LONGLONG_TYPE)
typedef unsigned long long intptr;
#elif defined(_WIN64)
typedef uint64_t intptr;
#else
#error NO UNSIGNED 64 BITS TYPE KNOWN ON THIS 64 BITS ARCHITECTURE (intptr_t)
#endif

typedef double realptr; // a float with the same size as a data pointer

#else // __SIZEOF_POINTER not 4 nor 8
#error __SIZEOF_POINTER__ value not handled (only 4 and 8 are)
#endif

/**
 * This macro returns the first address aligned to 8 bytes from the parameter
 * addresss.
 *
 */

#define ALIGN8(__from_address__)      (((__from_address__) + 7) & ~7)

/**
 * This macro returns the first address aligned to 16 bytes from the parameter
 * addresss.
 *
 */

#define ALIGN16(__from_address__)     (((__from_address__) + 15) & ~15)

/*
 * Macros used to access bytes inside a buffer.
 *
 * ie: U32_AT(packet[8]), assuming that packet is a byte buffer, will access
 *     the 8th byte inside packet as a (native) unsigned 32bits integer.
 */

#define U8_AT(address__)              (*((uint8_t *)&(address__)))

#define GET_U8_AT(address__)          (*((uint8_t *)&(address__)))
#define SET_U8_AT(address__, value__) (*((uint8_t *)&(address__)) = (value__))

#ifndef WORDS_BIGENDIAN
#if __BYTE_ORDER == __BIG_ENDIAN
#define WORDS_BIGENDIAN 1
#endif
#else // WORDS_BIGENDIAN defined
#if WORDS_BIGENDIAN
#if __BYTE_ORDER == __LITTLE_ENDIAN
#error "confusing endianness"
#endif
#else
#if __BYTE_ORDER == __BIG_ENDIAN
#error "confusing endianness"
#endif
#endif
#endif

#define AVOID_ANTIALIASING 1

#ifndef DNSCORE_HAS_MEMALIGN_ISSUES
#error "DNSCORE_HAS_MEMALIGN_ISSUES is not defined.  Please ensure the relevant config.h is included at some level above."
#endif

#if !DNSCORE_HAS_MEMALIGN_ISSUES

#if AVOID_ANTIALIASING
static inline uint16_t GET_U16_AT_P(const void *address)
{
    const uint16_t *p = (const uint16_t *)address;
    return *p;
}
static inline void SET_U16_AT_P(void *address, uint16_t value)
{
    uint16_t *p = (uint16_t *)address;
    *p = value;
}
static inline uint32_t GET_U32_AT_P(const void *address)
{
    const uint32_t *p = (const uint32_t *)address;
    return *p;
}
static inline void SET_U32_AT_P(void *address, uint32_t value)
{
    uint32_t *p = (uint32_t *)address;
    *p = value;
}
static inline uint64_t GET_U64_AT_P(const void *address)
{
    const uint64_t *p = (const uint64_t *)address;
    return *p;
}
static inline void SET_U64_AT_P(void *address, uint64_t value)
{
    uint64_t *p = (uint64_t *)address;
    *p = value;
}

#define GET_U16_AT(address__)          GET_U16_AT_P(&(address__))
#define SET_U16_AT(address__, value__) SET_U16_AT_P(&(address__), (value__))
#define GET_U32_AT(address__)          GET_U32_AT_P(&(address__))
#define SET_U32_AT(address__, value__) SET_U32_AT_P(&(address__), (value__))
#define GET_U64_AT(address__)          GET_U64_AT_P(&(address__))
#define SET_U64_AT(address__, value__) SET_U64_AT_P(&(address__), (value__))
#else
#define GET_U16_AT(address)        (*((uint16_t *)&(address)))
#define SET_U16_AT(address, value) *((uint16_t *)&(address)) = (value)

#define GET_U32_AT(address)        (*((uint32_t *)&(address)))
#define SET_U32_AT(address, value) *((uint32_t *)&(address)) = (value)

#define GET_U64_AT(address)        (*((uint64_t *)&(address)))
#define SET_U64_AT(address, value) *((uint64_t *)&(address)) = (value)
#endif

#else /* sparc ... */

/*
 *  Why in caps ? Traditionnaly it was an helper macro.  Macros are in caps except when they hide a virtual call.
 *
 */

static inline uint16_t GET_U16_AT_P(const void *p)
{
    const uint8_t *p8 = (const uint8_t *)p;
    uint16_t       v;

#ifdef WORDS_BIGENDIAN
    v = p8[0];
    v <<= 8;
    v |= p8[1];
#else
    v = p8[1];
    v <<= 8;
    v |= p8[0];
#endif

    return v;
}

#define GET_U16_AT(x) GET_U16_AT_P(&(x))

static inline void SET_U16_AT_P(void *p, uint16_t v)
{
    uint8_t *p8 = (uint8_t *)p;

#ifdef WORDS_BIGENDIAN
    p8[0] = v >> 8;
    p8[1] = v;
#else
    p8[0] = v;
    p8[1] = v >> 8;
#endif
}

#define SET_U16_AT(x___, y___) SET_U16_AT_P(&(x___), (y___))

static inline uint32_t GET_U32_AT_P(const void *p)
{
    const uint8_t *p8 = (const uint8_t *)p;
    uint32_t       v;

#ifdef WORDS_BIGENDIAN
    v = p8[0];
    v <<= 8;
    v |= p8[1];
    v <<= 8;
    v |= p8[2];
    v <<= 8;
    v |= p8[3];
#else
    v = p8[3];
    v <<= 8;
    v |= p8[2];
    v <<= 8;
    v |= p8[1];
    v <<= 8;
    v |= p8[0];
#endif
    return v;
}

#define GET_U32_AT(x) GET_U32_AT_P(&(x))

static inline void SET_U32_AT_P(void *p, uint32_t v)
{
    uint8_t *p8 = (uint8_t *)p;

#ifdef WORDS_BIGENDIAN
    p8[0] = v >> 24;
    p8[1] = v >> 16;
    p8[2] = v >> 8;
    p8[3] = v;
#else
    p8[0] = v;
    p8[1] = v >> 8;
    p8[2] = v >> 16;
    p8[3] = v >> 24;
#endif
}

#define SET_U32_AT(x___, y___) SET_U32_AT_P(&(x___), (y___))

static inline uint64_t GET_U64_AT_P(const void *p)
{
    const uint8_t *p8 = (const uint8_t *)p;
    uint32_t       v;

#ifdef WORDS_BIGENDIAN
    v = p8[0];
    v <<= 8;
    v |= p8[1];
    v <<= 8;
    v |= p8[2];
    v <<= 8;
    v |= p8[3];
    v <<= 8;
    v |= p8[4];
    v <<= 8;
    v |= p8[5];
    v <<= 8;
    v |= p8[6];
    v <<= 8;
    v |= p8[7];
#else
    v = p8[7];
    v <<= 8;
    v |= p8[6];
    v <<= 8;
    v |= p8[5];
    v <<= 8;
    v |= p8[4];
    v <<= 8;
    v = p8[3];
    v <<= 8;
    v |= p8[2];
    v <<= 8;
    v |= p8[1];
    v <<= 8;
    v |= p8[0];
#endif
    return v;
}

#define GET_U64_AT(x) GET_U64_AT_P(&(x))

static inline void SET_U64_AT_P(void *p, uint64_t v)
{
    uint8_t *p8 = (uint8_t *)p;

#ifdef WORDS_BIGENDIAN
    p8[0] = v >> 56;
    p8[1] = v >> 48;
    p8[2] = v >> 40;
    p8[3] = v >> 32;
    p8[4] = v >> 24;
    p8[5] = v >> 16;
    p8[6] = v >> 8;
    p8[7] = v;
#else
    p8[0] = v;
    p8[1] = v >> 8;
    p8[2] = v >> 16;
    p8[3] = v >> 24;
    p8[4] = v >> 32;
    p8[5] = v >> 40;
    p8[6] = v >> 48;
    p8[7] = v >> 56;
#endif
}

#define SET_U64_AT(x___, y___) SET_U64_AT_P(&(x___), (y___))

#endif

#if __SIZEOF_POINTER__ == 4
#define SET_PTR_AT_P SET_U32_AT_P
#define SET_PTR_AT   SET_U32_AT
#define GET_PTR_AT_P GET_U32_AT_P
#define GET_PTR_AT   GET_U32_AT
#elif __SIZEOF_POINTER__ == 8
#define SET_PTR_AT_P SET_U64_AT_P
#define SET_PTR_AT   SET_U64_AT
#define GET_PTR_AT_P GET_U64_AT_P
#define GET_PTR_AT   GET_U64_AT
#else
#error "unsupported pointer size"
#endif

#define U8_MAX         ((uint8_t)0xff)
#define U16_MAX        ((uint16_t)0xffff)
#define U32_MAX        ((uint32_t)0xffffffffUL)
#define U64_MAX        ((uint64_t)0xffffffffffffffffULL)

#define S8_MAX         ((int8_t)0x7f)
#define S16_MAX        ((int16_t)0x7fff)
#define S32_MAX        ((int32_t)0x7fffffffL)
#define S64_MAX        ((int64_t)0x7fffffffffffffffLL)

#define S8_MIN         ((int8_t)0x80)
#define S16_MIN        ((int16_t)0x8000)
#define S32_MIN        ((int32_t)0x80000000L)
#define S64_MIN        ((int64_t)0x8000000000000000LL)

#define CLEARED_SOCKET (-1)

#ifdef __GNUC__
#define GCC_VERSION ((__GNUC__ * 10000) + (__GNUC_MINOR__ * 100) + __GNUC_PATCHLEVEL__)
#endif

#ifndef htobe64

#if defined __APPLE__
#define __bswap_16 _OSSwapInt16
#define __bswap_32 _OSSwapInt32
#define __bswap_64 _OSSwapInt64
#elif defined __sun && defined(__GNUC__)
#define __bswap_16 __builtin_bswap16
#define __bswap_32 __builtin_bswap32
#define __bswap_64 __builtin_bswap64
#endif

/* Conversion interfaces.  */

#if __BYTE_ORDER == __LITTLE_ENDIAN

#if __unix__
#define htobe16(x) __bswap_16(x)
#define htole16(x) (x)
#define be16toh(x) __bswap_16(x)
#define le16toh(x) (x)

#define htobe32(x) __bswap_32(x)
#define htole32(x) (x)
#define be32toh(x) __bswap_32(x)
#define le32toh(x) (x)

#define htobe64(x) __bswap_64(x)
#define htole64(x) (x)
#define be64toh(x) __bswap_64(x)
#define le64toh(x) (x)
#else
#define htobe16(x) _byteswap_ushort(x)
#define htole16(x) (x)
#define be16toh(x) _byteswap_ushort(x)
#define le16toh(x) (x)

#define htobe32(x) _byteswap_ulong(x)
#define htole32(x) (x)
#define be32toh(x) _byteswap_ulong(x)
#define le32toh(x) (x)

#define htobe64(x) _byteswap_uint64(x)
#define htole64(x) (x)
#define be64toh(x) _byteswap_uint64(x)
#define le64toh(x) (x)
#endif

#else
#define htobe16(x) (x)
#define htole16(x) __bswap_16(x)
#define be16toh(x) (x)
#define le16toh(x) __bswap_16(x)

#define htobe32(x) (x)
#define htole32(x) __bswap_32(x)
#define be32toh(x) (x)
#define le32toh(x) __bswap_32(x)

#define htobe64(x) (x)
#define htole64(x) __bswap_64(x)
#define be64toh(x) (x)
#define le64toh(x) __bswap_64(x)
#endif // __BYTE_ORDER
#endif // htobe64

/**/

/// Used for collection callback processing (list)
/// Their support by a collection is not guaranteed

/// @note PROCESS_THEN_STOP = PROCESS|STOP

#define COLLECTION_ITEM_SKIP              0
#define COLLECTION_ITEM_PROCESS           1
#define COLLECTION_ITEM_STOP              2
#define COLLECTION_ITEM_PROCESS_THEN_STOP (COLLECTION_ITEM_PROCESS | COLLECTION_ITEM_STOP)

/**/

typedef uint32_t process_flags_t;

#if WORDS_BIGENDIAN
#define NU16(value) ((uint16_t)(value))
#define NU32(value) ((uint32_t)(value))
#else
#define NU16(value) ((uint16_t)(((((uint16_t)(value)) >> 8) & 0xff) | (((uint16_t)(value)) << 8)))
#define NU32(value) ((uint32_t)(((((uint32_t)(value)) >> 24) & 0xff) | ((((uint32_t)(value)) >> 8) & 0xff00) | ((((uint32_t)(value)) << 8) & 0xff0000) | (((uint32_t)(value)) << 24)))
#endif

#define VERSION_U32(h__, l__)      (((h__) << 16) | (l__))
#define VERSION_U16(h__, l__)      (((h__) << 8) | (l__))
#define VERSION_U8(h__, l__)       (((h__) << 4) | (l__))

#define NETWORK_ONE_16             NU16(0x0001)
#define IS_WILD_LABEL(u8dnslabel_) (GET_U16_AT(*(u8dnslabel_)) == NU16(0x012a)) /* 01 2a = 1 '*' */

/* sys_types.h is included everywhere.  This ensure the debug hooks will be too. */

#define TMPBUFFR_TAG               0x5246465542504d54

#if !DEBUG
#define MALLOC_OR_DIE(cast, target, size, tag)                                                                                                                                                                                                 \
    if(((target) = (cast)malloc(size)) == NULL)                                                                                                                                                                                                \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        exit(EXIT_CODE_OUTOFMEMORY_ERROR);                                                                                                                                                                                                     \
    }
#define MALLOC_OBJECT_OR_DIE(target__, object__, tag__)                                                                                                                                                                                        \
    if(((target__) = (object__ *)malloc(sizeof(object__))) == NULL)                                                                                                                                                                            \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        exit(EXIT_CODE_OUTOFMEMORY_ERROR);                                                                                                                                                                                                     \
    }
#define MALLOC_OBJECT_ARRAY_OR_DIE(target__, object__, count__, tag__)                                                                                                                                                                         \
    if(((target__) = (object__ *)malloc(sizeof(object__) * (count__))) == NULL)                                                                                                                                                                \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        exit(EXIT_CODE_OUTOFMEMORY_ERROR);                                                                                                                                                                                                     \
    }
#define MALLOC_OBJECT_ARRAY(target__, object__, count__, tag__) (target__) = (object__ *)malloc(sizeof(object__) * (count__))
#else
#define MALLOC_OR_DIE(cast_, target_, size_, tag_)                                                                                                                                                                                             \
    if(((target_) = (cast_)malloc(size_)) != NULL)                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                          \
        memset((void *)(target_), 0xac, (size_));                                                                                                                                                                                              \
    }                                                                                                                                                                                                                                          \
    else                                                                                                                                                                                                                                       \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        exit(EXIT_CODE_OUTOFMEMORY_ERROR);                                                                                                                                                                                                     \
    }
#define MALLOC_OBJECT_OR_DIE(target__, object__, tag__)                                                                                                                                                                                        \
    if(((target__) = (object__ *)malloc(sizeof(object__))) != NULL)                                                                                                                                                                            \
    {                                                                                                                                                                                                                                          \
        memset((void *)(target__), 0xac, (sizeof(object__)));                                                                                                                                                                                  \
    }                                                                                                                                                                                                                                          \
    else                                                                                                                                                                                                                                       \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        exit(EXIT_CODE_OUTOFMEMORY_ERROR);                                                                                                                                                                                                     \
    }
#define MALLOC_OBJECT_ARRAY_OR_DIE(target__, object__, count__, tag__)                                                                                                                                                                         \
    if(((target__) = (object__ *)malloc(sizeof(object__) * (count__))) != NULL)                                                                                                                                                                \
    {                                                                                                                                                                                                                                          \
        memset((void *)(target__), 0xac, (sizeof(object__) * (count__)));                                                                                                                                                                      \
    }                                                                                                                                                                                                                                          \
    else                                                                                                                                                                                                                                       \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        exit(EXIT_CODE_OUTOFMEMORY_ERROR);                                                                                                                                                                                                     \
    }
#define MALLOC_OBJECT_ARRAY(target__, object__, count__, tag__)                                                                                                                                                                                \
    if(((target__) = (object__ *)malloc(sizeof(object__) * (count__))) != NULL)                                                                                                                                                                \
    {                                                                                                                                                                                                                                          \
        memset((void *)(target__), 0xac, (sizeof(object__) * (count__)));                                                                                                                                                                      \
    }
#endif

#define REALLOC_OR_DIE(cast, src_and_target, newsize, tag)                                                                                                                                                                                     \
    if(((src_and_target) = (cast)realloc((src_and_target), (newsize))) == NULL)                                                                                                                                                                \
    {                                                                                                                                                                                                                                          \
        perror(__FILE__);                                                                                                                                                                                                                      \
        abort();                                                                                                                                                                                                                               \
    }

// the string if not NULL, else a empty string

#define STRNULL(__str__)                    (((__str__) != NULL) ? (__str__) : "")

// the fqdn if not NULL, else "."

#define FQDNNULL(__str__)                   (((__str__) != NULL) ? (__str__) : (const uint8_t *)"")

#define TOSTRING(s)                         TOSTRING_(s)
#define TOSTRING_(s)                        #s
#define PREPROCESSOR_INT2STR(x)             #x
#define PREPROCESSOR_EVAL(a__)              a__
#define PREPROCESSOR_CONCAT(a__, b__)       a__##b__
#define PREPROCESSOR_CONCAT_EVAL_(a__, b__) a__##b__
#define PREPROCESSOR_CONCAT_EVAL(a__, b__)  PREPROCESSOR_CONCAT_EVAL_(a__, b__)

/**
 * strcpy is not safe
 * strncpy is filling buffers needlessly
 *
 * This one does what we want.
 */

static inline void strcpy_ex(char *dest, const char *src, size_t n)
{
    size_t src_len = strlen(src) + 1;
    if(src_len <= n)
    {
        memcpy(dest, src, src_len);
    }
    else
    {
        --n;
        memcpy(dest, src, n);
        dest[n] = '\0';
    }
}

#define BOOL2INT(b_) ((b_) ? 1 : 0)
#define BOOL2STR(b_) ((b_) ? "true" : "false")
#define BOOL2CHR(b_) ((b_) ? 'y' : 'n')

#include <dnscore/debug.h>

#ifdef MIN
#undef MIN
#endif
#define MIN(a, b) (((a) <= (b)) ? (a) : (b))

#ifdef MAX
#undef MAX
#endif
#define MAX(a, b)                           (((a) >= (b)) ? (a) : (b))

#define BOUND(a, b, c)                      (((b) <= (a)) ? (a) : (((b) >= (c)) ? (c) : (b)))

#define ZEROMEMORY(buffer__, size__)        memset(buffer__, 0, size__)
#define MEMCOPY(target__, source__, size__) memcpy((target__), (source__), (size__))

// a magic number as 32 bits
#define MAGIC4(b0_, b1_, b2_, b3_)          NU32((((uint32_t)b0_) << 24) | (((uint32_t)b1_) << 16) | (((uint32_t)b2_) << 8) | ((uint32_t)b3_))

#define TYPE_CLASS_TTL_RDLEN_SIZE           10

#if !__windows__
#define PACKED_STRUCTURE_ATTRIBUTE __attribute__((__packed__))
#else
#define PACKED_STRUCTURE_ATTRIBUTE
#endif

struct type_class_ttl_rdlen_s
{
    uint16_t rtype;
    uint16_t rclass;
    int32_t  ttl;
    uint16_t rdlen;
} PACKED_STRUCTURE_ATTRIBUTE;

typedef struct type_class_ttl_rdlen_s type_class_ttl_rdlen_t;

#if USES_ICC

#ifndef inline
#define inline __inline
#endif

#else

#ifndef inline
#define inline __inline__
#endif

#endif

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#if __unix__
static inline bool filepath_is_absolute(const char *path) { return path[0] == '/'; }
#else
static inline bool filepath_is_absolute(const char *path) { return (path[0] == '/') || ((path[0] != '\0') && (path[1] == ':')); }
#endif

#ifdef __cplusplus
}
#endif

#if __unix__
#define DEV_NULL_PATH "/dev/null"
#else
#define DEV_NULL_PATH "nul"
#endif

#endif /* _SYSTYPES_H */

/** @} */
