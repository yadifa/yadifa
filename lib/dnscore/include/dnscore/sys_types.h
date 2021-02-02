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

/** @defgroup systemtypes Definition of types in order to ensure architecture-independence
 *  @ingroup dnscore
 *  @brief Definition of types in order to ensure architecture-independence
 *
 * @{
 */

#ifndef _SYSTYPES_H
#define	_SYSTYPES_H

#include <dnscore/dnscore-config-features.h>

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
#include <stdbool.h>
#include <unistd.h>
#include <stddef.h>

#ifdef _MSC_VER 
#include <malloc.h>
#define C11_VLA_AVAILABLE 0
static void* stack_alloc(size_t size)
{
    // VS wants to use _malloca instead which allocates on the heap if size > _ALLOCA_S_THRESHOLD (1024)
    // I'd rather have a bigger stack

    return _alloca(size);
}
#else
#define C11_VLA_AVAILABLE 1
#endif

#ifndef __has_c_attribute       // Optional of course.
#define __has_c_attribute(x) 0  // Compatibility with non-clang compilers.
#endif
#if __has_c_attribute(fallthrough)
// __attribute__ ((fallthrough));   // C and C++03
// [[fallthrough]];                 // C++17 and above
#define FALLTHROUGH __attribute__ ((fallthrough));
#else
#define FALLTHROUGH
#endif

#if defined __FreeBSD__
#include <sys/endian.h>

#ifndef __BYTE_ORDER
    #if defined(_BYTE_ORDER)
        #define __BIG_ENDIAN _BIG_ENDIAN
        #define __LITTLE_ENDIAN _LITTLE_ENDIAN
        #define __BYTE_ORDER _BYTE_ORDER
    #elif defined(WORDS_BIGENDIAN)
        #define __BIG_ENDIAN 4321
        #define __LITTLE_ENDIAN 1234
        #define __BYTE_ORDER __BIG_ENDIAN
    #else
        #error "endianness detection code will most likely fail"
    #endif
#endif

#elif defined __APPLE__
#include <machine/endian.h>

#ifndef __BYTE_ORDER
    #if defined(BYTE_ORDER)
        #define __BIG_ENDIAN BIG_ENDIAN
        #define __LITTLE_ENDIAN LITTLE_ENDIAN
        #define __BYTE_ORDER BYTE_ORDER
    #elif defined(WORDS_BIGENDIAN)
        #define __BIG_ENDIAN 4321
        #define __LITTLE_ENDIAN 1234
        #define __BYTE_ORDER __BIG_ENDIAN
    #else
        #error "endianness detection code will most likely fail"
    #endif
#endif
#elif defined __sun
#include <sys/byteorder.h>
#ifndef __BYTE_ORDER
    #if defined(__BYTE_ORDER__)
        #define __BIG_ENDIAN __ORDER_BIG_ENDIAN__
        #define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
        #define __BYTE_ORDER __BYTE_ORDER__
    #else
        // assume big endian
        #define __BIG_ENDIAN 4321
        #define __LITTLE_ENDIAN 1234
        #define __BYTE_ORDER __BIG_ENDIAN
    #endif
#endif
#elif defined __OpenBSD__ || defined __NetBSD__
#include <endian.h>
#ifndef __BYTE_ORDER
    #if defined(BYTE_ORDER)
        #define __BIG_ENDIAN BIG_ENDIAN
        #define __LITTLE_ENDIAN LITTLE_ENDIAN
        #define __BYTE_ORDER BYTE_ORDER
    #else
        // assume big endian
        #define __BIG_ENDIAN 4321
        #define __LITTLE_ENDIAN 1234
        #define __BYTE_ORDER __BIG_ENDIAN
    #endif
#endif
#elif defined(WIN32)
#define WIN32_LEAN_AND_MEAN
#pragma message("windows")
#include <Windows.h>
#include <BaseTsd.h>
#include <windef.h>
//#include <minwindef.h>
//#include <minwinbase.h>
#undef inline
#define inline
typedef int uid_t;
typedef int gid_t;
typedef HANDLE pid_t;
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

#include <dnscore/dnscore-config-features.h>
#include <dnscore/sys_error.h>

#include <sys/types.h> /** @note must be used for u_char on Mac OS X */

#ifdef	__cplusplus
extern "C"
{
#endif
    
#define SIZEOF_TIMEVAL 16
    
#ifndef HAS_DYNAMIC_PROVISIONING
#define HAS_DYNAMIC_PROVISIONING 1
#endif
    
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if defined(__bool_true_false_are_defined) && __bool_true_false_are_defined != 0

#ifndef TRUE
#define TRUE  true
#endif

#ifndef FALSE
#define FALSE false
#endif

#else

typedef int bool;

#ifndef TRUE
#define TRUE  (0==0)
#endif

#ifndef FALSE
#define FALSE (0==1)
#endif

#endif

#define UNSIGNED_TYPE_VALUE_MAX(__type__)    ((__type__)~0)
#define SIGNED_TYPE_VALUE_MAX(__type__)      (((__type__)~0)>>1)
#define SIGNED_TYPE_VALUE_MIN(__type__)      (((__type__)~0) - (((__type__)~0)>>1))

#define UNSIGNED_VAR_VALUE_MAX(__var__)     ((~0ULL)>>((sizeof(~0ULL) - sizeof(__var__)) * 8LL))
#define SIGNED_VAR_VALUE_MAX(__var__)      (UNSIGNED_VAR_VALUE_MAX(__var__)>>1)
#define SIGNED_VAR_VALUE_MIN(__var__)      (UNSIGNED_VAR_VALUE_MAX(__var__) - SIGNED_VAR_VALUE_MAX(__var__))

#define UNSIGNED_VAR_VALUE_IS_MAX(__var__) (__var__ == UNSIGNED_VAR_VALUE_MAX(__var__))
#define SIGNED_VAR_VALUE_IS_MAX(__var__) (__var__ == SIGNED_VAR_VALUE_MAX(__var__))

/* This is the basic type definition set                        */
/* Tweaks will be added for each setup (using the preprocessor) */

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef short s16;
typedef unsigned int u32;
typedef int s32;

#if defined(HAVE_UINT64_T) && defined(HAVE_INT64_T)
typedef uint64_t u64;
typedef int64_t s64;
#elif defined(HAVE_LONG_LONG)
typedef unsigned long long u64;
typedef signed long long s64;
#elif defined(_LONGLONG)  && ( _LONGLONG == 1 ) // FreeBSD 9.1 gcc 4.2.1
typedef unsigned long long u64;
typedef signed long long s64;
#elif defined(__SIZEOF_LONG_LONG__) && (__SIZEOF_LONG_LONG__ == 8)
typedef unsigned long long u64;
typedef signed long long s64;
#elif defined(__LONG_LONG_MAX__) && (__LONG_LONG_MAX__ == 9223372036854775807LL)
typedef unsigned long long u64;
typedef signed long long s64;
#elif defined(_LONGLONG_TYPE)
typedef unsigned long long u64;
typedef signed long long s64;
#elif defined(WIN32)
typedef __int8 s8;
typedef unsigned __int8 u8;
typedef __int16 s16;
typedef unsigned __int16 u16;
typedef __int32 s32;
typedef unsigned __int32 u32;
typedef __int64 s64;
typedef unsigned __int64 u64;
#else
#error NO UNSIGNED 64 BITS TYPE KNOWN ON THIS 64 BITS ARCHITECTURE (u64 + s64)
#endif

typedef void callback_function(void*);
typedef ya_result result_callback_function(void*, void*);

/*
AIX : __64BIT__
HP: __LP64__
SUN: __sparcv9, _LP64
SGI: _MIPS_SZLONG==64
NT: _M_IA64
 */

#ifndef __SIZEOF_POINTER__
#if defined(__LP64__)||defined(__LP64)||defined(_LP64)||defined(__64BIT__)||defined(MIPS_SZLONG)||defined(_M_IA64)||defined(_WIN64)
#define __SIZEOF_POINTER__ 8
#else
#define __SIZEOF_POINTER__ 4
#endif
#endif

#if __SIZEOF_POINTER__ == 4

typedef unsigned int intptr; // an integer with the same size as a data pointer

typedef float realptr;  // a float with the same size as a data pointer

#elif __SIZEOF_POINTER__ == 8

#if defined(HAVE_UINT64_T)
typedef uint64_t intptr;
#elif defined(HAVE_LONG_LONG)
typedef unsigned long long intptr;
#elif defined(__LONG_LONG_MAX__) && (__LONG_LONG_MAX__ == 9223372036854775807LL)
typedef unsigned long long intptr;
#elif defined(__SIZEOF_LONG_LONG__) && (__SIZEOF_LONG_LONG__ == 8)
typedef unsigned long long intptr;
#elif defined(_LONGLONG)  && ( _LONGLONG == 1 ) // FreeBSD 9.1 gcc 4.2.1
typedef unsigned long long intptr;
#elif defined(_LONGLONG_TYPE)
typedef unsigned long long intptr;
#elif defined(_WIN64)
typedef u64 intptr;
#else
#error NO UNSIGNED 64 BITS TYPE KNOWN ON THIS 64 BITS ARCHITECTURE (intptr)
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

#define ALIGN8(__from_address__) (((__from_address__)+7)&~7)

/**
 * This macro returns the first address aligned to 16 bytes from the parameter
 * addresss.
 * 
 */

#define ALIGN16(__from_address__) (((__from_address__)+15)&~15)

/*
 * Macros used to access bytes inside a buffer.
 *
 * ie: U32_AT(packet[8]), assuming that packet is a byte buffer, will access
 *     the 8th byte inside packet as a (native) unsigned 32bits integer.
 */

#define U8_AT(address__)  (*((u8*)&(address__)))

#define GET_U8_AT(address__) (*((u8*)&(address__)))
#define SET_U8_AT(address__,value__) (*((u8*)&(address__)) = (value__))

#ifndef WORDS_BIGENDIAN
#if __BYTE_ORDER == __BIG_ENDIAN
#define WORDS_BIGENDIAN 1
#endif
#else // WORDS_BIGENDIAN defined
#if __BYTE_ORDER == __LITTLE_ENDIAN
#error "confusing endianness"
#endif
#endif

#define AVOID_ANTIALIASING 1

#ifndef DNSCORE_HAS_MEMALIGN_ISSUES
#error "DNSCORE_HAS_MEMALIGN_ISSUES is not defined.  Please ensure the relevant config.h is included at some level above."
#endif

#if !DNSCORE_HAS_MEMALIGN_ISSUES

#if AVOID_ANTIALIASING
static inline u16 GET_U16_AT_P(const void* address)
{
    const u16 *p = (const u16*)address;
    return *p;
}
static inline void SET_U16_AT_P(void* address, u16 value)
{
    u16 *p = (u16*)address;
    *p = value;
}
static inline u32 GET_U32_AT_P(const void* address)
{
    const u32 *p = (const u32*)address;
    return *p;
}
static inline void SET_U32_AT_P(void* address, u32 value)
{
    u32 *p = (u32*)address;
    *p = value;
}
static inline u64 GET_U64_AT_P(const void* address)
{
    const u64 *p = (const u64*)address;
    return *p;
}
static inline void SET_U64_AT_P(void* address, u64 value)
{
    u64 *p = (u64*)address;
    *p = value;
}

#define GET_U16_AT(address__) GET_U16_AT_P(&(address__))
#define SET_U16_AT(address__,value__) SET_U16_AT_P(&(address__),(value__))
#define GET_U32_AT(address__) GET_U32_AT_P(&(address__))
#define SET_U32_AT(address__,value__) SET_U32_AT_P(&(address__),(value__))
#define GET_U64_AT(address__) GET_U64_AT_P(&(address__))
#define SET_U64_AT(address__,value__) SET_U64_AT_P(&(address__),(value__))
#else
#define GET_U16_AT(address) (*((u16*)&(address)))
#define SET_U16_AT(address,value) *((u16*)&(address))=(value)

#define GET_U32_AT(address) (*((u32*)&(address)))
#define SET_U32_AT(address,value) *((u32*)&(address))=(value)

#define GET_U64_AT(address) (*((u64*)&(address)))
#define SET_U64_AT(address,value) *((u64*)&(address))=(value)
#endif

#else /* sparc ... */

/*
 *  Why in caps ? Traditionnaly it was an helper macro.  Macros are in caps except when they hide a virtual call.
 *
 */

static inline u16 GET_U16_AT_P(const void* p)
{
    const u8* p8=(const u8*)p;
    u16 v;

#ifdef WORDS_BIGENDIAN
    v=p8[0];
    v<<=8;
    v|=p8[1];
#else
    v=p8[1];
    v<<=8;
    v|=p8[0];
#endif
    
    return v;
}

#define GET_U16_AT(x) GET_U16_AT_P(&(x))

static inline void SET_U16_AT_P(void* p, u16 v)
{
    u8* p8=(u8*)p;

#ifdef WORDS_BIGENDIAN
    p8[0]=v>>8;
    p8[1]=v;
#else
    p8[0]=v;
    p8[1]=v>>8;
#endif
}

#define SET_U16_AT(x___,y___) SET_U16_AT_P(&(x___),(y___))

static inline u32 GET_U32_AT_P(const void* p)
{
    const u8* p8=(const u8*)p;
    u32 v;

#ifdef WORDS_BIGENDIAN
    v=p8[0];
    v<<=8;
    v|=p8[1];
    v<<=8;
    v|=p8[2];
    v<<=8;
    v|=p8[3];
#else
    v=p8[3];
    v<<=8;
    v|=p8[2];
    v<<=8;
    v|=p8[1];
    v<<=8;
    v|=p8[0];
#endif
    return v;
}

#define GET_U32_AT(x) GET_U32_AT_P(&(x))

static inline void SET_U32_AT_P(void* p, u32 v)
{
    u8* p8=(u8*)p;

#ifdef WORDS_BIGENDIAN
    p8[0]=v>>24;
    p8[1]=v>>16;
    p8[2]=v>>8;
    p8[3]=v;
#else
    p8[0]=v;
    p8[1]=v>>8;
    p8[2]=v>>16;
    p8[3]=v>>24;
#endif
}

#define SET_U32_AT(x___,y___) SET_U32_AT_P(&(x___),(y___))

static inline u64 GET_U64_AT_P(const void* p)
{
    const u8* p8=(const u8*)p;
    u32 v;

#ifdef WORDS_BIGENDIAN
    v=p8[0];
    v<<=8;
    v|=p8[1];
    v<<=8;
    v|=p8[2];
    v<<=8;
    v|=p8[3];
    v<<=8;
    v|=p8[4];
    v<<=8;
    v|=p8[5];
    v<<=8;
    v|=p8[6];
    v<<=8;
    v|=p8[7];
#else
    v=p8[7];
    v<<=8;
    v|=p8[6];
    v<<=8;
    v|=p8[5];
    v<<=8;
    v|=p8[4];
    v<<=8;
    v=p8[3];
    v<<=8;
    v|=p8[2];
    v<<=8;
    v|=p8[1];
    v<<=8;
    v|=p8[0];
#endif
    return v;
}

#define GET_U64_AT(x) GET_U64_AT_P(&(x))

static inline void SET_U64_AT_P(void* p, u64 v)
{
    u8* p8=(u8*)p;

#ifdef WORDS_BIGENDIAN
    p8[0]=v>>56;
    p8[1]=v>>48;
    p8[2]=v>>40;
    p8[3]=v>>32;
    p8[4]=v>>24;
    p8[5]=v>>16;
    p8[6]=v>>8;
    p8[7]=v;
#else
    p8[0]=v;
    p8[1]=v>>8;
    p8[2]=v>>16;
    p8[3]=v>>24;
    p8[4]=v>>32;
    p8[5]=v>>40;
    p8[6]=v>>48;
    p8[7]=v>>56;
#endif
}

#define SET_U64_AT(x___,y___) SET_U64_AT_P(&(x___),(y___))

#endif

#if __SIZEOF_POINTER__ == 4
#define SET_PTR_AT_P SET_U32_AT_P
#define SET_PTR_AT SET_U32_AT
#define GET_PTR_AT_P GET_U32_AT_P
#define GET_PTR_AT GET_U32_AT
#elif __SIZEOF_POINTER__ == 8
#define SET_PTR_AT_P SET_U64_AT_P
#define SET_PTR_AT SET_U64_AT
#define GET_PTR_AT_P GET_U64_AT_P
#define GET_PTR_AT GET_U64_AT
#else
#error "unsupported pointer size"
#endif

#define MAX_U8  ((u8)0xff)
#define MAX_U16 ((u16)0xffff)
#define MAX_U32 ((u32)0xffffffffUL)
#define MAX_U64 ((u64)0xffffffffffffffffULL)

#define MAX_S8  ((s8)0x7f)
#define MAX_S16 ((s16)0x7fff)
#define MAX_S32 ((s32)0x7fffffffL)
#define MAX_S64 ((s64)0x7fffffffffffffffLL)

#define MIN_S8  ((s8)0xff)
#define MIN_S16 ((s16)0xffff)
#define MIN_S32 ((s32)0xffffffffL)
#define MIN_S64 ((s64)0xffffffffffffffffLL)

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

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htobe16(x) __bswap_16 (x)
#  define htole16(x) (x)
#  define be16toh(x) __bswap_16 (x)
#  define le16toh(x) (x)

#  define htobe32(x) __bswap_32 (x)
#  define htole32(x) (x)
#  define be32toh(x) __bswap_32 (x)
#  define le32toh(x) (x)

#  define htobe64(x) __bswap_64 (x)
#  define htole64(x) (x)
#  define be64toh(x) __bswap_64 (x)
#  define le64toh(x) (x)
# else
#  define htobe16(x) (x)
#  define htole16(x) __bswap_16 (x)
#  define be16toh(x) (x)
#  define le16toh(x) __bswap_16 (x)

#  define htobe32(x) (x)
#  define htole32(x) __bswap_32 (x)
#  define be32toh(x) (x)
#  define le32toh(x) __bswap_32 (x)

#  define htobe64(x) (x)
#  define htole64(x) __bswap_64 (x)
#  define be64toh(x) (x)
#  define le64toh(x) __bswap_64 (x)
# endif // __BYTE_ORDER
#endif // htobe64

/**/

/// Used for collection callback processing (list)
/// Their support by a collection is not guaranteed

/// @note PROCESS_THEN_STOP = PROCESS|STOP

#define COLLECTION_ITEM_SKIP                    0
#define COLLECTION_ITEM_PROCESS                 1
#define COLLECTION_ITEM_STOP                    2
#define COLLECTION_ITEM_PROCESS_THEN_STOP       (COLLECTION_ITEM_PROCESS|COLLECTION_ITEM_STOP)

/**/

typedef u32 process_flags_t;

#ifdef WORDS_BIGENDIAN
#define NU16(value)     ((u16)(value))
#define NU32(value)     ((u32)(value))
#else
#define NU16(value)     ((u16)(((((u16)(value))>>8)&0xff)|(((u16)(value))<<8)))
#define NU32(value)     ((u32)(( (((u32)(value)) >> 24) & 0xff) | ((((u32)(value)) >> 8) & 0xff00) | ((((u32)(value)) << 8) & 0xff0000) | (((u32)(value)) << 24)))
#endif

#define VERSION_U32(h__,l__) (((h__) << 16) | (l__))
#define VERSION_U16(h__,l__) (((h__) <<  8) | (l__))
#define VERSION_U8(h__,l__)  (((h__) <<  4) | (l__))

#define NETWORK_ONE_16  NU16(0x0001)
#define IS_WILD_LABEL(u8dnslabel_) ( GET_U16_AT(*(u8dnslabel_)) == NU16(0x012a))       /* 01 2a = 1 '*' */

/* sys_types.h is included everywhere.  This ensure the debug hooks will be too. */

#define TMPBUFFR_TAG 0x5246465542504d54

#if !DEBUG
#define MALLOC_OR_DIE(cast,target,size,tag) if(((target)=(cast)malloc(size))==NULL){perror(__FILE__);exit(EXIT_CODE_OUTOFMEMORY_ERROR);}
#define MALLOC_OBJECT_OR_DIE(target__,object__,tag__) if(((target__)=(object__*)malloc(sizeof(object__)))==NULL){perror(__FILE__);exit(EXIT_CODE_OUTOFMEMORY_ERROR);}
#define MALLOC_OBJECT_ARRAY_OR_DIE(target__,object__,count__,tag__) if(((target__)=(object__*)malloc(sizeof(object__)*(count__)))==NULL){perror(__FILE__);exit(EXIT_CODE_OUTOFMEMORY_ERROR);}
#define MALLOC_OBJECT_ARRAY(target__,object__,count__,tag__) (target__)=(object__*)malloc(sizeof(object__)*(count__))
#else
#define MALLOC_OR_DIE(cast_,target_,size_,tag_) if(((target_)=(cast_)malloc(size_))!=NULL){memset((void*)(target_),0xac,(size_));}else{perror(__FILE__);exit(EXIT_CODE_OUTOFMEMORY_ERROR);}
#define MALLOC_OBJECT_OR_DIE(target__,object__,tag__) if(((target__)=(object__*)malloc(sizeof(object__)))!=NULL){memset((void*)(target__),0xac,(sizeof(object__)));}else{perror(__FILE__);exit(EXIT_CODE_OUTOFMEMORY_ERROR);}
#define MALLOC_OBJECT_ARRAY_OR_DIE(target__,object__,count__,tag__) if(((target__)=(object__*)malloc(sizeof(object__)*(count__)))!=NULL){memset((void*)(target__),0xac,(sizeof(object__)*(count__)));}else{perror(__FILE__);exit(EXIT_CODE_OUTOFMEMORY_ERROR);}
#define MALLOC_OBJECT_ARRAY(target__,object__,count__,tag__) if(((target__)=(object__*)malloc(sizeof(object__)*(count__)))!=NULL){memset((void*)(target__),0xac,(sizeof(object__)*(count__)));}
#endif

#define REALLOC_OR_DIE(cast,src_and_target,newsize,tag) if(((src_and_target)=(cast)realloc((src_and_target),(newsize)))==NULL){perror(__FILE__);abort();}

// the string if not NULL, else a empty string

#define STRNULL(__str__) (((__str__)!=NULL)?(__str__):"")

// the fqdn if not NULL, else "."

#define FQDNNULL(__str__) (((__str__)!=NULL)?(__str__):(const u8*)"")

#define TOSTRING(s) TOSTRING_(s)
#define TOSTRING_(s) #s    
#define PREPROCESSOR_INT2STR(x) #x
#define PREPROCESSOR_EVAL(a__) a__
#define PREPROCESSOR_CONCAT(a__,b__) a__##b__
#define PREPROCESSOR_CONCAT_EVAL_(a__,b__) a__##b__
#define PREPROCESSOR_CONCAT_EVAL(a__,b__) PREPROCESSOR_CONCAT_EVAL_(a__,b__)

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

#define BOOL2INT(b_) ((b_)?1:0)
#define BOOL2STR(b_) ((b_)?"true":"false")
#define BOOL2CHR(b_) ((b_)?'y':'n')

#include <dnscore/debug.h>

#ifdef MIN
#undef MIN
#endif
#define MIN(a,b) (((a)<=(b))?(a):(b))

#ifdef MAX
#undef MAX
#endif
#define MAX(a,b) (((a)>=(b))?(a):(b))

#define BOUND(a,b,c) (((b)<=(a))?(a):(((b)>=(c))?(c):(b)))

#define ZEROMEMORY(buffer__,size__) memset(buffer__, 0, size__)
#define MEMCOPY(target__,source__,size__) memcpy((target__),(source__),(size__))

// a magic number as 32 bits
#define MAGIC4(b0_,b1_,b2_,b3_) NU32((((u32)b0_)<<24)|(((u32)b1_)<<16)|(((u32)b2_)<<8)|((u32)b3_))

struct type_class_ttl_rdlen
{
    u16 qtype;
    u16 qclass;
    s32 ttl;
    u16 rdlen;
};

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

#ifdef	__cplusplus
}
#endif


#endif	/* _SYSTYPES_H */

/** @} */
