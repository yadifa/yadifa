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

/** @defgroup dnscoreerror Error
 *  @ingroup dnscore
 *  @brief 
 *
 *  
 *
 * @{
 *
 *----------------------------------------------------------------------------*/
#ifndef ERROR_H_
#define ERROR_H_

/*    ------------------------------------------------------------
 *
 *      INCLUDES
 */

/*
 * Please only include "native" stuff.  sys_error.h should NOT depend
 * on anything else (beside sys_types but sys_types.h already includes
 * sys_error.h)
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/*
 * 8000 ERRNO
 * 8001 SERVER
 * 8002 CORE
 * 8003 DNS
 * 8004 DATABASE
 * 8005 DNSSEC
 * 8006 ACL
 * 8007 CONFIG?
 * 8008 YDF
 * 8009 EAI
 * 800A ZONE FILE READ
 * 800B SANITY
 * 800C NEW CONFIG
 * 800D PARSER
 * C000 DNS RCODE
 */

#if !defined(_SYSTYPES_H)
#error Included from a disallowed place.
#endif


#define SUCCESS                         0
#define OK                              0

// The basic error code

/// @note Everywhere in the source, "return ERROR;" should be replaced by something more specific

#ifdef ERROR
#undef ERROR
#endif
#define ERROR                           -1
#define NOK				                -1

#define TRACK_RETURNED_GENERIC_ERROR    0

#define ERRNO_ERROR_BASE                0x80000000

typedef int32_t ya_result;

/* Two macros to easily check an error status */

#define YA_ERROR_BASE(err_) ((err_) & 0xffff0000UL)
#define YA_ERROR_CODE(err_) ((err_) & 0x0000ffffUL)

#if !DEBUG
#define FAIL(result__) ((result__)<0)
#define ISOK(result__) ((result__)>=0)
#else

#if TRACK_RETURNED_GENERIC_ERROR
bool dnscore_monitored_isok(ya_result ret);
bool dnscore_monitored_fail(ya_result ret);
#define FAIL(result__) dnscore_monitored_fail((result__))
#define ISOK(result__) dnscore_monitored_isok((result__))
#else
#define FAIL(result) ((((u32)(result)) & ((u32)ERRNO_ERROR_BASE)) != 0) // trying to make scan-build understand
#define ISOK(result) ((((u32)(result)) & ((u32)ERRNO_ERROR_BASE)) == 0)
#endif
#endif

/* 16 most significant bits : GROUP, the sign bit being ALWAYS set
 * 16 least significant bits : ID
 */

#define ERRNO_ERROR                     ((s32)(ERRNO_ERROR_BASE+errno))
#define MAKE_ERRNO_ERROR(err_)          ((s32)(ERRNO_ERROR_BASE+(err_)))

#define EXITFAIL(x) if((x)<0) {DIE(ERROR);exit(EXIT_FAILURE);}

#define DNSMSG_ERROR_BASE               0xc0000000


/* -----------------------------------------------------------------------------
 *
 *   STRUCTS
 */

#define RCODE_ERROR_BASE                        0x80010000
#define RCODE_ERROR_CODE(code_)                 ((s32)(RCODE_ERROR_BASE+(code_)))
#define RCODE_ERROR_GETCODE(error_)             ((error_)&0xffff)
#define MAKE_DNSMSG_ERROR(err_)                 RCODE_ERROR_CODE(err_)

#define CORE_ERROR_BASE                         0x80020000
#define CORE_ERROR_CODE(code_)                  ((s32)(CORE_ERROR_BASE+(code_)))

#define LOGGER_INITIALISATION_ERROR             CORE_ERROR_CODE(1)
#define COMMAND_ARGUMENT_EXPECTED               CORE_ERROR_CODE(2)
#define OBJECT_NOT_INITIALIZED                  CORE_ERROR_CODE(3)
#define FORMAT_ALREADY_REGISTERED               CORE_ERROR_CODE(4)
#define STOPPED_BY_APPLICATION_SHUTDOWN         CORE_ERROR_CODE(5)
#define INVALID_STATE_ERROR                     CORE_ERROR_CODE(6)
#define FEATURE_NOT_IMPLEMENTED_ERROR           CORE_ERROR_CODE(7)
#define UNEXPECTED_NULL_ARGUMENT_ERROR          CORE_ERROR_CODE(8)
#define INVALID_ARGUMENT_ERROR                  CORE_ERROR_CODE(9)
#define UNABLE_TO_COMPLETE_FULL_READ            CORE_ERROR_CODE(11)
#define UNEXPECTED_EOF                          CORE_ERROR_CODE(12)
#define UNSUPPORTED_TYPE                        CORE_ERROR_CODE(13)
#define UNKNOWN_NAME                            CORE_ERROR_CODE(14)     /* name->value table */
#define BIGGER_THAN_PATH_MAX                    CORE_ERROR_CODE(15)
#define UNABLE_TO_COMPLETE_FULL_WRITE           CORE_ERROR_CODE(16)
#define BUFFER_WOULD_OVERFLOW                   CORE_ERROR_CODE(17)
#define CHROOT_NOT_A_DIRECTORY                  CORE_ERROR_CODE(18)
#define CHROOT_ALREADY_JAILED                   CORE_ERROR_CODE(19)
#define IP_VERSION_NOT_SUPPORTED                CORE_ERROR_CODE(20)
#define COLLECTION_DUPLICATE_ENTRY              CORE_ERROR_CODE(21)
#define INVALID_PATH                            CORE_ERROR_CODE(22)
#define PID_LOCKED                              CORE_ERROR_CODE(23)
#define ZALLOC_ERROR_MMAPFAILED                 CORE_ERROR_CODE(24)
#define ZALLOC_ERROR_OUTOFMEMORY                CORE_ERROR_CODE(25)
#define DIRECTORY_NOT_WRITABLE                  CORE_ERROR_CODE(26)
#define FEATURE_NOT_SUPPORTED                   CORE_ERROR_CODE(27)
#define LOCK_TIMEOUT                            CORE_ERROR_CODE(28)
#define CIRCULAR_FILE_FULL                      CORE_ERROR_CODE(29)
#define CIRCULAR_FILE_SHORT                     CORE_ERROR_CODE(30)
#define CIRCULAR_FILE_END                       CORE_ERROR_CODE(31)
#define CIRCULAR_FILE_LIMIT_EXCEEDED            CORE_ERROR_CODE(32)
#define DATA_FORMAT_ERROR                       CORE_ERROR_CODE(33)
#define LOCK_FAILED                             CORE_ERROR_CODE(34)
#define UNSUPPORTED_CLASS                       CORE_ERROR_CODE(35)
#define CANNOT_OPEN_FILE                        CORE_ERROR_CODE(36)

#define PARSEB16_ERROR                          CORE_ERROR_CODE(0x1001)
#define PARSEB32_ERROR                          CORE_ERROR_CODE(0x1002)
#define PARSEB32H_ERROR                         CORE_ERROR_CODE(0x1003)
#define PARSEB64_ERROR                          CORE_ERROR_CODE(0x1004)
#define PARSEINT_ERROR                          CORE_ERROR_CODE(0x1005)
#define PARSEDATE_ERROR                         CORE_ERROR_CODE(0x1006)
#define PARSEIP_ERROR                           CORE_ERROR_CODE(0x1007)
#define PARSEWORD_NOMATCH_ERROR                 CORE_ERROR_CODE(0x1081)
#define PARSESTRING_ERROR                       CORE_ERROR_CODE(0x1082)
#define PARSE_BUFFER_TOO_SMALL_ERROR            CORE_ERROR_CODE(0x1083)
#define PARSE_INVALID_CHARACTER                 CORE_ERROR_CODE(0x1084)
#define PARSE_INVALID_ARGUMENT                  CORE_ERROR_CODE(0x1085)
#define PARSE_EMPTY_ARGUMENT                    CORE_ERROR_CODE(0x1086)

#define CONFIG_SECTION_CALLBACK_ALREADY_SET     CORE_ERROR_CODE(0x1801)
#define CONFIG_SECTION_CALLBACK_NOT_SET         CORE_ERROR_CODE(0x1802)
#define CONFIG_SECTION_CALLBACK_NOT_FOUND       CORE_ERROR_CODE(0x1803)
#define CONFIG_NOT_A_REGULAR_FILE               CORE_ERROR_CODE(0x1804)
#define CONFIG_TOO_MANY_HOSTS                   CORE_ERROR_CODE(0x1805)
#define CONFIG_FQDN_NOT_ALLOWED                 CORE_ERROR_CODE(0x1806)
#define CONFIG_PORT_NOT_ALLOWED                 CORE_ERROR_CODE(0x1807)
#define CONFIG_EXPECTED_VALID_PORT_VALUE        CORE_ERROR_CODE(0x1808)
#define CONFIG_TSIG_NOT_ALLOWED                 CORE_ERROR_CODE(0x1809)
#define CONFIG_INTERNAL_ERROR                   CORE_ERROR_CODE(0x180a)
#define CONFIG_IPV4_NOT_ALLOWED                 CORE_ERROR_CODE(0x180b)
#define CONFIG_IPV6_NOT_ALLOWED                 CORE_ERROR_CODE(0x180c)
#define CONFIG_KEY_UNKNOWN                      CORE_ERROR_CODE(0x180d)
#define CONFIG_KEY_PARSE_ERROR                  CORE_ERROR_CODE(0x180e)
#define CONFIG_SECTION_ERROR                    CORE_ERROR_CODE(0x180f)
#define CONFIG_IS_BUSY                          CORE_ERROR_CODE(0x1810)
#define CONFIG_FILE_NOT_FOUND                   CORE_ERROR_CODE(0x1811)

#define THREAD_CREATION_ERROR                   CORE_ERROR_CODE(0x2001)
#define THREAD_DOUBLEDESTRUCTION_ERROR          CORE_ERROR_CODE(0x2002)
#define SERVICE_ID_ERROR                        CORE_ERROR_CODE(0x2003)
#define SERVICE_WITHOUT_ENTRY_POINT             CORE_ERROR_CODE(0x2004)
#define SERVICE_ALREADY_INITIALISED             CORE_ERROR_CODE(0x2005)
#define SERVICE_ALREADY_RUNNING                 CORE_ERROR_CODE(0x2006)
#define SERVICE_NOT_RUNNING                     CORE_ERROR_CODE(0x2007)
#define SERVICE_NOT_INITIALISED                 CORE_ERROR_CODE(0x2008)
#define SERVICE_HAS_RUNNING_THREADS             CORE_ERROR_CODE(0x2009)
#define SERVICE_ALREADY_PAUSED                  CORE_ERROR_CODE(0x200a)
#define SERVICE_INITIALISATION_ERROR            CORE_ERROR_CODE(0x200b)

#define TSIG_DUPLICATE_REGISTRATION             CORE_ERROR_CODE(0x3001)
#define TSIG_UNABLE_TO_SIGN                     CORE_ERROR_CODE(0x3002)

#define NET_UNABLE_TO_RESOLVE_HOST              CORE_ERROR_CODE(0x4001)
#define TCP_RATE_TOO_SLOW                       CORE_ERROR_CODE(0x4002)

#define CHARON_ERROR_FILE_LOCKED                CORE_ERROR_CODE(0x5001)
#define CHARON_ERROR_NOT_AUTHORISED             CORE_ERROR_CODE(0x5002)
#define CHARON_ERROR_UNKNOWN_ID                 CORE_ERROR_CODE(0x5003)
#define CHARON_ERROR_EXPECTED_MAGIC_HEAD        CORE_ERROR_CODE(0x5004)
#define CHARON_ERROR_INVALID_HEAD               CORE_ERROR_CODE(0x5006)
#define CHARON_ERROR_INVALID_TAIL               CORE_ERROR_CODE(0x5007)
#define CHARON_ERROR_INVALID_COMMAND            CORE_ERROR_CODE(0x5008)
#define CHARON_ERROR_COMMAND_SEQ_MISMATCHED     CORE_ERROR_CODE(0x5009)
#define CHARON_ERROR_UNKNOWN_MAGIC              CORE_ERROR_CODE(0x500a)
#define CHARON_ERROR_ALREADY_RUNNING            CORE_ERROR_CODE(0x500b)
#define CHARON_ERROR_ALREADY_STOPPED            CORE_ERROR_CODE(0x500c)

#define LOGGER_CHANNEL_ALREADY_REGISTERED       CORE_ERROR_CODE(0x6001)
#define LOGGER_CHANNEL_NOT_REGISTERED           CORE_ERROR_CODE(0x6002)
#define LOGGER_CHANNEL_HAS_LINKS                CORE_ERROR_CODE(0x6003)

#define ALARM_REARM                             CORE_ERROR_CODE(0xff00) // KEEP, used by alarm callback functions to automatically re-arm

#define DNS_ERROR_BASE                          0x80030000
#define DNS_ERROR_CODE(code_)                   ((s32)(DNS_ERROR_BASE+(code_)))
#define DOMAIN_TOO_LONG                         DNS_ERROR_CODE(1)    /* FQDN is longer than 255           */
#define INCORRECT_IPADDRESS                     DNS_ERROR_CODE(2)    /* Incorrect ip address              */
#define INCORRECT_RDATA                         DNS_ERROR_CODE(3)

#define LABEL_TOO_LONG                          DNS_ERROR_CODE(10)      /* label is longer than 63                      */
#define INVALID_CHARSET                         DNS_ERROR_CODE(11)      /*                                              */
#define ZONEFILE_INVALID_TYPE                   DNS_ERROR_CODE(12)      /* Type is unknown                              */
#define DOMAINNAME_INVALID                      DNS_ERROR_CODE(13)      /* invalid dnsname usually : double dot         */

#define TSIG_FORMERR                            DNS_ERROR_CODE(14)
#define TSIG_SIZE_LIMIT_ERROR                   DNS_ERROR_CODE(15)

#define TSIG_BADSIG                             DNS_ERROR_CODE(16)      /* TSIG timestamp outisde of the time window    */
#define TSIG_BADKEY                             DNS_ERROR_CODE(17)      /* Unknown key name in TSIG record              */
#define TSIG_BADTIME                            DNS_ERROR_CODE(18)      /* TSIG timestamp outisde of the time window    */
#define TSIG_BADMODE                            DNS_ERROR_CODE(19)
#define TSIG_BADNAME                            DNS_ERROR_CODE(20)
#define TSIG_BADALG                             DNS_ERROR_CODE(21)
#define TSIG_BADTRUNC                           DNS_ERROR_CODE(22)
#define UNPROCESSABLE_MESSAGE                   DNS_ERROR_CODE(23)
#define INVALID_PROTOCOL                        DNS_ERROR_CODE(24)
#define INVALID_RECORD                          DNS_ERROR_CODE(25)
#define UNSUPPORTED_RECORD                      DNS_ERROR_CODE(26)
#define ZONE_ALREADY_UP_TO_DATE                 DNS_ERROR_CODE(27)
#define UNKNOWN_DNS_TYPE                        DNS_ERROR_CODE(28)
#define UNKNOWN_DNS_CLASS                       DNS_ERROR_CODE(29)

//#define INVALID_MESSAGE                         DNS_ERROR_CODE(30)
#define INVALID_MESSAGE                         UNPROCESSABLE_MESSAGE

#define MESSAGE_HAS_WRONG_ID                    DNS_ERROR_CODE(31)
#define MESSAGE_IS_NOT_AN_ANSWER                DNS_ERROR_CODE(32)
#define MESSAGE_UNEXPECTED_ANSWER_DOMAIN        DNS_ERROR_CODE(33)
#define MESSAGE_UNEXPECTED_ANSWER_TYPE_CLASS    DNS_ERROR_CODE(34)
#define MESSAGE_CONTENT_OVERFLOW                DNS_ERROR_CODE(35)
#define MESSAGE_TRUNCATED                       DNS_ERROR_CODE(36)

#define RRSIG_COVERED_TYPE_DIFFERS              DNS_ERROR_CODE(50)
#define RRSIG_OUTPUT_DIGEST_SIZE_TOO_BIG        DNS_ERROR_CODE(51)
#define RRSIG_UNSUPPORTED_COVERED_TYPE          DNS_ERROR_CODE(52)
#define RRSIG_VERIFICATION_FAILED               DNS_ERROR_CODE(53)

#define DNSSEC_ALGORITHM_UNKOWN                     DNS_ERROR_CODE(100)

/// @note EAI error codes are used for getaddrinfo
///
/// @note EAI_ERROR_BADFLAGS error code is used for getaddrinfo through EAI_ERROR_CODE
/// @note EAI_ERROR_NONAME error code is used for getaddrinfo through EAI_ERROR_CODE
/// @note EAI_ERROR_AGAIN error code is used for getaddrinfo through EAI_ERROR_CODE
/// @note EAI_ERROR_FAIL error code is used for getaddrinfo through EAI_ERROR_CODE
/// @note EAI_ERROR_FAMILY error code is used for getaddrinfo through EAI_ERROR_CODE
/// @note EAI_ERROR_SOCKTYPE error code is used for getaddrinfo through EAI_ERROR_CODE
/// @note EAI_ERROR_SERVICE error code is used for getaddrinfo through EAI_ERROR_CODE
/// @note EAI_ERROR_MEMORY error code is used for getaddrinfo through EAI_ERROR_CODE
/// @note EAI_ERROR_SYSTEM error code is used for getaddrinfo through EAI_ERROR_CODE
/// @note EAI_ERROR_OVERFLOW error code is used for getaddrinfo through EAI_ERROR_CODE

#define EAI_ERROR_BASE                          0x80090000
#define EAI_ERROR_CODE(code_)                   ((s32)(EAI_ERROR_BASE+(code_)))

#define EAI_ERROR_BADFLAGS                      EAI_ERROR_CODE(-EAI_BADFLAGS)   /* minus because EAI_ values are < 0 */
#define EAI_ERROR_NONAME                        EAI_ERROR_CODE(-EAI_NONAME)
#define EAI_ERROR_AGAIN                         EAI_ERROR_CODE(-EAI_AGAIN)
#define EAI_ERROR_FAIL                          EAI_ERROR_CODE(-EAI_FAIL)
#define EAI_ERROR_FAMILY                        EAI_ERROR_CODE(-EAI_FAMILY)
#define EAI_ERROR_SOCKTYPE                      EAI_ERROR_CODE(-EAI_SOCKTYPE)
#define EAI_ERROR_SERVICE                       EAI_ERROR_CODE(-EAI_SERVICE)
#define EAI_ERROR_MEMORY                        EAI_ERROR_CODE(-EAI_MEMORY)
#define EAI_ERROR_SYSTEM                        EAI_ERROR_CODE(-EAI_SYSTEM)
#define EAI_ERROR_OVERFLOW                      EAI_ERROR_CODE(-EAI_OVERFLOW)

#define EXIT_CODE_SELFCHECK_ERROR               249
#define EXIT_CODE_OUTOFMEMORY_ERROR             250
#define EXIT_CODE_THREADCREATE_ERROR            251
#define EXIT_CODE_FORMAT_ERROR                  252
#define EXIT_CODE_LOGLEVEL_ERROR                253
#define EXIT_CODE_LOGQUIT_ERROR                 254

/* -----------------------------------------------------------------------------
 *
 *      PROTOTYPES
 */

void dief(ya_result error_code, const char *format, ...);

/**
 *
 * Release the memory used by the error table
 * 
 */

void error_unregister_all();

void error_register(ya_result code, const char * const text);

/**
 * @brief Returns the string associated to an error code
 *
 * Returns the string associated to an error code
 * 
 * This is NOT thread-safe.  Only to be used 
 *
 * @param[in] err the ya_result error code
 *
 * @return a pointer to the error message
 */

const char* error_gettext(ya_result code);

struct output_stream;

void error_writetext(struct output_stream *os, ya_result code);

void dnscore_register_errors();

ya_result ya_ssl_error();

#define DIE(code) dief((code), "%s:%i\n", __FILE__, __LINE__);abort()
#define DIE_MSG(msg) dief(ERROR, "%s:%i %s\n", __FILE__, __LINE__, (msg));abort()

#endif /* ERROR_H_ */

/** @} */

