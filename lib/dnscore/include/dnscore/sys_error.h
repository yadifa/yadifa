/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011, EURid. All rights reserved.
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
 * DOCUMENTATION */
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

#if !defined(_SYSTYPES_H)
#error Included from a disallowed place.
#endif


#define SUCCESS                         0
#define OK                              0

/* The basic error code */
/* In the source, "return ERROR;" should be replaced by something more specific */

#define ERROR                           -1
#define NOK				                -1

/* Two macros to easily check an error status */

#define FAIL(result) ((result)<0)
#define ISOK(result) ((result)>=0)

/* 16 most significant bits : GROUP, the sign bit being ALWAYS set
 * 16 least significant bits : ID
 */

#define ERRNO_ERROR_BASE                0x80000000
#define ERRNO_ERROR                     ((s32)(ERRNO_ERROR_BASE+errno))
#define MAKE_ERRNO_ERROR(err_)          ((s32)(ERRNO_ERROR_BASE+(err_)))

#define EXITFAIL(x) if((x)<0) {DIE(ERROR);exit(EXIT_FAILURE);}

#define DNSMSG_ERROR_BASE               0xc0000000
#define MAKE_DNSMSG_ERROR(err_)         ((s32)(DNSMSG_ERROR_BASE+(err_)))

/* -----------------------------------------------------------------------------
 *
 *   STRUCTS
 */

typedef int32_t ya_result;

#define SERVER_ERROR_BASE                       0x80010000
#define SERVER_ERROR_CODE(code_)                ((s32)(SERVER_ERROR_BASE+(code_)))
#define SERVER_ERROR_GETCODE(error_)            ((error_)&0xffff)

#define CORE_ERROR_BASE                         0x80020000
#define CORE_ERROR_CODE(code_)                  ((s32)(CORE_ERROR_BASE+(code_)))
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

#define TCP_RATE_TOO_SLOW                       CORE_ERROR_CODE(0x1085)


#define LOGGER_INITIALISATION_ERROR             CORE_ERROR_CODE(1)
#define COMMAND_ARGUMENT_EXPECTED               CORE_ERROR_CODE(2)
#define OBJECT_NOT_INITIALIZED                  CORE_ERROR_CODE(3)
#define FORMAT_ALREADY_REGISTERED               CORE_ERROR_CODE(4)
#define STOPPED_BY_APPLICATION_SHUTDOWN         CORE_ERROR_CODE(5)

#define UNABLE_TO_COMPLETE_FULL_READ            CORE_ERROR_CODE(11)

#define UNEXPECTED_EOF                          CORE_ERROR_CODE(12)
#define UNSUPPORTED_TYPE                        CORE_ERROR_CODE(13)
#define UNKNOWN_NAME                            CORE_ERROR_CODE(14)     /* name->value table */
#define BIGGER_THAN_MAX_PATH                    CORE_ERROR_CODE(15)

#define THREAD_CREATION_ERROR                   CORE_ERROR_CODE(0x2001)
#define THREAD_DOUBLEDESTRUCTION_ERROR          CORE_ERROR_CODE(0x2002)
#define SERVICE_ID_ERROR                        CORE_ERROR_CODE(0x2003)
#define SERVICE_WITHOUT_ENTRY_POINT             CORE_ERROR_CODE(0x2004)
#define SERVICE_ALREADY_INITIALISED             CORE_ERROR_CODE(0x2005)
#define SERVICE_ALREADY_RUNNING                 CORE_ERROR_CODE(0x2006)
#define SERVICE_NOT_RUNNING                     CORE_ERROR_CODE(0x2007)

#define TSIG_DUPLICATE_REGISTRATION             CORE_ERROR_CODE(0x3001)
#define TSIG_UNABLE_TO_SIGN                     CORE_ERROR_CODE(0x3002)

#define NET_UNABLE_TO_RESOLVE_HOST              CORE_ERROR_CODE(0x4001)

#define CHARON_ERROR_FILE_LOCKED                CORE_ERROR_CODE(0x5001)
#define CHARON_ERROR_NOT_AUTHORISED             CORE_ERROR_CODE(0x5002)
#define CHARON_ERROR_UNKNOWN_ID                 CORE_ERROR_CODE(0x5003)

#define ALARM_REARM                             CORE_ERROR_CODE(0xff00)

#define DNS_ERROR_BASE                          0x80030000
#define DNS_ERROR_CODE(code_)                   ((s32)(DNS_ERROR_BASE+(code_)))
#define DOMAIN_TOO_LONG                         DNS_ERROR_CODE(1)    /* FQDN is longer than 255           */
#define INCORRECT_IPADDRESS                     DNS_ERROR_CODE(2)    /* Incorrect ip address              */
#define INCORRECT_RDATA                         DNS_ERROR_CODE(3)
#define SALT_TO_BIG                             DNS_ERROR_CODE(4)
#define SALT_NOT_EVEN_LENGTH                    DNS_ERROR_CODE(5)
#define HASH_TOO_BIG                            DNS_ERROR_CODE(6)
#define HASH_NOT_X8_LENGTH                      DNS_ERROR_CODE(7)   /* Actually it's not "multiple of 8" length */
#define HASH_TOO_SMALL                          DNS_ERROR_CODE(8)
#define HASH_BASE32DECODE_FAILED                DNS_ERROR_CODE(9)
#define HASH_BASE32DECODE_WRONGSIZE             DNS_ERROR_CODE(10)
#define ZONEFILE_UNSUPPORTED_TYPE               DNS_ERROR_CODE(11)      /* Type is unknown                              */
#define LABEL_TOO_LONG                          DNS_ERROR_CODE(12)      /* label is longer than 63                      */
#define INVALID_CHARSET                         DNS_ERROR_CODE(13)      /*                                              */
#define NO_LABEL_FOUND                          DNS_ERROR_CODE(14)      /* No labels found empty domain name            */
#define NO_ORIGIN_FOUND                         DNS_ERROR_CODE(15)      /* No origin found where we should              */
#define DOMAINNAME_INVALID                      DNS_ERROR_CODE(16)      /* invalid dnsname usually : double dot         */
#define TSIG_BADKEY                             DNS_ERROR_CODE(17)      /* Unknown key name in TSIG record              */
#define TSIG_BADTIME                            DNS_ERROR_CODE(18)      /* TSIG timestamp outisde of the time window    */
#define TSIG_BADSIG                             DNS_ERROR_CODE(19)      /* TSIG timestamp outisde of the time window    */
#define TSIG_FORMERR                            DNS_ERROR_CODE(20)
#define TSIG_SIZE_LIMIT_ERROR                   DNS_ERROR_CODE(21)
#define UNPROCESSABLE_MESSAGE                   DNS_ERROR_CODE(22)
#define MESSAGE_ALREADY_PROCESSED               DNS_ERROR_CODE(23)      /* CH & cie */
#define INVALID_PROTOCOL                        DNS_ERROR_CODE(24)
#define INVALID_RECORD                          DNS_ERROR_CODE(25)
#define UNSUPPORTED_RECORD                      DNS_ERROR_CODE(26)
#define ZONE_ALREADY_UP_TO_DATE                 DNS_ERROR_CODE(27)

#define INVALID_MESSAGE                         DNS_ERROR_CODE(30)

#define MESSAGE_HAS_WRONG_ID                    DNS_ERROR_CODE(31)
#define MESSAGE_IS_NOT_AN_ANSWER                DNS_ERROR_CODE(32)
#define MESSAGE_UNEXCPECTED_ANSWER_DOMAIN       DNS_ERROR_CODE(33)
#define MESSAGE_UNEXCPECTED_ANSWER_TYPE_CLASS   DNS_ERROR_CODE(34)

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

void error_register(ya_result code, const char *text);

/**
 * @brief Returns the string associated to an error code
 *
 * Returns the string associated to an error code
 *
 * @param[in] err the ya_result error code
 *
 * @return a pointer to the error message
 */


const char* error_gettext(ya_result code);

struct output_stream;

void error_writetext(struct output_stream *os, ya_result code);

void dnscore_register_errors();

#define DIE(code) dief((code), "%s:%i\n", __FILE__, __LINE__)
#define DIE_MSG(msg) dief(ERROR, "%s:%i %s\n", __FILE__, __LINE__, (msg))

#endif /* ERROR_H_ */

/** @} */

/*----------------------------------------------------------------------------*/

