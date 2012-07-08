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
/** @defgroup config Configuration handling
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/
#ifndef _CONFIG_ERROR_H
#define	_CONFIG_ERROR_H

#ifdef	__cplusplus
extern "C"
{
#endif

#define     CFG_ERROR_BASE            0x80070000
#define     CFG_ERROR_CODE(code_)     ((s32)(CFG_ERROR_BASE+(code_)))

#define	    CFG_LINE_LIMIT_REACHED      CFG_ERROR_CODE(1)

    /* Config errorcodes */
#define     NO_DATAPATH_FOUND           CFG_ERROR_CODE(30)	/* No data path is empty                    */
#define     NO_VARIABLE_FOUND           CFG_ERROR_CODE(31)	/* No variable param found in config file   */
#define     NO_VALUE_FOUND              CFG_ERROR_CODE(32)	/* No value param found in config file      */
#define     NO_ARGUMENT_FOUND           CFG_ERROR_CODE(33)	/* No argument param found in config file   */
#define     INCORRECT_CONFIG_LINE       CFG_ERROR_CODE(34)	/* Problems with some of the params         */
#define     CONFIG_FILE_OPEN_FAILED     CFG_ERROR_CODE(35)	/* config file open failed */
#define     CONFIG_FILE_INCL_FAILED     CFG_ERROR_CODE(36)	/* config file open failed */
#define     CONFIG_FILE_BROKEN_TAG      CFG_ERROR_CODE(37)	/* config tag didn't end with > */
#define     CONFIG_FILE_BAD_CONT_END 	CFG_ERROR_CODE(38)	/* config unexpected container end found */
#define     CONFIG_FILE_BAD_CONT_START 	CFG_ERROR_CODE(39)	/* config unexpected container start found */
#define     CONFIG_FILE_BAD_KEYWORD     CFG_ERROR_CODE(40)  /* config found an unknown keyword outside the containers */

#define     CONFIG_ZONE_ERR             CFG_ERROR_CODE(50)	/* Error in config file */
#define     CONFIG_BAD_UID_ERR          CFG_ERROR_CODE(51)	/* Error in config file */
#define     CONFIG_BAD_GID_ERR          CFG_ERROR_CODE(52)	/* Error in config file */
#define     CONFIG_EMPTY_PATH_ERR       CFG_ERROR_CODE(53)	/* Error in config file */
#define     CONFIG_UNKNOWN_SETTING_ERR  CFG_ERROR_CODE(54)	/* Error in config file */
#define     CONFIG_ZONE_CHAIN_ERR       CFG_ERROR_CODE(55)

#define     CONFIG_KEY_WRONG_FIELD      CFG_ERROR_CODE(56)
#define     CONFIG_KEY_INCOMPLETE_KEY   CFG_ERROR_CODE(57)
#define     CONFIG_KEY_UNSUPPORTED_ALGORITHM CFG_ERROR_CODE(58)
#define     CONFIG_ZONE_DNSSEC_CONFLICT CFG_ERROR_CODE(59)

#define     NO_CLASS_FOUND		CFG_ERROR_CODE(61)	/* No class found in resource record        */
#define     DIFFERENT_CLASSES		CFG_ERROR_CODE(62)	/* Different classes found in one zone file */
#define     WRONG_APEX			CFG_ERROR_CODE(63)	/* The first type in a zone file must be SOA */
#define     DUPLICATED_SOA		CFG_ERROR_CODE(64)	/* Only one soa type in a zone file          */
#define     INCORRECT_TTL		CFG_ERROR_CODE(65)	/* ttl is a incorrect number                 */
#define     INCORRECT_ORIGIN		CFG_ERROR_CODE(66)	/* Origin is not a correct fqdn with a dot   */
//#define     NO_ORIGIN_FOUND           CFG_ERROR_CODE(67)	/* No origin found where we should           */

#define     NO_TYPE_FOUND		CFG_ERROR_CODE(69)     /* No type found in resource record          */
#define     INCORRECT_RR		CFG_ERROR_CODE(70)     /* As it says "INCORRECT"                    */
#define     DUPLICATED_CLOSED_BRACKET	CFG_ERROR_CODE(71)     /* More than 1 closed bracket found in rdata */
#define     DUPLICATED_OPEN_BRACKET	CFG_ERROR_CODE(72)     /* More than 1 open bracket found in rdata   */
#define     INCORRECT_LABEL_LEN		CFG_ERROR_CODE(74)     /* Length of label bigger than 63 */
#define     INCORRECT_DOMAIN_LEN	CFG_ERROR_CODE(75)     /* Length of domain bigger than 255 */
#define     INCORRECT_DOMAINNAME	CFG_ERROR_CODE(76)     /* Not accepted character in domain name     */
//#define     NO_LABEL_FOUND            CFG_ERROR_CODE(78)     /* No labels found empty domain name         */
#define     INCORRECT_PREFERENCE	CFG_ERROR_CODE(79)

    /* Zone errorcondes */
#define     SOA_PARSING_ERR		CFG_ERROR_CODE(90)     /* Error parsing SOA RR                     */
#define     NO_SOA_FOUND_ERR		CFG_ERROR_CODE(91)     /* No SOA RR at the begining                */
#define     BRACKET_OPEN_ERR		CFG_ERROR_CODE(92)     /* No closing bracket in for RR             */
#define     PARSING_RR_ERR		CFG_ERROR_CODE(93)	 /* Error parsing RR                         */
#define     QNAME_LEN_ERR		CFG_ERROR_CODE(94)     /* Qname is too long or does not exist      */

#define     CONFIG_CHANNEL_DUPLICATE    CFG_ERROR_CODE(101)
#define     CONFIG_CHANNEL_UNDEFINED    CFG_ERROR_CODE(102)
#define     CONFIG_INVALID_DEBUGLEVEL   CFG_ERROR_CODE(103)
#define     CONFIG_LOGGER_UNDEFINED     CFG_ERROR_CODE(104)

#define     CONFIG_WRONG_SIG_TYPE       CFG_ERROR_CODE(201)
#define     CONFIG_WRONG_SIG_VALIDITY   CFG_ERROR_CODE(202)
#define     CONFIG_WRONG_SIG_REGEN      CFG_ERROR_CODE(203)

#define     DATABASE_ZONE_NOT_FOUND     CFG_ERROR_CODE(300)
#define     DATABASE_ZONE_MISSING_DOMAIN CFG_ERROR_CODE(301)
#define     DATABASE_ZONE_MISSING_MASTER CFG_ERROR_CODE(302)
#define     DATABASE_ZONE_CONFIG_DUP    CFG_ERROR_CODE(304)
#define     DATABASE_EMPTY              CFG_ERROR_CODE(305)

#ifdef	__cplusplus
}
#endif

#endif	/* _CONFIG_ERROR_H */

/*    ------------------------------------------------------------    */

/** @} */

/*----------------------------------------------------------------------------*/
