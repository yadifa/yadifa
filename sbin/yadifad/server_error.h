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
/** @defgroup server Server
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#ifndef _SERVER_ERROR_H
#define	_SERVER_ERROR_H

#ifdef	__cplusplus
extern "C"
{
#endif

/*    ------------------------------------------------------------
 *
 *      VALUES
 */

#define		YDF_ERROR_BASE				0x80080000
#define		YDF_ERROR_CODE(code_)			((s32)(YDF_ERROR_BASE+(code_)))

/* Main errorcodes */
#define		YDF_ERROR_CONFIGURATION         YDF_ERROR_CODE( 2)      /* Error in configuration                   */

#define		YDF_ERROR_CHOWN			YDF_ERROR_CODE( 3)     /* Can change owner of file                 */

#define		VALUE_FOUND             YDF_ERROR_CODE( 4)     /* Pointer is not empty                     */

#define		FILE_NOT_FOUND_ERR      YDF_ERROR_CODE(20)     /* No file found                            */
#define     FILE_OPEN_ERR           YDF_ERROR_CODE(21)     /* Error opening file                       */
#define     FILE_CLOSE_ERR          YDF_ERROR_CODE(22)     /* Error closing file                       */
#define     FILE_READ_ERR           YDF_ERROR_CODE(23)     /* Error reading file                       */
#define     FILE_WRITE_ERR          YDF_ERROR_CODE(24)     /* Error writing file                       */
#define     FILE_CHOWN_ERR          YDF_ERROR_CODE(25)     /* Error changing owner of file             */

#define     ZONE_LOAD_MASTER_TYPE_EXPECTED          YDF_ERROR_CODE(30)
#define     ZONE_LOAD_MASTER_ZONE_FILE_UNDEFINED    YDF_ERROR_CODE(31)
#define     ZONE_LOAD_SLAVE_TYPE_EXPECTED           YDF_ERROR_CODE(40)
    
#define     ANSWER_NOT_ACCEPTABLE   YDF_ERROR_CODE(50)
#define     ANSWER_UNEXPECTED_EOF   YDF_ERROR_CODE(51)
    
#define     NOTIFY_ANSWER_NOT_AA    YDF_ERROR_CODE(1025)
#define     NOTIFY_QUERY_TO_MASTER  YDF_ERROR_CODE(1026)
#define     NOTIFY_QUERY_TO_UNKNOWN YDF_ERROR_CODE(1027)
#define     NOTIFY_QUERY_FROM_UNKNOWN YDF_ERROR_CODE(1028)
    
#define     EXIT_CONFIG_ERROR                10
#define     EXIT_CODE_DATABASE_LOAD_ERROR    11
#define     EXIT_CODE_SYSCLEANUP_ERROR       12


#ifdef	__cplusplus
}
#endif

#endif	/* _SERVER_ERROR_H */

/*    ------------------------------------------------------------    */

/** @} */

