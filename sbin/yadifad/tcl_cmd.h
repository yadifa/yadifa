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
/** @defgroup ### #######
 *  @ingroup yadifad
 *  @brief
 *
 * @{
 */
/*----------------------------------------------------------------------------*/

#ifndef TCL_CMD_H_
#define TCL_CMD_H_
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include	<config.h>
#include	<stdlib.h>
#include	<string.h>
#include        <tcl.h>

/*    ------------------------------------------------------------
 *
 *      VALUES
 */
#define		YA_TCLPROMPT		"puts -nonewline \""PACKAGE"-%s$ \""
#define		YA_TCLRCFILE		PACKAGE".tcl"

/*    ------------------------------------------------------------
 *
 *      ENUM
 */


/*    ------------------------------------------------------------
 *
 *      MACROS
 */

/*    ------------------------------------------------------------
 *
 *      STRUCTS
 */

/*    ------------------------------------------------------------
 *
 *      PROTOTYPES
 */
int Tcl_AppInit(Tcl_Interp *interp);
int TclCommandsInit(Tcl_Interp *interp);
int tcl_tcltest(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]);


/*    ------------------------------------------------------------    */

#endif /* TCL_CMD_H_ */


/*    ------------------------------------------------------------    */

/** @} */
