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
/** @ingroup yadifad
 *
 */
/*----------------------------------------------------------------------------*/
#ifndef LIST_H_
#define LIST_H_

/*    ------------------------------------------------------------
 *
 *      INCLUDES
 */

#include	<stdio.h>
#include	<string.h>

#define     MAX_LINE_SIZE    1024

/* it depends if host is DARWIN or LINUX */
#ifdef HAVE_SYS_SYSLIMITS_H
#include        <sys/syslimits.h>
#elif HAVE_LINUX_LIMITS_H
#include        <linux/limits.h>
#endif /* HAVE_SYS_SYSLIMITS_H */

#ifdef HAVE_I386_TYPES_H
#include        <i386/types.h>
#elif HAVE_SYS_TYPES_H
#include        <sys/types.h>
#endif /* HAVE_I386_TYPES_H */

#ifdef HAVE_PPC_LIMITS_H
#include        <ppc/limits.h>
#endif /* HAVE_PPC_LIMITS_H */

#ifdef HAVE_I386_LIMITS_H
#include        <i386/limits.h>
#endif /* HAVE_I386_LIMITS_H */

#if 1
#include	"wrappers.h"
#endif

#include <dnscore/output_stream.h>

#include	"config.h"

/*    ------------------------------------------------------------
 *
 *      STRUCTS
 */

/* Linked list for interface data */
struct list_data
{
    char data[MAX_LINE_SIZE];
    struct list_data *next;
};
typedef struct list_data list_data;

/*    ------------------------------------------------------------
 *
 *      PROTOTYPES
 */
int list_add(list_data **, const char *);
void list_remove(list_data **);
void list_remove_all(list_data **);
list_data ** list_search(list_data **, const char *);
void list_print(list_data *, const char *, output_stream*);
size_t list_length(list_data *);

/*    ------------------------------------------------------------    */

#endif /* LIST_H_ */

