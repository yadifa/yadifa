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
*/
/** @defgroup hintsfile Zone file loader module
 *  @ingroup dnshints
 *  @brief Zone file loader module
 *
 *  Implementation of routines for the hints_data struct
 *   - add
 *   - adjust
 *   - init
 *   - parse
 *   - print
 *   - remove database
 *
 * @{
 */
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>		/* or netinet/in.h */

#include <dnscore/format.h>
#include <dnscore/logger.h>
#include <dnscore/buffer_input_stream.h>
#include <dnscore/file_input_stream.h>

#include "dnszone/hints_file_reader.h"

#define ZFREADER_TAG 0x524544414552465a

/** \def ttl value used for the zone hints if none provided */
#define		DEFAULT_TTL             86400
#define		DOT_DOMAIN              "."

#define		BRACKET_CLOSED          0x00U
#define		BRACKET_OPEN            0x01U
/**  flag settings for printing the zone hints
 * \param 0 means not printing of the resource records
 * \param 1 means printing of the resource records
 */
#define		WITHOUT_RR		        0
#define		WITH_RR                 1


#ifndef NAME_MAX
#define NAME_MAX 1024
#endif

#define MAX_LINE_SIZE 1024

extern logger_handle *g_zone_logger;
#define MODULE_MSG_HANDLE g_zone_logger

/****************************************************************************************************/
/* Parsing											    */
/*												    */
/* These are the parsing functions used by the text-form hints file loader.			    */
/* It is NOT the right place for them.  It would be better to have a parser in the core so both the */
/* dnshints and the server can use it.								    */
/*												    */
/****************************************************************************************************/

/***************************************************************************************************/

typedef struct hints_file_reader hints_file_reader;
struct hints_file_reader
{
    input_stream ins;
    
    /* Domain name of the hints file */  /* LOAD */
    u8 *origin;                         /* LOAD */
    /* Resource record data */          /* LOAD */
    resource_record *rr;                /* LOAD */
    u32 default_ttl;                    /* LOAD */
    u32 line_number;                    /* LOAD */
    int bracket_status;                 /* LOAD */
    u16 qclass;
    u8  label[MAX_DOMAIN_LENGTH];       /* LOAD */
};

static ya_result
hints_file_reader_unread_record(zone_reader *zr, resource_record *entry)
{
    return ERROR; // not implemented
}

/** @brief Reads a ZDB hints file entry
 *
 *  Reads a ZDB hints file entry
 *
 *  @param[in]  hints a pointer to a valid (hints_file_open'ed) hints-file structure
 *  @param[out] entry a pointer to a hintsfile_entry structure that will hold the record
 *
 *  @return     A result code
 *  @retval     OK : a record has been read successfully
 *  @retval     else : an error occurred
 */
static ya_result
hints_file_reader_read_record(zone_reader *zr, resource_record *entry)
{
    return ERROR; // not implemented
}

static ya_result
hints_file_reader_free_record(zone_reader *hints, resource_record *entry)
{
    return ERROR;
}

/** @brief Closes a hints file entry
 *
 *  Closes a hints file entry.  The function will do nothing if the hintsfile has already been closed
 *
 *  @param[in] hintsfile a pointer to a valid (hints_file_open'ed) hints-file structure
 *
 */
static void
hints_file_reader_close(zone_reader *zr)
{
   
}

static bool
hints_file_reader_canwriteback(zone_reader *zr)
{
    return TRUE;
}

static void
hints_file_reader_handle_error(zone_reader *zr, ya_result error_code)
{
    /* nop */
}

static zone_reader_vtbl hints_file_reader_vtbl =
{
    hints_file_reader_read_record,
    hints_file_reader_unread_record,
    hints_file_reader_free_record,
    hints_file_reader_close,
    hints_file_reader_handle_error,
    hints_file_reader_canwriteback,
    "hints_file_reader"
};

/** @brief Initializing hints_data variable
 *
 *  The function not only initialize a new hints_data struct, but if needed
 *  will add the struct to the linked list
 *
 *  @param[in,out] dst the new hints_data struct
 *
 *  @retval OK
 */
	/* BUT ALSO ... */
/** @brief Opens a hints file
 *
 *  Opens a hints file
 *
 *  @param[in]  fullpath the path and name of the file to open
 *  @param[out] hints a pointer to a structure that will be used by the function
 *              to hold the hints-file information
 *
 *  @return     A result code
 *  @retval     OK   : the file has been opened successfully
 *  @retval     else : an error occurred
 */
ya_result
hints_file_reader_open(const char* fullpath, zone_reader *dst)
{
    (void)&hints_file_reader_vtbl;
    return ERROR;
}


/** @} */

/*----------------------------------------------------------------------------*/
