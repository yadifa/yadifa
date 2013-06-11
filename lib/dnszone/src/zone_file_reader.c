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
/** @defgroup zonefile Zone file loader module
 *  @ingroup dnszone
 *  @brief Zone file loader module
 *
 *  Implementation of routines for the zone_data struct
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
#include <dnscore/bytearray_output_stream.h>

#include "dnszone/zone_file_reader.h"

#define ZFREADER_TAG 0x524544414552465a

#ifndef NAME_MAX
#define NAME_MAX 1024
#endif

#define MAX_LINE_SIZE 1024

extern logger_handle *g_zone_logger;
#define MODULE_MSG_HANDLE g_zone_logger

/****************************************************************************************************/
/* Parsing											    */
/*												    */
/* These are the parsing functions used by the text-form zone file loader.			    */
/* It is NOT the right place for them.  It would be better to have a parser in the core so both the */
/* dnszone and the server can use it.								    */
/*												    */
/****************************************************************************************************/

#define TRIM_RR_LINE2(ptr)                                       \
    remove_comment((char *)ptr, ';');                            \
    remove_whitespace_from_right((char *)ptr);

#define SKIP_WORD(ptr)                                           \
    while(!isspace((char)*ptr))                                  \
    {                                                            \
        ptr++;                                                   \
    }                                                            \
    ++ptr;

/** \brief Remove comments at the end of the line
 *
 *  @param[in,out] p string to be trimmed of the comments
 *  @param[in] token is charackter that gives the start of the comment
 */
static void
remove_comment(char *p, const char token)
{
    char *end_p;

    /*    ------------------------------------------------------------    */

    end_p = p;

    while((*end_p != token) && (*end_p != '\0'))
    {
        end_p++;
    }
    *end_p = '\0';
}

/** \brief  Remove white space at the end of the line before the comments
 *
 *  @param[in,out] p string to be trimmed of the white-space at the right
 */
static void
remove_whitespace_from_right(char *p)
{
    char *end_p;

    /*    ------------------------------------------------------------    */

    end_p = p + strlen(p) - 1;	/* if |p|==0 the -1 offset will be dodged by the while test */

    while((end_p >= p) && isspace(*end_p))
    {
        --end_p;
    }
    *(++end_p) = '\0';
}


/***************************************************************************************************/

typedef struct zone_file_reader zone_file_reader;
struct zone_file_reader
{
    /** @todo The zone data is a persistent information along with loading context information. Maybe it should be splitted.
     */

    //FILE *file_handle;                  /* LOAD */
    input_stream ins;
    
    /* Domain name of the zone file */  /* LOAD */
    u8 *origin;                         /* LOAD */
    /* Resource record data */          /* LOAD */
    resource_record *rr;                /* LOAD */
    u32 default_ttl;                    /* LOAD */
    u32 line_number;                    /* LOAD */
    int bracket_status;                 /* LOAD */
    u16 qclass;
    bool soa_found;                     /* LOAD */
    u8  label[MAX_DOMAIN_LENGTH];       /* LOAD */
};

/** @brief Reads a ZDB zone file entry
 *
 *  Reads a ZDB zone file entry
 *
 *  @param[in]  zone a pointer to a valid (zone_file_open'ed) zone-file structure
 *  @param[out] entry a pointer to a zonefile_entry structure that will hold the record
 *
 *  @return     A result code
 *  @retval     OK : a record has been read successfully
 *  @retval     else : an error occurred
 */
static ya_result
zone_file_reader_read_record(zone_reader *zr, resource_record *entry)
{
    zassert((zr != NULL) && (entry != NULL));

    zone_file_reader *zone = (zone_file_reader*)zr->data;

    /*    ------------------------------------------------------------    */

    char                                                     *needle = NULL;
    
    ya_result                                              return_code = OK;
    u32                                                     soa_min_ttl = 0;
    bool                                            default_ttl_set = FALSE;
    char                                                line[MAX_LINE_SIZE];
    char                                                      line_bak[160];

    /*    ------------------------------------------------------------    */

    /* reset resource record entry */

    entry->type     = 0;

    entry->rdata[0] = '\0';
    
    //while(NULL != fgets(line, MAX_LINE_SIZE, zone->file_handle))
    
    while(buffer_input_stream_read_line(&zone->ins, line, sizeof(line)) > 0)
    {
        zone->line_number++;
	
        /* If comment at the beginning of the line, skip the line completely */
        if((line[0] == '#') || (line[0] == ';'))
        {
            continue;
        }

        /* Remove unwanted comments and white spaces at the end of the line */
        TRIM_RR_LINE2(line);
        /* Check empty line */

        size_t line_len = strlen(line);

        if(line_len == 0)
        {
            continue;
        }

        memcpy(line_bak, line, MIN(line_len + 1, sizeof(line_bak)));
        line_bak[sizeof(line_bak) - 1] = '\0';

        /* Check for $ORIGIN directive */
        if(*line == '$')
        {
            if((needle = strstr(line, "$ORIGIN")) != 0)
            {
                SKIP_WORD(needle);

                if(FAIL(return_code = rr_get_origin(needle, &zone->origin)))
                {
                    log_err("zone file: parse: origin error at line %i: '%s': %r", zone->line_number, line_bak, return_code);

                    return return_code;
                }

                /* If okay reset label */
                zone->label[0] = '\0';	    /* label cannot be NULL : it's static */

                continue;
            }
            else if((needle = strstr(line, "$TTL")) != 0) /* Check for $TTL directive */
            {
                SKIP_WORD(needle);
                
                u32 default_ttl = 0;

                if(FAIL(return_code = rr_get_ttl(needle, &default_ttl)))
                {
                    log_err("zone file: parse: $TTL error at line %i: '%s': %r", zone->line_number, line_bak, return_code);

                    return return_code;
                }
                
                // this should never be triggered because rr_get_ttl did some filtering already
                
                if(default_ttl > MAX_S32) // ensures [0; 2^31 - 1]
                {
                    /* rfc 2181
                     * Implementations should treat TTL values received with the most
                     * significant bit set as if the entire value received was zero.
                     */
                    
                    log_warn("zone file: parse: $TTL=%u out of range at line %i (setting to 0)", default_ttl, zone->line_number);
                    default_ttl = 0;
                }
                
                if(default_ttl <= soa_min_ttl)
                {
                    log_warn("zone file: parse: $TTL=%d less or equal to negative-caching/minimum TTL at line %i, consider changing it", default_ttl, soa_min_ttl, zone->line_number);
                }
                
                zone->default_ttl = default_ttl;
                
                default_ttl_set = TRUE;
                
                continue;
            }
            else if((needle = strstr(line, "$INCLUDE")) != 0)
            {
#if 1
                log_err("zone file: parse: $INCLUDE not supported");
                return ERROR;
#endif
                SKIP_WORD(needle);
                continue;
            }
            else if((needle = strstr(line, "$GENERATE")) != 0)
            {
#if 1
                log_err("zone file: parse: $GENERATE not supported");
                return ERROR;
#endif

                SKIP_WORD(needle);
                continue;
            }
            else
            {
                /* parse error ? */
            }
        }

        /* Must be a resource record so parse it */
        if(FAIL(return_code = rr_parse_line(line, zone->origin,
                        zone->label,
                        zone->default_ttl, entry,
                        &zone->bracket_status)))
        {
            log_err("zone file: parse: error at line %i: '%s': %r", zone->line_number, line_bak, return_code);
	    
            return return_code;
        }

        /* We have the full resource record(s) and the bracket_status is closed */
        if(zone->bracket_status == BRACKET_CLOSED)
        {
            if(zone->qclass == 0)
            {
                if(entry->class != 0)
                {
                    zone->qclass = entry->class;
                }
                else
                {
                    log_err("zone file: parse: class error at line %i: '%s': %r", zone->line_number, line_bak, ZRE_NO_CLASS_FOUND);

                    return ZRE_NO_CLASS_FOUND;
                }
            }
            else
            {
                /* Check for existing class */
                if(entry->class == 0)
                {
                    entry->class = zone->qclass;
                }
                else if(entry->class != zone->qclass)
                {
                    log_err("zone file: parse: class error at line %i: '%s': %r", zone->line_number, line_bak, ZRE_DIFFERENT_CLASSES);

                    return ZRE_DIFFERENT_CLASSES;
                }
            }

            /* Init SOA type found marker */
            if(!zone->soa_found)
            {
                /* First resource record  must be of "type" SOA */
                if(entry->type != TYPE_SOA)
                {
                    log_err("zone file: parse: apex error at line %i: '%s': %r", zone->line_number, line_bak, ZRE_WRONG_APEX);

                    return ZRE_WRONG_APEX;
                }
                
                zone->soa_found = TRUE;
                
                /*
                 * ensure $TTL is not SOA min-ttl/negative-caching ttl
                 */
                
                const u8 *p = (const u8*)bytearray_output_stream_buffer(&entry->os_rdata);
                const u8 *limit = p + bytearray_output_stream_size(&entry->os_rdata);
                
                p += dnsname_len(p);
                p += dnsname_len(p);
                if(&p[20] == limit)
                {
                    u32 min_ttl = ntohl(GET_U32_AT(p[16]));

                    if(default_ttl_set && (zone->default_ttl <= min_ttl))
                    {
                        log_warn("zone file: parse: default TTL of %d equals the negative-caching/minimum TTL found in the SOA", zone->default_ttl);
                    }
                    else
                    {
                        // silently change the default_ttl

                        zone->default_ttl = MIN(min_ttl + 1, MAX_S32);
                    }
                }
                else
                {
                    log_err("zone file: parse: error parsing SOA record at line %i", zone->line_number);
                    
                    return PARSESTRING_ERROR;
                }
            }
            else
            {
                if(entry->type == TYPE_SOA)
                {
                    log_err("zone file: parse: SOA error at line %i: '%s': %r", zone->line_number, line_bak, ZRE_DUPLICATED_SOA);

                    return ZRE_DUPLICATED_SOA;
                }
            }
            return OK;
        }
    }

    return 1;
}

static ya_result
zone_file_reader_free_record(zone_reader *zone, resource_record *entry)
{
    return OK;
}

/** @brief Closes a zone file entry
 *
 *  Closes a zone file entry.  The function will do nothing if the zonefile has already been closed
 *
 *  @param[in] zonefile a pointer to a valid (zone_file_open'ed) zone-file structure
 *
 */
static void
zone_file_reader_close(zone_reader *zr)
{
    zassert(zr != NULL);

    zone_file_reader *zone = (zone_file_reader*)zr->data;

    free(zone->origin);


#if (DNSDB_USE_POSIX_ADVISE != 0) && (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L)
    int fd = fd_input_stream_get_filedescriptor(&zone->ins);
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif

    input_stream_close(&zone->ins);

    free(zone);
    
    zr->data = NULL;
    zr->vtbl = NULL;
}

static void
zone_file_reader_handle_error(zone_reader *zr, ya_result error_code)
{
    /* nop */
}

static zone_reader_vtbl zone_file_reader_vtbl =
{
    zone_file_reader_read_record,
    zone_file_reader_free_record,
    zone_file_reader_close,
    zone_file_reader_handle_error,
    "zone_file_reader"
};


ya_result
zone_file_reader_parse_stream(input_stream *ins, zone_reader *dst)
{
    zone_file_reader *zone;
    
    /*    ------------------------------------------------------------    */
    
    MALLOC_OR_DIE(zone_file_reader*, zone, sizeof (zone_file_reader), ZFREADER_TAG);

    ZEROMEMORY(zone, sizeof (zone_file_reader));

    buffer_input_stream_init(ins,&zone->ins, 4096);
    
    zone->origin    = NULL;
    zone->rr        = NULL;
    zone->line_number = 0;
    /*zone->type        = 1;*/
    zone->qclass      = 0;
    zone->default_ttl = 86400;      // should be at least one day and different than min-ttl
    zone->bracket_status = 0;
    zone->soa_found   = FALSE;

    dst->data = zone;
    dst->vtbl = &zone_file_reader_vtbl;

    return OK;
}

/** @brief Initializing zone_data variable
 *
 *  The function not only initialize a new zone_data struct, but if needed
 *  will add the struct to the linked list
 *
 *  @param[in,out] dst the new zone_data struct
 *
 *  @retval OK
 */
	/* BUT ALSO ... */
/** @brief Opens a zone file
 *
 *  Opens a zone file
 *
 *  @param[in]  fullpath the path and name of the file to open
 *  @param[out] zone a pointer to a structure that will be used by the function
 *              to hold the zone-file information
 *
 *  @return     A result code
 *  @retval     OK   : the file has been opened successfully
 *  @retval     else : an error occurred
 */
ya_result
zone_file_reader_open(const char* fullpath, zone_reader *dst)
{
    input_stream ins;
    ya_result return_value;
    
    if(FAIL(return_value = file_input_stream_open(fullpath, &ins)))
    {
            log_debug("zone file: cannot open: '%s': %r", fullpath, return_value);
            return ZRE_FILE_OPEN_ERR;
    }
    
#if (DNSDB_USE_POSIX_ADVISE != 0) && (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L)
    int fd = fd_input_stream_get_filedescriptor(&ins);
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
    
    return_value = zone_file_reader_parse_stream(&ins, dst);
    
    return return_value;
}

void
zone_file_reader_ignore_missing_soa(zone_reader *zr)
{
    zone_file_reader *zone = (zone_file_reader*)zr->data;
    zone->soa_found = TRUE;
}

/** @} */

/*----------------------------------------------------------------------------*/
