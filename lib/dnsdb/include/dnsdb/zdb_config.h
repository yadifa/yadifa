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
/** @defgroup config Database configuration
 *  @ingroup dnsdb
 *  @brief Database configuration
 *
 *  Database configuration #defines
 *
 * @{
 */

#ifndef _ZDB_CONFIG_H
#define	_ZDB_CONFIG_H

#include <dnscore/sys_types.h>

#include <dnsdb/zdb-config-features.h>

#ifdef	__cplusplus
extern "C"
{
#endif

#define DEFAULT_ASSUMED_CPU_COUNT       2
    
/**
 * Version of the database.
 */

#define ZDB_VERSION "1.0"

/**
 * Inlines the find operation of the AVLs/BTREEs
 */

#define ZDB_INLINES_AVL_FIND 1

/**
 * Inlines the quick operation of the HTBT
 */

#define ZDB_INLINES_HTBT_FIND 1

/**
 *
 * Enables or disables the use of openssl for digital signatures.
 * Disabling this is not fully supported yet. (Not at all actually)
 *
 * MANDATORY: 1 (for now)
 *
 */


#define ZDB_OPENSSL_SUPPORT 1

/*
 * Required for building the IXFR streams
 */

#define ZDB_CHANGE_FEEDBACK_SUPPORT 1

/*
 * Use the threadpool system instead of the raw threads
 */

#define ZDB_USE_THREADPOOL 1

/*#define ZDB_HAS_DNSSEC_SUPPORT (ZDB_HAS_NSEC_SUPPORT+ZDB_HAS_NSEC3_SUPPORT)*/
#ifdef ZDB_HAS_DNSSEC_SUPPORT
#define ZDB_HAS_DNSSEC_SUPPORT 1
#else
#define ZDB_HAS_DNSSEC_SUPPORT 0
#endif

/* Here disable all the DNSSEC related third party libs */
#if ZDB_HAS_DNSSEC_SUPPORT == 0
      #undef ZDB_OPENSSL_SUPPORT
      #define ZDB_OPENSSL_SUPPORT 0
#endif

/**
 *
 * Enables or disables caching.
 *
 * 0 => global_resource_record field not needed
 * 1 => global_resource_record field is the cache
 *
 */

#if 0 /* fix */
#else
#define ZDB_CACHE_ENABLED 0
#endif

/**
 * Enables (1) or disables (0) the specialized memory allocator.
 *
 * It is faster and uses less memory than malloc : RECOMMENDED
 *
 * Recommended value: 1
 */
#define ZDB_USES_ZALLOC         1
    
#define ZDB_ZALLOC_THREAD_SAFE  1

/**
 * Debugging with ZALLOC enabled can be difficult.  This flag disables ZALLOC on debug builds.
 */
       
#if defined(DEBUG)
#undef ZDB_USES_ZALLOC
#define ZDB_USES_ZALLOC 0
#endif

/**
 *
 * Keeps some ZALLOC memory usage information.
 *
 * Recommended value: 0
 */

#define ZDB_ZALLOC_STATISTICS 0

/**
 * DEBUG: Ensures that the memory allocated by ZALLOC is trashed.
 * This is of course to avoid uninitialized memory issues.
 *
 * Please disable for production.
 *
 * Recommended value: 0
 */

#define ZDB_DEBUG_ZALLOC_TRASHMEMORY 0 /*defined(DEBUG)*/

/**
 * If the number of items in a dictionnary goes beyond this number, the dictionnary
 * will change from a balanced tree (AVL) to an hash-table of balanced trees.
 *
 * Recommended value: 500000
 *
 */

#define ZDB_HASHTABLE_THRESHOLD 500000

/**
 *
 * Number of classes [1..n] to support.
 * Set to 1 to support only the IN class
 *
 * Setting this to 1 also enables some code optimizations.
 *
 * Please note that the caller is responsible for checking that (qclass>0)&&(qclass<=ZDB_RECORDS_MAX_CLASS)
 * zdb_query_ex does the check but really should not.
 * It's faster to check that a qclass is in that range or is not "CHaos" or "HeSiod" on the caller's side.
 * (ie: if ==IN -> query, else if ==CH answer chaos, else answer no match.)
 *
 * Recommended value: 1
 *
 */

#define ZDB_RECORDS_MAX_CLASS   1

/**
 * Previously, readers had to be "stopped" before any write was done into the database.  It's a reasonably fast mechanism.
 * With the drastic improve of the MT model on kernels > 3.x, the zone can now be explicitely locked by readers.
 * The first experiments tends to show that the price is minimal.
 * The lock can still be drastically improved.
 * 
 * == 0: no lock
 * != 0: lock
 * 
 * The locking mechanism itself can be vastly improved
 */
    

#define ZDB_EXPLICIT_READER_ZONE_LOCK 1
    
/**
 *
 * DEBUG: Enables (1) or disable (0) stdout statistics output while loading a zone.
 *
 * Recommended value: 0
 *
 */

#define ZDB_DEBUG_LOADZONE  0

/**
 * DEBUG: try to read the zone file no matter what error occurs.
 *
 * Recommended value: 0
 *
 */

#define ZDB_DEBUG_ZONEFILE_BESTEFFORT 0


/**
 * The maximum number of loops allowed with a cname.
 */
    
#define ZDB_CNAME_LOOP_MAX  20

/**
 * The fixed minimum number of file descriptors opened at the same time for journals
 */

#define ZDB_JOURNAL_FD_MIN      4096
    
/**
 * The fixed maximum number of file descriptors opened at the same time for journals
 */

#define ZDB_JOURNAL_FD_MAX      4096
    
/**
 * The default maximum number of file descriptors opened at the same time for journals
 */
    
#define ZDB_JOURNAL_FD_DEFAULT  512
    
#ifdef	__cplusplus
}
#endif

#endif	/* _ZDB_CONFIG_H */

/** @} */
