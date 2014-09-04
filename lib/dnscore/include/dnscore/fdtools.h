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
/** @defgroup dnscoretools Generic Tools
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#ifndef _FDTOOLS_H
#define	_FDTOOLS_H

#include <dnscore/sys_types.h>

#ifdef	__cplusplus
extern "C"
{
#endif
    
#define US_RATE(x) (0.000001 * (x))

/**
 * Writes fully the buffer to the fd
 * It will only return a short count for system errors.
 * ie: fs full, non-block would block, fd invalid/closed, ...
 */

ssize_t writefully(int fd, const void *buf, size_t count);


/**
 * Reads fully the buffer from the fd
 * It will only return a short count for system errors.
 * ie: fs full, non-block would block, fd invalid/closed, ...
 */

ssize_t readfully(int fd, void *buf, size_t count);

ssize_t writefully_limited(int fd, const void *buf, size_t count, double minimum_rate);

ssize_t readfully_limited(int fd, void *buf, size_t count, double minimum_rate);

/**
 * Reads an ASCII text line from fd, stops at EOF or '\n'
 */

ssize_t readtextline(int fd, char *buf, size_t count);

/**
 * Deletes a file (see man 2 unlink).
 * Handles EINTR and other retry errors.
 * 
 * @param fd
 * @return 
 */

int unlink_ex(const char *folder, const char *filename);

/**
 * Opens a file. (see man 2 open)
 * Handles EINTR and other retry errors.
 * 
 * @param fd
 * @return 
 */

ya_result open_ex(const char *pathname, int flags);

/**
 * Opens a file, create if it does not exist. (see man 2 open with O_CREAT)
 * Handles EINTR and other retry errors.
 * 
 * @param fd
 * @return 
 */

ya_result open_create_ex(const char *pathname, int flags, mode_t mode);

/**
 * Closes a file descriptor (see man 2 close)
 * Handles EINTR and other retry errors.
 * At return the file will be closed or not closable.
 * 
 * @param fd
 * @return 
 */

ya_result close_ex(int fd);


/**
 * Returns the size of a file
 * 
 * @param name
 * @return 
 */

s64 filesize(const char *name);

#ifdef	__cplusplus
}
#endif

#endif	/* _FDTOOLS_H */

/** @} */
