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

#ifndef WRAPPERS_H_
#define WRAPPERS_H_
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */

#include	<fcntl.h>
#include	<sys/socket.h>
#include	<sys/stat.h>
#include	<sys/types.h>
#include	<unistd.h>

#include <dnscore/logger.h>

/* NOTE: Always put the dependency includes before */

#include	"config.h"

/*    ------------------------------------------------------------
 *
 *      PROTOTYPES
 */
ya_result Bind(int fd, const struct sockaddr *, socklen_t);
void Chdir(const char *);
void Chroot(const char *);
void Close(int);
void Socketpair(int domain, int type, int sv[2]);                               /* 0 uses */
void Connect(int, const struct sockaddr *, socklen_t);                          /* 0 uses */
pid_t Fork(void);                                                               /* 0 uses */
ya_result Listen(int, int);                                                     /* 1 use */
int Open(const char *, int, mode_t);                                            /* 1 use */
ssize_t Recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);     /* 0 uses */

int Select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
ya_result Setsockopt(int, int, int, const void *, socklen_t);
void Setgid(gid_t);
void Setuid(uid_t);
int Socket(int, int, int);
char * Strcpy(void *, const void *);
void Unlink(const char *);

int Fcntl(int fd, int cmd, long arg);

/** \brief Write output
 *
 *  with error capturing
 *
 *  @param[in,out] fd
 *  @param[in] ptr
 *  @param[in] nbytes
 *
 *  @return NONE
 */
void Write(int fd, void *ptr, size_t nbytes);

/*    ------------------------------------------------------------    */

#endif /* WRAPPERS_H_ */

/*    ------------------------------------------------------------    */

/** @} */
