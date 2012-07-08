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
/*------------------------------------------------------------------------------
 *
 * USE INCLUDES */
#include <dnscore/logger.h>
#include <dnscore/format.h>

#include "server.h"
#include "wrappers.h"

#define MODULE_MSG_HANDLE g_server_logger

/*------------------------------------------------------------------------------
 * FUNCTIONS */

/** \brief Bind a name to a socket
 *
 *  with error capturing
 *
 *  @param[in] fd file descriptor
 *  @param[in] sa
 *  @param[in] salen
 *
 *  @return NONE
 */
ya_result
Bind(int fd, const struct sockaddr *sa, socklen_t salen)
{
    ya_result return_value = SUCCESS;
    
    if(bind(fd, sa, salen) == -1)
    {
        return_value = ERRNO_ERROR;
        
        log_err("bind: %r", return_value);
    }
    
    return return_value;
}

/** \brief Change current working directory
 *
 *  with error capturing
 *
 *  @param[in] path
 *
 *  @return NONE
 */
void
Chdir(const char *path)
{
    char buffer[PATH_MAX];
    
    if((g_config->server_flags & SERVER_FL_CHROOT) && !g_config->chrooted)
    {
        if(FAIL(snformat(buffer,sizeof(buffer),"%s/%s", g_config->chroot_path, path)))
        {
            log_err("chdir(%s/%s): path is too big", g_config->chroot_path, path);
            exit(EXIT_FAILURE);
        }
        
        path = buffer;
    }
    
    if(chdir(path) < 0)
    {
        log_err("can't change to directory: %s (%s)", path, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

/** \brief Change root directory
 *
 *  with error capturing
 *
 *  @param[in] path
 *
 *  @return NONE
 */
void
Chroot(const char *path)
{
    if(chroot(path) < 0)
    {
        
        log_err("unable to chroot to: '%s': %r", path, ERRNO_ERROR);
        
        if(*path != '/')
        {
            char cwd[PATH_MAX];
            
            cwd[0] = '\0';
            
            if(getcwd(cwd,sizeof(cwd)) == NULL)
            {
                log_err("getcwd: %r", ERRNO_ERROR);
            }
            else
            {            
                log_err("current directory: '%s'", cwd);
            }
        }
        
        exit(EXIT_FAILURE);
    }
    
    g_config->chrooted = TRUE;
}

/** \brief Closes a descriptor
 *
 *  with error capturing and logging
 *
 *  @param[in] fd
 *
 *  @return NONE
 */
void
Close(int fd)
{
    while(close(fd) < 0)
    {
        int err = errno;
        
        if(err != EINTR)
        {
            log_err("close error fd=%d: %r", fd, ERRNO_ERROR);
            break;
        }
    }
}

/** \brief Creates a socketpair
 *
 *  @return NONE
 */
void
Socketpair(int domain, int type, int sv[2])
{
    if(socketpair(domain, type, 0, sv) == -1)
    {
        log_quit("socketpair error: %r", ERRNO_ERROR);
    }
}

/** Initiate a connection on a socket
 *
 *  with error capturing
 *
 *  @param[in] fd
 *  @param[in] sa
 *  @param[in] salen
 *
 *  @return NONE
 */
void
Connect(int fd, const struct sockaddr *sa, socklen_t salen)
{
    if(connect(fd, sa, salen) < 0)
    {
        log_quit("connect error (%s)", strerror(errno));
    }
}

/** \brief file control
 *
 *  with error capturing
 *
 *  @param[in] fd
 *  @param[in] cmd
 *  @param[in] arg
 *
 *  @return NONE
 */
int
Fcntl(int fd, int cmd, long arg)
{
    int val;

    if((val = fcntl(fd, cmd, arg)) == -1)
    {
        log_quit("cannot fcntl interface: %s", strerror(errno));
    }

    return val;
}

/** \brief Create a new process
 *
 *  with error capturing
 *
 *  @param NONE
 *
 *  @retval pid program id
 */
pid_t
Fork(void)
{
    pid_t pid;

    /*    ------------------------------------------------------------    */

    if((pid = fork()) == -1)
    {
        log_err("fork error (%s)", strerror(errno));
        exit(EXIT_FAILURE);
    }

    return (pid);
}

/** \brief Listen for connections on a socket
 *
 *  with error capturing
 *
 *  @param[in] socket  Must be of type SOCK_STREAM or SOCK_SEQPACKET
 *  @param[in] backlog Defines the maximum length for the queue of pending
 *                     connections
 *
 *  @return NONE
 */
ya_result
Listen(int socket, int backlog)
{
    ya_result return_value = SUCCESS;
    
    /** @note Listen needs some extra development */

    if(listen(socket, backlog) < 0)
    {
        return_value = ERRNO_ERROR;
        
        log_err("listen: %r", return_value);
    }
    
    return return_value;
}

/** \brief Open a file for reading
 *
 *  with error capturing
 *
 *  @param[in] path_name path and file_name of to be opened file
 *  @param[in] oflag
 *  @param[in] mode
 *
 *  @retval fd file descriptor of opened file
 */
int
Open(const char *path_name, int oflag, mode_t mode)
{
    int fd;

    /*    ------------------------------------------------------------    */

    if((fd = open(path_name, oflag, mode)) == -1)
    {
        int err = errno;

        char buffer[1024];

        if(getcwd(buffer, sizeof(buffer)) == NULL)
        {
            log_err("getcwd: %s", strerror(errno));
            buffer[0] = '\0';
        }

        log_err("can't open '%s' (oflag=%o, mode=%o, err=%s, cwd=%s)", path_name, oflag, mode, strerror(err), buffer);
        exit(EXIT_FAILURE);
    }
    
    return fd;
}

/** \brief Receive a message from a socket
 *
 *  with error capturing
 *
 *  @param[in] fd
 *  @param[in] ptr
 *  @param[in] nbytes
 *  @param[in] flags
 *  @param[in] sa
 *  @param[in] salenptr
 *
 *  retval n size of received message
 * 
 * 0 uses
 */
ssize_t
Recvfrom(int fd, void *ptr, size_t nbytes, int flags,
	 struct sockaddr *sa, socklen_t *salenptr)
{
    ssize_t n;

    while((n = recvfrom(fd, ptr, nbytes, flags, sa, salenptr)) < 0)
    {
        if(errno == EINTR)
        {
            continue;
        }

        log_quit("recvfrom error (%s)", strerror(errno));
    }
    return n;
}

/** \brief set options on sockets
 *
 *  with error capturing
 *
 *  @param[in] fd
 *  @param[in] level
 *  @param[in] optname
 *  @param[in] optval
 *  @param[in] optlen
 *
 *  @return NONE
 */
ya_result
Setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    ya_result return_value = SUCCESS;
    
    if(setsockopt(fd, level, optname, optval, optlen) < 0)
    {
        return_value = ERRNO_ERROR;
        
        log_err("setsockopt: %r", return_value);
    }
    
    return return_value;
}

/** \brief Set group ID
 *
 *  with error capturing
 *
 *  @param[in] gid
 *
 *  @return NONE
 */
void
Setgid(gid_t gid)
{
    if(setgid(gid) < 0)
    {
        log_err("can't setgid: %d (%s)", gid, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

/** \brief Set user ID
 *
 *  with error capturing
 *
 *  @param[in] uid
 *
 *  @return NONE
 */
void
Setuid(uid_t uid)
{
    if(setuid(uid) < 0)
    {
        log_err("can't setuid: %d (%s)", uid, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

/** \brief Creates an endpoint for communication and returns a descriptor
 *
 *  with error capturing
 *
 *  @param[in] family
 *  @param[in] type
 *  @param[in] protocol
 *
 *  @return
 */
int
Socket(int family, int type, int protocol)
{
    int n;

    /*    ------------------------------------------------------------    */

    if((n = socket(family, type, protocol)) < 0)
    {
        log_quit("socket error (%s)", strerror(errno));
    }

    return n;
}

/** \brief Copy strings
 *
 *  Wrapper around strcpy if source is NULL
 *
 *  @param[out] dest
 *  @param[in] src
 *
 *  @return
 */
char *
/*Strcpy(u_char *dest, const u_char *src)*/
Strcpy(void *dest_cstr, const void *src_cstr)
{
    char * dest = (char*)dest_cstr;
    const char * src = (const char*)src_cstr;

    char *result = NULL;

    /*    ------------------------------------------------------------    */

    if(src != NULL)
    {
        result = strcpy(dest, src);
        return (result);
    }

    *dest = '\0';
    return NULL;
}

/** \brief Remove directory entries
 *
 *  with error capturing, on error gives fatal error
 *
 *  @param[in] pathname file name to remove
 *
 *  @return NONE
 */
void
Unlink(const char *path_name)
{
    if(unlink(path_name) == -1)
    {
        log_err("unlink error for %s (%s)", path_name, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

/** @} */

/*----------------------------------------------------------------------------*/

