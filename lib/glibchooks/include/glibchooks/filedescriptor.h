/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2025, EURid vzw. All rights reserved.
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
#pragma once
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <dirent.h>
#include <netinet/in.h>

// open

struct open_function_args_s
{
    uint64_t    mask;
    const char *filename;
    int         flags;
    int         mode;
    int         fd;
    int         errno_value;
};

typedef struct open_function_args_s open_function_args_t;

typedef void (*open_function_hook_t)(open_function_args_t *args);

// creat

struct creat_function_args_s
{
    uint64_t    mask;
    const char *filename;
    int         mode;
    int         fd;
    int         errno_value;
};

typedef struct creat_function_args_s creat_function_args_t;

typedef void (*creat_function_hook_t)(creat_function_args_t *args);

// read

struct read_function_args_s
{
    uint64_t mask;
    int      fd;
    void    *buf;
    size_t   count;
    ssize_t  n;
    int      errno_value;
};

typedef struct read_function_args_s read_function_args_t;

typedef void (*read_function_hook_t)(read_function_args_t *args);

// write

struct write_function_args_s
{
    uint64_t    mask;
    int         fd;
    const void *buf;
    size_t      count;
    ssize_t     n;
    int         errno_value;
};

typedef struct write_function_args_s write_function_args_t;

typedef void (*write_function_hook_t)(write_function_args_t *args);

// close

struct close_function_args_s
{
    uint64_t mask;
    int      fd;
    int      ret;
    int      errno_value;
};

typedef struct close_function_args_s close_function_args_t;

typedef void (*close_function_hook_t)(close_function_args_t *args);

// lseek

struct lseek_function_args_s
{
    uint64_t mask;
    int      fd;
    off_t    offset;
    int      whence;
    off_t    pos;
    int      errno_value;
};

typedef struct lseek_function_args_s lseek_function_args_t;

typedef void (*lseek_function_hook_t)(lseek_function_args_t *args);

// send

struct send_function_args_s
{
    uint64_t    mask;
    int         sockfd;
    const void *buf;
    size_t      count;
    int         flags;
    ssize_t     n;
    int         errno_value;
};

typedef struct send_function_args_s send_function_args_t;

typedef void (*send_function_hook_t)(send_function_args_t *args);

// sendto

struct sendto_function_args_s
{
    uint64_t               mask;
    int                    sockfd;
    const void            *buf;
    size_t                 count;
    int                    flags;
    const struct sockaddr *dest_addr;
    socklen_t              addrlen;
    ssize_t                n;
    int                    errno_value;
};

typedef struct sendto_function_args_s sendto_function_args_t;

typedef void (*sendto_function_hook_t)(sendto_function_args_t *args);

// sendmsg

struct sendmsg_function_args_s
{
    uint64_t             mask;
    int                  sockfd;
    const struct msghdr *msg;
    int                  flags;
    ssize_t              n;
    int                  errno_value;
};

typedef struct sendmsg_function_args_s sendmsg_function_args_t;

typedef void (*sendmsg_function_hook_t)(sendmsg_function_args_t *args);

// recv

struct recv_function_args_s
{
    uint64_t mask;
    int      sockfd;
    void    *buf;
    size_t   count;
    int      flags;
    ssize_t  n;
    int      errno_value;
};

typedef struct recv_function_args_s recv_function_args_t;

typedef void (*recv_function_hook_t)(recv_function_args_t *args);

// recvfrom

struct recvfrom_function_args_s
{
    uint64_t         mask;
    int              sockfd;
    void            *buf;
    size_t           count;
    int              flags;
    struct sockaddr *dest_addr;
    socklen_t       *addrlen;
    ssize_t          n;
    int              errno_value;
};

typedef struct recvfrom_function_args_s recvfrom_function_args_t;

typedef void (*recvfrom_function_hook_t)(recvfrom_function_args_t *args);

// recvmsg

struct recvmsg_function_args_s
{
    uint64_t       mask;
    int            sockfd;
    struct msghdr *msg;
    int            flags;
    ssize_t        n;
    int            errno_value;
};

typedef struct recvmsg_function_args_s recvmsg_function_args_t;

typedef void (*recvmsg_function_hook_t)(recvmsg_function_args_t *args);

// unlink

struct unlink_function_args_s
{
    uint64_t    mask;
    const char *pathname;
    int         n;
    int         errno_value;
};

typedef struct unlink_function_args_s unlink_function_args_t;

typedef void (*unlink_function_hook_t)(unlink_function_args_t *args);

// unlinkat

struct unlinkat_function_args_s
{
    uint64_t    mask;
    int         dirfd;
    const char *pathname;
    int         flags;
    int         n;
    int         errno_value;
};

typedef struct unlinkat_function_args_s unlinkat_function_args_t;

typedef void (*unlinkat_function_hook_t)(unlinkat_function_args_t *args);

// getcwd

struct getcwd_function_args_s
{
    uint64_t mask;
    char    *buf;
    size_t   size;
    char    *text;
    int      errno_value;
};

typedef struct getcwd_function_args_s getcwd_function_args_t;

typedef void (*getcwd_function_hook_t)(getcwd_function_args_t *args);

// fsync

struct fsync_function_args_s
{
    uint64_t mask;
    int      fd;
    int      ret;
    int      errno_value;
};

typedef struct fsync_function_args_s fsync_function_args_t;

typedef void (*fsync_function_hook_t)(fsync_function_args_t *args);

// fdatasync

struct fdatasync_function_args_s
{
    uint64_t mask;
    int      fd;
    int      ret;
    int      errno_value;
};

typedef struct fdatasync_function_args_s fdatasync_function_args_t;

typedef void (*fdatasync_function_hook_t)(fdatasync_function_args_t *args);

// dup

struct dup_function_args_s
{
    uint64_t mask;
    int      oldfd;
    int      fd;
    int      errno_value;
};

typedef struct dup_function_args_s dup_function_args_t;

typedef void (*dup_function_hook_t)(dup_function_args_t *args);

// dup2

struct dup2_function_args_s
{
    uint64_t mask;
    int      oldfd;
    int      newfd;
    int      fd;
    int      errno_value;
};

typedef struct dup2_function_args_s dup2_function_args_t;

typedef void (*dup2_function_hook_t)(dup2_function_args_t *args);

// truncate

struct truncate_function_args_s
{
    uint64_t    mask;
    const char *path;
    off_t       len;
    int         ret;
    int         errno_value;
};

typedef struct truncate_function_args_s truncate_function_args_t;

typedef void (*truncate_function_hook_t)(truncate_function_args_t *args);

// ftruncate

struct ftruncate_function_args_s
{
    uint64_t mask;
    int      fd;
    off_t    len;
    int      ret;
    int      errno_value;
};

typedef struct ftruncate_function_args_s ftruncate_function_args_t;

typedef void (*ftruncate_function_hook_t)(ftruncate_function_args_t *args);

// socket

struct socket_function_args_s
{
    uint64_t mask;
    int      domain;
    int      type;
    int      protocol;
    int      ret;
    int      errno_value;
};

typedef struct socket_function_args_s socket_function_args_t;

typedef void (*socket_function_hook_t)(socket_function_args_t *args);

// getsockopt

struct getsockopt_function_args_s
{
    uint64_t   mask;
    int        socket;
    int        level;
    int        option_name;
    void      *option_value;
    socklen_t *option_len;
    int        ret;
    int        errno_value;
};

typedef struct getsockopt_function_args_s getsockopt_function_args_t;

typedef void (*getsockopt_function_hook_t)(getsockopt_function_args_t *args);

// setsockopt

struct setsockopt_function_args_s
{
    uint64_t    mask;
    int         socket;
    int         level;
    int         option_name;
    const void *option_value;
    socklen_t   option_len;
    int         ret;
    int         errno_value;
};

typedef struct setsockopt_function_args_s setsockopt_function_args_t;

typedef void (*setsockopt_function_hook_t)(setsockopt_function_args_t *args);

// bind

struct bind_function_args_s
{
    uint64_t               mask;
    int                    sockfd;
    const struct sockaddr *addr;
    socklen_t              addrlen;
    int                    ret;
    int                    errno_value;
};

typedef struct bind_function_args_s bind_function_args_t;

typedef void (*bind_function_hook_t)(bind_function_args_t *args);

// listen

struct listen_function_args_s
{
    uint64_t mask;
    int      sockfd;
    int      backlog;
    int      ret;
    int      errno_value;
};

typedef struct listen_function_args_s listen_function_args_t;

typedef void (*listen_function_hook_t)(listen_function_args_t *args);

// stat

struct stat_function_args_s
{
    uint64_t     mask;
    const char  *pathname;
    struct stat *statbuf;
    int          ret;
    int          errno_value;
};

typedef struct stat_function_args_s stat_function_args_t;

typedef void (*stat_function_hook_t)(stat_function_args_t *args);

// fstat

struct fstat_function_args_s
{
    uint64_t     mask;
    int          fd;
    struct stat *statbuf;
    int          ret;
    int          errno_value;
};

typedef struct fstat_function_args_s fstat_function_args_t;

typedef void (*fstat_function_hook_t)(fstat_function_args_t *args);

// lstat

struct lstat_function_args_s
{
    uint64_t     mask;
    const char  *pathname;
    struct stat *statbuf;
    int          ret;
    int          errno_value;
};

typedef struct lstat_function_args_s lstat_function_args_t;

typedef void (*lstat_function_hook_t)(lstat_function_args_t *args);

// fstatat

struct fstatat_function_args_s
{
    uint64_t     mask;
    int          dirfd;
    const char  *pathname;
    struct stat *statbuf;
    int          flags;
    int          ret;
    int          errno_value;
};

typedef struct fstatat_function_args_s fstatat_function_args_t;

typedef void (*fstatat_function_hook_t)(fstatat_function_args_t *args);

// mkdir

struct mkdir_function_args_s
{
    uint64_t    mask;
    const char *pathname;
    mode_t      mode;
    int         ret;
    int         errno_value;
};

typedef struct mkdir_function_args_s mkdir_function_args_t;

typedef void (*mkdir_function_hook_t)(mkdir_function_args_t *args);

// fcntl

struct fcntl_function_args_s // va_arg but all our uses are 2 or 3 args
{
    uint64_t mask;
    int      fd;
    int      cmd;
    int      arg;
    int      ret;
    int      errno_value;
};

typedef struct fcntl_function_args_s fcntl_function_args_t;

typedef void (*fcntl_function_hook_t)(fcntl_function_args_t *args);

// opendir

struct opendir_function_args_s
{
    uint64_t    mask;
    const char *name;
    DIR        *ret;
    int         errno_value;
};

typedef struct opendir_function_args_s opendir_function_args_t;

typedef void (*opendir_function_hook_t)(opendir_function_args_t *args);

// fdopendir

struct fdopendir_function_args_s
{
    uint64_t mask;
    int      fd;
    DIR     *ret;
    int      errno_value;
};

typedef struct fdopendir_function_args_s fdopendir_function_args_t;

typedef void (*fdopendir_function_hook_t)(fdopendir_function_args_t *args);

// readdir

struct readdir_function_args_s
{
    uint64_t       mask;
    DIR           *dirp;
    struct dirent *ret;
    int            errno_value;
};

typedef struct readdir_function_args_s readdir_function_args_t;

typedef void (*readdir_function_hook_t)(readdir_function_args_t *args);

// closedir

struct closedir_function_args_s
{
    uint64_t mask;
    DIR     *dirp;
    int      ret;
    int      errno_value;
};

typedef struct closedir_function_args_s closedir_function_args_t;

typedef void (*closedir_function_hook_t)(closedir_function_args_t *args);

// access

struct access_function_args_s
{
    uint64_t    mask;
    const char *pathname;
    int         mode;
    int         ret;
    int         errno_value;
};

typedef struct access_function_args_s access_function_args_t;

typedef void (*access_function_hook_t)(access_function_args_t *args);
