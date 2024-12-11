/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>

#include "glibchooks/glibchooks_internal.h"
#include "glibchooks/filedescriptor.h"

#ifndef O_TMPFILE
#ifdef __O_TMPFILE
#define O_TMPFILE __O_TMPFILE
#else
#define O_TMPFILE 0
#endif
#endif

static void function_hook_dummy(void *args) { (void)args; }

// open ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static open_function_hook_t open_function_hook = (void *)function_hook_dummy;

// creat //////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static creat_function_hook_t creat_function_hook = (void *)function_hook_dummy;

// read //////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static read_function_hook_t read_function_hook = (void *)function_hook_dummy;

// write //////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static write_function_hook_t write_function_hook = (void *)function_hook_dummy;

// close //////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static close_function_hook_t close_function_hook = (void *)function_hook_dummy;

// lseek //////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static lseek_function_hook_t lseek_function_hook = (void *)function_hook_dummy;

// send ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static send_function_hook_t send_function_hook = (void *)function_hook_dummy;

// sendto /////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static sendto_function_hook_t sendto_function_hook = (void *)function_hook_dummy;

// sendmsg ////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static sendmsg_function_hook_t sendmsg_function_hook = (void *)function_hook_dummy;

// recv ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static recv_function_hook_t recv_function_hook = (void *)function_hook_dummy;

// recvfrom ///////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static recvfrom_function_hook_t recvfrom_function_hook = (void *)function_hook_dummy;

// recvmsg ////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static recvmsg_function_hook_t recvmsg_function_hook = (void *)function_hook_dummy;

// unlink /////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static unlink_function_hook_t unlink_function_hook = (void *)function_hook_dummy;

// unlinkat ///////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static unlinkat_function_hook_t unlinkat_function_hook = (void *)function_hook_dummy;

// getcwd /////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static getcwd_function_hook_t getcwd_function_hook = (void *)function_hook_dummy;

// fsync //////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static fsync_function_hook_t fsync_function_hook = (void *)function_hook_dummy;

// fdatasync //////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static fdatasync_function_hook_t fdatasync_function_hook = (void *)function_hook_dummy;

// dup ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static dup_function_hook_t dup_function_hook = (void *)function_hook_dummy;

// dup2 ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static dup2_function_hook_t dup2_function_hook = (void *)function_hook_dummy;

// truncate ///////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static truncate_function_hook_t truncate_function_hook = (void *)function_hook_dummy;

// ftruncate //////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static ftruncate_function_hook_t ftruncate_function_hook = (void *)function_hook_dummy;

// socket /////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static socket_function_hook_t socket_function_hook = (void *)function_hook_dummy;

// getsockopt /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static getsockopt_function_hook_t getsockopt_function_hook = (void *)function_hook_dummy;

// setsockopt /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static setsockopt_function_hook_t setsockopt_function_hook = (void *)function_hook_dummy;

// bind ///////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static bind_function_hook_t bind_function_hook = (void *)function_hook_dummy;

// listen /////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static listen_function_hook_t listen_function_hook = (void *)function_hook_dummy;

// stat /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static stat_function_hook_t stat_function_hook = (void *)function_hook_dummy;

// fstat /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static fstat_function_hook_t fstat_function_hook = (void *)function_hook_dummy;

// lstat /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static lstat_function_hook_t lstat_function_hook = (void *)function_hook_dummy;

// fstatat /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static fstatat_function_hook_t fstatat_function_hook = (void *)function_hook_dummy;

// mkdir /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static mkdir_function_hook_t mkdir_function_hook = (void *)function_hook_dummy;

// fcntl /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static fcntl_function_hook_t fcntl_function_hook = (void *)function_hook_dummy;

// opendir /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static opendir_function_hook_t opendir_function_hook = (void *)function_hook_dummy;

// fdopendir /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static fdopendir_function_hook_t fdopendir_function_hook = (void *)function_hook_dummy;

// readdir /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static readdir_function_hook_t readdir_function_hook = (void *)function_hook_dummy;

// closedir /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static closedir_function_hook_t closedir_function_hook = (void *)function_hook_dummy;

// access /////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static access_function_hook_t access_function_hook = (void *)function_hook_dummy;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static function_hooks_t filedescriptor_function_hooks[] = {{"open", (void **)&open_function_hook},
                                                           {"creat", (void **)&creat_function_hook},
                                                           {"read", (void **)&read_function_hook},
                                                           {"write", (void **)&write_function_hook},
                                                           {"close", (void **)&close_function_hook},
                                                           {"lseek", (void **)&lseek_function_hook},
                                                           {"send", (void **)&send_function_hook},
                                                           {"sendto", (void **)&sendto_function_hook},
                                                           {"sendmsg", (void **)&sendmsg_function_hook},
                                                           {"recv", (void **)&recv_function_hook},
                                                           {"recvfrom", (void **)&recvfrom_function_hook},
                                                           {"recvmsg", (void **)&recvmsg_function_hook},
                                                           {"unlink", (void **)&unlink_function_hook},
                                                           {"unlinkat", (void **)&unlinkat_function_hook},
                                                           {"getcwd", (void **)&getcwd_function_hook},
                                                           {"fsync", (void **)&fsync_function_hook},
                                                           {"fdatasync", (void **)&fdatasync_function_hook},
                                                           {"dup", (void **)&dup_function_hook},
                                                           {"dup2", (void **)&dup2_function_hook},
                                                           {"truncate", (void **)&truncate_function_hook},
                                                           {"ftruncate", (void **)&ftruncate_function_hook},
                                                           {"socket", (void **)&socket_function_hook},
                                                           {"getsockopt", (void **)&getsockopt_function_hook},
                                                           {"setsockopt", (void **)&setsockopt_function_hook},
                                                           {"listen", (void **)&listen_function_hook},
                                                           {"bind", (void **)&bind_function_hook},
                                                           {"stat", (void **)&stat_function_hook},
                                                           {"fstat", (void **)&fstat_function_hook},
                                                           {"lstat", (void **)&lstat_function_hook},
                                                           {"fstatat", (void **)&fstatat_function_hook},
                                                           {"mkdir", (void **)&mkdir_function_hook},
                                                           {"fcntl", (void **)&fcntl_function_hook},
                                                           {"opendir", (void **)&opendir_function_hook},
                                                           {"fdopendir", (void **)&fdopendir_function_hook},
                                                           {"readdir", (void **)&readdir_function_hook},
                                                           {"closedir", (void **)&closedir_function_hook},
                                                           {"access", (void **)&access_function_hook},
                                                           {NULL, NULL}};

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static int (*glibc_open)(const char *filename, int oflag, ...);
static int (*glibc_creat)(const char *pathname, mode_t mode);
static ssize_t (*glibc_read)(int fd, void *buf, size_t count);
static ssize_t (*glibc_write)(int fd, const void *buf, size_t count);
static off_t (*glibc_lseek)(int fildes, off_t offset, int whence);
static int (*glibc_close)(int fd);
static ssize_t (*glibc_send)(int sockfd, const void *buf, size_t len, int flags);
static ssize_t (*glibc_sendto)(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
static ssize_t (*glibc_sendmsg)(int sockfd, const struct msghdr *msg, int flags);
static ssize_t (*glibc_recv)(int sockfd, void *buf, size_t len, int flags);
static ssize_t (*glibc_recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
static ssize_t (*glibc_recvmsg)(int sockfd, struct msghdr *msg, int flags);
static int (*glibc_unlink)(const char *pathname);
static int (*glibc_unlinkat)(int dirfd, const char *pathname, int flags);
static char *(*glibc_getcwd)(char *buf, size_t size);
static int (*glibc_fsync)(int fd);
static int (*glibc_fdatasync)(int fd);
static int (*glibc_dup)(int oldfd);
static int (*glibc_dup2)(int oldfd, int newfd);
static int (*glibc_truncate)(const char *path, off_t len);
static int (*glibc_ftruncate)(int fd, off_t len);
static int (*glibc_socket)(int domain, int type, int protocol);
static int (*glibc_getsockopt)(int socket, int level, int option_name, void *option_value, socklen_t *option_len);
static int (*glibc_setsockopt)(int socket, int level, int option_name, const void *option_value, socklen_t option_len);
static int (*glibc_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int (*glibc_listen)(int sockfd, int backlog);
static int (*glibc_stat)(const char *pathname, struct stat *statbuf);
static int (*glibc_fstat)(int fd, struct stat *statbuf);
static int (*glibc_lstat)(const char *pathname, struct stat *statbuf);
static int (*glibc_fstatat)(int dirfd, const char *pathname, struct stat *statbuf, int flags);
static int (*glibc_mkdir)(const char *pathname, mode_t mode);
static int (*glibc_fcntl)(int fd, int md, ...);
static DIR *(*glibc_opendir)(const char *name);
static DIR *(*glibc_fdopendir)(int fd);
static struct dirent *(*glibc_readdir)(DIR *dirp);
static int (*glibc_closedir)(DIR *dirp);
static int (*glibc_access)(const char *pathname, int mode);

static void filedescriptor_hooks_init()
{
    glibc_open = function_hook("open");
    glibc_creat = function_hook("creat");
    glibc_read = function_hook("read");
    glibc_write = function_hook("write");
    glibc_lseek = function_hook("lseek");
    glibc_close = function_hook("close");
    glibc_send = function_hook("send");
    glibc_sendto = function_hook("sendto");
    glibc_sendmsg = function_hook("sendmsg");
    glibc_recv = function_hook("recv");
    glibc_recvfrom = function_hook("recvfrom");
    glibc_recvmsg = function_hook("recvmsg");
    glibc_unlink = function_hook("unlink");
    glibc_unlinkat = function_hook("unlinkat");
    glibc_getcwd = function_hook("getcwd");
    glibc_fsync = function_hook("fsync");
    glibc_fdatasync = function_hook("fdatasync");
    glibc_dup = function_hook("dup");
    glibc_dup2 = function_hook("dup2");
    glibc_truncate = function_hook("truncate");
    glibc_ftruncate = function_hook("ftruncate");
    glibc_socket = function_hook("socket");
    glibc_getsockopt = function_hook("getsockopt");
    glibc_setsockopt = function_hook("setsockopt");
    glibc_bind = function_hook("bind");
    glibc_listen = function_hook("listen");
    glibc_stat = function_hook("stat");
    glibc_fstat = function_hook("fstat");
    glibc_lstat = function_hook("lstat");
    glibc_fstatat = function_hook("fstatat");
    glibc_mkdir = function_hook("mkdir");
    glibc_fcntl = function_hook("fcntl");
    glibc_opendir = function_hook("opendir");
    glibc_fdopendir = function_hook("fdopendir");
    glibc_readdir = function_hook("readdir");
    glibc_closedir = function_hook("closedir");
    glibc_access = function_hook("access");
}

static void            filedescriptor_hooks_print(FILE *f) { (void)f; }

INTERNAL hook_module_t filedescriptor_module = {"filedescriptor", filedescriptor_function_hooks, filedescriptor_hooks_init, filedescriptor_hooks_print};

int                    open(const char *filename, int flags, ...)
{
    int                  fd;
    int                  mode = 0;
    open_function_args_t fargs;
    fargs.filename = filename;
    fargs.flags = flags;

    if((flags & (O_CREAT | O_TMPFILE)) == 0)
    {
        fargs.mask = 0x03;
    }
    else
    {
        fargs.mask = 0x07;
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    fargs.mode = mode;

    open_function_hook(&fargs);

    if((fargs.mask & 0x18) != 0)
    {
        fd = fargs.fd;
        errno = fargs.errno_value;
        return fd;
    }

    fd = glibc_open(fargs.filename, fargs.flags, fargs.mode);

    fargs.mask = 0x1f;
    fargs.fd = fd;
    fargs.errno_value = errno;

    open_function_hook(&fargs);

    fd = fargs.fd;
    errno = fargs.errno_value;
    return fd;
}

int creat(const char *filename, mode_t mode)
{
    int                   fd;
    creat_function_args_t fargs;
    fargs.mask = 0x03;
    fargs.filename = filename;
    fargs.mode = mode;

    creat_function_hook(&fargs);

    if((fargs.mask & 0x0c) != 0)
    {
        fd = fargs.fd;
        errno = fargs.errno_value;
        return fd;
    }

    fd = glibc_creat(fargs.filename, fargs.mode);

    fargs.mask = 0x0c;
    fargs.fd = fd;
    fargs.errno_value = errno;

    creat_function_hook(&fargs);

    fd = fargs.fd;
    errno = fargs.errno_value;
    return fd;
}

ssize_t read(int fd, void *buf, size_t count)
{
    ssize_t              n;
    read_function_args_t fargs;
    fargs.mask = 0x07;
    fargs.fd = fd;
    fargs.buf = buf;
    fargs.count = count;

    read_function_hook(&fargs);

    if((fargs.mask & 0x018) != 0)
    {
        n = fargs.n;
        errno = fargs.errno_value;
        return n;
    }

    n = glibc_read(fargs.fd, fargs.buf, fargs.count);

    fargs.mask = 0x1f;
    fargs.n = n;
    fargs.errno_value = errno;

    read_function_hook(&fargs);

    n = fargs.n;
    errno = fargs.errno_value;
    return n;
}

ssize_t write(int fd, const void *buf, size_t count)
{
    ssize_t               n;
    write_function_args_t fargs;
    fargs.mask = 0x07;
    fargs.fd = fd;
    fargs.buf = buf;
    fargs.count = count;

    write_function_hook(&fargs);

    if((fargs.mask & 0x018) != 0)
    {
        n = fargs.n;
        errno = fargs.errno_value;
        return n;
    }

    n = glibc_write(fargs.fd, fargs.buf, fargs.count);

    fargs.mask = 0x1f;
    fargs.n = n;
    fargs.errno_value = errno;

    write_function_hook(&fargs);

    n = fargs.n;
    errno = fargs.errno_value;
    return n;
}

int close(int fd)
{
    int                   ret;
    close_function_args_t fargs;
    fargs.mask = 0x01;
    fargs.fd = fd;

    close_function_hook(&fargs);

    if((fargs.mask & 0x06) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_close(fargs.fd);

    fargs.mask = 0x07;
    fargs.ret = ret;
    fargs.errno_value = errno;

    close_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;

    return ret;
}

off_t lseek(int fd, off_t offset, int whence)
{
    off_t                 pos;
    lseek_function_args_t fargs;
    fargs.mask = 0x07;
    fargs.fd = fd;
    fargs.offset = offset;
    fargs.whence = whence;

    lseek_function_hook(&fargs);

    if((fargs.mask & 0x18) != 0)
    {
        pos = fargs.pos;
        errno = fargs.errno_value;
        return pos;
    }

    pos = glibc_lseek(fargs.fd, fargs.offset, fargs.whence);

    fargs.mask = 0x1f;
    fargs.pos = pos;
    fargs.errno_value = errno;

    lseek_function_hook(&fargs);

    pos = fargs.pos;
    errno = fargs.errno_value;
    return pos;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    ssize_t              n;
    send_function_args_t fargs;
    fargs.mask = 0x0f;
    fargs.sockfd = sockfd;
    fargs.buf = buf;
    fargs.count = len;
    fargs.flags = flags;

    send_function_hook(&fargs);

    if((fargs.mask & 0x030) != 0)
    {
        n = fargs.n;
        errno = fargs.errno_value;
        return n;
    }

    n = glibc_send(fargs.sockfd, fargs.buf, fargs.count, fargs.flags);

    fargs.mask = 0x3f;
    fargs.n = n;
    fargs.errno_value = errno;

    send_function_hook(&fargs);

    n = fargs.n;
    errno = fargs.errno_value;
    return n;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
    ssize_t                n;
    sendto_function_args_t fargs;
    fargs.mask = 0x3f;
    fargs.sockfd = sockfd;
    fargs.buf = buf;
    fargs.count = len;
    fargs.flags = flags;
    fargs.dest_addr = dest_addr;
    fargs.addrlen = addrlen;

    sendto_function_hook(&fargs);

    if((fargs.mask & 0x0c0) != 0)
    {
        n = fargs.n;
        errno = fargs.errno_value;
        return n;
    }

    n = glibc_sendto(fargs.sockfd, fargs.buf, fargs.count, fargs.flags, fargs.dest_addr, fargs.addrlen);

    fargs.mask = 0xff;
    fargs.n = n;
    fargs.errno_value = errno;

    sendto_function_hook(&fargs);

    n = fargs.n;
    errno = fargs.errno_value;
    return n;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    ssize_t                 n;
    sendmsg_function_args_t fargs;
    fargs.mask = 0x07;
    fargs.sockfd = sockfd;
    fargs.msg = msg;
    fargs.flags = flags;

    sendmsg_function_hook(&fargs);

    if((fargs.mask & 0x018) != 0)
    {
        n = fargs.n;
        errno = fargs.errno_value;
        return n;
    }

    n = glibc_sendmsg(fargs.sockfd, fargs.msg, fargs.flags);

    fargs.mask = 0x1f;
    fargs.n = n;
    fargs.errno_value = errno;

    sendmsg_function_hook(&fargs);

    n = fargs.n;
    errno = fargs.errno_value;
    return n;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    ssize_t              n;
    recv_function_args_t fargs;
    fargs.mask = 0x0f;
    fargs.sockfd = sockfd;
    fargs.buf = buf;
    fargs.count = len;
    fargs.flags = flags;

    recv_function_hook(&fargs);

    if((fargs.mask & 0x030) != 0)
    {
        n = fargs.n;
        errno = fargs.errno_value;
        return n;
    }

    n = glibc_recv(fargs.sockfd, fargs.buf, fargs.count, fargs.flags);

    fargs.mask = 0x3f;
    fargs.n = n;
    fargs.errno_value = errno;

    recv_function_hook(&fargs);

    n = fargs.n;
    errno = fargs.errno_value;
    return n;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    ssize_t                  n;
    recvfrom_function_args_t fargs;
    fargs.mask = 0x3f;
    fargs.sockfd = sockfd;
    fargs.buf = buf;
    fargs.count = len;
    fargs.flags = flags;
    fargs.dest_addr = src_addr;
    fargs.addrlen = addrlen;

    recvfrom_function_hook(&fargs);

    if((fargs.mask & 0x0c0) != 0)
    {
        n = fargs.n;
        errno = fargs.errno_value;
        return n;
    }

    n = glibc_recvfrom(fargs.sockfd, fargs.buf, fargs.count, fargs.flags, fargs.dest_addr, fargs.addrlen);

    fargs.mask = 0xff;
    fargs.n = n;
    fargs.errno_value = errno;

    recvfrom_function_hook(&fargs);

    n = fargs.n;
    errno = fargs.errno_value;
    return n;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    ssize_t                 n;
    recvmsg_function_args_t fargs;
    fargs.mask = 0x07;
    fargs.sockfd = sockfd;
    fargs.msg = msg;
    fargs.flags = flags;

    recvmsg_function_hook(&fargs);

    if((fargs.mask & 0x018) != 0)
    {
        n = fargs.n;
        errno = fargs.errno_value;
        return n;
    }

    n = glibc_recvmsg(fargs.sockfd, fargs.msg, fargs.flags);

    fargs.mask = 0x1f;
    fargs.n = n;
    fargs.errno_value = errno;

    recvmsg_function_hook(&fargs);

    n = fargs.n;
    errno = fargs.errno_value;
    return n;
}

int unlink(const char *pathname)
{
    ssize_t                n;
    unlink_function_args_t fargs;
    fargs.mask = 0x01;
    fargs.pathname = pathname;

    unlink_function_hook(&fargs);

    if((fargs.mask & 0x06) != 0)
    {
        n = fargs.n;
        errno = fargs.errno_value;
        return n;
    }

    n = glibc_unlink(fargs.pathname);

    fargs.mask = 0x07;
    fargs.n = n;
    fargs.errno_value = errno;

    unlink_function_hook(&fargs);

    n = fargs.n;
    errno = fargs.errno_value;
    return n;
}

int unlinkat(int dirfd, const char *pathname, int flags)
{
    ssize_t                  n;
    unlinkat_function_args_t fargs;
    fargs.mask = 0x07;
    fargs.dirfd = dirfd;
    fargs.pathname = pathname;
    fargs.flags = flags;

    unlinkat_function_hook(&fargs);

    if((fargs.mask & 0x018) != 0)
    {
        n = fargs.n;
        errno = fargs.errno_value;
        return n;
    }

    n = glibc_unlinkat(fargs.dirfd, fargs.pathname, fargs.flags);

    fargs.mask = 0x1f;
    fargs.n = n;
    fargs.errno_value = errno;

    unlinkat_function_hook(&fargs);

    n = fargs.n;
    errno = fargs.errno_value;
    return n;
}

char *getcwd(char *buf, size_t size)
{
    char                  *text;
    getcwd_function_args_t fargs;
    fargs.mask = 0x03;
    fargs.buf = buf;
    fargs.size = size;

    getcwd_function_hook(&fargs);

    if((fargs.mask & 0x0c) != 0)
    {
        text = fargs.text;
        errno = fargs.errno_value;
        return text;
    }

    text = glibc_getcwd(fargs.buf, fargs.size);

    fargs.mask = 0x0f;
    fargs.text = text;
    fargs.errno_value = errno;

    getcwd_function_hook(&fargs);

    text = fargs.text;
    errno = fargs.errno_value;
    return text;
}

int fsync(int fd)
{
    int                   ret;
    fsync_function_args_t fargs;
    fargs.mask = 0x01;
    fargs.fd = fd;

    fsync_function_hook(&fargs);

    if((fargs.mask & 0x06) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_fsync(fargs.fd);

    fargs.mask = 0x07;
    fargs.ret = ret;
    fargs.errno_value = errno;

    fsync_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int fdatasync(int fd)
{
    int                       ret;
    fdatasync_function_args_t fargs;
    fargs.mask = 0x01;
    fargs.fd = fd;

    fdatasync_function_hook(&fargs);

    if((fargs.mask & 0x06) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_fdatasync(fargs.fd);

    fargs.mask = 0x07;
    fargs.ret = ret;
    fargs.errno_value = errno;

    fdatasync_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int dup(int oldfd)
{
    int                 fd;
    dup_function_args_t fargs;
    fargs.mask = 0x01;
    fargs.oldfd = oldfd;

    dup_function_hook(&fargs);

    if((fargs.mask & 0x06) != 0)
    {
        fd = fargs.fd;
        errno = fargs.errno_value;
        return fd;
    }

    fd = glibc_dup(fargs.oldfd);

    fargs.mask = 0x07;
    fargs.fd = fd;
    fargs.errno_value = errno;

    dup_function_hook(&fargs);

    fd = fargs.fd;
    errno = fargs.errno_value;
    return fd;
}

int dup2(int oldfd, int newfd)
{
    int                  fd;
    dup2_function_args_t fargs;
    fargs.mask = 0x03;
    fargs.oldfd = oldfd;
    fargs.newfd = newfd;

    dup2_function_hook(&fargs);

    if((fargs.mask & 0x0c) != 0)
    {
        fd = fargs.fd;
        errno = fargs.errno_value;
        return fd;
    }

    fd = glibc_dup2(fargs.oldfd, fargs.newfd);

    fargs.mask = 0x0f;
    fargs.fd = fd;
    fargs.errno_value = errno;

    dup2_function_hook(&fargs);

    fd = fargs.fd;
    errno = fargs.errno_value;
    return fd;
}

int truncate(const char *path, off_t len)
{
    int                      ret;
    truncate_function_args_t fargs;
    fargs.mask = 0x03;
    fargs.path = path;
    fargs.len = len;

    truncate_function_hook(&fargs);

    if((fargs.mask & 0x0c) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_truncate(fargs.path, fargs.len);

    fargs.mask = 0x0f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    truncate_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int ftruncate(int fd, off_t len)
{
    int                       ret;
    ftruncate_function_args_t fargs;
    fargs.mask = 0x03;
    fargs.fd = fd;
    fargs.len = len;

    ftruncate_function_hook(&fargs);

    if((fargs.mask & 0x0c) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_ftruncate(fargs.fd, fargs.len);

    fargs.mask = 0x0f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    ftruncate_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int socket(int domain, int type, int protocol)
{
    int                    ret;
    socket_function_args_t fargs;
    fargs.mask = 0x07;
    fargs.domain = domain;
    fargs.type = type;
    fargs.protocol = protocol;

    socket_function_hook(&fargs);

    if((fargs.mask & 0x18) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_socket(fargs.domain, fargs.type, fargs.protocol);

    fargs.mask = 0x1f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    socket_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int getsockopt(int socket, int level, int option_name, void *option_value, socklen_t *option_len)
{
    int                        ret;
    getsockopt_function_args_t fargs;
    fargs.mask = 0x1f;
    fargs.socket = socket;
    fargs.level = level;
    fargs.option_name = option_name;
    fargs.option_value = option_value;
    fargs.option_len = option_len;

    getsockopt_function_hook(&fargs);

    if((fargs.mask & 0x60) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_getsockopt(fargs.socket, fargs.level, fargs.option_name, fargs.option_value, fargs.option_len);

    fargs.mask = 0x7f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    getsockopt_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len)
{
    int                        ret;
    setsockopt_function_args_t fargs;
    fargs.mask = 0x1f;
    fargs.socket = socket;
    fargs.level = level;
    fargs.option_name = option_name;
    fargs.option_value = option_value;
    fargs.option_len = option_len;

    setsockopt_function_hook(&fargs);

    if((fargs.mask & 0x60) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_setsockopt(fargs.socket, fargs.level, fargs.option_name, fargs.option_value, fargs.option_len);

    fargs.mask = 0x7f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    setsockopt_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int                  ret;
    bind_function_args_t fargs;
    fargs.mask = 0x07;
    fargs.sockfd = sockfd;
    fargs.addr = addr;
    fargs.addrlen = addrlen;

    bind_function_hook(&fargs);

    if((fargs.mask & 0x018) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_bind(fargs.sockfd, fargs.addr, fargs.addrlen);

    fargs.mask = 0x1f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    bind_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int listen(int sockfd, int backlog)
{
    int                    ret;
    listen_function_args_t fargs;
    fargs.mask = 0x03;
    fargs.sockfd = sockfd;
    fargs.backlog = backlog;

    listen_function_hook(&fargs);

    if((fargs.mask & 0x0c) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_listen(fargs.sockfd, fargs.backlog);

    fargs.mask = 0x0f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    listen_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int stat(const char *pathname, struct stat *statbuf)
{
    int                  ret;
    stat_function_args_t fargs;
    fargs.mask = 0x03;
    fargs.pathname = pathname;
    fargs.statbuf = statbuf;

    stat_function_hook(&fargs);

    if((fargs.mask & 0x0c) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_stat(fargs.pathname, fargs.statbuf);

    fargs.mask = 0x0f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    stat_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int fstat(int fd, struct stat *statbuf)
{
    int                   ret;
    fstat_function_args_t fargs;
    fargs.mask = 0x03;
    fargs.fd = fd;
    fargs.statbuf = statbuf;

    fstat_function_hook(&fargs);

    if((fargs.mask & 0x0c) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_fstat(fargs.fd, fargs.statbuf);

    fargs.mask = 0x0f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    fstat_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int lstat(const char *pathname, struct stat *statbuf)
{
    int                   ret;
    lstat_function_args_t fargs;
    fargs.mask = 0x03;
    fargs.pathname = pathname;
    fargs.statbuf = statbuf;

    lstat_function_hook(&fargs);

    if((fargs.mask & 0x0c) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_lstat(fargs.pathname, fargs.statbuf);

    fargs.mask = 0x0f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    lstat_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    int                     ret;
    fstatat_function_args_t fargs;
    fargs.mask = 0x0f;
    fargs.dirfd = dirfd;
    fargs.pathname = pathname;
    fargs.statbuf = statbuf;
    fargs.flags = flags;

    fstatat_function_hook(&fargs);

    if((fargs.mask & 0x30) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_fstatat(fargs.dirfd, fargs.pathname, fargs.statbuf, fargs.flags);

    fargs.mask = 0x3f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    fstatat_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int mkdir(const char *pathname, mode_t mode)
{
    int                   ret;
    mkdir_function_args_t fargs;
    fargs.mask = 0x03;
    fargs.pathname = pathname;
    fargs.mode = mode;

    mkdir_function_hook(&fargs);

    if((fargs.mask & 0x0c) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_mkdir(fargs.pathname, fargs.mode);

    fargs.mask = 0x0f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    mkdir_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int fcntl(int fd, int cmd, ...)
{
    int     ret;
    va_list args;
    va_start(args, cmd);
    int arg = va_arg(args, int);
    va_end(args);
    fcntl_function_args_t fargs;
    fargs.mask = 0x07;
    fargs.fd = fd;
    fargs.cmd = cmd;
    fargs.arg = arg;

    fcntl_function_hook(&fargs);

    if((fargs.mask & 0x18) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_fcntl(fargs.fd, fargs.cmd, fargs.arg);

    fargs.mask = 0x1f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    fcntl_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

DIR *opendir(const char *name)
{
    DIR                    *ret;
    opendir_function_args_t fargs;
    fargs.mask = 0x01;
    fargs.name = name;

    opendir_function_hook(&fargs);

    if((fargs.mask & 0x06) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_opendir(fargs.name);

    fargs.mask = 0x1f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    opendir_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

DIR *fdopendir(int fd)
{
    DIR                      *ret;
    fdopendir_function_args_t fargs;
    fargs.mask = 0x01;
    fargs.fd = fd;

    fdopendir_function_hook(&fargs);

    if((fargs.mask & 0x06) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_fdopendir(fargs.fd);

    fargs.mask = 0x1f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    fdopendir_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

struct dirent *readdir(DIR *dirp)
{
    struct dirent          *ret;
    readdir_function_args_t fargs;
    fargs.mask = 0x01;
    fargs.dirp = dirp;

    readdir_function_hook(&fargs);

    if((fargs.mask & 0x06) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_readdir(fargs.dirp);

    fargs.mask = 0x1f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    readdir_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int closedir(DIR *dirp)
{
    int                      ret;
    closedir_function_args_t fargs;
    fargs.mask = 0x01;
    fargs.dirp = dirp;

    closedir_function_hook(&fargs);

    if((fargs.mask & 0x06) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_closedir(fargs.dirp);

    fargs.mask = 0x1f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    closedir_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}

int access(const char *pathname, int mode)
{
    int                    ret;
    access_function_args_t fargs;
    fargs.mask = 0x03;
    fargs.pathname = pathname;
    fargs.mode = mode;

    access_function_hook(&fargs);

    if((fargs.mask & 0x06) != 0)
    {
        ret = fargs.ret;
        errno = fargs.errno_value;
        return ret;
    }

    ret = glibc_access(fargs.pathname, fargs.mode);

    fargs.mask = 0x0f;
    fargs.ret = ret;
    fargs.errno_value = errno;

    access_function_hook(&fargs);

    ret = fargs.ret;
    errno = fargs.errno_value;
    return ret;
}
