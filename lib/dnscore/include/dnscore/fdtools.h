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
 *----------------------------------------------------------------------------*/

/**-----------------------------------------------------------------------------
 * @defgroup dnscoretools Generic Tools
 * @ingroup dnscore
 * @brief
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#include <dirent.h>
#include <dnscore/sys_types.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#if __windows__
#include <direct.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#define US_RATE(x) (0.000001 * (x))

#ifndef _DIRENT_HAVE_D_TYPE
#ifndef DT_UNKNOWN
#define DT_UNKNOWN 0
#endif
#ifndef DT_REG
#define DT_REG 8
#endif
#ifndef DT_DIR
#define DT_DIR 4
#endif
#endif

#ifndef O_CLOEXEC
#if __linux__ || __OpenBSD__
#define O_CLOEXEC 0200000
#elif __FreeBSD__
#define O_CLOEXEC 04000000
#elif __APPLE__
#if __DARWIN_C_LEVEL >= 200809L
#define O_CLOEXEC 0x1000000
#endif
#elif __windows__
#define O_CLOEXEC 0200000
#else
#error "O_CLOEXEC not available and I don't know what placeholder value to use for this system"
#endif
#define DNSCORE_FDTOOLS_CLOEXEC 1
#endif

/**
 * When stored statically, use dirent_storage to mitigate very long names issues.
 * Note also than on some architectures (ie: Solaris) the space reserved for the
 * name is only 1 byte.
 *
 */

union dirent_storage
{
    struct dirent _dirent;
    char          _reserved[PATH_MAX];
};

typedef union dirent_storage dirent_storage;

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

int     sendfully_limited(int fd, const void *buf, int count, int flags, double minimum_rate_us);

ssize_t readfully_limited(int fd, void *buf, size_t count, double minimum_rate_us);

/**
 * Reads fully the buffer from the fd or up until timeout_seconds has elapsed
 * The socket need to have a read timeout applied.
 * It will only return a short count for system errors.
 *
 * ie: fs full, fd invalid/closed, ...
 */

ssize_t readfully_ex(int fd, void *buf, size_t length, int timeout_seconds);

ssize_t readfully_limited_ex(int fd, void *buf, size_t count, int64_t timeout_us, double minimum_rate_us);

int     recvfully_limited_ex(int fd, void *buf, int count, int flags, int64_t timeout_us, double minimum_rate_us);

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
 * Copies the absolute path of a file into a buffer.
 *
 * @param filename the file name
 * @param buffer the output buffer
 * @param buffer_size the size of the output buffer
 * @return the string length (without the terminator)
 */

ya_result file_get_absolute_path(const char *filename, char *buffer, size_t buffer_size);

/**
 * Copies the absolute path of the file parent directory in the buffer.
 *
 * @param filename the filename, with or without an absolute or relative path
 * @param buffer the destination buffer
 * @param buffer_size the destination buffer size
 */

ya_result file_get_absolute_parent_directory(const char *filename, char *buffer, size_t buffer_size);

/**
 * Opens a file. (see man 2 open)
 * Handles EINTR and other retry errors.
 * Safe to use in the logger thread as it only logs (debug) if the current
 * thread is not the logger's
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
 * Wrapper
 *
 * @param template
 * @return
 */

int mkstemp_ex(char *tmp_name_template);

/**
 * Opens a file, create if it does not exist. (see man 2 open with O_CREAT)
 * Handles EINTR and other retry errors.
 * This version of open_create_ex does NOT log anything, which is very important sometimes in the logger thread
 *
 * @param fd
 * @return
 */

ya_result open_create_ex_nolog(const char *pathname, int flags, mode_t mode);

/**
 * Closes a file descriptor (see man 2 close)
 * Handles EINTR and other retry errors.
 * At return the file will be closed or not closable.
 *
 * @param fd
 * @return
 */

#if !DNSCORE_HAS_CLOSE_EX_REF
ya_result close_ex(int fd);
#else
ya_result close_ex_ref(int *fdp);
#define close_ex(fd_) close_ex_ref((int *)&(fd_))
#endif

#if !DNSCORE_HAS_CLOSE_EX_REF
ya_result socketclose_ex(int fd);
#else
ya_result socketclose_ex_ref(int *fdp);
#define socketclose_ex(fd_) socketclose_ex_ref((int *)&(fd_))
#endif

/**
 * Closes a file descriptor (see man 2 close)
 * Handles EINTR and other retry errors.
 * At return the file will be closed or not closable.
 *
 * @param fd
 * @return
 */

#if !DNSCORE_HAS_CLOSE_EX_REF
ya_result close_ex_nolog(int fd);
#else
ya_result close_ex_nolog_ref(int *fdp);
#define close_ex_nolog(fd_) close_ex_nolog_ref((int *)&(fd_))
#endif

int fsync_ex(int fd);

int fdatasync_ex(int fd);

int dup_ex(int fd);

int dup2_ex(int old_fd, int new_fd);

int truncate_ex(const char *path, off_t len);

int ftruncate_ex(int fd, off_t len);

/**
 * Returns the type of socket.
 *
 * @param fd the file descriptor of the socket
 * @return SOCK_STREAM, SOCK_DGRAM, SOCK_RAW or an errno error code like MAKE_ERRON_ERROR(EBADF) or
 * MAKE_ERRON_ERROR(ENOTSOCK)
 */

ya_result fd_getsockettype(int fd);

/**
 * Returns the stat struct of a file
 *
 * @param name
 * @return
 */

static inline int filestat(const char *name, struct stat *sp) { return stat(name, sp); }

/**
 * Returns the size of a file
 *
 * @param name
 * @return
 */

int64_t filesize(const char *name);

/**
 * Checks for existence of a file/dir/link
 *
 * @param name the file name
 *
 * @return 1 if the file exists, 0 if the file does not exists, or an error code (access rights & cie)
 */

ya_result file_exists(const char *name);

/**
 *
 * Checks if a file exists and is a link
 *
 * @param name the file name
 *
 * @return  0 : not a link
 *          1 : a link
 *        < 0 : error
 */

ya_result file_is_link(const char *name);

/**
 *
 * Checks if a file exists and is a directory
 *
 * @param name the file name
 *
 * @return  0 : not a link
 *          1 : a link
 *        < 0 : error
 */
ya_result file_is_directory(const char *name);

/**
 *
 * @param pathname
 * @param mode
 * @return
 */

#define MKDIR_EX_PATH_TO_FILE 1 // ie: pathname points to a file, so skip the file part

int mkdir_ex(const char *pathname, mode_t mode, uint32_t flags);

/**
 * Returns the modification time of the file in microseconds
 * This does not mean the precision of the time is that high.
 * This is only to simplify reading the time on a file.
 *
 * @param name the file name
 * @param timestamp a pointer to the timestamp
 * @return an error code
 */

ya_result file_mtime(const char *name, int64_t *timestamp);

/**
 * Returns the modification time of the file in microseconds
 * This does not mean the precision of the time is that high.
 * This is only to simplify reading the time on a file.
 *
 * @param fd the file descriptor
 * @param timestamp a pointer to the timestamp
 * @return an error code
 */

ya_result fd_mtime(int fd, int64_t *timestamp);

ya_result fd_setcloseonexec(int fd);

ya_result fd_setnonblocking(int fd);

ya_result fd_setblocking(int fd);

/**
 * Fixes an issue with the dirent not always set as expected.
 *
 * The type can be set to DT_UNKNOWN instead of file or directory.
 * In that case the function will call stats to get the type.
 */

uint8_t dirent_get_file_type(const char *folder, const char *name);

uint8_t dirent_get_type_from_fullpath(const char *fullpath);

#define READDIR_CALLBACK_CONTINUE 0
#define READDIR_CALLBACK_ENTER    1
#define READDIR_CALLBACK_EXIT     2

typedef ya_result readdir_callback(const char *basedir, const char *file, uint8_t filetype, void *args);

/**
 * Calls the callback for every entry from basedir
 *
 * @param basedir the base directory
 * @param func the callback to call
 * @param args the arg to give to the callback
 *
 * @return an error code
 */

ya_result readdir_forall(const char *basedir, readdir_callback *func, void *args);

/**
 * Deletes a directory and, optionally, its content.
 *
 * @param directory the directory
 * @param recursive recursively delete the content
 *
 * @return an error code
 */

ya_result rmdir_ex(const char *directory, bool recursive);

#define ACCESS_CHECK_READ      R_OK
#define ACCESS_CHECK_WRITE     W_OK
#define ACCESS_CHECK_EXECUTE   X_OK
#define ACCESS_CHECK_EXISTS    F_OK

#define ACCESS_CHECK_READWRITE (ACCESS_CHECK_READ | ACCESS_CHECK_WRITE)

struct storage_info_s
{
    int64_t size_total;
    int64_t size_free;
    int64_t inodes_total;
    int64_t inodes_free;
};

typedef struct storage_info_s storage_info_t;

ya_result                     access_check(const char *path, int mode);

/**
 * Returns the available space in bytes in the filesystem hosting the file.
 *
 * @param path the file in the filesystem
 * @param si a pointer to a storage_info_t structure
 *
 * @return the free size in bytes
 */

int64_t storage_info(const char *path, storage_info_t *si);

#ifdef __cplusplus
}
#endif

/** @} */
