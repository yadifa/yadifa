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
 * @defgroup
 * @ingroup
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/

#pragma once

#include <dnscore/sys_types.h>

#include <sys/types.h>
#include <unistd.h>

/**
 * Read pid file, program quits on log_quit
 *
 * Made available again for a project still using it.
 *
 * @param pid_file_path the path of the pid file
 * @param pidp a pointer that will be set with the pid from inside the file
 *
 * @return SUCCESS or an error code
 */

ya_result pid_file_read(const char *pid_file_path, pid_t *pidp);

/**
 * Creates or overwrites a pid file with its new process id
 * Doesn't work if another program has already created the pid file
 *
 * @param pid_file_path the path of the pid file
 * @param pidp a pointer that will be set with the pid of the running instance of the program
 * @param new_uid the user owner of the file (if the program runs as root), it's doing a fchown
 * @param new_gid the group owner of the file (if the program runs as root), it's doing a fchown
 *
 * @return SUCCESS or an error code
 */

ya_result pid_file_create(const char *pid_file_path, pid_t *pidp, uid_t uid, gid_t gid);

/**
 * Check if program is already running checking the existence of a pid file.
 *
 * @param pid_file_path the path of the pid file
 * @param pidp a pointer that will be set with the pid from inside the file
 *
 * @return SUCCESS if the program doesn't appear to be running.
 * @return an error code (INVALID_PATH or PID_LOCKED)
 */

ya_result pid_check_running_program(const char *pid_file_path, pid_t *out_pid);

/**
 * Deletes a pid file.
 * File is being opened and locked while the deletion occurs. This is to avoid race conditions.
 *
 * @param pid_file_path the path of the pid file
 */

void pid_file_destroy(const char *pid_file_path);

/** @} */
