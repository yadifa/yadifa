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
 * @ingroup dnscore
 * @brief
 *
 *
 *
 * @{
 *----------------------------------------------------------------------------*/
#pragma once

/**
 * This helper header allows to chose the kind of mutex used.
 * This is part of the sendto queue experiment.
 */

#include <dnscore/dnscore_config_features.h>

#if !defined(__OpenBSD__) && !defined(__gnu_hurd__)
#define MUTEX_PROCESS_SHARED_SUPPORTED 1
#else
#define MUTEX_PROCESS_SHARED_SUPPORTED 0
#endif

#ifndef DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#error "DNSCORE_HAS_MUTEX_DEBUG_SUPPORT must be set to either 0 or 1"
#endif

/**
 * Keeps the owner and the stacktrace of a mutex (Has no effect if MUTEX_DEBUG is disabled)
 */

#define DNSCORE_HAS_MUTEX_NOLOCK_CHECK          0

/**
 * Keeps track of who is locking and who is waiting
 * Only use this if you are debugging mutexes. (Has no effect if MUTEX_DEBUG is disabled)
 */

#define DNSCORE_MUTEX_CONTENTION_MONITOR        0

/**
 * Notify the monitor is enabled during the build. (Has no effect if MUTEX_DEBUG is disabled)
 * Note that it is never build for a release build anymore and it shouldn't be an issue in DEBUG.
 */

#define DNSCORE_MUTEX_CONTENTION_MONITOR_NOTIFY 0

#ifndef MUTEX_USE_SPINLOCK
#define MUTEX_USE_SPINLOCK 0 // keep it that way
#endif

#if MUTEX_USE_SPINLOCK && DNSCORE_HAS_MUTEX_DEBUG_SUPPORT
#error "Cannot mix spinlock and mutex debug support"
#endif

// these two are for error reporting in debug builds
#define MUTEX_LOCKED_TOO_MUCH_TIME_US 5000000
#define MUTEX_WAITED_TOO_MUCH_TIME_US 2000000

/** @} */
