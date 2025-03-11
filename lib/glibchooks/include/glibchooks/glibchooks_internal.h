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
#define _GNU_SOURCE
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <sys/time.h>
#include <dlfcn.h>
#include <errno.h>

#if !__windows__
#define INTERNAL __attribute__((visibility("hidden")))
#else
#define INTERNAL
#endif

#define MAX(a_, b_) ((a_) > (b_)) ? (a_) : (b_)

struct hook_table_s
{
    const char *name;
    void      **ptrp;
};

typedef struct hook_table_s hook_table_t;

struct function_hooks_s
{
    const char *name;
    void      **hook;
};

typedef struct function_hooks_s function_hooks_t;

struct hook_module_s
{
    const char *const name;
    function_hooks_t *hook_table;
    void (*init)(void);
    void (*print)(FILE *f);
};

typedef struct hook_module_s hook_module_t;

INTERNAL void                glibchooks_write(int fd, const char *buffer, size_t len);
INTERNAL void                glibchooks_puts(const char *txt);
INTERNAL void                glibchooks_vprintf(const char *text, va_list args);
INTERNAL void                glibchooks_printf(const char *text, ...);
INTERNAL void               *function_hook(const char *restrict name);
