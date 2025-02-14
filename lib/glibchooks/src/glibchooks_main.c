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

#define __GLIBCHOOKS_MAIN_C__ 1

#include "glibchooks/glibchooks_internal.h"

/**
 * Note: release build doesn't work.
 */

#if __linux__ || __gnu_hurd__
#define HOOK_LIBC_START_MAIN 1 // hooking main doesn't work, this does
#elif __FreeBSD__
#define HOOK_LIBC_START_MAIN 0
int __FreeBSD__hooked_main_function__(int argc, char *argv[], char *env[]);
#else
#error "OS Not supported"
#endif

extern INTERNAL hook_module_t alloc_module;
extern INTERNAL hook_module_t filedescriptor_module;

static hook_module_t         *modules[] = {&alloc_module, &filedescriptor_module, NULL};

#if HOOK_LIBC_START_MAIN
static int (*glibc__libc_start_main)(int (*main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void(*stack_end));
#else
static int (*program_main)(int argc, char *argv[], char *env[]);
#endif

// because I plan to extend this lib to be able to generate I/O errors (unit testing)
static ssize_t (*glibc_write)(int fd, const void *buffer, size_t count);
static int (*glibc_fsync)(int fd);

static int64_t   program_start_time = 0;
static int64_t   program_stop_time = 0;

INTERNAL int64_t timeus()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    int64_t r = tv.tv_sec;
    r *= 1000000LL;
    r += tv.tv_usec;
    return r;
}

// a few functions to avoid using anything more than "write"

INTERNAL void glibchooks_write(int fd, const char *buffer, size_t len)
{
    do
    {
        ssize_t n = glibc_write(fd, buffer, len);
        if(n < 0)
        {
            int err = errno;
            if(err == EINTR)
            {
                continue;
            }
            break;
        }
        len -= n;
        buffer += n;
    } while(len > 0);
}

INTERNAL void glibchooks_puts(const char *txt)
{
    size_t len = strlen(txt);
    glibchooks_write(1, txt, len);
    glibchooks_write(1, "\n", 1);
    glibc_fsync(1);
}

INTERNAL void glibchooks_vprintf(const char *text, va_list args)
{
    char   buffer[1024];
    size_t buffer_size = sizeof(buffer);
    int    len = vsnprintf(buffer, buffer_size, text, args);
    glibchooks_write(1, buffer, len);
}

INTERNAL void glibchooks_printf(const char *text, ...)
{
    va_list args;
    va_start(args, text);
    glibchooks_vprintf(text, args);
    va_end(args);
}

INTERNAL void *function_hook(const char *restrict name)
{
    void *ptr = dlsym(RTLD_NEXT, name);
    if(ptr == NULL)
    {
        glibchooks_printf("error hooking function '%s': %s\n", name, dlerror());
        exit(1);
    }
    return ptr;
}

/**
 * This function is meant to be hooked by the program.
 */

bool glibchooks_set_real(const char *name, void *hook_function)
{
    for(int i = 0; modules[i] != NULL; ++i)
    {
        function_hooks_t *hooks_table = modules[i]->hook_table;
        if(hooks_table != NULL)
        {
            for(int j = 0; hooks_table[j].name != NULL; ++j)
            {
                if(strcmp(hooks_table[j].name, name) == 0)
                {
                    *hooks_table[j].hook = hook_function;
                    return true;
                }
            }
        }
    }
    fflush(NULL);
    fprintf(stderr, "glibchooks_set: unknown name '%s'\n", name);
    fflush(stderr);
    return false;
}

static void glibc_hooks_init()
{
#if HOOK_LIBC_START_MAIN
    glibc__libc_start_main = function_hook("__libc_start_main");
#else
    // program_main = function_hook("main");
    program_main = __FreeBSD__hooked_main_function__;
#endif
    glibc_write = function_hook("write");
    glibc_fsync = function_hook("fsync");

    for(int i = 0; modules[i] != NULL; ++i)
    {
        modules[i]->init();
    }
}

static void glibc_hooks_finalise()
{
    program_stop_time = timeus();

    FILE       *f = NULL;
    const char *filename = getenv("GLIBCHOOKS_OUTPUT_FILE");

    if(filename != NULL)
    {
        f = fopen(filename, "a+");
    }

    if(f == NULL)
    {
        f = stdout;
    }

    fflush(NULL);
    fprintf(f, "summary:\n");
    int64_t program_time = program_stop_time - program_start_time;
    fprintf(f, "timing: start=%" PRIi64 " stopped=%" PRIi64 " duration=%" PRIi64 " duration_seconds=%f\n", program_start_time, program_stop_time, program_time, (double)program_time / 1000000.0);
    for(int i = 0; modules[i] != NULL; ++i)
    {
        modules[i]->print(f);
    }
    fflush(NULL);
    if(f != stdout)
    {
        fclose(f);
    }
}

#if HOOK_LIBC_START_MAIN
int __libc_start_main(int (*main)(int, char **, char **), int argc, char **ubp_av, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void(*stack_end))
{
    glibc_hooks_init();
    glibchooks_puts("hooks in place (__libc_start_main)");
    atexit(glibc_hooks_finalise);
    program_start_time = timeus();
    int exit_code = glibc__libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
    return exit_code;
}
#else
int glibchooks_main(int argc, char *argv[], char *env[])
{
    glibc_hooks_init();
    glibchooks_puts("hooks in place (main)");
    atexit(glibc_hooks_finalise);
    program_start_time = timeus();
    return program_main(argc, argv, env);
}
#endif
