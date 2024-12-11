#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "glibchooks/glibchooks_controller.h"
#include "glibchooks/filedescriptor.h"

static void my_open_function_hook(open_function_args_t *args)
{
    args->mask = 0x1f;
    args->fd = -1;
    args->errno_value = ENOENT;
}

static void my_write_function_hook(write_function_args_t *args)
{
    static bool recursion = false;

    if(recursion)
    {
        return;
    }

    recursion = true;

    if(args->mask == 0x07)
    {
        const char *text = args->buf;
        for(int i = 0; i < args->count; ++i)
        {
            putchar(text[i]);
        }
    }

    recursion = false;
}

int main(int argc, char *argv[])
{
    printf("main called with %i arguments:\n", argc);
    fflush(stdout);
    for(int i = 0; i < argc; ++i)
    {
        printf("[%3i] '%s'\n", i, argv[i]);
    }

    ssize_t ret = glibchooks_controller_init();
    printf("glibchooks_controller_init() = %li\n", ret);
    if(ret >= 0)
    {
        ret = glibchooks_set("open", my_open_function_hook);
        printf("glibchooks_hook_set(\"open\", my_open_function_hook) = %li\n", ret);
        glibchooks_set("write", my_write_function_hook);
    }

    int fd = open("/etc/passwd", O_RDONLY, 0);
    if(fd < 0)
    {
        printf("error: %i (%s)\n", errno, strerror(errno));
        write(-1, "Hello World", 11);
    }
    else
    {
        puts("success (NOT EXPECTED)");
    }
    fflush(stdout);

    void *p = malloc(65536);
    free(p);

    return 0;
}
