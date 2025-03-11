#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#define YATEST_MIN(a_, b_) ((a_) <= (b_)) ? (a_) : (b_)

static FILE           *yatest_log_file = NULL;
static pthread_mutex_t yatest_mtx;

static void            yatest_write(FILE *f, const char *text, size_t text_len)
{
    pthread_mutex_lock(&yatest_mtx);
    fwrite(text, text_len, 1, f);
    fflush(f);
    if(yatest_log_file != NULL)
    {
        fwrite(text, text_len, 1, yatest_log_file);
        fflush(yatest_log_file);
    }
    pthread_mutex_unlock(&yatest_mtx);
}

static void yatest_log(const char *text, ...)
{
    int     buffer_size = 65536;
    int     needed_size;
    char   *buffer;
    va_list args;

    for(;;)
    {
        buffer = malloc(buffer_size);
        if(buffer == NULL)
        {
            static const char malloc_null_msg[] = "yatest_log: malloc returned NULL";
            yatest_write(stdout, malloc_null_msg, sizeof(malloc_null_msg) - 1);
            yatest_write(stderr, malloc_null_msg, sizeof(malloc_null_msg) - 1);
            exit(1);
        }
        va_start(args, text);
        needed_size = vsnprintf(buffer, buffer_size, text, args);
        va_end(args);
        if(needed_size < buffer_size)
        {
            break;
        }
        free(buffer);
        buffer_size = needed_size + 2;
    }
    buffer[needed_size++] = '\n';
    yatest_write(stdout, buffer, needed_size);
    free(buffer);
}

static void yatest_err(const char *text, ...)
{
    int     buffer_size = 65536;
    int     needed_size;
    char   *buffer;
    va_list args;
    for(;;)
    {
        buffer = malloc(buffer_size);
        if(buffer == NULL)
        {
            static const char malloc_null_msg[] = "yatest_err: malloc returned NULL";
            yatest_write(stdout, malloc_null_msg, sizeof(malloc_null_msg) - 1);
            yatest_write(stderr, malloc_null_msg, sizeof(malloc_null_msg) - 1);
            exit(1);
        }
        va_start(args, text);
        needed_size = vsnprintf(buffer, buffer_size, text, args);
        va_end(args);
        if(needed_size < buffer_size)
        {
            break;
        }
        free(buffer);
        buffer_size = needed_size + 2;
    }
    buffer[needed_size++] = '\n';
    yatest_write(stderr, buffer, needed_size);
    free(buffer);
}

void yatest_hexdump(const void *buffer_, const void *limit_)
{
    const uint8_t *buffer = (const uint8_t *)buffer_;
    const uint8_t *limit = (const uint8_t *)limit_;
    uint32_t       width = 16;
    char           line[1024];
    const char    *line_limit = &line[sizeof(line)];

    while(buffer < limit)
    {
        uint32_t total = limit - buffer;
        uint32_t remaining = YATEST_MIN(total, width);
        uint32_t padding = width - remaining;

        char    *p = line;
        for(uint32_t i = 0; i < remaining; ++i)
        {
            snprintf(p, line_limit - p, "%02x ", buffer[i]);
            p += 3;
        }
        memset(p, ' ', padding * 3);
        p += padding * 3;
        *p++ = '|';
        *p++ = ' ';
        for(uint32_t i = 0; i < remaining; ++i)
        {
            char c = buffer[i];
            if((c >= ' ') /* && (c <= 127)*/)
            {
                *p = c;
            }
            else
            {
                *p = '.';
            }
            ++p;
        }
        *p = '\0';
        yatest_log(line);

        buffer += remaining;
    }
}

void yatest_hexdump_err(const void *buffer_, const void *limit_)
{
    const uint8_t *buffer = (const uint8_t *)buffer_;
    const uint8_t *limit = (const uint8_t *)limit_;
    uint32_t       width = 16;
    char           line[1024];
    const char    *line_limit = &line[sizeof(line)];

    while(buffer < limit)
    {
        uint32_t total = limit - buffer;
        uint32_t remaining = YATEST_MIN(total, width);
        uint32_t padding = width - remaining;

        char    *p = line;
        for(uint32_t i = 0; i < remaining; ++i)
        {
            snprintf(p, line_limit - p, "%02x ", buffer[i]);
            p += 3;
        }
        memset(p, ' ', padding * 3);
        p += padding * 3;
        *p++ = '|';
        *p++ = ' ';
        for(uint32_t i = 0; i < remaining; ++i)
        {
            char c = buffer[i];
            if((c >= ' ') /* && (c <= 127)*/)
            {
                *p = c;
            }
            else
            {
                *p = '.';
            }
            ++p;
        }
        *p = '\0';
        yatest_err(line);

        buffer += remaining;
    }
}

struct yatest_kstr_vstr_s
{
    const char *key;
    const char *value;
};

typedef struct yatest_kstr_vstr_s yatest_kstr_vstr_t;

struct yatest_entry_s
{
    const char *name;
    int (*f)();
};

typedef struct yatest_entry_s yatest_entry_t;

static inline void            yatest_time_now(int64_t *tp)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    *tp = (int64_t)tv.tv_sec * 1000000LL + (int64_t)tv.tv_usec;
}

static inline void yatest_time_sleep(int64_t timeus)
{
    int64_t now;
    yatest_time_now(&now);
    int64_t end = now + timeus;
    do
    {
        usleep(end - now);
        yatest_time_now(&now);
    } while(now <= end);
}

static inline void yatest_timer_start(int64_t *tp) { yatest_time_now(tp); }

static inline void yatest_timer_stop(int64_t *tp)
{
    int64_t now;
    yatest_time_now(&now);
    *tp = now - *tp;
}

static inline double yatest_timer_seconds(int64_t *tp) { return ((double)(*tp)) / 1000000.0; }

static inline void   yatest_random_init(uint64_t *rnd)
{
    *rnd = 1129291482536299457ULL; // prime
}

static inline uint64_t yatest_random_next64(uint64_t *rnd)
{
    *rnd = *rnd * 9037112199850418137 + 2801324094080402467;
    if(*rnd == 0)
    {
        *rnd = 1129291482536299457ULL;
    }
    return *rnd;
}

static inline uint64_t yatest_random_next32(uint64_t *rnd) { return (uint32_t)yatest_random_next64(rnd); }

int64_t                yatest_time()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int64_t now = tv.tv_sec * 1000000LL + tv.tv_usec;
    return now;
}

void yatest_sleep(int seconds)
{
    int64_t start = yatest_time();
    int64_t stop = start + 1000000LL * seconds;
    do
    {
        usleep(stop - start);
        start = yatest_time();
    } while(stop > start);
}

static inline bool yatest_pid_exists(pid_t pid) { return kill(pid, 0) >= 0; }

void               yatest_mkdir(const char *path)
{
    struct stat st;
    if(stat(path, &st) < 0)
    {
        if(errno == ENOENT)
        {
            if(mkdir(path, 0755) < 0)
            {
                yatest_err("yatest_mkdir(%s): mkdir failed with %s", path, strerror(errno));
                exit(1);
            }
        }
        else
        {
            yatest_err("yatest_mkdir(%s): stat failed with %s", path, strerror(errno));
            exit(1);
        }
    }
    else
    {
        if(!S_ISDIR(st.st_mode))
        {
            yatest_err("yatest_mkdir(%s): entry exists but is not a directory", path);
            exit(1);
        }
    }
}

static inline void *yatest_malloc(size_t size)
{
    void *ptr = malloc(size);
    if(ptr != NULL)
    {
        memset(ptr, 0, size);
        return ptr;
    }
    else
    {
        yatest_err("malloc(%x) failed: internal error", size);
        exit(1);
    }
}

static inline char *yatest_strdup(const char *text)
{
    if(text != NULL)
    {
        size_t text_size = strlen(text) + 1;
        char  *text_dup = (char *)yatest_malloc(text_size);
        memcpy(text_dup, text, text_size);
        return text_dup;
    }
    else
    {
        yatest_err("yatest_strdup called over NULL");
        exit(1);
    }
}

static void yatest_mutex_init()
{
    int                 err;
    pthread_mutexattr_t mta;
    err = pthread_mutexattr_init(&mta);
    if(err != 0)
    {
        perror("yatest: failed to init mutex attribute");
        exit(1);
    }

    err = pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);

    if(err != 0)
    {
        perror("yatest: failed to set mutex recursive attribute");
        exit(1);
    }

    err = pthread_mutex_init(&yatest_mtx, &mta);

    if(err != 0)
    {
        perror("yatest: failed to init mutex");
        exit(1);
    }

    pthread_mutexattr_destroy(&mta);
}

#define YATEST_TABLE_BEGIN             static const yatest_entry_t yatest_entry_table[] = {
#define YATEST(__test_function_name__) {#__test_function_name__, __test_function_name__},
#define YATEST_TABLE_END                                                                                                                                                                                                                       \
    {                                                                                                                                                                                                                                          \
        NULL, NULL                                                                                                                                                                                                                             \
    }                                                                                                                                                                                                                                          \
    }                                                                                                                                                                                                                                          \
    ;                                                                                                                                                                                                                                          \
    static int yatest_run(const char *name)                                                                                                                                                                                                    \
    {                                                                                                                                                                                                                                          \
        yatest_mutex_init();                                                                                                                                                                                                                   \
        const yatest_entry_t *entry = &yatest_entry_table[0];                                                                                                                                                                                  \
        bool                  all = strcmp(name, "*") == 0;                                                                                                                                                                                    \
        while(entry->name != NULL)                                                                                                                                                                                                             \
        {                                                                                                                                                                                                                                      \
            if(all || (strcmp(entry->name, name) == 0))                                                                                                                                                                                        \
            {                                                                                                                                                                                                                                  \
                int    ret;                                                                                                                                                                                                                    \
                time_t ts = time(NULL);                                                                                                                                                                                                        \
                char   yatest_log_file_name[4096];                                                                                                                                                                                             \
                snprintf(yatest_log_file_name, sizeof(yatest_log_file_name), "yatest-%08x-%s.log", (int32_t)ts, entry->name);                                                                                                                  \
                yatest_log_file = fopen(yatest_log_file_name, "a");                                                                                                                                                                            \
                yatest_log("YATEST: %s begin\n", entry->name);                                                                                                                                                                                 \
                ret = entry->f();                                                                                                                                                                                                              \
                if((ret & 0xffff0000) == 0x80000000)                                                                                                                                                                                           \
                {                                                                                                                                                                                                                              \
                    yatest_log("YATEST: %s end with %i = %x (%s)\n", entry->name, ret, ret, strerror(ret & 0xffff));                                                                                                                           \
                }                                                                                                                                                                                                                              \
                else                                                                                                                                                                                                                           \
                {                                                                                                                                                                                                                              \
                    yatest_log("YATEST: %s end with %i = %x\n", entry->name, ret, ret);                                                                                                                                                        \
                }                                                                                                                                                                                                                              \
                if(!all || (ret != 0))                                                                                                                                                                                                         \
                {                                                                                                                                                                                                                              \
                    return ret;                                                                                                                                                                                                                \
                }                                                                                                                                                                                                                              \
            }                                                                                                                                                                                                                                  \
            ++entry;                                                                                                                                                                                                                           \
        }                                                                                                                                                                                                                                      \
        if(all)                                                                                                                                                                                                                                \
        {                                                                                                                                                                                                                                      \
            printf("all tests done\n");                                                                                                                                                                                                        \
            return 0;                                                                                                                                                                                                                          \
        }                                                                                                                                                                                                                                      \
        printf("unknown test: '%s'\n", name);                                                                                                                                                                                                  \
        fflush(stdout);                                                                                                                                                                                                                        \
        return 1;                                                                                                                                                                                                                              \
    }                                                                                                                                                                                                                                          \
                                                                                                                                                                                                                                               \
    static void yatest_print_all(int print)                                                                                                                                                                                                    \
    {                                                                                                                                                                                                                                          \
        const yatest_entry_t *entry = &yatest_entry_table[0];                                                                                                                                                                                  \
        while(entry->name != NULL)                                                                                                                                                                                                             \
        {                                                                                                                                                                                                                                      \
            if(print)                                                                                                                                                                                                                          \
                puts(entry->name);                                                                                                                                                                                                             \
            ++entry;                                                                                                                                                                                                                           \
        }                                                                                                                                                                                                                                      \
    }                                                                                                                                                                                                                                          \
    static void silence_warnings()                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                          \
        int64_t t;                                                                                                                                                                                                                             \
        yatest_log("");                                                                                                                                                                                                                        \
        yatest_err("");                                                                                                                                                                                                                        \
        yatest_timer_start(&t);                                                                                                                                                                                                                \
        yatest_timer_stop(&t);                                                                                                                                                                                                                 \
    }                                                                                                                                                                                                                                          \
    int main(int argc, char *argv[])                                                                                                                                                                                                           \
    {                                                                                                                                                                                                                                          \
        if(argc == 2)                                                                                                                                                                                                                          \
        {                                                                                                                                                                                                                                      \
            yatest_print_all(0);                                                                                                                                                                                                               \
            return yatest_run(argv[1]);                                                                                                                                                                                                        \
        }                                                                                                                                                                                                                                      \
        else                                                                                                                                                                                                                                   \
        {                                                                                                                                                                                                                                      \
            yatest_print_all(1);                                                                                                                                                                                                               \
            silence_warnings();                                                                                                                                                                                                                \
            return 1;                                                                                                                                                                                                                          \
        }                                                                                                                                                                                                                                      \
    }
