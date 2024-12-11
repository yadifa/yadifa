#pragma once

#include "yatest.h"
#include <dnscore/network.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/wait.h>

#ifndef YATEST_SOCKETSERVER_START_NO_FORK
#define YATEST_SOCKETSERVER_START_NO_FORK 0
#endif

union yatest_socketaddress_u
{
    struct sockaddr         sa;
    struct sockaddr_in      sa4;
    struct sockaddr_in6     sa6;
    struct sockaddr_storage ss;
    unsigned short int      family;
};

typedef union yatest_socketaddress_u yatest_socketaddress_t;

struct yatest_serverclient_s
{
    socklen_t              sa_len;
    int                    sockfd;
    yatest_socketaddress_t sa;
};

struct yatest_socketserver_s;

typedef struct yatest_serverclient_s yatest_serverclient_t;

typedef void(yatest_serversocket_client_init_t)(struct yatest_socketserver_s *);
typedef void(yatest_serversocket_client_handler_t)(struct yatest_socketserver_s *, yatest_serverclient_t *);
typedef void(yatest_serversocket_client_finalise_t)(struct yatest_socketserver_s *);

struct yatest_socketserver_mtx_s
{
    pthread_mutex_t mtx;
    pthread_cond_t  cond;
    atomic_intptr_t serial;
    atomic_intptr_t state;
    atomic_intptr_t stop;
};

typedef struct yatest_socketserver_mtx_s yatest_socketserver_control_t;

enum yatest_serversocket_handler_mode_e
{
    YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE = 0,
    YATEST_SERVERSOCKET_HANDLER_MODE_THREADPOOL = 1,
    YATEST_SERVERSOCKET_HANDLER_MODE_FORK = 2,
};

struct yatest_socketserver_s
{
    char                                   *server_ip_text;
    uint8_t                                *shared_memory;
    size_t                                  shared_memory_size;
    yatest_socketserver_control_t          *control;
    socklen_t                               server_sa_len;
    int                                     server_ip_port;
    int                                     socket_type;
    int                                     server_socket;
    pthread_t                               server_thread;
    pid_t                                   child_pid;
    enum yatest_serversocket_handler_mode_e handler_mode;
    yatest_socketaddress_t                  server_sa;
    yatest_serversocket_client_init_t      *init;
    yatest_serversocket_client_handler_t   *handler;
    yatest_serversocket_client_finalise_t  *finalise;
    struct yatest_socketserver_s           *next;
    bool                                    initialised;
};

#define YATEST_SOCKETSERVER_UNINITIALISED {NULL, NULL, 0, NULL, 0, 0, 0, 0, 0, 0, 0, {.family = 0}, NULL, NULL, NULL, NULL, false}

typedef struct yatest_socketserver_s yatest_socketserver_t;

socklen_t                            yatest_socketaddress_init(yatest_socketaddress_t *sa, const char *listento, int port)
{
    int       ret;
    socklen_t sa_len;
    uint8_t   ip_raw[16];

    yatest_log("yatest_socketaddress_init(%s, %i) parsing", listento, port);

    if(inet_pton(AF_INET, listento, ip_raw) == 1)
    {
        ret = 4;
    }
    else if(inet_pton(AF_INET6, listento, ip_raw) == 1)
    {
        ret = 16;
    }
    else
    {
        yatest_err("yatest_serversocket_create(%s, %i): inet_pton failed", listento, port);
        exit(1);
    }
    switch(ret)
    {
        case 4:
        {
            sa->sa4.sin_family = AF_INET;
            sa->sa4.sin_port = htons(port);
            memcpy(&sa->sa4.sin_addr, ip_raw, 4);
            sa_len = sizeof(sa->sa4);
            break;
        }
        case 16:
        {
            sa->sa6.sin6_family = AF_INET6;
            sa->sa6.sin6_port = htons(port);
            sa->sa6.sin6_flowinfo = 0;
            memcpy(&sa->sa6.sin6_addr, ip_raw, 16);
            sa->sa6.sin6_scope_id = 0;
            sa_len = sizeof(sa->sa6);
            break;
        }
    }

    return sa_len;
}

int yatest_socket_protocol_from_type(int socket_type)
{
#if __unix__
    (void)socket_type;
    return 0;
#else
    return (((sock_type__) == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP)
#endif
}

char *yatest_sockaddr_to_string(const struct sockaddr *sa)
{
    char       *text;
    void       *ip;
    int         port;
    const char *fmt;
    char        buffer[64];
    switch(sa->sa_family)
    {
        case AF_INET:
        {
            ip = (void *)&((struct sockaddr_in *)sa)->sin_addr;
            port = ntohs(((struct sockaddr_in *)sa)->sin_port);
            fmt = "%s:%i";
            break;
        }
        case AF_INET6:
        {
            ip = (void *)&((struct sockaddr_in6 *)sa)->sin6_addr;
            port = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
            fmt = "[%s]:%i";
            break;
        }
        default:
        {
            yatest_err("yatest_sockaddr_to_string: wrong sockaddr with family %i", sa->sa_family);
            exit(1);
        }
    }
    inet_ntop(sa->sa_family, ip, buffer, sizeof(buffer));
    asprintf(&text, fmt, buffer, port);
    return text;
}

int yatest_socket_create(const char *server, int port, int socket_type)
{
    yatest_socketaddress_t sa;
    socklen_t              sa_len;

    sa_len = yatest_socketaddress_init(&sa, server, port);
    int sockfd = socket(sa.sa.sa_family, socket_type, yatest_socket_protocol_from_type(socket_type));
    if(sockfd < 0)
    {
        yatest_err("yatest_socket_create(%s, %i, %i): socket: failed with %s", strerror(errno));
        exit(1);
    }
    if(socket_type == SOCK_STREAM)
    {
        int tries = 3;
        for(;;)
        {
            if(connect(sockfd, &sa.sa, sa_len) >= 0)
            {
                break;
            }
            if(errno == EINTR)
            {
                continue;
            }
            if(tries <= 0)
            {
                yatest_err("yatest_socket_create(%s, %i, %i): connect: failed with %s", strerror(errno));
                exit(1);
            }
            else
            {
                yatest_log("yatest_socket_create(%s, %i, %i): connect: failed with %s", strerror(errno));
            }
            --tries;
        }
    }
    return sockfd;
}

int yatest_serversocket_create(const char *listento, int port, int server_type)
{
    if((server_type != SOCK_STREAM) && (server_type != SOCK_DGRAM))
    {
        yatest_log("yatest_serversocket_create(%s, %i) invalid socket type %i", listento, port, server_type);
        exit(1);
    }

    int                    ret;
    int                    on = 1;
    int                    server_socket;
    socklen_t              sa_len;

    yatest_socketaddress_t sa;
    memset(&sa, 0, sizeof(yatest_socketaddress_t));

    sa_len = yatest_socketaddress_init(&sa, listento, port);

    yatest_log("yatest_serversocket_create(%s, %i) socket", listento, port);

    server_socket = socket(sa.ss.ss_family, server_type, 0);
    if(server_socket < 0)
    {
        yatest_err("yatest_serversocket_create(%s, %i) socket failed with %s", listento, port, strerror(errno));
        exit(1);
    }

    yatest_log("yatest_serversocket_create(%s, %i) SO_REUSEADDR", listento, port);

#ifdef SO_REUSEADDR
    ret = setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));
    if(ret < 0)
    {
        yatest_log("yatest_serversocket_create(%s, %i) setsockopt SO_REUSEADDR failed with %s", listento, port, strerror(errno));
    }
#endif

    yatest_log("yatest_serversocket_create(%s, %i) SO_REUSEPORT", listento, port);

#ifdef SO_REUSEPORT
    ret = setsockopt(server_socket, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on));
    if(ret < 0)
    {
        yatest_log("yatest_serversocket_create(%s, %i) setsockopt SO_REUSEPORT failed with %s", listento, port, strerror(errno));
    }
#endif

    yatest_log("yatest_serversocket_create(%s, %i) bind", listento, port);

    ret = bind(server_socket, &sa.sa, sa_len);
    if(ret < 0)
    {
        yatest_err("yatest_serversocket_create(%s, %i) bind failed with %s", listento, port, strerror(errno));
        exit(1);
    }

    if(server_type == SOCK_STREAM)
    {
        yatest_log("yatest_serversocket_create(%s, %i) listen", listento, port);

        ret = listen(server_socket, 10);
        if(ret < 0)
        {
            yatest_err("yatest_serversocket_create(%s, %i) listen failed with %s", listento, port, strerror(errno));
            exit(1);
        }
    }

    yatest_log("yatest_serversocket_create(%s, %i) socket %i is ready", listento, port, server_socket);

    return server_socket;
}

int yatest_serversocket_create_tcp(const char *listento, int port) { return yatest_serversocket_create(listento, port, SOCK_STREAM); }

int yatest_serversocket_create_udp(const char *listento, int port) { return yatest_serversocket_create(listento, port, SOCK_DGRAM); }

int yatest_serversocket_accept(int server_socket, yatest_serverclient_t *client)
{
    if(client == NULL)
    {
        yatest_err("yatest_serversocket_accept: invalid parameters");
        exit(1);
    }
    yatest_log("yatest_serversocket_accept(%i) accept", server_socket);
    client->sa_len = sizeof(struct sockaddr_storage);
    int ret = accept_ex2(server_socket, &client->sa.sa, &client->sa_len, 10000); // 10s timeout
    if(ret >= 0)
    {
        client->sockfd = ret;
    }
    else
    {
        yatest_err("yatest_serversocket_accept(%i) accept failed with %s", server_socket, strerror(errno));
    }
    return ret;
}

int yatest_serversocket_recvfrom(int server_socket, yatest_serverclient_t *client, uint8_t *buffer, size_t buffer_size)
{
    if(client == NULL)
    {
        yatest_err("yatest_serversocket_recvfrom: invalid parameters");
        exit(1);
    }
    yatest_log("yatest_serversocket_recvfrom(%i) recvfrom", server_socket);
    client->sa_len = sizeof(struct sockaddr_storage);
    int ret = recvfrom(server_socket, buffer, buffer_size, 0, &client->sa.sa, &client->sa_len);
    if(ret >= 0)
    {
        client->sockfd = server_socket;
    }
    else
    {
        yatest_err("yatest_serversocket_recvfrom(%i) recvfrom failed with %s", server_socket, strerror(errno));
    }
    return ret;
}

struct yatest_socketserver_worker_thread_args_s
{
    yatest_socketserver_t *ssctx;
    yatest_serverclient_t *client;
};

static void *yatest_socketserver_worker_thread(void *args_)
{
    struct yatest_socketserver_worker_thread_args_s *args = (struct yatest_socketserver_worker_thread_args_s *)args_;
    yatest_socketserver_t                           *ssctx = args->ssctx;
    yatest_serverclient_t                           *client = args->client;
    free(args);
    yatest_log("yatest_socketserver_worker(%s, %i) handling (thread)", ssctx->server_ip_text, ssctx->server_ip_port);
    ssctx->handler(ssctx, client);
    yatest_log("yatest_socketserver_worker(%s, %i) handling done (thread)", ssctx->server_ip_text, ssctx->server_ip_port);
    return NULL;
}

static void yatest_socketserver_mode_switch(yatest_socketserver_t *ssctx, yatest_serverclient_t *client)
{
    switch(ssctx->handler_mode)
    {
        case YATEST_SERVERSOCKET_HANDLER_MODE_ONEBYONE:
        {
            yatest_log("yatest_socketserver_worker(%s, %i) handling (one)", ssctx->server_ip_text, ssctx->server_ip_port);
            ssctx->handler(ssctx, client);
            yatest_log("yatest_serversocket_accept(%s, %i) handling (one) done", ssctx->server_ip_text, ssctx->server_ip_port);
            break;
        }
        case YATEST_SERVERSOCKET_HANDLER_MODE_THREADPOOL: // current implementation only launches one thread and waits
                                                          // for it (TODO: improve)
        {
            struct yatest_socketserver_worker_thread_args_s *args = (struct yatest_socketserver_worker_thread_args_s *)malloc(sizeof(struct yatest_socketserver_worker_thread_args_s));
            args->ssctx = ssctx;
            args->client = client;
            pthread_t t;
            yatest_log("yatest_socketserver_worker(%s, %i) creating thread", ssctx->server_ip_text, ssctx->server_ip_port);
            if(pthread_create(&t, NULL, yatest_socketserver_worker_thread, ssctx) != 0)
            {
                yatest_log("yatest_socketserver_worker(%s, %i) handling failed (thread)", ssctx->server_ip_text, ssctx->server_ip_port);
                free(client);
                free(args);
            }
            yatest_log("yatest_socketserver_worker(%s, %i) joining thread", ssctx->server_ip_text, ssctx->server_ip_port);
            pthread_join(t, NULL);
            break;
        }
        case YATEST_SERVERSOCKET_HANDLER_MODE_FORK:
        {
            yatest_log("yatest_socketserver_worker(%s, %i) forking", ssctx->server_ip_text, ssctx->server_ip_port);
            pid_t handler_pid = fork();
            if(handler_pid == 0)
            {
                yatest_log("yatest_socketserver_worker(%s, %i) handling (fork)", ssctx->server_ip_text, ssctx->server_ip_port);
                ssctx->handler(ssctx, client);
                yatest_log("yatest_serversocket_accept(%s, %i) handling (fork) done", ssctx->server_ip_text, ssctx->server_ip_port);
                exit(0);
            }
            else
            {
                if(handler_pid > 0)
                {
                    yatest_log("yatest_socketserver_worker(%s, %i) forked to %i", ssctx->server_ip_text, ssctx->server_ip_port, handler_pid);
                    for(;;)
                    {
                        if(waitpid(handler_pid, NULL, 0) >= 0)
                        {
                            break;
                        }
                        int err = errno;
                        if(err != EINTR)
                        {
                            yatest_log("yatest_socketserver_worker(%s, %i) failed to wait child: %s", ssctx->server_ip_text, ssctx->server_ip_port, strerror(err));
                            break;
                        }
                    }
                }
                else
                {
                    yatest_log("yatest_socketserver_worker(%s, %i) fork failed with %s", ssctx->server_ip_text, ssctx->server_ip_port, strerror(errno));
                }
            }

            break;
        }
        default:
        {
            yatest_log("yatest_socketserver_worker(%s, %i) bad mode (bug in the test)", ssctx->server_ip_text, ssctx->server_ip_port);
            exit(1);
        }
    }
}

static void *yatest_socketserver_worker(void *ssctx_)
{
    yatest_socketserver_t *ssctx = (yatest_socketserver_t *)ssctx_;

    yatest_log("server: creating socket");
    ssctx->server_socket = yatest_serversocket_create(ssctx->server_ip_text, ssctx->server_ip_port, ssctx->socket_type);

    yatest_log("server: initialising");
    ssctx->init(ssctx);

    while(!ssctx->control->stop)
    {
        int                    ret;
        yatest_serverclient_t *client = (yatest_serverclient_t *)malloc(sizeof(yatest_serverclient_t));

        if(ssctx->socket_type == SOCK_STREAM)
        {
            yatest_log("server: accept");
            ret = yatest_serversocket_accept(ssctx->server_socket, client);
            yatest_log("server: accept returned %i", ret);
            if(ret >= 0)
            {
                // handle that client
                yatest_socketserver_mode_switch(ssctx, client);
            }
        }
        else // SOCK_DGRAM
        {
            // handle that client
            yatest_socketserver_mode_switch(ssctx, client);
        }
    }

    yatest_log("server: finalising");

    ssctx->finalise(ssctx);
    return NULL;
}

void yatest_socketserver_stop(yatest_socketserver_t *ssctx)
{
    if(!ssctx->initialised)
    {
        return;
    }
    ssctx->initialised = false;

    ssctx->control->stop = true;
    if(ssctx->child_pid > 0)
    {
        yatest_log("server: stopping with a SIGHUP");
        kill(ssctx->child_pid, SIGHUP);
        int child_status = -1;
        for(int countdown = 10; countdown > 0; --countdown)
        {
            pid_t pid = waitpid(ssctx->child_pid, &child_status, WNOHANG);
            if(pid != 0)
            {
                yatest_log("server: gracefully stopped");
                return;
            }
            usleep(500);
        }
        yatest_log("server: killing with a SIGKILL");
        kill(ssctx->child_pid, SIGKILL);
    }
    else if(ssctx->server_thread != 0)
    {
        yatest_log("server: sending SIGHUP to thread");
        pthread_kill(ssctx->server_thread, SIGHUP);
        for(int countdown = 10; countdown > 0; --countdown)
        {
            if(pthread_kill(ssctx->server_thread, 0) != 0)
            {
                // the thread doesn't exist anymore
                yatest_log("server: thread has gracefully stopped");
                return;
            }
            usleep(500);
        }
        yatest_log("server: killing thread with a SIGKILL");
        kill(ssctx->child_pid, SIGKILL);
    }
}

static struct yatest_socketserver_s *yatest_socketserver_stack = NULL;

static void                          yatest_socketserver_killall()
{
    struct yatest_socketserver_s *stack = yatest_socketserver_stack;
    while(stack != NULL)
    {
        struct yatest_socketserver_s *next = stack->next;
        if(stack->initialised)
        {
            yatest_log("YATEST: atexit: stopping remaining socketserver@%p", stack);
        }
        yatest_socketserver_stop(stack);
        stack = next;
    }
}

void yatest_socketserver_start(yatest_socketserver_t *ssctx, const char *ip_text, int port, int socket_type, yatest_serversocket_client_init_t *init, yatest_serversocket_client_handler_t *handler,
                               yatest_serversocket_client_finalise_t *finalise, size_t shared_memory_size, enum yatest_serversocket_handler_mode_e handler_mode)
{
    int  ret;
    bool process_shared_supported = false;

    if(yatest_socketserver_stack == NULL)
    {
        atexit(yatest_socketserver_killall);
    }

    yatest_log("server: setting up");
    ssctx->server_sa_len = yatest_socketaddress_init(&ssctx->server_sa, ip_text, port);

    const size_t yatest_socketserver_mtx_size = (sizeof(yatest_socketserver_control_t) + 31) & ~31;
    shared_memory_size += yatest_socketserver_mtx_size;

    void *ptr = mmap(NULL, yatest_socketserver_mtx_size + shared_memory_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if(ptr == MAP_FAILED)
    {
        yatest_err("mmap failed");
        exit(1);
    }
    ssctx->shared_memory = ((uint8_t *)ptr) + yatest_socketserver_mtx_size;
    ssctx->shared_memory_size = shared_memory_size;
    ssctx->control = (yatest_socketserver_control_t *)ptr;
    ssctx->control->serial = 0;
    ssctx->control->state = 0;
    ssctx->control->stop = false;

#if !YATEST_SOCKETSERVER_START_NO_FORK
    pthread_mutexattr_t mtx_attr;
    pthread_mutexattr_init(&mtx_attr);
    ret = pthread_mutexattr_setpshared(&mtx_attr, PTHREAD_PROCESS_SHARED);
    if(ret == 0)
    {
        process_shared_supported = true;
    }
    else
    {
        process_shared_supported = false;
    }

    if(process_shared_supported)
    {
        pthread_condattr_t cond_attr;
        pthread_condattr_init(&cond_attr);
        ret = pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED);
        if(ret == 0)
        {
            process_shared_supported = true;
        }
        else
        {
            process_shared_supported = false;
        }
        if(process_shared_supported)
        {
            pthread_mutex_init(&ssctx->control->mtx, &mtx_attr);
            pthread_cond_init(&ssctx->control->cond, &cond_attr);
        }
        pthread_condattr_destroy(&cond_attr);
    }
    pthread_mutexattr_destroy(&mtx_attr);
    if(process_shared_supported)
    {
        yatest_log("server: process shared supported");
    }
    else
#endif
    {
        yatest_log("server: process shared not supported");
        pthread_mutex_init(&ssctx->control->mtx, NULL);
        pthread_cond_init(&ssctx->control->cond, NULL);
        if(handler_mode == YATEST_SERVERSOCKET_HANDLER_MODE_FORK)
        {
            handler_mode = YATEST_SERVERSOCKET_HANDLER_MODE_THREADPOOL;
        }
    }

    ssctx->server_ip_text = strdup(ip_text);
    ssctx->server_ip_port = port;
    ssctx->socket_type = socket_type;
    ssctx->init = init;
    ssctx->handler = handler;
    ssctx->finalise = finalise;

    ssctx->handler_mode = handler_mode;

    ssctx->server_thread = 0;
    ssctx->server_socket = -1;
    ssctx->child_pid = 0;

    if(process_shared_supported)
    {
        yatest_log("server: forking");

        pid_t child = fork();
        if(child != 0)
        {
            if(child < 0)
            {
                yatest_err("fork failed with %s", strerror(errno));
                exit(1);
            }
            ssctx->child_pid = child;
        }
        else
        {
            yatest_log("server: calling worker");
            yatest_socketserver_worker(ssctx);
            exit(0);
        }
    }
    else
    {
        yatest_log("server: threading worker");
        pthread_create(&ssctx->server_thread, NULL, yatest_socketserver_worker, ssctx);
    }
    ssctx->next = yatest_socketserver_stack;
    ssctx->initialised = true;
    yatest_socketserver_stack = ssctx;
}
