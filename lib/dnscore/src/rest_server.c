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
 *----------------------------------------------------------------------------*/

#include "dnscore/host_address.h"
#include "dnscore/pid.h"
#include "dnscore/fdtools.h"
#include "dnscore/logger.h"
#include "dnscore/thread_pool.h"
#include "dnscore/tcp_io_stream.h"
#include "dnscore/zalloc.h"
#include "dnscore/string_set.h"
#include "dnscore/buffer_output_stream.h"
#include "dnscore/ptr_treemap.h"
#include "dnscore/bytearray_output_stream.h"
#include "dnscore/process.h"
#include "dnscore/rest_server.h"
#include "dnscore/uri.h"
#include "dnscore/tools.h"
#include "dnscore/signals.h"

extern logger_handle_t *g_rest_logger;
#define MODULE_MSG_HANDLE                    g_rest_logger

#define SERVER_RECV_TO_US                    900000 // MUST BE < 1000000
#define SERVER_SEND_TO_US                    900000 // MUST BE < 1000000

#define REST_SERVER_PAGE_REGISTER_TOKENS_MAX 128

struct rest_server_service_data_s
{
    const host_address_t *address;
    struct addrinfo      *addr;
    int                   sockfd;
};

typedef struct rest_server_service_data_s rest_server_service_data_t;

struct rest_server_path_component_s
{
    ptr_treemap_t       path_components; // if variable_name is set, path_component only contains one key
    rest_server_page_t *page;
};

typedef struct rest_server_path_component_s rest_server_path_component_t;

static struct thread_pool_s                *rest_server_answer_thread_pool = NULL;
static struct service_s                     rest_server_service = UNINITIALIZED_SERVICE;
static rest_server_service_data_t          *rest_server_service_data = NULL;
static int                                  rest_server_service_data_count = -1;
static bool                                 rest_server_shutdown = false;
// static ptr_treemap_t rest_server_pages = PTR_TREEMAP_ASCIIZCASE_EMPTY;
static rest_server_path_component_t rest_server_pages_root = {PTR_TREEMAP_ASCIIZCASE_EMPTY, NULL};
static mutex_t                      rest_server_pages_mtx = MUTEX_INITIALIZER;

static void                         rest_server_signal_handler(int signo, siginfo_t *info, void *context)
{
    (void)info;
    (void)context;

    switch(signo)
    {
        case SIGINT:
        case SIGTERM:
        {
            rest_server_shutdown = true;
            break;
        }
    }
}

static int rest_server_new_socket(struct addrinfo *addr)
{
    ya_result ret;
    int       sockfd;
    int       family = SOCK_STREAM;
    const int on = 1;

    if(FAIL(sockfd = socket(addr->ai_family, family, 0)))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to create socket %{sockaddr}: %r", addr->ai_addr, ret);

        return ret;
    }

    /**
     * Associate the name of the interface to the socket
     */

    /**
     * This is distribution/system dependent. With this we ensure that IPv6 will only listen on IPv6 addresses.
     */

    if(addr->ai_family == AF_INET6)
    {
        if(FAIL(setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on))))
        {
            ret = ERRNO_ERROR;
            ttylog_err("failed to force IPv6 on %{sockaddr}: %r", addr->ai_addr, ret);
            close_ex(sockfd);
            return ret;
        }
    }

    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on))))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to reuse address %{sockaddr}: %r", addr->ai_addr, ret);
        close_ex(sockfd);
        return ret;
    }

    if(FAIL(setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on))))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to use reuse feature: %r", ret);
        close_ex(sockfd);
        return ret;
    }

    if(FAIL(bind(sockfd, (struct sockaddr *)addr->ai_addr, addr->ai_addrlen)))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to bind address %{sockaddr}: %r", addr->ai_addr, ret);
        close_ex(sockfd);
        return ret;
    }

    if(FAIL(listen(sockfd, 64)))
    {
        ret = ERRNO_ERROR;
        ttylog_err("failed to listen to address %{sockaddr}: %r", addr->ai_addr, ret);
        close_ex(sockfd);
        return ret;
    }

    return sockfd;
}

static ya_result rest_server_network_setup(rest_server_network_setup_args_t *args)
{
    ya_result                   ret;
    rest_server_service_data_t *service_data;

#if DNSCORE_REST_HAS_HTTPS
    if(args->https)
    {
        if(!file_exists(args->ca))
        {
            log_err("server: SSL enabled but certificate root CA '%s' does not exist", args->ca);
            return ERROR;
        }

        if(!file_exists(args->cert))
        {
            log_err("server: SSL enabled but certificate '%s' does not exist", args->cert);
            return ERROR;
        }

        if(!file_exists(args->key))
        {
            log_err("server: SSL enabled but key '%s' does not exist", args->key);
            return ERROR;
        }

        log_info("server: HTTPS enabled with certificate '%s' and key '%s'", args->cert, args->key);
    }
#endif

    int count = (int)host_address_count(args->listen);
    MALLOC_OR_DIE(rest_server_service_data_t *, service_data, sizeof(rest_server_service_data_t) * count, GENERIC_TAG);

    int i = 0;
    for(host_address_t *ha = args->listen; ha != NULL; ha = ha->next)
    {
        if(FAIL(ret = host_address2addrinfo(ha, &service_data[i].addr)))
        {
            free(service_data);
            return ret;
        }

        service_data[i].address = ha;

        ++i;
    }

    for(i = 0; i < count; ++i)
    {
        log_info("server: binding %{hostaddr}", service_data[i].address);

        if(FAIL(ret = rest_server_new_socket(service_data[i].addr)))
        {
            log_err("server: could not bind %{hostaddr}: %r", service_data[i].address, ret);

            for(int j = 0; j < i; ++j)
            {
                close_ex(service_data[j].sockfd);
            }

            free(service_data);
            return ret;
        }

        service_data[i].sockfd = ret;
    }

    // service_data has the socket opened

    rest_server_service_data = service_data;
    rest_server_service_data_count = count;

    return SUCCESS;
}

int rest_server_setup(rest_server_network_setup_args_t *args)
{
    ya_result ret;

    if((args == NULL) || (args->listen == NULL))
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    args->pid = 0;

    for(host_address_t *ha = args->listen; ha != NULL; ha = ha->next)
    {
        if(ha->port == 0)
        {
            ha->port = htons(args->default_port);
        }
    }

    if(args->pid_file != NULL)
    {
        for(int countdown = 5; countdown >= 0; --countdown)
        {
            ret = pid_file_create(args->pid_file, &args->pid, getuid(), getgid());

            if(ISOK(ret))
            {
                break;
            }

            if(countdown > 0)
            {
                ttylog_out("could not lock pid '%s': %r (retrying)", args->pid_file, ret);

                if(file_exists(args->pid_file))
                {
                    pid_t runpid = 0;
                    ret = pid_file_read(args->pid_file, &runpid);
                    if(ISOK(ret))
                    {
                        pid_t mypid = getpid_ex();
                        ttylog_out("... pid in %s is %i, my pid is %i", args->pid_file, runpid, mypid);
                        if(runpid != mypid)
                        {
                            int kill_ret = kill(runpid, 0);
                            if(kill_ret != 0)
                            {
                                ttylog_out("... kill(%i, 0) failed with %i (%s)", runpid, errno, strerror(errno));
                            }
                        }
                    }
                }
                else
                {
                    ttylog_out("... file %s doesn't exist", args->pid_file);
                }

                usleep_ex(ONE_SECOND_US);
            }
            else
            {
                ttylog_err("could not lock pid '%s': %r", args->pid_file, ret);
                return ret;
            }
        }

        if(FAIL(ret = pid_check_running_program(args->pid_file, &args->pid)))
        {
            ttylog_err("program is already running: %r", ret);
            return ret;
        }
    }

    if(args->pid_file != NULL)
    {
        ret = pid_file_create(args->pid_file, &args->pid, args->uid, args->gid);

        if(FAIL(ret))
        {
            if(file_exists(args->pid_file))
            {
                ttylog_err("could not create pid file '%s': file already exists", args->pid_file);
            }
            else
            {
                ttylog_err("could not create pid file '%s': please check path and/or access rights", args->pid_file);
            }

            return ret;
        }
    }

    if(FAIL(ret = rest_server_network_setup(args)))
    {
        ttylog_err("could not setup the network: %r", ret);
        return ret;
    }

    if(args->setup_signals)
    {
        static const uint8_t handled_signals[] = {SIGHUP,  /* Hangup (POSIX).  */
                                                  SIGINT,  /* Interrupt (ANSI).  */
                                                  SIGQUIT, /* Quit (POSIX).  */
                                                  SIGIOT,  /* IOT trap (4.2 BSD).  */
                                                  SIGUSR1, /* User-defined signal 1 (POSIX).  */
#if SIGNAL_HOOK_COREDUMP
                                                  SIGABRT, /* Abort (ANSI).  */
                                                  SIGILL,
                                                  /* Illegal instruction (ANSI).  */ /* ERROR/EXIT */
                                                  SIGBUS,                            /* BUS error (4.2 BSD).  */
                                                  SIGFPE,
                                                  /* Floating-point exception (ANSI).  */ /* ERROR/EXIT */
                                                  SIGSEGV,
        /* Segmentation violation (ANSI).  */ /* ERROR/EXIT */
#endif
                                                  SIGUSR2,           /* User-defined signal 2 (POSIX).  */
                                                  SIGALRM,           /* Alarm clock (POSIX).  */
                                                  SIGTERM,           /* Termination (ANSI).  */
                                                  /*	SIGSTKFLT,*/ /* Stack fault.  */
                                                  SIGCHLD,           /* Child status has changed (POSIX).  */
                                                  SIGCONT,           /* Continue (POSIX).  */
                                                  SIGTSTP,           /* Keyboard stop (POSIX).  */
                                                  SIGTTIN,           /* Background read from tty (POSIX).  */
                                                  SIGTTOU,           /* Background write to tty (POSIX).  */
                                                  SIGURG,            /* Urgent condition on socket (4.2 BSD).  */
                                                  SIGXCPU,           /* CPU limit exceeded (4.2 BSD).  */
                                                  SIGXFSZ,           /* File size limit exceeded (4.2 BSD).  */
                                                  0};

        static const uint8_t ignored_signals[] = {SIGPIPE, /* Broken pipe (POSIX).  */
                                                  0};

        struct sigaction     action;
        int                  signal_idx;

        ZEROMEMORY(&action, sizeof(action));

        action.sa_sigaction = rest_server_signal_handler;

        for(signal_idx = 0; handled_signals[signal_idx] != 0; signal_idx++)
        {
#ifdef SA_NOCLDWAIT
            action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_NOCLDWAIT;
#else /// @note 20151119 edf -- quick fix for Debian Hurd i386, and any other system missing SA_NOCLDWAIT
            action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP;
#endif

            switch(signal_idx)
            {
                case SIGBUS:
                case SIGFPE:
                case SIGILL:
                case SIGSEGV:
                {
                    sigemptyset(&action.sa_mask); /* can interrupt the interrupt */

                    break;
                }
                default:
                {
                    sigfillset(&action.sa_mask); /* don't interrupt the interrupt */
                    break;
                }
            }
            sigaction(handled_signals[signal_idx], &action, NULL);
        }

        action.sa_handler = SIG_IGN;

        for(signal_idx = 0; ignored_signals[signal_idx] != 0; signal_idx++)
        {
            sigaction(ignored_signals[signal_idx], &action, NULL);
        }
    }

    return ret;
}

void rest_server_context_init(rest_server_context_t *ctx)
{
    memset(ctx, 0, sizeof(rest_server_context_t));
    ctx->page_args.compare = ptr_treemap_asciizcasep_node_compare;
    ctx->path_args.compare = ptr_treemap_asciizcasep_node_compare;
}

static ya_result rest_server_client_uri_callback(void *args, const char *name, const char *value)
{
    rest_server_context_t *ctx = (rest_server_context_t *)args;
    if(value == NULL)
    {
        if(name != NULL)
        {
            ctx->page_name = strdup(name);
            return SUCCESS;
        }
        else
        {
            return UNEXPECTED_NULL_ARGUMENT_ERROR;
        }
    }
    // value != NULL
    if(name == NULL)
    {
        return UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    ptr_treemap_node_t *node = ptr_treemap_insert(&ctx->page_args, (char *)name);
    if(node->value == NULL)
    {
        node->key = strdup(name);
        node->value = strdup(value);
    }
    return SUCCESS;
}

void rest_server_context_node_destroy(ptr_treemap_node_t *node)
{
    free(node->key);
    free(node->value);
    node->key = NULL;
    node->value = NULL;
}

#if DNSCORE_REST_HAS_HTTPS
static int rest_server_service_SSL_error_cb(const char *str, size_t len, void *u)
{
    (void)len;
    (void)u;
    log_err("%s", str);
    return 1;
}
#endif

static void rest_server_context_finalise(rest_server_context_t *ctx)
{
#if DNSCORE_REST_HAS_HTTPS
    ya_result ret;

    if(g_euipo_server_settings.https)
    {
        do
        {
            ret = SSL_shutdown(ctx->sslsock);
            if(ret < 0)
            {
                ERR_print_errors_cb(rest_server_service_SSL_error_cb, NULL);

                int ssl_err = SSL_get_error(ctx->sslsock, ret);
                log_err("query from %{sockaddr}: unable to accept connection: %i: ssl:%i", &ctx->client->sa.sa, ret, ssl_err);
            }
        } while(ret == 0);

        SSL_free(ctx->sslsock);
        close_ex(ctx->client->sockfd);
        SSL_CTX_free(ctx->sslctx);
    }
    else
    {
#endif

        output_stream_flush(&ctx->os);
        fd_output_stream_detach(&ctx->fos);
        output_stream_close(&ctx->os);
        shutdown(ctx->client->sockfd, SHUT_WR);
        input_stream_close(&ctx->is);
#if DNSCORE_REST_HAS_HTTPS
    }
#endif

    free(ctx->page_name);
    ptr_treemap_callback_and_finalise(&ctx->page_args, rest_server_context_node_destroy);
    ptr_treemap_callback_and_finalise(&ctx->path_args, rest_server_context_node_destroy);
}

#if DNSCORE_REST_HAS_HTTPS
static void rest_server_service_error(int sockfd, int error_code, const char *error_text)
{
    output_stream fos;
    output_stream os;
    fd_output_stream_attach(&fos, sockfd);
    buffer_output_stream_init(&os, &fos, 4096);
    osformat(&os,
             "HTTP/1.1 %d %s\r\n"
             "\r\n",
             error_code,
             error_text);
    output_stream_flush(&os);
    fd_output_stream_detach(&fos);
    output_stream_close(&os);
}
#endif

static void rest_server_service_answer(void *parm)
{
    rest_server_service_client_t *client = (rest_server_service_client_t *)parm;

    const size_t                  line_size = 65536;
    char                         *line = (char *)malloc(line_size);
    if(line == NULL)
    {
        log_err("can't allocate memory for the URI");
        rest_server_service_client_free(client);
        return;
    }

    rest_server_context_t ctx;
    rest_server_context_init(&ctx);

    ctx.client = client;
    ctx.answer_start = timeus();

    log_debug("query from %{sockaddr} received (fd = %i)", &client->sa.sa, client->sockfd);

    // in the meantime ...

    if(client->sockfd < 0)
    {
        log_err("client socket < 0: %i", client->sockfd);
        free(line);
        rest_server_service_client_free(client);
        return;
    }

    ya_result ret;

    tcp_set_recvtimeout(client->sockfd, 3, SERVER_RECV_TO_US);
    tcp_set_sendtimeout(client->sockfd, 3, SERVER_SEND_TO_US);

#if DNSCORE_REST_HAS_HTTPS
    SSL_CTX *sslctx = NULL;
    SSL     *sslsock = NULL;

    if(g_euipo_server_settings.https)
    {
        sslctx = SSL_CTX_new(SSLv23_server_method());

        ret = SSL_CTX_load_verify_locations(sslctx, g_euipo_server_settings.ca, NULL);

        if(ret != 1)
        {
            log_err("query from %{sockaddr}: cannot set CA location to '%s'", &client->sa.sa, g_euipo_server_settings.ca);

            ERR_print_errors_cb(rest_server_service_SSL_error_cb, NULL);

            rest_server_service_error(client->sockfd, 500, "Internal server error (CA)");
            close_ex(client->sockfd);
            SSL_CTX_free(sslctx);
            return NULL;
        }

        SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        SSL_CTX_set_verify_depth(sslctx, 1);

        ret = SSL_CTX_use_certificate_chain_file(sslctx, g_euipo_server_settings.cert);

        if(ret != 1)
        {
            log_err("query from %{sockaddr}: unable to use certificate '%s'", &client->sa.sa, g_euipo_server_settings.cert);
            ERR_print_errors_cb(rest_server_service_SSL_error_cb, NULL);

            rest_server_service_error(client->sockfd, 500, "Internal server error (cert)");
            close_ex(client->sockfd);
            SSL_CTX_free(sslctx);
            return NULL;
        }

        ret = SSL_CTX_use_PrivateKey_file(sslctx, g_euipo_server_settings.key, SSL_FILETYPE_PEM);

        if(ret != 1)
        {
            log_err("query from %{sockaddr}: unable to use private key '%s'", &client->sa.sa, g_euipo_server_settings.key);
            ERR_print_errors_cb(rest_server_service_SSL_error_cb, NULL);

            rest_server_service_error(client->sockfd, 500, "Internal server error (key)");
            close_ex(client->sockfd);
            SSL_CTX_free(sslctx);
            return NULL;
        }

        ret = SSL_CTX_check_private_key(sslctx);

        if(ret != 1)
        {
            log_err("query from %{sockaddr}: mismatched certificate '%s' and private key '%s'", &client->sa.sa, g_euipo_server_settings.cert, g_euipo_server_settings.key);
            rest_server_service_error(client->sockfd, 500, "Internal server error (cert/key)");

            SSL_free(sslsock);
            close_ex(client->sockfd);
            SSL_CTX_free(sslctx);
            return NULL;
        }

        sslsock = SSL_new(sslctx);
        ret = SSL_set_fd(sslsock, client->sockfd);

        if(ret != 1)
        {
            ERR_print_errors_cb(rest_server_service_SSL_error_cb, NULL);

            int ssl_err = SSL_get_error(sslsock, ret);

            log_err("query from %{sockaddr}: unable to accept connection: %i: ssl:%i", &client->sa.sa, ret, ssl_err);
            rest_server_service_error(client->sockfd, 500, "Internal server error (accept)");

            SSL_free(sslsock);
            close_ex(client->sockfd);
            SSL_CTX_free(sslctx);
            return NULL;
        }

        for(;;)
        {
            ret = SSL_accept(sslsock);

            if(ret == 1)
            {
                break;
            }

            int ssl_err = SSL_get_error(sslsock, ret);

            if((ssl_err != SSL_ERROR_WANT_READ) && (ssl_err != SSL_ERROR_WANT_WRITE))
            {
                if(ssl_err == SSL_ERROR_SYSCALL)
                {
                    ret = ERRNO_ERROR;
                    log_err("query from %{sockaddr}: unable to accept connection: %r", &client->sa.sa, ret);
                }
                else
                {
                    log_err("query from %{sockaddr}: unable to accept connection: SSL_get_error returned ssl:%i", &client->sa.sa, ssl_err);
                }

                ERR_print_errors_cb(rest_server_service_SSL_error_cb, NULL);

                rest_server_service_error(client->sockfd, 500, "Internal server error (accept)");

                do
                {
                    ret = SSL_shutdown(sslsock);
                    if(ret < 0)
                    {
                        ERR_print_errors_cb(rest_server_service_SSL_error_cb, NULL);

                        int ssl_err = SSL_get_error(sslsock, ret);
                        log_err("query from %{sockaddr}: unable to accept connection: %i: ssl:%i", &client->sa.sa, ret, ssl_err);
                    }
                } while(ret == 0);

                SSL_free(sslsock);
                close_ex(client->sockfd);
                SSL_CTX_free(sslctx);
                return NULL;
            }
        }

        X509 *peer = SSL_get_peer_certificate(sslsock);

        if(peer != NULL)
        {
            X509_NAME *peer_subject_name = X509_get_subject_name(peer);
            char       peer_name_buffer[512];
            peer_name_buffer[0] = '?';
            peer_name_buffer[1] = '\0';
            char *peer_name = X509_NAME_oneline(peer_subject_name, peer_name_buffer, sizeof(peer_name_buffer));

            ret = SSL_get_verify_result(sslsock);
            if(ret == X509_V_OK /*|| ret == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN*/)
            {
                // The client sent a certificate which verified OK
                log_debug("query from %{sockaddr} using certificate '%s'", &client->sa.sa, peer_name);
            }
            else // X509_V_ERR_CERT_SIGNATURE_FAILURE
            {
                const char *err_str = X509_verify_cert_error_string(ret);
                log_err("query from %{sockaddr} using certificate '%s': ssl:%s", &client->sa.sa, peer_name, err_str);

                ERR_print_errors_cb(rest_server_service_SSL_error_cb, NULL);

                rest_server_service_error(client->sockfd, 401, err_str);

                do
                {
                    ret = SSL_shutdown(sslsock);
                    if(ret < 0)
                    {
                        ERR_print_errors_cb(rest_server_service_SSL_error_cb, NULL);

                        int ssl_err = SSL_get_error(sslsock, ret);
                        log_err("query from %{sockaddr}: unable to accept connection: %i: ssl:%i", &client->sa.sa, ret, ssl_err);
                    }
                } while(ret == 0);

                SSL_free(sslsock);
                close_ex(client->sockfd);
                SSL_CTX_free(sslctx);
                return NULL;
            }
        }

        openssl_input_stream_wrap(&ctx.is, sslsock);
    }
    else
    {
#endif
        fd_input_stream_attach(&ctx.is, client->sockfd); // only fails for negative values of the file descriptor
#if DNSCORE_REST_HAS_HTTPS
    }
#endif

    // don't: buffer_input_stream_init(&is, &is, 4096);

    int  timeout_countdown = 5;
    bool has_get_line = false;

    for(;;)
    {
        ret = input_stream_read_line(&ctx.is, line, line_size);

        if(ret < 0)
        {
            // if the error is a timeout, retry a few times before giving up
            if(ret == MAKE_ERRNO_ERROR(ETIMEDOUT))
            {
                if(--timeout_countdown >= 0)
                {
                    continue;
                }
            }
            break;
        }

        timeout_countdown = 5;

        if(ret == (int)line_size)
        {
            // answer with 414
            ret = BUFFER_WOULD_OVERFLOW;
            break;
        }

        --ret;

        while((ret >= 0) && (line[ret] <= ' '))
        {
            line[ret--] = '\0';
        }

        ++ret;

        if(ret == 0)
        {
            break;
        }

        log_info("query from %{sockaddr}: [%s]", &client->sa.sa, line);
        int usable_line_size = MIN(ret, client->query_line_size - 1);
        memcpy(client->query_line, line, usable_line_size);
        client->query_line[usable_line_size] = '\0';

        if(memcmp(line, "GET ", 4) == 0)
        {
            // URL ?
            if(memcmp(&line[ret - 9], " HTTP/1.1", 9) == 0)
            {
                if(FAIL(ret = uri_path_decode(line, &line[ret - 9], rest_server_client_uri_callback, &ctx)))
                {
                    log_warn("query from %{sockaddr}: could not decode URI parameters", &client->sa.sa);
                }
                else
                {
                    has_get_line = true;
                }
            }
            else
            {
                log_warn("query from %{sockaddr}: expected HTTP/1.1", &client->sa.sa);
            }
        }
    }

    // check that a GET line was available

    if(ISOK(ret) && !has_get_line)
    {
        ret = INVALID_PROTOCOL;
    }

    free(line);
    line = NULL;

#if DNSCORE_REST_HAS_HTTPS
    if(g_euipo_server_settings.https)
    {
        openssl_output_stream_wrap(&ctx.os, ctx.sslsock);
    }
    else
    {
#endif
        fd_output_stream_attach(&ctx.fos, ctx.client->sockfd);
        buffer_output_stream_init(&ctx.os, &ctx.fos, 4096);
#if DNSCORE_REST_HAS_HTTPS
    }
#endif

    if(ISOK(ret))
    {
        // lock the page set
        // get the function for the page
        // unlock the page set
        // call the page

        rest_server_page_t *page = NULL;

        if(ctx.page_name != NULL)
        {
            mutex_lock(&rest_server_pages_mtx);

            const char *name = ctx.page_name;

            while(*name == '/')
            {
                ++name;
            }

            char                         *tokens[REST_SERVER_PAGE_REGISTER_TOKENS_MAX];
            size_t                        token_count = text_split_to_array(name, '/', tokens, REST_SERVER_PAGE_REGISTER_TOKENS_MAX);

            rest_server_path_component_t *current = &rest_server_pages_root;
            ptr_treemap_node_t           *token_node;
            for(size_t token_index = 0; token_index < token_count; ++token_index)
            {
                // check if current is a variable
                token_node = ptr_treemap_get_first(&current->path_components);
                char *node_name = token_node->key;
                if(node_name[0] != '$')
                {
                    token_node = ptr_treemap_find(&current->path_components, tokens[token_index]);
                    if(token_node != NULL)
                    {
                        current = token_node->value;
                    }
                    else
                    {
                        break; // path not registered
                    }
                }
                else
                {
                    // tokens[token_index] is a value
                    ptr_treemap_node_t *path_args_node = ptr_treemap_insert(&ctx.path_args, &node_name[1]);
                    if(path_args_node->value == NULL)
                    {
                        path_args_node->key = strdup(&node_name[1]);
                        path_args_node->value = strdup(tokens[token_index]);
                    }
                    current = token_node->value;
                }
            }

            page = current->page;

            for(size_t token_index = 0; token_index < token_count; ++token_index)
            {
                free(tokens[token_index]);
            }

            mutex_unlock(&rest_server_pages_mtx);

            if(page != NULL)
            {
                page(&ctx);
            }
            else
            {
                rest_server_write_http_header_and_print(&ctx, 404, "Page Not Found", "{\"message\": \"Page Not Found\"}");
            }
        }
    }
    else
    {
        if(ret == BUFFER_WOULD_OVERFLOW)
        {
            rest_server_write_http_header_and_print(&ctx, 414, "Request-URI Too Long", "{\"message\": \"Request-URI Too Long\"}");
        }
        else if(ret == INVALID_PROTOCOL)
        {
            rest_server_write_http_header_and_print(&ctx, 404, "Bad Request", "{\"message\": \"Bad Request\"}");
        }
        else
        {
            rest_server_write_http_header_and_print(&ctx, 500, "Internal Server Error", "{\"message\": \"Error code %08x (%s)\"}", ret, error_gettext(ret));
        }
    }

    rest_server_context_finalise(&ctx);
    rest_server_service_client_free(client);
}

static int rest_server_service_main(struct service_worker_s *worker)
{
    int             sockfd = rest_server_service_data[worker->worker_index].sockfd;
    socketaddress_t sa;

    tcp_set_recvtimeout(sockfd, 1, SERVER_RECV_TO_US);
    tcp_set_sendtimeout(sockfd, 1, SERVER_SEND_TO_US);

    log_info("rest server is accepting connections");

    const int                     client_line_size = 65536;

    rest_server_service_client_t *client = rest_server_service_client_new_instance(client_line_size);

    while(service_should_run(worker) && !rest_server_shutdown)
    {
        if(client == NULL)
        {
            log_err("out-of-memory allocating client context: shutting down");
            dnscore_shutdown();
            break;
        }

        client->sa_len = sizeof(sa);
        int client_socket = accept_ex2(sockfd, &client->sa.sa, &client->sa_len, 1000);

        if(client_socket < 0)
        {
            int err = errno;

            if(!(err == EINTR || err == EAGAIN || err == EWOULDBLOCK || err == ETIMEDOUT))
            {
                log_err("rest server: failure to accept a new connection: %r", MAKE_ERRNO_ERROR(err));
            }

            continue;
        }

        // send socket to pool

        client->sockfd = client_socket;

        if(ISOK(thread_pool_try_enqueue_call(rest_server_answer_thread_pool, rest_server_service_answer, client, NULL, "server-answer")))
        {
            client = rest_server_service_client_new_instance(client_line_size);
        }
        else
        {
            log_warn("rest server: worker queue is full, closing new connection");
            close_ex(client_socket);
        }
    }

    rest_server_service_client_free(client);

    log_info("rest server is shutting down");

    return 0;
}

ya_result rest_server_start(rest_server_network_setup_args_t *args)
{
    ya_result ret;

    // start the service

    rest_server_answer_thread_pool = thread_pool_init_ex(args->worker_count, args->queue_size, "distance-accept");

    if(rest_server_answer_thread_pool == NULL)
    {
        log_err("failed to start server pool");
        return ERROR;
    }

    if(ISOK(ret = service_init_ex(&rest_server_service, rest_server_service_main, "rest-server", rest_server_service_data_count)))
    {
        log_info("server starting");

        ret = service_start(&rest_server_service);
    }

    return ret;
}

void rest_server_wait(rest_server_network_setup_args_t *args)
{
    (void)args;
    service_wait(&rest_server_service);

    log_info("server closing sockets");

    for(int i = 0; i < rest_server_service_data_count; ++i)
    {
        close_ex(rest_server_service_data[i].sockfd);
    }

    log_info("server terminated");
}

void rest_server_stop(rest_server_network_setup_args_t *args)
{
    (void)args;
    log_info("rest server: stop requested");
    logger_flush();
    if(rest_server_service_data != NULL)
    {
        log_info("rest server: closing rest accept sockets");
        logger_flush();
        for(int i = 0; i < rest_server_service_data_count; ++i)
        {
            close_ex(rest_server_service_data[i].sockfd);
            rest_server_service_data[i].sockfd = -1;
        }
        log_info("rest server: stopping");
        logger_flush();
        service_stop(&rest_server_service);
        log_info("rest server: finalising");
        logger_flush();
        service_finalise(&rest_server_service);
    }
    else
    {
        log_info("rest server: stop requested but the server hasn't been started");
        logger_flush();
    }
}

ya_result rest_server_page_register(const char *name, rest_server_page_t *page)
{
    ya_result ret = SUCCESS;
    mutex_lock(&rest_server_pages_mtx);
    if((name != NULL) && (page != NULL))
    {
        // split name into components;
        while(*name == '/')
        {
            ++name;
        }

        char  *tokens[REST_SERVER_PAGE_REGISTER_TOKENS_MAX];
        size_t token_count = text_split_to_array(name, '/', tokens, REST_SERVER_PAGE_REGISTER_TOKENS_MAX);
        if(token_count > 0)
        {
            rest_server_path_component_t *current = &rest_server_pages_root;
            ptr_treemap_node_t           *token_node;

            for(size_t token_index = 0; token_index < token_count; ++token_index)
            {
                // coherence check:

                if(tokens[token_index][0] == '$')
                {
                    ptr_treemap_node_t *first_node = ptr_treemap_get_first(&current->path_components);
                    if(first_node != NULL)
                    {
                        // the key better have the same name
                        if(strcmp(first_node->key, tokens[token_index]) != 0)
                        {
                            // two registered paths having two different variable names at the same position
                            ret = INVALID_STATE_ERROR;
                            break;
                        }
                    }
                }

                token_node = ptr_treemap_insert(&current->path_components, tokens[token_index]);
                if(token_node->value == NULL)
                {
                    token_node->key = strdup(tokens[token_index]);
                    rest_server_path_component_t *component;
                    ZALLOC_OBJECT_OR_DIE(component, rest_server_path_component_t, GENERIC_TAG);
                    component->path_components.root = NULL;
                    component->path_components.compare = ptr_treemap_asciizcasep_node_compare;
                    component->page = NULL;
                    current = component;
                    token_node->value = current;
                }
                else
                {
                    // already exists
                    current = token_node->value;
                }
            }

            // last found/inserted node gets the page
            current->page = page;

            // for all tokens[1..] above ...
        }

        for(size_t token_index = 0; token_index < token_count; ++token_index)
        {
            free(tokens[token_index]);
        }
    }
    else
    {
        ret = UNEXPECTED_NULL_ARGUMENT_ERROR;
    }

    mutex_unlock(&rest_server_pages_mtx);

    return ret;
}

const char *rest_server_context_varg_get(rest_server_context_t *ctx, const char *name_, va_list args)
{
    const char *ret = NULL;
    const char *name = name_;

    if(name == NULL)
    {
        return NULL;
    }

    for(;;)
    {
        ptr_treemap_node_t *node = ptr_treemap_find(&ctx->page_args, name);

        if(node != NULL)
        {
            ret = (const char *)node->value;
            break;
        }

        char *arg = va_arg(args, char *);
        if(arg == NULL)
        {
            break;
        }
        name = arg;
    }
    return ret;
}

bool rest_server_context_arg_get(rest_server_context_t *ctx, char **text, const char *name_, ...)
{
    const char *value;
    va_list     args;
    va_start(args, name_);
    value = rest_server_context_varg_get(ctx, name_, args);
    bool hasit = (value != NULL);
    if(hasit)
    {
        *text = (char *)value;
    }
    va_end(args);
    return hasit;
}

bool rest_server_context_arg_get_double(rest_server_context_t *ctx, double *valuep, const char *name_, ...)
{
    const char *value;
    va_list     args;
    va_start(args, name_);
    value = rest_server_context_varg_get(ctx, name_, args);
    bool hasit = (value != NULL);
    if(hasit)
    {
        hasit = sscanf(value, "%lf", valuep) == 1;
    }
    va_end(args);
    return hasit;
}

bool rest_server_context_arg_get_int(rest_server_context_t *ctx, int *valuep, const char *name_, ...)
{
    const char *value;
    va_list     args;
    va_start(args, name_);
    value = rest_server_context_varg_get(ctx, name_, args);
    bool hasit = (value != NULL);
    if(hasit)
    {
        hasit = sscanf(value, "%i", valuep) == 1;
    }
    va_end(args);
    return hasit;
}

bool rest_server_context_arg_get_int64(rest_server_context_t *ctx, int64_t *valuep, const char *name_, ...)
{
    const char *value;
    va_list     args;
    va_start(args, name_);
    value = rest_server_context_varg_get(ctx, name_, args);
    bool hasit = (value != NULL);
    if(hasit)
    {
        hasit = sscanf(value, "%li", valuep) == 1;
    }
    va_end(args);
    return hasit;
}

bool rest_server_context_arg_get_u8(rest_server_context_t *ctx, uint8_t *valuep, const char *name_, ...)
{
    const char *value;
    va_list     args;
    va_start(args, name_);
    value = rest_server_context_varg_get(ctx, name_, args);
    bool hasit = (value != NULL);
    if(hasit)
    {
        hasit = sscanf(value, "%hhu", valuep) == 1;
    }
    va_end(args);
    return hasit;
}

bool rest_server_context_arg_get_bool(rest_server_context_t *ctx, bool *valuep, const char *name_, ...)
{
    const char *value;
    va_list     args;
    va_start(args, name_);
    value = rest_server_context_varg_get(ctx, name_, args);
    bool hasit = (value != NULL);
    if(hasit)
    {
        int tmp;
        hasit = sscanf(value, "%i", &tmp) == 1;
        if(hasit)
        {
            *valuep = tmp != 0;
        }
    }
    va_end(args);
    return hasit;
}

bool rest_server_context_path_arg_get(rest_server_context_t *ctx, char **text, const char *name)
{
    bool                ret;
    ptr_treemap_node_t *node = ptr_treemap_find(&ctx->path_args, name);
    if((ret = (node != NULL)))
    {
        *text = node->value;
    }
    return ret;
}

bool rest_server_context_path_arg_get_double(rest_server_context_t *ctx, double *valuep, const char *name)
{
    bool  ret;
    char *text;
    if((ret = rest_server_context_path_arg_get(ctx, &text, name)))
    {
        ret = sscanf(text, "%lf", valuep) == 1;
    }
    return ret;
}

bool rest_server_context_path_arg_get_int(rest_server_context_t *ctx, int *valuep, const char *name)
{
    bool  ret;
    char *text;
    if((ret = rest_server_context_path_arg_get(ctx, &text, name)))
    {
        ret = sscanf(text, "%i", valuep) == 1;
    }
    return ret;
}

bool rest_server_context_path_arg_get_int64(rest_server_context_t *ctx, int64_t *valuep, const char *name)
{
    bool  ret;
    char *text;
    if((ret = rest_server_context_path_arg_get(ctx, &text, name)))
    {
        ret = sscanf(text, "%li", valuep) == 1;
    }
    return ret;
}

bool rest_server_context_path_arg_get_u8(rest_server_context_t *ctx, uint8_t *valuep, const char *name)
{
    bool  ret;
    char *text;
    if((ret = rest_server_context_path_arg_get(ctx, &text, name)))
    {
        ret = sscanf(text, "%hhu", valuep) == 1;
    }
    return ret;
}

bool rest_server_context_path_arg_get_bool(rest_server_context_t *ctx, bool *valuep, const char *name)
{
    bool  ret;
    char *text;
    if((ret = rest_server_context_path_arg_get(ctx, &text, name)))
    {
        int tmp;
        ret = sscanf(text, "%i", &tmp) == 1;
        if(ret)
        {
            *valuep = tmp != 0;
        }
    }
    return ret;
}

ya_result rest_server_write_http_header_and_body(rest_server_context_t *ctx, int code, const char *code_text, int buffer_size, const void *buffer)
{
    osformat(&ctx->os,
             "HTTP/1.1 %d %s\r\n"
             "Content-Encoding: text/plain\r\n"
             "Content-Type: application/json;charset=utf-8\r\n",
             code,
             code_text);

    if(ctx->access_control_allow_origin != NULL)
    {
        osformat(&ctx->os, "Access-Control-Allow-Origin: %s\r\n", ctx->access_control_allow_origin);
    }

    if(buffer != NULL)
    {
        osformat(&ctx->os, "Content-Length: %i\r\n", buffer_size);
    }

    output_stream_write(&ctx->os, "\r\n", 2);

    if(buffer != NULL)
    {
        output_stream_write(&ctx->os, buffer, buffer_size);
    }

    return SUCCESS;
}

ya_result rest_server_write_http_header_and_print(rest_server_context_t *ctx, int code, const char *code_text, const char *fmt, ...)
{
    osformat(&ctx->os,
             "HTTP/1.1 %d %s\r\n"
             "Content-Encoding: text/plain\r\n"
             "Content-Type: application/json;charset=utf-8\r\n",
             code,
             code_text);

    if(ctx->access_control_allow_origin != NULL)
    {
        osformat(&ctx->os, "Access-Control-Allow-Origin: %s\r\n", ctx->access_control_allow_origin);
    }

    va_list args;
    va_start(args, fmt);
    output_stream_t baos;
    bytearray_output_stream_init(&baos, NULL, 0);
    vosformat(&baos, fmt, args);
    va_end(args);

    uint32_t buffer_size = bytearray_output_stream_size(&baos);

    if(buffer_size > 0)
    {
        osformat(&ctx->os, "Content-Length: %i\r\n", buffer_size);
    }

    output_stream_write(&ctx->os, "\r\n", 2);

    if(buffer_size > 0)
    {
        output_stream_write(&ctx->os, bytearray_output_stream_buffer(&baos), buffer_size);
    }

    output_stream_close(&baos);

    return SUCCESS;
}
