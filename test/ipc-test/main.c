/*------------------------------------------------------------------------------
 *
 * Copyright (c) 2011-2021, EURid vzw. All rights reserved.
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

/** @defgroup test
 *  @ingroup test
 *  @brief ipc_test file
 * 
 * ipc_test test program, will not be installed with a "make install"
 * 
 * To create a new test based on the ipc_test:
 * 
 * _ copy the folder
 * _ replace "ipc_test" by the name of the test
 * _ add the test to the top level Makefile.am and configure.ac
 *
 */

#include <dnscore/dnscore.h>
#include <dnscore/fdtools.h>
#include <dnscore/format.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

pid_t fork_ex();

#define LOTS_OF_MESSAGES 0x2000000

#define RECEIVER_BUFFER_SIZE 0x1000//00

static int waitpid_ex(pid_t pid, int *wstatus, int options)
{
    int ret;
    
    format("waitpid: %i should terminate soon\n", pid);
    
    while((ret = waitpid(pid, wstatus, options)) < 0)
    {
        int err = errno;
        
        if(err == EINTR)
        {
            continue;
        }
        else
        {
            perror("waitpid: ");
            return -1;
        }
    }
    
    format("waitpid: %i exited\n", ret);
    
    return ret;
}

struct msg_str
{
    s64 timestamp;
    u16 id;
    u16 cmd;
    u32 size;
    u8 data[];
};

static int message_test_with_size_recv(int fin, int size)
{
    s64 latency_min = MAX_S64;
    s64 latency_max = MIN_S64;
    s64 latency_total = 0;
    s64 latency_count = 0;
    
    struct msg_str message_in;
    
    size_t buffer_size = 0x100000;    
    u8 *buffer = (u8*)malloc(buffer_size);
    if(buffer == NULL)
    {
        formatln("message_test: malloc failed: %r", ERRNO_ERROR);
        return -2;
    }

    s64 start = timeus();
    s64 now = start + 1;
    s64 last_dump = start;
    s64 i;
    
    int ret = 0;

    for(i = 0;; ++i)
    {
        int n = readfully(fin, &message_in, sizeof(message_in));
        
        if(n < 0)
        {
            formatln("message_test: read: %r", ERRNO_ERROR);
            ret = -3;
            break;
        }

        u32 data_size = message_in.size;
        while(data_size > 0)
        {
            int chunk_size = readfully(fin, buffer, MIN(buffer_size, data_size));
            if(chunk_size < 0)
            {
                ret = -4;
                goto message_test_with_size_recv_end;
            }
            data_size -= chunk_size;
        }
        
        now = timeus();

        s64 latency = now - message_in.timestamp;
        if(latency < 0) latency = 0;

        latency_min = MIN(latency_min, latency);
        latency_max = MAX(latency_max, latency);
        latency_total += latency;
        ++latency_count;

        if(message_in.id !=  0)
        {
            formatln("message_test: broken stream");
            osprint_dump(termout, &message_in, 16, sizeof(struct msg_str), OSPRINT_DUMP_LAYOUT_ERIC | OSPRINT_DUMP_HEXTEXT);
            break;
        }

        if(message_in.cmd == 0xffff)
        {
            formatln("message_test: stop command received");
            break;
        }

        if(now - last_dump > 1000000LL)
        {
            last_dump = now;
            s64 delta = MAX(now - start, 1LL);
            formatln("%lli messages, latency [%lli;%lli] us, mean: %lli, mps=%lli bps=%lli",
                        i, latency_min, latency_max, latency_total / latency_count,
                        (i * 1000000LL) / delta,
                        (i * 1000000LL * (size + sizeof(struct msg_str))) / delta
                    );
        }
    }

message_test_with_size_recv_end:
    {
        s64 delta = MAX(now - start, 1LL);
        formatln("%lli messages, latency [%lli;%lli] us, mean: %lli, mps=%lli bps=%lli (done)",
                 i, latency_min, latency_max, latency_total / latency_count,
                 (i * 1000000LL) / delta,
                 (i * 1000000LL * (size + sizeof(struct msg_str))) / delta
        );
    }
    
    free(buffer);

    return ret;
}


static int message_test_with_size_recv2(int fin, int size)
{
    s64 latency_min = MAX_S64;
    s64 latency_max = MIN_S64;
    s64 latency_total = 0;
    s64 latency_count = 0;
    
    println("message_test_with_size_recv2");
    
    size_t buffer_size = RECEIVER_BUFFER_SIZE;    
    u8 * const buffer = (u8*)malloc(buffer_size);
    if(buffer == NULL)
    {
        formatln("message_test_with_size_recv2: malloc failed: %r", ERRNO_ERROR);
        close_ex(fin);
        return -2;
    }
    
    u8 * const buffer2 = (u8*)malloc(buffer_size);
    if(buffer2 == NULL)
    {
        formatln("message_test_with_size_recv2: malloc failed: %r", ERRNO_ERROR);
        free(buffer);
        close_ex(fin);
        return -2;
    }
    
    s64 start = timeus();
    s64 now = start + 1;
    s64 last_dump = start;
    
    u8 *ptr = buffer;
    int n = 0;
    int ret = 0;
    s64 i;
    
    for(i = 0;;)
    {
        for(;;)
        {
            ssize_t chunk = read(fin, ptr, RECEIVER_BUFFER_SIZE - n);
            
            if(chunk >= 0)
            {
                n += chunk;
                ptr += chunk;
                
                if((size_t)n >= sizeof(struct msg_str))
                {
                    break;
                }
            }
            else
            {
                int err = errno;
                if(err != EINTR)
                {
                    ret = -err;
                    goto named_pipe_test_with_size_recv2_end;
                }
            }
        }
        
        // at least one message has been read
        
        struct msg_str *message_in = (struct msg_str *)buffer;
        u32 avail = n;

        do
        {
            avail -= sizeof(struct msg_str);
            
            if(message_in->size > avail)
            {
                // there is more to be read, artificially

                u32 remain = message_in->size - avail;
                while(remain > 0)
                {
                    int chunk = readfully(fin, buffer2, MIN(buffer_size, remain));
                    if(chunk < 0)
                    {
                        goto named_pipe_test_with_size_recv2_end;
                    }
                    remain -= chunk;
                }

                // finished reading the data, nothing available anymore
                avail = 0;
            }
            else
            {
                avail -= message_in->size;
            }

            // ready to process the message

            now = timeus();
            
            ++i;

            s64 latency = now - message_in->timestamp;
            if(latency < 0) latency = 0;

            latency_min = MIN(latency_min, latency);
            latency_max = MAX(latency_max, latency);
            latency_total += latency;
            ++latency_count;

            if(message_in->id !=  0)
            {
                formatln("message_test_with_size_recv2: broken stream");
                osprint_dump(termout, &message_in, 16, sizeof(struct msg_str), OSPRINT_DUMP_LAYOUT_ERIC | OSPRINT_DUMP_HEXTEXT);
                ret = -5;
                goto named_pipe_test_with_size_recv2_end;
            }

            if(message_in->cmd == 0xffff)
            {
                formatln("message_test: stop command received");
                goto named_pipe_test_with_size_recv2_end;
            }

            if(now - last_dump > 1000000LL)
            {
                last_dump = now;
                s64 delta = now - start;
                formatln("%lli messages, latency [%lli;%lli] us, mean: %lli, mps=%lli bps=%lli",
                            i, latency_min, latency_max, latency_total / latency_count,
                            (i * 1000000LL) / delta,
                            (i * 1000000LL * (size + sizeof(struct msg_str))) / delta
                        );
            }

            // if what is available is bigger than a header, loop
            
            message_in = (struct msg_str *)&buffer[sizeof(struct msg_str) + message_in->size];
        }
        while(avail >= sizeof(struct msg_str));

        memmove(buffer, message_in, avail);
        n = avail;
        ptr = &buffer[n];
    }

named_pipe_test_with_size_recv2_end:

    {
        s64 delta = MIN(now - start, 1LL);
        formatln("%lli messages, latency [%lli;%lli] us, mean: %lli, mps=%lli bps=%lli (done)",
                 i, latency_min, latency_max, latency_total / latency_count,
                 (i * 1000000LL) / delta,
                 (i * 1000000LL * (size + sizeof(struct msg_str))) / delta
        );
    }
    
    free(buffer2);
    free(buffer);
    
    println("message_test_with_size_recv2: done");
    
    return ret;
}

static int message_test_with_size_send(int fout, int size)
{
    struct msg_str *message_out;
    size_t message_out_size = sizeof(struct msg_str) + size;
    message_out = (struct msg_str*)malloc(message_out_size);

    message_out->id = 0;
    message_out->cmd = 0;
    message_out->size = size;
    
    println("message_test_with_size_send");

    for(int i = 0; i < size; ++i)
    {
        message_out->data[i] = i;
    }

    formatln("message with data size %i ready", size);

    for(int i = 0; i < LOTS_OF_MESSAGES; ++i)
    {
        s64 now = timeus();

        message_out->timestamp = now;

        int n = writefully(fout, message_out, message_out_size);

        if(n < 0)
        {
            formatln("message_test: write: %r", ERRNO_ERROR);
            return -4;
        }
    }

    message_out->cmd = 0xffff;
    message_out->size = 0;

    int ret = writefully(fout, message_out, sizeof(struct msg_str));
    
    println("message_test_with_size_send_done");
    
    return ret;
}

static int message_test_with_size_send_slow(int fout, int size, int delay)
{
    struct msg_str *message_out;
    size_t message_out_size = sizeof(struct msg_str) + size;
    message_out = (struct msg_str*)malloc(message_out_size);

    message_out->id = 0;
    message_out->cmd = 0;
    message_out->size = size;
    
    println("message_test_with_size_send_slow");

    for(int i = 0; i < size; ++i)
    {
        message_out->data[i] = i;
    }

    formatln("message with data size %i ready", size);

    for(int i = 0; i < 1000; ++i)
    {
        s64 now = timeus();

        message_out->timestamp = now;

        int n = writefully(fout, message_out, message_out_size);

        if(n < 0)
        {
            formatln("message_test: write: %r", ERRNO_ERROR);
            return -4;
        }
        
        usleep(delay);
    }

    message_out->cmd = 0xffff;
    message_out->size = 0;

    int ret = writefully(fout, message_out, sizeof(struct msg_str));
    
    println("message_test_with_size_send_slow: done");
    
    return ret;
}

static int named_pipe_test_with_size_recv(const char* name, int size, pid_t pid)
{
    (void)pid;
    int fin;
    
    char fifo_name[PATH_MAX];
    snformat(fifo_name, sizeof(fifo_name), "%s-i", name);
    
    println("named_pipe_test_with_size_recv");

    if((fin = open_ex(fifo_name, O_RDONLY)) < 0)
    {
        formatln("named_pipe_test: mkfifo: %s: %r", fifo_name, ERRNO_ERROR);
        return -1;
    }
    
    int ret = message_test_with_size_recv(fin, size);
    
    close_ex(fin);
        
    return ret;
}

static int named_pipe_test_with_size_recv2(const char* name, int size, pid_t pid)
{
    (void)pid;
    int fin;
    
    char fifo_name[PATH_MAX];
    snformat(fifo_name, sizeof(fifo_name), "%s-i", name);
    
    println("named_pipe_test_with_size_recv2");

    if((fin = open_ex(fifo_name, O_RDONLY)) < 0)
    {
        formatln("named_pipe_test_2: mkfifo: %s: %r", fifo_name, ERRNO_ERROR);
        return -4;
    }

    int ret = message_test_with_size_recv2(fin, size);
    
    close_ex(fin);
    
    return ret;
}

static int named_pipe_test_with_size_send(const char* name, int size)
{
    int fout;
    
    char fifo_name[PATH_MAX];
    
    snformat(fifo_name, sizeof(fifo_name), "%s-i", name);
    
    println("named_pipe_test_with_size_send");
    
    if((fout = open_ex(fifo_name, O_WRONLY)) < 0)
    {
        formatln("named_pipe_test: mkfifo: %s: %r", fifo_name, ERRNO_ERROR);
        return -3;
    }

    int ret = message_test_with_size_send(fout, size);
    
    close_ex(fout);
    
    return ret;
}

static int named_pipe_test_with_size_send_slow(const char* name, int size)
{
    int fout;
    
    char fifo_name[PATH_MAX];
    
    snformat(fifo_name, sizeof(fifo_name), "%s-i", name);
    
    println("named_pipe_test_with_size_send_slow");
    
    if((fout = open_ex(fifo_name, O_WRONLY)) < 0)
    {
        formatln("named_pipe_test_slow: mkfifo: %s: %r", fifo_name, ERRNO_ERROR);
        return -3;
    }

    int ret = message_test_with_size_send_slow(fout, size, 1000);
    
    close_ex(fout);
    
    return ret;
}

static void named_pipe_test_with_size(const char* name, int size)
{
    pid_t pid;
    
    println("test: named_pipe_test_with_size");
    
    //key_t key = ftok(name, 0xl337beef);
    //int mq = msgget(IPC_PRIVATE, IPC_CREAT);
    
    char fifo_name[PATH_MAX];
    snformat(fifo_name, sizeof(fifo_name), "%s-i", name);
    
    if(mkfifo(fifo_name, 0600) < 0)
    {
        formatln("named_pipe_test_with_size: mkfifo(%s,0600) failed: %r", fifo_name, ERRNO_ERROR);
    }
        
    if((pid = fork_ex()) != 0)
    {
        named_pipe_test_with_size_recv(name, size, pid);
        
        // kill(pid, SIGTERM);
        
        int wstatus = 0;
        waitpid_ex(pid, &wstatus, 0);
    }
    else
    {
        named_pipe_test_with_size_send(name, size);
        exit(0);
    }
}

static void named_pipe_test_with_size2(const char* name, int size)
{
    pid_t pid;
    
    println("test: named_pipe_test_with_size2");
    
    //key_t key = ftok(name, 0xl337beef);
    //int mq = msgget(IPC_PRIVATE, IPC_CREAT);
    
    char fifo_name[PATH_MAX];
    snformat(fifo_name, sizeof(fifo_name), "%s-i", name);
    
    if(mkfifo(fifo_name, 0600) < 0)
    {
        formatln("named_pipe_test_with_size2: mkfifo(%s,0600) failed: %r", fifo_name, ERRNO_ERROR);
    }
        
    if((pid = fork_ex()) != 0)
    {
        named_pipe_test_with_size_recv2(name, size, pid);
        
        // kill(pid, SIGTERM);
        
        int wstatus = 0;
        waitpid_ex(pid, &wstatus, 0);
    }
    else
    {
        named_pipe_test_with_size_send(name, size);
        exit(0);
    }
}

static void named_pipe_test_with_size_slow(const char* name, int size)
{
    pid_t pid;
    
    println("test: named_pipe_test_with_size_slow");
    
    //key_t key = ftok(name, 0xl337beef);
    //int mq = msgget(IPC_PRIVATE, IPC_CREAT);
    
    char fifo_name[PATH_MAX];
    snformat(fifo_name, sizeof(fifo_name), "%s-i", name);
    
    if(mkfifo(fifo_name, 0600) < 0)
    {
        formatln("named_pipe_test_with_size_slow: mkfifo(%s,0600) failed: %r", fifo_name, ERRNO_ERROR);
    }
        
    if((pid = fork_ex()) != 0)
    {
        named_pipe_test_with_size_recv(name, size, pid);
        
        // kill(pid, SIGTERM);
        
        int wstatus = 0;
        waitpid_ex(pid, &wstatus, 0);
    }
    else
    {
        named_pipe_test_with_size_send_slow(name, size);
        exit(0);
    }
}

static void named_pipe_test_with_size2_slow(const char* name, int size)
{
    pid_t pid;
    
    println("test: named_pipe_test_with_size2_slow");
    
    //key_t key = ftok(name, 0xl337beef);
    //int mq = msgget(IPC_PRIVATE, IPC_CREAT);
    
    char fifo_name[PATH_MAX];
    snformat(fifo_name, sizeof(fifo_name), "%s-i", name);
    
    if(mkfifo(fifo_name, 0600) < 0)
    {
        formatln("named_pipe_test_with_size2_slow: mkfifo(%s,0600) failed: %r", fifo_name, ERRNO_ERROR);
    }
        
    if((pid = fork_ex()) != 0)
    {
        named_pipe_test_with_size_recv2(name, size, pid);
        
        // kill(pid, SIGTERM);
        
        int wstatus = 0;
        waitpid_ex(pid, &wstatus, 0);
    }
    else
    {
        named_pipe_test_with_size_send_slow(name, size);
        exit(0);
    }
}

static int unix_socket_test_with_size_recv(const char* abstract_name, size_t abstract_name_size, int size)
{
    struct sockaddr_un myaddr;
    memset(&myaddr, 0, sizeof(myaddr));
    int ret = -1;
    
    println("unix_socket_test_with_size_recv");
    
    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    if(server >= 0)
    {
        myaddr.sun_family = AF_UNIX;
        assert(abstract_name_size <= sizeof(myaddr.sun_path));
        memcpy(myaddr.sun_path, abstract_name, abstract_name_size);
        if(bind(server, (struct sockaddr*)&myaddr, sizeof(struct sockaddr_un)) >= 0)
        {
            if(listen(server, 5) >= 0)
            {
                int client = accept(server, NULL, NULL);
                
                if(client >= 0)
                {
                    ret = message_test_with_size_recv(client, size);

                    close_ex(client);
                }
                else
                {
                    perror("unix_socket_test_with_size_recv: accept");
                }
            }
            else
            {
                perror("unix_socket_test_with_size_recv: listen");
            }
        }
        else
        {
            perror("unix_socket_test_with_size_recv: bind");
        }
        
        close_ex(server);
    }
    else
    {
        perror("unix_socket_test_with_size_recv: socket");
    }
    
    println("unix_socket_test_with_size_recv: done");
    
    return ret;
}

static int unix_socket_test_with_size_recv2(const char* abstract_name, size_t abstract_name_size, int size)
{
    struct sockaddr_un myaddr;
    memset(&myaddr, 0, sizeof(myaddr));
    int ret = -1;
    
    println("unix_socket_test_with_size_recv2");
    
    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    if(server >= 0)
    {
        myaddr.sun_family = AF_UNIX;
        assert(abstract_name_size <= sizeof(myaddr.sun_path));
        memcpy(myaddr.sun_path, abstract_name, abstract_name_size);
        if(bind(server, (struct sockaddr*)&myaddr, sizeof(struct sockaddr_un)) >= 0)
        {
            if(listen(server, 5) >= 0)
            {
                int client = accept(server, NULL, NULL);
                
                if(client >= 0)
                {
                    ret = message_test_with_size_recv2(client, size);

                    close_ex(client);
                }
                else
                {
                    perror("unix_socket_test_with_size_recv2: accept");
                }
            }
            else
            {
                perror("unix_socket_test_with_size_recv2: listen");
            }
        }
        else
        {
            perror("unix_socket_test_with_size_recv2: bind");
        }
        
        close_ex(server);
    }
    else
    {
        perror("unix_socket_test_with_size_recv2: socket");
    }
    
    println("unix_socket_test_with_size_recv2: done");
    
    return ret;
}


static int unix_socket_test_with_size_send(const char* abstract_name, size_t abstract_name_size, int size)
{
    struct sockaddr_un myaddr;
    int ret = -1;
    
    println("unix_socket_test_with_size_send");
    
    memset(&myaddr, 0, sizeof(myaddr));
    for(int tries = 3; tries >= 0; --tries)
    {
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if(sock >= 0)
        {
            myaddr.sun_family = AF_UNIX;
            assert(abstract_name_size <= sizeof(myaddr.sun_path));
            memcpy(myaddr.sun_path, abstract_name, abstract_name_size);
            if(connect(sock, (struct sockaddr*)&myaddr, sizeof(struct sockaddr_un)) >= 0)
            {
                ret = message_test_with_size_send(sock, size);
                break;
            }
            else
            {
                perror("unix_socket_test_with_size_send: connect");
            }

            close_ex(sock);
        }
        else
        {
            perror("unix_socket_test_with_size_send: socket");
        }
        
        sleep(1);
    }
    
    println("unix_socket_test_with_size_send: done");
    
    return ret;
}

static int unix_socket_test_with_size_send_slow(const char* abstract_name, size_t abstract_name_size, int size)
{
    struct sockaddr_un myaddr;
    int ret = -1;
    
    println("unix_socket_test_with_size_send_slow");
    
    memset(&myaddr, 0, sizeof(myaddr));
    
    for(int tries = 3; tries >= 0; --tries)
    {
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if(sock >= 0)
        {
            myaddr.sun_family = AF_UNIX;
            assert(abstract_name_size <= sizeof(myaddr.sun_path));
            memcpy(myaddr.sun_path, abstract_name, abstract_name_size);
            if(connect(sock, (struct sockaddr*)&myaddr, sizeof(struct sockaddr_un)) >= 0)
            {
                ret = message_test_with_size_send_slow(sock, size, 1000);
                break;
            }
            else
            {
                perror("unix_socket_test_with_size_send_slow: connect");
            }

            close_ex(sock);
        }
        else
        {
            perror("unix_socket_test_with_size_send_slow: socket");
        }
        
        sleep(1);
    }
    
    println("unix_socket_test_with_size_send_slow: done");
    
    return ret;
}


static const char abstract_name[9] = {'\0', 'y','a','d','i','f','a','d','\0'};

static void unix_socket_test_with_size(const char* abstract_name, int abstract_name_size, int size)
{
    pid_t pid;
    
    println("test: unix_socket_test_with_size");

    if((pid = fork_ex()) != 0)
    {
        unix_socket_test_with_size_recv(abstract_name, abstract_name_size, size);
        
        // kill(pid, SIGTERM);
        
        int wstatus = 0;
        waitpid_ex(pid, &wstatus, 0);
    }
    else
    {  
        unix_socket_test_with_size_send(abstract_name, abstract_name_size, size);
        exit(0);
    }
}

static void unix_socket_test_with_size_slow(const char* abstract_name, int abstract_name_size, int size)
{
    pid_t pid;
    
    println("test: unix_socket_test_with_size_slow");

    if((pid = fork_ex()) != 0)
    {
        unix_socket_test_with_size_recv(abstract_name, abstract_name_size, size);
        
        // kill(pid, SIGTERM);
        
        int wstatus = 0;
        waitpid_ex(pid, &wstatus, 0);
    }
    else
    {  
        unix_socket_test_with_size_send_slow(abstract_name, abstract_name_size, size);
        exit(0);
    }
}

static void unix_socket_test_with_size2(const char* abstract_name, int abstract_name_size, int size)
{
    pid_t pid;
    
    println("test: unix_socket_test_with_size2");

    if((pid = fork_ex()) != 0)
    {
        unix_socket_test_with_size_recv2(abstract_name, abstract_name_size, size);
        
        // kill(pid, SIGTERM);
        
        int wstatus = 0;
        waitpid_ex(pid, &wstatus, 0);
    }
    else
    {  
        sleep(1);
        unix_socket_test_with_size_send(abstract_name, abstract_name_size, size);
        exit(0);
    }
}

static void unix_socket_test_with_size2_slow(const char* abstract_name, int abstract_name_size, int size)
{
    pid_t pid;
    
    println("test: unix_socket_test_with_size2_slow");

    if((pid = fork_ex()) != 0)
    {
        unix_socket_test_with_size_recv2(abstract_name, abstract_name_size, size);
        
        // kill(pid, SIGTERM);
        
        int wstatus = 0;
        waitpid_ex(pid, &wstatus, 0);
    }
    else
    {  
        sleep(1);
        unix_socket_test_with_size_send_slow(abstract_name, abstract_name_size, size);
        exit(0);
    }
}

int
main(int argc, char *argv[])
{
    int size = 0;
    
    if(argc > 1)
    {
        size = atoi(argv[1]);
    }
    
    /* initializes the core library */
        
    dnscore_init();
    
    formatln("payload size: %i", size);

    println("----- unix_socket_test_with_size -----");fflush(NULL);
    unix_socket_test_with_size(abstract_name, sizeof(abstract_name), size);
    println("----- NEXT -----");fflush(NULL);
    sleep(1);
    println("----- unix_socket_test_with_size_slow -----");fflush(NULL);
    unix_socket_test_with_size_slow(abstract_name, sizeof(abstract_name), size);
    println("----- NEXT -----");fflush(NULL);
    sleep(1);
    println("----- unix_socket_test_with_size2 -----");fflush(NULL);
    unix_socket_test_with_size2(abstract_name, sizeof(abstract_name), size);
    println("----- NEXT -----");fflush(NULL);
    sleep(1);
    println("----- unix_socket_test_with_size2_slow -----");fflush(NULL);
    unix_socket_test_with_size2_slow(abstract_name, sizeof(abstract_name), size);
    println("----- NEXT -----");fflush(NULL);
    sleep(1);
    println("----- named_pipe_test_with_size -----");fflush(NULL);
    named_pipe_test_with_size(argv[0], size);
    println("----- NEXT -----");fflush(NULL);
    sleep(1);
    println("----- named_pipe_test_with_size_slow -----");fflush(NULL);
    named_pipe_test_with_size_slow(argv[0], size);
    println("----- NEXT -----");fflush(NULL);
    sleep(1);
    println("----- named_pipe_test_with_size2 -----");fflush(NULL);
    named_pipe_test_with_size2(argv[0], size);
    println("----- NEXT -----");fflush(NULL);
    sleep(1);
    println("----- named_pipe_test_with_size2_slow -----");fflush(NULL);
    named_pipe_test_with_size2_slow(argv[0], size);
    println("----- NEXT -----");fflush(NULL);
    sleep(1);
    flushout();
    flusherr();
    fflush(NULL);

    dnscore_finalize();

    return EXIT_SUCCESS;
}
