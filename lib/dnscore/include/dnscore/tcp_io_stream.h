/*------------------------------------------------------------------------------
*
* Copyright (c) 2011, EURid. All rights reserved.
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
* DOCUMENTATION */
/** @defgroup streaming Streams
 *  @ingroup dnscore
 *  @brief
 *
 * @{
 */

#ifndef _TCP_INPUT_STREAM_H
#define	_TCP_INPUT_STREAM_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <dnscore/file_input_stream.h>
#include <dnscore/file_output_stream.h>
#include <dnscore/io_stream.h>

#include <dnscore/host_address.h>

#ifdef	__cplusplus
extern "C"
{
#endif
    
ya_result
gethostaddr(const char* host, u16 port, struct sockaddr *sa, int family);

ya_result
tcp_input_output_stream_connect_sockaddr(struct sockaddr *sa, input_stream *istream_, output_stream *ostream_, struct sockaddr *bind_from, u8 to_sec);

ya_result
tcp_input_output_stream_connect_ex(const char *server, u16 port, input_stream *istream_, output_stream *ostream_, struct sockaddr *bind_from, u8 to_sec);

ya_result
tcp_input_output_stream_connect(const char *server, u16 port, input_stream *istream, output_stream *ostream);

ya_result
tcp_input_output_stream_connect_host_address(host_address *ha, input_stream *istream_, output_stream *ostream_, u8 to_sec);

ya_result
tcp_io_stream_connect_ex(const char *server, u16 port, io_stream *ios, struct sockaddr *bind_from);

ya_result
tcp_io_stream_connect(const char *server, u16 port, io_stream *ios);

void tcp_set_sendtimeout(int fd, int seconds, int useconds);
void tcp_get_sendtimeout(int fd, int *seconds, int *useconds);

void tcp_set_recvtimeout(int fd, int seconds, int useconds);
void tcp_get_recvtimeout(int fd, int *seconds, int *useconds);

void tcp_set_linger(int fd, bool enable, int seconds);

static inline void tcp_set_graceful_close(int fd)
{
    tcp_set_linger(fd, FALSE, 0);
}

static inline void tcp_set_abortive_close(int fd)
{
    tcp_set_linger(fd, TRUE, 0);
}

static inline void tcp_set_agressive_close(int fd, int seconds)
{
    tcp_set_linger(fd, TRUE, seconds);
}

#ifdef	__cplusplus
}
#endif

#endif	/* _TCP_INTPUT_STREAM_H */

/** @} */
