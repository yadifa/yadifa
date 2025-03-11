################################################################################
#
# Copyright (c) 2011-2025, EURid vzw. All rights reserved.
# The YADIFA TM software product is provided under the BSD 3-clause license:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#        * Redistributions of source code must retain the above copyright
#          notice, this list of conditions and the following disclaimer.
#        * Redistributions in binary form must reproduce the above copyright
#          notice, this list of conditions and the following disclaimer in the
#          documentation and/or other materials provided with the distribution.
#        * Neither the name of EURid nor the names of its contributors may be
#          used to endorse or promote products derived from this software
#          without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
################################################################################

include(CheckIncludeFile)

function(check_headers_files)
    check_include_file(arpa/inet.h HAVE_ARPA_INET_H)
    check_include_file(asm/unistd.h HAVE_ASM_UNISTD_H)
    check_include_file(assert.h HAVE_ASSERT_H)
    check_include_file(bfd.h HAVE_BFD_H)
    check_include_file(byteswap.h HAVE_BYTESWAP_H)
    check_include_file(cpuid.h HAVE_CPUID_H)
    check_include_file(ctype.h HAVE_CTYPE_H)
    check_include_file(dirent.h HAVE_DIRENT_H)
    check_include_file(dlfcn.h HAVE_DLFCN_H)
    check_include_file(endian.h HAVE_ENDIAN_H)
    check_include_file(errno.h HAVE_ERRNO_H)
    check_include_file(execinfo.h HAVE_EXECINFO_H)
    check_include_file(fcntl.h HAVE_FCNTL_H)
    check_include_file(getopt.h HAVE_GETOPT_H)
    check_include_file(grp.h HAVE_GRP_H)
    check_include_file(limits.h HAVE_LIMITS_H)
    check_include_file(linux/limits.h HAVE_LINUX_LIMITS_H)
    check_include_file(mach/clock.h HAVE_MACH_CLOCK_H)
    check_include_file(machine/endian.h HAVE_MACHINE_ENDIAN_H)
    check_include_file(mach/mach.h HAVE_MACH_MACH_H)
    check_include_file(malloc.h HAVE_MALLOC_H)
    check_include_file(netdb.h HAVE_NETDB_H)
    check_include_file(net/ethernet.h HAVE_NET_ETHERNET_H)
    check_include_file(netinet/in.h HAVE_NETINET_IN_H)
    check_include_file(netinet6/in6.h HAVE_NETINET_IN_H)
    check_include_file(netinet/tcp.h HAVE_NETINET_TCP_H)
    check_include_file(pcap/pcap.h HAVE_PCAP_PCAP_H)
    check_include_file(poll.h HAVE_POLL_H)
    check_include_file(pthread.h HAVE_PTHREAD_H)
    check_include_file(pwd.h HAVE_PWD_H)
    check_include_file(sched.h HAVE_SCHED_H)
    check_include_file(signal.h HAVE_SIGNAL_H)
    check_include_file(stdarg.h HAVE_STDARG_H)
    check_include_file(stdatomic.h HAVE_STDATOMIC_H)
    check_include_file(stdbool.h HAVE_STDBOOL_H)
    check_include_file(stddef.h HAVE_STDDEF_H)
    check_include_file(stdint.h HAVE_STDINT_H)
    check_include_file(stdio.h HAVE_STDIO_H)
    check_include_file(stdlib.h HAVE_STDLIB_H)
    check_include_file(string.h HAVE_STRING_H)
    check_include_file(strings.h HAVE_STRINGS_H)
    check_include_file(sys/byteorder.h HAVE_SYS_BYTEORDER_H)
    check_include_file(sys/cpuset.h HAVE_SYS_CPUSET_H)
    check_include_file(sys/endian.h HAVE_SYS_ENDIAN_H)
    check_include_file(sys/file.h HAVE_SYS_FILE_H)
    check_include_file(sys/ipc.h HAVE_SYS_IPC_H)
    check_include_file(syslog.h HAVE_SYSLOG_H)
    check_include_file(sys/mman.h HAVE_SYS_MMAN_H)
    check_include_file(sys/msg.h HAVE_SYS_MSG_H)
    check_include_file(sys/param.h HAVE_SYS_PARAM_H)
    check_include_file(sys/prctl.h HAVE_SYS_PRCTL_H)
    check_include_file(sys/resource.h HAVE_SYS_RESOURCE_H)
    check_include_file(sys/socket.h HAVE_SYS_SOCKET_H)
    check_include_file(sys/stat.h HAVE_SYS_STAT_H)
    check_include_file(sys/syslimits.h HAVE_SYS_SYSLIMITS_H)
    check_include_file(sys/time.h HAVE_SYS_TIME_H)
    check_include_file(sys/types.h HAVE_SYS_TYPES_H)
    check_include_file(sys/un.h HAVE_SYS_UN_H)
    check_include_file(sys/wait.h HAVE_SYS_WAIT_H)
    check_include_file(tcl.h HAVE_TCL_H)
    check_include_file(time.h HAVE_TIME_H)
    check_include_file(ucontext.h HAVE_UCONTEXT_H)
    check_include_file(unistd.h HAVE_UNISTD_H)
    check_include_file(stdnoreturn.h HAVE_STDNORETURN_H)
endfunction()

