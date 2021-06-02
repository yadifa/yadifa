/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* number of hardware core if the auto-detect fails */
#define DEFAULT_ASSUMED_CPU_COUNT 2

/* acl = ACL_SUPPORT enabled */
#define HAS_ACL_SUPPORT 1

/* bfd debug support disabled. */
#define HAS_BFD_DEBUG_SUPPORT 0

/* Disable timestamps in the build disabled. */
#define HAS_BUILD_TIMESTAMP 1

/* Compiler supports feature */
#define HAS_CC_ADDRESS_SANITIZER_CHECK 0

/* Compiler supports feature */
#define HAS_CC_ANSI 1

/* Compiler supports feature */
#define HAS_CC_ANSI_ALIAS 0

/* Compiler supports feature */
#define HAS_CC_CATCH_UNDEFINED_BEHAVIOR 0

/* Compiler supports feature */
#define HAS_CC_DWARF2 1

/* Compiler supports feature */
#define HAS_CC_DWARF3 1

/* Compiler supports feature */
#define HAS_CC_DWARF4 1

/* Compiler supports feature */
#define HAS_CC_EXCEPTIONS 1

/* Compiler supports feature */
#define HAS_CC_G 1

/* Compiler supports feature */
#define HAS_CC_G3 1

/* Compiler supports feature */
#define HAS_CC_M32 0

/* Compiler supports feature */
#define HAS_CC_M64 1

/* Compiler supports feature */
#define HAS_CC_MISSING_FIELD_INITIALIZERS 1

/* Compiler supports feature */
#define HAS_CC_NO_IDENT 1

/* Compiler supports feature */
#define HAS_CC_NO_OMIT_FRAME_POINTER 1

/* Compiler supports feature */
#define HAS_CC_PEDANTIC 1

/* Compiler supports feature */
#define HAS_CC_RDYNAMIC 1

/* Compiler supports feature */
#define HAS_CC_SANITIZE_ADDRESS 0

/* Compiler supports feature */
#define HAS_CC_STACK_PROTECTOR 1

/* Compiler supports feature */
#define HAS_CC_STD_C11 1

/* Compiler supports feature */
#define HAS_CC_STD_C99 1

/* Compiler supports feature */
#define HAS_CC_STD_GNU11 1

/* Compiler supports feature */
#define HAS_CC_STD_GNU99 1

/* Compiler supports feature */
#define HAS_CC_TUNE_NATIVE 1

/* Compiler supports feature */
#define HAS_CC_WALL 1

/* Compiler supports feature */
#define HAS_CC_XC99 0

/* close_ex(fd) to change the value of fd to detect double-closes issues
   (debug) disabled. */
#define HAS_CLOSE_EX_REF 0

/* i386, Athlon, Opteron, Core2, i3, i5, i7, ... */
#define HAS_CPU_AMDINTEL 1

/* T1000 has a Niagara cpu */
/* #undef HAS_CPU_NIAGARA */

/* yadifa ctrl remote control tool disabled. */
#define HAS_CTRL 1

/* MUST be enabled if either NSEC3 or NSEC are enabled */
#define HAS_DNSSEC_SUPPORT 1

/* enable DNSSEC module for yadifa */
#define HAS_DNSSEC_TOOLS 1

/* dynamic update support disabled. */
#define HAS_DYNUPDATE_SUPPORT 1

/* Elliptic Curve (ECDSA) support (ie: the available OpenSSL does not support
   it) disabled. */
#define HAS_ECDSA_SUPPORT 1

/* Adds support for dynamically loaded module that gets events from yadifad
   and is allowed to fetch some information disabled. */
#define HAS_EVENT_DYNAMIC_MODULE 0

/* file pool uses cache (dev) disabled. */
#define HAS_FILEPOOL_CACHE 0

/* acceptance of ASCII7 characters in DNS names (not recommended) disabled. */
#define HAS_FULL_ASCII7 0

/* yadifa keygen tool disabled. */
#define HAS_KEYGEN 0

/* libc malloc debug support monitors program-wide allocations disabled. */
#define HAS_LIBC_MALLOC_DEBUG_SUPPORT 0

/* zone lock debug support disabled. */
#define HAS_LOCK_DEBUG_SUPPORT 0

/* where to put the log files */
#define HAS_LOGDIR 1

/* a column with the pid in each line of log disabled. */
#define HAS_LOG_PID 1

/* a column with an alphanumeric id consistent in the lowest 32 bits of a
   thread id in each log line disabled. */
#define HAS_LOG_THREAD_ID 0

/* a column with a 8 letters human-readable tag identifying a thread in each
   log line disabled. */
#define HAS_LOG_THREAD_TAG 1

/* malloc debug support for yadifa objects disabled. */
#define HAS_MALLOC_DEBUG_SUPPORT 0

/* DNS master disabled. */
#define HAS_MASTER_SUPPORT 1

/* Define this to enable slow but safe unaligned memory accesses */
#define HAS_MEMALIGN_ISSUES 0

/* mutex debug support disabled. */
#define HAS_MUTEX_DEBUG_SUPPORT 0

/* defaults axfr-strict-authority to no. Lenient acceptance of AXFR answer
   from master that do not have AA bit by default (Microsoft DNS) disabled. */
#define HAS_NON_AA_AXFR_SUPPORT 0

/* NSEC3 enabled */
#define HAS_NSEC3_SUPPORT 1

/* NSEC enabled */
#define HAS_NSEC_SUPPORT 1

/* NSID support disabled. */
#define HAS_NSID_SUPPORT 1

/* not linked with an OpenSSL compatible API */
#define HAS_OPENSSL 1

/* The system supports thread affinity */
#define HAS_PTHREAD_SETAFFINITY_NP 1

/* The system supports thread names */
#define HAS_PTHREAD_SETNAME_NP 1

/* The system supports spinlocks */
#define HAS_PTHREAD_SPINLOCK 1

/* DNS Response Rate Limiter disabled. */
#define HAS_RRL_SUPPORT 1

/* RRSIG verification and generation for zones disabled. */
#define HAS_RRSIG_MANAGEMENT_SUPPORT 1

/* The system supports setgroups */
#define HAS_SETGROUPS 1

/* The sockaddr_in6 struct has an sin6_len field */
#define HAS_SOCKADDR_IN6_SIN6_LEN 0

/* The sockaddr_in struct has an sin_len field */
#define HAS_SOCKADDR_IN_SIN_LEN 0

/* The sockaddr struct has an sa_len field */
#define HAS_SOCKADDR_SA_LEN 0

/* An alternative to be used if stdatomics is not available */
#define HAS_SYNC_BUILTINS 1

/* to set do-not-listen to "127.0.0.53 port 53" by default (otherwise the list
   is empty by default) disabled. */
#define HAS_SYSTEMD_RESOLVED_AVOIDANCE 0

/* Enables the TCP manager disabled. */
#define HAS_TCP_MANAGER 0

/* Without various internal test programs. */
#define HAS_TESTS 1

/* Without provided DNS-related tools. */
#define HAS_TOOLS 1

/* tracking of the instanciated zones for detecting potential leaks.
   Relatively cheap with a small (<100) amount of zones. disabled. */
#define HAS_TRACK_ZONES_DEBUG_SUPPORT 0

/* tsig = TSIG_SUPPORT enabled */
#define HAS_TSIG_SUPPORT 1

/* where to put the log files */
#define HAS_WITH_LOGDIR "${prefix}/var/log/yadifa" // ${prefix}/var/log/yadifa

/* building with controller */
#define HAS_YADIFA 1

/* zalloc debug support for yadifa objects disabled. */
#define HAS_ZALLOC_DEBUG_SUPPORT 0

/* zalloc statistics support disabled. */
#define HAS_ZALLOC_STATISTICS_SUPPORT 0

/* zalloc memory system disabled. */
#define HAS_ZALLOC_SUPPORT 1

/* yadifa zonesign tool disabled. */
#define HAS_ZONESIGN 0

/* Define to 1 if you have the `alarm' function. */
#define HAVE_ALARM 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <asm/unistd.h> header file. */
#define HAVE_ASM_UNISTD_H 1

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the `atexit' function. */
#define HAVE_ATEXIT 1

/* Define to 1 if you have the <bfd.h> header file. */
/* #undef HAVE_BFD_H */

/* Define to 1 if you have the <byteswap.h> header file. */
#define HAVE_BYTESWAP_H 1

/* Define to 1 if you have the `bzero' function. */
#define HAVE_BZERO 1

/* Define to 1 if your system has a working `chown' function. */
#define HAVE_CHOWN 1

/* Define to 1 if you have the `clock_gettime' function. */
#define HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have the <cpuid.h> header file. */
#define HAVE_CPUID_H 1

/* Define to 1 if you have the <ctype.h> header file. */
#define HAVE_CTYPE_H 1

/* Define to 1 if you have the declaration of `tzname', and to 0 if you don't.
   */
/* #undef HAVE_DECL_TZNAME */

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `dup2' function. */
#define HAVE_DUP2 1

/* Define to 1 if you have the <endian.h> header file. */
#define HAVE_ENDIAN_H 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <execinfo.h> header file. */
#define HAVE_EXECINFO_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `fdatasync' function. */
#define HAVE_FDATASYNC 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `ftruncate' function. */
#define HAVE_FTRUNCATE 1

/* Define to 1 if you have the `getcwd' function. */
#define HAVE_GETCWD 1

/* Define to 1 if you have the `gethostname' function. */
#define HAVE_GETHOSTNAME 1

/* Define to 1 if you have the <getopt.h> header file. */
#define HAVE_GETOPT_H 1

/* Define to 1 if you have the `getpagesize' function. */
#define HAVE_GETPAGESIZE 1

/* The system supports gettid */
/* #undef HAVE_GETTID */

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define to 1 if you have the <i386/limits.h> header file. */
/* #undef HAVE_I386_LIMITS_H */

/* Define to 1 if you have the <i386/types.h> header file. */
/* #undef HAVE_I386_TYPES_H */

/* Define to 1 if you have the `inet_ntoa' function. */
#define HAVE_INET_NTOA 1

/* Define to 1 if the system has the type `int16_t'. */
#define HAVE_INT16_T 1

/* Define to 1 if the system has the type `int32_t'. */
#define HAVE_INT32_T 1

/* Define to 1 if the system has the type `int64_t'. */
#define HAVE_INT64_T 1

/* Define to 1 if the system has the type `int8_t'. */
#define HAVE_INT8_T 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `c' library (-lc). */
#define HAVE_LIBC 1

/* Define to 1 if you have the `dnscore' library (-ldnscore). */
/* #undef HAVE_LIBDNSCORE */

/* Define to 1 if you have the `dnsdb' library (-ldnsdb). */
/* #undef HAVE_LIBDNSDB */

/* Define to 1 if you have the `dnslg' library (-ldnslg). */
/* #undef HAVE_LIBDNSLG */

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <linux/limits.h> header file. */
#define HAVE_LINUX_LIMITS_H 1

/* Define to 1 if you have the `localtime_r' function. */
#define HAVE_LOCALTIME_R 1

/* Define to 1 if the system has the type `long long'. */
#define HAVE_LONG_LONG 1

/* Define to 1 if you have the <machine/endian.h> header file. */
/* #undef HAVE_MACHINE_ENDIAN_H */

/* Define to 1 if you have the <mach/clock.h> header file. */
/* #undef HAVE_MACH_CLOCK_H */

/* Define to 1 if you have the <mach/mach.h> header file. */
/* #undef HAVE_MACH_MACH_H */

/* Define to 1 if your system has a GNU libc compatible `malloc' function, and
   to 0 otherwise. */
#define HAVE_MALLOC 1

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the `memchr' function. */
#define HAVE_MEMCHR 1

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the `mkdir' function. */
#define HAVE_MKDIR 1

/* Define to 1 if you have the `mkfifo' function. */
#define HAVE_MKFIFO 1

/* Define to 1 if you have a working `mmap' system call. */
#define HAVE_MMAP 1

/* Define to 1 if you have the `munmap' function. */
#define HAVE_MUNMAP 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet6/in6.h> header file. */
/* #undef HAVE_NETINET6_IN6_H */

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <netinet/tcp.h> header file. */
#define HAVE_NETINET_TCP_H 1

/* Define to 1 if you have the <net/ethernet.h> header file. */
#define HAVE_NET_ETHERNET_H 1

/* Define to 1 if you have the <pcap/pcap.h> header file. */
/* #undef HAVE_PCAP_PCAP_H */

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H 1

/* Define to 1 if you have the <ppc/limits.h> header file. */
/* #undef HAVE_PPC_LIMITS_H */

/* Define to 1 if you have the <pthread.h> header file. */
#define HAVE_PTHREAD_H 1

/* Define to 1 if the system has the type `ptrdiff_t'. */
#define HAVE_PTRDIFF_T 1

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 if your system has a GNU libc compatible `realloc' function,
   and to 0 otherwise. */
#define HAVE_REALLOC 1

/* Has recvmmsg system call */
#define HAVE_RECVMMSG 1

/* Define to 1 if you have the <sched.h> header file. */
#define HAVE_SCHED_H 1

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Has sendmmsg system call */
#define HAVE_SENDMMSG 1

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* Define to 1 if `stat' has the bug that it succeeds when given the
   zero-length file name argument. */
/* #undef HAVE_STAT_EMPTY_STRING_BUG */

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stdatomic.h> header file. */
#define HAVE_STDATOMIC_H 1

/* Define to 1 if you have the <stdbool.h> header file. */
#define HAVE_STDBOOL_H 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <stdnoreturn.h> header file. */
#define HAVE_STDNORETURN_H 1

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strncasecmp' function. */
#define HAVE_STRNCASECMP 1

/* Define to 1 if you have the `strrchr' function. */
#define HAVE_STRRCHR 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define to 1 if `tm_zone' is a member of `struct tm'. */
#define HAVE_STRUCT_TM_TM_ZONE 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/byteorder.h> header file. */
/* #undef HAVE_SYS_BYTEORDER_H */

/* Define to 1 if you have the <sys/cpuset.h> header file. */
/* #undef HAVE_SYS_CPUSET_H */

/* Define to 1 if you have the <sys/endian.h> header file. */
/* #undef HAVE_SYS_ENDIAN_H */

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/ipc.h> header file. */
#define HAVE_SYS_IPC_H 1

/* Define to 1 if you have the <sys/mman.h> header file. */
#define HAVE_SYS_MMAN_H 1

/* Define to 1 if you have the <sys/msg.h> header file. */
#define HAVE_SYS_MSG_H 1

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/prctl.h> header file. */
#define HAVE_SYS_PRCTL_H 1

/* Define to 1 if you have the <sys/resource.h> header file. */
#define HAVE_SYS_RESOURCE_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/syslimits.h> header file. */
/* #undef HAVE_SYS_SYSLIMITS_H */

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <tcl.h> header file. */
/* #undef HAVE_TCL_H */

/* Define to 1 if you have the `timegm' function. */
#define HAVE_TIMEGM 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if your `struct tm' has `tm_zone'. Deprecated, use
   `HAVE_STRUCT_TM_TM_ZONE' instead. */
#define HAVE_TM_ZONE 1

/* Define to 1 if you don't have `tm_zone' but do have the external array
   `tzname'. */
/* #undef HAVE_TZNAME */

/* Define to 1 if you have the <ucontext.h> header file. */
#define HAVE_UCONTEXT_H 1

/* Define to 1 if the system has the type `uint16_t'. */
#define HAVE_UINT16_T 1

/* Define to 1 if the system has the type `uint32_t'. */
#define HAVE_UINT32_T 1

/* Define to 1 if the system has the type `uint64_t'. */
#define HAVE_UINT64_T 1

/* Define to 1 if the system has the type `uint8_t'. */
#define HAVE_UINT8_T 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if the system has the type `u_char'. */
#define HAVE_U_CHAR 1

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* Define to 1 if the system has the type `_Bool'. */
#define HAVE__BOOL 1

/* BSD */
#define IS_BSD_FAMILY 0

/* OSX */
#define IS_DARWIN_OS 0

/* LINUX */
#define IS_LINUX_FAMILY 1

/* SOLARIS */
#define IS_SOLARIS_FAMILY 0

/* Define to 1 if `lstat' dereferences a symlink specified with a trailing
   slash. */
#define LSTAT_FOLLOWS_SLASHED_SYMLINK 1

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Define to 1 if your C compiler doesn't accept -c and -o together. */
/* #undef NO_MINUS_C_MINUS_O */

/* Name of package */
#define PACKAGE "yadifa"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "info@yadifa.eu"

/* Define to the full name of this package. */
#define PACKAGE_NAME "yadifa"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "yadifa 2.5.0-10188"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "yadifa"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.5.0-10188"

/* Define to the type of arg 1 for `select'. */
#define SELECT_TYPE_ARG1 int

/* Define to the type of args 2, 3 and 4 for `select'. */
#define SELECT_TYPE_ARG234 (fd_set *)

/* Define to the type of arg 5 for `select'. */
#define SELECT_TYPE_ARG5 (struct timeval *)

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Define to 1 if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Version number of package */
#define VERSION "2.5.0-10188"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define for Solaris 2.5.1 so the uint32_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT32_T */

/* Define for Solaris 2.5.1 so the uint64_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT64_T */

/* Define for Solaris 2.5.1 so the uint8_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT8_T */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to the type of a signed integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int16_t */

/* Define to the type of a signed integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int32_t */

/* Define to the type of a signed integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int64_t */

/* Define to the type of a signed integer type of width exactly 8 bits if such
   a type exists and the standard includes do not define it. */
/* #undef int8_t */

/* Define to rpl_malloc if the replacement function should be used. */
/* #undef malloc */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef mode_t */

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to rpl_realloc if the replacement function should be used. */
/* #undef realloc */

/* Define to the equivalent of the C99 'restrict' keyword, or to
   nothing if this is not supported.  Do not define if restrict is
   supported directly.  */
#define restrict __restrict
/* Work around a bug in Sun C++: it does not support _Restrict or
   __restrict__, even though the corresponding Sun C compiler ends up with
   "#define restrict _Restrict" or "#define restrict __restrict__" in the
   previous line.  Perhaps some future version of Sun C++ will work with
   restrict; if so, hopefully it defines __RESTRICT like Sun C does.  */
#if defined __SUNPRO_CC && !defined __RESTRICT
# define _Restrict
# define __restrict__
#endif

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef ssize_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Define to the type of an unsigned integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint16_t */

/* Define to the type of an unsigned integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint32_t */

/* Define to the type of an unsigned integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint64_t */

/* Define to the type of an unsigned integer type of width exactly 8 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint8_t */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */
