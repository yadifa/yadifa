dnl ############################################################################
dnl 
dnl Copyright (c) 2011, EURid. All rights reserved.
dnl The YADIFA TM software product is provided under the BSD 3-clause license:
dnl  
dnl Redistribution and use in source and binary forms, with or without 
dnl modification, are permitted provided that the following conditions
dnl are met:
dnl 
dnl        * Redistributions of source code must retain the above copyright 
dnl          notice, this list of conditions and the following disclaimer.
dnl        * Redistributions in binary form must reproduce the above copyright
dnl          notice, this list of conditions and the following disclaimer in
dnl          the documentation and/or other materials provided with the 
dnl          distribution.
dnl        * Neither the name of EURid nor the names of its contributors may be
dnl          used to endorse or promote products derived from this software 
dnl          without specific prior written permission.
dnl 
dnl THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
dnl AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
dnl IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
dnl ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
dnl LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
dnl CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
dnl SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
dnl INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
dnl CONTRACT, STRICT LIABILITY,OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
dnl ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
dnl POSSIBILITY OF SUCH DAMAGE.
dnl 
dnl ############################################################################



dnl Assume it is true
cpu_intel_compatible=1
icc_enabled=0

dnl handles Darwin libtoolize -> glibtoolize

AC_DEFUN([AC_DARWIN_LIBTOOL], [

case "$(uname -s)" in
    Darwin)
        alias libtoolize="glibtoolize"

        which libtool > /dev/null 2>&1
        if [[ $? -ne 0 ]]
        then
            which glibtool > /dev/null 2>&1
            if [[ $? -eq 0 ]]
            then
                alias libtool="glibtool"
            fi
        fi

        echo 'brol' | sed 's/brol/truc/' > /dev/null 2>&1
        if [[ $? -ne 0 ]]
        then
            alias sed="gsed"
        fi

        AC_MSG_RESULT([Darwin workaround])

        ;;
    *)
        AC_MSG_RESULT([nothing to do])
        ;;
esac

])

ac_os_workaround_done=0

AC_DEFUN([AC_OS_WORKAROUND], [

if [[ $ac_os_workaround_done -eq 0 ]]
then

ac_os_workaround_done=1

AC_MSG_CHECKING(what kind of OS this is)

is_darwin_os=0
is_bsd_family=0
is_solaris_family=0
is_linux_family=0

case "$(uname -s)" in
    Darwin)
        is_darwin_os=1
        is_bsd_family=1
        AC_MSG_RESULT([OSX])

        ;;
    FreeBSD)
        is_bsd_family=1

        AC_MSG_RESULT([BSD])
        ;;
    Linux)
        is_linux_family=1
        
        AC_MSG_RESULT([Linux])
        ;;
    SunOS)
        is_solaris_family=1

        AC_MSG_RESULT([SunOS])
        ;;
    *)

        AC_MSG_RESULT([not specifically supported])
        ;;
esac

if [[ "$is_darwin_os" = "" ]]
then
    echo "OS detection failed to give relevant results"
    exit 1;
fi

if [[ $is_darwin_os -ne 0 ]]
then
    AC_DEFINE_UNQUOTED(IS_DARWIN_OS, [1], [OSX])
    AM_CONDITIONAL([IS_DARWIN_OS], [true])
else
    AC_DEFINE_UNQUOTED(IS_DARWIN_OS, [0], [OSX])
    AM_CONDITIONAL([IS_DARWIN_OS], [false])
fi

AC_SUBST(IS_DARWIN_OS)

if [[ $is_bsd_family -ne 0 ]]
then
    AC_DEFINE_UNQUOTED(IS_BSD_FAMILY, [1], [BSD])
    AM_CONDITIONAL([IS_BSD_FAMILY], [true])
else
    AC_DEFINE_UNQUOTED(IS_BSD_FAMILY, [0], [BSD])
    AM_CONDITIONAL([IS_BSD_FAMILY], [false])
fi

AC_SUBST(IS_BSD_FAMILY)

if [[ $is_linux_family -ne 0 ]]
then
    AC_DEFINE_UNQUOTED(IS_LINUX_FAMILY, [1], [LINUX])
    AM_CONDITIONAL([IS_LINUX_FAMILY], [true])
else
    AC_DEFINE_UNQUOTED(IS_LINUX_FAMILY, [0], [LINUX])
    AM_CONDITIONAL([IS_LINUX_FAMILY], [false])
fi

AC_SUBST(IS_LINUX_FAMILY)

if [[ $is_solaris_family -ne 0 ]]
then
    AC_DEFINE_UNQUOTED(IS_SOLARIS_FAMILY, [1], [SOLARIS])
    AM_CONDITIONAL([IS_SOLARIS_FAMILY], [true])
else
    AC_DEFINE_UNQUOTED(IS_SOLARIS_FAMILY, [0], [SOLARIS])
    AM_CONDITIONAL([IS_SOLARIS_FAMILY], [false])
fi

AC_SUBST(IS_SOLARIS_FAMILY)

fi

])

dnl Compiler support

dnl ####################################################
dnl
dnl COMPILER SUPPORT
dnl
dnl ####################################################

AC_DEFUN([AC_COMPILER_SUPPORTS], [
#
# AC_COMPILER_SUPPORTS $1
#
# CHECKING
AC_MSG_CHECKING(if compiler supports [$1])
if [[ "$CC" = "" ]]
then
    AC_MSG_RESULT("[compiler not set yet, fix this]")
    exit 1
fi
cat > test-gcc-$2.c <<_ACEOF
#include "confdefs.h"
#if HAVE_STDLIB_H
#include<stdlib.h>
#endif
int main(int argc,char** argv)
{
    (void)argc;
    (void)argv;
    puts("Hello World!");
    return 0;
}
_ACEOF
$CC $1 test-gcc-$2.c -o test-gcc-$2 > /dev/null 2>&1
if [[ $? -ne 0 ]]
then
    AM_CONDITIONAL(HAS_CC_$2, [false])
    AC_MSG_RESULT([no])
else
    AM_CONDITIONAL(HAS_CC_$2, [true])
    AC_MSG_RESULT([yes])
fi
AC_SUBST(HAS_CC_$2)
rm -rf test-gcc-$2*
])

dnl Memory aligment issues (T1000)

AC_DEFUN([AC_MEMALIGN_CHECK], [

AC_MSG_CHECKING([checking if memory accesses must be size-aligned])
AM_CONDITIONAL([HAS_MEMALIGN_ISSUES], [false])
cat > memalign_issues_test.c <<_ACEOF
#include "confdefs.h"
#if HAVE_STDLIB_H
#include<stdlib.h>
#endif

int main(int argc, char** argv)
{
	char* p = (char*)malloc(8);
	p++;
	int* intp= (int*)p;
	*intp=1;
	return 0;
}
_ACEOF
${CC} ${CFLAGS} memalign_issues_test.c -o memalign_issues_test > /dev/null 2>&1
has_memalign_issues=0
./memalign_issues_test > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
	has_memalign_issues=1
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi
rm -f memalign_issues_test memalign_issues_test.c
AM_CONDITIONAL([HAS_MEMALIGN_ISSUES], [test $has_memalign_issues])
AC_DEFINE_UNQUOTED([HAS_MEMALIGN_ISSUES], [$has_memalign_issues], [Define this to enable slow but safe unaligned memory accesses])

])

dnl ####################################################

dnl Architecture

AC_DEFUN([AC_CPU_CHECK], [

AC_DEFINE_UNQUOTED([DEFAULT_ASSUMED_CPU_COUNT], [2], [number of harware core if the auto-detect fails])

cpu_intel_compatible=1

AM_CONDITIONAL([HAS_CPU_NIAGARA], [false])
AM_CONDITIONAL([HAS_CPU_AMDINTEL], [false])

AC_MSG_CHECKING([checking for the CPU options])
CPU_UNKNOWN=1

CFLAGS3264=
case "$(uname -i 2>/dev/null)" in
	SUNW,SPARC-Enterprise-T1000)
		AC_DEFINE_UNQUOTED([HAS_CPU_NIAGARA], [1], [T1000 has a Niagara cpu])
		AM_CONDITIONAL([HAS_CPU_NIAGARA], [true])
		AC_MSG_RESULT([UtrasparcT1])
		CFLAGS3264=-m64
		CPU_UNKNOWN=0
		cpu_intel_compatible=0
		;;
	*)
		;;
esac

case "$(uname -m)" in
	x86_64)
		AC_DEFINE_UNQUOTED([HAS_CPU_AMDINTEL], [1], [i386, Athlon, Opteron, Core2, i3, i5, i7, ...])
		AM_CONDITIONAL([HAS_CPU_AMDINTEL], [true])
		AC_MSG_RESULT([AMD/Intel])
		CFLAGS3264=-m64
		CPU_UNKNOWN=0
		cpu_intel_compatible=1
		;;
	*)
		;;
esac

case "${CPU_UNKNOWN}" in
	1)
		AC_MSG_RESULT([generic])
		;;
	0)
		;;
esac

if [[ "$is_solaris_family" = "" ]]
then
    echo "OS must be detected first"
    exit 1
fi

if [[ $is_solaris_family -eq 1 ]]
then
    echo "Solaris ..."

    AC_MSG_CHECKING([if either force 32 or 64 bits is enabled])
    if [[ ! "$enable_force32bits" = "yes" ]]
    then
        if [[ ! "$enable_force64bits" = "yes" ]]
        then
            AC_MSG_RESULT([no, forcing 64 bits])
            enable_force64bits="yes"
        else
            AC_MSG_RESULT([yes])
        fi
    else
        AC_MSG_RESULT([yes])
    fi
else
    echo "Not Solaris ..."
fi

echo "Force ..."

dnl Forced 32/64 bits architecture
AC_MSG_CHECKING([if force 32 bits is enabled])
AM_CONDITIONAL([FORCE32BITS], [false])
AC_ARG_ENABLE(force32bits, AS_HELP_STRING([--enable-force32bits], [Forces a 32 bits binary compilation]), [enable_force32bits=yes], [enable_force32bits=no])
AC_MSG_RESULT($enable_force32bits)
case "$enable_force32bits" in
    yes)
        CFLAGS3264=-m32
        AM_CONDITIONAL([FORCE32BITS], [test $enable_force32bits = yes])
        ;;
    *)
        ;;
esac

AC_MSG_CHECKING([if force 64 bits is enabled])
AM_CONDITIONAL([FORCE64BITS], [false])
AC_ARG_ENABLE(force64bits, AS_HELP_STRING([--enable-force64bits], [Forces a 64 bits binary compilation]), [enable_force64bits=yes], [enable_force64bits=no])
AC_MSG_RESULT($enable_force64bits)
case "$enable_force64bits" in
    yes)
        CFLAGS3264=-m64
        AM_CONDITIONAL([FORCE64BITS], [test $enable_force64bits = yes])

        if [[ "$enable_force32" = "yes" ]]
        then
            echo "cannot do both --enable-force32bits and --enable-force64bits at the same time"
            exit 1
        fi

        ;;
    *)
        ;;
esac

])

dnl Endianness


#
AC_DEFUN([AC_ENDIANNESS], [
#
# AC_ENDIANNESS
#
# CHECKING
AC_MSG_CHECKING([endianness: ])
if [[ "$CC" = "" ]]
then
    AC_MSG_RESULT("[compiler not set yet, fix this]")
    exit 1
fi
cat > test-gcc-endian.c <<_ACEOF
#include "confdefs.h"
#if HAVE_STDLIB_H
#include<stdlib.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if defined __FreeBSD__
#if HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#elif defined __APPLE__
#if HAVE_MACHINE_ENDIAN_H
#include <machine/endian.h>
#endif
#elif defined __sun
#if HAVE_SYS_BYTEORDER_H
#include <sys/byteorder.h>
#endif
#else
#if HAVE_ENDIAN_H
#include <endian.h>
#endif
#if HAVE_BYTESWAP_H
#include <byteswap.h>
#endif
#endif
static int magic = 0x00525545;
int main(int argc,char** argv)
{
    (void)argc;
    (void)argv;
    int pp = -1;
    int c = -1;

#if defined _BIG_ENDIAN
    pp = 2;
#elif defined _LITTLE_ENDIAN
    pp = 1;
#endif

#ifdef __BYTE_ORDER
#if __BYTE_ORDER == __LITTLE_ENDIAN
    pp = 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
    pp = 2;
#endif
//    printf("__BYTE_ORDER=%x\n", __BYTE_ORDER);
#endif

#ifdef _BYTE_ORDER
#if _BYTE_ORDER == _LITTLE_ENDIAN
    pp = 1;
#elif _BYTE_ORDER == _BIG_ENDIAN
    pp = 2;
#endif
    printf("_BYTE_ORDER=%x\n", _BYTE_ORDER);
#endif

#ifdef BYTE_ORDER
#if BYTE_ORDER == LITTLE_ENDIAN
    pp = 1;
#elif BYTE_ORDER == BIG_ENDIAN
    pp = 2;
#endif
//    printf("BYTE_ORDER=%x\n", BYTE_ORDER);
#endif
#
#ifdef WORDS_BIGENDIAN
    
//    printf("WORDS_BIGENDIAN=%x\n", WORDS_BIGENDIAN);

    if(pp == 1) // could be -1 or 2
    {
        pp = -2;
    }
    else
    {
        pp = 2;
    }
#endif

    char *p = (char*)&magic;
    if(*p == '\0')
    {
        c = 2;
    }
    else if(*p == 'E')
    {
        c = 1;
    }

    if((pp < 0) || (c < 0))
    {
       printf("*** WARNING *** preprocessor says %i, real test says %i *** WARNING ***\n", pp, c);
    }

    if(c == pp)
    {
        return c;
    }
    else
    {
        return -1;
    }
}
_ACEOF
$CC $1 test-gcc-endian.c -o test-gcc-endian > /dev/null 2>&1
if [[ $? -ne 0 ]]
then
    AC_MSG_RESULT("[failed to compile test]")
    exit 1
fi
./test-gcc-endian
if [[ $? -eq 1 ]]
then
    AM_CONDITIONAL(HAS_LITTLE_ENDIAN, [true])
    AM_CONDITIONAL(HAS_BIG_ENDIAN, [false])
    AC_MSG_RESULT([little])
else
    AM_CONDITIONAL(HAS_LITTLE_ENDIAN, [false])
    AM_CONDITIONAL(HAS_BIG_ENDIAN, [true])
    AC_MSG_RESULT([big])
fi
AC_SUBST(HAS_LITTLE_ENDIAN)
AC_SUBST(HAS_BIG_ENDIAN)
rm -f test-gcc-endian.c* test-gcc-endian
])

dnl Compiler

AC_DEFUN([AC_COMPILER_CHECK], [

AC_OS_WORKAROUND

AC_CPU_CHECK

cat /etc/redhat-version > /dev/null 2>&1
if [[ $? -eq 0 ]]
then
    is_redhat_family=1
else
    is_redhat_family=0
fi

CFLAGS=

VERSION_OPT=--version
$CC --version > /dev/null 2>&1
if [[ $? -ne 0 ]]
then
    $CC -V > /dev/null 2>&1
    if [[ $? -ne 0 ]]
    then
        CCVER='0.0'
        CCNAME='unknown'
        VERSION_OPT=''
    else
        VERSION_OPT='-V'
    fi
fi

if [[ ! "$VERSION_OPT" = "" ]]
then

dnl $CC --version 2>&1
dnl $CC $VERSION_OPT 2>&1|head -1
dnl $CC $VERSION_OPT 2>&1|head -1|sed 's/[[^0-9.]]*\([[0-9.]]*\).*/\1/'
dnl $CC $VERSION_OPT 2>&1|head -1|sed -e 's/.*clang.*/clang/' -e 's/.*gcc.*/gcc/' -e 's/.*icc.*/icc/' -e 's/.*Sun C.*/Sun C/'|tr A-Z a-z

CCVER=$($CC $VERSION_OPT 2>&1|head -1|sed 's/[[^0-9.]]*\([[0-9.]]*\).*/\1/')
dnl echo $CC $VERSION_OPT "2>&1" |head -1|sed 's/[[^0-9.]]*\([[0-9.]]*\).*/\1/'
if [[ "$CCVER" = "" ]]
then
	CCVER='0.0'
fi

CCNAME=$($CC $VERSION_OPT 2>&1|head -1|sed -e 's/.*clang.*/clang/' -e 's/.*gcc.*/gcc/' -e 's/.*icc.*/icc/' -e 's/.*Sun C.*/Sun C/'|tr A-Z a-z)
dnl echo $CC $VERSION_OPT "2>&1"|head -1|sed -e 's/.*clang.*/clang/' -e 's/.*gcc.*/gcc/' -e 's/.*icc.*/icc/' -e 's/.*Sun C.*/Sun C/'|tr A-Z a-z
if [[ "$CCNAME" = "" ]]
then
	CCNAME='unknown'
fi

else

CCVER='0.0'
CCNAME='unknown'

fi # version opt

CCMAJOR=$(echo $CCVER | sed 's/\./ /g' | awk '{ print @S|@1}')
CCMINOR=$(echo $CCVER | sed 's/\./ /g' | awk '{ print @S|@2}')

dnl echo "$CC $VERSION_OPT : CCNAME='$CCNAME' CCVER='$CCVER' CCMAJOR='$CCMAJOR' CCMINOR='$CCMINOR'"

if [[ "$CCMAJOR" = "" ]]
then
	CCMAJOR=0
fi

if [[ "$CCMINOR" = "" ]]
then
	CCMINOR=0
fi

if [[ "$CCNAME" = "gcc" ]]
then
	CCOPTIMISATIONFLAGS=-O3

	if [[ $CCMAJOR -lt 4 ]]
	then
		CCOPTIMISATIONFLAGS=-O0

		echo "WARNING: GCC < 4.0 has optimisations issues with YADIFA."
		sleep 1

	elif [[ $CCMAJOR -eq 4 ]]
	then
		if [[ $CCMINOR -lt 6 ]]
		then
			CCOPTIMISATIONFLAGS=-O0

			echo "WARNING: GCC before 4.6 have optimisation issues with YADIFA."
			sleep 1

		elif [[ $CCMINOR -eq 6 ]]
		then
			CCOPTIMISATIONFLAGS=-O2
		else
			# hopefully after 4.6 the issue is fixed ...
			CCOPTIMISATIONFLAGS=-O3
		fi
	fi

    AM_CONDITIONAL([USES_ICC], [false])
    AM_CONDITIONAL([USES_GCC], [true])
    AM_CONDITIONAL([USES_CLANG], [false])
    AM_CONDITIONAL([USES_SUNC], [false])
    AM_CONDITIONAL([USES_UNKNOWN], [false])

elif [[ "$CCNAME" = "icc" ]]
then
	echo "ICC"

	CCOPTIMISATIONFLAGS=-O3

    AM_CONDITIONAL([USES_ICC], [true])
    AM_CONDITIONAL([USES_GCC], [false])
    AM_CONDITIONAL([USES_CLANG], [false])
    AM_CONDITIONAL([USES_SUNC], [false])
    AM_CONDITIONAL([USES_UNKNOWN], [false])

	AR=xiar

elif [[ "$CCNAME" = "clang" ]]
then
	echo "CLANG"

	CCOPTIMISATIONFLAGS=-O3
	
    AM_CONDITIONAL([USES_ICC], [false])
    AM_CONDITIONAL([USES_GCC], [false])
    AM_CONDITIONAL([USES_CLANG], [true])
    AM_CONDITIONAL([USES_SUNC], [false])
    AM_CONDITIONAL([USES_UNKNOWN], [false])
elif [[ "$CCNAME" = "Sun C" ]]
then
    echo "Sun C"

    CCOPTIMISATIONFLAGS=-xO5

	AM_CONDITIONAL([USES_ICC], [false])
    AM_CONDITIONAL([USES_GCC], [false])
    AM_CONDITIONAL([USES_CLANG], [false])	
    AM_CONDITIONAL([USES_SUNC], [true])
    AM_CONDITIONAL([USES_UNKNOWN], [false])

else
	echo "unsupported compiler"

	CCNAME=$CC

	CCOPTIMISATIONFLAGS=-O2
	
	AM_CONDITIONAL([USES_ICC], [false])
    AM_CONDITIONAL([USES_GCC], [false])
    AM_CONDITIONAL([USES_CLANG], [false])	
    AM_CONDITIONAL([USES_SUNC], [false])
    AM_CONDITIONAL([USES_UNKNOWN], [true])
fi

#
# We've been told RedHat does not like -O3 at all, so ...
#

if [[ $is_redhat_family -ne 0 ]]
then
    if [[ "$CCOPTIMISATIONFLAGS " eq "-O3" ]]
    then
        CCOPTIMISATIONFLAGS=-O2
    fi
fi

echo "detected compiler is $CCNAME $CCMAJOR $CCMINOR"

AC_SUBST(CCOPTIMISATIONFLAGS, $CCOPTIMISATIONFLAGS)

if [[ $cpu_intel_compatible -eq 0 ]]
then
	if [[ $icc_enabled -ne 0 ]]
	then
		echo "ERROR: cannot enable ICC with CPU other than x86 or amd64"
		exit 1
	fi
fi

AC_COMPILER_SUPPORTS([-mtune=native],TUNE_NATIVE)
AC_COMPILER_SUPPORTS([-fno-ident],NO_IDENT)
AC_COMPILER_SUPPORTS([-ansi],ANSI)
AC_COMPILER_SUPPORTS([-ansi-alias],ANSI_ALIAS)
AC_COMPILER_SUPPORTS([-pedantic],PEDANTIC)
AC_COMPILER_SUPPORTS([-std=gnu99],STD_GNU99)
AC_COMPILER_SUPPORTS([-std=c99],STD_C99)
AC_COMPILER_SUPPORTS([-xc99],XC99)
AC_COMPILER_SUPPORTS([-m32],M32)
AC_COMPILER_SUPPORTS([-m64],M64)
AC_COMPILER_SUPPORTS([-Wall],WALL)
AC_COMPILER_SUPPORTS([-g],G)
AC_COMPILER_SUPPORTS([-g3],G3)
AC_COMPILER_SUPPORTS([-gdwarf-2],DWARF2)
AC_COMPILER_SUPPORTS([-gdwarf-3],DWARF3)
AC_COMPILER_SUPPORTS([-gdwarf-4],DWARF4)
AC_COMPILER_SUPPORTS([-fstack-protector --param=ssp-buffer-size=4],STACK_PROTECTOR)
AC_COMPILER_SUPPORTS([-fexceptions],EXCEPTIONS)
AC_COMPILER_SUPPORTS([-Werror=missing-field-initializers],MISSING_FIELD_INITIALIZERS)
AC_COMPILER_SUPPORTS([-fsanitize=address],SANITIZE_ADDRESS)
AC_COMPILER_SUPPORTS([-fno-omit-frame-pointer],NO_OMIT_FRAME_POINTER)
AC_COMPILER_SUPPORTS([-faddress-sanitizer],ADDRESS_SANITIZER_CHECK)
AC_COMPILER_SUPPORTS([-fcatch_undefined_behavior],CATCH_UNDEFINED_BEHAVIOR)
AC_COMPILER_SUPPORTS([-rdynamic],RDYNAMIC)

AC_MEMALIGN_CHECK

AC_ENDIANNESS
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([stdio.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([endian.h])
AC_CHECK_HEADERS([syslog.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([pthread.h])
AC_CHECK_HEADERS([linux/limits.h sys/syslimits.h i386/limits.h ppc/limits.h])
AC_CHECK_HEADERS([byteswap.h])
AC_CHECK_HEADERS([machine/endian.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([sys/stat.h])
AC_CHECK_HEADERS([sys/endian.h])
AC_CHECK_HEADERS([sys/byteorder.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([netinet6/in6.h])

])

dnl pthread spinlock support

AC_DEFUN([AC_PTHREAD_SPINLOCK_CHECK], [

AC_MSG_CHECKING([checking for pthread_spin_init])

AC_TRY_LINK([#include<pthread.h>],[pthread_spinlock_t lock; pthread_spin_init(&lock, 0);],[AC_DEFINE_UNQUOTED([HAS_PTHREAD_SPINLOCK], [1], [The system supports spinlocks]) echo yes],[echo no]);

])

dnl pthread_setname_np support

AC_DEFUN([AC_PTHREAD_SETNAME_NP_CHECK], [

AC_MSG_CHECKING([checking for pthread_setname_np])

AC_TRY_LINK([#define __USE_GNU
#include<pthread.h>],[pthread_setname_np(pthread_self(), "myname");],[AC_DEFINE_UNQUOTED([HAS_PTHREAD_SETNAME_NP], [1], [The system supports thread names]) echo yes],[echo no]);

])

dnl gethostbyname inet_pton inet_ntop ... (Solaris requires a lib)

AC_DEFUN([AC_GETHOSTBYNAME_CHECK], [

AC_MSG_CHECKING([checking for gethostbyname inet_pton inet_ntop])
AC_MSG_CHECKING([if gethostbyname requires some lib])
AC_TRY_LINK([#include<netdb.h>],[struct hostent *host = gethostbyname("www.yadifa.eu.");],
    [
        AC_MSG_RESULT([no])
    ],
    [
        AC_MSG_CHECKING([if gethostbyname requires nsl])
        OLD_LDFLAGS="$LDFLAGS"
        LDFLAGS="-lnsl $LDFLAGS"
        AC_TRY_LINK([#include<netdb.h>],[struct hostent *host = gethostbyname("www.yadifa.eu.");],
            [
                AC_MSG_RESULT([yes])
            ],
            [
                LDFLAGS="$OLDLDFLAGS"
                AC_MSG_RESULT([no, and I could not find it ...])
                exit 1;   
            ])
    ])
])

dnl pthread_setname_np support

AC_DEFUN([AC_PTHREAD_SETNAME_NP_CHECK], [

AC_MSG_CHECKING([checking for pthread_setname_np])

AC_TRY_LINK([#define __USE_GNU
#include<pthread.h>],[pthread_setname_np(pthread_self(), "myname");],[AC_DEFINE_UNQUOTED([HAS_PTHREAD_SETNAME_NP], [1], [The system supports thread names]) echo yes],[echo no]);

])



dnl LTO

AC_DEFUN([AC_CHECK_LTO], [

AC_MSG_CHECKING(if LTO has been enabled)
AC_ARG_ENABLE(lto, AS_HELP_STRING([--enable-lto], [Enable LTO support, requires gold linker]), [enable_lto=yes], [enable_lto=no])
AC_MSG_RESULT($enable_lto)
case "$enable_lto" in
    yes)

	type -p gold

	if [[ $? -ne 0 ]]
	then
		AC_MSG_RESULT([WARNING: 'gold' not found])
		sleep 1
	fi

	if [[ ! "$LD" = "" ]]
	then
		$LD -v |grep -i gold > /dev/null 2>&1

		if [[ $? -ne 0 ]]
		then
			AC_MSG_RESULT([WARNING: LTO enabled but LD ($LD) is not gold])
			sleep 1
		fi
	else
		AC_MSG_RESULT([LD not defined])
	fi
	
	AM_CONDITIONAL(HAS_LTO_SUPPORT, [true])
        ;;
    no|*)
	AM_CONDITIONAL(HAS_LTO_SUPPORT, [false])
        ;;
esac

])

AC_DEFUN([AC_SOCKADDR_SA_LEN_CHECK],
[
dnl Check for sa_len field
AC_MSG_CHECKING([if sockaddr has a sa_len field])
cat > sockaddr_sa_len.c <<_ACEOF
#include "confdefs.h"
#if HAVE_STDLIB_H
#include<stdlib.h>
#endif
#if HAVE_SYS_TYPES_H
#include<sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include<sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include<netinet/in.h>
#endif
#if HAVE_NETINET6_IN6_H
#include<netinet6/in6.h>
#endif
int main(int argc, char** argv)
{
    struct sockaddr sa;
    sa.sa_len = 4;
}
_ACEOF
has_sockaddr_sa_len=0
${CC} ${CFLAGS} sockaddr_sa_len.c > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    has_sockaddr_sa_len=1;
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi
rm -f sockaddr_sa_len.c sockaddr_sa_len
AM_CONDITIONAL([HAS_SOCKADDR_SA_LEN], [test $has_sockaddr_sa_len = yes])
AC_DEFINE_UNQUOTED([HAS_SOCKADDR_SA_LEN], [$has_sockaddr_sa_len], [The sockaddr struct has an sa_len field])
])

AC_DEFUN([AC_SOCKADDR_IN_SIN_LEN_CHECK],
[
dnl Check for sin_len field
AC_MSG_CHECKING([if sockaddr_in has a sin_len field])
cat > sockaddr_in_sin_len.c <<_ACEOF
#include "confdefs.h"
#if HAVE_STDLIB_H
#include<stdlib.h>
#endif
#if HAVE_SYS_TYPES_H
#include<sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include<sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include<netinet/in.h>
#endif
#if HAVE_NETINET6_IN6_H
#include<netinet6/in6.h>
#endif
int main(int argc, char** argv)
{
    struct sockaddr_in sa;
    sa.sin_len = sizeof(struct sockaddr_in);
}
_ACEOF
has_sockaddr_in_sin_len=0
${CC} ${CFLAGS} sockaddr_in_sin_len.c > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    has_sockaddr_in_sin_len=1;
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi
rm -f sockaddr_in_sin_len.c sockaddr_in_sin_len
AM_CONDITIONAL([HAS_SOCKADDR_IN_SIN_LEN], [test $has_sockaddr_in_sin_len = yes])
AC_DEFINE_UNQUOTED([HAS_SOCKADDR_IN_SIN_LEN], [$has_sockaddr_in_sin_len], [The sockaddr_in struct has an sin_len field])
])

AC_DEFUN([AC_SOCKADDR_IN6_SIN6_LEN_CHECK],
[
dnl Check for sin6_len field
AC_MSG_CHECKING([if sockaddr_in6 has a sin6_len field])
cat > sockaddr_in6_sin6_len.c <<_ACEOF
#include "confdefs.h"
#if HAVE_STDLIB_H
#include<stdlib.h>
#endif
#if HAVE_SYS_TYPES_H
#include<sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include<sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include<netinet/in.h>
#endif
#if HAVE_NETINET6_IN6_H
#include<netinet6/in6.h>
#endif
int main(int argc, char** argv)
{
    struct sockaddr_in6 sa;
    sa.sin6_len = sizeof(struct sockaddr_in6);
}
_ACEOF
has_sockaddr_in6_sin6_len=0
${CC} ${CFLAGS} sockaddr_in6_sin6_len.c > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    has_sockaddr_in6_sin6_len=1;
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi
rm -f sockaddr_in6_sin6_len.c sockaddr_in6_sin6_len
AM_CONDITIONAL([HAS_SOCKADDR_IN6_SIN6_LEN], [test $has_sockaddr_in6_sin6_len = yes])
AC_DEFINE_UNQUOTED([HAS_SOCKADDR_IN6_SIN6_LEN], [$has_sockaddr_in6_sin6_len], [The sockaddr_in6 struct has an sin6_len field])
])

AC_DEFUN([AC_EURID_SUMMARY], [

cat <<EOF
	CC		:	$CC
	CPP		:	$CPP
	LD		:	$LD
	AR		:	$AR

	CFLAGS		:	$CFLAGS
	CPPFLAGS	:	$CPPFLAGS
	LDFLAGS		:	$LDFLAGS

	MEMALIGN ISSUES	:	$has_memalign_issues
	32/64		:	$CFLAGS3264
	LTO		:	$enable_lto
    log :   $logdir
EOF
])

AC_DEFUN([AC_MAKE_BUILDINFO], [
make buildinfo.h
])



