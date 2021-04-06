dnl ############################################################################
dnl
dnl Copyright (c) 2011-2021, EURid vzw. All rights reserved.
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

dnl ####################################################
dnl
dnl AC_HAS_ENABLE(low-case --enable-*, up-case HAS_*, text, config.h text,ifyes,ifno)
dnl
dnl This macro creates a parameter with
dnl _ a shell-variable-name that will be used for --enable-VARIABLENAME
dnl     '_' of the variable name will be replaced by a '-' in the command
dnl
dnl _ SOMETHINGSOMETHING that will be transformed into a HAS_SOMETHINGSOMETHING define (both C & Makefile)
dnl
dnl _ A text to be put next to the --enable-this line in the --help
dnl
dnl _ An optional text to be put in the config.h output file.  If not set or empty, the --help text is used
dnl
dnl _ A block to execute if the option is enabled (--enable-this)
dnl
dnl _ A block to execute if the option is disabled (--disable-this or not set)
dnl
dnl ####################################################

AC_DEFUN([AC_HAS_ENABLE], [
#
# AC_HAS_ENABLE $1
#
# CHECKING
AC_MSG_CHECKING(if [$2] has been enabled)
# ARG ENABLE
AC_ARG_ENABLE([$1], AS_HELP_STRING([--enable-[translit($1,[_],[-])]], [Enable $3]))
dnl # MSG RESULT
dnl AC_MSG_RESULT($enable_[$1])
dnl echo "enabled: '$enable_[$1]'"
# CASE
case "y$enable_[$1]" in
        yyes)
# DEFINE Y
                AC_DEFINE_UNQUOTED([HAS_$2], [1], ifelse($4,,[$3 enabled.],$4))
# CONDITIONAL Y
        	enable_[$1]="yes"
	        AC_MSG_RESULT([yes])
# IF YES
        	$5
# ENDIF
                ;;
        yno|y|*)
# DEFINE N
                AC_DEFINE_UNQUOTED([HAS_$2], [0], ifelse($4,,[$3 disabled.],$4))
# CONDITIONAL N
        	enable_[$1]="no"
	        AC_MSG_RESULT([no])
# IF NO
        	$6
# ENDIF
        ;;
esac
# CONDITIONAL
AM_CONDITIONAL([HAS_$2], [test y$enable_[$1] = yyes])
# SUBST
AC_SUBST(HAS_$2)
# AC_HAS_ENABLE $1 DONE
])

dnl ####################################################
dnl
dnl AC_FORCE_ENABLE(var)
dnl
dnl Forces --enable-var
dnl
dnl ####################################################

AC_DEFUN([AC_FORCE_ENABLE], [
#
# AC_FORCE_ENABLE $1
#
enable_[$1]=yes
AC_DEFINE_UNQUOTED([HAS_$2], [1], [$1 = $2 enabled])
AM_CONDITIONAL([HAS_$2], [test y$enable_[$1] = yyes])
AC_SUBST(HAS_$2)
# AC_FORCE_ENABLE $1 DONE
])

dnl ####################################################
dnl
dnl AC_HAS_DISABLE(low-case --disable-*, up-case HAS_*, text, config.h text,ifyes,ifno)
dnl
dnl This macro creates a parameter with
dnl _ a shell-variable-name that will be used for --disable-VARIABLENAME
dnl     '_' of the variable name will be replaced by a '-' in the command
dnl
dnl _ SOMETHINGSOMETHING that will be transformed into a HAS_SOMETHINGSOMETHING define (both C & Makefile)
dnl
dnl _ A text to be put next to the --disable-this line in the --help
dnl
dnl _ An optional text to be put in the config.h output file.  If not set or empty, the --help text is used
dnl
dnl _ A block to execute if the option is enabled (--enable-this or not set)
dnl
dnl _ A block to execute if the option is disabled (--disable-this)
dnl
dnl ####################################################

AC_DEFUN([AC_HAS_DISABLE], [
#
# AC_HAS_DISABLE $1
#
# CHECKING
AC_MSG_CHECKING(if [$2] has been disabled)
# ARG ENABLE
AC_ARG_ENABLE([$1], AS_HELP_STRING([--disable-[translit($1,[_],[-])]],[Disable $3]))
# MSG RESULT
dnl echo "enabled: '$enable_[$1]'"
# CASE
case "y$enable_[$1]" in
        yyes|y)
# DEFINE Y
                AC_DEFINE_UNQUOTED([HAS_$2], [1], ifelse($4,,[$3 enabled.],$4))
# CONDITIONAL Y
                enable_[$1]=yes
                AC_MSG_RESULT([no])
# IF YES
                $5
# ENDIF
                ;;
        yno|*)
# DEFINE N
                AC_DEFINE_UNQUOTED([HAS_$2], [0], ifelse($4,,[$3 disabled.],$4))
# CONDITIONAL N
                enable_[$1]=no
                AC_MSG_RESULT([yes])
# IF NO
                $6
# ENDIF
        ;;
esac
# CONDITIONAL
AM_CONDITIONAL([HAS_$2], [test y$enable_[$1] != yno])
# SUBST
AC_SUBST(HAS_$2)
# AC_HAS_DISABLE $1 DONE
])

dnl ####################################################
dnl
dnl AC_HAS_WITH(low-case --with-*, up-case HAS_*, text, config.h text,ifyes,ifno)
dnl
dnl This macro creates a parameter with
dnl _ a shell-variable-name that will be used for --with-VARIABLENAME
dnl     '_' of the variable name will be replaced by a '-' in the command
dnl
dnl _ SOMETHINGSOMETHING that will be transformed into a HAS_SOMETHINGSOMETHING define (both C & Makefile)
dnl
dnl _ A text to be put next to the --with-this line in the --help
dnl
dnl _ An optional text to be put in the config.h output file.  If not set or empty, the --help text is used
dnl
dnl _ A block to execute if the option is withd (--with-this)
dnl
dnl _ A block to execute if the option is withoutd (--without-this or not set)
dnl
dnl ####################################################

AC_DEFUN([AC_HAS_WITH], [
#
# AC_HAS_WITH $1
#
# CHECKING
AC_MSG_CHECKING(if [translit($1,[_A-Z],[ a-z])] has been given)
# ARG WITH
AC_ARG_WITH([$1], AS_HELP_STRING([--with-[translit($1,[_],[-])]], [With $3]),
[
# DEFINE Y
        AC_DEFINE_UNQUOTED([HAS_$2], [1], ifelse($4,,[With $3.],$4))
# CONDITIONAL Y
        AC_DEFINE_UNQUOTED([HAS_WITH_$2], "$with_[$1]" // $withval, ifelse($4,,[build $3.],$4))
        with_[$1]="yes"
        AC_MSG_RESULT([yes])
# IF YES
        $5
# ENDIF
]
,
[
# DEFINE N
        AC_DEFINE_UNQUOTED([HAS_$2], [0], ifelse($4,,[Without $3.],$4))
# CONDITIONAL N
        with_[$1]="no"
        AC_MSG_RESULT([no])
# IF NO
        $6
# ENDIF
])
# CONDITIONAL
AM_CONDITIONAL([HAS_$2], [test "y$with_[$1]" == "yyes"])
# SUBST
AC_SUBST([HAS_$2])
# AC_HAS_WITH $1 DONE
])

dnl ####################################################
dnl
dnl AC_HAS_WITHOUT(low-case --without-*, up-case HAS_*, text, config.h text,ifyes,ifno)
dnl
dnl This macro creates a parameter with
dnl _ a shell-variable-name that will be used for --without-VARIABLENAME
dnl     '_' of the variable name will be replaced by a '-' in the command
dnl
dnl _ SOMETHINGSOMETHING that will be transformed into a HAS_SOMETHINGSOMETHING define (both C & Makefile)
dnl
dnl _ A text to be put next to the --without-this line in the --help
dnl
dnl _ An optional text to be put in the config.h output file.  If not set or empty, the --help text is used
dnl
dnl _ A block to execute if the option is withd (--with-this or not set)
dnl
dnl _ A block to execute if the option is withoutd (--without-this)
dnl
dnl ####################################################

AC_DEFUN([AC_HAS_WITHOUT], [
#
# AC_HAS_WITHOUT $1
#
# CHECKING
AC_MSG_CHECKING(if [$1] has to be build)
# ARG WITH
AC_ARG_WITH([$1], AS_HELP_STRING([--without-[translit($1,[_],[-])]],[Without $3]))

# MSG RESULT
case "y$with_[$1]" in
    yyes|y)
# DEFINE Y
                AC_DEFINE_UNQUOTED([HAS_$2], [1], ifelse($4,,[With $3.],$4))
# CONDITIONAL Y
                with_[$1]=yes
                AC_MSG_RESULT([yes])
# IF YES
                $5
# ENDIF
        ;;

    yno|*)
# DEFINE N
                AC_DEFINE_UNQUOTED([HAS_$2], [0], ifelse($4,,[Without $3.],$4))
# CONDITIONAL N
                with_[$1]=no
                AC_MSG_RESULT([no])
# IF NO
                $6
# ENDIF
        ;;
esac

dnl # CONDITIONAL
AM_CONDITIONAL([HAS_$2], [test "y$with_[$1]" != "yno"])
# Used to check the test was correct (it is)
#AM_CONDITIONAL([TEST_HAS_$2], [echo test "y$with_[$1]" != "yno" > /tmp/test_has_$2.txt])
# SUBST
AC_SUBST([HAS_$2])
# AC_HAS_WITHOUT $1 DONE
])

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

AC_DEFUN([YA_TRY_LINK], [
AC_LINK_IFELSE([AC_LANG_PROGRAM([$1],[$2],[$3],[$4])])
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
        osx_version_major=$(uname -r|sed 's/\..*//')
        AC_MSG_RESULT([OSX $osx_version_major])
        CFLAGS="$CFLAGS -D__APPLE_USE_RFC_3542=1"
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
    is_darwin_os_txt="yes"
    if [[ $osx_version_major -ge 14 ]]
    then
        osx_version_major_ge14="yes"
    else
        osx_version_major_ge14="no"
    fi
else
    AC_DEFINE_UNQUOTED(IS_DARWIN_OS, [0], [OSX])
    is_darwin_os_txt="no"
    osx_version_major_ge14="no"
fi

AM_CONDITIONAL([IS_DARWIN_OS], [test "y$isdarwin_os_txt" == "yyes"])
AM_CONDITIONAL([IS_DARWIN_GE14], [test "y$osx_version_major_ge14" == "yyes"])
AC_SUBST(IS_DARWIN_OS)
AC_SUBST(IS_DARWIN_GE14)

if [[ $is_bsd_family -ne 0 ]]
then
    is_bsd_family_txt="yes"
    AC_DEFINE_UNQUOTED(IS_BSD_FAMILY, [1], [BSD])
else
    is_bsd_family_txt="no"
    AC_DEFINE_UNQUOTED(IS_BSD_FAMILY, [0], [BSD])
fi
AM_CONDITIONAL([IS_BSD_FAMILY], [test "y$is_bsd_family_txt" == "yyes"])

AC_SUBST(IS_BSD_FAMILY)

if [[ $is_linux_family -ne 0 ]]
then
    is_linux_family_txt="yes"
    AC_DEFINE_UNQUOTED(IS_LINUX_FAMILY, [1], [LINUX])
else
    is_linux_family_txt="no"
    AC_DEFINE_UNQUOTED(IS_LINUX_FAMILY, [0], [LINUX])
fi
AM_CONDITIONAL([IS_LINUX_FAMILY], [test "y$is_linux_family_txt" == "yyes"])

AC_SUBST(IS_LINUX_FAMILY)

if [[ $is_solaris_family -ne 0 ]]
then
    is_solaris_family_txt="yes"
    AC_DEFINE_UNQUOTED(IS_SOLARIS_FAMILY, [1], [SOLARIS])
else
    is_solaris_family_txt="no"
    AC_DEFINE_UNQUOTED(IS_SOLARIS_FAMILY, [0], [SOLARIS])
fi
AM_CONDITIONAL([IS_SOLARIS_FAMILY], [test "y$is_solaris_family_txt" == "yyes"])

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
    has_cc_[$2]="no"
    AM_CONDITIONAL(HAS_CC_$2, [false])
    AC_DEFINE_UNQUOTED([HAS_CC_$2], [0], [Compiler supports feature])
    AC_MSG_RESULT([no])
else
    has_cc_[$2]="yes"
    AM_CONDITIONAL(HAS_CC_$2, [true])
    AC_DEFINE_UNQUOTED([HAS_CC_$2], [1], [Compiler supports feature])
    AC_MSG_RESULT([yes])
fi
# CONDITIONAL
AM_CONDITIONAL(HAS_CC_$2, [test "y$has_cc_[$2]" == "yyes"])
# SUBST
AC_SUBST(HAS_CC_$2)
rm -rf test-gcc-$2*
])

dnl setgroups support

AC_DEFUN([AC_SETGROUPS_CHECK], [
AC_MSG_CHECKING([for setgroups])
AC_CHECK_LIB(c,setgroups,
    [
        AC_DEFINE_UNQUOTED([HAS_SETGROUPS], [1], [The system supports setgroups])
        AC_MSG_RESULT([yes])
    ],
    [
        AC_MSG_RESULT([no])
    ]
)
])

dnl __sync builtins

AC_DEFUN([AC_SYNC_BUILTINS], [

AC_MSG_CHECKING([if the compiler supports __sync builtins])
cat > sync_builtin_test.c <<_ACEOF
typedef int atomic_flag;

static int atomic_flag_test_and_set(atomic_flag* v)
{
    atomic_flag old = __sync_fetch_and_or(v, (atomic_flag)1);
    return old;
}

static void atomic_flag_clear(atomic_flag* v)
{
    __sync_fetch_and_and(v, (atomic_flag)0);
}

int main()
{
        atomic_flag f;
        atomic_flag old = atomic_flag_test_and_set(&f);
        atomic_flag_clear(&f);
        return 0;
}

_ACEOF
${CC} ${CFLAGS} sync_builtin_test.c -o sync_builtin_test > /dev/null 2>&1
./sync_builtin_test > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
        has_sync_builtins=1
        AC_MSG_RESULT([yes])
else
        has_sync_builtins=0
	AC_MSG_RESULT([no])
fi
rm -f sync_builtin_test sync_builtin_test.c
# CONDITIONAL
AM_CONDITIONAL([HAS_SYNC_BUILTINS], [test $has_sync_builtins -eq 1])
# SUBST
AC_SUBST(HAS_SYNC_BUILTINS)
AC_DEFINE_UNQUOTED([HAS_SYNC_BUILTINS], [$has_sync_builtins], [An alternative to be used if stdatomics is not available])

])

dnl ####################################################

dnl Memory aligment issues (T1000)

AC_DEFUN([AC_MEMALIGN_CHECK], [

AC_MSG_CHECKING([if memory accesses must be size-aligned])
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
./memalign_issues_test > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
	has_memalign_issues=1
    	AC_MSG_RESULT([yes])
else
	has_memalign_issues=0
        AC_MSG_RESULT([no])
fi
rm -f memalign_issues_test memalign_issues_test.c
# CONDITIONAL
AM_CONDITIONAL([HAS_MEMALIGN_ISSUES], [test $has_memalign_issues -eq 1])
# SUBST
AC_SUBST(HAS_MEMALIGN_ISSUES)
AC_DEFINE_UNQUOTED([HAS_MEMALIGN_ISSUES], [$has_memalign_issues], [Define this to enable slow but safe unaligned memory accesses])

])

dnl ####################################################

dnl Architecture

AC_DEFUN([AC_CPU_CHECK], [

AC_DEFINE_UNQUOTED([DEFAULT_ASSUMED_CPU_COUNT], [2], [number of hardware core if the auto-detect fails])

cpu_intel_compatible=1


AC_MSG_CHECKING([for the CPU options])
cpu_unknown=1
has_cpu_niagara=0
has_cpu_amdintel=0

CFLAGS3264=
case "$(uname -i 2>/dev/null)" in
        SUNW,SPARC-Enterprise-T1000)
                AC_DEFINE_UNQUOTED([HAS_CPU_NIAGARA], [1], [T1000 has a Niagara cpu])
                has_cpu_niagara=1
                AC_MSG_RESULT([UtrasparcT1])
                CFLAGS3264=-m64
                cpu_unknown=0
                cpu_intel_compatible=0
                ;;
        *)
                ;;
esac

AC_REQUIRE([AC_CANONICAL_HOST])
AS_IF([test "x$host_cpu" = xx86_64],[
		AC_DEFINE_UNQUOTED([HAS_CPU_AMDINTEL], [1], [i386, Athlon, Opteron, Core2, i3, i5, i7, ...])
		AM_CONDITIONAL([HAS_CPU_AMDINTEL], [true])
		AC_MSG_RESULT([AMD/Intel ($host)])
		AS_IF([test "x$host" = "xx86_64-linux-gnux32"],,[CFLAGS3264=-m64])
		CPU_UNKNOWN=0
		cpu_intel_compatible=1
])

case "${cpu_unknown}" in
        1)
                AC_MSG_RESULT([generic])
                ;;
        0)
                ;;
esac

AM_CONDITIONAL([HAS_CPU_NIAGARA], [test $has_cpu_niagara -eq 1])
AM_CONDITIONAL([HAS_CPU_AMDINTEL], [test $has_cpu_amdintel -eq 1])

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
AC_ARG_ENABLE(force32bits, AS_HELP_STRING([--enable-force32bits], [Forces a 32 bits binary compilation]), [enable_force32bits=yes], [enable_force32bits=no])
AC_MSG_RESULT($enable_force32bits)
case "$enable_force32bits" in
    yes)
        CFLAGS3264=-m32
        ;;
    *)
        ;;
esac

AM_CONDITIONAL([FORCE32BITS], [test "y$enable_force32bits" == "yyes"])

AC_MSG_CHECKING([if force 64 bits is enabled])
AC_ARG_ENABLE(force64bits, AS_HELP_STRING([--enable-force64bits], [Forces a 64 bits binary compilation]), [enable_force64bits=yes], [enable_force64bits=no])
AC_MSG_RESULT($enable_force64bits)
case "$enable_force64bits" in
    yes)
        CFLAGS3264=-m64

        if [[ "$enable_force32" = "yes" ]]
        then
            echo "cannot do both --enable-force32bits and --enable-force64bits at the same time"
            exit 1
        fi

        ;;
    *)
        ;;
esac
AM_CONDITIONAL([FORCE64BITS], [test "y$enable_force64bits" = "yyes"])

])

dnl ####################################################

dnl Endianness

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
    cpu_endian="little"
    AC_MSG_RESULT([little])
else
    cpu_endian="big"
    AC_MSG_RESULT([big])
fi
# CONDITIONAL
AM_CONDITIONAL(HAS_LITTLE_ENDIAN, [test "$cpu_endian" == "little"])
AM_CONDITIONAL(HAS_BIG_ENDIAN, [test "$cpu_endian" == "big"])
# SUBST
AC_SUBST(HAS_LITTLE_ENDIAN)
AC_SUBST(HAS_BIG_ENDIAN)
rm -f test-gcc-endian.c* test-gcc-endian
])

dnl ####################################################

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

EURID_CFLAGS=

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

uses_icc=0
uses_gcc=0
uses_clang=0        
uses_sunc=0
uses_unknown=0

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

        uses_gcc=1

elif [[ "$CCNAME" = "icc" ]]
then
        echo "ICC"

        CCOPTIMISATIONFLAGS=-O3

        uses_icc=1

        AR=xiar

elif [[ "$CCNAME" = "clang" ]]
then
        echo "CLANG"

        CCOPTIMISATIONFLAGS=-O3
        
	uses_clang=1

elif [[ "$CCNAME" = "Sun C" ]]
then
    echo "Sun C"

    CCOPTIMISATIONFLAGS=-xO5

        uses_sunc=1
else
        echo "unsupported compiler"

        CCNAME=$CC

        CCOPTIMISATIONFLAGS=-O2
        
        uses_unknown=1
fi

AM_CONDITIONAL([USES_ICC], [test $uses_icc -eq 1])
AM_CONDITIONAL([USES_GCC], [test $uses_gcc -eq 1])
AM_CONDITIONAL([USES_CLANG], [test $uses_clang -eq 1])
AM_CONDITIONAL([USES_SUNC], [test $uses_sunc -eq 1])
AM_CONDITIONAL([USES_UNKNOWN], [test $uses_unknown -eq 1])

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
AC_COMPILER_SUPPORTS([-std=gnu11],STD_GNU11)
AC_COMPILER_SUPPORTS([-std=c11],STD_C11)
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

AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([asm/unistd.h])
AC_CHECK_HEADERS([assert.h])
AC_CHECK_HEADERS([bfd.h])
AC_CHECK_HEADERS([byteswap.h])
AC_CHECK_HEADERS([cpuid.h])
AC_CHECK_HEADERS([ctype.h])
AC_CHECK_HEADERS([dirent.h])
AC_CHECK_HEADERS([dlfcn.h])
AC_CHECK_HEADERS([endian.h])
AC_CHECK_HEADERS([errno.h])
AC_CHECK_HEADERS([execinfo.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([getopt.h])
AC_CHECK_HEADERS([grp.h])
AC_CHECK_HEADERS([limits.h])
AC_CHECK_HEADERS([linux/limits.h])
AC_CHECK_HEADERS([mach/clock.h])
AC_CHECK_HEADERS([machine/endian.h])
AC_CHECK_HEADERS([mach/mach.h])
AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([net/ethernet.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([netinet6/in6.h])
AC_CHECK_HEADERS([netinet/tcp.h])
AC_CHECK_HEADERS([pcap/pcap.h])
AC_CHECK_HEADERS([poll.h])
AC_CHECK_HEADERS([pthread.h])
AC_CHECK_HEADERS([pwd.h])
AC_CHECK_HEADERS([sched.h])
AC_CHECK_HEADERS([signal.h])
AC_CHECK_HEADERS([stdarg.h])
AC_CHECK_HEADERS([stdatomic.h])
AC_CHECK_HEADERS([stdbool.h])
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_HEADERS([stdint.h])
AC_CHECK_HEADERS([stdio.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([strings.h])
AC_CHECK_HEADERS([sys/byteorder.h])
AC_CHECK_HEADERS([sys/cpuset.h])
AC_CHECK_HEADERS([sys/endian.h])
AC_CHECK_HEADERS([sys/file.h])
AC_CHECK_HEADERS([sys/ipc.h])
AC_CHECK_HEADERS([syslog.h])
AC_CHECK_HEADERS([sys/mman.h])
AC_CHECK_HEADERS([sys/msg.h])
AC_CHECK_HEADERS([sys/param.h])
AC_CHECK_HEADERS([sys/prctl.h])
AC_CHECK_HEADERS([sys/resource.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/stat.h])
AC_CHECK_HEADERS([sys/syslimits.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([sys/un.h])
AC_CHECK_HEADERS([sys/wait.h])
AC_CHECK_HEADERS([tcl.h])
AC_CHECK_HEADERS([time.h])
AC_CHECK_HEADERS([ucontext.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([stdnoreturn.h])

AC_MEMALIGN_CHECK
AC_SYNC_BUILTINS
AC_SETGROUPS_CHECK
AC_ENDIANNESS
])

dnl ####################################################

dnl timegm support

AC_DEFUN([AC_TIMEGM_CHECK], [

AC_MSG_CHECKING([for timegm])

YA_TRY_LINK([#include<time.h>],[struct tm t; timegm(&t);],[AC_DEFINE_UNQUOTED([HAS_TIMEGM], [1], [The system supports timegm]) echo yes],[echo no])

])

dnl ####################################################

dnl mremap support

AC_DEFUN([AC_MREMAP_CHECK], [

AC_MSG_CHECKING([for mremap])

YA_TRY_LINK([#define _GNU_SOURCE
             #include<sys/mman.h>],[mremap(0,0,0,0);],[AC_DEFINE_UNQUOTED([HAS_MREMAP], [1], [The system supports mremap]) echo yes],[echo no])

])

dnl ####################################################

dnl pthread spinlock support

AC_DEFUN([AC_PTHREAD_SPINLOCK_CHECK], [

AC_MSG_CHECKING([for pthread_spin_init])
AC_SEARCH_LIBS(pthread_spin_init,pthread,[AC_DEFINE_UNQUOTED([HAS_PTHREAD_SPINLOCK], [1], [The system supports spinlocks]) echo yes],[echo no])
])

dnl ####################################################

dnl pthread_setname_np support

AC_DEFUN([AC_PTHREAD_SETNAME_NP_CHECK], [

AC_MSG_CHECKING([for pthread_setname_np])
AC_SEARCH_LIBS(pthread_setname_np, pthread,[AC_DEFINE_UNQUOTED([HAS_PTHREAD_SETNAME_NP], [1], [The system supports thread names]) echo yes],[echo no])
])

dnl ####################################################

dnl pthread_setaffinity_np support

AC_DEFUN([AC_PTHREAD_SETAFFINITY_NP_CHECK], [

AC_MSG_CHECKING([for pthread_setaffinity_np])
AC_SEARCH_LIBS(pthread_setaffinity_np,pthread,[AC_DEFINE_UNQUOTED([HAS_PTHREAD_SETAFFINITY_NP], [1], [The system supports thread affinity]) echo yes],[echo no])
])

dnl ####################################################

dnl gettid support

AC_DEFUN([AC_GETTID_CHECK], [

    AC_MSG_CHECKING([for gettid])
AC_SEARCH_LIBS(gettid,,[AC_DEFINE_UNQUOTED([HAVE_GETTID], [1], [The system supports gettid]) echo yes],[echo no])
])

dnl ####################################################

dnl gethostbyname inet_pton inet_ntop ... (Solaris requires a lib)

AC_DEFUN([AC_GETHOSTBYNAME_CHECK], [

AC_MSG_CHECKING([for gethostbyname inet_pton inet_ntop])
AC_MSG_CHECKING([if gethostbyname requires some lib])
YA_TRY_LINK([#include<netdb.h>],[struct hostent *host = gethostbyname("www.yadifa.eu.");],
    [
        AC_MSG_RESULT([no])
    ],
    [
        AC_MSG_CHECKING([if gethostbyname requires nsl])
        OLD_LDFLAGS="$LDFLAGS"
        LDFLAGS="-lnsl $LDFLAGS"
        YA_TRY_LINK([#include<netdb.h>],[struct hostent *host = gethostbyname("www.yadifa.eu.");],
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

dnl ####################################################

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
        
        ;;
    no|*)
        ;;
esac

AM_CONDITIONAL(HAS_LTO_SUPPORT, [test "x$enable_lto" == "yyes"])

])

dnl ####################################################

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

dnl ####################################################

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

dnl ####################################################

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

dnl ####################################################

AC_DEFUN([AC_EURID_SUMMARY], [

cat <<EOF
        CC               :        $CC
        CPP              :        $CPP
        LD               :        $LD
        AR               :        $AR

        CFLAGS           :        $CFLAGS
        CPPFLAGS         :        $CPPFLAGS
        LDFLAGS          :        $LDFLAGS

        MEMALIGN ISSUES  :        $has_memalign_issues
        32/64            :        $CFLAGS3264
        LTO              :        $enable_lto
        LOG              :        $logdir
EOF
])

dnl ####################################################

AC_DEFUN([AC_MAKE_BUILDINFO], [
make buildinfo.h
])

