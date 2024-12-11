################################################################################
#
# Copyright (c) 2011-2024, EURid vzw. All rights reserved.
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

################################################################################
#
# find out on which system cmake runs
#
################################################################################

function(gathering_host)
    message(STATUS "gathering host information:")
    message(STATUS "---------------------------\n")

    if(CMAKE_HOST_UNIX)
        FIND_PROGRAM(CMAKE_UNAME uname /bin /usr/bin /usr/local/bin )
        if(CMAKE_UNAME)
            message(STATUS "CMAKE ${CMAKE_UNAME}")
            exec_program(uname ARGS -s OUTPUT_VARIABLE CMAKE_HOST_SYSTEM_NAME)
        #   set(CMAKE_HOST_SYSTEM_NAME "${CMAKE_HOST_SYSTEM_NAME}" CACHE STRING "cmake host system name")
            exec_program(uname ARGS -r OUTPUT_VARIABLE CMAKE_HOST_SYSTEM_VERSION)

            if(CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
                exec_program(uname ARGS -m OUTPUT_VARIABLE CMAKE_HOST_SYSTEM_PROCESSOR RETURN_VALUE val)
            else(CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
                exec_program(uname ARGS -p OUTPUT_VARIABLE CMAKE_HOST_SYSTEM_PROCESSOR RETURN_VALUE val)
                 if("${val}" GREATER 0)
                    exec_program(uname ARGS -m OUTPUT_VARIABLE CMAKE_HOST_SYSTEM_PROCESSOR RETURN_VALUE val)
                endif("${val}" GREATER 0)

                if(CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin")

                    # get the first characters without '.' from the version string
                    string(REGEX REPLACE 
                            "^([^\.]+).*" 
                            "\\1" CMAKE_HOST_SYSTEM_VERSION "${CMAKE_HOST_SYSTEM_VERSION}")

                endif(CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin")

            endif(CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")

            # check the return of the last uname -m or -p
            if("${val}" GREATER 0)
                set(CMAKE_HOST_SYSTEM_PROCESSOR "unknown")
            endif("${val}" GREATER 0)

            set(CMAKE_UNAME ${CMAKE_UNAME} CACHE INTERNAL "uname command")

            # processor may have double quote in the name, and that needs to be removed
            string(REGEX REPLACE "\"" "" CMAKE_HOST_SYSTEM_PROCESSOR "${CMAKE_HOST_SYSTEM_PROCESSOR}")
            string(REGEX REPLACE "/" "_" CMAKE_HOST_SYSTEM_PROCESSOR "${CMAKE_HOST_SYSTEM_PROCESSOR}")
        endif(CMAKE_UNAME)

    else(CMAKE_HOST_UNIX)
        # check if 'Windows'
        if(CMAKE_HOST_WIN32)
            set(CMAKE_HOST_SYSTEM_NAME "Windows")
            set(CMAKE_HOST_SYSTEM_PROCESSOR "$ENV{PROCESSOR_ARCHITECTURE}")
        endif(CMAKE_HOST_WIN32)
    endif(CMAKE_HOST_UNIX)

    message(STATUS "check host                        : ${CMAKE_HOST_SYSTEM_NAME}")
    message(STATUS "check version                     : ${CMAKE_HOST_SYSTEM_VERSION}")
    message(STATUS "check system processor            : ${CMAKE_HOST_SYSTEM_PROCESSOR}\n")


    # make the variables 'global'
    set(CMAKE_HOST_SYSTEM_NAME      ${CMAKE_HOST_SYSTEM_NAME}      CACHE STRING "host system name" FORCE)
    set(CMAKE_HOST_SYSTEM_VERSION   ${CMAKE_HOST_SYSTEM_VERSION}   CACHE STRING "host system version" FORCE)
    set(CMAKE_HOST_SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR} CACHE STRING "host system processor" FORCE)
endfunction(gathering_host)

