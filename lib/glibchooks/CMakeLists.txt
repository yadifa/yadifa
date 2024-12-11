cmake_minimum_required(VERSION 3.22)
project(glibchooks LANGUAGES C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-strict-prototypes")

set(CMAKE_C_STANDARD 23)

set(SRC "src")
set(INC "include/glibchooks")

set(LIBRARY_HEADERS
        ${INC}/glibchooks_internal.h
        ${INC}/filedescriptor.h
        ${INC}/alloc.h)

add_library(glibchooks SHARED
        ${SRC}/glibchooks_main.c
        ${SRC}/filedescriptor.c
        ${SRC}/alloc.c
        ${LIBRARY_HEADERS})

target_include_directories(glibchooks PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_library(glibchooksload STATIC
        ${SRC}/glibchooks_mainload.c
        ${LIBRARY_HEADERS})
target_include_directories(glibchooksload PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_library(glibchooksctrl SHARED
        ${SRC}/glibchooks_controller.c
        ${INC}/glibchooks_controller.h)
target_include_directories(glibchooksctrl PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
