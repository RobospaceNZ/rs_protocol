cmake_minimum_required(VERSION 3.20.0)

# Build the rs_protocol in this repository as a Zephyr module
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# safebuffer is needed by rs_protocol. A safebuffer cloned next to rs_protocol is used, otherwise the one in the west
# workspace. Override with -DSAFEBUFFER_DIR=<path> to test against another copy.
if(NOT DEFINED SAFEBUFFER_DIR AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/../../../safebuffer/zephyr/module.yml)
    set(SAFEBUFFER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../safebuffer)
endif()
if(DEFINED SAFEBUFFER_DIR)
    list(APPEND ZEPHYR_EXTRA_MODULES ${SAFEBUFFER_DIR})
endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(rs_protocol_test)

target_sources(app PRIVATE src/main.c)
