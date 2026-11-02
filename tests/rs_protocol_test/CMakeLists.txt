cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(rs_protocol_test)

# safebuffer is needed by rs_protocol. Override with -DSAFEBUFFER_DIR=<path> to test against another copy.
if(NOT DEFINED SAFEBUFFER_DIR)
    set(SAFEBUFFER_DIR ${ZEPHYR_BASE}/../modules/lib/safebuffer)
endif()

target_sources(app PRIVATE
    src/main.c
    ../../rs_protocol.c
    ${SAFEBUFFER_DIR}/safebuffer.c
)

target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../.. ${SAFEBUFFER_DIR})
