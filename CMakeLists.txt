#
# Copyright (c) 2025 Hubert Jetschko
#
# SPDX-License-Identifier: MIT
#

if(CONFIG_RS_PROTOCOL)
  zephyr_library_named(rs_protocol)
  zephyr_library_sources(rs_protocol.c)
  zephyr_include_directories(.)
endif()
