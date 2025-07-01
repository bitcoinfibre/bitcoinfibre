# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(bitcoin_fec STATIC EXCLUDE_FROM_ALL
  cm256.cpp
  gf256.cpp
  wirehair.cpp
  WirehairCodec.cpp
  WirehairCodec.h
  WirehairTools.cpp
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64|i[3-6]86)")
  target_compile_options(bitcoin_fec PRIVATE -mssse3)
endif()
set_target_properties(bitcoin_fec PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(bitcoin_fec PUBLIC cxx_std_17)
