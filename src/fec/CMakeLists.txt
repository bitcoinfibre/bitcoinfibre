# src/fec/CMakeLists.txt
set(FEC_SOURCES 
    cm256.cpp 
    cm256.h
    wirehair.cpp
    wirehair/wirehair.h
    gf256.cpp
    gf256.h
    WirehairCodec.cpp
    WirehairCodec.h
    WirehairTools.cpp
    WirehairTools.h)  

add_library(bitcoin_fec STATIC ${FEC_SOURCES})

# Platform-specific SIMD optimizations
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Check if compiling for x86/x64
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64|i[3-6]86)")
        target_compile_options(bitcoin_fec PRIVATE -mssse3)
        # Optionally add more SIMD flags if needed:
        # target_compile_options(bitcoin_fec PRIVATE -msse4.1 -msse4.2)
    endif()
elseif(MSVC)
    # MSVC enables appropriate SIMD by default for x64
    # But you can be explicit if needed:
    # target_compile_options(bitcoin_fec PRIVATE /arch:AVX)
endif()

# Ensure position independent code for static library
set_target_properties(bitcoin_fec PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Make sure we're using C++17 or later (adjust as needed)
target_compile_features(bitcoin_fec PUBLIC cxx_std_17)