cmake_minimum_required(VERSION 3.20)
project(quickwork VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

# Fetch Boost
set(BOOST_INCLUDE_LIBRARIES beast asio program_options)
set(BOOST_ENABLE_CMAKE ON)

FetchContent_Declare(
    Boost
    URL https://github.com/boostorg/boost/releases/download/boost-1.86.0/boost-1.86.0-cmake.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP ON
)
FetchContent_MakeAvailable(Boost)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# For static builds, manually specify all static libraries with linker group
option(BUILD_STATIC "Build static binary" OFF)
if(BUILD_STATIC)
    # Use linker group to resolve circular dependencies between static libraries
    # Include SSL/Crypto in the group since curl depends on them
    # Note: libz.a is in /lib/ on Alpine, not /usr/lib/
    set(CURL_LIBRARIES
        -Wl,--start-group
        /usr/lib/libcurl.a
        /usr/lib/libssl.a
        /usr/lib/libcrypto.a
        /usr/lib/libcares.a
        /usr/lib/libnghttp2.a
        /usr/lib/libpsl.a
        /usr/lib/libidn2.a
        /usr/lib/libunistring.a
        /usr/lib/libzstd.a
        /usr/lib/libbrotlidec.a
        /usr/lib/libbrotlicommon.a
        /lib/libz.a
        -Wl,--end-group
    )
    
    find_path(CURL_INCLUDE_DIR curl/curl.h)
    message(STATUS "Static CURL libraries: ${CURL_LIBRARIES}")
    
    # Override OpenSSL to avoid duplicate linking
    set(OPENSSL_CRYPTO_LIBRARY "")
    set(OPENSSL_SSL_LIBRARY "")
else()
    find_package(CURL REQUIRED)
    set(CURL_LIBRARIES CURL::libcurl)
endif()

# Fetch QuickJS from bellard.org
FetchContent_Declare(
    quickjs
    URL https://bellard.org/quickjs/quickjs-2025-09-13-2.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP ON
)
FetchContent_GetProperties(quickjs)
if(NOT quickjs_POPULATED)
    FetchContent_Populate(quickjs)
    # Remove the 'version' file that conflicts with C++ <version> header
    file(REMOVE "${quickjs_SOURCE_DIR}/version")
endif()

# Create quickjs library (note: libbf.c removed, dtoa.c added in 2025 versions)
add_library(quickjs_lib STATIC
    ${quickjs_SOURCE_DIR}/quickjs.c
    ${quickjs_SOURCE_DIR}/libregexp.c
    ${quickjs_SOURCE_DIR}/libunicode.c
    ${quickjs_SOURCE_DIR}/cutils.c
    ${quickjs_SOURCE_DIR}/dtoa.c
    ${quickjs_SOURCE_DIR}/quickjs-libc.c
)
target_include_directories(quickjs_lib PRIVATE ${quickjs_SOURCE_DIR})
target_compile_definitions(quickjs_lib PRIVATE
    CONFIG_VERSION="2025-09-13"
    _GNU_SOURCE
)

# Export quickjs include directory for users
set(QUICKJS_INCLUDE_DIR ${quickjs_SOURCE_DIR} CACHE INTERNAL "")

# Main executable
add_executable(quickwork
    src/main.cpp
    src/server.cpp
    src/handler_store.cpp
    src/js_runtime.cpp
    src/js_bindings.cpp
    src/thread_pool.cpp
    src/module_resolver.cpp
    src/kv_store.cpp
)

target_include_directories(quickwork 
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    SYSTEM PRIVATE ${QUICKJS_INCLUDE_DIR}
)

target_include_directories(quickwork PRIVATE ${CURL_INCLUDE_DIR})

if(BUILD_STATIC)
    # For static builds, all libraries are in CURL_LIBRARIES with proper link group
    target_link_libraries(quickwork PRIVATE
        quickjs_lib
        Boost::beast
        Boost::asio
        Boost::program_options
        Threads::Threads
        ${CURL_LIBRARIES}
        ${CMAKE_DL_LIBS}
    )
else()
    target_link_libraries(quickwork PRIVATE
        quickjs_lib
        Boost::beast
        Boost::asio
        Boost::program_options
        Threads::Threads
        OpenSSL::Crypto
        OpenSSL::SSL
        ${CURL_LIBRARIES}
        ${CMAKE_DL_LIBS}
    )
endif()

# Compiler warnings
# Use -fpermissive to allow QuickJS macros that mix designated/non-designated initializers
target_compile_options(quickwork PRIVATE
    -Wall -Wextra -fpermissive
)

# Testing support
enable_testing()

# Custom test target that runs the comprehensive test suite
add_custom_target(run_tests
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.sh
    DEPENDS quickwork
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Running quickwork test suite..."
)

# Add a simple CTest entry
add_test(
    NAME quickwork_test_suite
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
