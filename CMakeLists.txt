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
)

target_include_directories(quickwork 
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    SYSTEM PRIVATE ${QUICKJS_INCLUDE_DIR}
)

target_link_libraries(quickwork PRIVATE
    quickjs_lib
    Boost::beast
    Boost::asio
    Boost::program_options
    Threads::Threads
    OpenSSL::Crypto
    ${CMAKE_DL_LIBS}
)

target_compile_options(quickwork PRIVATE
    -Wall -Wextra -Wpedantic
)
