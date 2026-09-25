cmake_minimum_required(VERSION 3.16)
project(utse1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# BICYCL. Header-only for our purposes (.hpp + .inl): we do not build or
# install it, we just need the directory that contains src/bicycl.hpp.
# ---------------------------------------------------------------------------
set(BICYCL_DIR "" CACHE PATH
    "Path to the BICYCL source tree (the directory containing src/bicycl.hpp)")

if(NOT BICYCL_DIR)
  message(FATAL_ERROR
    "BICYCL_DIR is not set. Example:\n"
    "  cmake -S . -B build -DBICYCL_DIR=/path/to/bicycl")
endif()

if(EXISTS "${BICYCL_DIR}/src/bicycl.hpp")
  set(BICYCL_INCLUDE_DIR "${BICYCL_DIR}/src")
elseif(EXISTS "${BICYCL_DIR}/bicycl.hpp")
  set(BICYCL_INCLUDE_DIR "${BICYCL_DIR}")
else()
  message(FATAL_ERROR "bicycl.hpp not found under '${BICYCL_DIR}' or '${BICYCL_DIR}/src'.")
endif()
message(STATUS "BICYCL headers: ${BICYCL_INCLUDE_DIR}")

# ---------------------------------------------------------------------------
# GMP (no official CMake package, so look it up by hand).
# ---------------------------------------------------------------------------
find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARY NAMES gmp)
find_library(GMPXX_LIBRARY NAMES gmpxx)

if(NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARY OR NOT GMPXX_LIBRARY)
  message(FATAL_ERROR
    "GMP not found. Install libgmp-dev (Debian/Ubuntu), gmp-devel (Fedora), or gmp (brew).\n"
    "  gmp.h   : ${GMP_INCLUDE_DIR}\n"
    "  libgmp  : ${GMP_LIBRARY}\n"
    "  libgmpxx: ${GMPXX_LIBRARY}")
endif()
message(STATUS "GMP: ${GMP_LIBRARY}")

# ---------------------------------------------------------------------------
# OpenSSL (SHAKE256 via EVP; needs >= 1.1.1 for EVP_DigestFinalXOF).
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Every source file is a header; every executable is exactly one .cpp
# (Util.hpp explains why: three functions in BICYCL's gmp_extras.inl are
# defined without `inline`, so a second translation-unit including BICYCL
# fails to link with "multiple definition").
# ---------------------------------------------------------------------------
function(utse1_add_exe name source)
  add_executable(${name} ${source})
  target_include_directories(${name} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${BICYCL_INCLUDE_DIR}"
    "${GMP_INCLUDE_DIR}"
  )
  target_link_libraries(${name} PRIVATE
    "${GMPXX_LIBRARY}"
    "${GMP_LIBRARY}"
    OpenSSL::Crypto
    Threads::Threads
  )
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()
endfunction()

utse1_add_exe(utse1_inproc inproc/main.cpp)
utse1_add_exe(utse1_net    net/main.cpp)
