# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rafael Roquetto

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src/Makefile
   OR NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/zlib/CMakeLists.txt
   OR NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/zstd/build/cmake/CMakeLists.txt)
    message(FATAL_ERROR
        "3rdparty submodules are not populated. Run:\n"
        "  git submodule update --init --recursive\n"
        "Or re-clone with --recursive.")
endif()

set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
add_subdirectory(zlib EXCLUDE_FROM_ALL)

set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZSTD_LEGACY_SUPPORT OFF CACHE BOOL "" FORCE)
add_subdirectory(zstd/build/cmake EXCLUDE_FROM_ALL)

set(LIBBPF_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src)
set(LIBBPF_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_INSTALL_DIR ${LIBBPF_BUILD_DIR}/install)
set(LIBBPF_LIB ${LIBBPF_BUILD_DIR}/libbpf.a)
set(LIBBPF_INSTALL_DIR ${LIBBPF_INSTALL_DIR} PARENT_SCOPE)

add_custom_command(
    OUTPUT ${LIBBPF_LIB}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${LIBBPF_BUILD_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${LIBBPF_INSTALL_DIR}
    COMMAND $(MAKE) -C ${LIBBPF_SRC_DIR}
        BUILD_STATIC_ONLY=1
        OBJDIR=${LIBBPF_BUILD_DIR}
        DESTDIR=${LIBBPF_INSTALL_DIR}
        PREFIX=
        LIBDIR=
        INCLUDEDIR=
        UAPIDIR=
        install_headers install_uapi_headers
    COMMAND $(MAKE) -C ${LIBBPF_SRC_DIR}
        BUILD_STATIC_ONLY=1
        OBJDIR=${LIBBPF_BUILD_DIR}
    COMMENT "Building vendored libbpf (static)"
    VERBATIM
)

add_custom_target(libbpf_make DEPENDS ${LIBBPF_LIB})

add_library(vendor_libbpf STATIC IMPORTED GLOBAL)
add_dependencies(vendor_libbpf libbpf_make)

file(MAKE_DIRECTORY ${LIBBPF_INSTALL_DIR})

set_target_properties(vendor_libbpf PROPERTIES
    IMPORTED_LOCATION ${LIBBPF_LIB}
    INTERFACE_INCLUDE_DIRECTORIES ${LIBBPF_INSTALL_DIR}
)
target_link_libraries(vendor_libbpf INTERFACE zlibstatic libzstd_static)
