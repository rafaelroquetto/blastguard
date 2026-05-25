# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rafael Roquetto

cmake_minimum_required(VERSION 3.20)
project(blastguard VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" ARCH_LOWER)

if(ARCH_LOWER MATCHES "x86_64")
    set(BPF_ARCH x86)
elseif(ARCH_LOWER MATCHES "aarch64")
    set(BPF_ARCH arm64)
elseif(ARCH_LOWER MATCHES "arm")
    set(BPF_ARCH arm)
else()
    message(FATAL_ERROR "Unsupported architecture for BPF: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

if(NOT EXISTS /sys/kernel/btf/vmlinux)
    message(FATAL_ERROR "/sys/kernel/btf/vmlinux not found; CO-RE BPF requires kernel BTF")
endif()

set(BPF_PROG   ${CMAKE_CURRENT_LIST_DIR}/src/bpf/blastguard.bpf.c)
set(BPF_OBJ    ${CMAKE_CURRENT_BINARY_DIR}/blastguard.bpf.o)
set(BPF_SKEL   ${CMAKE_CURRENT_BINARY_DIR}/blastguard.skel.h)
set(VMLINUX_H  ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)
set(BPF_SRCDIR ${CMAKE_CURRENT_LIST_DIR}/src/bpf)

add_custom_command(
    OUTPUT ${VMLINUX_H}
    COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}
    COMMENT "Generating vmlinux.h from /sys/kernel/btf/vmlinux"
    VERBATIM
)

add_custom_command(
    OUTPUT ${BPF_OBJ} ${BPF_SKEL}
    COMMAND clang -g -O2 -target bpf -D__BPF__ -D__TARGET_ARCH_${BPF_ARCH}
            -I${BPF_SRCDIR}
            -I${CMAKE_CURRENT_BINARY_DIR}
            -c -o ${BPF_OBJ} ${BPF_PROG}
    COMMAND bpftool gen skeleton ${BPF_OBJ} > ${BPF_SKEL}
    DEPENDS ${BPF_PROG} ${BPF_SRCDIR}/events.h ${VMLINUX_H}
    COMMENT "Building BPF object and skeleton"
)

add_custom_target(bpf_build DEPENDS ${BPF_OBJ} ${BPF_SKEL})

set(DAEMON_SRC
    ${CMAKE_CURRENT_LIST_DIR}/src/common/io.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/common/io.h
    ${CMAKE_CURRENT_LIST_DIR}/src/common/proto.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/common/proto.h
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/main.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/daemon.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/daemon.h
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/args.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/args.h
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/ipcserver.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/ipcserver.h
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/ebpfmanager.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/ebpfmanager.h
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/attributor.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/attributor.h
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/session.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/session.h
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/rules.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/rules.h
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/report.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/daemon/report.h
)

add_executable(blastguardd ${DAEMON_SRC} ${BPF_SKEL})
add_dependencies(blastguardd bpf_build)

target_include_directories(blastguardd PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/src
)

target_link_libraries(blastguardd PRIVATE bpf)

set(CTL_SRC
    ${CMAKE_CURRENT_LIST_DIR}/src/common/io.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/common/io.h
    ${CMAKE_CURRENT_LIST_DIR}/src/common/proto.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/common/proto.h
    ${CMAKE_CURRENT_LIST_DIR}/src/ctl/main.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/ctl/args.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/ctl/args.h
)

add_executable(blastguardctl ${CTL_SRC})

target_include_directories(blastguardctl PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
)

file(GLOB_RECURSE FORMAT_SRCS
    CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_LIST_DIR}/src/*.h
    ${CMAKE_CURRENT_LIST_DIR}/src/*.c
    ${CMAKE_CURRENT_LIST_DIR}/src/*.cpp
)
list(FILTER FORMAT_SRCS EXCLUDE REGEX "vmlinux\\.h$")

find_program(CLANG_FORMAT_EXE clang-format)

if(CLANG_FORMAT_EXE)
    add_custom_target(format
        COMMAND ${CLANG_FORMAT_EXE} -i ${FORMAT_SRCS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        COMMENT "Formatting sources with clang-format"
        VERBATIM
    )

    add_custom_target(format-check
        COMMAND ${CLANG_FORMAT_EXE} --dry-run --Werror ${FORMAT_SRCS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        COMMENT "Checking formatting with clang-format"
        VERBATIM
    )
endif()

file(GLOB_RECURSE LICENSE_CHECK_FILES
    CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_LIST_DIR}/src/*.h
    ${CMAKE_CURRENT_LIST_DIR}/src/*.c
    ${CMAKE_CURRENT_LIST_DIR}/src/*.cpp
    ${CMAKE_CURRENT_LIST_DIR}/action/*.yml
    ${CMAKE_CURRENT_LIST_DIR}/.github/workflows/*.yml
    ${CMAKE_CURRENT_LIST_DIR}/test/integration/*.sh
    ${CMAKE_CURRENT_LIST_DIR}/test/fixtures/*/*.sh
    ${CMAKE_CURRENT_LIST_DIR}/action/install.sh
    ${CMAKE_CURRENT_LIST_DIR}/scripts/*.sh
)
list(FILTER LICENSE_CHECK_FILES EXCLUDE REGEX "vmlinux\\.h$")
list(APPEND LICENSE_CHECK_FILES ${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt)

add_custom_target(license-check
    COMMAND ${CMAKE_CURRENT_LIST_DIR}/scripts/check-license-headers.sh ${LICENSE_CHECK_FILES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMENT "Checking license headers"
    VERBATIM
)

add_custom_target(tests
    COMMAND ${CMAKE_CURRENT_LIST_DIR}/test/integration/run-benign.sh
    COMMAND ${CMAKE_CURRENT_LIST_DIR}/test/integration/run-evil.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    DEPENDS blastguardd blastguardctl
    USES_TERMINAL
    COMMENT "Running integration tests"
    VERBATIM
)
