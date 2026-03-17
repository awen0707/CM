execute_process(COMMAND uname -p OUTPUT_VARIABLE BUILD_TUPLE OUTPUT_STRIP_TRAILING_WHITESPACE)
if (${BUILD_TUPLE} STREQUAL "x86_64")
    set(OS_OPTIONS -msse4.2 -mcx16)
    add_definitions(-DUSE_SSE42_CRC32C_WITH_RUNTIME_CHECK)
elseif (${BUILD_TUPLE} STREQUAL "aarch64")
    set(USE_SSE42_CRC32C_WITH_RUNTIME_CHECK OFF)
    if (USE_LSE)
        # lse may not support in some OS.
        set(OS_OPTIONS -march=armv8-a+crc+lse)
        message(STATUS "Build aarch64 with LSE")
    else ()
        set(OS_OPTIONS -march=armv8-a+crc)
    endif (USE_LSE)
endif ()

# set install path if not pointed
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX ${PROJECT_BINARY_DIR}/${BUILD_MODE})
    message("We set CMAKE_INSTALL_PREFIX default path to [${CMAKE_INSTALL_PREFIX}]")
endif ()

message("We will install target to ${CMAKE_INSTALL_PREFIX}, build mode: <${CMAKE_BUILD_TYPE}>.")

set(SECURE_OPTIONS -fno-common -fstack-protector-strong -fPIE)
set(SECURE_LINK_OPTS -Wl,-z,noexecstack -Wl,-z,relro,-z,now -pie)
set(PROTECT_OPTIONS -fwrapv -std=c++11 ${OPTIMIZE_LEVEL})
set(WARNING_OPTIONS -Wall -Wendif-labels -Werror -Wformat-security)
set(OPTIMIZE_OPTIONS -pipe -fno-aggressive-loop-optimizations -fno-expensive-optimizations -fno-omit-frame-pointer
        -fno-strict-aliasing -freg-struct-return)
set(CHECK_OPTIONS -Wmissing-format-attribute -Wno-attributes -Wno-unused-but-set-variable
        -Wno-write-strings -Wpointer-arith)

if (ENABLE_MULTIPLE_NODES)
    message("ENABLE_MULTIPLE_NODES is on!")
    add_definitions(-D ENABLE_MULTIPLE_NODES)
    set(DIST_PATH ${PROJECT_SOURCE_DIR}/distribute)
endif ()

if (ENABLE_PRIVATEGAUSS)
    message("ENABLE_PRIVATEGAUSS is on!")
    add_definitions(-D ENABLE_PRIVATEGAUSS)
    set(DIST_PATH ${PROJECT_SOURCE_DIR}/distribute)
endif()

if (ENABLE_LIBPQ)
    message("ENABLE_LIBPQ is on!")
    add_definitions(-D ENABLE_LIBPQ)
endif()

set(GCC_VERSION $ENV{GCC_VERSION})
if ("x${GCC_VERSION}" STREQUAL "x")
    set(GCC_VERSION "7.3.0")
endif ()

if (ENABLE_MEMCHECK)
    message("add memcheck dependencies.")
    set(MEMCHECK_HOME ${3RD_DEPENDENCY_ROOT}/memcheck/debug)
    set(MEMCHECK_LIB_PATH ${MEMCHECK_HOME}/gcc${GCC_VERSION}/lib)
    list(REMOVE_ITEM SECURE_OPTIONS -fstack-protector)
    add_definitions(-D ENABLE_MEMCHECK)
    add_compile_options(-fsanitize=address -fsanitize=leak -fno-omit-frame-pointer -lasan)
    add_link_options(-fsanitize=address -fsanitize=leak -fno-omit-frame-pointer -lasan)
endif ()

if (ENABLE_GCOV)
    message("add coverage dependencies.")
    set(GCOV_FLAGS -fprofile-arcs -ftest-coverage)
    set(GCOV_LIBS gcov)

    link_libraries(${GCOV_LIBS})
    add_compile_options(${GCOV_FLAGS})
    add_definitions(-D ENABLE_GCOV)
endif ()

if (ENABLE_HOTPATCH)
    if (NOT ${RET_ARM_HOTPATCH} EQUAL -1)
        set(HOTPATCH_ATOMIC_LDS -Wl,-T${3RD_HOTPATCH_TOOL}/atomic.lds)
    endif ()
endif ()

if (ENABLE_ETCD)
    list(APPEND 3RD_LIB_PATH ${ETCD_DIRECTORY_LIB})
endif ()

set(G_BIN_EXT_LIBS ${MEMCHECK_LIBS})

set(G_COMPILE_OPTIONS ${OS_OPTIONS} ${CM_COMMON_FLAGS} ${OPTIMIZE_LEVEL} ${SECURE_OPTIONS} ${PROTECT_OPTIONS}
        ${WARNING_OPTIONS} ${OPTIMIZE_OPTIONS} ${CHECK_OPTIONS})

set(G_LINK_OPTIONS ${CM_COMMON_FLAGS} ${SECURE_LINK_OPTS})
# secure opt
set(CMAKE_SKIP_RPATH TRUE)

add_compile_options(${G_COMPILE_OPTIONS})
add_link_options(${G_LINK_OPTIONS})

link_directories(${3RD_LIB_PATH})

set(PROJECT_INC_BASE ${OPENCM_PROJECT_SOURCE_DIR}/src/include)
set(COMM_INC
        ${PROJECT_INC_BASE}
        ${PROJECT_INC_BASE}/cm
        ${PROJECT_INC_BASE}/cm/cm_adapter/cm_sharedisk
        ${PROJECT_INC_BASE}/cm/cm_adapter
        ${PROJECT_INC_BASE}/cm/cm_server
        ${PROJECT_INC_BASE}/cm/cm_agent
        ${PROJECT_INC_BASE}/cm/cm_ctl
        ${SSL_DIRECTORY_INC}
        ${SECURE_DIRECTORY_INC}
        ${CMAKE_BINARY_DIR}
        )

# libpq must need krb5
if (ENABLE_KRB OR ENABLE_LIBPQ)
    set(KRB_LIBS gssapi_krb5_gauss krb5_gauss k5crypto_gauss com_err_gauss krb5support_gauss)
    link_directories(${KRB_HOME}/lib)
    list(APPEND COMM_INC ${KRB_HOME}/include)

    if (ENABLE_KRB)
        add_definitions(-D KRB5)
    endif ()
endif ()

if (ENABLE_LIBPQ)
    list(APPEND COMM_INC
            ${PROJECT_INC_BASE}/cm/cm_agent/clients/libpq)
endif ()
list(APPEND COMM_INC
        ${PROJECT_INC_BASE}/opengauss
        ${PROJECT_INC_BASE}/opengauss/cm
        ${PROJECT_INC_BASE}/opengauss/alarm
        ${PROJECT_INC_BASE}/opengauss/common/config
        )
