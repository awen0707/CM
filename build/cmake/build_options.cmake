
set(CMAKE_CXX_STANDARD 11)

# flags that used for all modules
set(CM_COMMON_FLAGS "-std=c++11")
set(G_LIB_VERSION 1)

# cmake opts
option(ENABLE_UT "enable ut(ON/OFF)" OFF)
option(ENABLE_MEMCHECK "enable memory check" OFF)
option(ENABLE_GCOV "distribute or centralize" OFF)
option(USE_LSE OFF)

include(${PROJECT_SOURCE_DIR}/build/cmake/feature_options.cmake)

set(BUILD_MODE Debug)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "")
    set(BUILD_MODE Debug)
    set(CMAKE_BUILD_TYPE Debug)
    set(OPTIMIZE_LEVEL -O0 -g)
    add_definitions(-D CM_DEBUG_VERSION)
elseif (${CMAKE_BUILD_TYPE} STREQUAL "Release")
    set(BUILD_MODE Release)
    set(ENABLE_MEMCHECK OFF)
    set(ENABLE_UT OFF)
    set(OPTIMIZE_LEVEL -O2 -g3)
else ()
    message(FATAL_ERROR "unsupported CMAKE_BUILD_TYPE = " ${CMAKE_BUILD_TYPE})
endif ()

if (ENABLE_MEMCHECK)
    set(BUILD_MODE Memcheck)
    message("ENABLE_MEMCHECK is on!")
endif ()

if (ENABLE_UT)
    set(BUILD_MODE Ut)
    message("ENABLE_UT is on!, we use llt lib, and build debug pkg.")
    set(LIB_MODE llt)
    add_definitions(-D ENABLE_UT)
endif ()

if (${ENABLE_MULTIPLE_NODES}_${ENABLE_PRIVATEGAUSS} STREQUAL OFF_OFF)
    set(ENABLE_HOTPATCH OFF)
endif ()

if (NOT ENABLE_LIBPQ)
    message("ENABLE_LIBPQ is on, we only support this in single node mode without alarm.")
    set(ENABLE_MULTIPLE_NODES OFF)
    set(ENABLE_ALARM OFF)
endif ()

execute_process(
        COMMAND sh ${OPENCM_PROJECT_SOURCE_DIR}/build/get_PlatForm_str.sh
        OUTPUT_VARIABLE PLAT_FORM_NAME OUTPUT_STRIP_TRAILING_WHITESPACE)

set(HOTPATCH_PLATFORM_LIST suse11_sp1_x86_64 suse12_sp5_x86_64 euleros2.0_sp8_aarch64 euleros2.0_sp9_aarch64 euleros2.0_sp10_aarch64 euleros2.0_sp2_x86_64 euleros2.0_sp5_x86_64 euleros2.0_sp10_x86_64 kylinv10_sp1_aarch64 kylinv10_sp1_x86_64)
set(HOTPATCH_ARM_LIST euleros2.0_sp8_aarch64 euleros2.0_sp9_aarch64 euleros2.0_sp10_aarch64 kylinv10_sp1_aarch64)
list(FIND HOTPATCH_PLATFORM_LIST "${PLAT_FORM_NAME}" RET_HOTPATCH)
list(FIND HOTPATCH_ARM_LIST "${PLAT_FORM_NAME}" RET_ARM_HOTPATCH)
if (ENABLE_HOTPATCH AND (${RET_HOTPATCH} STREQUAL -1))
    message(WARNING "Current OS(${PLAT_FORM_NAME}) is not in os list, don't support ENABLE_HOTPATCH!!, supported plantform list is ${HOTPATCH_PLATFORM_LIST}")
    set(ENABLE_HOTPATCH OFF)
endif ()
