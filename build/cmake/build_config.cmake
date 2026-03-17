EXECUTE_PROCESS(
        COMMAND bash -c "git rev-parse HEAD | cut -b 1-8"
        OUTPUT_VARIABLE COMMIT_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
EXECUTE_PROCESS(
        COMMAND bash -c "date \"+%Y-%m-%d %H:%M:%S\""
        OUTPUT_VARIABLE COMPILE_TIME
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
EXECUTE_PROCESS(
        COMMAND bash -c "which dos2unix > /dev/null 2> /dev/null; if [[ $? -eq 0 ]]; then echo 1; else echo -1;fi"
        OUTPUT_VARIABLE DOS2UNIX_INSTALLED
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
if (${DOS2UNIX_INSTALLED} EQUAL -1)
        message(FATAL_ERROR "Please make sure dependency 'dos2unix' is installed according to current OS plantform!")
endif ()

EXECUTE_PROCESS(
        COMMAND bash -c "dos2unix ${PROJECT_SOURCE_DIR}/build/cm.ver && source ${PROJECT_SOURCE_DIR}/build/cm.ver && echo \"\${PRODUCT} ${CMAKE_PROJECT_NAME} \${VERSION}\""
        OUTPUT_VARIABLE PRO_INFO
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

if ("x${PRO_INFO}" STREQUAL "x${CMAKE_PROJECT_NAME}")
    message(FATAL_ERROR "Unkown version conf in ${PROJECT_SOURCE_DIR}/build/cm.ver!")
endif ()

# CM_VERSION_STR like: cm_ctl (opengauss CM 3.0.0 build ab4a14da) compiled at 2000-01-01 00:00:00 debug)
SET(CM_VERSION_STR
        "(${PRO_INFO} build ${COMMIT_ID}) compiled at ${COMPILE_TIME} ${BUILD_MODE}"
)

message(LOG "Version info: ******* [${CM_VERSION_STR}] *******.")

CONFIGURE_FILE(
        "${OPENCM_PROJECT_SOURCE_DIR}/build/cmake/config.h.in"
        "${CMAKE_BINARY_DIR}/config.h"
)
