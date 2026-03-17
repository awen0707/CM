aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_cmcommon_SRC)
list(APPEND TGT_cmcommon_SRC ${OPENCM_PROJECT_SOURCE_DIR}/src/lib/pq/port/path.cpp)
if (ENABLE_MULTIPLE_NODES)
    aux_source_directory(${DIST_PATH}/cm_common TGT_cmcommonD_SRC)
    list(APPEND TGT_cmcommon_SRC ${TGT_cmcommonD_SRC})
endif ()

set(TGT_cmcommon_INC
        ${CGROUP_DIRECTORY_INC}
        ${CJSON_DIRECTORY_INC}
        )

set(cmcommon_LIB_PATH
        ${CJSON_DIRECTORY_LIB}
        ${CGROUP_DIRECTORY_LIB}
        )

set(TGT_cmcommon_ALL ${TGT_cmcommon_INC} ${TGT_cmcommon_SRC})
set(TGT_cocommon_LIBS cjson alarmclient_static)
if (ENABLE_MULTIPLE_NODES)
    set(TGT_cocommon_LIBS ${TGT_cocommon_LIBS} cgroup)
endif ()

add_static_tgt(cmcommon TGT_cmcommon_SRC TGT_cmcommon_INC)
if (ENABLE_UT)
    add_shared_tgt(utcmcommon TGT_cmcommon_SRC TGT_cmcommon_INC)
    target_link_libraries(utcmcommon ${TGT_cocommon_LIBS})

    install(TARGETS utcmcommon LIBRARY DESTINATION lib)
else ()
    add_shared_tgt(cmcommon TGT_cmcommon_SRC TGT_cmcommon_INC)
    target_link_libraries(cmcommon PRIVATE ${TGT_cocommon_LIBS})
endif ()

if (ENABLE_MULTIPLE_NODES)
    install_static_libs(${CGROUP_DIRECTORY_LIB} "libcgroup.so*")
endif ()

install_static_libs(${CJSON_DIRECTORY_LIB} "libcjson.so*")

install_static_libs(${SSL_DIRECTORY_LIB} "libcrypto.so*")
install_static_libs(${SSL_DIRECTORY_LIB} "libssl.so*")
