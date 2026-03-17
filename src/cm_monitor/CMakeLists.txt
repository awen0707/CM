# om_monitor bin
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_ommonitor_SRC)

set(CMM_LIB_PATHS
        ${PGPORT_HOME}
        ${CJSON_DIRECTORY_LIB}
        ${CGROUP_DIRECTORY_LIB}
        )

set(CMM_LINK_LIBS cmpq_static cmddbadapter_static config_static alarmclient_static cmcommon_static
        cjson crypt dl m ssl crypto pthread rt securec ${G_BIN_EXT_LIBS})
if (ENABLE_MULTIPLE_NODES)
    set(CMM_LINK_LIBS ${CMM_LINK_LIBS} cgroup)
endif ()

link_directories(${CMM_LIB_PATHS})
if (ENABLE_UT)
    add_shared_tgt(utcmmonitor TGT_ommonitor_SRC "")
    target_link_libraries(utcmmonitor ${CMM_LINK_LIBS})
    install(TARGETS utcmmonitor LIBRARY DESTINATION lib)
else ()
    add_exec_tgt(om_monitor TGT_ommonitor_SRC "")
    target_link_libraries(om_monitor PRIVATE ${CMM_LINK_LIBS})
    install(TARGETS om_monitor RUNTIME DESTINATION bin)
endif ()