# cmserver bin
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_cmserver_SRC)
if (ENABLE_MULTIPLE_NODES)
    aux_source_directory(${DIST_PATH}/cm_server TGT_cmserverlD_SRC)
    list(APPEND TGT_cmserver_SRC ${TGT_cmserverlD_SRC})
endif ()

set(CMS_LIB_PATHS
        ${PGPORT_HOME}
        ${CJSON_DIRECTORY_LIB}
        ${CGROUP_DIRECTORY_LIB}
        ${DCC_ALL_LIBS}
        ${ETCD_DIRECTORY_LIB}
        )

set(CMS_LINK_LIBS cmprotocol_static cmpq_static cmclient_static ${HOTPATCH_LIBS}
        config_static cmcommon_static pthread cjson alarmclient_static ${CM_ADPT_LIBS} securec m dl ${G_BIN_EXT_LIBS})
if (ENABLE_MULTIPLE_NODES)
    set(CMS_LINK_LIBS ${CMS_LINK_LIBS} cgroup)
endif ()

if (ENABLE_KRB)
    list(APPEND CMS_LINK_LIBS ${KRB_LIBS})
endif ()

if (ENABLE_HOTPATCH)
    list(APPEND CMS_LIB_PATHS ${3RD_HOTPATCH_LIB})
    list(APPEND CMS_LINK_LIBS doprapatch)
endif ()

link_directories(${CMS_LIB_PATHS})


if (ENABLE_UT)
    add_shared_tgt(utcmserver TGT_cmserver_SRC "")
    target_link_libraries(utcmserver ${CMS_LINK_LIBS})
    target_link_options(utcmserver PRIVATE ${HOTPATCH_ATOMIC_LDS})
    install(TARGETS utcmserver LIBRARY DESTINATION lib)
else ()
    add_exec_tgt(cm_server TGT_cmserver_SRC "")
    target_link_libraries(cm_server PRIVATE ${CMS_LINK_LIBS})
    target_link_options(cm_server PRIVATE ${HOTPATCH_ATOMIC_LDS})

    if (ENABLE_HOTPATCH)
        add_custom_command(TARGET cm_server POST_BUILD
                COMMAND ${3RD_HOTPATCH_TOOL}/makepatch -CHECK -CRC ${CMAKE_CURRENT_BINARY_DIR}/cm_server > crc.log
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    endif ()

    install(TARGETS cm_server RUNTIME DESTINATION bin)
endif ()


if (ENABLE_MULTIPLE_NODES)
    install(FILES cm_server.conf.sample DESTINATION share/config)
else ()
    if (ENABLE_LIBPQ)
        install(FILES cm_server.centralized.conf.sample DESTINATION share/config RENAME cm_server.conf.sample)
    else ()
        install(FILES cm_server.centralized_new.conf.sample DESTINATION share/config RENAME cm_server.conf.sample)
    endif ()
endif ()
