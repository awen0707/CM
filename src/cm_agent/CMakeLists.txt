# cmagent bin
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_cmagent_SRC)
if (ENABLE_MULTIPLE_NODES)
    aux_source_directory(${DIST_PATH}/cm_agent TGT_cmagentD_SRC)
    list(APPEND TGT_cmagent_SRC ${TGT_cmagentD_SRC})
endif ()

set(TGT_cmagent_INC ${ZLIB_DIRECTORY_INC} ${CBB_DIRECTORY_INC})

set(CMA_LIB_PATHS
        ${PGPORT_HOME}
        ${CJSON_DIRECTORY_LIB}
        ${CGROUP_DIRECTORY_LIB}
        ${DCC_ALL_LIBS}
        ${ZLIB_DIRECTORY_LIB}
        ${CBB_DIRECTORY_LIB}
        )

set(CMA_LINK_LIBS cmprotocol_static cmcommon_static cmpq_static cmclient_static m z
        config_static pthread cjson alarmclient_static ${CM_ADPT_LIBS} securec dl ${G_BIN_EXT_LIBS} libcbb.a)

if (ENABLE_LIBPQ)
    aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/client_adpts/libpq TGT_cmagentPQ_SRC)
    list(APPEND TGT_cmagent_SRC ${TGT_cmagentPQ_SRC})
    list(APPEND TGT_cmagent_INC ${PROJECT_INC_BASE}/cm/cm_agent/clients/libpq)
else ()
    aux_source_directory(${DIST_PATH}/cm_agent/client_adpts/script TGT_cmagentS_SRC)
    list(APPEND TGT_cmagent_SRC ${TGT_cmagentS_SRC})
endif ()

if (ENABLE_KRB)
    list(APPEND CMA_LINK_LIBS ${KRB_LIBS} gssrpc_gauss)
endif ()

link_directories(${CMA_LIB_PATHS})

if (ENABLE_UT)
    add_shared_tgt(utcmagent TGT_cmagent_SRC TGT_cmagent_INC)
    target_link_libraries(utcmagent ${CMA_LINK_LIBS})
    install(TARGETS utcmagent LIBRARY DESTINATION lib)
else ()
    add_exec_tgt(cm_agent TGT_cmagent_SRC TGT_cmagent_INC)
    target_link_libraries(cm_agent PRIVATE ${CMA_LINK_LIBS})
    install(TARGETS cm_agent RUNTIME DESTINATION bin)
endif ()

if (ENABLE_MEMCHECK)
    # handle dlopen not found some symbols
    target_link_options(cm_agent PRIVATE -rdynamic)
endif ()

if (ENABLE_MULTIPLE_NODES)
    install(FILES cm_agent.conf.sample DESTINATION share/config)
else ()
    if (ENABLE_LIBPQ)
        install(FILES cm_agent.centralized.conf.sample DESTINATION share/config RENAME cm_agent.conf.sample)
    else ()
        install(FILES cm_agent.centralized_new.conf.sample DESTINATION share/config RENAME cm_agent.conf.sample)
        install(DIRECTORY ${DIST_PATH}/cm_agent/client_adpts/script/cm_script DESTINATION bin)
    endif ()
endif ()

install_static_libs(${ZLIB_DIRECTORY_LIB} "libz.so*")
