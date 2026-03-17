aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_client_SRC)

set(TGT_client_INC ${PROJECT_INC_BASE}/cm/cm_client)
# other project may dependens on client library use dlopen, so we need to ensure its symbols integrity.
set(TGT_LINK_LIBS pthread cmcommon_static securec ${MEMCHECK_LIBS})

add_link_options(-Wl,--exclude-libs,ALL)

if (ENABLE_UT)
    add_shared_tgt(utcmclient TGT_client_SRC TGT_client_INC)
    target_link_libraries(utcmclient ${TGT_LINK_LIBS})

    install(TARGETS utcmclient LIBRARY DESTINATION lib)
else ()
    add_shared_tgt(client TGT_client_SRC TGT_client_INC)
    add_static_tgt(client TGT_client_SRC TGT_client_INC)
    target_link_libraries(client PRIVATE ${TGT_LINK_LIBS})

    install(TARGETS client LIBRARY DESTINATION lib)
endif ()
