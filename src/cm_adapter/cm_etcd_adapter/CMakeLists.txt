set(ADT_ETCD_LIBS alarmclient_static)
if (ENABLE_ETCD)
    aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_cmetcdadapter_SRC)
    list(REMOVE_ITEM TGT_cmetcdadapter_SRC ${CMAKE_CURRENT_SOURCE_DIR}/cm_ddb_etcd_stub.cpp)
    list(APPEND ADT_ETCD_LIBS etcdapi_static)
else ()
    set(TGT_cmetcdadapter_SRC ${CMAKE_CURRENT_SOURCE_DIR}/cm_ddb_etcd_stub.cpp)
    # add stack-protector-all for stub file
    add_compile_options(-fstack-protector-all)
endif ()

add_shared_tgt(cmetcdadapter TGT_cmetcdadapter_SRC "")
add_static_tgt(cmetcdadapter TGT_cmetcdadapter_SRC "")

target_link_libraries(cmetcdadapter ${ADT_ETCD_LIBS})
