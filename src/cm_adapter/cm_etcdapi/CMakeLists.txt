aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_etcdapi_SRC)

set(TGT_cmdccapi_INC ${ETCD_DIRECTORY_INC})

add_shared_tgt(etcdapi TGT_etcdapi_SRC TGT_cmdccapi_INC)
add_static_tgt(etcdapi TGT_etcdapi_SRC TGT_cmdccapi_INC)

target_link_libraries(etcdapi PRIVATE ${ETCD_LIBS})
target_link_libraries(etcdapi_static ${ETCD_LIBS})
