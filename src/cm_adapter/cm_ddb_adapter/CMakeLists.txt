aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_cmddbadapter_SRC)

add_shared_tgt(cmddbadapter TGT_cmddbadapter_SRC "")
add_static_tgt(cmddbadapter TGT_cmddbadapter_SRC "")

set(TGT_ADPT_LIBS cmdccapi_static ${DCC_LIBS})

set(CM_ADPT_LIBS cmddbadapter_static cmdccapi_static ${DCC_LIBS} cmetcdadapter_static cmsdadapter_static CACHE INTERNAL "adapter dependency")
if (ENABLE_ETCD)
    list(APPEND TGT_ADPT_LIBS cmetcdadapter_static)
    set(CM_ADPT_LIBS ${CM_ADPT_LIBS} etcdapi_static CACHE INTERNAL "adapter dependency")
endif ()

target_link_libraries(cmddbadapter ${TGT_ADPT_LIBS})
