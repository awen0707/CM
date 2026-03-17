aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_cmclient_SRC)

set(TGT_cmclient_INC
        ${PROJECT_INC_BASE}
        ${PROJECT_INC_BASE}/cm
        )

add_static_tgt(cmclient TGT_cmclient_SRC TGT_cmclient_INC)
add_shared_tgt(cmclient TGT_cmclient_SRC TGT_cmclient_INC)

if (ENABLE_KRB)
    install_static_libs(${KRB_HOME}/lib "libcom_err_gauss.so*")
    install_static_libs(${KRB_HOME}/lib "libgssapi_krb5_gauss.so*")
    install_static_libs(${KRB_HOME}/lib "libgssrpc_gauss.so*")
    install_static_libs(${KRB_HOME}/lib "libkrb5_gauss.so*")
    install_static_libs(${KRB_HOME}/lib "libk5crypto_gauss.so*")
    install_static_libs(${KRB_HOME}/lib "libkrb5support_gauss.so*")
endif ()
