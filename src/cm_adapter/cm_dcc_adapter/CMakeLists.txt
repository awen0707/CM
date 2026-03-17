aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_cmdccapi_SRC)

set(TGT_cmdccapi_INC ${DCC_DIRECTORY_INC})
set(cmdccapi_LIB_PATH ${DCC_DIRECTORY_LIB})

add_static_tgt(cmdccapi TGT_cmdccapi_SRC TGT_cmdccapi_INC)
add_shared_tgt(cmdccapi TGT_cmdccapi_SRC TGT_cmdccapi_INC)

target_link_directories(cmdccapi PUBLIC ${cmdccapi_LIB_PATH})
target_link_libraries(cmdccapi PRIVATE dcc cmprotocol_static)

install(DIRECTORY ${LIB_DCC_HOME}/lib/ DESTINATION lib)

# other
install_static_libs(${LZ4_DIRECTORY_LIB} "liblz4.so*")
install_static_libs(${ZSTD_DIRECTORY_LIB} "libzstd.so*")
