aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_PROTOCOL_SRC)

add_static_tgt(cmprotocol TGT_PROTOCOL_SRC "")
add_shared_tgt(cmprotocol TGT_PROTOCOL_SRC "")
