aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_cmpq_SRC)

add_static_tgt(cmpq TGT_cmpq_SRC "")
add_shared_tgt(cmpq TGT_cmpq_SRC "")
