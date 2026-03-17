aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_cmsharedisk_SRC)

set(TGT_cmsharedisk_INC ${PROJECT_INC_BASE}/cm/cm_adapter/cm_sharedisk)

add_static_tgt(cmsharedisk TGT_cmsharedisk_SRC TGT_cmsharedisk_INC)


