AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} TGT_cmsdadapter_SRC)

SET(TGT_cmddbsd_INC ${PROJECT_INC_BASE}/cm/cm_adapter)

add_static_objtgt(cmsdadapter_static TGT_cmsdadapter_SRC TGT_cmddbsd_INC)

find_package(ZLIB REQUIRED)
target_link_libraries(cmsdadapter_static cmsharedisk_static ZLIB::ZLIB dl libcbb.a)