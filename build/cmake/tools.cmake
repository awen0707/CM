# defination of compile and link functions to avoid some repeated actions.

function(add_exec_tgt TGT_NAME TGT_SRC_LIST TGT_INC_LIST)
    add_executable(${TGT_NAME} ${${TGT_SRC_LIST}})
    target_compile_options(${TGT_NAME} PRIVATE -fPIE)
    target_link_options(${TGT_NAME} PRIVATE -pie)
    #IF (TGT_INC_LIST)
    target_include_directories(${TGT_NAME} PUBLIC ${${TGT_INC_LIST}})
    #ENDIF ()
endfunction(add_exec_tgt)

function(add_static_tgt TGT_NAME TGT_SRC_LIST TGT_INC_LIST)
    add_library(${TGT_NAME}_static STATIC ${${TGT_SRC_LIST}})
    target_compile_options(${TGT_NAME}_static PRIVATE -fPIC)
    #IF (TGT_INC_LIST)
    target_include_directories(${TGT_NAME}_static PUBLIC ${${TGT_INC_LIST}})
    #ENDIF ()
    set_target_properties(${TGT_NAME}_static PROPERTIES OUTPUT_NAME ${TGT_NAME})
endfunction(add_static_tgt)

function(add_static_objtgt TGT_NAME TGT_SRC_LIST TGT_INC_LIST)
    add_library(${TGT_NAME} OBJECT ${${TGT_SRC_LIST}})
    target_compile_options(${TGT_NAME} PRIVATE -fPIC)
    #IF (TGT_INC_LIST)
    target_include_directories(${TGT_NAME} PUBLIC ${${TGT_INC_LIST}})
    #ENDIF ()
endfunction(add_static_objtgt)

function(add_shared_tgt TGT_NAME TGT_SRC_LIST TGT_INC_LIST)
    add_library(${TGT_NAME} SHARED ${${TGT_SRC_LIST}})
    # TARGET_LINK_OPTIONS(${TGT_NAME} PRIVATE xxx)
    target_compile_options(${TGT_NAME} PRIVATE -fPIC)
    #IF (TGT_INC_LIST)
    target_include_directories(${TGT_NAME} PUBLIC ${${TGT_INC_LIST}})
    #ENDIF ()
    set_target_properties(${TGT_NAME} PROPERTIES VERSION ${G_LIB_VERSION})
endfunction(add_shared_tgt)

function(install_static_libs LIB_PATH LIB_PARTTEN)
    execute_process(
            COMMAND sh -c "A=`ls -m ${LIB_PATH}/${LIB_PARTTEN}`;echo $A | sed -e 's/, /;/g'"
            OUTPUT_VARIABLE INSTALL_FILES OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    install(FILES ${INSTALL_FILES} DESTINATION lib)
endfunction(install_static_libs)

function(not_support OPTS)
    if (${OPTS})
        MESSAGE(FATAL_ERROR " The option ${OPTS} is not supported thus should be turned off.")
    endif ()
endfunction(not_support)

function(must_support OPTS)
    if (NOT ${OPTS})
        MESSAGE(FATAL_ERROR " The option ${OPTS} is not supported thus should be turned off.")
    endif ()
endfunction(must_support)
