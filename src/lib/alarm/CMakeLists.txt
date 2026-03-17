if (ENABLE_ALARM)
    aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TGT_alarmclient_SRC)
    list(REMOVE_ITEM TGT_alarmclient_SRC ${CMAKE_CURRENT_SOURCE_DIR}/alarm_stub.cpp)
    set(ALM_LINK_LIBS securec)
    install(FILES alarmItem.conf DESTINATION bin)
else()
    set(TGT_alarmclient_SRC ${CMAKE_CURRENT_SOURCE_DIR}/alarm_stub.cpp)
endif()

add_static_tgt(alarmclient TGT_alarmclient_SRC "")
target_link_libraries(alarmclient_static ${ALM_LINK_LIBS})

# we always need alarmConfig.conf
install(FILES alarmConfig.conf DESTINATION bin)
