cmake_minimum_required(VERSION 3.14)
set(CONTROLLER_SOURCE_FILES 
    main.cpp
    sshpass.c
)

SET(CONTROLLER_HEADER_FILES
    sshpass.h
    VariadicTable.h
)

add_executable(Cid-Controller ${CONTROLLER_SOURCE_FILES} ${CONTROLLER_HEADER_FILES})
target_link_libraries(Cid-Controller -static)
set_property(TARGET Cid-Controller PROPERTY CXX_STANDARD 17)
set_property(TARGET Cid-Controller PROPERTY CXX_STANDARD_REQUIRED ON)
