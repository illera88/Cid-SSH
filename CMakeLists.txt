cmake_minimum_required(VERSION 2.8)
project(SSHIUU)

set(SSHIUU_SOURCE_FILES 
    src/SSHIUU.cpp
    src/server.cpp
    src/sts_queue.c
    src/socks_proxy.c
    #src/client.cpp
)

SET(SSHIUU_HEADER_FILES
    src/server.h
    src/sts_queue.h
    src/socks_proxy.h
    src/global.h
    #src/client.h
)

# Options to specify libssh paths
set(LIBSSH_CONFIG_PATH "" CACHE FILEPATH "Path to the config.h libssh configuration file")
if(NOT (LIBSSH_CONFIG_PATH))
    message(FATAL_ERROR "Path required for LIBSSH_CONFIG_PATH")
endif()

set(LIBSSH_INCLUDE_PATH "" CACHE FILEPATH "Path to the config.h libssh configuration file")
if(NOT (LIBSSH_INCLUDE_PATH))
    message(FATAL_ERROR "Path required for LIBSSH_INCLUDE_PATH")
endif()


add_executable(SSHIUU ${SSHIUU_SOURCE_FILES} ${SSHIUU_HEADER_FILES})

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    #ToDo
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    #g++ -static SSHIUU.cpp server.cpp /usr/local/lib/libssh.a /usr/local/lib/libcrypto.a /usr/lib/x86_64-linux-gnu/libutil.a -ldl -pthread -Wl,--whole-archive -lpthread -Wl,--no-whole-archive
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    target_link_libraries(SSHIUU "/usr/local/lib/libssh.a")
    target_link_libraries(SSHIUU "/usr/local/lib/libcrypto.a")
    target_link_libraries(SSHIUU "-Wl,-Bstatic /usr/lib/x86_64-linux-gnu/libutil.a -Wl,-Bdynamic")
    target_link_libraries(SSHIUU "-lpthread")
    target_link_libraries(SSHIUU "-ldl")
    target_compile_definitions(SSHIUU PRIVATE "-DHAVE_PTHREAD")
    
    target_include_directories(SSHIUU PRIVATE ${LIBSSH_CONFIG_PATH}) # for the config.h
    target_include_directories(SSHIUU PRIVATE ${LIBSSH_INCLUDE_PATH})
    # target_include_directories(SSHIUU PRIVATE "/home/foca/shared/libssh-0.8.7/build/") # for the config.h
    # target_include_directories(SSHIUU PRIVATE "/home/foca/shared/libssh-0.8.7/include/")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    #/usr/local/opt/gcc/bin/g++-8 -std=gnu++11 -static-libgcc -static-libstdc++ SSHIUU.cpp server.cpp -I/usr/local/opt/openssl/include/ /usr/local/lib/libssh.a /usr/local/opt/openssl/lib/libcrypto.a -lutil -lpthread
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 -static-libgcc -static-libstdc++")
    # We want to use the gcc installed with brew instead of the system one
    set(CMAKE_C_COMPILER "/usr/local/opt/gcc/bin/gcc-8")
    set(CMAKE_CXX_COMPILER "/usr/local/opt/gcc/bin/g++-8")
    target_include_directories(SSHIUU PRIVATE "/usr/local/opt/openssl/include/")
    target_link_libraries(SSHIUU "/usr/local/lib/libssh.a")
    target_link_libraries(SSHIUU "/usr/local/opt/openssl/lib/libcrypto.a")
    target_link_libraries(SSHIUU "-lutil")
    target_link_libraries(SSHIUU "-lpthread")
    target_compile_definitions(SSHIUU PRIVATE "-DHAVE_PTHREAD")
endif()

if(${CMAKE_BUILD_TYPE} MATCHES "Debug")
    target_compile_definitions(SSHIUU PRIVATE "-DIS_DEBUG")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g -fsanitize=address -lasan")
else() # Release by default
    # Strip the binary
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s")
endif()