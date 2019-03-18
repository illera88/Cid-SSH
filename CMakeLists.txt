cmake_minimum_required(VERSION 2.8)
project(SSHIUU)

set(SSHIUU_SOURCE_FILES 
    src/SSHIUU.cpp
    src/server.cpp
    src/socks_proxy.c
    src/sts_queue.c
    #src/client.cpp
)

SET(SSHIUU_HEADER_FILES
    src/server.h
    src/socks_proxy.h
    src/sts_queue.h
    #src/client.h
)

add_executable(SSHIUU ${SSHIUU_SOURCE_FILES} ${SSHIUU_HEADER_FILES})

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    #ToDo
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    #g++ -static SSHIUU.cpp server.cpp /usr/local/lib/libssh.a /usr/local/lib/libcrypto.a /usr/lib/x86_64-linux-gnu/libutil.a -ldl -pthread -Wl,--whole-archive -lpthread -Wl,--no-whole-archive
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")
    target_link_libraries(SSHIUU "/usr/local/lib/libssh.a")
    target_link_libraries(SSHIUU "/usr/local/lib/libcrypto.a")
    # Not sure why cmake tries to use -lutil if I don't specific the -Wl,-Bstatic
    target_link_libraries(SSHIUU "-Wl,-Bstatic /usr/lib/x86_64-linux-gnu/libutil.a")
    # This is the way to link pthread statically
    target_link_libraries(SSHIUU "-pthread -Wl,--whole-archive -lpthread -Wl,--no-whole-archive")
    target_link_libraries(SSHIUU "-ldl")
    target_compile_definitions(SSHIUU PRIVATE "-DHAVE_PTHREAD")
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
endif()

if(${CMAKE_BUILD_TYPE} MATCHES "Debug")
    target_compile_definitions(SSHIUU PRIVATE "-DIS_DEBUG")
else() # Release by default
    # Strip the binary
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s")
endif()