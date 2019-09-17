cmake_minimum_required(VERSION 3.13)

include(ExternalProject)

#ExternalProject_Add(openssl, )

ExternalProject_Add(libssh_builder
    GIT_REPOSITORY https://github.com/RedRangerz/libssh.git
    GIT_TAG origin/buildfixes
    CMAKE_CACHE_ARGS
        -DWITH_GSSAPI:BOOL=OFF
        -DWITH_ZLIB:BOOL=OFF
        -DWITH_SFTP:BOOL=ON
        -DWITH_STATIC_LIB:BOOL=ON
        -DWITH_PCAP:BOOL=OFF
        -DWITH_NACL:BOOL=OFF
        -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)

ExternalProject_Get_Property(libssh_builder INSTALL_DIR)

set(LIBSSH_INCLUDE_DIR ${INSTALL_DIR}/include PARENT_SCOPE)
set(LIBSSH_LIB_DIR ${INSTALL_DIR}/lib PARENT_SCOPE)

add_library(libssh STATIC IMPORTED GLOBAL)
set_target_properties(libssh PROPERTIES IMPORTED_LOCATION ${INSTALL_DIR}/lib/libssh.a)
