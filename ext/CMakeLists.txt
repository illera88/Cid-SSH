cmake_minimum_required(VERSION 3.13)

include(ExternalProject)

get_property(LIB64 GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS)


if ("${LIB64}" STREQUAL "TRUE")
    set(LIBSUFFIX 64)

    if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        set(LIBSUFFIX "")
    endif()
else()
    set(LIBSUFFIX "")
endif()


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
        -DOPENSSL_USE_STATIC_LIBS:BOOL=ON
        -DCMAKE_TOOLCHAIN_FILE:PATH=${CMAKE_TOOLCHAIN_FILE}
)

ExternalProject_Get_Property(libssh_builder INSTALL_DIR)

set(LIBSSH_INCLUDE_DIR ${INSTALL_DIR}/include PARENT_SCOPE)
set(LIBSSH_LIB_DIR ${INSTALL_DIR}/lib PARENT_SCOPE)

add_library(libssh STATIC IMPORTED GLOBAL)
set_target_properties(libssh 
    PROPERTIES IMPORTED_LOCATION
    ${INSTALL_DIR}/lib${LIBSUFFIX}/libssh.a
)
