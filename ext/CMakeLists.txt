include(ExternalProject)

get_property(LIB64 GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS)

# Add Multi-processor compilation
if(MSVC)
  add_definitions(/MP)
endif()

if ("${LIB64}" STREQUAL "TRUE")
    set(LIBSUFFIX 64)

    if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
        set(LIBSUFFIX "")
    endif()
else()
    set(LIBSUFFIX "")
endif()

set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_MSVC_STATIC_RT TRUE)

ExternalProject_Add(libssh_builder
    GIT_REPOSITORY https://github.com/RedRangerz/libssh.git
    GIT_TAG origin/msvcstatic
    CMAKE_CACHE_ARGS
        -DWITH_GSSAPI:BOOL=OFF
        -DWITH_ZLIB:BOOL=OFF
        -DWITH_SFTP:BOOL=ON
        -DWITH_STATIC_LIB:BOOL=ON
        -DWITH_PCAP:BOOL=OFF
        -DWITH_NACL:BOOL=OFF
        -DWITH_EXAMPLES:BOOL=OFF
        -DWITH_TESTING:BOOL=OFF
        -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
        -DOPENSSL_USE_STATIC_LIBS:BOOL=${OPENSSL_STATIC_LIBS}
        -DOPENSSL_MSVC_STATIC_RT:BOOL=${OPENSSL_MSVC_STATIC_RT}
        -DCMAKE_TOOLCHAIN_FILE:PATH=${CMAKE_TOOLCHAIN_FILE}
        -DVCPKG_TARGET_TRIPLET:STRING=${VCPKG_TARGET_TRIPLET}
        -DOPENSSL_ROOT_DIR:STRING=${OPENSSL_ROOT_DIR}
)

ExternalProject_Get_Property(libssh_builder INSTALL_DIR)

set(LIBSSH_INCLUDE_DIR ${INSTALL_DIR}/include PARENT_SCOPE)
set(LIBSSH_LIB_DIR ${INSTALL_DIR}/lib PARENT_SCOPE)

add_library(libssh STATIC IMPORTED GLOBAL)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set_target_properties(libssh
        PROPERTIES IMPORTED_LOCATION
        ${INSTALL_DIR}/lib/static/ssh.lib
    )
else()
    set_target_properties(libssh
        PROPERTIES IMPORTED_LOCATION
        ${INSTALL_DIR}/lib${LIBSUFFIX}/libssh.a
    )
endif()


if(${WITH_WEBSOCKETS} OR ${WITH_WSPROXY})
add_subdirectory(beastsocks)
endif()
