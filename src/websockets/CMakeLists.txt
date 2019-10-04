set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_MSVC_STATIC_RT TRUE)
include(FindOpenSSL)

include(CheckIncludeFileCXX)

# CHECK_INCLUDE_FILE_CXX updates the global CMAKE_CXX_FLAGS
SET(CMAKE_CXX_FLAGS_BAK ${CMAKE_CXX_FLAGS})

CHECK_INCLUDE_FILE_CXX("asio.hpp"
    HAS_ASIO
    "-I${CMAKE_SOURCE_DIR}/ext/asio/asio/include/ -DASIO_STANDALONE"
)
CHECK_INCLUDE_FILE_CXX(
    "websocketpp/client.hpp"
    HAS_WEBSOCKETPP
    "-I${CMAKE_SOURCE_DIR}/ext/websocketpp/ -DASIO_STANDALONE -D_WEBSOCKETPP_CPP11_STL_"
)

if (NOT HAS_ASIO)
    message(FATAL_ERROR
        "Unable to find Boost ASIO headers. Please check git submodule checkout"
    )
endif()

if (NOT HAS_WEBSOCKETPP)
    message(FATAL_ERROR
        "Unable to find WebSocket++ headers. Please check git submodule checkout"
    )
endif()
SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS_BAK})

add_library(WebsocketsWrapper STATIC
    wrapper.cpp
)
set_target_properties(WebsocketsWrapper PROPERTIES EXPORT_NAME WebsocketsWrapper)
target_include_directories(WebsocketsWrapper
    PUBLIC
        $<INSTALL_INTERFACE:include/websocketswrapper/>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
    PRIVATE
        ${CMAKE_SOURCE_DIR}/ext/asio/asio/include/
        ${CMAKE_SOURCE_DIR}/ext/websocketpp/
)
target_compile_features(WebsocketsWrapper PRIVATE cxx_std_17)
target_compile_definitions(WebsocketsWrapper
    PUBLIC
        ASIO_STANDALONE
        _WEBSOCKETPP_CPP11_STL_
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set_target_properties(WebsocketsWrapper PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions (WebsocketsWrapper PUBLIC _WINSOCK_DEPRECATED_NO_WARNINGS)
else()
    set_target_properties(WebsocketsWrapper PROPERTIES LINK_SEARCH_START_STATIC 1)
    set_target_properties(WebsocketsWrapper PROPERTIES LINK_SEARCH_END_STATIC 1)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif()

# Find libraries after we set the LINK_SEARCH_STATIC property
target_link_libraries(WebsocketsWrapper
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
)

include(GNUInstallDirs)
install(TARGETS WebsocketsWrapper EXPORT WebsocketsWrapper-export
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/ DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}/websocketswrapper/
)
