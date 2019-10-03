cmake_minimum_required(VERSION 3.13)

set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_MSVC_STATIC_RT TRUE)
include(FindOpenSSL)

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
