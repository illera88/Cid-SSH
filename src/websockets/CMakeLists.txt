set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_MSVC_STATIC_RT TRUE)
include(FindOpenSSL)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_NO_BOOST_CMAKE 1)  # Required on macOS
find_package(Boost 1.70 REQUIRED COMPONENTS system)

# Add Multi-processor compilation
if(MSVC)
  add_definitions(/MP)
endif()

include(CheckIncludeFileCXX)

# CHECK_INCLUDE_FILE_CXX updates the global CMAKE_CXX_FLAGS
set(CMAKE_CXX_FLAGS_BAK ${CMAKE_CXX_FLAGS})

CHECK_INCLUDE_FILE_CXX(
    "boost/beast.hpp"
    HAS_BOOST_BEAST
    "-I${Boost_INCLUDE_DIRS}"
)

if (NOT HAS_BOOST_BEAST)
    message(FATAL_ERROR
        "Verify Boost.Beast is correctly installed"
    )
endif()

CHECK_INCLUDE_FILE_CXX(
    "boost/asio.hpp"
    HAS_BOOST_ASIO
    "-I${Boost_INCLUDE_DIRS}"
)

if (NOT HAS_BOOST_ASIO)
    message(FATAL_ERROR
        "Verify Boost.Asio is correctly installed"
    )
endif()
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS_BAK})

add_library(WebsocketsWrapper STATIC
    acceptor.cpp
    bridge.cpp
    tcpconn.cpp
    uri.cpp
    wrapper.cpp
    wsconn.cpp
)
set_target_properties(WebsocketsWrapper PROPERTIES EXPORT_NAME WebsocketsWrapper)
target_include_directories(WebsocketsWrapper
    PUBLIC
        $<INSTALL_INTERFACE:include/websocketswrapper/>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
)
target_compile_features(WebsocketsWrapper PRIVATE cxx_std_17)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set_target_properties(WebsocketsWrapper PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions (WebsocketsWrapper PUBLIC _WINSOCK_DEPRECATED_NO_WARNINGS _WIN32_WINNT=0x0A00)
else()
    set_target_properties(WebsocketsWrapper PROPERTIES LINK_SEARCH_START_STATIC 1)
    set_target_properties(WebsocketsWrapper PROPERTIES LINK_SEARCH_END_STATIC 1)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif()

# Find libraries after we set the LINK_SEARCH_STATIC property
target_link_libraries(WebsocketsWrapper
    PUBLIC
        OpenSSL::SSL  # Link against OpenSSL
        OpenSSL::Crypto  # Link against OpenSSL's crypto
        Boost::system  # Link against Boost.System
        Boost::boost  # Build with Boost header location
        BeastSocks  # Build with Beast Socks header location
)

include(GNUInstallDirs)
install(TARGETS WebsocketsWrapper EXPORT WebsocketsWrapper-export
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/ DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}/websocketswrapper/
)
