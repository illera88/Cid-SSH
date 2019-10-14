set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_NO_BOOST_CMAKE 1)  # Required on macOS
find_package(Boost 1.70 REQUIRED COMPONENTS system)

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


add_executable(ws_proxy_server ws_proxy_server.cpp)
add_dependencies(ws_proxy_server libssh_builder)

target_include_directories(ws_proxy_server
    PRIVATE
        ${LIBSSH_INCLUDE_DIR}
)

target_compile_features(ws_proxy_server PRIVATE cxx_std_17)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    target_link_libraries(ws_proxy_server Ws2_32.lib)
    set_target_properties(ws_proxy_server PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions (ws_proxy_server PUBLIC _WINSOCK_DEPRECATED_NO_WARNINGS)
endif()

target_link_libraries(ws_proxy_server
    libssh  # Link against libssh
    WebsocketsWrapper  # Link against our WebsocketsWrapper
    Boost::system  # Link against Boost.System
    Boost::boost  # Pull in include directories for Boost
)
