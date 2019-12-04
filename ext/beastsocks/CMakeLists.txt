set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_MSVC_STATIC_RT TRUE)
include(FindOpenSSL)

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

add_library(BeastSocks INTERFACE)
set_target_properties(BeastSocks PROPERTIES EXPORT_NAME BeastSocks)
target_include_directories(BeastSocks
    INTERFACE
        $<INSTALL_INTERFACE:include/beastsocks/>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/>
)
target_compile_features(BeastSocks INTERFACE cxx_std_17)

target_link_libraries(BeastSocks
    INTERFACE
        Boost::boost  # Build with Boost header location
)

include(GNUInstallDirs)
install(DIRECTORY socks/ DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}/beastsocks/
)

