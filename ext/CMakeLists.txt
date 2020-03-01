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

if(WITH_WEBSOCKETS OR WITH_WSPROXY)
    add_subdirectory(beastsocks)
endif()
