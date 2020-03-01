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

if((DEFINED WITH_WEBSOCKETS AND WITH_WEBSOCKETS) OR (DEFINED WITH_WSPROXY AND WITH_WSPROXY))
    add_subdirectory(beastsocks)
endif()
