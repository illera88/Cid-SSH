
### Add a global compilation stuff
if (WIN32)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS=1)
else(WIN32)
  add_definitions(-D_POSIX_C_SOURCE=200112L)
  set(CMAKE_CXX_FLAGS "-fvisibility=hidden ${CMAKE_CXX_FLAGS}")
endif(WIN32)

add_subdirectory(libmodman)

### Modules
include(cmake/modules.cmk)

### Dev files
include(cmake/devfiles.cmk)

### Main library
include(cmake/libproxy.cmk)
