cmake_minimum_required(VERSION 3.10)
project("minim-lnk-parser")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR})

# adds a library from libyal as a global target
function(add_libyal_lib libname)
  include_directories("deps/${libname}/include")
  link_directories("deps/${libname}/${libname}/.libs")
  add_library("${libname}" STATIC IMPORTED GLOBAL)
  set_property(TARGET "${libname}" PROPERTY IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/deps/${libname}/${libname}/.libs/${libname}.so")
endfunction()

add_libyal_lib(liblnk)
add_libyal_lib(libfwsi)
add_libyal_lib(libbfio)

set_property(TARGET liblnk PROPERTY INTERFACE_COMPILE_DEFINITIONS "LIBLNK_HAVE_BFIO")

add_subdirectory(src)
