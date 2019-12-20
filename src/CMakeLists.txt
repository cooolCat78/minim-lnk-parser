list(APPEND libs liblnk)

add_executable(LnkParser main.cpp)
target_link_libraries(LnkParser ${libs})
