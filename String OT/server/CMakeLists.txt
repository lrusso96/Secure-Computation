file(GLOB_RECURSE SRCS *.cpp)                                                                            

include_directories(${CMAKE_SOURCE_DIR})

add_executable(custom_ot_server  ${SRCS})
                                             
target_link_libraries(custom_ot_server libOTe cryptoTools)