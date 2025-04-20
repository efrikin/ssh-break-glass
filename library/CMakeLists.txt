set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(${CMAKE_PROJECT_NAME} STATIC ${CMAKE_PROJECT_NAME}.h
                                         ${CMAKE_PROJECT_NAME}.c)
