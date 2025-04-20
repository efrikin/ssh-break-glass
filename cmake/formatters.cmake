find_program(CLANG_FORMAT "clang-format")
if(CLANG_FORMAT)
  file(GLOB_RECURSE ALL_CXX_SOURCE_FILES ${PROJECT_SOURCE_DIR}/*.[ch])

  add_custom_target(
    clang-format COMMAND clang-format -i -style=file:../.clang-format
                         ${ALL_CXX_SOURCE_FILES})
endif()

find_program(CMAKE_FORMAT "cmake-format")
if(CMAKE_FORMAT)
  file(GLOB_RECURSE ALL_CXX_SOURCE_FILES ${PROJECT_SOURCE_DIR}/CMakeLists.txt)

  add_custom_target(cmake-format COMMAND cmake-format ${ALL_CXX_SOURCE_FILES})
endif()
