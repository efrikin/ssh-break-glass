include(GNUInstallDirs)

add_library(${CMAKE_PROJECT_NAME} MODULE ${CMAKE_PROJECT_NAME}.c)

target_include_directories(${CMAKE_PROJECT_NAME}
                           PUBLIC ${PROJECT_SOURCE_DIR}/library)

target_link_libraries(${CMAKE_PROJECT_NAME} ${PARENT_PROJECT_NAME})

set_target_properties(
  ${CMAKE_PROJECT_NAME}
  PROPERTIES VERSION ${CMAKE_PROJECT_VERSION}
             SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
             PREFIX "")

install(
  TARGETS ${CMAKE_PROJECT_NAME}
  LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/security/)
