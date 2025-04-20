cmake_minimum_required(VERSION 3.20)

project(brkgl2s LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(macros)
include(variables)
include(formatters)

find_package(PAM REQUIRED)
if(!PAM_FOUND)
  message("Need to install PAM headers")
endif()

find_package(NSS REQUIRED)
if(!NSS_FOUND)
  message("Need to install NSS headers")
endif()

add_compile_options(-Wall -Werror)

set(PARENT_PROJECT_NAME ${PROJECT_NAME})

add_subdirectory(library)

project(
  nss_brkgl2s
  VERSION 0.0.0
  DESCRIPTION "NSS module for creating user"
  LANGUAGES C)

set_install_prefix()
add_subdirectory(nss)

project(
  pam_brkgl2s
  VERSION 0.0.0
  DESCRIPTION "PAM module for ssh break-glass"
  LANGUAGES C)

set_install_prefix()
add_subdirectory(pam)
