find_path(
  PAM_INCLUDE_DIR
  NAMES pam_appl.h
  PATH_SUFFIXES security pam)

find_library(PAM_LIBRARY pam)
