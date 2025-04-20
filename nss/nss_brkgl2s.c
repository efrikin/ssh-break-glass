#include <nss.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "brkgl2s.h"

/* Temporary user creation*/
enum nss_status
_nss_brkgl2s_getpwnam_r (const char *name, struct passwd *p, char *buffer,
                         size_t buflen, int *errnop)
{
  uid_t uid = 0;
  struct passwd pw;

  /* Do not pass the returned pointer to free(3).
     Source: man 3 getpwnam_r */
  char *home = (char *)malloc (strlen (HOME) + strlen (name) + 1);

  if (!home)
    {
      syslog (LOG_ERR, "allocation memory error");
      return NSS_STATUS_RETURN;
    }

  if (!get_proc_by_pid ())
    {
      syslog (LOG_ERR, "getting PID service error");
      free (home);
      return NSS_STATUS_RETURN;
    }

  /* Does the user contain "break-glass" prefix ?*/
  if (!check_username ((char *)name))
    {
      syslog (LOG_ERR, "%s must be a break-glass user", name);
      free (home);
      return NSS_STATUS_RETURN;
    }

  srand (time (NULL));
  uid = (rand () % (UID_MAX - UID_MIN + 1)) + UID_MIN;

  /* Random UID alocation */
  while (getpwuid (uid) != NULL)
    uid++;

  /* Path to home directory */
  strcpy (home, HOME);
  strcat (home, name);

  pw.pw_dir = (char *)home;
  pw.pw_gecos = (char *)USER_GECOS;
  pw.pw_name = (char *)name;
  pw.pw_passwd = (char *)USER_DEFAULT_PASSWD;
  pw.pw_gid = uid;
  pw.pw_uid = uid;
  pw.pw_shell = (char *)USER_SHELL;

  /* Creates user and returns them to calling service */
  *p = adduser (&pw);

  syslog (LOG_INFO, "break-glass user %s has been created", p->pw_name);
  return NSS_STATUS_SUCCESS;
}
