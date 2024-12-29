#define PAM_SM_SESSION
#include <pwd.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syslog.h>

#include "brkgl2s.h"

/* Linux-PAM separates the tasks of authentication into four independent
   management groups: account management; authentication management; password
   management; and session management. In order to configure user's session
   the PAM module must perform the task in the session management group.

Source: man pam */
PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{

  int len;
  char *pubkey, *username, *service;
  struct pubkey_info pb;
  struct passwd *p;

  if (pam_get_item (pamh, PAM_SERVICE, (const void **)&service) != PAM_SUCCESS)
    {
      pam_syslog (pamh, LOG_ERR, "getting PAM service error");
      return PAM_SERVICE_ERR;
    }

  /* Does the service name match ssh or sshd ?*/
  if (!check_service (service))
    {
      pam_syslog (pamh, LOG_ERR, "received %s is not equal ssh(d)", service);
      return PAM_SERVICE_ERR;
    }

  if (pam_get_item (pamh, PAM_USER, (const void **)&username) != PAM_SUCCESS)
    {
      pam_syslog (pamh, LOG_ERR, "getting PAM user error");
      return PAM_AUTH_ERR;
    }

  /* Does the user contain "break-glass" prefix ?*/
  if (!check_username (username))
    {
      pam_syslog (pamh, LOG_ERR, "%s must be a break-glass user", service);
      return PAM_AUTH_ERR;
    }

  /* Do not pass the returned pointer to free(3).

     Source: man 3 getpwnam */
  p = getpwnam (username);

  if (p == NULL)
    {
      pam_syslog (pamh, LOG_ERR, "getting user error");
      return PAM_SESSION_ERR;
    }

  /* Gets pubkey from environment variable.
     The application is not allowed to free the data.

     Source: man 3 pam_getenv */
  pubkey = (char *)pam_getenv (pamh, SSH_AUTH_INFO);

  if (pubkey == NULL)
    {
      pam_syslog (pamh, LOG_ERR, "getting pubkey error");
      return PAM_AUTHINFO_UNAVAIL;
    }

  len = strlen (pubkey);
  /* TODO */
  if (!get_pubkey (pubkey, len))
    {
      pam_syslog (pamh, LOG_ERR, "getting pubkey error");
      return PAM_AUTHINFO_UNAVAIL;
    }

  len = strlen (pubkey);

  pam_syslog (pamh, LOG_INFO, "%s has been used", pubkey);

  /* Gets information such as: pubkey type, Key ID, etc.
     and return struct */
  if (!get_pubkey_info (&pb, pubkey, len))
    return PAM_SESSION_ERR;

  /* If pubkey type is cert then continue */
  if (pb.isCert)
    {
      if (create_sudoers_file (p->pw_name, pb.sudo_group))
        {
          pam_syslog (pamh, LOG_INFO,
                      "sudoers file has been created for %s with %s permission",
                      p->pw_name, pb.sudo_group);
        }
      printf (WELCOME);
      free (pb.version);
      free (pb.environment);
      free (pb.sudo_group);
      pam_syslog (pamh, LOG_INFO, "break-glass session has been started for %s",
                  p->pw_name);
      return PAM_SUCCESS;
    }

  return PAM_SESSION_ERR;
}

/* In order to deconfigure user's session the PAM module must
   perform the task in the session management group.

Source: man pam */
PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc,
                      const char **argv)
{

  char *username;
  struct passwd *p;

  if (pam_get_item (pamh, PAM_USER, (const void **)&username) != PAM_SUCCESS)
    {
      pam_syslog (pamh, LOG_ERR, "getting PAM user error");
      return PAM_AUTH_ERR;
    }

  /* Do not pass the returned pointer to free(3).
     Source: man 3 getpwnam */
  p = getpwnam (username);

  if (p == NULL)
    return PAM_SESSION_ERR;

  if (!(p->pw_uid < UID_MIN || p->pw_uid > UID_MAX))
    {
      if (deluser (p))
        {
          delete_sudoers_file (p->pw_name);
          pam_syslog (pamh, LOG_INFO, "Home directory %s has been removed",
                      p->pw_dir);
          pam_syslog (pamh, LOG_INFO, "Session for %s has been closed",
                      p->pw_name);
          return PAM_SUCCESS;
        }
    }
  return PAM_SESSION_ERR;
}
