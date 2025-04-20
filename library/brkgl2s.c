#define _GNU_SOURCE
#include <errno.h>
#include <ftw.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "brkgl2s.h"

static const char *default_version = "ssh_v1";
static const char *default_sudo_group = "users";

static char *cmd[] = { "ssh-keygen", "-L", "-f-", NULL };

// clang-format off
/* Where to start and stop deletion into /etc/password.

Source: https://git.busybox.net/busybox/tree/loginutils/deluser.c?h=0_60_4#n33 */
// clang-format on
typedef struct
{
  size_t start;
  size_t stop;
} Bounds;

// clang-format off
/* An interesting side-effect of boundary()'s implementation is that the first
   user (typically root) cannot be removed. Let's call it a feature.

Source: https://git.busybox.net/busybox/tree/loginutils/deluser.c?h=0_60_4#n39 */
// clang-format on
static inline Bounds
boundary (const char *buffer, const char *login)
{
  char needle[256];
  char *start;
  char *stop;
  Bounds b;

  snprintf (needle, 256, "\n%s:", login);
  needle[255] = 0;
  start = strstr (buffer, needle);
  if (!start)
    {
      b.start = 0;
      b.stop = 0;
      return b;
    }
  start++;

  stop = index (start, '\n'); /* index is a BSD-ism */
  b.start = start - buffer;
  b.stop = stop - buffer;
  return b;
}

// clang-format off
/* grep -v ^login (except it only deletes the first match)
   ...in fact, I think I'm going to simplify this later.

Source: https://git.busybox.net/busybox/tree/loginutils/deluser.c?h=0_60_4#n65 */
// clang-format on
int
del_line_matching (const char *login, const char *filename)
{
  char *buffer;
  FILE *passwd;
  size_t len;
  Bounds b;
  struct stat statbuf;

  /* load into buffer */
  passwd = fopen (filename, "r");
  if (!passwd)
    {
      return 1;
    }
  stat (filename, &statbuf);
  len = statbuf.st_size;
  buffer = (char *)malloc (len * sizeof (char));

  if (!buffer)
    {
      fclose (passwd);
      return 1;
    }
  fread (buffer, len, sizeof (char), passwd);

  fclose (passwd);

  /* find the user to remove */
  b = boundary (buffer, login);
  if (b.stop == 0)
    {
      free (buffer);
      return 1;
    }

  /* write the file w/o the user */
  passwd = fopen (filename, "w");
  if (!passwd)
    {
      return 1;
    }
  fwrite (buffer, (b.start - 1), sizeof (char), passwd);
  fwrite (&buffer[b.stop], (len - b.stop), sizeof (char), passwd);

  fclose (passwd);

  return 0;
}

// clang-format off
/* Source: https://sourceware.org/git/?p=glibc.git;a=blob;f=support/test-container.c;h=ebcc722da5824d9f5c8811a485535d5a41a288ab;hb=HEAD#l409 */
// clang-format on
static int
unlink_cb (const char *fpath, const struct stat *sb, int typeflag,
           struct FTW *ftwbuf)
{
  return remove (fpath);
}

// clang-format off
/* Removes dir recursively.

Input: /path/to/dir
Output:
  True: if dir has been removed
  False: if dir has not been removed
Source: https://sourceware.org/git/?p=glibc.git;a=blob;f=support/test-container.c;h=ebcc722da5824d9f5c8811a485535d5a41a288ab;hb=HEAD#l416 */
// clang-format on
static int
recursive_remove (char *path)
{
  int r = nftw (path, unlink_cb, 1000, FTW_DEPTH | FTW_PHYS);
  if (r == -1)
    return false;
  return true;
}

/* Adds a record about the user into /etc/passwd, creates home directory,
   and changes permissions.
Input:
  struct passwd {
      char    *pw_name;      // username
      char    *pw_passwd;    // user password
      uid_t    pw_uid;       // user ID
      gid_t    pw_gid;       // group ID
      char    *pw_gecos;     // user information
      char    *pw_dir;       // home directory
      char    *pw_shell;     // shell program
  };
Output:
  struct passwd
Source: man getpwent_r */
struct passwd
adduser (struct passwd *p)
{
  struct stat s;
  FILE *fd = fopen (PASSWD_FILE, "a");

  if (fd == NULL)
    return *p;

  if (putpwent (p, fd) == -1)
    return *p;

  fclose (fd);

  if (stat (HOME, &s) && mkdir (HOME, 0755))
    pass;

  if (mkdir (p->pw_dir, 0700))
    pass;

  if (chown (p->pw_dir, p->pw_uid, p->pw_gid))
    pass;

  return *p;
}

/* Removes user and home directory.

Input:
  struct passwd
Output:
  True: if the record about user in /etc/passwd and home directory have been
  removed
  False: if the record about user and home directory have not been removed
Source: man getpwent_r */
int
deluser (struct passwd *p)
{
  if (!del_line_matching (p->pw_name, PASSWD_FILE)
      && recursive_remove (p->pw_dir))
    return true;
  return false;
}

/* Checks username for compliance break-glass mode.

Input:
  username (e.g. test.brkgl2s)
Output:
  True: if username contains .brkgl2s prefix
  False: if username doesn't contain .brkgl2s prefix */
int
check_username (char *username)
{
  if (strstr (username, USERNAME_POSTFIX))
    return true;
  return false;
}

/* Checks service name for compliance break-glass mode.

Input:
  service name (e.g. sshd)
Output:
  True: if service name equals sshd
  False: if service name doesn't equal sshd */
int
check_service (char *service)
{
  if (strstr (service, "sshd") || (strstr (service, "ssh")))
    return true;
  return false;
}

/* Gets PID process of service name which called NSS

Input: -
Output:
  True: if /proc/%s/comm value equals ssh or sshd
  False: if /proc/%s/comm value doesn't equal ssh or sshd */
int
get_proc_by_pid ()
{
  char service[5];
  if (!getenv ("SYSTEMD_EXEC_PID"))
    return false;

  /* The caller must take care not to modify this string.

     Source: man getenv */
  char *pid = getenv ("SYSTEMD_EXEC_PID");
  char *path = (char *)malloc (sizeof (6) + strlen (pid) + sizeof (5) + 1);

  sprintf (path, "/proc/%s/comm", pid);

  FILE *fd = fopen (path, "r");

  if (!fd)
    return false;

  if (fgets (service, sizeof (service), fd))
    {
      if (check_service (service))
        {
          free (path);
          return true;
        }
    }
  free (path);
  return false;
}

/* Trims some char(s) both on the left and right.

Input: Eexample, 1
Output: example */
char *
trim (char *s, int pos)
{
  size_t len = strlen (s);
  if (len > abs (pos))
    {
      if (pos > 0)
        s = s + pos;
      else
        s[len + pos] = 0;
    }
  return s;
}

/* Checks Key ID field in pubkey for comliance
   (e.g version:environment:sudo_group).

Input:
  string (e.g. ssh_v1:dev:users, ssh_v1:users)
Output:
  Number of colon (:)
  ssh_v1:dev:users - two colon
  ssh_v1:users - one colon */
int
check_keyid (char *s)
{
  return *s == '\0' ? 0 : check_keyid (s + 1) + (*s == ':');
}

// clang-format off
/* Removes publickey word from pubkey string. Original string contain publickey
word which causes error while receiving information about pubkey.
(e.g. ssh-key -L -f /path/to/cert)

Input:
  publickey ssh-ed25519-cert-v01@openssh.com AAAA..., 47
Output:
  ssh-ed25519-cert-v01@openssh.com AAAA...
Source: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys */
// clang-format on
char *
get_pubkey (char *pb, int len)
{
  char *dst = (char *)malloc (len + 1);
  strncpy (dst, pb, 9);
  if (!strcmp (dst, "publickey"))
    {
      memmove (pb, pb + 10, len);
      free (dst);
      return pb;
    }
  free (dst);
  return pb;
}

/* Fills gap skipped field either default values or "!" (exclamation mark)
e.g. if pubkey was created with "::" Key ID (ssh-keygen -s id_ca -I ::) then
PAM will process the field as "ssh_v1:!:users"

Input:
  - ::
  - ssh_v1::
  - ssh_v1:dev:
  - ssh_v1:dev:admin
Output:
  - ssh_v1:!:users (version: ssh_v1, sudo_group: users)
  - ssh_v1:!:users (version: ssh_v1, sudo_group: users)
  - ssh_v1:dev:users (version: ssh_v1, sudo_group: users)
  - ssh_v1:dev:admin (version: ssh_v1, sudo_group: admin) */
int
fill_gap_keyid (char *str)
{
  size_t len = strlen (str);
  int isVersionUndef, isSudoUndef;
  if (str[0] == ':')
    isVersionUndef = true;
  if (str[len - 1] == ':')
    isSudoUndef = true;
  for (int i = 0; i < len; i++)
    {
      // printf("%i->%c\n", i, str[i]);
      if (str[i] == ':' && str[i] == str[i - 1])
        {
          size_t prev_size = strlen (str) + 1;
          char *tmp = realloc (str, prev_size + 1);
          if (tmp == NULL)
            return false;
          memmove (&tmp[i + 1], &tmp[i], prev_size - i);
          tmp[i] = '!';
          str = tmp;
        }
    }

  if (isVersionUndef)
    {
      char *tmp = (char *)malloc (strlen (str) + 3);
      strcpy (tmp, default_version);
      strcat (tmp, str);
      char *ptr = realloc (str, sizeof (tmp));
      if (ptr == NULL)
        return false;
      strcpy (ptr, tmp);
      free (tmp);
    }

  if (isSudoUndef)
    {
      char *tmp = (char *)malloc (sizeof (str) + 6);
      strcpy (tmp, str);
      strcat (tmp, default_sudo_group);
      char *ptr = realloc (str, sizeof (tmp));
      if (ptr == NULL)
        return false;
      strcpy (ptr, tmp);
      free (tmp);
    }
  return true;
}

/* Gets certificate info and make processing. The processing can be imagined
   as the following command:
     "echo pubkey | ssh-keygen -L -f- | awk '{if ($1 ~ /Type:/) print $0; \
          else if ($1 ~ /Key/) print $0}'"

Input:
        struct pubkey_info {
                int isCert;
                char *version;
                char *environment;
                char *sudo_group;
        };

        ssh-ed25519-cert-v01@openssh.com AAAA...
Output:
  True: if pubkey type is cert. For example:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Key ID: "ssh_v1::users"

        struct pubkey_info {
                int isCert = true; // pubkey type is cert
                char "ssh_v1";
                char "!";
                char "users";
        };
  False: If pubkey type isn't a certificate then struct will be undefined */
int
get_pubkey_info (struct pubkey_info *pb, char *pubkey, int len)
{
  /* ssh-keygen => PAM */
  int pp1[2];
  /* PAM => ssh-keygen */
  int pp2[2];
  char *token, line[255];

  if (pipe (pp1) == -1)
    return false;

  switch (fork ())
    {
    case 0:
      if (pipe (pp2) == -1)
        return false;
      switch (fork ())
        {
        /* Pubkey is sent to ssh-keygen stdin. In fact this action can be
           imagined as the following command:
             "echo pubkey | ssh-keygen -L -f-" */
        case 0:

          dup2 (pp2[1], STDOUT_FILENO);
          close (pp2[0]);
          close (pp2[1]);
          write (STDOUT_FILENO, pubkey, len);
          /* In order to emulate the end of typing it's necessary to send
             "\n" to stdin and return exit code via execlp.*/
          write (STDOUT_FILENO, "\n", 1);
          execlp ("true", "true", NULL);
          exit (EXIT_SUCCESS);

        /* ssh-keygen reads pubkey from stdin and transfers the result to the
           following programm via pipe. */
        default:
          dup2 (pp2[0], STDIN_FILENO);
          dup2 (pp1[1], STDOUT_FILENO);
          close (pp2[0]);
          close (pp2[1]);
          execvp (cmd[0], cmd);
          exit (EXIT_SUCCESS);
        }
      exit (EXIT_SUCCESS);

    default:
      /* PAM module receives ssh-keygen output and looks up some values.
         For example:

           Type: ssh-ed25519-cert-v01@openssh.com user certificate
           Public key: ED25519-CERT SHA256:XoLe...
           Signing CA: ED25519 SHA256:2whaY... (using ssh-ed25519)
           Key ID: "ssh_v1:dev:users"
           Serial: 1
           Valid: from 2024-12-25T19:06:42 to 2024-12-25T20:07:12
           Principals:
                  test.brkgl2s
           Critical Options: (none)
           Extensions:
                  permit-pty */
      dup2 (pp1[0], STDIN_FILENO);
      close (pp1[0]);
      close (pp1[1]);

      /* PAM reads output line-by-line */
      while (fgets (line, sizeof (line), stdin))
        {
          if (strstr (line, "Type:") && strstr (line, "certificate"))
            pb->isCert = true;
          if (strstr (line, "Key ID:"))
            {
              /* Spaces, tabs, quotes will be removed from Key ID field */
              strcpy (line, trim (line, 17));
              strcpy (line, trim (line, -2));

              /* Currently PAM supports Key ID format such as:
                 version:environment:sudo_group */
              if (check_keyid (line) < 2 || check_keyid (line) > 2)
                return false;
              char *str = (char *)malloc (sizeof (line));
              memmove (str, line, sizeof (line));
              /* If Key ID field has empty subfield(s)
                 then they need to be filled */
              fill_gap_keyid (str);
              strcpy (line, str);
              free (str);
              token = strtok (line, ":");

              /* Gets subfields from Key ID field and the values are saved
                 to struct fields */
              for (int i = 0; token != NULL; i++)
                {
                  switch (i)
                    {
                    case 0:
                      pb->version = malloc (strlen (token) + 1);
                      strcpy (pb->version, token);
                      break;
                    case 1:
                      pb->environment = malloc (strlen (token) + 1);
                      strcpy (pb->environment, token);
                      break;
                    case 2:
                      pb->sudo_group = malloc (strlen (token) + 1);
                      strcpy (pb->sudo_group, token);
                      break;
                    }
                  token = strtok (NULL, ":");
                }
            }
        }
    }
  return true;
}

// clang-format off
/* sudo will read each file in /etc/sudoers.d, skipping file names that end in
"~" or contain a "." character to avoid causing problems with package manager or
editor temporary/backup file

Input:
  user.brkgl2s
Output:
  user_brkgl2s
Source: https://www.sudo.ws/docs/man/1.8.13/sudoers.man/#Including_other_files_from_within_sudoers */
// clang-format on
void
replace_dots_to_underline (char *str)
{
  int i, len;
  len = strlen (str);
  for (i = 0; i < len; i++)
    if (str[i] == '.')
      str[i] = '_';
}

/* Creates sudoers file for some user.
Input:
  user.brkgl2s, admin
Output:
  The /etc/sudoers.d/user_brkgl2s file is created with the following content:
  "ALL=(ALL) NOPASSWD: ALL". If sudo_group is "users" file creating will be
  skipped */
int
create_sudoers_file (char *user, char *sudo_group)
{
  if (strcmp (sudo_group, "users") == 0)
    return false;

  char *usr;
  char *path = (char *)malloc (strlen (SUDO_PATH) + strlen (user) + 1);

  if (path == NULL)
    return false;
  usr = strdup (user);
  replace_dots_to_underline (usr);
  strcpy (path, SUDO_PATH);
  strcat (path, usr);

  FILE *fd = fopen (path, "w+");

  if (!fd)
    return false;

  if (strcmp (sudo_group, "admin") == 0)
    fprintf (fd, "%s\t%s", user, SUDO_GROUP_ADMIN);
  fclose (fd);
  chmod (path, 0440);
  free (path);
  free (usr);
  return true;
}

/* Deletes sudoers file for some user.
Input:
  user.brkgl2s
Output:
  If the /etc/sudoers.d/user_brkgl2s exists It will be deleted */
int
delete_sudoers_file (char *user)
{
  struct stat f;
  char *usr;
  char *path = (char *)malloc (strlen (SUDO_PATH) + strlen (user) + 1);

  if (path == NULL)
    {
      free (path);
      return false;
    }

  usr = strdup (user);
  replace_dots_to_underline (usr);
  strcpy (path, SUDO_PATH);
  strcat (path, usr);

  if (stat (path, &f) == 0)
    remove (path);

  free (path);
  free (usr);
  return true;
}
