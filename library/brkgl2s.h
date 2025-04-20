/* Unused range in systemd for dynamic break-glass users

Source: https://systemd.io/UIDS-GIDS/ */
#define UID_MIN 60578
#define UID_MAX 61183

#define PASSWD_FILE "/etc/passwd"
#define USERNAME_POSTFIX ".brkgl2s"

#define USER_SHELL "/bin/bash"
#define USER_GECOS "Break-Glass User"

/* If the password field contains some string that is not a valid result of
   crypt(3), for instance ! or *, the user will not be able to use a unix
   password to log in (but the user may log in the system by other means).

Source: man 5 shadow */
#define USER_DEFAULT_PASSWD "!"
#define USER_HOMEDIR_PREFIX "/home"

#define SUDO_PATH "/etc/sudoers.d/"
#define SUDO_GROUP_ADMIN "ALL=(ALL) NOPASSWD: ALL"

/* Macros implements concatenation two strings

Input:
  s1: /home
  s2: .brkgl2s
Output: /home/.brkgl2s/ */
#define CONCAT(s1, s2) (s1 "/" s2 "/")
#define HOME CONCAT (USER_HOMEDIR_PREFIX, USERNAME_POSTFIX)

// clang-format off
/* The environment variable stores authentication information
   to PAM (e.g. pubkey).

Source: https://github.com/openssh/openssh-portable/blob/953fa5b59afb04c3c74ed82d7bace65c13cd8baa/auth-pam.c#L778-L796 */
// clang-format on
#define SSH_AUTH_INFO "SSH_AUTH_INFO_0"

#define WELCOME "\033[1;31m\nYou entered to Break-Glass mode\n\n\033[0m"

/* Implemets noop operator */
#define pass (void)0

struct pubkey_info
{
  int isCert;
  char *version;
  char *environment;
  char *sudo_group;
};

struct passwd adduser (struct passwd *p);

int deluser (struct passwd *p);

int get_proc_by_pid ();

int check_username (char *username);

int check_service (char *service);

int delete_sudoers_file (char *user);

int create_sudoers_file (char *user, char *sudo_group);

int get_pubkey_info (struct pubkey_info *pb, char *pubkey, int len);

char *get_pubkey (char *pb, int len);

char *trim (char *s, int pos);
