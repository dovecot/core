#ifndef IPWD_H
#define IPWD_H

#include <pwd.h>
#include <grp.h>

/* Replacements for standard getpw/gr*(), fixing their ability to report errors
   properly. As with standard getpw/gr*(), second call overwrites data used
   by the first one.

   Functions return 1 if user/group is found, 0 if not or
   -1 if error (with errno set). */

int i_getpwnam(const char *name, struct passwd *pwd_r);
int i_getpwuid(uid_t uid, struct passwd *pwd_r);

int i_getgrnam(const char *name, struct group *grp_r);
int i_getgrgid(gid_t gid, struct group *grp_r);

/* Free memory used by above functions. */
void ipwd_deinit(void);

#endif
