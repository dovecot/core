#ifndef SAFE_MKSTEMP_H
#define SAFE_MKSTEMP_H

/* Create a new file with a given prefix. The string is updated to contain the
   created filename. uid and gid can be (uid_t)-1 and (gid_t)-1 to use the
   defaults. */
int safe_mkstemp(string_t *prefix, mode_t mode, uid_t uid, gid_t gid);
int safe_mkstemp_group(string_t *prefix, mode_t mode,
		       gid_t gid, const char *gid_origin);
/* Append host and PID to the prefix. */
int safe_mkstemp_hostpid(string_t *prefix, mode_t mode, uid_t uid, gid_t gid);
int safe_mkstemp_hostpid_group(string_t *prefix, mode_t mode,
			       gid_t gid, const char *gid_origin);

#endif
