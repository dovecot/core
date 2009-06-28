#ifndef EACCES_ERROR_H
#define EACCES_ERROR_H

/* Return a user-friendly error message for EACCES failures. */
const char *eacces_error_get(const char *func, const char *path);
const char *eacces_error_get_creating(const char *func, const char *path);
/* Return a user-friendly error message for fchown() or chown() EPERM
   failures when only the group is being changed. gid_origin specifies why
   exactly this group is being used. */
const char *eperm_error_get_chgrp(const char *func, const char *path,
				  gid_t gid, const char *gid_origin);

#endif
