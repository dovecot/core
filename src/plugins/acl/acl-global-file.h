#ifndef ACL_GLOBAL_FILE_H
#define ACL_GLOBAL_FILE_H

#include "acl-api.h"

struct acl_global_file *
acl_global_file_init(const char *path, unsigned int refresh_interval_secs,
		     bool debug);
void acl_global_file_deinit(struct acl_global_file **file);

/* Read the global ACLs into memory. */
int acl_global_file_refresh(struct acl_global_file *file);
/* Return stat data for the last refresh. */
void acl_global_file_last_stat(struct acl_global_file *file, struct stat *st_r);

/* Return global ACL rights matching the mailbox name. The file must already
   have been refreshed at least once. */
void acl_global_file_get(struct acl_global_file *file, const char *vname,
			 pool_t pool, ARRAY_TYPE(acl_rights) *rights_r);
/* Returns TRUE if there are any global ACLs matching the mailbox name. */
bool acl_global_file_have_any(struct acl_global_file *file, const char *vname);

#endif
