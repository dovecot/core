#ifndef ACL_RIGHTS_CACHE_H
#define ACL_RIGHTS_CACHE_H

#include "acl-api.h"

#define ACL_RIGHTS_CACHE "acl-rights.cache"

struct acl_backend_vfile;
struct acl_rights_cache_file;

struct acl_rights_cache_file *
acl_rights_cache_file_init(struct acl_backend *backend);
void acl_rights_cache_file_deinit(struct acl_rights_cache_file **_file);

/* Read the ACL rights cache into memory. Returns 1 if the cache was loaded,
   0 if there is no cache file (the entries loaded earlier are forgotten)
   and -1 on error. */
int acl_rights_cache_file_refresh(struct acl_rights_cache_file *file);

/* Returns TRUE and the mtime stored for the mailbox's cache entry, FALSE if
   the mailbox has no entry. */
bool acl_rights_cache_file_get_mtime(struct acl_rights_cache_file *file,
				     const char *name, struct timeval *mtime_r);

/* Append the cached ACL rights of the mailbox to rights_r, allocated from
   pool. The cache must already have been refreshed. */
void acl_rights_cache_file_get(struct acl_rights_cache_file *file,
			       const char *name, pool_t pool,
			       ARRAY_TYPE(acl_rights) *rights_r);

/* Returns TRUE if there are any cached ACLs for the mailbox name and
   identifier. If identifier is NULL it is ignored. */
bool acl_rights_cache_file_have_any(struct acl_rights_cache_file *file,
				    const char *name,
				    const char *identifier);

/* Returns 1 if the cache file exists, 0 if it doesn't and -1 on error. */
int acl_rights_cache_file_exists(struct acl_rights_cache_file *file);

#endif
