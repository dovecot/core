#ifndef ACL_BACKEND_VFILE_H
#define ACL_BACKEND_VFILE_H

#include "acl-api-private.h"
#include "mail-storage-private.h"

#define ACL_FILENAME "dovecot-acl"

#define ACL_VFILE_VALIDITY_MTIME_NOTFOUND 0
#define ACL_VFILE_VALIDITY_MTIME_NOACCESS -1

struct acl_vfile_validity {
	time_t last_check;

	time_t last_read_time;
	time_t last_mtime;
	/* microseconds of last_mtime, for the rights cache */
	unsigned int last_mtime_usecs;
	off_t last_size;
};

struct acl_backend_vfile_validity {
	struct acl_vfile_validity global_validity, local_validity;
};

struct acl_object_vfile {
	struct acl_object aclobj;

	char *local_path;
	bool failed:1;
};

#define ACL_RIGHTS_CACHE_LOCK_TIMEOUT_SECS 5

struct acl_backend_vfile {
	struct acl_backend backend;

	unsigned int cache_secs;
	/* how long a rights cache update waits for a concurrent writer */
	unsigned int rights_cache_lock_timeout_secs;
	bool rebuilding_aclcache:1;
	bool iterating_aclcache:1;
};

void acl_vfile_write_rights_list(string_t *dest, const char *const *rights);
int acl_backend_vfile_object_update(struct acl_object *aclobj,
				    const struct acl_rights_update *update);

struct acl_mailbox_list_context *
acl_backend_vfile_nonowner_iter_init(struct acl_backend *backend);
bool acl_backend_vfile_nonowner_iter_next(struct acl_mailbox_list_context *ctx,
					 const char **name_r);
int
acl_backend_vfile_nonowner_iter_deinit(struct acl_mailbox_list_context *ctx);
int acl_backend_vfile_nonowner_lookups_rebuild(struct acl_backend *backend,
					       bool fetch_all);
int acl_backend_vfile_nonowner_lookups_rename(struct acl_backend *backend,
					      const char *name,
					      struct acl_backend *dest_backend,
					      const char *dest_name);

int acl_backend_vfile_object_get_mtime(struct acl_object *aclobj,
				       struct timeval *mtime_r);

/* Read the mailbox's dovecot-acl file into rights_r without going through
   the ACL object refresh (no acl_cache or configuration ACL side effects).
   pool must not be a data stack pool - the lines are parsed inside a
   nested data stack frame. Returns 1 if the file was read, 0 if there is
   no (readable) local ACL file and -1 on error. */
int acl_backend_vfile_object_read_rights(struct acl_object *aclobj,
					 pool_t pool,
					 ARRAY_TYPE(acl_rights) *rights_r,
					 struct timeval *mtime_r);

#endif
