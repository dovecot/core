#ifndef ACL_BACKEND_VFILE_H
#define ACL_BACKEND_VFILE_H

#include "acl-api-private.h"

#define ACL_FILENAME "dovecot-acl"
#define ACLLIST_FILENAME "dovecot-acl-list"

struct acl_object_vfile {
	struct acl_object aclobj;

	pool_t rights_pool;
	ARRAY_DEFINE(rights, struct acl_rights);

	char *global_path, *local_path;
};

struct acl_backend_vfile_acllist {
	time_t mtime;
	const char *name;
};

struct acl_backend_vfile {
	struct acl_backend backend;
	const char *global_dir;

	pool_t acllist_pool;
	ARRAY_DEFINE(acllist, struct acl_backend_vfile_acllist);

	time_t acllist_last_check;
	time_t acllist_mtime;
	unsigned int acllist_change_counter;

	unsigned int cache_secs;
	unsigned int rebuilding_acllist:1;
	unsigned int iterating_acllist:1;
};

void acl_backend_vfile_acllist_refresh(struct acl_backend_vfile *backend);
int acl_backend_vfile_acllist_rebuild(struct acl_backend_vfile *backend);
void acl_backend_vfile_acllist_verify(struct acl_backend_vfile *backend,
				      const char *name, time_t mtime);

struct acl_mailbox_list_context *
acl_backend_vfile_nonowner_iter_init(struct acl_backend *backend);
int acl_backend_vfile_nonowner_iter_next(struct acl_mailbox_list_context *ctx,
					 const char **name_r);
void
acl_backend_vfile_nonowner_iter_deinit(struct acl_mailbox_list_context *ctx);
int acl_backend_vfile_nonowner_lookups_rebuild(struct acl_backend *backend);

int acl_backend_vfile_object_get_mtime(struct acl_object *aclobj,
				       time_t *mtime_r);

#endif
