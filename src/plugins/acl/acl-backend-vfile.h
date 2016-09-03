#ifndef ACL_BACKEND_VFILE_H
#define ACL_BACKEND_VFILE_H

#include "acl-api-private.h"

#define ACL_FILENAME "dovecot-acl"
#define ACLLIST_FILENAME "dovecot-acl-list"

#define ACL_VFILE_VALIDITY_MTIME_NOTFOUND 0
#define ACL_VFILE_VALIDITY_MTIME_NOACCESS -1

struct acl_vfile_validity {
	time_t last_check;

	time_t last_read_time;
	time_t last_mtime;
	off_t last_size;
};

struct acl_backend_vfile_validity {
	struct acl_vfile_validity global_validity, local_validity;
	struct acl_vfile_validity mailbox_validity;
};

struct acl_object_vfile {
	struct acl_object aclobj;

	/* if backend->global_file is NULL, assume legacy separate global
	   ACL file per mailbox */
	char *global_path, *local_path;
};

struct acl_backend_vfile_acllist {
	time_t mtime;
	const char *name;
};

struct acl_backend_vfile {
	struct acl_backend backend;
	const char *global_path;

	pool_t acllist_pool;
	ARRAY(struct acl_backend_vfile_acllist) acllist;

	time_t acllist_last_check;
	time_t acllist_mtime;
	unsigned int acllist_change_counter;

	unsigned int cache_secs;
	bool rebuilding_acllist:1;
	bool iterating_acllist:1;
};

void acl_vfile_write_rights_list(string_t *dest, const char *const *rights);
int acl_backend_vfile_object_update(struct acl_object *aclobj,
				    const struct acl_rights_update *update);

void acl_backend_vfile_acllist_refresh(struct acl_backend_vfile *backend);
int acl_backend_vfile_acllist_rebuild(struct acl_backend_vfile *backend);
void acl_backend_vfile_acllist_verify(struct acl_backend_vfile *backend,
				      const char *name, time_t mtime);

struct acl_mailbox_list_context *
acl_backend_vfile_nonowner_iter_init(struct acl_backend *backend);
bool acl_backend_vfile_nonowner_iter_next(struct acl_mailbox_list_context *ctx,
					 const char **name_r);
int
acl_backend_vfile_nonowner_iter_deinit(struct acl_mailbox_list_context *ctx);
int acl_backend_vfile_nonowner_lookups_rebuild(struct acl_backend *backend);

int acl_backend_vfile_object_get_mtime(struct acl_object *aclobj,
				       time_t *mtime_r);

#endif
