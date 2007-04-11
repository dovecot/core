#ifndef __ACL_API_PRIVATE_H
#define __ACL_API_PRIVATE_H

#include "acl-api.h"

struct acl_backend_vfuncs {
	struct acl_backend *(*alloc)(void);
	int (*init)(struct acl_backend *backend, const char *data);
	void (*deinit)(struct acl_backend *backend);

	struct acl_object *(*object_init)(struct acl_backend *backend,
					  struct mail_storage *storage,
					  const char *name);
	void (*object_deinit)(struct acl_object *aclobj);

	int (*object_refresh_cache)(struct acl_object *aclobj);
	int (*object_update)(struct acl_object *aclobj,
			     const struct acl_rights *rights);

	struct acl_object_list_iter *
		(*object_list_init)(struct acl_object *aclobj);
	int (*object_list_next)(struct acl_object_list_iter *iter,
				struct acl_rights *rights_r);
	void (*object_list_deinit)(struct acl_object_list_iter *iter);
};

struct acl_backend {
	pool_t pool;
	const char *username, *owner_username;
	const char **groups;
	unsigned int group_count;

	struct mailbox_list *list;
	struct acl_cache *cache;

	struct acl_object *default_aclobj;
	struct acl_mask *default_aclmask;

	struct acl_backend_vfuncs v;

	unsigned int debug:1;
};

struct acl_object {
	struct acl_backend *backend;
	char *name;
};

struct acl_object_list_iter {
	struct acl_object *aclobj;
};

#endif
