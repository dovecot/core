#ifndef ACL_API_PRIVATE_H
#define ACL_API_PRIVATE_H

#include "acl-api.h"

#define ACL_ID_NAME_ANYONE "anyone"
#define ACL_ID_NAME_AUTHENTICATED "authenticated"
#define ACL_ID_NAME_OWNER "owner"
#define ACL_ID_NAME_USER_PREFIX "user="
#define ACL_ID_NAME_GROUP_PREFIX "group="
#define ACL_ID_NAME_GROUP_OVERRIDE_PREFIX "group-override="

struct acl_backend_vfuncs {
	struct acl_backend *(*alloc)(void);
	int (*init)(struct acl_backend *backend, const char *data);
	void (*deinit)(struct acl_backend *backend);

	struct acl_mailbox_list_context *
		(*nonowner_lookups_iter_init)(struct acl_backend *backend);
	int (*nonowner_lookups_iter_next)(struct acl_mailbox_list_context *ctx,
					  const char **name_r);
	void (*nonowner_lookups_iter_deinit)
		(struct acl_mailbox_list_context *ctx);
	int (*nonowner_lookups_rebuild)(struct acl_backend *backend);

	struct acl_object *(*object_init)(struct acl_backend *backend,
					  const char *name);
	struct acl_object *(*object_init_parent)(struct acl_backend *backend,
						 const char *child_name);
	void (*object_deinit)(struct acl_object *aclobj);

	int (*object_refresh_cache)(struct acl_object *aclobj);
	int (*object_update)(struct acl_object *aclobj,
			     const struct acl_rights_update *update);

	struct acl_object_list_iter *
		(*object_list_init)(struct acl_object *aclobj);
	int (*object_list_next)(struct acl_object_list_iter *iter,
				struct acl_rights *rights_r);
	void (*object_list_deinit)(struct acl_object_list_iter *iter);
};

struct acl_backend {
	pool_t pool;
	const char *username;
	const char **groups;
	unsigned int group_count;

	struct mailbox_list *list;
	struct acl_cache *cache;

	struct acl_object *default_aclobj;
	struct acl_mask *default_aclmask;
	const char *const *default_rights;

	struct acl_backend_vfuncs v;

	unsigned int owner:1;
	unsigned int debug:1;
};

struct acl_mailbox_list_context {
	struct acl_backend *backend;
};

struct acl_object {
	struct acl_backend *backend;
	char *name;
};

struct acl_object_list_iter {
	struct acl_object *aclobj;

	unsigned int idx;
	unsigned int failed:1;
};

extern const char *const all_mailbox_rights[];

const char *const *
acl_backend_mask_get_names(struct acl_backend *backend,
			   const struct acl_mask *mask, pool_t pool);
int acl_backend_get_default_rights(struct acl_backend *backend,
				   const struct acl_mask **mask_r);
void acl_rights_write_id(string_t *dest, const struct acl_rights *right);
bool acl_rights_has_nonowner_lookup_changes(const struct acl_rights *rights);

int acl_identifier_parse(const char *line, struct acl_rights *rights);

#endif
