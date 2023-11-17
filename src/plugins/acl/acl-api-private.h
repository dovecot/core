#ifndef ACL_API_PRIVATE_H
#define ACL_API_PRIVATE_H

#include "acl-api.h"
#include "acl-settings.h"

struct acl_backend_vfuncs {
	const char *name;
	struct acl_backend *(*alloc)(void);
	int (*init)(struct acl_backend *backend, const char **error_r);
	void (*deinit)(struct acl_backend *backend);

	struct acl_mailbox_list_context *
		(*nonowner_lookups_iter_init)(struct acl_backend *backend);
	bool (*nonowner_lookups_iter_next)(struct acl_mailbox_list_context *ctx,
					  const char **name_r);
	int (*nonowner_lookups_iter_deinit)
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
	int (*last_changed)(struct acl_object *aclobj, time_t *last_changed_r);

	struct acl_object_list_iter *
		(*object_list_init)(struct acl_object *aclobj);
	bool (*object_list_next)(struct acl_object_list_iter *iter,
				struct acl_rights *rights_r);
	int (*object_list_deinit)(struct acl_object_list_iter *iter);
};

struct acl_backend {
	pool_t pool;
	const struct acl_settings *set;
	const char *username;

	struct event *event;
	struct mailbox_list *list;
	struct acl_cache *cache;
	struct acl_global_file *global_file;

	struct acl_object *default_aclobj;
	struct acl_mask *default_aclmask;
	const char *const *default_rights;

	const struct acl_backend_vfuncs *v;

	bool owner:1;
};

struct acl_mailbox_list_context {
	struct acl_backend *backend;

	bool empty:1;
	bool failed:1;
	const char *error;
};

struct acl_object {
	struct acl_backend *backend;
	char *name;

	pool_t rights_pool;
	ARRAY_TYPE(acl_rights) rights;
};

struct acl_object_list_iter {
	struct acl_object *aclobj;
	pool_t pool;

	struct acl_rights *rights;
	unsigned int idx, count;

	bool empty:1;
	bool failed:1;
	const char *error;
};

extern const char *const all_mailbox_rights[];
extern struct event_category event_category_acl;
struct acl_object_list_iter *
acl_default_object_list_init(struct acl_object *aclobj);
bool acl_default_object_list_next(struct acl_object_list_iter *iter,
				  struct acl_rights *rights_r);
int acl_default_object_list_deinit(struct acl_object_list_iter *iter);

const char *const *
acl_backend_mask_get_names(struct acl_backend *backend,
			   const struct acl_mask *mask, pool_t pool);
struct acl_object *acl_backend_get_default_object(struct acl_backend *backend);
int acl_backend_get_default_rights(struct acl_backend *backend,
				   const struct acl_mask **mask_r);
void acl_rights_sort(struct acl_object *aclobj);
void acl_object_rebuild_cache(struct acl_object *aclobj);
void acl_object_remove_all_access(struct acl_object *aclobj);
void acl_object_add_global_acls(struct acl_object *aclobj);

int acl_backend_get_mailbox_acl(struct acl_backend *backend,
				struct acl_object *aclobj);

void acl_backend_register(const struct acl_backend_vfuncs *v);
void acl_backend_unregister(const char *name);

#endif
