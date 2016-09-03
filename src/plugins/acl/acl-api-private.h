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
	const char *username;
	const char **groups;
	unsigned int group_count;

	struct mailbox_list *list;
	struct acl_cache *cache;
	struct acl_global_file *global_file;

	struct acl_object *default_aclobj;
	struct acl_mask *default_aclmask;
	const char *const *default_rights;

	struct acl_backend_vfuncs v;

	bool owner:1;
	bool debug:1;
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
void acl_rights_write_id(string_t *dest, const struct acl_rights *right);
bool acl_rights_has_nonowner_lookup_changes(const struct acl_rights *rights);

int acl_identifier_parse(const char *line, struct acl_rights *rights);
int acl_rights_update_import(struct acl_rights_update *update,
			     const char *id, const char *const *rights,
			     const char **error_r);
const char *acl_rights_export(const struct acl_rights *rights);
int acl_rights_parse_line(const char *line, pool_t pool,
			  struct acl_rights *rights_r, const char **error_r);
void acl_rights_dup(const struct acl_rights *src,
		    pool_t pool, struct acl_rights *dest_r);
int acl_rights_cmp(const struct acl_rights *r1, const struct acl_rights *r2);
void acl_rights_sort(struct acl_object *aclobj);

const char *const *
acl_right_names_parse(pool_t pool, const char *acl, const char **error_r);
void acl_right_names_write(string_t *dest, const char *const *rights);
void acl_right_names_merge(pool_t pool, const char *const **destp,
			   const char *const *src, bool dup_strings);
bool acl_right_names_modify(pool_t pool,
			    const char *const **rightsp,
			    const char *const *modify_rights,
			    enum acl_modify_mode modify_mode);
void acl_object_rebuild_cache(struct acl_object *aclobj);
void acl_object_remove_all_access(struct acl_object *aclobj);
void acl_object_add_global_acls(struct acl_object *aclobj);

#endif
