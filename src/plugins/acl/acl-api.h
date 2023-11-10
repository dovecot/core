#ifndef ACL_API_H
#define ACL_API_H

#include <sys/stat.h>

#include "acl-rights.h"

struct mailbox_list;
struct mail_storage;
struct mailbox;
struct acl_object;
struct acl_backend;

#define MAILBOX_ATTRIBUTE_PREFIX_ACL \
	MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT"acl/"

int acl_backend_init_auto(struct mailbox_list *list, struct acl_backend **backend_r,
			  const char **error_r);
void acl_backend_deinit(struct acl_backend **backend);

/* Returns the acl_username passed to acl_backend_init(). Note that with
   anonymous users NULL is returned. */
const char *acl_backend_get_acl_username(struct acl_backend *backend);

/* Returns TRUE if user isn't anonymous. */
bool acl_backend_user_is_authenticated(struct acl_backend *backend);
/* Returns TRUE if user owns the storage. */
bool acl_backend_user_is_owner(struct acl_backend *backend);
/* Returns TRUE if given name matches the ACL user name. */
bool acl_backend_user_name_equals(struct acl_backend *backend,
				  const char *username);
/* Returns TRUE if ACL user is in given group. */
bool acl_backend_user_is_in_group(struct acl_backend *backend,
				  const char *group_name);
/* Returns index for the right name. If it doesn't exist, it's created. */
unsigned int acl_backend_lookup_right(struct acl_backend *backend,
				      const char *right);
/* Returns TRUE if acl_rights matches backend user. */
bool acl_backend_rights_match_me(struct acl_backend *backend,
				 const struct acl_rights *rights);

/* List mailboxes that have lookup right to some non-owners. */
struct acl_mailbox_list_context *
acl_backend_nonowner_lookups_iter_init(struct acl_backend *backend);
bool acl_backend_nonowner_lookups_iter_next(struct acl_mailbox_list_context *ctx,
					   const char **name_r);
int
acl_backend_nonowner_lookups_iter_deinit(struct acl_mailbox_list_context **ctx);

/* Force a rebuild for nonowner lookups index */
int acl_backend_nonowner_lookups_rebuild(struct acl_backend *backend);

struct acl_object *acl_object_init_from_name(struct acl_backend *backend,
					     const char *name);
struct acl_object *acl_object_init_from_parent(struct acl_backend *backend,
					       const char *child_name);
void acl_object_deinit(struct acl_object **aclobj);

/* Returns 1 if we have the requested rights, 0 if not, or -1 if internal
   error occurred. */
int acl_object_have_right(struct acl_object *aclobj, unsigned int right_idx);
/* Returns 0 = ok, -1 = internal error */
int acl_object_get_my_rights(struct acl_object *aclobj, pool_t pool,
			     const char *const **rights_r);
/* Returns the default rights for the object. */
const char *const *acl_object_get_default_rights(struct acl_object *aclobj);
/* Returns timestamp of when the ACLs were last changed for this object,
   or 0 = never. */
int acl_object_last_changed(struct acl_object *aclobj, time_t *last_changed_r);

/* Update ACL of given object. */
int acl_object_update(struct acl_object *aclobj,
		      const struct acl_rights_update *update);

/* List all identifiers. */
struct acl_object_list_iter *acl_object_list_init(struct acl_object *aclobj);
bool acl_object_list_next(struct acl_object_list_iter *iter,
			  struct acl_rights *rights_r);
int acl_object_list_deinit(struct acl_object_list_iter **iter);

#endif
