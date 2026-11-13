#ifndef ACL_STORAGE_H
#define ACL_STORAGE_H

#include "mail-storage.h"

struct acl_rights_update;
struct acl_backend;

enum acl_storage_rights {
	ACL_STORAGE_RIGHT_LOOKUP,
	ACL_STORAGE_RIGHT_READ,
	ACL_STORAGE_RIGHT_WRITE,
	ACL_STORAGE_RIGHT_WRITE_SEEN,
	ACL_STORAGE_RIGHT_WRITE_DELETED,
	ACL_STORAGE_RIGHT_INSERT,
	ACL_STORAGE_RIGHT_POST,
	ACL_STORAGE_RIGHT_EXPUNGE,
	ACL_STORAGE_RIGHT_CREATE,
	ACL_STORAGE_RIGHT_DELETE,
	ACL_STORAGE_RIGHT_ADMIN,

	ACL_STORAGE_RIGHT_COUNT
};

/* Returns acl_object for the given mailbox. */
struct acl_object *acl_mailbox_get_aclobj(struct mailbox *box);
/* Returns 1 if we have the requested right. If not, returns 0 and sets storage
   error to MAIL_ERROR_PERM. Returns -1 if internal error occurred and also
   sets storage error. */
int acl_mailbox_right_lookup(struct mailbox *box, unsigned int right_idx);

/* Returns TRUE if mailbox has the necessary extra ACL for accessing
   attributes. The caller must have checked the LOOKUP right already. */
bool acl_mailbox_have_extra_attribute_rights(struct mailbox *box);

int acl_mailbox_update_acl(struct mailbox_transaction_context *t,
			   const struct acl_rights_update *update);

int acl_attribute_set(struct mailbox_transaction_context *t,
		      enum mail_attribute_type type, const char *key,
		      const struct mail_attribute_value *value);
int acl_attribute_get(struct mailbox *box,
		      enum mail_attribute_type type, const char *key,
		      struct mail_attribute_value *value_r);
struct mailbox_attribute_iter *
acl_attribute_iter_init(struct mailbox *box, enum mail_attribute_type type,
			const char *prefix);
const char *acl_attribute_iter_next(struct mailbox_attribute_iter *iter);
int acl_attribute_iter_deinit(struct mailbox_attribute_iter *iter);

bool acl_backend_get_root_dir(struct acl_backend *backend,
			      const char **root_dir_r,
			      enum mailbox_list_path_type *type_r);

enum mailbox_list_path_type
mail_storage_get_acl_list_path_type(struct mail_storage *storage);
/* Returns TRUE if the backend's storage has
   MAIL_STORAGE_CLASS_FLAG_CACHED_FILES: a mailbox's ACL file that isn't
   locally available may still exist. */
bool acl_backend_storage_has_cached_files(struct acl_backend *backend);

#endif
