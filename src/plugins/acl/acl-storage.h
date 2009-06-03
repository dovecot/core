#ifndef ACL_STORAGE_H
#define ACL_STORAGE_H

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

#endif
