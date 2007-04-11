#ifndef __ACL_API_H
#define __ACL_API_H

struct mailbox_list;
struct mail_storage;
struct acl_object;

/* Show mailbox in mailbox list. Allow subscribing to it. */
#define MAIL_ACL_LOOKUP		"lookup"
/* Allow opening mailbox for reading */
#define MAIL_ACL_READ		"read"
/* Allow permanent flag changes (except for seen/deleted).
   If not set, doesn't allow save/copy to set any flags either. */
#define MAIL_ACL_WRITE		"write"
/* Allow permanent seen-flag changes */
#define MAIL_ACL_WRITE_SEEN	"write-seen"
/* Allow permanent deleted-flag changes */
#define MAIL_ACL_WRITE_DELETED	"write-deleted"
/* Allow saving and copying mails into the mailbox */
#define MAIL_ACL_INSERT		"insert"
/* Allow expunging mails */
#define MAIL_ACL_EXPUNGE	"expunge"
/* Allow creating child mailboxes */
#define MAIL_ACL_CREATE		"create"
/* Allow deleting this mailbox */
#define MAIL_ACL_DELETE		"delete"
/* Allow changing ACL state in this mailbox */
#define MAIL_ACL_ADMIN		"admin"

enum acl_id_type {
	/* Anyone's rights, including anonymous's.
	   identifier name is ignored. */
	ACL_ID_ANYONE,
	/* Authenticate users' rights, overrides anyone's rights.
	   identifier name is ignored. */
	ACL_ID_AUTHENTICATED,
	/* Group's rights, overrides authenticated users' rights */
	ACL_ID_GROUP,
	/* User's rights, overrides group's rights */
	ACL_ID_USER,
	/* Same as group's rights, but also overrides user's rights */
	ACL_ID_GROUP_OVERRIDE,

	ACL_ID_TYPE_COUNT
};

enum acl_modify_mode {
	/* Add rights to existing ACL (or create a new one) */
	ACL_MODIFY_MODE_ADD = 0,
	/* Remove rights from existing ACL */
	ACL_MODIFY_MODE_REMOVE,
	/* Replace existing ACL with given rights */
	ACL_MODIFY_MODE_REPLACE
};

struct acl_rights {
	/* Type of the identifier, user/group */
	enum acl_id_type id_type;
	/* Identifier, eg. username / group name */
	const char *identifier;

	/* Rights assigned */
	const char *const *rights;
	/* Negative rights assigned */
	const char *const *neg_rights;

	/* For set: */
	enum acl_modify_mode modify_mode;
	enum acl_modify_mode neg_modify_mode;
};

/* data contains the information needed to initialize ACL backend. If username
   is NULL, it means the user is anonymous. Username and groups are matched
   case-sensitively. */
struct acl_backend *
acl_backend_init(const char *data, struct mailbox_list *list,
		 const char *acl_username, const char *const *groups,
		 const char *owner_username);
void acl_backend_deinit(struct acl_backend **user);
/* Returns TRUE if user isn't anonymous. */
bool acl_backend_user_is_authenticated(struct acl_backend *backend);
/* Returns TRUE if given name matches the ACL user name. */
bool acl_backend_user_name_equals(struct acl_backend *backend,
				  const char *username);
/* Returns TRUE if ACL user is in given group. */
bool acl_backend_user_is_in_group(struct acl_backend *backend,
				  const char *group_name);
/* Returns index for the right name. If it doesn't exist, it's created. */
unsigned int acl_backend_lookup_right(struct acl_backend *backend,
				      const char *right);

struct acl_object *acl_object_init_from_name(struct acl_backend *backend,
					     struct mail_storage *storage,
					     const char *name);
void acl_object_deinit(struct acl_object **aclobj);

/* Returns 1 if we have the requested rights, 0 if not, or -1 if internal
   error occurred. */
int acl_object_have_right(struct acl_object *aclobj, unsigned int right_idx);
/* Returns 0 = ok, -1 = internal error */
int acl_object_get_my_rights(struct acl_object *aclobj, pool_t pool,
			     const char *const **rights_r);

/* Update ACL of given object. */
int acl_object_update(struct acl_object *aclobj,
		      const struct acl_rights *rights);

/* List all identifiers. */
struct acl_object_list_iter *acl_object_list_init(struct acl_object *aclobj);
int acl_object_list_next(struct acl_object_list_iter *iter,
                         struct acl_rights *rights_r);
void acl_object_list_deinit(struct acl_object_list_iter *iter);

#endif
