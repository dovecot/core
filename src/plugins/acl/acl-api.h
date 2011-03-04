#ifndef ACL_API_H
#define ACL_API_H

struct mailbox_list;
struct mail_storage;
struct mailbox;
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
/* Allow posting mails to the mailbox (e.g. Sieve fileinto) */
#define MAIL_ACL_POST		"post"
/* Allow expunging mails */
#define MAIL_ACL_EXPUNGE	"expunge"
/* Allow creating child mailboxes */
#define MAIL_ACL_CREATE		"create"
/* Allow deleting this mailbox */
#define MAIL_ACL_DELETE		"delete"
/* Allow changing ACL state in this mailbox */
#define MAIL_ACL_ADMIN		"admin"

/* ACL identifiers in override order */
enum acl_id_type {
	/* Anyone's rights, including anonymous's.
	   identifier name is ignored. */
	ACL_ID_ANYONE,
	/* Authenticate users' rights. identifier name is ignored. */
	ACL_ID_AUTHENTICATED,
	/* Group's rights */
	ACL_ID_GROUP,
	/* Owner's rights, used when user is the storage's owner.
	   identifier name is ignored. */
	ACL_ID_OWNER,
	/* User's rights */
	ACL_ID_USER,
	/* Same as group's rights, but also overrides user's rights */
	ACL_ID_GROUP_OVERRIDE,

	ACL_ID_TYPE_COUNT
};

enum acl_modify_mode {
	/* Remove rights from existing ACL */
	ACL_MODIFY_MODE_REMOVE = 0,
	/* Add rights to existing ACL (or create a new one) */
	ACL_MODIFY_MODE_ADD,
	/* Replace existing ACL with given rights */
	ACL_MODIFY_MODE_REPLACE,
	/* Clear all the rights from an existing ACL */
	ACL_MODIFY_MODE_CLEAR
};

struct acl_rights {
	/* Type of the identifier, user/group */
	enum acl_id_type id_type;
	/* Identifier, eg. username / group name */
	const char *identifier;

	/* Rights assigned. NULL entry can be ignored, but { NULL } means user
	   has no rights. */
	const char *const *rights;
	/* Negative rights assigned */
	const char *const *neg_rights;

	/* These rights are global for all users */
	unsigned int global:1;
};

struct acl_rights_update {
	struct acl_rights rights;

	enum acl_modify_mode modify_mode;
	enum acl_modify_mode neg_modify_mode;
};

/* data contains the information needed to initialize ACL backend. If username
   is NULL, it means the user is anonymous. Username and groups are matched
   case-sensitively. */
struct acl_backend *
acl_backend_init(const char *data, struct mailbox_list *list,
		 const char *acl_username, const char *const *groups,
		 bool owner);
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
int acl_backend_nonowner_lookups_iter_next(struct acl_mailbox_list_context *ctx,
					   const char **name_r);
void
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

/* Update ACL of given object. */
int acl_object_update(struct acl_object *aclobj,
		      const struct acl_rights_update *update);

/* List all identifiers. */
struct acl_object_list_iter *acl_object_list_init(struct acl_object *aclobj);
int acl_object_list_next(struct acl_object_list_iter *iter,
                         struct acl_rights *rights_r);
void acl_object_list_deinit(struct acl_object_list_iter **iter);

#endif
