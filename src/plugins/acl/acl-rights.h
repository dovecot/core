#ifndef ACL_RIGHTS_H
#define ACL_RIGHTS_H

/* <settings checks> */

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

#define ACL_ID_NAME_ANYONE "anyone"
#define ACL_ID_NAME_AUTHENTICATED "authenticated"
#define ACL_ID_NAME_OWNER "owner"
#define ACL_ID_NAME_USER_PREFIX "user="
#define ACL_ID_NAME_GROUP_PREFIX "group="
#define ACL_ID_NAME_GROUP_OVERRIDE_PREFIX "group-override="

struct acl_letter_map {
	const char letter;
	const char *name;
};

extern const struct acl_letter_map acl_letter_map[];
extern const char *const all_mailbox_rights[];

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
	bool global:1;
};
ARRAY_DEFINE_TYPE(acl_rights, struct acl_rights);

/* </settings checks> */

struct acl_rights_update {
	/* Holder for rights */
	struct acl_rights rights;
	/* Type of modification */
	enum acl_modify_mode modify_mode;
	/* Type of modification for negative rights */
	enum acl_modify_mode neg_modify_mode;

	/* These changes' "last changed" timestamp */
	time_t last_change;
};

/* Returns the canonical ID for the right. */
const char *acl_rights_get_id(const struct acl_rights *right);

/* Append the id name to dest from rights */
void acl_rights_write_id(string_t *dest, const struct acl_rights *right);

/* Returns true if the rights are not for owner, and there is MAIL_ACL_LOOKUP
   right. */
bool acl_rights_has_nonowner_lookup_changes(const struct acl_rights *rights);

/* <settings checks> */
/* Parses identifier from line */
int acl_identifier_parse(const char *line, struct acl_rights *rights);
/* </settings checks> */

int acl_rights_update_import(struct acl_rights_update *update,
			     const char *id, const char *const *rights,
			     const char **error_r);

/* Exports ACL rights to string */
const char *acl_rights_export(const struct acl_rights *rights);

/* <settings checks> */
/* Parses line containing identifier and rights */
int acl_rights_parse_line(const char *line, pool_t pool,
			  struct acl_rights *rights_r, const char **error_r);
/* </settings checks> */

/* Duplicates a right */
void acl_rights_dup(const struct acl_rights *src,
		    pool_t pool, struct acl_rights *dest_r);

/* Comparison for rights */
int acl_rights_cmp(const struct acl_rights *r1, const struct acl_rights *r2);

/* <settings checks> */
/* Parses acl letter string to names */
const char *const *
acl_right_names_parse(pool_t pool, const char *acl, const char **error_r);
/* </settings checks> */

/* Writes acl names to destination string as acl letters */
void acl_right_names_write(string_t *dest, const char *const *rights);

/* Merges ACL names */
void acl_right_names_merge(pool_t pool, const char *const **destp,
			   const char *const *src, bool dup_strings);

/* Modifies ACL rights */
bool acl_right_names_modify(pool_t pool,
			    const char *const **rightsp,
			    const char *const *modify_rights,
			    enum acl_modify_mode modify_mode);
#endif
