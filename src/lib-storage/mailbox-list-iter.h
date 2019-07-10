#ifndef MAILBOX_LIST_ITER_H
#define MAILBOX_LIST_ITER_H

#include "mail-namespace.h"
#include "mailbox-list.h"

enum mailbox_list_iter_flags {
	/* Ignore index file and ACLs (used by ACL plugin internally) */
	MAILBOX_LIST_ITER_RAW_LIST		= 0x000001,
	/* Don't list autocreated mailboxes (e.g. INBOX) unless they
	   physically exist */
	MAILBOX_LIST_ITER_NO_AUTO_BOXES		= 0x000004,

	/* Skip all kinds of mailbox aliases. This typically includes symlinks
	   that point to the same directory. Also when iterating with
	   mailbox_list_iter_init_namespaces() skip namespaces that
	   have alias_for set. */
	MAILBOX_LIST_ITER_SKIP_ALIASES		= 0x000008,
	/* For mailbox_list_iter_init_namespaces(): '*' in a pattern doesn't
	   match beyond namespace boundary (e.g. "foo*" or "*o" doesn't match
	   "foo." namespace's mailboxes, but "*.*" does). also '%' can't match
	   namespace prefixes, if there exists a parent namespace whose children
	   it matches. */
	MAILBOX_LIST_ITER_STAR_WITHIN_NS	= 0x000010,

	/* List only subscribed mailboxes */
	MAILBOX_LIST_ITER_SELECT_SUBSCRIBED	= 0x000100,
	/* Return MAILBOX_CHILD_* if mailbox's children match selection
	   criteria, even if the mailbox itself wouldn't match. */
	MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH	= 0x000200,
	/* Return only mailboxes that have special use flags */
	MAILBOX_LIST_ITER_SELECT_SPECIALUSE	= 0x000400,

	/* Don't return any flags unless it can be done without cost */
	MAILBOX_LIST_ITER_RETURN_NO_FLAGS	= 0x001000,
	/* Return MAILBOX_SUBSCRIBED flag */
	MAILBOX_LIST_ITER_RETURN_SUBSCRIBED	= 0x002000,
	/* Return children flags */
	MAILBOX_LIST_ITER_RETURN_CHILDREN	= 0x004000,
	/* Return IMAP special use flags */
	MAILBOX_LIST_ITER_RETURN_SPECIALUSE	= 0x008000
};

struct mailbox_info {
	const char *vname;
	const char *special_use;
	enum mailbox_info_flags flags;

	struct mail_namespace *ns;
};

/* Returns a single pattern from given reference and pattern. */
const char *mailbox_list_join_refpattern(struct mailbox_list *list,
					 const char *ref, const char *pattern);

/* Initialize new mailbox list request. Pattern may contain '%' and '*'
   wildcards as defined by RFC-3501. */
struct mailbox_list_iterate_context *
mailbox_list_iter_init(struct mailbox_list *list, const char *pattern,
		       enum mailbox_list_iter_flags flags);
/* Like mailbox_list_iter_init(), but support multiple patterns. Patterns is
   a NULL-terminated list of strings. It must contain at least one pattern. */
struct mailbox_list_iterate_context *
mailbox_list_iter_init_multiple(struct mailbox_list *list,
				const char *const *patterns,
				enum mailbox_list_iter_flags flags);
/* Like mailbox_list_iter_init_multiple(), but list mailboxes from all the
   specified namespaces. If it fails, the error message is set to the first
   namespaces->list. */
struct mailbox_list_iterate_context *
mailbox_list_iter_init_namespaces(struct mail_namespace *namespaces,
				  const char *const *patterns,
				  enum mail_namespace_type type_mask,
				  enum mailbox_list_iter_flags flags);
/* Get next mailbox. Returns the mailbox name */
const struct mailbox_info *
mailbox_list_iter_next(struct mailbox_list_iterate_context *ctx);
/* Deinitialize mailbox list request. Returns -1 if some error
   occurred while listing. The error string can be looked up with
   mailbox_list_get_last_error(). */
int mailbox_list_iter_deinit(struct mailbox_list_iterate_context **ctx);
/* List one mailbox. Returns 1 if info returned, 0 if mailbox doesn't exist,
   -1 if error. */
int mailbox_list_mailbox(struct mailbox_list *list, const char *name,
			 enum mailbox_info_flags *flags_r);
/* Returns 1 if mailbox has children, 0 if not, -1 if error. */
int mailbox_has_children(struct mailbox_list *list, const char *name);

#endif
