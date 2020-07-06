#ifndef MAIL_NAMESPACE_H
#define MAIL_NAMESPACE_H

#include "mail-user.h"

struct mail_storage_callbacks;

enum mail_namespace_type {
	MAIL_NAMESPACE_TYPE_PRIVATE	= 0x01,
	MAIL_NAMESPACE_TYPE_SHARED	= 0x02,
	MAIL_NAMESPACE_TYPE_PUBLIC	= 0x04
#define MAIL_NAMESPACE_TYPE_MASK_ALL \
	(MAIL_NAMESPACE_TYPE_PRIVATE | MAIL_NAMESPACE_TYPE_SHARED | \
	 MAIL_NAMESPACE_TYPE_PUBLIC)
};

enum namespace_flags {
	/* Namespace contains the user's INBOX mailbox. Normally only a single
	   namespace has this flag set, but when using alias_for for the INBOX
	   namespace the flag gets copied to the alias namespace as well */
	NAMESPACE_FLAG_INBOX_USER	= 0x01,
	/* Namespace contains someone's INBOX. This is set for both user's
	   INBOX namespace and also for any other users' shared namespaces. */
	NAMESPACE_FLAG_INBOX_ANY	= 0x02,
	/* Namespace is visible only by explicitly using its full prefix */
	NAMESPACE_FLAG_HIDDEN		= 0x04,
	/* Namespace prefix is visible with LIST */
	NAMESPACE_FLAG_LIST_PREFIX	= 0x08,
	/* Namespace prefix isn't visible with LIST, but child mailboxes are */
	NAMESPACE_FLAG_LIST_CHILDREN	= 0x10,
	/* Namespace uses its own subscriptions. */
	NAMESPACE_FLAG_SUBSCRIPTIONS	= 0x20,

	/* Namespace was created automatically (for shared mailboxes) */
	NAMESPACE_FLAG_AUTOCREATED	= 0x1000,
	/* Namespace has at least some usable mailboxes. Autocreated namespaces
	   that don't have usable mailboxes may be removed automatically. */
	NAMESPACE_FLAG_USABLE		= 0x2000,
	/* Automatically created namespace for a user that doesn't exist. */
	NAMESPACE_FLAG_UNUSABLE		= 0x4000,
	/* Don't track quota for this namespace */
	NAMESPACE_FLAG_NOQUOTA		= 0x8000,
	/* Don't enforce ACLs for this namespace */
	NAMESPACE_FLAG_NOACL		= 0x10000
};

struct mail_namespace {
	/* Namespaces are sorted by their prefix length, "" comes first */
	struct mail_namespace *next;
	int refcount;

        enum mail_namespace_type type;
	enum namespace_flags flags;

	char *prefix;
	size_t prefix_len;

	/* If non-NULL, this points to a namespace with identical mail location
	   and it should be considered as the primary way to access the
	   mailboxes. This allows for example FTS plugin to avoid duplicating
	   indexes for same mailboxes when they're accessed via different
	   namespaces. */
	struct mail_namespace *alias_for;
	/* alias_for->alias_chain_next starts each chain. The chain goes
	   through all namespaces that have the same alias_for. */
	struct mail_namespace *alias_chain_next;

	struct mail_user *user, *owner;
	struct mailbox_list *list;
	struct mail_storage *storage; /* default storage */
	ARRAY(struct mail_storage *) all_storages;

	/* This may point to user->set, but it may also point to
	   namespace-specific settings. When accessing namespace-specific
	   settings it should be done through here instead of through the
	   mail_user. */
	struct mail_user_settings *user_set;

	const struct mail_namespace_settings *set, *unexpanded_set;
	const struct mail_storage_settings *mail_set;

	bool special_use_mailboxes:1;
	bool destroyed:1;
};

/* Returns TRUE when namespace can be removed without consequence. */
static inline bool mail_namespace_is_removable(const struct mail_namespace *ns)
{
	return ((ns->flags & NAMESPACE_FLAG_USABLE) == 0 &&
		(ns->flags & NAMESPACE_FLAG_AUTOCREATED) != 0);
}

/* Allocate a new namespace, and fill it based on the passed in settings.
   This is the most low-level namespace creation function. The storage isn't
   initialized for the namespace.

   user_all_settings normally points to user->set. If you want to override
   settings for the created namespace, you can duplicate the user's settings
   and provide a pointer to it here. Note that the pointer must contain
   ALL the settings, including the dynamic driver-specific settings, so it
   needs to created via settings-parser API. */
int mail_namespace_alloc(struct mail_user *user,
			 void *user_all_settings,
			 struct mail_namespace_settings *ns_set,
			 struct mail_namespace_settings *unexpanded_set,
			 struct mail_namespace **ns_r,
			 const char **error_r);

/* Add and initialize namespaces to user based on namespace settings. */
int mail_namespaces_init(struct mail_user *user, const char **error_r);
/* Add and initialize INBOX namespace to user based on the given location. */
int mail_namespaces_init_location(struct mail_user *user, const char *location,
				  const char **error_r) ATTR_NULL(2);
/* Add an empty namespace to user. */
struct mail_namespace *mail_namespaces_init_empty(struct mail_user *user);
/* Deinitialize all namespaces. mail_user_deinit() calls this automatically
   for user's namespaces. */
void mail_namespaces_deinit(struct mail_namespace **namespaces);

/* Allocate a new namespace and initialize it. This is called automatically by
   mail_namespaces_init(). */
int mail_namespaces_init_add(struct mail_user *user,
			     struct mail_namespace_settings *ns_set,
			     struct mail_namespace_settings *unexpanded_ns_set,
			     struct mail_namespace **ns_p, const char **error_r);
int mail_namespaces_init_finish(struct mail_namespace *namespaces,
				const char **error_r);

void mail_namespace_ref(struct mail_namespace *ns);
void mail_namespace_unref(struct mail_namespace **ns);

/* Set storage callback functions to use in all namespaces. */
void mail_namespaces_set_storage_callbacks(struct mail_namespace *namespaces,
					   struct mail_storage_callbacks *callbacks,
					   void *context);

/* Add a new storage to namespace. */
void mail_namespace_add_storage(struct mail_namespace *ns,
				struct mail_storage *storage);
/* Destroy a single namespace and remove it from user's namespaces list. */
void mail_namespace_destroy(struct mail_namespace *ns);

/* Returns the default storage to use for newly created mailboxes. */
struct mail_storage *
mail_namespace_get_default_storage(struct mail_namespace *ns);

/* Return namespace's hierarchy separator. */
char mail_namespace_get_sep(struct mail_namespace *ns);
/* Returns the hierarchy separator for mailboxes that are listed at root. */
char mail_namespaces_get_root_sep(struct mail_namespace *namespaces)
	ATTR_PURE;

/* Returns namespace based on the mailbox name's prefix. Note that there is
   always a prefix="" namespace, so for this function NULL is never returned. */
struct mail_namespace *
mail_namespace_find(struct mail_namespace *namespaces, const char *mailbox);
/* Same as mail_namespace_find(), but if the namespace has alias_for set,
   return that namespace instead and change mailbox name to be a valid
   inside it. */
struct mail_namespace *
mail_namespace_find_unalias(struct mail_namespace *namespaces,
			    const char **mailbox);

/* Like mail_namespace_find(), but ignore hidden namespaces. */
struct mail_namespace *
mail_namespace_find_visible(struct mail_namespace *namespaces,
			    const char *mailbox);
/* Like mail_namespace_find(), but find only from namespaces with
   subscriptions=yes. */
struct mail_namespace *
mail_namespace_find_subscribable(struct mail_namespace *namespaces,
				 const char *mailbox);
/* Like mail_namespace_find(), but find only from namespaces with
   subscriptions=no. */
struct mail_namespace *
mail_namespace_find_unsubscribable(struct mail_namespace *namespaces,
				   const char *mailbox);
/* Returns the INBOX namespace. It always exists, so NULL is never returned. */
struct mail_namespace *
mail_namespace_find_inbox(struct mail_namespace *namespaces);
/* Find a namespace with given prefix. */
struct mail_namespace *
mail_namespace_find_prefix(struct mail_namespace *namespaces,
			   const char *prefix);
/* Like _find_prefix(), but ignore trailing separator */
struct mail_namespace *
mail_namespace_find_prefix_nosep(struct mail_namespace *namespaces,
				 const char *prefix);

/* Called internally by mailbox_list_create(). */
void mail_namespace_finish_list_init(struct mail_namespace *ns,
				     struct mailbox_list *list);

/* Returns TRUE if this is the root of a type=shared namespace that is actually
   used for accessing shared users' mailboxes (as opposed to marking a
   type=public namespace "wrong"). */
bool mail_namespace_is_shared_user_root(struct mail_namespace *ns);

/* Returns TRUE if namespace includes INBOX that should be \Noinferiors.
   This happens when the namespace has a prefix, which is not empty and not
   "INBOX". This happens, because if storage_name=INBOX/foo it would be
   converted to vname=prefix/INBOX/foo. */
static inline bool
mail_namespace_is_inbox_noinferiors(struct mail_namespace *ns)
{
	return (ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
		ns->prefix_len > 0 &&
		strncmp(ns->prefix, "INBOX", ns->prefix_len-1) != 0;
}

#endif
