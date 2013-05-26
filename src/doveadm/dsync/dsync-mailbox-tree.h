#ifndef DSYNC_MAILBOX_TREE_H
#define DSYNC_MAILBOX_TREE_H

#include "guid.h"

struct mail_namespace;

enum dsync_mailbox_trees_sync_type {
	/* two-way sync for both mailboxes */
	DSYNC_MAILBOX_TREES_SYNC_TYPE_TWOWAY,
	/* make remote tree look exactly like the local tree */
	DSYNC_MAILBOX_TREES_SYNC_TYPE_PRESERVE_LOCAL,
	/* make local tree look exactly like the remote tree */
	DSYNC_MAILBOX_TREES_SYNC_TYPE_PRESERVE_REMOTE
};

enum dsync_mailbox_node_existence {
	/* this is just a filler node for children or for
	   subscription deletion */
	DSYNC_MAILBOX_NODE_NONEXISTENT = 0,
	/* if mailbox GUID is set, the mailbox exists.
	   otherwise the directory exists. */
	DSYNC_MAILBOX_NODE_EXISTS,
	/* if mailbox GUID is set, the mailbox has been deleted.
	   otherwise the directory has been deleted. */
	DSYNC_MAILBOX_NODE_DELETED
};

struct dsync_mailbox_node {
	struct dsync_mailbox_node *parent, *next, *first_child;

	/* namespace where this node belongs to */
	struct mail_namespace *ns;
	/* this node's name (not including parents) */
	const char *name;
	/* mailbox GUID, or full of zeros if this is about a directory name */
	guid_128_t mailbox_guid;
	/* mailbox's UIDVALIDITY/UIDNEXT (may be 0 if not assigned yet) */
	uint32_t uid_validity, uid_next;

	/* existence of this mailbox/directory.
	   doesn't affect subscription state. */
	enum dsync_mailbox_node_existence existence;
	/* last time the mailbox/directory was created/renamed,
	   0 if not known */
	time_t last_renamed_or_created;

	/* last time the subscription state was changed, 0 if not known */
	time_t last_subscription_change;
	/* is this mailbox or directory subscribed? */
	unsigned int subscribed:1;

	/* Internal syncing flags: */
	unsigned int sync_delayed_guid_change:1;
	unsigned int sync_temporary_name:1;
};
ARRAY_DEFINE_TYPE(dsync_mailbox_node, struct dsync_mailbox_node *);

#define dsync_mailbox_node_guids_equal(node1, node2) \
	(memcmp((node1)->mailbox_guid, (node2)->mailbox_guid, \
		sizeof(guid_128_t)) == 0)

#define dsync_mailbox_node_is_dir(node) \
	guid_128_is_empty((node)->mailbox_guid)

enum dsync_mailbox_delete_type {
	/* Delete mailbox by given GUID */
	DSYNC_MAILBOX_DELETE_TYPE_MAILBOX = 1,
	/* Delete mailbox directory by given SHA1 name */
	DSYNC_MAILBOX_DELETE_TYPE_DIR,
	/* Unsubscribe mailbox by given SHA1 name */
	DSYNC_MAILBOX_DELETE_TYPE_UNSUBSCRIBE,
};

struct dsync_mailbox_delete {
	enum dsync_mailbox_delete_type type;
	guid_128_t guid;
	time_t timestamp;
};

enum dsync_mailbox_tree_sync_type {
	DSYNC_MAILBOX_TREE_SYNC_TYPE_CREATE_BOX,
	DSYNC_MAILBOX_TREE_SYNC_TYPE_CREATE_DIR,
	DSYNC_MAILBOX_TREE_SYNC_TYPE_DELETE_BOX,
	DSYNC_MAILBOX_TREE_SYNC_TYPE_DELETE_DIR,
	/* Rename given mailbox name and its children */
	DSYNC_MAILBOX_TREE_SYNC_TYPE_RENAME,
	DSYNC_MAILBOX_TREE_SYNC_TYPE_SUBSCRIBE,
	DSYNC_MAILBOX_TREE_SYNC_TYPE_UNSUBSCRIBE
};

struct dsync_mailbox_tree_sync_change {
	enum dsync_mailbox_tree_sync_type type;

	/* for all types: */
	struct mail_namespace *ns;
	const char *full_name;

	/* for create_box and delete_box: */
	guid_128_t mailbox_guid;
	/* for create_box: */
	uint32_t uid_validity;
	/* for rename: */
	const char *rename_dest_name;
};

struct dsync_mailbox_tree *dsync_mailbox_tree_init(char sep, char alt_char);
void dsync_mailbox_tree_deinit(struct dsync_mailbox_tree **tree);

/* Lookup a mailbox node by name. Returns NULL if not known. */
struct dsync_mailbox_node *
dsync_mailbox_tree_lookup(struct dsync_mailbox_tree *tree,
			  const char *full_name);
/* Lookup a mailbox node by GUID. Returns NULL if not known.
   The mailbox GUID hash must have been build before calling this. */
struct dsync_mailbox_node *
dsync_mailbox_tree_lookup_guid(struct dsync_mailbox_tree *tree,
			       const guid_128_t guid);
/* Lookup or create a mailbox node by name. */
struct dsync_mailbox_node *
dsync_mailbox_tree_get(struct dsync_mailbox_tree *tree, const char *full_name);

/* Returns full name for the given mailbox node. */
const char *dsync_mailbox_node_get_full_name(const struct dsync_mailbox_tree *tree,
					     const struct dsync_mailbox_node *node);

/* Copy everything from src to dest, except name and hierarchy pointers */
void dsync_mailbox_node_copy_data(struct dsync_mailbox_node *dest,
				  const struct dsync_mailbox_node *src);

/* Add nodes to tree from the given namespace. If box_name or box_guid is
   non-NULL, add only that mailbox to the tree. */
int dsync_mailbox_tree_fill(struct dsync_mailbox_tree *tree,
			    struct mail_namespace *ns, const char *box_name,
			    const guid_128_t box_guid,
			    const char *const *exclude_mailboxes);

/* Return all known deleted mailboxes and directories. */
const struct dsync_mailbox_delete *
dsync_mailbox_tree_get_deletes(struct dsync_mailbox_tree *tree,
			       unsigned int *count_r);
/* Return mailbox node for a given delete record, or NULL if it doesn't exist.
   The delete record is intended to come from another tree, possibly with
   a different hierarchy separator. dsync_mailbox_tree_build_guid_hash() must
   have been called before this. */
struct dsync_mailbox_node *
dsync_mailbox_tree_find_delete(struct dsync_mailbox_tree *tree,
			       const struct dsync_mailbox_delete *del);
/* Build GUID lookup hash, if it's not already built. Returns 0 if ok, -1 if
   there are duplicate GUIDs. The nodes with the duplicate GUIDs are
   returned. */
int dsync_mailbox_tree_build_guid_hash(struct dsync_mailbox_tree *tree,
				       struct dsync_mailbox_node **dup_node1_r,
				       struct dsync_mailbox_node **dup_node2_r);
/* Manually add a new node to hash. */
int dsync_mailbox_tree_guid_hash_add(struct dsync_mailbox_tree *tree,
				     struct dsync_mailbox_node *node,
				     struct dsync_mailbox_node **old_node_r);
/* Set remote separator used for directory deletions in
   dsync_mailbox_tree_find_delete() */
void dsync_mailbox_tree_set_remote_sep(struct dsync_mailbox_tree *tree,
				       char remote_sep);

/* Iterate through all nodes in a tree (depth-first) */
struct dsync_mailbox_tree_iter *
dsync_mailbox_tree_iter_init(struct dsync_mailbox_tree *tree);
bool dsync_mailbox_tree_iter_next(struct dsync_mailbox_tree_iter *iter,
				  const char **full_name_r,
				  struct dsync_mailbox_node **node_r);
void dsync_mailbox_tree_iter_deinit(struct dsync_mailbox_tree_iter **iter);

/* Sync local and remote trees so at the end they're exactly the same.
   Return changes done to local tree. */
struct dsync_mailbox_tree_sync_ctx *
dsync_mailbox_trees_sync_init(struct dsync_mailbox_tree *local_tree,
			      struct dsync_mailbox_tree *remote_tree,
			      enum dsync_mailbox_trees_sync_type sync_type);
const struct dsync_mailbox_tree_sync_change *
dsync_mailbox_trees_sync_next(struct dsync_mailbox_tree_sync_ctx *ctx);
void dsync_mailbox_trees_sync_deinit(struct dsync_mailbox_tree_sync_ctx **ctx);

#endif
