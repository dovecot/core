/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "aqueue.h"
#include "hash.h"
#include "dsync-mailbox-tree-private.h"

struct dsync_mailbox_tree_bfs_iter {
	struct dsync_mailbox_tree *tree;

	ARRAY_DEFINE(queue_arr, struct dsync_mailbox_node *);
	struct aqueue *queue;
	struct dsync_mailbox_node *cur;
};

struct dsync_mailbox_tree_sync_ctx {
	pool_t pool;
	struct dsync_mailbox_tree *local_tree, *remote_tree;

	ARRAY_DEFINE(changes, struct dsync_mailbox_tree_sync_change);
	unsigned int change_idx;
};

static struct dsync_mailbox_tree_bfs_iter *
dsync_mailbox_tree_bfs_iter_init(struct dsync_mailbox_tree *tree)
{
	struct dsync_mailbox_tree_bfs_iter *iter;

	iter = i_new(struct dsync_mailbox_tree_bfs_iter, 1);
	iter->tree = tree;
	i_array_init(&iter->queue_arr, 32);
	iter->queue = aqueue_init(&iter->queue_arr.arr);
	iter->cur = tree->root.first_child;
	return iter;
}

static bool
dsync_mailbox_tree_bfs_iter_next(struct dsync_mailbox_tree_bfs_iter *iter,
				 struct dsync_mailbox_node **node_r)
{
	struct dsync_mailbox_node *const *nodep;

	if (iter->cur == NULL) {
		if (aqueue_count(iter->queue) == 0)
			return FALSE;
		nodep = array_idx(&iter->queue_arr, aqueue_idx(iter->queue, 0));
		iter->cur = *nodep;
		aqueue_delete_tail(iter->queue);
	}
	*node_r = iter->cur;

	if (iter->cur->first_child != NULL)
		aqueue_append(iter->queue, &iter->cur->first_child);
	iter->cur = iter->cur->next;
	return TRUE;
}

static bool
dsync_mailbox_tree_bfs_iter_is_eob(struct dsync_mailbox_tree_bfs_iter *iter)
{
	return iter->cur == NULL;
}

static void
dsync_mailbox_tree_bfs_iter_deinit(struct dsync_mailbox_tree_bfs_iter **_iter)
{
	struct dsync_mailbox_tree_bfs_iter *iter = *_iter;

	*_iter = NULL;

	aqueue_deinit(&iter->queue);
	array_free(&iter->queue_arr);
	i_free(iter);
}

static int dsync_mailbox_node_sync_cmp(struct dsync_mailbox_node *const *n1,
				       struct dsync_mailbox_node *const *n2)
{
	return strcmp((*n1)->name, (*n2)->name);
}

static void sort_siblings(ARRAY_TYPE(dsync_mailbox_node) *siblings)
{
	struct dsync_mailbox_node *const *nodes;
	unsigned int i, count;

	array_sort(siblings, dsync_mailbox_node_sync_cmp);

	nodes = array_get(siblings, &count);
	if (count == 0)
		return;

	nodes[0]->parent->first_child = nodes[0];
	for (i = 1; i < count; i++)
		nodes[i-1]->next = nodes[i];
	nodes[count-1]->next = NULL;
}

static void
sync_delete_mailbox(struct dsync_mailbox_tree_sync_ctx *ctx,
		    struct dsync_mailbox_tree *tree,
		    struct dsync_mailbox_node *node)
{
	struct dsync_mailbox_tree *other_tree;
	struct dsync_mailbox_node *other_node;
	struct dsync_mailbox_tree_sync_change *change;
	const char *name;

	other_tree = tree == ctx->local_tree ?
		ctx->remote_tree : ctx->local_tree;
	other_node = hash_table_lookup(other_tree->guid_hash,
				       node->mailbox_guid);
	if (other_node == NULL) {
		/* doesn't exist / already deleted */
	} else if (other_tree == ctx->local_tree) {
		/* delete this mailbox locally */
		change = array_append_space(&ctx->changes);
		change->type = DSYNC_MAILBOX_TREE_SYNC_TYPE_DELETE_BOX;
		change->ns = other_node->ns;
		name = dsync_mailbox_node_get_full_name(other_tree, other_node);
		change->full_name = p_strdup(ctx->pool, name);
		memcpy(change->mailbox_guid, node->mailbox_guid,
		       sizeof(change->mailbox_guid));
	}

	/* for the rest of this sync assume that the mailbox has
	   already been deleted */
	if (other_node != NULL) {
		other_node->existence = DSYNC_MAILBOX_NODE_DELETED;
		memset(other_node->mailbox_guid, 0,
		       sizeof(other_node->mailbox_guid));
	}
	memset(node->mailbox_guid, 0, sizeof(node->mailbox_guid));
}

static void
sync_tree_sort_and_delete_mailboxes(struct dsync_mailbox_tree_sync_ctx *ctx,
				    struct dsync_mailbox_tree *tree)
{
	struct dsync_mailbox_tree_bfs_iter *iter;
	struct dsync_mailbox_node *node, *parent = NULL;
	ARRAY_TYPE(dsync_mailbox_node) siblings;

	t_array_init(&siblings, 64);

	iter = dsync_mailbox_tree_bfs_iter_init(tree);
	while (dsync_mailbox_tree_bfs_iter_next(iter, &node)) {
		if (node->parent != parent) {
			sort_siblings(&siblings);
			array_clear(&siblings);
			parent = node->parent;
		}
		if (node->existence == DSYNC_MAILBOX_NODE_DELETED &&
		    !guid_128_is_empty(node->mailbox_guid))
			sync_delete_mailbox(ctx, tree, node);
		array_append(&siblings, &node, 1);
	}
	sort_siblings(&siblings);
	dsync_mailbox_tree_bfs_iter_deinit(&iter);
}

static struct dsync_mailbox_node *
sync_find_node(struct dsync_mailbox_tree *tree,
	       struct dsync_mailbox_node *other_node)
{
	struct dsync_mailbox_node *n1, *n2;

	if (!guid_128_is_empty(other_node->mailbox_guid)) {
		return hash_table_lookup(tree->guid_hash,
					 other_node->mailbox_guid);
	}
	/* if we can find a node that has all of the same mailboxes as children,
	   return it. */
	for (n1 = other_node->first_child; n1 != NULL; n1 = n1->next) {
		if (!guid_128_is_empty(n1->mailbox_guid))
			break;
	}
	if (n1 == NULL)
		return NULL;
	n2 = hash_table_lookup(tree->guid_hash, n1->mailbox_guid);
	if (n2 == NULL)
		return NULL;

	/* note that all of the nodes are sorted at this point. */
	n1 = n1->parent->first_child;
	n2 = n2->parent->first_child;
	for (; n1 != NULL && n2 != NULL; n1 = n1->next, n2 = n2->next) {
		if (strcmp(n1->name, n2->name) != 0 ||
		    memcmp(n1->mailbox_guid, n2->mailbox_guid,
			   sizeof(n1->mailbox_guid)) != 0)
			break;
	}
	if (n1 != NULL || n2 != NULL)
		return NULL;
	return n2;
}

static bool node_names_equal(const struct dsync_mailbox_node *n1,
			     const struct dsync_mailbox_node *n2)
{
	while (n1 != NULL && n2 != NULL) {
		if (strcmp(n1->name, n2->name) != 0)
			return FALSE;
		n1 = n1->parent;
		n2 = n2->parent;
	}
	return n1 == NULL && n2 == NULL;
}

static void
dsync_mailbox_tree_node_detach(struct dsync_mailbox_node *node)
{
	struct dsync_mailbox_node **p;
	for (p = &node->parent->first_child;; p = &(*p)->next) {
		if (*p == node) {
			*p = node->next;
			break;
		}
	}
}

static void
dsync_mailbox_tree_node_attach_sorted(struct dsync_mailbox_node *node,
				      struct dsync_mailbox_node *parent)
{
	struct dsync_mailbox_node **p;

	node->parent = parent;
	for (p = &parent->first_child; *p != NULL; p = &(*p)->next) {
		if (dsync_mailbox_node_sync_cmp(p, &node) > 0)
			break;
	}
	node->next = *p;
	*p = node;
}

static void
dsync_mailbox_tree_node_move_sorted(struct dsync_mailbox_node *node,
				    struct dsync_mailbox_node *parent)
{
	if (node->parent != parent) {
		/* detach from old parent */
		dsync_mailbox_tree_node_detach(node);
		/* attach to new parent */
		dsync_mailbox_tree_node_attach_sorted(node, parent);
	}
}

static struct dsync_mailbox_node *
sorted_tree_get(struct dsync_mailbox_tree *tree, const char *name)
{
	struct dsync_mailbox_node *node, *parent, *ret;

	node = ret = dsync_mailbox_tree_get(tree, name);
	while (node->parent != NULL &&
	       node->existence == DSYNC_MAILBOX_NODE_NONEXISTENT) {
		parent = node->parent;
		dsync_mailbox_tree_node_detach(node);
		dsync_mailbox_tree_node_attach_sorted(node, parent);
		node = parent;
	}
	return ret;
}

static struct dsync_mailbox_node *
sorted_tree_get_by_node_name(struct dsync_mailbox_tree *tree,
			     struct dsync_mailbox_tree *other_tree,
			     struct dsync_mailbox_node *other_node)
{
	const char *parent_name;

	if (other_node == &other_tree->root)
		return &tree->root;

	parent_name = dsync_mailbox_node_get_full_name(other_tree, other_node);
	return sorted_tree_get(tree, parent_name);
}

static void
sync_rename_node(struct dsync_mailbox_tree_sync_ctx *ctx,
		 struct dsync_mailbox_tree *tree,
		 struct dsync_mailbox_node *node,
		 struct dsync_mailbox_node *other_node)
{
	struct dsync_mailbox_tree_sync_change *change;
	struct dsync_mailbox_tree *other_tree;
	struct dsync_mailbox_node *parent;
	const char *name, *other_name;
	bool use_node_name, local_tree_changed;

	other_tree = tree == ctx->local_tree ?
		ctx->remote_tree : ctx->local_tree;

	name = dsync_mailbox_node_get_full_name(tree, node);
	other_name = dsync_mailbox_node_get_full_name(other_tree, other_node);

	if (node->last_renamed > other_node->last_renamed ||
	    (node->last_renamed == other_node->last_renamed &&
	     strcmp(name, other_name) > 0)) {
		/* use node's name */
		local_tree_changed = tree == ctx->remote_tree;
		other_node->name = p_strdup(other_tree->pool, node->name);

		/* move node if necessary */
		parent = sorted_tree_get_by_node_name(other_tree, tree,
						      node->parent);
		dsync_mailbox_tree_node_move_sorted(other_node, parent);
	} else {
		/* other other_node's name */
		use_node_name = FALSE;
		local_tree_changed = other_tree == ctx->remote_tree;
		node->name = p_strdup(tree->pool, other_node->name);

		/* move node if necessary */
		parent = sorted_tree_get_by_node_name(tree, other_tree,
						      other_node->parent);
		dsync_mailbox_tree_node_move_sorted(node, parent);
	}

	//FIXME: handle if destination name already exists

	if (local_tree_changed) {
		change = array_append_space(&ctx->changes);
		change->type = DSYNC_MAILBOX_TREE_SYNC_TYPE_RENAME;
		change->ns = other_node->ns;
		if (use_node_name) {
			change->full_name = p_strdup(ctx->pool, other_name);
			change->rename_dest_name = p_strdup(ctx->pool, name);
		} else {
			change->full_name = p_strdup(ctx->pool, name);
			change->rename_dest_name =
				p_strdup(ctx->pool, other_name);
		}
	}
}

static void sync_rename_branch(struct dsync_mailbox_tree_sync_ctx *ctx,
			       struct dsync_mailbox_tree_bfs_iter *iter,
			       struct dsync_mailbox_tree *tree)
{
	struct dsync_mailbox_tree *other_tree;
	struct dsync_mailbox_node *node, *other_node;

	other_tree = tree == ctx->local_tree ?
		ctx->remote_tree : ctx->local_tree;
	while (!dsync_mailbox_tree_bfs_iter_is_eob(iter)) {
		if (!dsync_mailbox_tree_bfs_iter_next(iter, &node))
			i_unreached();

		other_node = sync_find_node(other_tree, node);
		if (other_node == NULL) {
			/* this mailbox will be created later */
		} else if (node_names_equal(node, other_node)) {
			/* mailbox name hasn't changed */
		} else {
			/* mailbox name or tree branch has changed */
			sync_rename_node(ctx, tree, node, other_node);
		}
	}
}

static void sync_rename_mailboxes(struct dsync_mailbox_tree_sync_ctx *ctx)
{
	struct dsync_mailbox_tree_bfs_iter *local_iter, *remote_iter;
	struct dsync_mailbox_node *node;

	local_iter = dsync_mailbox_tree_bfs_iter_init(ctx->local_tree);
	remote_iter = dsync_mailbox_tree_bfs_iter_init(ctx->remote_tree);

	do {
		sync_rename_branch(ctx, local_iter, ctx->local_tree);
		sync_rename_branch(ctx, remote_iter, ctx->remote_tree);
	} while (dsync_mailbox_tree_bfs_iter_next(local_iter, &node) ||
		 dsync_mailbox_tree_bfs_iter_next(remote_iter, &node));

	dsync_mailbox_tree_bfs_iter_deinit(&local_iter);
	dsync_mailbox_tree_bfs_iter_deinit(&remote_iter);
}

static void
sync_add_create_change(struct dsync_mailbox_tree_sync_ctx *ctx,
		       const struct dsync_mailbox_node *node, const char *name)
{
	struct dsync_mailbox_tree_sync_change *change;

	change = array_append_space(&ctx->changes);
	change->type = DSYNC_MAILBOX_TREE_SYNC_TYPE_CREATE_BOX;
	change->ns = node->ns;
	change->full_name = p_strdup(ctx->pool, name);
	memcpy(change->mailbox_guid, node->mailbox_guid,
	       sizeof(change->mailbox_guid));
	change->uid_validity = node->uid_validity;
}

static void sync_create_mailboxes(struct dsync_mailbox_tree_sync_ctx *ctx,
				  struct dsync_mailbox_tree *tree)
{
	struct dsync_mailbox_tree *other_tree;
	struct dsync_mailbox_tree_iter *iter;
	struct dsync_mailbox_node *node, *other_node;
	const char *name;

	other_tree = tree == ctx->local_tree ?
		ctx->remote_tree : ctx->local_tree;

	iter = dsync_mailbox_tree_iter_init(tree);
	while (dsync_mailbox_tree_iter_next(iter, &name, &node)) {
		if (guid_128_is_empty(node->mailbox_guid))
			continue;

		i_assert(node->existence == DSYNC_MAILBOX_NODE_EXISTS);

		other_node = hash_table_lookup(other_tree->guid_hash,
					       node->mailbox_guid);
		if (other_node == NULL)
			other_node = sorted_tree_get(other_tree, name);
		if (!guid_128_is_empty(other_node->mailbox_guid)) {
			/* already exists */
			i_assert(node->existence == DSYNC_MAILBOX_NODE_EXISTS);
			// FIXME: remove this assert? for conflicting GUIDs
			i_assert(memcmp(node->mailbox_guid,
					other_node->mailbox_guid,
					sizeof(node->mailbox_guid)) == 0);
		} else {
			other_node->existence = DSYNC_MAILBOX_NODE_EXISTS;
			other_node->ns = node->ns;
			other_node->uid_validity = node->uid_validity;
			memcpy(other_node->mailbox_guid, node->mailbox_guid,
			       sizeof(other_node->mailbox_guid));
			if (other_tree == ctx->local_tree)
				sync_add_create_change(ctx, other_node, name);
		}
	}
	dsync_mailbox_tree_iter_deinit(&iter);
}

static void
sync_add_dir_change(struct dsync_mailbox_tree_sync_ctx *ctx,
		    const struct dsync_mailbox_node *node,
		    enum dsync_mailbox_tree_sync_type type)
{
	struct dsync_mailbox_tree_sync_change *change;
	const char *name;

	name = dsync_mailbox_node_get_full_name(ctx->local_tree, node);

	change = array_append_space(&ctx->changes);
	change->type = type;
	change->ns = node->ns;
	change->full_name = p_strdup(ctx->pool, name);
}

static struct dsync_mailbox_node *
sync_node_new(struct dsync_mailbox_tree *tree,
	      struct dsync_mailbox_node *parent,
	      const struct dsync_mailbox_node *src)
{
	struct dsync_mailbox_node *node;

	node = p_new(tree->pool, struct dsync_mailbox_node, 1);
	node->name = p_strdup(tree->pool, src->name);
	node->ns = src->ns;
	dsync_mailbox_tree_node_attach_sorted(node, parent);
	return node;
}

static void
sync_subscription(struct dsync_mailbox_tree_sync_ctx *ctx,
		  struct dsync_mailbox_node *local_node,
		  struct dsync_mailbox_node *remote_node)
{
	if (local_node->last_subscription_change >
	    remote_node->last_subscription_change ||
	    (local_node->last_subscription_change ==
	     remote_node->last_subscription_change && local_node->subscribed)) {
		/* use local subscription state */
		remote_node->subscribed = local_node->subscribed;
	} else {
		/* use remote subscription state */
		local_node->subscribed = remote_node->subscribed;
		sync_add_dir_change(ctx, local_node, local_node->subscribed ?
				    DSYNC_MAILBOX_TREE_SYNC_TYPE_SUBSCRIBE :
				    DSYNC_MAILBOX_TREE_SYNC_TYPE_UNSUBSCRIBE);
	}
}

static void sync_mailbox_child_dirs(struct dsync_mailbox_tree_sync_ctx *ctx,
				    struct dsync_mailbox_node *local_parent,
				    struct dsync_mailbox_node *remote_parent)
{
	struct dsync_mailbox_node *local_node, *remote_node;

	/* NOTE: the nodes are always sorted */
	local_node = local_parent->first_child;
	remote_node = remote_parent->first_child;
	while (local_node != NULL || remote_node != NULL) {
		/* add missing nodes, even if we don't really need to do
		   anything with them. */
		if (remote_node != NULL &&
		    (local_node == NULL ||
		     strcmp(local_node->name, remote_node->name) > 0)) {
			local_node = sync_node_new(ctx->local_tree, local_parent,
						   remote_node);
		}
		if (local_node != NULL &&
		    (remote_node == NULL ||
		     strcmp(remote_node->name, local_node->name) > 0)) {
			remote_node = sync_node_new(ctx->remote_tree, remote_parent,
						    local_node);
		}

		if (local_node->existence == DSYNC_MAILBOX_NODE_EXISTS &&
		    remote_node->existence == DSYNC_MAILBOX_NODE_NONEXISTENT) {
			/* create to remote */
			remote_node->existence = DSYNC_MAILBOX_NODE_EXISTS;
		}
		if (remote_node->existence == DSYNC_MAILBOX_NODE_EXISTS &&
		    local_node->existence == DSYNC_MAILBOX_NODE_NONEXISTENT) {
			/* create to local */
			local_node->existence = DSYNC_MAILBOX_NODE_EXISTS;
			sync_add_dir_change(ctx, local_node,
				DSYNC_MAILBOX_TREE_SYNC_TYPE_CREATE_DIR);
		}

		/* create/delete child dirs */
		sync_mailbox_child_dirs(ctx, local_node, remote_node);

		if (local_node->subscribed != remote_node->subscribed)
			sync_subscription(ctx, local_node, remote_node);

		if (local_node->existence == DSYNC_MAILBOX_NODE_DELETED &&
		    local_node->first_child == NULL &&
		    remote_node->existence == DSYNC_MAILBOX_NODE_EXISTS) {
			/* delete from remote */
			i_assert(remote_node->first_child == NULL);
			remote_node->existence = DSYNC_MAILBOX_NODE_NONEXISTENT;
		}
		if (remote_node->existence == DSYNC_MAILBOX_NODE_DELETED &&
		    remote_node->first_child == NULL &&
		    local_node->existence == DSYNC_MAILBOX_NODE_EXISTS) {
			/* delete from local */
			i_assert(local_node->first_child == NULL);
			local_node->existence = DSYNC_MAILBOX_NODE_NONEXISTENT;
			sync_add_dir_change(ctx, local_node,
				DSYNC_MAILBOX_TREE_SYNC_TYPE_DELETE_DIR);
		}

		local_node = local_node->next;
		remote_node = remote_node->next;
	}
}

static void sync_mailbox_dirs(struct dsync_mailbox_tree_sync_ctx *ctx)
{
	sync_mailbox_child_dirs(ctx, &ctx->local_tree->root,
				&ctx->remote_tree->root);
}

struct dsync_mailbox_tree_sync_ctx *
dsync_mailbox_trees_sync_init(struct dsync_mailbox_tree *local_tree,
			      struct dsync_mailbox_tree *remote_tree)
{
	struct dsync_mailbox_tree_sync_ctx *ctx;
	pool_t pool;

	i_assert(local_tree->guid_hash != NULL);
	i_assert(remote_tree->guid_hash != NULL);

	pool = pool_alloconly_create(MEMPOOL_GROWING"dsync mailbox trees sync",
				     1024*64);
	ctx = p_new(pool, struct dsync_mailbox_tree_sync_ctx, 1);
	ctx->pool = pool;
	ctx->local_tree = local_tree;
	ctx->remote_tree = remote_tree;
	i_array_init(&ctx->changes, 128);

	sync_tree_sort_and_delete_mailboxes(ctx, remote_tree);
	sync_tree_sort_and_delete_mailboxes(ctx, local_tree);
	sync_rename_mailboxes(ctx);
	sync_create_mailboxes(ctx, remote_tree);
	sync_create_mailboxes(ctx, local_tree);
	sync_mailbox_dirs(ctx);
	return ctx;
}

const struct dsync_mailbox_tree_sync_change *
dsync_mailbox_trees_sync_next(struct dsync_mailbox_tree_sync_ctx *ctx)
{
	if (ctx->change_idx == array_count(&ctx->changes))
		return NULL;
	return array_idx(&ctx->changes, ctx->change_idx++);
}

void dsync_mailbox_trees_sync_deinit(struct dsync_mailbox_tree_sync_ctx **_ctx)
{
	struct dsync_mailbox_tree_sync_ctx *ctx = *_ctx;

	*_ctx = NULL;

	array_free(&ctx->changes);
	pool_unref(&ctx->pool);
}
