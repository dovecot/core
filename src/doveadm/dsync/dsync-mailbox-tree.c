/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "sort.h"
#include "mailbox-list-private.h"
#include "dsync-mailbox-tree-private.h"


struct dsync_mailbox_tree_iter {
	struct dsync_mailbox_tree *tree;

	struct dsync_mailbox_node *cur;
	string_t *name;
};

struct dsync_mailbox_tree *dsync_mailbox_tree_init(char sep, char alt_char)
{
	struct dsync_mailbox_tree *tree;
	pool_t pool;

	i_assert(sep != '\0');

	pool = pool_alloconly_create(MEMPOOL_GROWING"dsync mailbox tree", 4096);
	tree = p_new(pool, struct dsync_mailbox_tree, 1);
	tree->pool = pool;
	tree->sep = tree->sep_str[0] = sep;
	tree->alt_char = alt_char;
	tree->root.name = "";
	i_array_init(&tree->deletes, 32);
	return tree;
}

void dsync_mailbox_tree_deinit(struct dsync_mailbox_tree **_tree)
{
	struct dsync_mailbox_tree *tree = *_tree;

	*_tree = NULL;
	hash_table_destroy(&tree->name128_hash);
	hash_table_destroy(&tree->guid_hash);
	array_free(&tree->deletes);
	pool_unref(&tree->pool);
}

static struct dsync_mailbox_node *
dsync_mailbox_node_find(struct dsync_mailbox_node *nodes, const char *name)
{
	for (; nodes != NULL; nodes = nodes->next) {
		if (strcmp(name, nodes->name) == 0)
			return nodes;
	}
	return NULL;
}

struct dsync_mailbox_node *
dsync_mailbox_tree_lookup(struct dsync_mailbox_tree *tree,
			  const char *full_name)
{
	struct dsync_mailbox_node *node = &tree->root;

	T_BEGIN {
		const char *const *path;

		path = t_strsplit(full_name, tree->sep_str);
		for (; *path != NULL && node != NULL; path++)
			node = dsync_mailbox_node_find(node->first_child, *path);
	} T_END;
	return node;
}

void dsync_mailbox_tree_node_attach(struct dsync_mailbox_node *node,
				    struct dsync_mailbox_node *parent)
{
	node->parent = parent;
	node->next = parent->first_child;
	parent->first_child = node;
}

void dsync_mailbox_tree_node_detach(struct dsync_mailbox_node *node)
{
	struct dsync_mailbox_node **p;

	for (p = &node->parent->first_child;; p = &(*p)->next) {
		if (*p == node) {
			*p = node->next;
			break;
		}
	}
	node->parent = NULL;
}

struct dsync_mailbox_node *
dsync_mailbox_tree_get(struct dsync_mailbox_tree *tree, const char *full_name)
{
	struct dsync_mailbox_node *parent = NULL, *node = &tree->root;

	i_assert(tree->iter_count == 0);

	T_BEGIN {
		const char *const *path;

		/* find the existing part */
		path = t_strsplit(full_name, tree->sep_str);
		for (; *path != NULL; path++) {
			parent = node;
			node = dsync_mailbox_node_find(node->first_child, *path);
			if (node == NULL)
				break;
		}
		/* create the rest */
		for (; *path != NULL; path++) {
			node = p_new(tree->pool, struct dsync_mailbox_node, 1);
			node->name = p_strdup(tree->pool, *path);
			node->ns = parent->ns;
			dsync_mailbox_tree_node_attach(node, parent);
			parent = node;
		}
	} T_END;
	return node;
}

static void
node_get_full_name_recurse(const struct dsync_mailbox_tree *tree,
			   const struct dsync_mailbox_node *node, string_t *str)
{
	if (node->parent != &tree->root)
		node_get_full_name_recurse(tree, node->parent, str);

	str_append(str, node->name);
	str_append_c(str, tree->sep);
}

const char *dsync_mailbox_node_get_full_name(const struct dsync_mailbox_tree *tree,
					     const struct dsync_mailbox_node *node)
{
	string_t *str = t_str_new(128);
	dsync_mailbox_node_append_full_name(str, tree, node);
	return str_c(str);
}

void dsync_mailbox_node_append_full_name(string_t *str,
					 const struct dsync_mailbox_tree *tree,
					 const struct dsync_mailbox_node *node)
{
	i_assert(node->parent != NULL);

	node_get_full_name_recurse(tree, node, str);
	/* remove the trailing separator */
	str_truncate(str, str_len(str)-1);
}

void dsync_mailbox_node_copy_data(struct dsync_mailbox_node *dest,
				  const struct dsync_mailbox_node *src)
{
	memcpy(dest->mailbox_guid, src->mailbox_guid,
	       sizeof(dest->mailbox_guid));
	dest->uid_validity = src->uid_validity;
	dest->uid_next = src->uid_next;
	dest->existence = src->existence;
	dest->last_renamed_or_created = src->last_renamed_or_created;
	dest->subscribed = src->subscribed;
	dest->last_subscription_change = src->last_subscription_change;
}

struct dsync_mailbox_tree_iter *
dsync_mailbox_tree_iter_init(struct dsync_mailbox_tree *tree)
{
	struct dsync_mailbox_tree_iter *iter;

	iter = i_new(struct dsync_mailbox_tree_iter, 1);
	iter->tree = tree;
	iter->name = str_new(default_pool, 128);
	iter->cur = &tree->root;

	tree->iter_count++;
	return iter;
}

static size_t node_get_full_name_length(struct dsync_mailbox_node *node)
{
	if (node->parent->parent == NULL)
		return strlen(node->name);
	else {
		return strlen(node->name) + 1 +
			node_get_full_name_length(node->parent);
	}
}

bool dsync_mailbox_tree_iter_next(struct dsync_mailbox_tree_iter *iter,
				  const char **full_name_r,
				  struct dsync_mailbox_node **node_r)
{
	size_t len;

	if (iter->cur->first_child != NULL)
		iter->cur = iter->cur->first_child;
	else {
		while (iter->cur->next == NULL) {
			if (iter->cur == &iter->tree->root)
				return FALSE;
			iter->cur = iter->cur->parent;
		}
		iter->cur = iter->cur->next;
		len = iter->cur->parent == &iter->tree->root ? 0 :
			node_get_full_name_length(iter->cur->parent);
		str_truncate(iter->name, len);
	}
	if (str_len(iter->name) > 0)
		str_append_c(iter->name, iter->tree->sep);
	str_append(iter->name, iter->cur->name);
	*full_name_r = str_c(iter->name);
	*node_r = iter->cur;
	return TRUE;
}

void dsync_mailbox_tree_iter_deinit(struct dsync_mailbox_tree_iter **_iter)
{
	struct dsync_mailbox_tree_iter *iter = *_iter;

	*_iter = NULL;

	i_assert(iter->tree->iter_count > 0);
	iter->tree->iter_count--;

	str_free(&iter->name);
	i_free(iter);
}

void dsync_mailbox_tree_build_name128_hash(struct dsync_mailbox_tree *tree)
{
	struct dsync_mailbox_tree_iter *iter;
	struct dsync_mailbox_node *node;
	const char *name;
	guid_128_t *sha128;
	uint8_t *guid_p;

	i_assert(!hash_table_is_created(tree->name128_hash));

	hash_table_create(&tree->name128_hash,
			  tree->pool, 0, guid_128_hash, guid_128_cmp);
	iter = dsync_mailbox_tree_iter_init(tree);
	while (dsync_mailbox_tree_iter_next(iter, &name, &node)) {
		sha128 = p_new(tree->pool, guid_128_t, 1);
		mailbox_name_get_sha128(name, *sha128);
		guid_p = *sha128;
		hash_table_insert(tree->name128_hash, guid_p, node);
	}
	dsync_mailbox_tree_iter_deinit(&iter);
}

static const char *
convert_name_to_remote_sep(struct dsync_mailbox_tree *tree, const char *name)
{
	string_t *str = t_str_new(128);

	for (; *name != '\0'; name++) {
		if (*name == tree->sep)
			str_append_c(str, tree->remote_sep);
		else if (*name == tree->remote_sep)
			str_append_c(str, tree->alt_char);
		else
			str_append_c(str, *name);
	}
	return str_c(str);
}

static void
dsync_mailbox_tree_build_name128_remotesep_hash(struct dsync_mailbox_tree *tree)
{
	struct dsync_mailbox_tree_iter *iter;
	struct dsync_mailbox_node *node;
	const char *name;
	guid_128_t *sha128;
	uint8_t *guid_p;

	i_assert(tree->sep != tree->remote_sep);
	i_assert(!hash_table_is_created(tree->name128_remotesep_hash));

	hash_table_create(&tree->name128_remotesep_hash, tree->pool, 0,
			  guid_128_hash, guid_128_cmp);
	iter = dsync_mailbox_tree_iter_init(tree);
	while (dsync_mailbox_tree_iter_next(iter, &name, &node)) {
		sha128 = p_new(tree->pool, guid_128_t, 1);
		T_BEGIN {
			const char *remote_name =
				convert_name_to_remote_sep(tree, name);
			mailbox_name_get_sha128(remote_name, *sha128);
		} T_END;
		guid_p = *sha128;
		hash_table_insert(tree->name128_remotesep_hash, guid_p, node);
	}
	dsync_mailbox_tree_iter_deinit(&iter);
}

int dsync_mailbox_tree_guid_hash_add(struct dsync_mailbox_tree *tree,
				     struct dsync_mailbox_node *node,
				     struct dsync_mailbox_node **old_node_r)
{
	struct dsync_mailbox_node *old_node;
	uint8_t *guid = node->mailbox_guid;

	if (guid_128_is_empty(node->mailbox_guid))
		return 0;

	*old_node_r = old_node = hash_table_lookup(tree->guid_hash, guid);
	if (old_node == NULL)
		hash_table_insert(tree->guid_hash, guid, node);
	else if (old_node != node)
		return -1;
	return 0;
}

int dsync_mailbox_tree_build_guid_hash(struct dsync_mailbox_tree *tree,
				       struct dsync_mailbox_node **dup_node1_r,
				       struct dsync_mailbox_node **dup_node2_r)
{
	struct dsync_mailbox_tree_iter *iter;
	struct dsync_mailbox_node *node, *old_node;
	const char *name;
	int ret = 0;

	if (!hash_table_is_created(tree->guid_hash)) {
		hash_table_create(&tree->guid_hash, tree->pool, 0,
				  guid_128_hash, guid_128_cmp);
	}
	iter = dsync_mailbox_tree_iter_init(tree);
	while (dsync_mailbox_tree_iter_next(iter, &name, &node)) {
		if (dsync_mailbox_tree_guid_hash_add(tree, node, &old_node) < 0) {
			*dup_node1_r = node;
			*dup_node2_r = old_node;
			ret = -1;
		}
	}
	dsync_mailbox_tree_iter_deinit(&iter);
	return ret;
}

struct dsync_mailbox_node *
dsync_mailbox_tree_lookup_guid(struct dsync_mailbox_tree *tree,
			       const guid_128_t guid)
{
	const uint8_t *guid_p = guid;

	return hash_table_lookup(tree->guid_hash, guid_p);
}

const struct dsync_mailbox_delete *
dsync_mailbox_tree_get_deletes(struct dsync_mailbox_tree *tree,
			       unsigned int *count_r)
{
	return array_get(&tree->deletes, count_r);
}

struct dsync_mailbox_node *
dsync_mailbox_tree_find_delete(struct dsync_mailbox_tree *tree,
			       const struct dsync_mailbox_delete *del)
{
	const uint8_t *guid_p = del->guid;

	i_assert(hash_table_is_created(tree->guid_hash));
	i_assert(tree->remote_sep != '\0');

	if (del->type == DSYNC_MAILBOX_DELETE_TYPE_MAILBOX) {
		/* find node by GUID */
		return hash_table_lookup(tree->guid_hash, guid_p);
	}

	/* find node by name. this is a bit tricky, since the hierarchy
	   separator may differ from ours. */
	if (tree->sep == tree->remote_sep) {
		if (!hash_table_is_created(tree->name128_hash))
			dsync_mailbox_tree_build_name128_hash(tree);
		return hash_table_lookup(tree->name128_hash, guid_p);
	} else {
		if (!hash_table_is_created(tree->name128_remotesep_hash))
			dsync_mailbox_tree_build_name128_remotesep_hash(tree);
		return hash_table_lookup(tree->name128_remotesep_hash, guid_p);
	}
}

void dsync_mailbox_tree_set_remote_sep(struct dsync_mailbox_tree *tree,
				       char remote_sep)
{
	i_assert(tree->remote_sep == '\0');

	tree->remote_sep = remote_sep;
}

static void
dsync_mailbox_tree_dup_nodes(struct dsync_mailbox_tree *dest_tree,
			     const struct dsync_mailbox_node *src,
			     string_t *path)
{
	size_t prefix_len = str_len(path);
	struct dsync_mailbox_node *node;

	if (prefix_len > 0) {
		str_append_c(path, dest_tree->sep);
		prefix_len++;
	}
	for (; src != NULL; src = src->next) {
		str_truncate(path, prefix_len);
		str_append(path, src->name);
		node = dsync_mailbox_tree_get(dest_tree, str_c(path));

		node->ns = src->ns;
		memcpy(node->mailbox_guid, src->mailbox_guid,
		       sizeof(node->mailbox_guid));
		node->uid_validity = src->uid_validity;
		node->uid_next = src->uid_next;
		node->existence = src->existence;
		node->last_renamed_or_created = src->last_renamed_or_created;
		node->subscribed = src->subscribed;
		node->last_subscription_change = src->last_subscription_change;

		if (src->first_child != NULL) {
			dsync_mailbox_tree_dup_nodes(dest_tree,
						     src->first_child, path);
		}
	}
}

struct dsync_mailbox_tree *
dsync_mailbox_tree_dup(const struct dsync_mailbox_tree *src)
{
	struct dsync_mailbox_tree *dest;
	string_t *str = t_str_new(128);

	dest = dsync_mailbox_tree_init(src->sep, src->alt_char);
	dsync_mailbox_tree_dup_nodes(dest, &src->root, str);
	return dest;
}

int dsync_mailbox_node_name_cmp(struct dsync_mailbox_node *const *n1,
				struct dsync_mailbox_node *const *n2)
{
	return strcmp((*n1)->name, (*n2)->name);
}

static bool
dsync_mailbox_nodes_equal(const struct dsync_mailbox_node *node1,
			  const struct dsync_mailbox_node *node2)
{
	return strcmp(node1->name, node2->name) == 0 &&
		node1->ns == node2->ns &&
		memcmp(node1->mailbox_guid, node2->mailbox_guid,
		       sizeof(node1->mailbox_guid)) == 0 &&
		node1->uid_validity == node2->uid_validity &&
		node1->existence == node2->existence &&
		node1->subscribed == node2->subscribed;
}

static bool
dsync_mailbox_branches_equal(struct dsync_mailbox_node *node1,
			     struct dsync_mailbox_node *node2)
{
	/* this function is used only for unit tests, so performance doesn't
	   really matter */
	struct dsync_mailbox_node *n, **snodes1, **snodes2;
	unsigned int i, count;

	for (n = node1, count = 0; n != NULL; n = n->next) count++;
	for (n = node2, i = 0; n != NULL; n = n->next) i++;
	if (i != count)
		return FALSE;
	if (count == 0)
		return TRUE;

	/* sort the trees by name */
	snodes1 = t_new(struct dsync_mailbox_node *, count);
	snodes2 = t_new(struct dsync_mailbox_node *, count);
	for (n = node1, i = 0; n != NULL; n = n->next, i++)
		snodes1[i] = n;
	for (n = node2, i = 0; n != NULL; n = n->next, i++)
		snodes2[i] = n;
	i_qsort(snodes1, count, sizeof(*snodes1), dsync_mailbox_node_name_cmp);
	i_qsort(snodes2, count, sizeof(*snodes2), dsync_mailbox_node_name_cmp);

	for (i = 0; i < count; i++) {
		if (!dsync_mailbox_nodes_equal(snodes1[i], snodes2[i]))
			return FALSE;
		if (!dsync_mailbox_branches_equal(snodes1[i]->first_child,
						  snodes2[i]->first_child))
			return FALSE;
	}
	return TRUE;
}

bool dsync_mailbox_trees_equal(struct dsync_mailbox_tree *tree1,
			       struct dsync_mailbox_tree *tree2)
{
	bool ret;

	T_BEGIN {
		ret = dsync_mailbox_branches_equal(&tree1->root, &tree2->root);
	} T_END;
	return ret;
}

const char *dsync_mailbox_node_to_string(const struct dsync_mailbox_node *node)
{
	return t_strdup_printf("guid=%s uid_validity=%u uid_next=%u subs=%s last_change=%ld last_subs=%ld",
			       guid_128_to_string(node->mailbox_guid),
			       node->uid_validity, node->uid_next,
			       node->subscribed ? "yes" : "no",
			       (long)node->last_renamed_or_created,
			       (long)node->last_subscription_change);
}

const char *
dsync_mailbox_delete_type_to_string(enum dsync_mailbox_delete_type type)
{
	switch (type) {
	case DSYNC_MAILBOX_DELETE_TYPE_MAILBOX:
		return "mailbox";
	case DSYNC_MAILBOX_DELETE_TYPE_DIR:
		return "dir";
	case DSYNC_MAILBOX_DELETE_TYPE_UNSUBSCRIBE:
		return "unsubscribe";
	}
	i_unreached();
}
