/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "mailbox-tree.h"

struct mailbox_tree_context {
	pool_t pool;
	char separator;
	bool parents_nonexistent;
	bool sorted;
	unsigned int node_size;

	struct mailbox_node *nodes;
};

struct mailbox_tree_iterate_context {
	struct mailbox_node *root, *next_node;
	unsigned int flags_mask;

	char separator;

	ARRAY(struct mailbox_node *) node_path;
	string_t *path_str;
	size_t parent_pos;

	bool first_child:1;
};

struct mailbox_tree_context *mailbox_tree_init(char separator)
{
	return mailbox_tree_init_size(separator, sizeof(struct mailbox_node));
}

struct mailbox_tree_context *
mailbox_tree_init_size(char separator, unsigned int mailbox_node_size)
{
	struct mailbox_tree_context *tree;

	i_assert(mailbox_node_size >= sizeof(struct mailbox_node));

	tree = i_new(struct mailbox_tree_context, 1);
	tree->pool = pool_alloconly_create(MEMPOOL_GROWING"mailbox_tree", 10240);
	tree->separator = separator;
	tree->node_size = mailbox_node_size;
	return tree;
}

void mailbox_tree_deinit(struct mailbox_tree_context **_tree)
{
	struct mailbox_tree_context *tree = *_tree;

	*_tree = NULL;
	pool_unref(&tree->pool);
	i_free(tree);
}

void mailbox_tree_set_separator(struct mailbox_tree_context *tree,
				char separator)
{
	tree->separator = separator;
}

void mailbox_tree_set_parents_nonexistent(struct mailbox_tree_context *tree)
{
	tree->parents_nonexistent = TRUE;
}

void mailbox_tree_clear(struct mailbox_tree_context *tree)
{
	p_clear(tree->pool);
	tree->nodes = NULL;
}

pool_t mailbox_tree_get_pool(struct mailbox_tree_context *tree)
{
	return tree->pool;
}

static struct mailbox_node * ATTR_NULL(2)
mailbox_tree_traverse(struct mailbox_tree_context *tree, const char *path,
		      bool create, bool *created_r)
{
	struct mailbox_node **node, *parent;
	const char *name;
	string_t *str;

	*created_r = FALSE;

	if (path == NULL)
		return tree->nodes;

	if (strncasecmp(path, "INBOX", 5) == 0 &&
	    (path[5] == '\0' || path[5] == tree->separator))
		path = t_strdup_printf("INBOX%s", path+5);

	parent = NULL;
	node = &tree->nodes;

	str = t_str_new(strlen(path)+1);
	for (name = path;; path++) {
		if (*path != tree->separator && *path != '\0')
			continue;

		str_truncate(str, 0);
		str_append_data(str, name, (size_t) (path - name));
		name = str_c(str);

		/* find the node */
		while (*node != NULL) {
			if (strcmp((*node)->name, name) == 0)
				break;

			node = &(*node)->next;
		}

		if (*node == NULL) {
			/* not found, create it */
			if (!create)
				break;

			*node = p_malloc(tree->pool, tree->node_size);
			(*node)->parent = parent;
			(*node)->name = p_strdup(tree->pool, name);
			if (tree->parents_nonexistent)
				(*node)->flags = MAILBOX_NONEXISTENT;
			tree->sorted = FALSE;
			*created_r = TRUE;
		}

		if (*path == '\0')
			break;

		name = path+1;

		parent = *node;
		node = &(*node)->children;
	}

	return *node;
}

struct mailbox_node *
mailbox_tree_get(struct mailbox_tree_context *tree, const char *path,
		 bool *created_r)
{
	struct mailbox_node *node;
	bool created;

	T_BEGIN {
		node = mailbox_tree_traverse(tree, path, TRUE, &created);
	} T_END;
	if (created && tree->parents_nonexistent)
		node->flags = 0;

	*created_r = created;
	return node;
}

struct mailbox_node *
mailbox_tree_lookup(struct mailbox_tree_context *tree, const char *path)
{
	struct mailbox_node *node;
	bool created;

	i_assert(tree != NULL);

	T_BEGIN {
		node = mailbox_tree_traverse(tree, path, FALSE, &created);
	} T_END;
	return node;
}

struct mailbox_tree_iterate_context *
mailbox_tree_iterate_init(struct mailbox_tree_context *tree,
			  struct mailbox_node *root, unsigned int flags_mask)
{
	struct mailbox_tree_iterate_context *ctx;

	ctx = i_new(struct mailbox_tree_iterate_context, 1);
	ctx->separator = tree->separator;
	ctx->root = root != NULL ? root : tree->nodes;
	ctx->flags_mask = flags_mask;
	ctx->path_str = str_new(default_pool, 256);
	i_array_init(&ctx->node_path, 16);

	ctx->next_node = ctx->root;
	return ctx;
}

static void
mailbox_tree_iterate_set_next_node(struct mailbox_tree_iterate_context *ctx)
{
	struct mailbox_node *node = ctx->next_node;
	struct mailbox_node *const *nodes;
	unsigned int i, count;

	if (node->children != NULL) {
		array_append(&ctx->node_path, &node, 1);
		ctx->parent_pos = str_len(ctx->path_str);
		node = node->children;
		ctx->first_child = TRUE;
	} else if (node->next != NULL) {
		node = node->next;
	} else {
		nodes = array_get(&ctx->node_path, &count);
		node = NULL;
		for (i = count; i != 0; i--) {
			size_t len = strlen(nodes[i-1]->name) + 1;

			i_assert(len <= ctx->parent_pos);
			ctx->parent_pos -= len;
			if (nodes[i-1]->next != NULL) {
				node = nodes[i-1]->next;
				ctx->first_child = TRUE;
				i--;

				if (ctx->parent_pos != 0)
					ctx->parent_pos--;
				break;
			}
		}
		array_delete(&ctx->node_path, i, count - i);
	}

	ctx->next_node = node;
}

struct mailbox_node *
mailbox_tree_iterate_next(struct mailbox_tree_iterate_context *ctx,
			  const char **path_r)
{
	struct mailbox_node *node;

	do {
		node = ctx->next_node;
		if (node == NULL)
			return NULL;

		str_truncate(ctx->path_str, ctx->parent_pos);
		if (ctx->first_child) {
			ctx->first_child = FALSE;
			if (node->parent != NULL) {
				str_append_c(ctx->path_str, ctx->separator);
				ctx->parent_pos++;
			}
		}
		str_append(ctx->path_str, node->name);

		mailbox_tree_iterate_set_next_node(ctx);
	} while ((node->flags & ctx->flags_mask) != ctx->flags_mask);

	*path_r = str_c(ctx->path_str);
	return node;
}

void mailbox_tree_iterate_deinit(struct mailbox_tree_iterate_context **_ctx)
{
	struct mailbox_tree_iterate_context *ctx = *_ctx;

	*_ctx = NULL;
	str_free(&ctx->path_str);
	array_free(&ctx->node_path);
	i_free(ctx);
}

static struct mailbox_node * ATTR_NULL(1, 2)
mailbox_tree_dup_branch(struct mailbox_tree_context *dest_tree,
			struct mailbox_node *dest_parent,
			const struct mailbox_node *src)
{
	struct mailbox_node *node, *dest_nodes = NULL, **dest = &dest_nodes;

	for (; src != NULL; src = src->next) {
		*dest = node = p_malloc(dest_tree->pool, dest_tree->node_size);
		node->name = p_strdup(dest_tree->pool, src->name);
		node->flags = src->flags;

		node->parent = dest_parent;
		node->children = mailbox_tree_dup_branch(dest_tree, node,
							 src->children);
		dest = &node->next;
	}
	return dest_nodes;
}

struct mailbox_tree_context *mailbox_tree_dup(struct mailbox_tree_context *src)
{
	struct mailbox_tree_context *dest;

	/* for now we don't need to support extra data */
	i_assert(src->node_size == sizeof(struct mailbox_node));

	dest = mailbox_tree_init_size(src->separator, src->node_size);
	dest->nodes = mailbox_tree_dup_branch(dest, NULL, src->nodes);
	return dest;
}

static int mailbox_node_name_cmp(struct mailbox_node *const *node1,
				 struct mailbox_node *const *node2)
{
	return strcmp((*node1)->name, (*node2)->name);
}

static void mailbox_tree_sort_branch(struct mailbox_node **nodes,
				     ARRAY_TYPE(mailbox_node) *tmparr)
{
	struct mailbox_node *node, *const *nodep, **dest;

	if (*nodes == NULL)
		return;

	/* first put the nodes into an array and sort it */
	array_clear(tmparr);
	for (node = *nodes; node != NULL; node = node->next)
		array_append(tmparr, &node, 1);
	array_sort(tmparr, mailbox_node_name_cmp);

	/* update the node pointers */
	dest = nodes;
	array_foreach(tmparr, nodep) {
		*dest = *nodep;
		dest = &(*dest)->next;
	}
	*dest = NULL;

	/* sort the children */
	for (node = *nodes; node != NULL; node = node->next)
		mailbox_tree_sort_branch(&node->children, tmparr);
}

void mailbox_tree_sort(struct mailbox_tree_context *tree)
{
	if (tree->sorted)
		return;
	tree->sorted = TRUE;

	T_BEGIN {
		ARRAY_TYPE(mailbox_node) tmparr;

		t_array_init(&tmparr, 32);
		mailbox_tree_sort_branch(&tree->nodes, &tmparr);
	} T_END;
}
