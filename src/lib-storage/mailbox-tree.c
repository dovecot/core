/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "mailbox-tree.h"

struct mailbox_tree_context {
	pool_t pool;
	char separator;
	struct mailbox_node *nodes;
};

struct mailbox_tree_iterate_context {
	struct mailbox_node *root, *next_node;
	unsigned int flags_mask;

	char separator;

	ARRAY_DEFINE(node_path, struct mailbox_node *);
	string_t *path_str;
	size_t parent_pos;

	unsigned int first_child:1;
};

struct mailbox_tree_context *mailbox_tree_init(char separator)
{
	struct mailbox_tree_context *tree;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"mailbox_tree", 10240);

	tree = p_new(pool, struct mailbox_tree_context, 1);
	tree->pool = pool;
	tree->separator = separator;
	return tree;
}

void mailbox_tree_deinit(struct mailbox_tree_context **_tree)
{
	struct mailbox_tree_context *tree = *_tree;

	*_tree = NULL;
	pool_unref(&tree->pool);
}

static struct mailbox_node *
mailbox_tree_traverse(struct mailbox_tree_context *tree, const char *path,
		      bool create, bool *created)
{
	struct mailbox_node **node, *parent;
	const char *name;
	string_t *str;

	if (created != NULL)
		*created = FALSE;

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
		str_append_n(str, name, (size_t) (path - name));
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

			*node = p_new(tree->pool, struct mailbox_node, 1);
			(*node)->parent = parent;
			(*node)->name = p_strdup(tree->pool, name);

			if (created != NULL)
				*created = TRUE;
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
		 bool *created)
{
	struct mailbox_node *node;

	T_BEGIN {
		node = mailbox_tree_traverse(tree, path, TRUE, created);
	} T_END;
	return node;
}

struct mailbox_node *
mailbox_tree_lookup(struct mailbox_tree_context *tree, const char *path)
{
	struct mailbox_node *node;

	T_BEGIN {
		node = mailbox_tree_traverse(tree, path, FALSE, NULL);
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
	ctx->root = root != NULL ? root : mailbox_tree_get(tree, NULL, NULL);
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
			unsigned int len = strlen(nodes[i-1]->name) + 1;

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
