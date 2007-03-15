/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "mailbox-tree.h"

struct mailbox_tree_context {
	pool_t pool;
	char separator;
	struct mailbox_node *nodes;
};

struct mailbox_tree_context *mailbox_tree_init(char separator)
{
	struct mailbox_tree_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"mailbox_tree", 10240);

	ctx = p_new(pool, struct mailbox_tree_context, 1);
	ctx->pool = pool;
	ctx->separator = separator;
	return ctx;
}

void mailbox_tree_deinit(struct mailbox_tree_context *ctx)
{
	pool_unref(ctx->pool);
}

static struct mailbox_node *
mailbox_tree_traverse(struct mailbox_tree_context *ctx, const char *path,
		      bool create, bool *created)
{
	struct mailbox_node **node;
	const char *name;
	string_t *str;

	if (created != NULL)
		*created = FALSE;

	if (path == NULL)
		return ctx->nodes;

	t_push();

	if (strncasecmp(path, "INBOX", 5) == 0 &&
	    (path[5] == '\0' || path[5] == ctx->separator))
		path = t_strdup_printf("INBOX%s", path+5);

	node = &ctx->nodes;

	str = t_str_new(strlen(path)+1);
	for (name = path;; path++) {
		if (*path != ctx->separator && *path != '\0')
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

			*node = p_new(ctx->pool, struct mailbox_node, 1);
			(*node)->name = p_strdup(ctx->pool, name);

			if (*path != '\0') {
				(*node)->flags = MAILBOX_NONEXISTENT |
					MAILBOX_CHILDREN;
			} else {
				if (created != NULL)
					*created = TRUE;
			}
		}

		if (*path == '\0')
			break;

		name = path+1;
		node = &(*node)->children;
	}
	t_pop();

	return *node;
}

struct mailbox_node *
mailbox_tree_get(struct mailbox_tree_context *ctx, const char *path,
		 bool *created)
{
	return mailbox_tree_traverse(ctx, path, TRUE, created);
}

struct mailbox_node *
mailbox_tree_update(struct mailbox_tree_context *ctx, const char *path)
{
	return mailbox_tree_traverse(ctx, path, FALSE, NULL);
}
