/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "strescape.h"
#include "commands.h"

struct list_node {
	struct list_node *next;
	struct list_node *children;

	char *name; /* escaped */
	enum mailbox_flags flags;
};

struct list_context {
	pool_t pool;
	struct list_node *nodes;
	struct mail_storage *storage;
};

static const char *mailbox_flags2str(enum mailbox_flags flags)
{
	const char *str;

	str = t_strconcat((flags & MAILBOX_NOSELECT) ? " \\Noselect" : "",
			  (flags & MAILBOX_NOINFERIORS) ? " \\NoInferiors" : "",
			  (flags & MAILBOX_MARKED) ? " \\Marked" : "",
			  (flags & MAILBOX_UNMARKED) ? " \\UnMarked" : "",
			  NULL);

	return *str == '\0' ? "" : str+1;
}

static struct list_node *list_node_get(pool_t pool, struct list_node **node,
				       const char *path, char separator)
{
	const char *name, *parent;

	parent = NULL;

	for (name = path;; path++) {
		if (*path != separator && *path != '\0')
			continue;

		t_push();

		/* escaping is done here to make sure we don't try to escape
		   the separator char */
		name = str_escape(t_strdup_until(name, path));

		/* find the node */
		while (*node != NULL) {
			if (strcmp((*node)->name, name) == 0)
				break;

			node = &(*node)->next;
		}

		if (*node == NULL) {
			/* not found, create it */
			*node = p_new(pool, struct list_node, 1);
			(*node)->name = p_strdup(pool, name);
			(*node)->flags = MAILBOX_NOSELECT;
		}

		t_pop();

		if (*path == '\0')
			break;

		name = path+1;
		parent = (*node)->name;
		node = &(*node)->children;
	}

	return *node;
}

static void list_send(struct client *client, struct list_node *node,
		      const char *cmd, const char *path, const char *sep)
{
	const char *name, *str;

	for (; node != NULL; node = node->next) {
		t_push();

		/* Send INBOX always uppercased */
		if (path != NULL)
			name = t_strconcat(path, sep, node->name, NULL);
		else if (strcasecmp(node->name, "INBOX") == 0)
			name = "INBOX";
		else
			name = node->name;

		/* node->name should already be escaped */
		str = t_strdup_printf("* %s (%s) \"%s\" \"%s\"", cmd,
				      mailbox_flags2str(node->flags),
				      sep, name);
		client_send_line(client, str);

		if (node->children != NULL)
			list_send(client, node->children, cmd, name, sep);

		t_pop();
	}
}

static void list_unsorted(struct client *client,
			  struct mailbox_list_context *ctx,
			  const char *cmd, const char *sep)
{
	struct mailbox_list *list;
	const char *name, *str;

	while ((list = client->storage->list_mailbox_next(ctx)) != NULL) {
		t_push();
		if (strcasecmp(list->name, "INBOX") == 0)
			name = "INBOX";
		else
			name = str_escape(list->name);
		str = t_strdup_printf("* %s (%s) \"%s\" \"%s\"", cmd,
				      mailbox_flags2str(list->flags),
				      sep, name);
		client_send_line(client, str);
		t_pop();
	}
}

static void list_and_sort(struct client *client,
			  struct mailbox_list_context *ctx,
			  const char *cmd, const char *sep)
{
	struct mailbox_list *list;
	struct list_node *nodes, *node;
	pool_t pool;

	pool = pool_alloconly_create("list_mailboxes", 10240);
	nodes = NULL;

	while ((list = client->storage->list_mailbox_next(ctx)) != NULL) {
		node = list_node_get(pool, &nodes, list->name,
				     client->storage->hierarchy_sep);

		/* set the flags, this also overrides the
		   NOSELECT flag set by list_node_get() */
		node->flags = list->flags;
	}

	list_send(client, nodes, cmd, NULL, sep);
	pool_unref(pool);
}

static int list_mailboxes(struct client *client, const char *mask,
			  int subscribed, const char *sep)
{
	struct mailbox_list_context *ctx;
	const char *cmd;
	int sorted;

	ctx = client->storage->
		list_mailbox_init(client->storage, mask,
				  subscribed ? MAILBOX_LIST_SUBSCRIBED : 0,
				  &sorted);
	if (ctx == NULL)
		return FALSE;

        cmd = subscribed ? "LSUB" : "LIST";
	if (sorted || (client_workarounds & WORKAROUND_LIST_SORT) == 0)
		list_unsorted(client, ctx, cmd, sep);
	else
		list_and_sort(client, ctx, cmd, sep);

	return client->storage->list_mailbox_deinit(ctx);
}

int _cmd_list_full(struct client *client, int subscribed)
{
	const char *ref, *mask;
	char sep_chr, sep[3];
	int failed;

	sep_chr = client->storage->hierarchy_sep;
	if (IS_ESCAPED_CHAR(sep_chr)) {
		sep[0] = '\\';
		sep[1] = sep_chr;
		sep[2] = '\0';
	} else {
		sep[0] = sep_chr;
		sep[1] = '\0';
	}

	/* <reference> <mailbox wildcards> */
	if (!client_read_string_args(client, 2, &ref, &mask))
		return FALSE;

	if (*mask == '\0' && !subscribed) {
		/* special request to return the hierarchy delimiter */
		client_send_line(client, t_strconcat(
			"* LIST (\\Noselect) \"", sep, "\" \"\"", NULL));
		failed = FALSE;
	} else {
		if (*ref != '\0') {
			/* join reference + mask */
			if (*mask == sep_chr &&
			    ref[strlen(ref)-1] == sep_chr) {
				/* LIST A. .B -> A.B */
				mask++;
			}
			if (*mask != sep_chr &&
			    ref[strlen(ref)-1] != sep_chr) {
				/* LIST A B -> A.B */
				mask = t_strconcat(ref, sep, mask, NULL);
			} else {
				mask = t_strconcat(ref, mask, NULL);
			}
		}

		failed = !list_mailboxes(client, mask, subscribed, sep);
	}

	if (failed)
		client_send_storage_error(client);
	else {
		client_send_tagline(client, subscribed ?
				    "OK Lsub completed." :
				    "OK List completed.");
	}
	return TRUE;
}

int cmd_list(struct client *client)
{
	return _cmd_list_full(client, FALSE);
}
