/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "imap-match.h"

typedef struct _ListNode ListNode;

struct _ListNode {
	ListNode *next;
	ListNode *children;

	char *name; /* escaped */
	MailboxFlags flags;
};

typedef struct {
	Pool pool;
	ListNode *nodes;
	MailStorage *storage;
} ListContext;

static const char *mailbox_flags2str(MailboxFlags flags)
{
	const char *str;

	str = t_strconcat((flags & MAILBOX_NOSELECT) ? " \\Noselect" : "",
			  (flags & MAILBOX_NOINFERIORS) ? " \\NoInferiors" : "",
			  (flags & MAILBOX_MARKED) ? " \\Marked" : "",
			  (flags & MAILBOX_UNMARKED) ? " \\UnMarked" : "",
			  NULL);

	return *str == '\0' ? "" : str+1;
}

static ListNode *list_node_get(Pool pool, ListNode **node,
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
		name = imap_escape(t_strdup_until(name, path));

		/* find the node */
		while (*node != NULL) {
			if (strcmp((*node)->name, name) == 0)
				break;

			node = &(*node)->next;
		}

		if (*node == NULL) {
			/* not found, create it */
			*node = p_new(pool, ListNode, 1);
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

static void list_func(MailStorage *storage __attr_unused__, const char *name,
		      MailboxFlags flags, void *context)
{
	ListContext *ctx = context;
	ListNode *node;

	node = list_node_get(ctx->pool, &ctx->nodes, name,
			     ctx->storage->hierarchy_sep);

	/* set the flags, this also nicely overrides the NOSELECT flag
	   set by list_node_get() */
	node->flags = flags;
}

static void list_send(Client *client, ListNode *node, const char *cmd,
		      const char *path, const char *sep, ImapMatchGlob *glob)
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

		if (node->children != NULL)
			list_send(client, node->children, cmd, name, sep, glob);

		if ((node->flags & MAILBOX_NOSELECT) == 0 ||
		    imap_match(glob, name) > 0) {
			/* node->name should already be escaped */
			str = t_strdup_printf("* %s (%s) \"%s\" \"%s\"", cmd,
					      mailbox_flags2str(node->flags),
					      sep, name);
			client_send_line(client, str);
		}
		t_pop();
	}
}

int _cmd_list_full(Client *client, int subscribed)
{
	ListContext ctx;
	const char *ref, *pattern;
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
	if (!client_read_string_args(client, 2, &ref, &pattern))
		return FALSE;

	if (*pattern == '\0' && !subscribed) {
		/* special request to return the hierarchy delimiter */
		client_send_line(client, t_strconcat(
			"* LIST (\\Noselect) \"", sep, "\" \"\"", NULL));
		failed = FALSE;
	} else {
		if (*ref != '\0') {
			/* join reference + pattern */
			if (*pattern == sep_chr &&
			    ref[strlen(ref)-1] == sep_chr) {
				/* LIST A. .B -> A.B */
				pattern++;
			}
			if (*pattern != sep_chr &&
			    ref[strlen(ref)-1] != sep_chr) {
				/* LIST A B -> A.B */
				pattern = t_strconcat(ref, sep, pattern, NULL);
			} else {
				pattern = t_strconcat(ref, pattern, NULL);
			}
		}

		ctx.pool = pool_alloconly_create("ListContext", 10240);
		ctx.nodes = NULL;
		ctx.storage = client->storage;

		if (!subscribed) {
			failed = !client->storage->
				find_mailboxes(client->storage,
					       pattern, list_func, &ctx);
		} else {
			failed = !client->storage->
				find_subscribed(client->storage,
						pattern, list_func, &ctx);
		}

		if (!failed) {
			list_send(client, ctx.nodes,
				  subscribed ? "LSUB" : "LIST", NULL, sep,
				  imap_match_init(pattern, TRUE, sep_chr));
		}
		pool_unref(ctx.pool);
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

int cmd_list(Client *client)
{
	return _cmd_list_full(client, FALSE);
}
