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
} ListData;

static const char *mailbox_flags2str(MailboxFlags flags)
{
	const char *str;

	str = t_strconcat((flags & MAILBOX_NOSELECT) ? " \\Noselect" : "",
			  (flags & MAILBOX_CHILDREN) ? " \\HasChildren" : "",
			  (flags & MAILBOX_NOCHILDREN) ? " \\HasNoChildren" :"",
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

	t_push();
	for (name = path;; path++) {
		if (*path != separator && *path != '\0')
			continue;

		/* escaping is done here to make sure we don't try to escape
		   the separator char */
		name = imap_escape(t_strndup(name, (unsigned int) (path-name)));

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

		if (*path == '\0')
			break;

		name = path+1;
		parent = (*node)->name;
		node = &(*node)->children;
	}
	t_pop();

	return *node;
}

static void list_func(MailStorage *storage __attr_unused__, const char *name,
		     MailboxFlags flags, void *user_data)
{
	ListData *data = user_data;
	ListNode *node;

	node = list_node_get(data->pool, &data->nodes, name,
			     data->storage->hierarchy_sep);

	/* set the flags, this also nicely overrides the NOSELECT flag
	   set by list_node_get() */
	node->flags = flags;
}

static void list_send(Client *client, ListNode *node, const char *cmd,
		      const char *path, const char *sep,
		      const ImapMatchGlob *glob)
{
	const char *name;

	for (; node != NULL; node = node->next) {
		t_push();

		name = path == NULL ? node->name :
			t_strconcat(path, sep, node->name, NULL);

		if (node->children == NULL)
			node->flags |= MAILBOX_NOCHILDREN;
		else {
			node->flags |= MAILBOX_CHILDREN;
			list_send(client, node->children, cmd, name, sep, glob);
		}

		if ((node->flags & MAILBOX_NOSELECT) &&
		    imap_match(glob, name, 0, NULL) < 0) {
			/* doesn't match the mask */
			t_pop();
			continue;
		}

		/* node->name should already be escaped */
		client_send_line(client,
				 t_strdup_printf("* %s (%s) \"%s\" \"%s\"", cmd,
						 mailbox_flags2str(node->flags),
						 sep, name));
		t_pop();
	}
}

int cmd_list_full(Client *client, int subscribed)
{
	ListData data;
	const char *ref, *pattern;
	char sep_chr, sep[3];

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
	} else {
		if (*ref != '\0') {
			/* join reference + pattern */
			if (*pattern == sep_chr &&
			    ref[strlen(ref)-1] == sep_chr) {
				/* LIST A. .B -> A.B */
				pattern++;
			}
			pattern = t_strconcat(ref, pattern, NULL);
		}

		data.pool = pool_create("ListData", 10240, FALSE);
		data.nodes = NULL;
		data.storage = client->storage;

		if (!subscribed) {
			client->storage->find_mailboxes(client->storage,
							pattern,
							list_func, &data);
		} else {
			client->storage->find_subscribed(client->storage,
							 pattern,
							 list_func, &data);
		}

		list_send(client, data.nodes, subscribed ? "LSUB" : "LIST",
			  NULL, sep, imap_match_init(pattern, TRUE, sep_chr));
		pool_unref(data.pool);
	}

	client_send_tagline(client, subscribed ?
			    "OK Lsub completed." :
			    "OK List completed.");
	return TRUE;
}

int cmd_list(Client *client)
{
	return cmd_list_full(client, FALSE);
}
