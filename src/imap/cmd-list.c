/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "strescape.h"
#include "imap-match.h"
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

struct list_send_context {
	struct client *client;
	const char *response_name;
	const char *sep;
	struct imap_match_glob *glob;
	int listext;
};

static const char *mailbox_flags2str(enum mailbox_flags flags, int listext)
{
	const char *str;

	if (flags & MAILBOX_PLACEHOLDER) {
		if (flags == MAILBOX_PLACEHOLDER) {
			if (!listext)
				flags = MAILBOX_NOSELECT;
		} else {
			/* it was at one point, but then we got better specs */
			flags &= ~MAILBOX_PLACEHOLDER;
		}
		flags |= MAILBOX_CHILDREN;
	}
	if ((flags & MAILBOX_NONEXISTENT) != 0 && !listext)
		flags |= MAILBOX_NOSELECT;

	str = t_strconcat((flags & MAILBOX_NOSELECT) ? " \\Noselect" : "",
			  (flags & MAILBOX_NONEXISTENT) ? " \\NonExistent" : "",
			  (flags & MAILBOX_PLACEHOLDER) ? " \\PlaceHolder" : "",
			  (flags & MAILBOX_CHILDREN) ? " \\Children" : "",
			  (flags & MAILBOX_NOCHILDREN) ? " \\NoChildren" : "",
			  (flags & MAILBOX_NOINFERIORS) ? " \\NoInferiors" : "",
			  (flags & MAILBOX_MARKED) ? " \\Marked" : "",
			  (flags & MAILBOX_UNMARKED) ? " \\UnMarked" : "",
			  NULL);

	return *str == '\0' ? "" : str+1;
}

static void list_node_update(pool_t pool, struct list_node **node,
			     const char *path, char separator,
			     enum mailbox_flags dir_flags,
			     enum mailbox_flags flags)
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
			(*node)->flags = *path == '\0' ? flags : dir_flags;
		} else {
			if (*path == '\0') {
				if (((*node)->flags & MAILBOX_NOSELECT) != 0 &&
				    (flags & MAILBOX_NOSELECT) == 0) {
					/* overrides previous flag */
					(*node)->flags &= ~MAILBOX_NOSELECT;
				}

				(*node)->flags |= flags;
			}
		}

		t_pop();

		if (*path == '\0')
			break;

		name = path+1;
		parent = (*node)->name;
		node = &(*node)->children;
	}
}

static void list_send(struct list_send_context *ctx, struct list_node *node,
		      const char *path)
{
	const char *name, *send_name, *str, *flagstr;
	enum imap_match_result match;

	for (; node != NULL; node = node->next) {
		t_push();

		/* Send INBOX always uppercased */
		if (path != NULL)
			name = t_strconcat(path, ctx->sep, node->name, NULL);
		else if (strcasecmp(node->name, "INBOX") == 0)
			name = "INBOX";
		else
			name = node->name;
		send_name = name;

		if ((node->flags & MAILBOX_PLACEHOLDER) == 0 &&
		    (node->flags & MAILBOX_NOSELECT) == 0)
			match = IMAP_MATCH_YES;
		else {
			/* make sure the placeholder matches. */
			const char *buf;

			buf = str_unescape(t_strdup_noconst(name));
			match = imap_match(ctx->glob, buf);
			if (match == IMAP_MATCH_CHILDREN) {
				send_name = t_strconcat(name, ctx->sep, NULL);
				buf = str_unescape(t_strdup_noconst(send_name));
				match = imap_match(ctx->glob, buf);
			}
		}

		if (match == IMAP_MATCH_YES) {
			/* node->name should already be escaped */
			flagstr = mailbox_flags2str(node->flags, ctx->listext);
			str = t_strdup_printf("* %s (%s) \"%s\" \"%s\"",
					      ctx->response_name, flagstr,
					      ctx->sep, send_name);
			client_send_line(ctx->client, str);
		}

		if (node->children != NULL)
			list_send(ctx, node->children,  name);

		t_pop();
	}
}

static void list_and_sort(struct client *client,
			  struct mailbox_list_context *ctx,
			  const char *response_name,
			  const char *sep, const char *mask,
			  enum mailbox_list_flags list_flags, int listext)
{
	struct mailbox_list *list;
	struct list_node *nodes;
	struct list_send_context send_ctx;
	enum mailbox_flags dir_flags;
	pool_t pool;

	dir_flags = (list_flags & MAILBOX_LIST_SUBSCRIBED) ?
		MAILBOX_PLACEHOLDER : MAILBOX_NOSELECT;

	pool = pool_alloconly_create("list_mailboxes", 10240);
	nodes = NULL;

	while ((list = client->storage->list_mailbox_next(ctx)) != NULL) {
		list_node_update(pool, &nodes, list->name,
				 client->storage->hierarchy_sep,
				 dir_flags, list->flags);
	}

	send_ctx.client = client;
	send_ctx.response_name = response_name;
	send_ctx.sep = sep;
	send_ctx.glob = imap_match_init(data_stack_pool, mask, TRUE,
					client->storage->hierarchy_sep);
	send_ctx.listext = listext;

	list_send(&send_ctx, nodes, NULL);
	imap_match_deinit(send_ctx.glob);
	pool_unref(pool);
}

static void list_unsorted(struct client *client,
			  struct mailbox_list_context *ctx,
			  const char *reply, const char *sep, int listext)
{
	struct mailbox_list *list;
	const char *name, *str;

	while ((list = client->storage->list_mailbox_next(ctx)) != NULL) {
		t_push();
		if (strcasecmp(list->name, "INBOX") == 0)
			name = "INBOX";
		else
			name = str_escape(list->name);
		str = t_strdup_printf("* %s (%s) \"%s\" \"%s\"", reply,
				      mailbox_flags2str(list->flags, listext),
				      sep, name);
		client_send_line(client, str);
		t_pop();
	}
}

static int parse_list_flags(struct client *client, struct imap_arg *args,
			    enum mailbox_list_flags *list_flags)
{
	const char *atom;

	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_send_command_error(client,
				"List options contains non-atoms.");
			return FALSE;
		}

		atom = IMAP_ARG_STR(args);

		if (strcasecmp(atom, "SUBSCRIBED") == 0)
			*list_flags |= MAILBOX_LIST_SUBSCRIBED;
		else if (strcasecmp(atom, "CHILDREN") == 0)
			*list_flags |= MAILBOX_LIST_CHILDREN;
		else {
			client_send_tagline(client, t_strconcat(
				"BAD Invalid list option ", atom, NULL));
			return FALSE;
		}
		args++;
	}
	return TRUE;
}

int _cmd_list_full(struct client *client, int lsub)
{
	struct imap_arg *args;
        enum mailbox_list_flags list_flags;
	struct mailbox_list_context *ctx;
	const char *ref, *mask;
	char sep_chr, sep[3];
	int failed, sorted, listext;

	sep_chr = client->storage->hierarchy_sep;
	if (IS_ESCAPED_CHAR(sep_chr)) {
		sep[0] = '\\';
		sep[1] = sep_chr;
		sep[2] = '\0';
	} else {
		sep[0] = sep_chr;
		sep[1] = '\0';
	}

	/* [(<options>)] <reference> <mailbox wildcards> */
	if (!client_read_args(client, 0, 0, &args))
		return FALSE;

	listext = FALSE;
	if (lsub)
		list_flags = MAILBOX_LIST_SUBSCRIBED | MAILBOX_LIST_FAST_FLAGS;
	else {
		list_flags = 0;
		if (args[0].type == IMAP_ARG_LIST) {
			listext = TRUE;
			if (!parse_list_flags(client,
					      IMAP_ARG_LIST(&args[0])->args,
					      &list_flags))
				return TRUE;
			args++;
		}
	}

	ref = imap_arg_string(&args[0]);
	mask = imap_arg_string(&args[1]);

	if (ref == NULL || mask == NULL) {
		client_send_command_error(client, "Invalid FETCH arguments.");
		return TRUE;
	}

	if (*mask == '\0' && !lsub) {
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

		ctx = client->storage->list_mailbox_init(client->storage, mask,
							 list_flags, &sorted);
		if (ctx == NULL)
			failed = TRUE;
		else {
			const char *response_name = lsub ? "LSUB" : "LIST";

			if (sorted) {
				list_unsorted(client, ctx, response_name, sep,
					      listext);
			} else {
				list_and_sort(client, ctx, response_name, sep,
					      mask, list_flags, listext);
			}

			failed = !client->storage->list_mailbox_deinit(ctx);
		}
	}

	if (failed)
		client_send_storage_error(client);
	else {
		client_send_tagline(client, lsub ?
				    "OK Lsub completed." :
				    "OK List completed.");
	}
	return TRUE;
}

int cmd_list(struct client *client)
{
	return _cmd_list_full(client, FALSE);
}
