/* Copyright (C) 2002-2004 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "strescape.h"
#include "imap-quote.h"
#include "imap-match.h"
#include "commands.h"
#include "namespace.h"

enum {
	_MAILBOX_LIST_HIDE_CHILDREN	= 0x1000000,
	_MAILBOX_LIST_LISTEXT		= 0x0800000
};

struct cmd_list_context {
	const char *ref;
	const char *mask;
	enum mailbox_list_flags list_flags;

	struct namespace *ns;
	struct mailbox_list_context *list_ctx;
	struct imap_match_glob *glob;

	unsigned int lsub:1;
	unsigned int inbox:1;
	unsigned int inbox_found:1;
	unsigned int match_inbox:1;
};

static const char *
mailbox_flags2str(enum mailbox_flags flags, enum mailbox_list_flags list_flags)
{
	const char *str;

	if (flags & MAILBOX_PLACEHOLDER) {
		i_assert((flags & ~MAILBOX_CHILDREN) == MAILBOX_PLACEHOLDER);

		if ((list_flags & _MAILBOX_LIST_LISTEXT) == 0)
			flags = MAILBOX_NOSELECT;
		flags |= MAILBOX_CHILDREN;
	}
	if ((flags & MAILBOX_NONEXISTENT) != 0 &&
	    (list_flags & _MAILBOX_LIST_LISTEXT) == 0) {
		flags |= MAILBOX_NOSELECT;
		flags &= ~MAILBOX_NONEXISTENT;
	}

	if ((list_flags & _MAILBOX_LIST_HIDE_CHILDREN) != 0)
		flags &= ~(MAILBOX_CHILDREN|MAILBOX_NOCHILDREN);

	str = t_strconcat(
		(flags & MAILBOX_NOSELECT) ? " \\Noselect" : "",
		(flags & MAILBOX_NONEXISTENT) ? " \\NonExistent" : "",
		(flags & MAILBOX_PLACEHOLDER) ? " \\PlaceHolder" : "",
		(flags & MAILBOX_CHILDREN) ? " \\HasChildren" : "",
		(flags & MAILBOX_NOCHILDREN) ? " \\HasNoChildren" : "",
		(flags & MAILBOX_NOINFERIORS) ? " \\NoInferiors" : "",
		(flags & MAILBOX_MARKED) ? " \\Marked" : "",
		(flags & MAILBOX_UNMARKED) ? " \\UnMarked" : "",
		NULL);

	return *str == '\0' ? "" : str+1;
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

static int
list_namespace_mailboxes(struct client *client, struct cmd_list_context *ctx)
{
	struct mailbox_list *list;
	const char *name;
	string_t *str, *name_str;
	int ret;

	if (ctx->list_ctx == NULL)
		return 1;

	t_push();
	str = t_str_new(256);
	name_str = t_str_new(256);
	while ((list = mail_storage_mailbox_list_next(ctx->list_ctx)) != NULL) {
		str_truncate(name_str, 0);
		str_append(name_str, ctx->ns->prefix);
		str_append(name_str, list->name);

		if (ctx->ns->sep != ctx->ns->real_sep) {
                        char *p = str_c_modifyable(name_str);
			for (; *p != '\0'; p++) {
				if (*p == ctx->ns->real_sep)
					*p = ctx->ns->sep;
			}
		}
		name = str_c(name_str);

		if (*ctx->ns->prefix != '\0') {
			/* With masks containing '*' we do the checks here
			   so prefix is included in matching */
			if (ctx->glob != NULL &&
			    imap_match(ctx->glob, name) != IMAP_MATCH_YES)
				continue;
		} else if (strcasecmp(list->name, "INBOX") == 0) {
			if (!ctx->ns->inbox)
				continue;

			name = "INBOX";
			ctx->inbox_found = TRUE;
		}

		str_truncate(str, 0);
		str_printfa(str, "* %s (%s) \"%s\" ",
			    ctx->lsub ? "LSUB" : "LIST",
			    mailbox_flags2str(list->flags, ctx->list_flags),
			    ctx->ns->sep_str);
		imap_quote_append_string(str, name, FALSE);
		if (client_send_line(client, str_c(str)) == 0) {
			/* buffer is full, continue later */
			t_pop();
			return 0;
		}
	}

	if (!ctx->inbox_found && ctx->ns->inbox && ctx->match_inbox) {
		/* INBOX always exists */
		str_truncate(str, 0);
		str_printfa(str, "* LIST (\\Unmarked) \"%s\" \"INBOX\"",
			    ctx->ns->sep_str);
		client_send_line(client, str_c(str));
	}
	t_pop();

	ret = mail_storage_mailbox_list_deinit(ctx->list_ctx);
	ctx->list_ctx = NULL;
	return ret < 0 ? -1 : 1;
}

static void skip_prefix(const char **prefix, const char **mask, int inbox)
{
	size_t mask_len, prefix_len, len;

	prefix_len = strlen(*prefix);
	mask_len = strlen(*mask);
	len = I_MIN(prefix_len, mask_len);

	if (strncmp(*prefix, *mask, len) == 0 ||
	    (inbox && len >= 6 &&
	     strncasecmp(*prefix, *mask, 6) == 0)) {
		*prefix += len;
		*mask += len;
	}
}

static void
list_namespace_init(struct client *client, struct cmd_list_context *ctx)
{
	struct namespace *ns = ctx->ns;
	const char *cur_prefix, *cur_ref, *cur_mask;
	enum imap_match_result match;
	unsigned int count;
	size_t len;

	cur_prefix = ns->prefix;
	cur_ref = ctx->ref;
	cur_mask = ctx->mask;

	if (*ctx->ref != '\0') {
		skip_prefix(&cur_prefix, &cur_ref, ctx->inbox);

		if (*cur_ref != '\0' && *cur_prefix != '\0') {
			/* reference parameter didn't match with
			   namespace prefix. skip this. */
			return;
		}
	}

	if (*cur_ref == '\0' && *cur_prefix != '\0') {
		skip_prefix(&cur_prefix, &cur_mask,
			    ctx->inbox && cur_ref == ctx->ref);
	}

	ctx->glob = imap_match_init(client->cmd_pool, ctx->mask,
				    ctx->inbox && cur_ref == ctx->ref, ns->sep);

	if (*cur_ref != '\0' || *cur_prefix == '\0')
		match = IMAP_MATCH_CHILDREN;
	else {
		len = strlen(cur_prefix);
		if (cur_prefix[len-1] == ns->sep)
			cur_prefix = t_strndup(cur_prefix, len-1);
		match = ns->hidden ? IMAP_MATCH_NO :
			imap_match(ctx->glob, cur_prefix);

		if (match == IMAP_MATCH_YES) {
			/* The prefix itself matches */
                        enum mailbox_flags flags;
			string_t *str = t_str_new(128);

			len = strlen(ns->prefix);
			if (strncmp(ns->prefix, "INBOX", len-1) == 0) {
				/* FIXME: INBOX prefix - we should get real
				   mailbox flags.. */
				flags = MAILBOX_CHILDREN;
				ctx->inbox_found = TRUE;
			} else {
				flags = MAILBOX_PLACEHOLDER;
			}

			str_printfa(str, "* LIST (%s) \"%s\" ",
				    mailbox_flags2str(flags, ctx->list_flags),
				    ns->sep_str);
			imap_quote_append_string(str,
				t_strndup(ns->prefix, len-1), FALSE);
			client_send_line(client, str_c(str));
		}
	}

	if (match < 0)
		return;

	count = 0;
	if (*cur_prefix != '\0') {
		/* we'll have to fix mask */
		for (; *cur_prefix != '\0'; cur_prefix++) {
			if (*cur_prefix == ns->sep)
					count++;
		}
		if (count == 0)
			count = 1;

		while (count > 0) {
			if (*cur_ref != '\0') {
				while (*cur_ref != '\0' &&
				       *cur_ref++ != ns->sep)
					;
			} else {
				while (*cur_mask != '\0' && *cur_mask != '*' &&
				       *cur_mask != ns->sep)
					cur_mask++;

				if (*cur_mask == '*') {
					cur_mask = "*";
					break;
				}
				if (*cur_mask == '\0')
					break;
				cur_mask++;
			}
			count--;
		}
	}

	ctx->match_inbox = imap_match(ctx->glob, "INBOX") == IMAP_MATCH_YES;

	if (*cur_mask != '*' || strcmp(ctx->mask, "*") == 0) {
		/* a) we don't have '*' in mask
		   b) we want to display everything

		   we don't need to do separate matching ourself */
		ctx->glob = NULL;
	}

	cur_ref = namespace_fix_sep(ns, cur_ref);
	cur_mask = namespace_fix_sep(ns, cur_mask);

	ctx->list_ctx = mail_storage_mailbox_list_init(ns->storage,
						       cur_ref, cur_mask,
						       ctx->list_flags);
}

static int cmd_list_continue(struct client *client)
{
        struct cmd_list_context *ctx = client->cmd_context;
	int ret;

	for (; ctx->ns != NULL; ctx->ns = ctx->ns->next) {
		if (ctx->list_ctx == NULL)
			list_namespace_init(client, ctx);

		if ((ret = list_namespace_mailboxes(client, ctx)) < 0) {
			client_send_storage_error(client, ctx->ns->storage);
			return TRUE;
		}
		if (ret == 0)
			return FALSE;
	}

	client_send_tagline(client, !ctx->lsub ?
			    "OK List completed." :
			    "OK Lsub completed.");
	return TRUE;
}

int _cmd_list_full(struct client *client, int lsub)
{
	struct namespace *ns;
	struct imap_arg *args;
	enum mailbox_list_flags list_flags;
        struct cmd_list_context *ctx;
	const char *ref, *mask;

	/* [(<options>)] <reference> <mailbox wildcards> */
	if (!client_read_args(client, 0, 0, &args))
		return FALSE;

	if (lsub) {
		/* LSUB - we don't care about flags */
		list_flags = MAILBOX_LIST_SUBSCRIBED | MAILBOX_LIST_FAST_FLAGS |
			_MAILBOX_LIST_HIDE_CHILDREN;
	} else if (args[0].type != IMAP_ARG_LIST) {
		/* LIST - allow children flags, but don't require them */
		list_flags = 0;
	} else {
		list_flags = _MAILBOX_LIST_LISTEXT;
		if (!parse_list_flags(client, IMAP_ARG_LIST(&args[0])->args,
				      &list_flags))
			return TRUE;
		args++;

		/* don't show children flags unless explicitly specified */
		if ((list_flags & MAILBOX_LIST_CHILDREN) == 0)
			list_flags |= _MAILBOX_LIST_HIDE_CHILDREN;
	}

	ref = imap_arg_string(&args[0]);
	mask = imap_arg_string(&args[1]);

	if (ref == NULL || mask == NULL) {
		client_send_command_error(client, "Invalid arguments.");
		return TRUE;
	}

	if (*mask == '\0' && !lsub) {
		/* special request to return the hierarchy delimiter */
		ns = namespace_find(client->namespaces, &ref);
		if (ns == NULL) {
			const char *empty = "";
			ns = namespace_find(client->namespaces, &empty);
		}

		if (ns != NULL) {
			client_send_line(client, t_strconcat(
				"* LIST (\\Noselect) \"", ns->sep_str,
				"\" \"\"", NULL));
		}
		client_send_tagline(client, "OK List completed.");
	} else {
		ctx = p_new(client->cmd_pool, struct cmd_list_context, 1);
		ctx->ref = ref;
		ctx->mask = mask;
		ctx->list_flags = list_flags;
		ctx->lsub = lsub;
		ctx->inbox = strncasecmp(ref, "INBOX", 5) == 0 ||
			(*ref == '\0' && strncasecmp(mask, "INBOX", 5) == 0);
		ctx->ns = client->namespaces;

		client->cmd_context = ctx;
		if (!cmd_list_continue(client)) {
			/* unfinished */
			client->command_pending = TRUE;
			client->cmd_func = cmd_list_continue;
			return FALSE;
		}

		client->cmd_context = NULL;
		return TRUE;
	}
	return TRUE;
}

int cmd_list(struct client *client)
{
	return _cmd_list_full(client, FALSE);
}
