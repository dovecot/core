/* Copyright (C) 2002-2004 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "strescape.h"
#include "imap-quote.h"
#include "imap-match.h"
#include "commands.h"
#include "mail-namespace.h"

enum {
	_MAILBOX_LIST_ITER_HIDE_CHILDREN	= 0x1000000,
	_MAILBOX_LIST_ITER_LISTEXT		= 0x0800000
};

struct cmd_list_context {
	const char *ref;
	const char *mask;
	enum mailbox_list_flags list_flags;

	struct mail_namespace *ns;
	struct mailbox_list_iterate_context *list_iter;
	struct imap_match_glob *glob;

	unsigned int lsub:1;
	unsigned int inbox_found:1;
	unsigned int match_inbox:1;
};

static void
mailbox_flags2str(string_t *str, enum mailbox_info_flags flags,
		  enum mailbox_list_flags list_flags)
{
	unsigned int orig_len = str_len(str);

	if ((flags & MAILBOX_NONEXISTENT) != 0 &&
	    (list_flags & _MAILBOX_LIST_ITER_LISTEXT) == 0) {
		flags |= MAILBOX_NOSELECT;
		flags &= ~MAILBOX_NONEXISTENT;
	}

	if ((list_flags & _MAILBOX_LIST_ITER_HIDE_CHILDREN) != 0)
		flags &= ~(MAILBOX_CHILDREN|MAILBOX_NOCHILDREN);

	if ((flags & MAILBOX_NOSELECT) != 0)
		str_append(str, "\\Noselect ");
	if ((flags & MAILBOX_NONEXISTENT) != 0)
		str_append(str, "\\NonExistent ");
	if ((flags & MAILBOX_CHILDREN) != 0)
		str_append(str, "\\HasChildren ");
	if ((flags & MAILBOX_NOCHILDREN) != 0)
		str_append(str, "\\HasNoChildren ");
	if ((flags & MAILBOX_NOINFERIORS) != 0)
		str_append(str, "\\NoInferiors ");
	if ((flags & MAILBOX_MARKED) != 0)
		str_append(str, "\\Marked ");
	if ((flags & MAILBOX_UNMARKED) != 0)
		str_append(str, "\\UnMarked ");

	if (str_len(str) != orig_len)
		str_truncate(str, str_len(str)-1);
}

static bool
parse_list_flags(struct client_command_context *cmd, struct imap_arg *args,
		 enum mailbox_list_flags *list_flags)
{
	const char *atom;

	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_send_command_error(cmd,
				"List options contains non-atoms.");
			return FALSE;
		}

		atom = IMAP_ARG_STR(args);

		if (strcasecmp(atom, "SUBSCRIBED") == 0)
			*list_flags |= MAILBOX_LIST_ITER_SUBSCRIBED;
		else if (strcasecmp(atom, "CHILDREN") == 0)
			*list_flags |= MAILBOX_LIST_ITER_CHILDREN;
		else {
			client_send_tagline(cmd, t_strconcat(
				"BAD Invalid list option ", atom, NULL));
			return FALSE;
		}
		args++;
	}
	return TRUE;
}

static void
list_namespace_inbox(struct client *client, struct cmd_list_context *ctx)
{
	const char *str;

	if (!ctx->inbox_found && ctx->ns->inbox && ctx->match_inbox &&
	    (ctx->list_flags & MAILBOX_LIST_ITER_SUBSCRIBED) == 0) {
		/* INBOX always exists */
		str = t_strdup_printf("* LIST (\\Unmarked) \"%s\" \"INBOX\"",
				      ctx->ns->sep_str);
		client_send_line(client, str);
	}
}

static int
list_namespace_mailboxes(struct client *client, struct cmd_list_context *ctx)
{
	struct mailbox_info *info;
	const char *name;
	string_t *str, *name_str;
	int ret = 0;

	if (ctx->list_iter == NULL) {
		list_namespace_inbox(client, ctx);
		return 1;
	}

	t_push();
	str = t_str_new(256);
	name_str = t_str_new(256);
	while ((info = mailbox_list_iter_next(ctx->list_iter)) != NULL) {
		str_truncate(name_str, 0);
		if (ctx->ns->inbox && strcasecmp(info->name, "INBOX") == 0) {
			/* Listing INBOX from inbox=yes namespace.
			   Don't insert the namespace prefix. */
			if (!ctx->match_inbox) {
				/* The mask doesn't match INBOX (eg. prefix.%).
				   We still want to list prefix.INBOX if it has
				   children. Otherwise we don't want to list
				   this INBOX at all. */
				if ((info->flags & MAILBOX_CHILDREN) == 0)
					continue;
				str_append(name_str, ctx->ns->prefix);
			}
		} else {
			str_append(name_str, ctx->ns->prefix);
		}
		str_append(name_str, info->name);

		if (ctx->ns->sep != ctx->ns->real_sep) {
                        char *p = str_c_modifiable(name_str);
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
		}
		if (strcasecmp(name, "INBOX") == 0) {
			if (!ctx->ns->inbox)
				continue;

			name = "INBOX";
			ctx->inbox_found = TRUE;
		}

		str_truncate(str, 0);
		str_printfa(str, "* %s (", ctx->lsub ? "LSUB" : "LIST");
		mailbox_flags2str(str, info->flags, ctx->list_flags);
		str_printfa(str, ") \"%s\" ", ctx->ns->sep_str);
		imap_quote_append_string(str, name, FALSE);
		if (client_send_line(client, str_c(str)) == 0) {
			/* buffer is full, continue later */
			t_pop();
			return 0;
		}
	}

	if (mailbox_list_iter_deinit(&ctx->list_iter) < 0) {
		mail_storage_set_list_error(ctx->ns->storage);
		ret = -1;
	}

	if (ret == 0)
		list_namespace_inbox(client, ctx);

	t_pop();
	return ret < 0 ? -1 : 1;
}

static bool list_mask_has_wildcards(const char *mask)
{
	for (; *mask != '\0'; mask++) {
		if (*mask == '%' || *mask == '*')
			return TRUE;
	}
	return FALSE;
}

static void
skip_namespace_prefix(const char **prefix, const char **mask,
		      bool inbox_check, char sep)
{
	size_t mask_len, prefix_len;
	bool match;

	prefix_len = strlen(*prefix);
	mask_len = strlen(*mask);

	if (mask_len < prefix_len) {
		/* eg. namespace prefix = "INBOX.", mask = "INBOX" */
		return;
	}

	match = strncmp(*prefix, *mask, prefix_len) == 0;
	if (!match && inbox_check) {
		/* try INBOX check. */
		match = prefix_len >= 5 &&
			strncasecmp(*prefix, *mask, 5) == 0 &&
			strncmp(*prefix + 5, *mask + 5, prefix_len - 5) == 0 &&
			strncasecmp(*prefix, "INBOX", 5) == 0 &&
			((*prefix)[5] == sep || (*prefix)[5] == '\0');
	}

	if (match) {
		*prefix += prefix_len;
		*mask += prefix_len;
	}
}

static void
list_namespace_init(struct client_command_context *cmd,
		    struct cmd_list_context *ctx)
{
        struct client *client = cmd->client;
	struct mail_namespace *ns = ctx->ns;
	const char *cur_ns_prefix, *cur_ref, *cur_mask;
	enum imap_match_result match;
	enum imap_match_result inbox_match;
	struct mailbox_list *list;
	struct imap_match_glob *inbox_glob;
	unsigned int count;
	size_t len;

	cur_ns_prefix = ns->prefix;
	cur_ref = ctx->ref;
	cur_mask = ctx->mask;

	if (*cur_ref != '\0' && *cur_ns_prefix != '\0') {
		/* reference argument given. skip namespace prefix using it.

		   cur_ns_prefix = foo/bar/
		   cur_ref = foo/
		     -> cur_ns_prefix=bar/, cur_ref=""
		   cur_ref = foo/bar/baz
		     -> cur_ns_prefix="", cur_ref="baz"
		   */
		skip_namespace_prefix(&cur_ns_prefix, &cur_ref, TRUE, ns->sep);

		if (*cur_ref != '\0' && *cur_ns_prefix != '\0') {
			/* reference parameter didn't match with
			   namespace prefix. skip this. */
			return;
		}
	}

	if (*cur_ns_prefix != '\0') {
		/* no reference parameter. skip namespace prefix from mask. */
		const char *old_ns_prefix = cur_ns_prefix;
		const char *old_mask = cur_mask;

		i_assert(*cur_ref == '\0');

		skip_namespace_prefix(&cur_ns_prefix, &cur_mask,
				      cur_ref == ctx->ref, ns->sep);

		if (*cur_mask == '\0' && *cur_ns_prefix == '\0') {
			/* trying to list the namespace prefix itself. */
			cur_ns_prefix = old_ns_prefix;
			cur_mask = old_mask;
		}
	}

	/* if the original reference and mask combined produces something
	   that matches INBOX, the INBOX casing is on. */
	inbox_glob = imap_match_init(cmd->pool,
				     t_strconcat(ctx->ref, ctx->mask, NULL),
				     TRUE, ns->sep);
	inbox_match = *ns->prefix == '\0' || ns->inbox ?
		imap_match(inbox_glob, "INBOX") : FALSE;
	ctx->match_inbox = inbox_match == IMAP_MATCH_YES;

	ctx->glob = imap_match_init(cmd->pool, ctx->mask,
				    (inbox_match == IMAP_MATCH_YES ||
				     inbox_match == IMAP_MATCH_PARENT) &&
				    cur_mask == ctx->mask,
				    ns->sep);

	if (*cur_ns_prefix != '\0') {
		/* namespace prefix still wasn't completely skipped over.
		   for example cur_ns_prefix=INBOX/, mask=%/% or mask=IN%.
		   Check that mask matches namespace prefix. */
		bool skip_trailing_sep = FALSE;
		i_assert(*cur_ref == '\0');

		/* drop the trailing separator in namespace prefix.
		   don't do it if we're listing only the prefix itself. */
		len = strlen(cur_ns_prefix);
		if (cur_ns_prefix[len-1] == ns->sep &&
		    strcmp(cur_mask, cur_ns_prefix) != 0) {
			skip_trailing_sep = TRUE;
			cur_ns_prefix = t_strndup(cur_ns_prefix, len-1);
		}

		/* hidden namespaces should still be seen without wildcards.
		   some clients rely on this. */
		match = (ns->hidden && list_mask_has_wildcards(cur_mask)) ?
			IMAP_MATCH_NO : imap_match(ctx->glob, cur_ns_prefix);
		if (match < 0)
			return;

		len = strlen(ns->prefix);
		if (match == IMAP_MATCH_YES &&
		    (ctx->list_flags & MAILBOX_LIST_ITER_SUBSCRIBED) == 0 &&
		    (!ctx->ns->inbox ||
		     strncmp(ns->prefix, "INBOX", len-1) != 0)) {
			/* The prefix itself matches */
                        enum mailbox_info_flags flags;
			string_t *str = t_str_new(128);

			flags = MAILBOX_NONEXISTENT | MAILBOX_CHILDREN;
			str_append(str, "* LIST (");
			mailbox_flags2str(str, flags, ctx->list_flags);
			str_printfa(str, ") \"%s\" ", ns->sep_str);
			imap_quote_append_string(str, skip_trailing_sep ?
				t_strndup(ns->prefix, len-1) : ns->prefix,
				FALSE);
			client_send_line(client, str_c(str));
		}
	}


	if (*cur_ns_prefix != '\0') {
		/* We didn't skip over the whole namespace prefix. For example
		   cur_ns_prefix=INBOX/ and mask=%/% or IN*.

		   We have already verified that the mask matches the namespace
		   prefix, so we'll just have to skip over as many hierarchies
		   from mask as there exists in namespace prefix.

		   The "INBOX" namespace match reply was already sent. We're
		   only listing the actual mailboxes now. */
		i_assert(*cur_ref == '\0');

		for (count = 1; *cur_ns_prefix != '\0'; cur_ns_prefix++) {
			if (*cur_ns_prefix == ns->sep)
					count++;
		}

		for (; count > 0; count--) {
			/* skip over one hierarchy */
			while (*cur_mask != '\0' && *cur_mask != '*' &&
			       *cur_mask != ns->sep)
				cur_mask++;

			if (*cur_mask == '*') {
				/* we'll just request "*" and filter it
				   ourself. otherwise this gets too complex. */
				cur_mask = "*";
				break;
			}
			if (*cur_mask == '\0') {
				/* mask ended too early. we won't be listing
				   any mailboxes. */
				break;
			}
			cur_mask++;
		}

		if (*cur_mask == '\0' && ctx->match_inbox) {
			/* oh what a horrible hack. ns_prefix="INBOX/" and
			   we wanted to list "%". INBOX should match. */
			cur_mask = "INBOX";
		}
	}

	if (*cur_mask != '*' || strcmp(ctx->mask, "*") == 0) {
		/* a) we don't have '*' in mask
		   b) we want to display everything

		   we don't need to do separate filtering ourself */
		ctx->glob = NULL;
	}

	cur_ref = mail_namespace_fix_sep(ns, cur_ref);
	cur_mask = mail_namespace_fix_sep(ns, cur_mask);

	list = mail_storage_get_list(ns->storage);
	cur_mask = mailbox_list_join_refmask(list, cur_ref, cur_mask);
	ctx->list_iter = mailbox_list_iter_init(list, cur_mask,
						ctx->list_flags);
}

static bool cmd_list_continue(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
        struct cmd_list_context *ctx = cmd->context;
	int ret;

	if (cmd->cancel) {
		if (ctx->list_iter != NULL) {
			if (mailbox_list_iter_deinit(&ctx->list_iter) < 0)
				mail_storage_set_list_error(ctx->ns->storage);
		}
		return TRUE;
	}
	for (; ctx->ns != NULL; ctx->ns = ctx->ns->next) {
		if (ctx->list_iter == NULL)
			list_namespace_init(cmd, ctx);

		if ((ret = list_namespace_mailboxes(client, ctx)) < 0) {
			client_send_storage_error(cmd, ctx->ns->storage);
			return TRUE;
		}
		if (ret == 0)
			return FALSE;
	}

	client_send_tagline(cmd, !ctx->lsub ?
			    "OK List completed." :
			    "OK Lsub completed.");
	return TRUE;
}

bool _cmd_list_full(struct client_command_context *cmd, bool lsub)
{
	struct client *client = cmd->client;
	struct mail_namespace *ns;
	struct imap_arg *args;
	enum mailbox_list_flags list_flags;
        struct cmd_list_context *ctx;
	const char *ref, *mask;

	/* [(<options>)] <reference> <mailbox wildcards> */
	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (lsub) {
		/* LSUB - we don't care about flags */
		list_flags = MAILBOX_LIST_ITER_SUBSCRIBED |
			MAILBOX_LIST_ITER_FAST_FLAGS |
			_MAILBOX_LIST_ITER_HIDE_CHILDREN;
	} else if (args[0].type != IMAP_ARG_LIST) {
		/* LIST - allow children flags, but don't require them */
		list_flags = 0;
	} else {
		list_flags =
			(enum mailbox_list_flags)_MAILBOX_LIST_ITER_LISTEXT;
		if (!parse_list_flags(cmd, IMAP_ARG_LIST(&args[0])->args,
				      &list_flags))
			return TRUE;
		args++;

		/* don't show children flags unless explicitly specified */
		if ((list_flags & MAILBOX_LIST_ITER_CHILDREN) == 0)
			list_flags |= _MAILBOX_LIST_ITER_HIDE_CHILDREN;
	}

	ref = imap_arg_string(&args[0]);
	mask = imap_arg_string(&args[1]);

	if (ref == NULL || mask == NULL) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	if (*mask == '\0' && !lsub) {
		const char *ns_prefix;

		/* special request to return the hierarchy delimiter and
		   mailbox root name. Mailbox root name is somewhat strange
		   concept which probably no other client uses than Pine.
		   Just try our best to emulate UW-IMAP behavior and hopefully
		   we're fine. */
		ns = mail_namespace_find_visible(client->namespaces, &ref);
		if (ns != NULL)
			ns_prefix = ns->prefix;
		else {
			const char *empty = "";

			ns_prefix = "";
			ns = mail_namespace_find(client->namespaces, &empty);
			if (ns == NULL) {
				/* we must reply something. use INBOX
				   namespace's separator. */
				const char *inbox = "INBOX";
				ns = mail_namespace_find(client->namespaces,
							 &inbox);
			}
		}

		if (ns != NULL) {
			string_t *str = t_str_new(64);

			str_printfa(str, "* LIST (\\Noselect) \"%s\" ",
				    ns->sep_str);
			if (*ns_prefix != '\0' && !ns->hidden) {
				/* public namespace, use it as the root name */
				imap_quote_append_string(str, ns_prefix, FALSE);
			} else {
				/* private namespace, or empty namespace
				   prefix. use the mailbox name's first part
				   as the root. */
				const char *p = strchr(ref, ns->sep);

				if (p == NULL)
					str_append(str, "\"\"");
				else {
					imap_quote_append_string(str,
						t_strdup_until(ref, p + 1),
						FALSE);
				}
			}
			client_send_line(client, str_c(str));
		}
		client_send_tagline(cmd, "OK List completed.");
	} else {
		ctx = p_new(cmd->pool, struct cmd_list_context, 1);
		ctx->ref = ref;
		ctx->mask = mask;
		ctx->list_flags = list_flags;
		ctx->lsub = lsub;
		ctx->ns = client->namespaces;

		cmd->context = ctx;
		if (!cmd_list_continue(cmd)) {
			/* unfinished */
			cmd->output_pending = TRUE;
			cmd->func = cmd_list_continue;
			return FALSE;
		}

		cmd->context = NULL;
		return TRUE;
	}
	return TRUE;
}

bool cmd_list(struct client_command_context *cmd)
{
	return _cmd_list_full(cmd, FALSE);
}
