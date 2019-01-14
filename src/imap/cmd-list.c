/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "mailbox-list-iter.h"
#include "imap-utf7.h"
#include "imap-quote.h"
#include "imap-match.h"
#include "imap-status.h"
#include "imap-commands.h"
#include "imap-list.h"

struct cmd_list_context {
	struct client_command_context *cmd;
	struct mail_user *user;

	enum mailbox_list_iter_flags list_flags;
	struct imap_status_items status_items;

	struct mailbox_list_iterate_context *list_iter;

	bool lsub:1;
	bool lsub_no_unsubscribed:1;
	bool used_listext:1;
	bool used_status:1;
};

static void
mailbox_flags2str(struct cmd_list_context *ctx, string_t *str,
		  const char *special_use, enum mailbox_info_flags flags)
{
	size_t orig_len = str_len(str);

	if ((flags & MAILBOX_NONEXISTENT) != 0 && !ctx->used_listext) {
		flags |= MAILBOX_NOSELECT;
		flags &= ~MAILBOX_NONEXISTENT;
	}

	if ((ctx->list_flags & MAILBOX_LIST_ITER_RETURN_CHILDREN) == 0)
		flags &= ~(MAILBOX_CHILDREN|MAILBOX_NOCHILDREN);

	if ((flags & MAILBOX_CHILD_SUBSCRIBED) != 0 &&
	    (flags & MAILBOX_SUBSCRIBED) == 0 && !ctx->used_listext) {
		/* LSUB uses \Noselect for this */
		flags |= MAILBOX_NOSELECT;
	} else if ((ctx->list_flags & MAILBOX_LIST_ITER_RETURN_SUBSCRIBED) == 0)
		flags &= ~MAILBOX_SUBSCRIBED;
	imap_mailbox_flags2str(str, flags);

	if ((ctx->list_flags & MAILBOX_LIST_ITER_RETURN_SPECIALUSE) != 0 &&
	    special_use != NULL) {
		if (str_len(str) != orig_len)
			str_append_c(str, ' ');
		str_append(str, special_use);
	}
}

static void
mailbox_childinfo2str(struct cmd_list_context *ctx, string_t *str,
		      enum mailbox_info_flags flags)
{
	if (!ctx->used_listext)
		return;

	if ((flags & MAILBOX_CHILD_SUBSCRIBED) != 0 &&
	    (ctx->list_flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0)
		str_append(str, " (CHILDINFO (\"SUBSCRIBED\"))");
	if ((flags & MAILBOX_CHILD_SPECIALUSE) != 0 &&
	    (ctx->list_flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0)
		str_append(str, " (CHILDINFO (\"SPECIAL-USE\"))");
}

static bool
parse_select_flags(struct cmd_list_context *ctx, const struct imap_arg *args)
{
	enum mailbox_list_iter_flags list_flags = 0;
	const char *str;

	while (!IMAP_ARG_IS_EOL(args)) {
		if (!imap_arg_get_atom(args, &str)) {
			client_send_command_error(ctx->cmd,
				"List options contains non-atoms.");
			return FALSE;
		}

		if (strcasecmp(str, "SUBSCRIBED") == 0) {
			list_flags |= MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
				MAILBOX_LIST_ITER_RETURN_SUBSCRIBED;
		} else if (strcasecmp(str, "RECURSIVEMATCH") == 0)
			list_flags |= MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH;
		else if (strcasecmp(str, "SPECIAL-USE") == 0) {
			list_flags |= MAILBOX_LIST_ITER_SELECT_SPECIALUSE |
				MAILBOX_LIST_ITER_RETURN_SPECIALUSE;
		} else if (strcasecmp(str, "REMOTE") == 0) {
			/* not supported, ignore */
		} else {
			/* skip also optional list value */
			client_send_command_error(ctx->cmd,
						  "Unknown select options");
			return FALSE;
		}
		args++;
	}

	if ((list_flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0 &&
	    (list_flags & (MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
			   MAILBOX_LIST_ITER_SELECT_SPECIALUSE)) == 0) {
		client_send_command_error(ctx->cmd,
			"RECURSIVEMATCH must not be the only selection.");
		return FALSE;
	}

	ctx->list_flags = list_flags;
	return TRUE;
}

static bool
parse_return_flags(struct cmd_list_context *ctx, const struct imap_arg *args)
{
	enum mailbox_list_iter_flags list_flags = 0;
	const struct imap_arg *list_args;
	const char *str;

	while (!IMAP_ARG_IS_EOL(args)) {
		if (!imap_arg_get_atom(args, &str)) {
			client_send_command_error(ctx->cmd,
				"List options contains non-atoms.");
			return FALSE;
		}

		if (strcasecmp(str, "SUBSCRIBED") == 0)
			list_flags |= MAILBOX_LIST_ITER_RETURN_SUBSCRIBED;
		else if (strcasecmp(str, "CHILDREN") == 0)
			list_flags |= MAILBOX_LIST_ITER_RETURN_CHILDREN;
		else if (strcasecmp(str, "SPECIAL-USE") == 0)
			list_flags |= MAILBOX_LIST_ITER_RETURN_SPECIALUSE;
		else if (strcasecmp(str, "STATUS") == 0 &&
			 imap_arg_get_list(&args[1], &list_args)) {
			if (imap_status_parse_items(ctx->cmd, list_args,
						    &ctx->status_items) < 0)
				return FALSE;
			ctx->used_status = TRUE;
			args++;
		} else {
			/* skip also optional list value */
			client_send_command_error(ctx->cmd,
						  "Unknown return options");
			return FALSE;
		}
		args++;
	}

	ctx->list_flags |= list_flags;
	return TRUE;
}

static const char *ns_prefix_mutf7(struct mail_namespace *ns)
{
	string_t *str;

	if (*ns->prefix == '\0')
		return "";

	str = t_str_new(64);
	if (imap_utf8_to_utf7(ns->prefix, str) < 0)
		i_panic("Namespace prefix not UTF-8: %s", ns->prefix);
	return str_c(str);
}

static void list_reply_append_ns_sep_param(string_t *str, char sep)
{
	str_append_c(str, '"');
	if (sep == '\\')
		str_append(str, "\\\\");
	else
		str_append_c(str, sep);
	str_append_c(str, '"');
}

static void
list_send_status(struct cmd_list_context *ctx, const char *name,
		 const char *mutf7_name, enum mailbox_info_flags flags)
{
	struct imap_status_result result;
	struct mail_namespace *ns;

	if ((flags & (MAILBOX_NONEXISTENT | MAILBOX_NOSELECT)) != 0) {
		/* doesn't exist, don't even try to get STATUS */
		return;
	}
	if ((flags & MAILBOX_SUBSCRIBED) == 0 &&
	    (flags & MAILBOX_CHILD_SUBSCRIBED) != 0) {
		/* listing subscriptions, but only child is subscribed */
		return;
	}

	/* if we're listing subscriptions and there are subscriptions=no
	   namespaces, ctx->ns may not point to correct one */
	ns = mail_namespace_find(ctx->user->namespaces, name);
	if (imap_status_get(ctx->cmd, ns, name,
			    &ctx->status_items, &result) < 0) {
		client_send_line(ctx->cmd->client,
				 t_strconcat("* ", result.errstr, NULL));
		return;
	}

	imap_status_send(ctx->cmd->client, mutf7_name,
			 &ctx->status_items, &result);
}

static bool cmd_list_continue(struct client_command_context *cmd)
{
        struct cmd_list_context *ctx = cmd->context;
	const struct mailbox_info *info;
	enum mailbox_info_flags flags;
	string_t *str, *mutf7_name;
	const char *name;
	int ret = 0;

	if (cmd->cancel) {
		if (ctx->list_iter != NULL)
			(void)mailbox_list_iter_deinit(&ctx->list_iter);
		return TRUE;
	}
	str = t_str_new(256);
	mutf7_name = t_str_new(128);
	while ((info = mailbox_list_iter_next(ctx->list_iter)) != NULL) {
		name = info->vname;
		flags = info->flags;

		if ((flags & MAILBOX_CHILD_SUBSCRIBED) != 0 &&
		    (flags & MAILBOX_SUBSCRIBED) == 0 &&
		    ctx->lsub_no_unsubscribed) {
			/* mask doesn't end with %. we don't want to show
			   any extra mailboxes. */
			continue;
		}

		str_truncate(mutf7_name, 0);
		if (imap_utf8_to_utf7(name, mutf7_name) < 0)
			i_panic("LIST: Mailbox name not UTF-8: %s", name);

		str_truncate(str, 0);
		str_printfa(str, "* %s (", ctx->lsub ? "LSUB" : "LIST");
		mailbox_flags2str(ctx, str, info->special_use, flags);
		str_append(str, ") ");
		list_reply_append_ns_sep_param(str,
			mail_namespace_get_sep(info->ns));
		str_append_c(str, ' ');
		imap_append_astring(str, str_c(mutf7_name));
		mailbox_childinfo2str(ctx, str, flags);

		ret = client_send_line_next(ctx->cmd->client, str_c(str));
		if (ctx->used_status) T_BEGIN {
			list_send_status(ctx, name, str_c(mutf7_name), flags);
		} T_END;
		if (ret == 0) {
			/* buffer is full, continue later */
			return FALSE;
		}
	}

	if (mailbox_list_iter_deinit(&ctx->list_iter) < 0) {
		client_send_list_error(cmd, ctx->user->namespaces->list);
		return TRUE;
	}
	client_send_tagline(cmd, !ctx->lsub ?
			    "OK List completed." :
			    "OK Lsub completed.");
	return TRUE;
}

static const char *const *
list_get_ref_patterns(struct cmd_list_context *ctx, const char *ref,
		      const char *const *patterns)
{
	struct mail_namespace *ns;
	const char *const *pat, *pattern;
	ARRAY(const char *) full_patterns;

	if (*ref == '\0')
		return patterns;

	ns = mail_namespace_find(ctx->user->namespaces, ref);

	t_array_init(&full_patterns, 16);
	for (pat = patterns; *pat != NULL; pat++) {
		pattern = mailbox_list_join_refpattern(ns->list, ref, *pat);
		array_push_back(&full_patterns, &pattern);
	}
	array_append_zero(&full_patterns); /* NULL-terminate */
	return array_front(&full_patterns);
}

static void cmd_list_init(struct cmd_list_context *ctx,
			  const char *const *patterns)
{
	enum mail_namespace_type type_mask = MAIL_NAMESPACE_TYPE_MASK_ALL;

	ctx->list_iter =
		mailbox_list_iter_init_namespaces(ctx->user->namespaces,
						  patterns, type_mask,
						  ctx->list_flags);
}

static void cmd_list_ref_root(struct client *client, const char *ref)
{
	struct mail_namespace *ns;
	const char *ns_prefix;
	char ns_sep;
	string_t *str;

	/* Special request to return the hierarchy delimiter and mailbox root
	   name. If namespace has a prefix, it's returned as the mailbox root.
	   Otherwise we'll emulate UW-IMAP behavior. */
	ns = mail_namespace_find_visible(client->user->namespaces, ref);
	if (ns != NULL) {
		ns_prefix = ns_prefix_mutf7(ns);
		ns_sep = mail_namespace_get_sep(ns);
	} else {
		ns_prefix = "";
		ns_sep = mail_namespaces_get_root_sep(client->user->namespaces);
	}

	str = t_str_new(64);
	str_append(str, "* LIST (\\Noselect) \"");
	if (ns_sep == '\\' || ns_sep == '"')
		str_append_c(str, '\\');
	str_printfa(str, "%c\" ", ns_sep);
	if (*ns_prefix != '\0') {
		/* non-hidden namespace, use it as the root name */
		imap_append_astring(str, ns_prefix);
	} else {
		/* Hidden namespace or empty namespace prefix. We could just
		   return an empty root name, but it's safer to emulate what
		   UW-IMAP does. With full filesystem access this might even
		   matter (root of "~user/mail/" is "~user/", not "") */
		const char *p = strchr(ref, ns_sep);

		if (p == NULL)
			str_append(str, "\"\"");
		else
			imap_append_astring(str, t_strdup_until(ref, p + 1));
	}
	client_send_line(client, str_c(str));
}

bool cmd_list_full(struct client_command_context *cmd, bool lsub)
{
	struct client *client = cmd->client;
	const struct imap_arg *args, *list_args;
	unsigned int arg_count;
	struct cmd_list_context *ctx;
	ARRAY(const char *) patterns = ARRAY_INIT;
	const char *ref, *pattern, *const *patterns_strarr;
	string_t *str;

	/* [(<selection options>)] <reference> <pattern>|(<pattern list>)
	   [RETURN (<return options>)] */
	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	ctx = p_new(cmd->pool, struct cmd_list_context, 1);
	ctx->cmd = cmd;
	ctx->lsub = lsub;
	ctx->user = client->user;

	cmd->context = ctx;

	if (!lsub && imap_arg_get_list(&args[0], &list_args)) {
		/* LIST-EXTENDED selection options */
		ctx->used_listext = TRUE;
		if (!parse_select_flags(ctx, list_args))
			return TRUE;
		args++;
	}

	if (!imap_arg_get_astring(&args[0], &ref)) {
		client_send_command_error(cmd, "Invalid reference.");
		return TRUE;
	}
	str = t_str_new(64);
	if (imap_utf7_to_utf8(ref, str) == 0)
		ref = p_strdup(cmd->pool, str_c(str));
	str_truncate(str, 0);

	if (imap_arg_get_list_full(&args[1], &list_args, &arg_count)) {
		ctx->used_listext = TRUE;
		/* convert pattern list to string array */
		p_array_init(&patterns, cmd->pool, arg_count);
		for (; !IMAP_ARG_IS_EOL(list_args); list_args++) {
			if (!imap_arg_get_astring(list_args, &pattern)) {
				client_send_command_error(cmd,
					"Invalid pattern list.");
				return TRUE;
			}
			if (imap_utf7_to_utf8(pattern, str) == 0)
				pattern = p_strdup(cmd->pool, str_c(str));
			array_push_back(&patterns, &pattern);
			str_truncate(str, 0);
		}
		args += 2;
	} else {
		if (!imap_arg_get_astring(&args[1], &pattern)) {
			client_send_command_error(cmd, "Invalid pattern.");
			return TRUE;
		}
		if (imap_utf7_to_utf8(pattern, str) == 0)
			pattern = p_strdup(cmd->pool, str_c(str));

		p_array_init(&patterns, cmd->pool, 1);
		array_push_back(&patterns, &pattern);
		args += 2;

		if (lsub) {
			size_t len = strlen(pattern);
			ctx->lsub_no_unsubscribed = len == 0 ||
				pattern[len-1] != '%';
		}
	}

	if (imap_arg_atom_equals(&args[0], "RETURN") &&
	    imap_arg_get_list(&args[1], &list_args)) {
		/* LIST-EXTENDED return options */
		ctx->used_listext = TRUE;
		if (!parse_return_flags(ctx, list_args))
			return TRUE;
		args += 2;
	}

	if (lsub) {
		/* LSUB - we don't care about flags except if
		   tb-lsub-flags workaround is explicitly set */
		ctx->list_flags |= MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
			MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH;
		/* Return SPECIAL-USE flags for LSUB anyway. Outlook 2013
		   does this and since it's not expensive for us to return
		   them, it's not worth the trouble of adding an explicit
		   workaround setting. */
		ctx->list_flags |= MAILBOX_LIST_ITER_RETURN_SPECIALUSE;
		if ((cmd->client->set->parsed_workarounds &
		     WORKAROUND_TB_LSUB_FLAGS) == 0)
			ctx->list_flags |= MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	} else if (!ctx->used_listext) {
		/* non-extended LIST: use default flags */
		ctx->list_flags |= MAILBOX_LIST_ITER_RETURN_CHILDREN |
			MAILBOX_LIST_ITER_RETURN_SPECIALUSE;
	}

	if (!IMAP_ARG_IS_EOL(args)) {
		client_send_command_error(cmd, "Extra arguments.");
		return TRUE;
	}

	array_append_zero(&patterns); /* NULL-terminate */
	patterns_strarr = array_front(&patterns);
	if (!ctx->used_listext && !lsub && *patterns_strarr[0] == '\0') {
		/* Only LIST ref "" gets us here */
		cmd_list_ref_root(client, ref);
		client_send_tagline(cmd, "OK List completed.");
	} else {
		patterns_strarr =
			list_get_ref_patterns(ctx, ref, patterns_strarr);
		cmd_list_init(ctx, patterns_strarr);

		if (!cmd_list_continue(cmd)) {
			/* unfinished */
			cmd->state = CLIENT_COMMAND_STATE_WAIT_OUTPUT;
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
	return cmd_list_full(cmd, FALSE);
}
