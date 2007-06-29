/* Copyright (C) 2002-2007 Timo Sirainen */

#include "common.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "imap-quote.h"
#include "imap-match.h"
#include "commands.h"
#include "mail-namespace.h"

struct cmd_list_context {
	struct client_command_context *cmd;
	const char *ref;
	const char *mask;
	enum mailbox_list_flags list_flags;

	struct mail_namespace *ns;
	struct mailbox_list_iterate_context *list_iter;
	struct imap_match_glob *glob;

	ARRAY_DEFINE(ns_prefixes_listed, struct mail_namespace *);

	unsigned int lsub:1;
	unsigned int inbox_found:1;
	unsigned int seen_inbox_namespace:1;
	unsigned int cur_ns_match_inbox:1;
	unsigned int cur_ns_send_prefix:1;
	unsigned int cur_ns_skip_trailing_sep:1;
	unsigned int used_listext:1;
};

static void
mailbox_flags2str(struct cmd_list_context *ctx, string_t *str,
		  enum mailbox_info_flags flags)
{
	unsigned int orig_len = str_len(str);

	if ((flags & MAILBOX_NONEXISTENT) != 0 && !ctx->used_listext) {
		flags |= MAILBOX_NOSELECT;
		flags &= ~MAILBOX_NONEXISTENT;
	}

	if ((ctx->list_flags & MAILBOX_LIST_ITER_RETURN_CHILDREN) == 0)
		flags &= ~(MAILBOX_CHILDREN|MAILBOX_NOCHILDREN);

	if ((flags & MAILBOX_SUBSCRIBED) != 0 &&
	    (ctx->list_flags & MAILBOX_LIST_ITER_RETURN_SUBSCRIBED) != 0)
		str_append(str, "\\Subscribed ");

	if ((flags & MAILBOX_CHILD_SUBSCRIBED) != 0 &&
	    (flags & MAILBOX_SUBSCRIBED) == 0 && !ctx->used_listext) {
		/* LSUB uses \Noselect for this */
		flags |= MAILBOX_NOSELECT;
	}

	if ((flags & MAILBOX_NOSELECT) != 0)
		str_append(str, "\\Noselect ");
	if ((flags & MAILBOX_NONEXISTENT) != 0)
		str_append(str, "\\NonExistent ");

	if ((flags & MAILBOX_CHILDREN) != 0)
		str_append(str, "\\HasChildren ");
	else if ((flags & MAILBOX_NOINFERIORS) != 0)
		str_append(str, "\\NoInferiors ");
	else if ((flags & MAILBOX_NOCHILDREN) != 0)
		str_append(str, "\\HasNoChildren ");

	if ((flags & MAILBOX_MARKED) != 0)
		str_append(str, "\\Marked ");
	if ((flags & MAILBOX_UNMARKED) != 0)
		str_append(str, "\\UnMarked ");

	if (str_len(str) != orig_len)
		str_truncate(str, str_len(str)-1);
}

static void
mailbox_childinfo2str(struct cmd_list_context *ctx, string_t *str,
		      enum mailbox_info_flags flags)
{
	if (!ctx->used_listext)
		return;

	if ((flags & MAILBOX_CHILD_SUBSCRIBED) != 0)
		str_append(str, " (\"CHILDINFO\" (\"SUBSCRIBED\"))");
}

static bool
parse_select_flags(struct client_command_context *cmd,
		   const struct imap_arg *args,
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

		if (strcasecmp(atom, "SUBSCRIBED") == 0) {
			*list_flags |= MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
				MAILBOX_LIST_ITER_RETURN_SUBSCRIBED;
		} else if (strcasecmp(atom, "RECURSIVEMATCH") == 0)
			*list_flags |= MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH;
		else {
			/* skip also optional list value */
			if (args[1].type == IMAP_ARG_LIST)
				args++;
		}
		args++;
	}

	if ((*list_flags & MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH) != 0 &&
	    (*list_flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0) {
		client_send_command_error(cmd,
			"RECURSIVEMATCH must not be the only selection.");
		return FALSE;
	}
	return TRUE;
}

static bool
parse_return_flags(struct client_command_context *cmd,
		   const struct imap_arg *args,
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
			*list_flags |= MAILBOX_LIST_ITER_RETURN_SUBSCRIBED;
		else if (strcasecmp(atom, "CHILDREN") == 0)
			*list_flags |= MAILBOX_LIST_ITER_RETURN_CHILDREN;
		else {
			/* skip also optional list value */
			if (args[1].type == IMAP_ARG_LIST)
				args++;
		}
		args++;
	}
	return TRUE;
}

static enum mailbox_info_flags
list_get_inbox_flags(struct cmd_list_context *ctx)
{
	struct mail_namespace *ns;
	struct mailbox_list_iterate_context *list_iter;
	const struct mailbox_info *info;
	enum mailbox_info_flags flags = MAILBOX_UNMARKED;

	if (ctx->seen_inbox_namespace &&
	    (ctx->ns->flags & NAMESPACE_FLAG_INBOX) == 0) {
		/* INBOX doesn't exist. use the default INBOX flags */
		return flags;
	}

	/* find the INBOX flags */
	ns = mail_namespace_find_inbox(ctx->cmd->client->namespaces);
	list_iter = mailbox_list_iter_init(ns->list, "INBOX", 0);
	info = mailbox_list_iter_next(list_iter);
	if (info != NULL) {
		i_assert(strcasecmp(info->name, "INBOX") == 0);
		flags = info->flags;
	}
	(void)mailbox_list_iter_deinit(&list_iter);
	return flags;
}

static bool list_namespace_has_children(struct cmd_list_context *ctx)
{
	struct mailbox_list_iterate_context *list_iter;
	const struct mailbox_info *info;
	bool ret = FALSE;

	list_iter = mailbox_list_iter_init(ctx->ns->list, "%",
					   MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	info = mailbox_list_iter_next(list_iter);
	if (info != NULL)
		ret = TRUE;
	if (mailbox_list_iter_deinit(&list_iter) < 0) {
		/* safer to answer TRUE in error conditions */
		ret = TRUE;
	}
	return ret;
}

static void
list_namespace_send_prefix(struct cmd_list_context *ctx, bool have_children)
{
	struct mail_namespace *const *listed;
	unsigned int i, count, len;
	enum mailbox_info_flags flags;
	const char *name;
	string_t *str;
	
	ctx->cur_ns_send_prefix = FALSE;

	/* see if we already listed this as a valid mailbox in another
	   namespace */
	listed = array_get(&ctx->ns_prefixes_listed, &count);
	for (i = 0; i < count; i++) {
		if (listed[i] == ctx->ns)
			return;
	}

	len = strlen(ctx->ns->prefix);
	if (len == 6 && strncasecmp(ctx->ns->prefix, "INBOX", len-1) == 0 &&
	    ctx->ns->prefix[len-1] == ctx->ns->sep) {
		/* INBOX namespace needs to be handled specially. */
		if (ctx->inbox_found) {
			/* we're just now going to send it */
			return;
		}

		ctx->inbox_found = TRUE;
		flags = list_get_inbox_flags(ctx);
	} else {
		flags = MAILBOX_NONEXISTENT;
	}

	if ((flags & MAILBOX_CHILDREN) == 0) {
		if (have_children || list_namespace_has_children(ctx)) {
			flags |= MAILBOX_CHILDREN;
			flags &= ~MAILBOX_NOCHILDREN;
		} else {
			flags |= MAILBOX_NOCHILDREN;
		}
	}

	name = ctx->cur_ns_skip_trailing_sep ?
		t_strndup(ctx->ns->prefix, len-1) : ctx->ns->prefix;

	str = t_str_new(128);
	str_append(str, "* LIST (");
	mailbox_flags2str(ctx, str, flags);
	str_printfa(str, ") \"%s\" ", ctx->ns->sep_str);
	imap_quote_append_string(str, name, FALSE);
	mailbox_childinfo2str(ctx, str, flags);

	client_send_line(ctx->cmd->client, str_c(str));
}

static bool
list_insert_ns_prefix(string_t *name_str, struct cmd_list_context *ctx,
		      const struct mailbox_info *info)
{
	if (strcasecmp(info->name, "INBOX") != 0) {
		/* non-INBOX always has prefix */
	} else if ((ctx->ns->flags & NAMESPACE_FLAG_INBOX) == 0) {
		/* INBOX from non-INBOX namespace. */
		if (*ctx->ns->prefix == '\0') {
			/* no namespace prefix, we can't list this */
			return FALSE;
		}
	} else if (!ctx->cur_ns_match_inbox) {
		/* The mask doesn't match INBOX (eg. prefix.%).
		   We still want to list prefix.INBOX if it has
		   children. Otherwise we don't want to list
		   this INBOX at all. */
		if ((info->flags & MAILBOX_CHILDREN) == 0)
			return FALSE;
	} else {
		/* Listing INBOX from inbox=yes namespace.
		   Don't insert the namespace prefix. */
		return TRUE;
	}
	str_append(name_str, ctx->ns->prefix);
	return TRUE;
}

static int
list_namespace_mailboxes(struct cmd_list_context *ctx)
{
	const struct mailbox_info *info;
	struct mail_namespace *ns;
	enum mailbox_info_flags flags;
	string_t *str, *name_str;
	const char *name;
	int ret = 0;

	t_push();
	str = t_str_new(256);
	name_str = t_str_new(256);
	while ((info = mailbox_list_iter_next(ctx->list_iter)) != NULL) {
		str_truncate(name_str, 0);

		if (!list_insert_ns_prefix(name_str, ctx, info))
			continue;
		str_append(name_str, info->name);

		if (ctx->ns->sep != ctx->ns->real_sep) {
                        char *p = str_c_modifiable(name_str);
			for (; *p != '\0'; p++) {
				if (*p == ctx->ns->real_sep)
					*p = ctx->ns->sep;
			}
		}
		name = str_c(name_str);
		flags = info->flags;

		if (*ctx->ns->prefix != '\0') {
			/* With masks containing '*' we do the checks here
			   so prefix is included in matching */
			if (ctx->glob != NULL &&
			    imap_match(ctx->glob, name) != IMAP_MATCH_YES)
				continue;
		}
		if (strcasecmp(name, "INBOX") == 0) {
			i_assert((ctx->ns->flags & NAMESPACE_FLAG_INBOX) != 0);
			if (ctx->inbox_found) {
				/* we already listed this at the beginning
				   of handling INBOX/ namespace */
				continue;
			}
			ctx->inbox_found = TRUE;
		}
		if (ctx->cur_ns_send_prefix)
			list_namespace_send_prefix(ctx, TRUE);

		/* if there's a namespace with this name, list it as
		   having children */
		ns = mail_namespace_find_prefix_nosep(ctx->ns, name);
		if (ns != NULL) {
			flags |= MAILBOX_CHILDREN;
			flags &= ~MAILBOX_NOCHILDREN;
			array_append(&ctx->ns_prefixes_listed, &ns, 1);
		}

		str_truncate(str, 0);
		str_printfa(str, "* %s (", ctx->lsub ? "LSUB" : "LIST");
		mailbox_flags2str(ctx, str, flags);
		str_printfa(str, ") \"%s\" ", ctx->ns->sep_str);
		imap_quote_append_string(str, name, FALSE);
		mailbox_childinfo2str(ctx, str, flags);

		if (client_send_line(ctx->cmd->client, str_c(str)) == 0) {
			/* buffer is full, continue later */
			t_pop();
			return 0;
		}
	}

	if (mailbox_list_iter_deinit(&ctx->list_iter) < 0)
		ret = -1;

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

static bool
skip_namespace_prefix_refmask(struct cmd_list_context *ctx,
			      const char **cur_ns_prefix_p,
			      const char **cur_ref_p, const char **cur_mask_p)
{
	const char *cur_ns_prefix = *cur_ns_prefix_p;
	const char *cur_ref = *cur_ref_p;
	const char *cur_mask = *cur_mask_p;

	if (*ctx->ns->prefix == '\0')
		return TRUE;

	if (*cur_ref != '\0') {
		/* reference argument given. skip namespace prefix using it.

		   cur_ns_prefix = foo/bar/
		   cur_ref = foo/
		     -> cur_ns_prefix=bar/, cur_ref=""
		   cur_ref = foo/bar/baz
		     -> cur_ns_prefix="", cur_ref="baz"
		   */
		skip_namespace_prefix(&cur_ns_prefix, &cur_ref, TRUE,
				      ctx->ns->sep);

		if (*cur_ref != '\0' && *cur_ns_prefix != '\0') {
			/* reference parameter didn't match with
			   namespace prefix. skip this. */
			return FALSE;
		}
	}

	if (*cur_ns_prefix != '\0') {
		/* skip namespace prefix using mask */
		const char *old_ns_prefix = cur_ns_prefix;
		const char *old_mask = cur_mask;

		i_assert(*cur_ref == '\0');

		skip_namespace_prefix(&cur_ns_prefix, &cur_mask,
				      cur_ref == ctx->ref, ctx->ns->sep);

		if (*cur_mask == '\0' && *cur_ns_prefix == '\0') {
			/* trying to list the namespace prefix itself. */
			cur_ns_prefix = old_ns_prefix;
			cur_mask = old_mask;
		}
	}

	*cur_ns_prefix_p = cur_ns_prefix;
	*cur_ref_p = cur_ref;
	*cur_mask_p = cur_mask;
	return TRUE;
}

static enum imap_match_result
list_use_inboxcase(struct cmd_list_context *ctx)
{
	struct imap_match_glob *inbox_glob;

	if (*ctx->ns->prefix != '\0' &&
	    (ctx->ns->flags & NAMESPACE_FLAG_INBOX) == 0)
		return IMAP_MATCH_NO;

	/* if the original reference and mask combined produces something
	   that matches INBOX, the INBOX casing is on. */
	inbox_glob = imap_match_init(ctx->cmd->pool,
				     t_strconcat(ctx->ref, ctx->mask, NULL),
				     TRUE, ctx->ns->sep);
	return imap_match(inbox_glob, "INBOX");
}

static void
skip_mask_wildcard_prefix(const char *cur_ns_prefix, char sep,
			  const char **cur_mask_p)
{
	const char *cur_mask = *cur_mask_p;
	unsigned int count;

	for (count = 1; *cur_ns_prefix != '\0'; cur_ns_prefix++) {
		if (*cur_ns_prefix == sep)
			count++;
	}

	for (; count > 0; count--) {
		/* skip over one hierarchy */
		while (*cur_mask != '\0' && *cur_mask != '*' &&
		       *cur_mask != sep)
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

	*cur_mask_p = cur_mask;
}

static void list_namespace_init(struct cmd_list_context *ctx)
{
	struct mail_namespace *ns = ctx->ns;
	const char *cur_ns_prefix, *cur_ref, *cur_mask;
	enum imap_match_result match;
	enum imap_match_result inbox_match;
	size_t len;

	cur_ns_prefix = ns->prefix;
	cur_ref = ctx->ref;
	cur_mask = ctx->mask;

	if ((ctx->ns->flags & NAMESPACE_FLAG_HIDDEN) != 0 &&
	    (ctx->list_flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		/* ignore hidden namespaces */
		return;
	}

	ctx->cur_ns_skip_trailing_sep = FALSE;

	if ((ns->flags & NAMESPACE_FLAG_INBOX) != 0)
		ctx->seen_inbox_namespace = TRUE;

	if (!skip_namespace_prefix_refmask(ctx, &cur_ns_prefix,
					   &cur_ref, &cur_mask))
		return;

	inbox_match = list_use_inboxcase(ctx);
	ctx->cur_ns_match_inbox = inbox_match == IMAP_MATCH_YES;

	ctx->glob = imap_match_init(ctx->cmd->pool, ctx->mask,
				    (inbox_match == IMAP_MATCH_YES ||
				     inbox_match == IMAP_MATCH_PARENT) &&
				    cur_mask == ctx->mask, ns->sep);

	if (*cur_ns_prefix != '\0') {
		/* namespace prefix still wasn't completely skipped over.
		   for example cur_ns_prefix=INBOX/, mask=%/% or mask=IN%.
		   Check that mask matches namespace prefix. */
		i_assert(*cur_ref == '\0');

		/* drop the trailing separator in namespace prefix.
		   don't do it if we're listing only the prefix itself
		   (LIST "" foo/ needs to return "foo/" entry) */
		len = strlen(cur_ns_prefix);
		if (cur_ns_prefix[len-1] == ns->sep &&
		    strcmp(cur_mask, cur_ns_prefix) != 0) {
			ctx->cur_ns_skip_trailing_sep = TRUE;
			cur_ns_prefix = t_strndup(cur_ns_prefix, len-1);
		}

		/* hidden and non-listable namespaces should still be seen
		   without wildcards. */
		match = ((ns->flags & NAMESPACE_FLAG_LIST) == 0 &&
			 list_mask_has_wildcards(cur_mask)) ?
			IMAP_MATCH_NO : imap_match(ctx->glob, cur_ns_prefix);
		if (match < 0)
			return;

		if (match == IMAP_MATCH_YES &&
		    (ns->flags & NAMESPACE_FLAG_LIST) != 0 &&
		    (ctx->list_flags &
		     MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0)
			ctx->cur_ns_send_prefix = TRUE;
	}


	if (*cur_ns_prefix != '\0') {
		/* We didn't skip over the whole namespace prefix. For example
		   cur_ns_prefix=INBOX/ and mask=%/% or IN*.

		   We have already verified that the mask matches the namespace
		   prefix, so we'll just have to skip over as many hierarchies
		   from mask as there exists in namespace prefix. */
		i_assert(*cur_ref == '\0');
		skip_mask_wildcard_prefix(cur_ns_prefix, ns->sep, &cur_mask);

		if (*cur_mask == '\0' && ctx->cur_ns_match_inbox) {
			/* ns_prefix="INBOX/" and we wanted to list "%".
			   This is an optimization to avoid doing an empty
			   listing followed by another INBOX listing later. */
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

	cur_mask = mailbox_list_join_refmask(ns->list, cur_ref, cur_mask);
	ctx->list_iter = mailbox_list_iter_init(ns->list, cur_mask,
						ctx->list_flags);
}

static void list_inbox(struct cmd_list_context *ctx)
{
	const char *str;

	/* INBOX always exists */
	if (!ctx->inbox_found && ctx->cur_ns_match_inbox &&
	    (ctx->ns->flags & NAMESPACE_FLAG_INBOX) != 0 &&
	    (ctx->list_flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0) {
		str = t_strdup_printf("* LIST (\\Unmarked) \"%s\" \"INBOX\"",
				      ctx->ns->sep_str);
		client_send_line(ctx->cmd->client, str);
	}
}

static bool cmd_list_continue(struct client_command_context *cmd)
{
        struct cmd_list_context *ctx = cmd->context;
	int ret;

	if (cmd->cancel) {
		if (ctx->list_iter != NULL)
			(void)mailbox_list_iter_deinit(&ctx->list_iter);
		return TRUE;
	}
	for (; ctx->ns != NULL; ctx->ns = ctx->ns->next) {
		if (ctx->list_iter == NULL) {
			list_namespace_init(ctx);
			if (ctx->list_iter == NULL)
				continue;
		}

		if ((ret = list_namespace_mailboxes(ctx)) < 0) {
			client_send_list_error(cmd, ctx->ns->list);
			return TRUE;
		}
		if (ret == 0)
			return FALSE;

		if (ctx->cur_ns_send_prefix) {
			/* no mailboxes in this namespace */
			list_namespace_send_prefix(ctx, FALSE);
		}
		list_inbox(ctx);
	}

	client_send_tagline(cmd, !ctx->lsub ?
			    "OK List completed." :
			    "OK Lsub completed.");
	return TRUE;
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
	ns = mail_namespace_find_visible(client->namespaces, &ref);
	if (ns != NULL) {
		ns_prefix = ns->prefix;
		ns_sep = ns->sep;
	} else {
		ns_prefix = "";
		ns_sep = mail_namespace_get_root_sep(client->namespaces);
	}

	str = t_str_new(64);
	str_append(str, "* LIST (\\Noselect) \"");
	if (ns_sep == '\\' || ns_sep == '"')
		str_append_c(str, '\\');
	str_printfa(str, "%c\" ", ns_sep);
	if (*ns_prefix != '\0') {
		/* non-hidden namespace, use it as the root name */
		imap_quote_append_string(str, ns_prefix, FALSE);
	} else {
		/* Hidden namespace or empty namespace prefix. We could just
		   return an empty root name, but it's safer to emulate what
		   UW-IMAP does. With full filesystem access this might even
		   matter (root of "~user/mail/" is "~user/", not "") */
		const char *p = strchr(ref, ns_sep);

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

bool _cmd_list_full(struct client_command_context *cmd, bool lsub)
{
	struct client *client = cmd->client;
	const struct imap_arg *args;
	enum mailbox_list_flags list_flags = 0;
        struct cmd_list_context *ctx;
	const char *ref, *mask;
	bool used_listext = FALSE;

	/* [(<selection options>)] <reference> <pattern>|(<pattern list>)
	   [RETURN (<return options>)] */
	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (args[0].type == IMAP_ARG_LIST && !lsub) {
		/* LIST-EXTENDED selection options */
		used_listext = TRUE;
		if (!parse_select_flags(cmd, IMAP_ARG_LIST(&args[0])->args,
					&list_flags))
			return TRUE;
		args++;
	}

	ref = imap_arg_string(&args[0]);
	if (ref == NULL) {
		/* broken */
		mask = NULL;
	} else if (args[1].type == IMAP_ARG_LIST) {
		/* FIXME: pattern list */
		mask = NULL;
		args += 2;
	} else {
		mask = imap_arg_string(&args[1]);
		args += 2;
	}

	if (args[0].type == IMAP_ARG_ATOM && args[1].type == IMAP_ARG_LIST &&
	    strcasecmp(imap_arg_string(&args[0]), "RETURN") == 0) {
		/* LIST-EXTENDED return options */
		used_listext = TRUE;
		if (!parse_return_flags(cmd, IMAP_ARG_LIST(&args[1])->args,
					&list_flags))
			return TRUE;
		args += 2;
	}

	if (lsub) {
		/* LSUB - we don't care about flags */
		list_flags = MAILBOX_LIST_ITER_SELECT_SUBSCRIBED |
			MAILBOX_LIST_ITER_SELECT_RECURSIVEMATCH |
			MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	} else if (!used_listext) {
		/* non-extended LIST - return children flags always */
		list_flags = MAILBOX_LIST_ITER_RETURN_CHILDREN;
	}

	if (ref == NULL || args[0].type != IMAP_ARG_EOL) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	if (mask != NULL && *mask == '\0' && !lsub) {
		/* only with mask string, not with list */
		cmd_list_ref_root(client, ref);
		client_send_tagline(cmd, "OK List completed.");
	} else {
		/* FIXME: handle mask lists */
		ctx = p_new(cmd->pool, struct cmd_list_context, 1);
		ctx->cmd = cmd;
		ctx->ref = ref;
		ctx->mask = mask;
		ctx->list_flags = list_flags;
		ctx->used_listext = used_listext;
		ctx->lsub = lsub;
		ctx->ns = client->namespaces;
		p_array_init(&ctx->ns_prefixes_listed, cmd->pool, 8);

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
