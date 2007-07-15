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
	const char *const *patterns;
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
		/* The pattern doesn't match INBOX (eg. prefix.%).
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
			/* With patterns containing '*' we do the checks here
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

static bool list_pattern_has_wildcards(const char *pattern)
{
	for (; *pattern != '\0'; pattern++) {
		if (*pattern == '%' || *pattern == '*')
			return TRUE;
	}
	return FALSE;
}

static void
skip_namespace_prefix(const char **prefix, const char **pattern,
		      bool inbox_check, char sep)
{
	size_t pattern_len, prefix_len;
	bool match;

	prefix_len = strlen(*prefix);
	pattern_len = strlen(*pattern);

	if (pattern_len < prefix_len) {
		/* eg. namespace prefix = "INBOX.", pattern = "INBOX" */
		return;
	}

	match = strncmp(*prefix, *pattern, prefix_len) == 0;
	if (!match && inbox_check) {
		/* try INBOX check. */
		match = prefix_len >= 5 &&
			strncasecmp(*prefix, *pattern, 5) == 0 &&
			strncmp(*prefix + 5, *pattern + 5,
				prefix_len - 5) == 0 &&
			strncasecmp(*prefix, "INBOX", 5) == 0 &&
			((*prefix)[5] == sep || (*prefix)[5] == '\0');
	}

	if (match) {
		*prefix += prefix_len;
		*pattern += prefix_len;
	}
}

static bool
skip_namespace_prefix_ref(struct cmd_list_context *ctx,
			  const char **cur_ns_prefix_p,
			  const char **cur_ref_p)
{
	const char *cur_ns_prefix = *cur_ns_prefix_p;
	const char *cur_ref = *cur_ref_p;

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

	*cur_ns_prefix_p = cur_ns_prefix;
	*cur_ref_p = cur_ref;
	return TRUE;
}

static void
skip_namespace_prefix_pattern(struct cmd_list_context *ctx,
			      const char **cur_ns_prefix_p,
			      const char *cur_ref, const char **cur_pattern_p)
{
	const char *cur_ns_prefix = *cur_ns_prefix_p;
	const char *cur_pattern = *cur_pattern_p;
	const char *old_ns_prefix = cur_ns_prefix;
	const char *old_pattern = cur_pattern;

	if (*cur_ns_prefix == '\0')
		return;

	/* skip namespace prefix using pattern */
	i_assert(*cur_ref == '\0');

	skip_namespace_prefix(&cur_ns_prefix, &cur_pattern,
			      cur_ref == ctx->ref, ctx->ns->sep);

	if (*cur_pattern == '\0' && *cur_ns_prefix == '\0') {
		/* trying to list the namespace prefix itself. */
		cur_ns_prefix = old_ns_prefix;
		cur_pattern = old_pattern;
	}

	*cur_ns_prefix_p = cur_ns_prefix;
	*cur_pattern_p = cur_pattern;
}

static enum imap_match_result
list_use_inboxcase(struct cmd_list_context *ctx)
{
	struct imap_match_glob *inbox_glob;
	const char *const *pat;
	enum imap_match_result match, ret;

	if (*ctx->ns->prefix != '\0' &&
	    (ctx->ns->flags & NAMESPACE_FLAG_INBOX) == 0)
		return IMAP_MATCH_NO;

	/* if the original reference and pattern combined produces something
	   that matches INBOX, the INBOX casing is on. */
	ret = IMAP_MATCH_NO;
	for (pat = ctx->patterns; *pat != NULL; pat++) {
		t_push();
		inbox_glob =
			imap_match_init(pool_datastack_create(),
					t_strconcat(ctx->ref, *pat, NULL),
					TRUE, ctx->ns->sep);
		match = imap_match(inbox_glob, "INBOX");
		t_pop();

		if (match == IMAP_MATCH_YES)
			return IMAP_MATCH_YES;
		if ((match & IMAP_MATCH_PARENT) != 0)
			ret = IMAP_MATCH_PARENT;
	}
	return ret;
}

static void
skip_pattern_wildcard_prefix(const char *cur_ns_prefix, char sep,
			     const char **cur_pattern_p)
{
	const char *cur_pattern = *cur_pattern_p;
	unsigned int count;

	for (count = 1; *cur_ns_prefix != '\0'; cur_ns_prefix++) {
		if (*cur_ns_prefix == sep)
			count++;
	}

	for (; count > 0; count--) {
		/* skip over one hierarchy */
		while (*cur_pattern != '\0' && *cur_pattern != '*' &&
		       *cur_pattern != sep)
			cur_pattern++;

		if (*cur_pattern == '*') {
			/* we'll just request "*" and filter it
			   ourself. otherwise this gets too complex. */
			cur_pattern = "*";
			break;
		}
		if (*cur_pattern == '\0') {
			/* pattern ended too early. we won't be listing
			   any mailboxes. */
			break;
		}
		cur_pattern++;
	}

	*cur_pattern_p = cur_pattern;
}

static bool
list_namespace_init_pattern(struct cmd_list_context *ctx, bool inboxcase,
			    const char *cur_ref, const char *cur_ns_prefix,
			    const char **cur_pattern_p, bool *want_glob_r)
{
	struct mail_namespace *ns = ctx->ns;
	struct imap_match_glob *pat_glob;
	const char *cur_pattern = *cur_pattern_p;
	enum imap_match_result match;
	size_t len;

	skip_namespace_prefix_pattern(ctx, &cur_ns_prefix,
				      cur_ref, &cur_pattern);
	if (*cur_ns_prefix == '\0') {
		*want_glob_r = FALSE;
		*cur_pattern_p = cur_pattern;
		return TRUE;
	}

	/* namespace prefix still wasn't completely skipped over.
	   for example cur_ns_prefix=INBOX/, pattern=%/% or pattern=IN%.
	   Check that pattern matches namespace prefix. */
	i_assert(*cur_ref == '\0');

	/* drop the trailing separator in namespace prefix.
	   don't do it if we're listing only the prefix itself
	   (LIST "" foo/ needs to return "foo/" entry) */
	len = strlen(cur_ns_prefix);
	if (cur_ns_prefix[len-1] == ns->sep &&
	    strcmp(cur_pattern, cur_ns_prefix) != 0) {
		ctx->cur_ns_skip_trailing_sep = TRUE;
		cur_ns_prefix = t_strndup(cur_ns_prefix, len-1);
	}

	/* hidden and non-listable namespaces are invisible to wildcards */
	if ((ns->flags & NAMESPACE_FLAG_LIST) == 0 &&
	    list_pattern_has_wildcards(cur_pattern))
		return FALSE;

	/* check if this namespace prefix matches the current pattern */
	pat_glob = imap_match_init(pool_datastack_create(), *cur_pattern_p,
				   inboxcase, ns->sep);
	match = imap_match(pat_glob, cur_ns_prefix);
	if ((match & (IMAP_MATCH_YES | IMAP_MATCH_CHILDREN)) == 0)
		return FALSE;

	if (match == IMAP_MATCH_YES && (ns->flags & NAMESPACE_FLAG_LIST) != 0 &&
	    (ctx->list_flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0) {
		/* the namespace prefix itself matches too. send it. */
		ctx->cur_ns_send_prefix = TRUE;
	}

	/* We have now verified that the pattern matches the namespace prefix,
	   so we'll just have to skip over as many hierarchies from pattern as
	   there exists in namespace prefix. */
	skip_pattern_wildcard_prefix(cur_ns_prefix, ns->sep, &cur_pattern);

	if (*cur_pattern == '\0' && ctx->cur_ns_match_inbox) {
		/* ns_prefix="INBOX/" and we wanted to list "%".
		   This is an optimization to avoid doing an empty
		   listing followed by another INBOX listing later. */
		cur_pattern = "INBOX";
		*want_glob_r = FALSE;
	} else if (*cur_pattern != '*' || strcmp(*cur_pattern_p, "*") == 0) {
		/* a) we don't have '*' in pattern
		   b) we want to display everything

		   we don't need to do separate filtering ourself */
		*want_glob_r = FALSE;
	} else {
		*want_glob_r = TRUE;
	}

	*cur_pattern_p = cur_pattern;
	return TRUE;
}

static void list_namespace_init(struct cmd_list_context *ctx)
{
	struct mail_namespace *ns = ctx->ns;
	const char *cur_ns_prefix, *cur_ref, *const *pat, *pattern;
	enum imap_match_result inbox_match;
	ARRAY_DEFINE(used_patterns, const char *);
	bool inboxcase, want_glob = FALSE, want_any_glob = FALSE;

	cur_ns_prefix = ns->prefix;
	cur_ref = ctx->ref;

	if ((ns->flags & NAMESPACE_FLAG_HIDDEN) != 0 &&
	    (ctx->list_flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		/* ignore hidden namespaces */
		return;
	}

	ctx->cur_ns_skip_trailing_sep = FALSE;

	if ((ns->flags & NAMESPACE_FLAG_INBOX) != 0)
		ctx->seen_inbox_namespace = TRUE;

	if (*cur_ns_prefix != '\0') {
		/* namespace has a prefix. see if we can skip over it. */
		if (!skip_namespace_prefix_ref(ctx, &cur_ns_prefix, &cur_ref))
			return;
	}

	inbox_match = list_use_inboxcase(ctx);
	ctx->cur_ns_match_inbox = inbox_match == IMAP_MATCH_YES;
	inboxcase = (inbox_match & (IMAP_MATCH_YES | IMAP_MATCH_PARENT)) != 0;

	t_array_init(&used_patterns, 16);
	for (pat = ctx->patterns; *pat != NULL; pat++) {
		pattern = *pat;
		if (list_namespace_init_pattern(ctx, inboxcase, cur_ref,
						cur_ns_prefix, &pattern,
						&want_glob)) {
			if (want_glob)
				want_any_glob = TRUE;
			pattern = mailbox_list_join_refpattern(ns->list,
				cur_ref, mail_namespace_fix_sep(ns, pattern));
			array_append(&used_patterns, &pattern, 1);
		}
	}

	if (array_count(&used_patterns) == 0)
		return;
	(void)array_append_space(&used_patterns); /* NULL-terminate */
	pat = array_idx(&used_patterns, 0);

	ctx->glob = !want_any_glob ? NULL :
		imap_match_init_multiple(ctx->cmd->pool, pat,
					 inboxcase, ns->sep);

	cur_ref = mail_namespace_fix_sep(ns, cur_ref);
	ctx->list_iter = mailbox_list_iter_init_multiple(ns->list, pat,
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
			t_push();
			list_namespace_init(ctx);
			t_pop();
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
	const struct imap_arg *args, *arg;
	enum mailbox_list_flags list_flags = 0;
        struct cmd_list_context *ctx;
	ARRAY_DEFINE(patterns, const char *) = ARRAY_INIT;
	const char *ref, *pattern, *const *patterns_strarr;
	bool used_listext = FALSE;

	/* [(<selection options>)] <reference> <pattern>|(<pattern list>)
	   [RETURN (<return options>)] */
	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (args[0].type == IMAP_ARG_LIST && !lsub) {
		/* LIST-EXTENDED selection options */
		used_listext = TRUE;
		if (!parse_select_flags(cmd, IMAP_ARG_LIST_ARGS(&args[0]),
					&list_flags))
			return TRUE;
		args++;
	}

	ref = imap_arg_string(&args[0]);
	if (ref == NULL) {
		/* broken */
	} else if (args[1].type == IMAP_ARG_LIST) {
		used_listext = TRUE;
		/* convert pattern list to string array */
		p_array_init(&patterns, cmd->pool,
			     IMAP_ARG_LIST_COUNT(&args[1]));
		arg = IMAP_ARG_LIST_ARGS(&args[1]);
		for (; arg->type != IMAP_ARG_EOL; arg++) {
			if (!IMAP_ARG_TYPE_IS_STRING(arg->type)) {
				/* broken */
				ref = NULL;
				break;
			}
			pattern = imap_arg_string(arg);
			array_append(&patterns, &pattern, 1);
		}
		args += 2;
	} else {
		pattern = imap_arg_string(&args[1]);
		if (pattern == NULL)
			ref = NULL;
		else {
			p_array_init(&patterns, cmd->pool, 1);
			array_append(&patterns, &pattern, 1);
		}
		args += 2;
	}

	if (args[0].type == IMAP_ARG_ATOM && args[1].type == IMAP_ARG_LIST &&
	    strcasecmp(imap_arg_string(&args[0]), "RETURN") == 0) {
		/* LIST-EXTENDED return options */
		used_listext = TRUE;
		if (!parse_return_flags(cmd, IMAP_ARG_LIST_ARGS(&args[1]),
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

	(void)array_append_space(&patterns); /* NULL-terminate */
	patterns_strarr = array_idx(&patterns, 0);
	if (!used_listext && !lsub && *patterns_strarr[0] == '\0') {
		/* Only LIST ref "" gets us here */
		cmd_list_ref_root(client, ref);
		client_send_tagline(cmd, "OK List completed.");
	} else {
		ctx = p_new(cmd->pool, struct cmd_list_context, 1);
		ctx->cmd = cmd;
		ctx->ref = ref;
		ctx->patterns = patterns_strarr;
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
