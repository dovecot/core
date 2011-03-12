/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "imap-quote.h"
#include "imap-match.h"
#include "imap-status.h"
#include "imap-commands.h"
#include "mail-namespace.h"

struct cmd_list_context {
	struct client_command_context *cmd;
	const char *ref;
	const char *const *patterns;
	enum mailbox_list_iter_flags list_flags;
	struct imap_status_items status_items;
	enum mailbox_info_flags inbox_flags;

	struct mail_namespace *ns;
	struct mailbox_list_iterate_context *list_iter;

	ARRAY_DEFINE(ns_prefixes_listed, struct mail_namespace *);

	unsigned int lsub:1;
	unsigned int lsub_no_unsubscribed:1;
	unsigned int inbox_found:1;
	unsigned int seen_inbox_namespace:1;
	unsigned int cur_ns_match_inbox:1;
	unsigned int cur_ns_send_prefix:1;
	unsigned int cur_ns_skip_trailing_sep:1;
	unsigned int used_listext:1;
	unsigned int used_status:1;
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
		str_append(str, " (CHILDINFO (\"SUBSCRIBED\"))");
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
		else if (strcasecmp(str, "REMOTE") == 0) {
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
	    (list_flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0) {
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

static enum mailbox_info_flags
list_get_inbox_flags(struct cmd_list_context *ctx)
{
	struct mail_namespace *ns;
	struct mailbox_list_iterate_context *list_iter;
	const struct mailbox_info *info;
	enum mailbox_info_flags flags = MAILBOX_UNMARKED;

	if (ctx->seen_inbox_namespace &&
	    (ctx->ns->flags & NAMESPACE_FLAG_INBOX_USER) == 0) {
		/* INBOX doesn't exist. use the default INBOX flags */
		return flags;
	}

	/* find the INBOX flags */
	ns = mail_namespace_find_inbox(ctx->cmd->client->user->namespaces);
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
	enum mailbox_list_iter_flags list_flags =
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	struct mailbox_list_iterate_context *list_iter;
	const struct mailbox_info *info;
	bool ret = FALSE;

	if ((ctx->list_flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		list_flags |= MAILBOX_LIST_ITER_SELECT_SUBSCRIBED;

	list_iter = mailbox_list_iter_init(ctx->ns->list,
		t_strconcat(ctx->ns->prefix, "%", NULL), list_flags);
	info = mailbox_list_iter_next(list_iter);
	if (info != NULL)
		ret = TRUE;
	if (mailbox_list_iter_deinit(&list_iter) < 0) {
		/* safer to answer TRUE in error conditions */
		ret = TRUE;
	}
	return ret;
}

static const char *ns_get_listed_prefix(struct cmd_list_context *ctx)
{
	struct imap_match_glob *glob;
	enum imap_match_result match;
	const char *ns_prefix, *p;
	bool inboxcase;

	inboxcase = strncasecmp(ctx->ns->prefix, "INBOX", 5) == 0 &&
		ctx->ns->prefix[5] == ctx->ns->sep;
	glob = imap_match_init_multiple(pool_datastack_create(),
					ctx->patterns, inboxcase,
					ctx->ns->sep);
	ns_prefix = ctx->ns->prefix;
	match = imap_match(glob, ns_prefix);
	if (match == IMAP_MATCH_YES) {
		return !ctx->cur_ns_skip_trailing_sep ? ns_prefix :
			t_strndup(ns_prefix, strlen(ns_prefix)-1);
	}

	while ((match & IMAP_MATCH_PARENT) != 0) {
		p = strrchr(ns_prefix, ctx->ns->sep);
		i_assert(p != NULL);
		ns_prefix = t_strdup_until(ns_prefix, p);
		match = imap_match(glob, ns_prefix);
	}
	i_assert(match == IMAP_MATCH_YES);
	return ns_prefix;
}

static void
list_namespace_send_prefix(struct cmd_list_context *ctx, bool have_children)
{
	struct mail_namespace *const *listed;
	unsigned int len;
	enum mailbox_info_flags flags;
	const char *name;
	string_t *str;
	bool same_ns, ends_with_sep;

	ctx->cur_ns_send_prefix = FALSE;

	/* see if we already listed this as a valid mailbox in another
	   namespace */
	array_foreach(&ctx->ns_prefixes_listed, listed) {
		if (*listed == ctx->ns)
			return;
	}

	name = ns_get_listed_prefix(ctx);
	len = strlen(ctx->ns->prefix);
	ends_with_sep = ctx->ns->prefix[len-1] == ctx->ns->sep;

	/* we may be listing namespace's parent. in such case we always want to
	   set the name as nonexistent. */
	same_ns = strcmp(name, ctx->ns->prefix) == 0 ||
		(strncmp(name, ctx->ns->prefix, len - 1) == 0 && ends_with_sep);
	if (len == 6 && strncasecmp(ctx->ns->prefix, "INBOX", len-1) == 0 &&
	    ends_with_sep) {
		/* INBOX namespace needs to be handled specially. */
		if (ctx->inbox_found) {
			/* we're just now going to send it */
			return;
		}

		ctx->inbox_found = TRUE;
		flags = list_get_inbox_flags(ctx);
	} else if (same_ns &&
		   mailbox_list_mailbox(ctx->ns->list, "", &flags) > 0) {
		/* mailbox with namespace prefix exists */
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

	if ((ctx->ns->flags & NAMESPACE_FLAG_LIST_CHILDREN) != 0 ||
	    (ctx->list_flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		if (have_children) {
			/* children are going to be listed. */
			return;
		}
		if ((flags & MAILBOX_CHILDREN) == 0) {
			/* namespace has no children. don't show it. */
			return;
		}
		/* namespace has children but they don't match the list
		   pattern. the prefix itself matches though, so show it. */
	}

	str = t_str_new(128);
	str_append(str, "* LIST (");
	mailbox_flags2str(ctx, str, flags);
	str_printfa(str, ") \"%s\" ", ctx->ns->sep_str);
	imap_quote_append_string(str, name, FALSE);
	mailbox_childinfo2str(ctx, str, flags);

	client_send_line(ctx->cmd->client, str_c(str));
}

static void list_send_status(struct cmd_list_context *ctx, const char *name,
			     enum mailbox_info_flags flags)
{
	struct imap_status_result result;
	struct mail_namespace *ns;
	const char *storage_name, *error;

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
	storage_name = name;
	ns = mail_namespace_find(ctx->ns->user->namespaces, &storage_name);
	if (imap_status_get(ctx->cmd, ns, storage_name,
			    &ctx->status_items, &result, &error) < 0) {
		client_send_line(ctx->cmd->client,
				 t_strconcat("* ", error, NULL));
		return;
	}

	imap_status_send(ctx->cmd->client, name, &ctx->status_items, &result);
}

static bool list_has_empty_prefix_ns(struct mail_user *user)
{
	struct mail_namespace *ns;

	ns = mail_namespace_find_prefix(user->namespaces, "");
	return ns != NULL && (ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
					   NAMESPACE_FLAG_LIST_CHILDREN)) != 0;
}

static int
list_namespace_mailboxes(struct cmd_list_context *ctx)
{
	const struct mailbox_info *info;
	struct mail_namespace *ns;
	enum mailbox_info_flags flags;
	string_t *str;
	const char *name;
	int ret = 0;

	str = t_str_new(256);
	while ((info = mailbox_list_iter_next(ctx->list_iter)) != NULL) {
		name = info->name;
		flags = info->flags;

		if (strcasecmp(name, "INBOX") == 0) {
			if (ctx->inbox_found) {
				/* we already listed this at the beginning
				   of handling INBOX/ namespace */
				continue;
			}
			if ((ctx->ns->flags & NAMESPACE_FLAG_INBOX_USER) == 0) {
				/* INBOX is in non-empty prefix namespace,
				   and we're now listing prefixless namespace
				   that contains INBOX. There's no way we can
				   show this mailbox. */
				ctx->inbox_flags = flags &
					(MAILBOX_CHILDREN|MAILBOX_NOCHILDREN);
				continue;
			}

			if (*info->ns->prefix != '\0' &&
			    list_has_empty_prefix_ns(info->ns->user)) {
				/* INBOX is in its own namespace, while a
				   namespace with prefix="" has its children. */
				flags &= ~(MAILBOX_CHILDREN|MAILBOX_NOCHILDREN|
					   MAILBOX_NOINFERIORS);
				flags |= ctx->inbox_flags;
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

		if ((flags & MAILBOX_CHILD_SUBSCRIBED) != 0 &&
		    (flags & MAILBOX_SUBSCRIBED) == 0 &&
		    ctx->lsub_no_unsubscribed) {
			/* mask doesn't end with %. we don't want to show
			   any extra mailboxes. */
			continue;
		}

		str_truncate(str, 0);
		str_printfa(str, "* %s (", ctx->lsub ? "LSUB" : "LIST");
		mailbox_flags2str(ctx, str, flags);
		str_printfa(str, ") \"%s\" ", ctx->ns->sep_str);
		imap_quote_append_string(str, name, FALSE);
		mailbox_childinfo2str(ctx, str, flags);

		ret = client_send_line(ctx->cmd->client, str_c(str));
		if (ctx->used_status) T_BEGIN {
			list_send_status(ctx, name, flags);
		} T_END;
		if (ret == 0) {
			/* buffer is full, continue later */
			return 0;
		}
	}

	if (mailbox_list_iter_deinit(&ctx->list_iter) < 0)
		ret = -1;

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
	    (ctx->ns->flags & NAMESPACE_FLAG_INBOX_USER) == 0)
		return IMAP_MATCH_NO;

	/* if the original reference and pattern combined produces something
	   that matches INBOX, the INBOX casing is on. */
	ret = IMAP_MATCH_NO;
	for (pat = ctx->patterns; *pat != NULL; pat++) {
		inbox_glob =
			imap_match_init(pool_datastack_create(),
					t_strconcat(ctx->ref, *pat, NULL),
					TRUE, ctx->ns->sep);
		match = imap_match(inbox_glob, "INBOX");

		if (match == IMAP_MATCH_YES)
			return IMAP_MATCH_YES;
		if ((match & IMAP_MATCH_PARENT) != 0)
			ret = IMAP_MATCH_PARENT;
	}
	return ret;
}

static bool
list_want_send_prefix(struct cmd_list_context *ctx, const char *pattern)
{
	/* don't send the prefix if we're listing subscribed mailboxes */
	if ((ctx->list_flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		if ((ctx->ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) == 0) {
			/* using parent's subscriptions file. it'll handle
			   this internally */
			return FALSE;
		}
		/* send prefix if namespace has at least some subscriptions,
		   but pattern doesn't match any children (e.g. "%") */
		return TRUE;
	}

	/* send the prefix if namespace is listable. if children are listable
	   we may or may not need to send it. */
	if ((ctx->ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
			       NAMESPACE_FLAG_LIST_CHILDREN)) != 0)
		return TRUE;

	/* ..or if pattern is exactly the same as namespace prefix.
	   some clients (mutt) want to do LIST "" prefix. */
	for (; *pattern != '\0'; pattern++) {
		if (*pattern == '*' || *pattern == '%')
			break;
	}
	return *pattern == '\0';
}

static bool
list_namespace_match_pattern(struct cmd_list_context *ctx, bool inboxcase,
			     const char *cur_ref, const char *cur_ns_prefix,
			     const char *cur_pattern)
{
	const char *orig_cur_pattern = cur_pattern;
	struct mail_namespace *ns = ctx->ns;
	struct imap_match_glob *pat_glob;
	enum imap_match_result match;
	const char *p;
	size_t len;

	skip_namespace_prefix_pattern(ctx, &cur_ns_prefix,
				      cur_ref, &cur_pattern);
	if (*cur_ns_prefix == '\0') {
		if (*ns->prefix == '\0') {
			/* no namespace prefix: if list=no we don't want to
			   show anything, except when the client does e.g.
			   LIST "" mailbox. prefix="", list=no namespace is
			   mainly useful for working around client bugs. */
			if ((ns->flags & NAMESPACE_FLAG_LIST_PREFIX) == 0 &&
			    list_pattern_has_wildcards(cur_pattern))
				return FALSE;
		}
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
	if ((ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
			  NAMESPACE_FLAG_LIST_CHILDREN)) == 0 &&
	    list_pattern_has_wildcards(cur_pattern))
		return FALSE;

	/* check if this namespace prefix matches the current pattern */
	pat_glob = imap_match_init(pool_datastack_create(), orig_cur_pattern,
				   inboxcase, ns->sep);
	match = imap_match(pat_glob, cur_ns_prefix);
	if (match == IMAP_MATCH_YES) {
		if (list_want_send_prefix(ctx, orig_cur_pattern))
			ctx->cur_ns_send_prefix = TRUE;

		/* if the pattern contains '*' characters, we'll need to
		   check our children too */
		for (p = orig_cur_pattern; *p != '\0'; p++) {
			if (*p == '*')
				return TRUE;
		}
	} else {
		while ((match & IMAP_MATCH_PARENT) != 0) {
			p = strrchr(cur_ns_prefix, ns->sep);
			if (p == NULL)
				break;
			cur_ns_prefix = t_strdup_until(cur_ns_prefix, p);
			match = imap_match(pat_glob, cur_ns_prefix);
		}
		if (match == IMAP_MATCH_YES &&
		    mail_namespace_find_prefix_nosep(ns->user->namespaces,
						     cur_ns_prefix) == NULL) {
			/* ns prefix="foo/bar/" and we're listing e.g. % */
			if (list_want_send_prefix(ctx, orig_cur_pattern))
				ctx->cur_ns_send_prefix = TRUE;
		}
	}

	return (match & IMAP_MATCH_CHILDREN) != 0;
}

static void list_namespace_init(struct cmd_list_context *ctx)
{
	struct mail_namespace *ns = ctx->ns;
	const char *cur_ns_prefix, *cur_ref, *const *pat, *pattern;
	enum imap_match_result inbox_match;
	ARRAY_DEFINE(used_patterns, const char *);
	bool inboxcase;

	cur_ns_prefix = ns->prefix;
	cur_ref = ctx->ref;

	if ((ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) == 0 &&
	    (ctx->list_flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		/* ignore namespaces which don't have subscriptions */
		return;
	}

	ctx->cur_ns_skip_trailing_sep = FALSE;

	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0)
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
		/* see if pattern even has a chance of matching the
		   namespace prefix */
		if (list_namespace_match_pattern(ctx, inboxcase, cur_ref,
						 cur_ns_prefix, pattern)) {
			pattern = mailbox_list_join_refpattern(ns->list,
							ctx->ref, pattern);
			array_append(&used_patterns, &pattern, 1);
		}
	}

	if (array_count(&used_patterns) == 0) {
		if (!ctx->cur_ns_match_inbox) {
			/* it's possible that the namespace prefix matched,
			   even though its children didn't */
			if (ctx->cur_ns_send_prefix)
				list_namespace_send_prefix(ctx, FALSE);
			return;
		}
		/* we should still list INBOX */
		pattern = "INBOX";
		array_append(&used_patterns, &pattern, 1);
	}
	(void)array_append_space(&used_patterns); /* NULL-terminate */
	pat = array_idx(&used_patterns, 0);

	cur_ref = mail_namespace_fix_sep(ns, cur_ref);
	ctx->list_iter = mailbox_list_iter_init_multiple(ns->list, pat,
							 ctx->list_flags);
}

static void list_inbox(struct cmd_list_context *ctx)
{
	const char *str;

	/* INBOX always exists */
	if (!ctx->inbox_found && ctx->cur_ns_match_inbox &&
	    (ctx->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
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
			T_BEGIN {
				list_namespace_init(ctx);
			} T_END;
			if (ctx->list_iter == NULL)
				continue;
		}

		T_BEGIN {
			ret = list_namespace_mailboxes(ctx);
		} T_END;
		if (ret < 0) {
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
	ns = mail_namespace_find_visible(client->user->namespaces, &ref);
	if (ns != NULL) {
		ns_prefix = ns->prefix;
		ns_sep = ns->sep;
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

bool cmd_list_full(struct client_command_context *cmd, bool lsub)
{
	struct client *client = cmd->client;
	const struct imap_arg *args, *list_args;
	unsigned int arg_count;
        struct cmd_list_context *ctx;
	ARRAY_DEFINE(patterns, const char *) = ARRAY_INIT;
	const char *pattern, *const *patterns_strarr;

	/* [(<selection options>)] <reference> <pattern>|(<pattern list>)
	   [RETURN (<return options>)] */
	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	ctx = p_new(cmd->pool, struct cmd_list_context, 1);
	ctx->cmd = cmd;
	ctx->ns = client->user->namespaces;
	ctx->lsub = lsub;

	cmd->context = ctx;

	if (!lsub && imap_arg_get_list(&args[0], &list_args)) {
		/* LIST-EXTENDED selection options */
		ctx->used_listext = TRUE;
		if (!parse_select_flags(ctx, list_args))
			return TRUE;
		args++;
	}

	if (!imap_arg_get_astring(&args[0], &ctx->ref)) {
		client_send_command_error(cmd, "Invalid reference.");
		return TRUE;
	}
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
			array_append(&patterns, &pattern, 1);
		}
		args += 2;
	} else {
		if (!imap_arg_get_astring(&args[1], &pattern)) {
			client_send_command_error(cmd, "Invalid pattern.");
			return TRUE;
		}

		p_array_init(&patterns, cmd->pool, 1);
		array_append(&patterns, &pattern, 1);
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
		if ((cmd->client->set->parsed_workarounds &
		     WORKAROUND_TB_LSUB_FLAGS) == 0)
			ctx->list_flags |= MAILBOX_LIST_ITER_RETURN_NO_FLAGS;
	} else if (!ctx->used_listext) {
		/* non-extended LIST - return children flags always */
		ctx->list_flags |= MAILBOX_LIST_ITER_RETURN_CHILDREN;
	}
	ctx->list_flags |= MAILBOX_LIST_ITER_SHOW_EXISTING_PARENT;

	if (!IMAP_ARG_IS_EOL(args)) {
		client_send_command_error(cmd, "Extra arguments.");
		return TRUE;
	}

	(void)array_append_space(&patterns); /* NULL-terminate */
	patterns_strarr = array_idx(&patterns, 0);
	if (!ctx->used_listext && !lsub && *patterns_strarr[0] == '\0') {
		/* Only LIST ref "" gets us here */
		cmd_list_ref_root(client, ctx->ref);
		client_send_tagline(cmd, "OK List completed.");
	} else {
		ctx->patterns = patterns_strarr;
		p_array_init(&ctx->ns_prefixes_listed, cmd->pool, 8);

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
