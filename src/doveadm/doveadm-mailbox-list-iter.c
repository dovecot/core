/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "mail-search.h"
#include "mail-namespace.h"
#include "mailbox-list.h"
#include "doveadm-mail.h"
#include "doveadm-mailbox-list-iter.h"

struct doveadm_mailbox_list_iter {
	struct mail_user *user;
	struct doveadm_mail_cmd_context *ctx;
	struct mail_search_args *search_args;
	enum mailbox_list_iter_flags iter_flags;

	struct mailbox_list_iterate_context *iter;

	struct mailbox_info info;
	ARRAY_TYPE(const_string) patterns;
	unsigned int pattern_idx;

	bool only_selectable;
};

static bool
search_args_get_mailbox_patterns(const struct mail_search_arg *args,
				 ARRAY_TYPE(const_string) *patterns,
				 bool *have_guid, bool *have_wildcards)
{
	const struct mail_search_arg *subargs;

	for (; args != NULL; args = args->next) {
		switch (args->type) {
		case SEARCH_OR:
			/* we don't currently try to optimize OR. */
			break;
		case SEARCH_SUB:
		case SEARCH_INTHREAD:
			subargs = args->value.subargs;
			for (; subargs != NULL; subargs = subargs->next) {
				if (!search_args_get_mailbox_patterns(subargs,
							patterns, have_guid,
							have_wildcards))
					return FALSE;
			}
			break;
		case SEARCH_MAILBOX_GLOB:
			*have_wildcards = TRUE;
			/* fall through */
		case SEARCH_MAILBOX:
			if (args->match_not) {
				array_clear(patterns);
				return FALSE;
			}
			array_push_back(patterns, &args->value.str);
			break;
		case SEARCH_MAILBOX_GUID:
			*have_guid = TRUE;
			break;
		default:
			break;
		}
	}
	return TRUE;
}

static struct doveadm_mailbox_list_iter *
doveadm_mailbox_list_iter_init_nsmask(struct doveadm_mail_cmd_context *ctx,
				      struct mail_user *user,
				      struct mail_search_args *search_args,
				      enum mailbox_list_iter_flags iter_flags,
				      enum mail_namespace_type ns_mask)
{
	static const char *all_pattern = "*";
	struct doveadm_mailbox_list_iter *iter;
	bool have_guid = FALSE, have_wildcards = FALSE;

	iter = i_new(struct doveadm_mailbox_list_iter, 1);
	iter->ctx = ctx;
	iter->search_args = search_args;
	iter->user = user;
	i_array_init(&iter->patterns, 16);
	(void)search_args_get_mailbox_patterns(search_args->args,
					       &iter->patterns,
					       &have_guid, &have_wildcards);

	if (array_count(&iter->patterns) == 0) {
		iter_flags |= MAILBOX_LIST_ITER_SKIP_ALIASES;
		if (have_guid) {
			ns_mask |= MAIL_NAMESPACE_TYPE_SHARED |
				MAIL_NAMESPACE_TYPE_PUBLIC;
		}
		array_push_back(&iter->patterns, &all_pattern);
	} else if (have_wildcards) {
		iter_flags |= MAILBOX_LIST_ITER_STAR_WITHIN_NS;
		ns_mask |= MAIL_NAMESPACE_TYPE_SHARED |
			MAIL_NAMESPACE_TYPE_PUBLIC;
	} else {
		/* just return the listed mailboxes without actually
		   iterating through. this also allows accessing mailboxes
		   without lookup ACL right */
		return iter;
	}
	array_append_zero(&iter->patterns);

	iter->only_selectable = TRUE;
	iter->iter_flags = iter_flags;
	iter->iter = mailbox_list_iter_init_namespaces(user->namespaces,
						       array_front(&iter->patterns),
						       ns_mask, iter_flags);
	return iter;
}

struct doveadm_mailbox_list_iter *
doveadm_mailbox_list_iter_init(struct doveadm_mail_cmd_context *ctx,
			       struct mail_user *user,
			       struct mail_search_args *search_args,
			       enum mailbox_list_iter_flags iter_flags)
{
	enum mail_namespace_type ns_mask = MAIL_NAMESPACE_TYPE_PRIVATE;

	return doveadm_mailbox_list_iter_init_nsmask(ctx, user, search_args,
						     iter_flags, ns_mask);
}

struct doveadm_mailbox_list_iter *
doveadm_mailbox_list_iter_full_init(struct doveadm_mail_cmd_context *ctx,
				    struct mail_user *user,
				    struct mail_search_args *search_args,
				    enum mailbox_list_iter_flags iter_flags)
{
	enum mail_namespace_type ns_mask = MAIL_NAMESPACE_TYPE_MASK_ALL;
	struct doveadm_mailbox_list_iter *iter;

	iter = doveadm_mailbox_list_iter_init_nsmask(ctx, user, search_args,
						     iter_flags, ns_mask);
	iter->only_selectable = FALSE;
	return iter;
}

int doveadm_mailbox_list_iter_deinit(struct doveadm_mailbox_list_iter **_iter)
{
	struct doveadm_mailbox_list_iter *iter = *_iter;
	enum mail_error error;
	int ret;

	*_iter = NULL;

	if (iter->iter == NULL)
		ret = 0;
	else if ((ret = mailbox_list_iter_deinit(&iter->iter)) < 0) {
		i_error("Listing mailboxes failed: %s",
			mailbox_list_get_last_internal_error(iter->user->namespaces->list, &error));
		doveadm_mail_failed_error(iter->ctx, error);
	}
	array_free(&iter->patterns);
	i_free(iter);
	return ret;
}

const struct mailbox_info *
doveadm_mailbox_list_iter_next(struct doveadm_mailbox_list_iter *iter)
{
	const struct mailbox_info *info;
	const char *const *patterns;
	unsigned int count;

	while (iter->iter == NULL) {
		patterns = array_get(&iter->patterns, &count);
		if (iter->pattern_idx == count)
			return NULL;

		iter->info.vname = patterns[iter->pattern_idx++];
		iter->info.ns = mail_namespace_find(iter->user->namespaces,
						    iter->info.vname);
		return &iter->info;
	}

	while ((info = mailbox_list_iter_next(iter->iter)) != NULL) {
		char sep = mail_namespace_get_sep(info->ns);

		if ((info->flags & (MAILBOX_NOSELECT |
				    MAILBOX_NONEXISTENT)) != 0) {
			if (iter->only_selectable)
				continue;
		}

		if (mail_search_args_match_mailbox(iter->search_args,
						   info->vname, sep))
			break;
	}
	return info;
}
