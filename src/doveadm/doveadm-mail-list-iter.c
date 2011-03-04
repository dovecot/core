/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "mail-search.h"
#include "mail-namespace.h"
#include "mailbox-list.h"
#include "doveadm-mail-list-iter.h"

struct doveadm_mail_list_iter {
	struct mail_search_args *search_args;
	enum mailbox_list_iter_flags iter_flags;

	struct mailbox_list_iterate_context *iter;
	bool only_selectable;
};

static int
search_args_get_mailbox_patterns(const struct mail_search_arg *args,
				 ARRAY_TYPE(const_string) *patterns,
				 bool *have_guid_r)
{
	const struct mail_search_arg *subargs;

	for (; args != NULL; args = args->next) {
		switch (args->type) {
		case SEARCH_OR:
		case SEARCH_SUB:
		case SEARCH_INTHREAD:
			subargs = args->value.subargs;
			for (; subargs != NULL; subargs = subargs->next) {
				if (!search_args_get_mailbox_patterns(subargs,
							patterns, have_guid_r))
					return 0;
			}
			break;
		case SEARCH_MAILBOX:
		case SEARCH_MAILBOX_GLOB:
			if (args->not) {
				array_clear(patterns);
				return 0;
			}
			array_append(patterns, &args->value.str, 1);
			break;
		case SEARCH_MAILBOX_GUID:
			*have_guid_r = TRUE;
			break;
		default:
			break;
		}
	}
	return 1;
}

struct doveadm_mail_list_iter *
doveadm_mail_list_iter_init(struct mail_user *user,
			    struct mail_search_args *search_args,
			    enum mailbox_list_iter_flags iter_flags)
{
	static const char *all_pattern = "*";
	struct doveadm_mail_list_iter *iter;
	ARRAY_TYPE(const_string) patterns;
	enum namespace_type ns_mask = NAMESPACE_PRIVATE;
	bool have_guid = FALSE;

	iter = i_new(struct doveadm_mail_list_iter, 1);
	iter->search_args = search_args;

	t_array_init(&patterns, 16);
	search_args_get_mailbox_patterns(search_args->args, &patterns,
					 &have_guid);
	if (array_count(&patterns) == 0) {
		iter_flags |= MAILBOX_LIST_ITER_SKIP_ALIASES;
		if (have_guid)
			ns_mask |= NAMESPACE_SHARED | NAMESPACE_PUBLIC;
		array_append(&patterns, &all_pattern, 1);
	} else {
		iter_flags |= MAILBOX_LIST_ITER_STAR_WITHIN_NS;
		ns_mask |= NAMESPACE_SHARED | NAMESPACE_PUBLIC;
	}
	(void)array_append_space(&patterns);

	iter->only_selectable = TRUE;
	iter->iter_flags = iter_flags;
	iter->iter = mailbox_list_iter_init_namespaces(user->namespaces,
						       array_idx(&patterns, 0),
						       ns_mask, iter_flags);
	return iter;
}

struct doveadm_mail_list_iter *
doveadm_mail_list_iter_full_init(struct mail_user *user,
				 struct mail_search_args *search_args,
				 enum mailbox_list_iter_flags iter_flags)
{
	struct doveadm_mail_list_iter *iter;

	iter = doveadm_mail_list_iter_init(user, search_args, iter_flags);
	iter->only_selectable = FALSE;
	return iter;
}

void doveadm_mail_list_iter_deinit(struct doveadm_mail_list_iter **_iter)
{
	struct doveadm_mail_list_iter *iter = *_iter;

	*_iter = NULL;

	if (mailbox_list_iter_deinit(&iter->iter) < 0)
		i_error("Listing mailboxes failed");
	i_free(iter);
}

const struct mailbox_info *
doveadm_mail_list_iter_next(struct doveadm_mail_list_iter *iter)
{
	const struct mailbox_info *info;
	unsigned int len;

	while ((info = mailbox_list_iter_next(iter->iter)) != NULL) {
		if ((info->flags & (MAILBOX_NOSELECT |
				    MAILBOX_NONEXISTENT)) != 0) {
			if (iter->only_selectable)
				continue;
		}
		len = strlen(info->name);
		if (len > 0 && info->name[len-1] == info->ns->sep) {
			/* when listing "foo/%" it lists "foo/". skip it. */
			continue;
		}

		if (mail_search_args_match_mailbox(iter->search_args,
						   info->name, info->ns->sep))
			break;
	}
	return info;
}
