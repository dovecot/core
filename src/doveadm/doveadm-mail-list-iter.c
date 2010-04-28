/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

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
	string_t *vname;
};

static void
search_args_get_mailbox_patterns(const struct mail_search_arg *args,
				 ARRAY_TYPE(const_string) *patterns)
{
	const struct mail_search_arg *subargs;

	for (; args != NULL; args = args->next) {
		switch (args->type) {
		case SEARCH_OR:
		case SEARCH_SUB:
		case SEARCH_INTHREAD:
			subargs = args->value.subargs;
			for (; subargs != NULL; subargs = subargs->next) {
				search_args_get_mailbox_patterns(subargs,
								 patterns);
			}
			break;
		case SEARCH_MAILBOX:
		case SEARCH_MAILBOX_GLOB:
			array_append(patterns, &args->value.str, 1);
			break;
		default:
			break;
		}
	}
}

struct doveadm_mail_list_iter *
doveadm_mail_list_iter_init(struct mail_user *user,
			    struct mail_search_args *search_args,
			    enum mailbox_list_iter_flags iter_flags)
{
	static const char *all_pattern = "*";
	struct doveadm_mail_list_iter *iter;
	ARRAY_TYPE(const_string) patterns;

	iter = i_new(struct doveadm_mail_list_iter, 1);
	iter->search_args = search_args;

	t_array_init(&patterns, 16);
	search_args_get_mailbox_patterns(search_args->args, &patterns);
	if (array_count(&patterns) == 0) {
		iter_flags |= MAILBOX_LIST_ITER_SKIP_ALIASES;
		array_append(&patterns, &all_pattern, 1);
	} else {
		iter_flags |= MAILBOX_LIST_ITER_STAR_WITHIN_NS;
	}
	(void)array_append_space(&patterns);

	iter->iter_flags = iter_flags;
	iter->iter = mailbox_list_iter_init_namespaces(user->namespaces,
						       array_idx(&patterns, 0),
						       NAMESPACE_PRIVATE,
						       iter_flags);
	iter->vname = str_new(default_pool, 256);
	return iter;
}

void doveadm_mail_list_iter_deinit(struct doveadm_mail_list_iter **_iter)
{
	struct doveadm_mail_list_iter *iter = *_iter;

	*_iter = NULL;

	if (mailbox_list_iter_deinit(&iter->iter) < 0)
		i_error("Listing mailboxes failed");
	str_free(&iter->vname);
	i_free(iter);
}

const struct mailbox_info *
doveadm_mail_list_iter_next(struct doveadm_mail_list_iter *iter)
{
	const struct mailbox_info *info;
	const char *vname;

	while ((info = mailbox_list_iter_next(iter->iter)) != NULL) {
		if ((iter->iter_flags & MAILBOX_LIST_ITER_VIRTUAL_NAMES) != 0)
			vname = info->name;
		else {
			vname = mail_namespace_get_vname(info->ns, iter->vname,
							 info->name);
		}
		if (mail_search_args_match_mailbox(iter->search_args, vname,
						   info->ns->sep))
			break;
	}
	return info;
}
