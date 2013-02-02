/* Copyright (c) 2006-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-search-build.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "mailbox-list-iter.h"
#include "quota-private.h"

static int
quota_count_mailbox(struct quota_root *root, struct mail_namespace *ns,
		    const char *vname, uint64_t *bytes_r, uint64_t *count_r)
{
	struct quota_rule *rule;
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct mail_search_args *search_args;
	enum mail_error error;
	uoff_t size;
	int ret = 0;

	rule = quota_root_rule_find(root->set, vname);
	if (rule != NULL && rule->ignore) {
		/* mailbox not included in quota */
		return 0;
	}

	box = mailbox_alloc(ns->list, vname, MAILBOX_FLAG_READONLY);
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		error = mailbox_get_last_mail_error(box);
		mailbox_free(&box);
		if (error == MAIL_ERROR_TEMP)
			return -1;
		/* non-temporary error, e.g. ACLs denied access. */
		return 0;
	}

	trans = mailbox_transaction_begin(box, 0);

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	ctx = mailbox_search_init(trans, search_args, NULL,
				  MAIL_FETCH_PHYSICAL_SIZE, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(ctx, &mail)) {
		if (mail_get_physical_size(mail, &size) == 0)
			*bytes_r += size;
		*count_r += 1;
	}
	if (mailbox_search_deinit(&ctx) < 0)
		ret = -1;

	if (ret < 0)
		mailbox_transaction_rollback(&trans);
	else
		(void)mailbox_transaction_commit(&trans);

	mailbox_free(&box);
	return ret;
}

static int
quota_count_namespace(struct quota_root *root, struct mail_namespace *ns,
		      uint64_t *bytes, uint64_t *count)
{
	struct mailbox_list_iterate_context *ctx;
	const struct mailbox_info *info;
	int ret = 0;

	ctx = mailbox_list_iter_init(ns->list, "*",
				     MAILBOX_LIST_ITER_SKIP_ALIASES |
				     MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(ctx)) != NULL) {
		if ((info->flags & (MAILBOX_NONEXISTENT |
				    MAILBOX_NOSELECT)) == 0) {
			ret = quota_count_mailbox(root, ns, info->vname,
						  bytes, count);
			if (ret < 0)
				break;
		}
	}
	if (mailbox_list_iter_deinit(&ctx) < 0)
		ret = -1;
	if (ns->prefix_len > 0 && ret == 0 &&
	    (ns->prefix_len != 6 || strncasecmp(ns->prefix, "INBOX", 5) != 0)) {
		/* if the namespace prefix itself exists, count it also */
		const char *name = t_strndup(ns->prefix, ns->prefix_len-1);
		ret = quota_count_mailbox(root, ns, name, bytes, count);
	}
	return ret;
}

int quota_count(struct quota_root *root, uint64_t *bytes_r, uint64_t *count_r)
{
	struct mail_namespace *const *namespaces;
	unsigned int i, count;
	int ret = 0;

	*bytes_r = *count_r = 0;
	if (root->recounting)
		return 0;
	root->recounting = TRUE;

	namespaces = array_get(&root->quota->namespaces, &count);
	for (i = 0; i < count; i++) {
		if (!quota_root_is_namespace_visible(root, namespaces[i]))
			continue;

		ret = quota_count_namespace(root, namespaces[i],
					    bytes_r, count_r);
		if (ret < 0)
			break;
	}
	root->recounting = FALSE;
	return ret;
}
