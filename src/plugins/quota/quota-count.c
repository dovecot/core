/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-search-build.h"
#include "mail-storage.h"
#include "mail-namespace.h"
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
	const char *storage_name;
	enum mail_error error;
	uoff_t size;
	int ret = 0;

	storage_name = mail_namespace_get_storage_name(ns, vname);

	rule = quota_root_rule_find(root->set, vname);
	if (rule != NULL && rule->ignore) {
		/* mailbox not included in quota */
		return 0;
	}

	box = mailbox_alloc(ns->list, storage_name,
			    MAILBOX_FLAG_READONLY | MAILBOX_FLAG_KEEP_RECENT);
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		mail_storage_get_last_error(mailbox_get_storage(box), &error);
		mailbox_free(&box);
		if (error == MAIL_ERROR_TEMP)
			return -1;
		/* non-temporary error, e.g. ACLs denied access. */
		return 0;
	}

	trans = mailbox_transaction_begin(box, 0);
	mail = mail_alloc(trans, MAIL_FETCH_PHYSICAL_SIZE, NULL);

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	ctx = mailbox_search_init(trans, search_args, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(ctx, mail)) {
		if (mail_get_physical_size(mail, &size) == 0)
			*bytes_r += size;
		*count_r += 1;
	}
	mail_free(&mail);
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
				     MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(ctx)) != NULL) {
		if ((info->flags & (MAILBOX_NONEXISTENT |
				    MAILBOX_NOSELECT)) == 0) {
			ret = quota_count_mailbox(root, ns, info->name,
						  bytes, count);
			if (ret < 0)
				break;
		}
	}
	if (mailbox_list_iter_deinit(&ctx) < 0)
		ret = -1;

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
