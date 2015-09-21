/* Copyright (c) 2006-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mailbox-list-iter.h"
#include "quota-private.h"

extern struct quota_backend quota_backend_count;

static int
quota_count_mailbox(struct quota_root *root, struct mail_namespace *ns,
		    const char *vname, uint64_t *bytes_r, uint64_t *count_r)
{
	struct quota_rule *rule;
	struct mailbox *box;
	struct mailbox_metadata metadata;
	struct mailbox_status status;
	enum mail_error error;
	const char *errstr;
	int ret;

	rule = quota_root_rule_find(root->set, vname);
	if (rule != NULL && rule->ignore) {
		/* mailbox not included in quota */
		return 0;
	}

	box = mailbox_alloc(ns->list, vname, MAILBOX_FLAG_READONLY);
	if (mailbox_get_metadata(box, root->quota->set->vsizes ?
				 MAILBOX_METADATA_VIRTUAL_SIZE :
				 MAILBOX_METADATA_PHYSICAL_SIZE,
				 &metadata) < 0 ||
	    mailbox_get_status(box, STATUS_MESSAGES, &status) < 0) {
		errstr = mailbox_get_last_error(box, &error);
		if (error == MAIL_ERROR_TEMP) {
			i_error("quota: Couldn't get size of mailbox %s: %s",
				vname, errstr);
			ret = -1;
		} else {
			/* non-temporary error, e.g. ACLs denied access. */
			ret = 0;
		}
	} else {
		ret = 1;
		*bytes_r = root->quota->set->vsizes ?
			metadata.virtual_size : metadata.physical_size;
		*count_r = status.messages;
	}
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
	if (mailbox_list_iter_deinit(&ctx) < 0) {
		i_error("quota: Listing namespace '%s' failed: %s",
			ns->prefix, mailbox_list_get_last_error(ns->list, NULL));
		ret = -1;
	}
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

static struct quota_root *count_quota_alloc(void)
{
	return i_new(struct quota_root, 1);
}

static int count_quota_init(struct quota_root *root, const char *args,
			    const char **error_r)
{
	if (!root->quota->set->vsizes) {
		*error_r = "quota count backend requires quota_vsizes=yes";
		return -1;
	}
	return quota_root_default_init(root, args, error_r);
}

static void count_quota_deinit(struct quota_root *_root)
{
	i_free(_root);
}

static const char *const *
count_quota_root_get_resources(struct quota_root *root ATTR_UNUSED)
{
	static const char *resources[] = {
		QUOTA_NAME_STORAGE_KILOBYTES, QUOTA_NAME_MESSAGES, NULL
	};
	return resources;
}

static int
count_quota_get_resource(struct quota_root *root,
			 const char *name, uint64_t *value_r)
{
	uint64_t bytes, count;

	if (quota_count(root, &bytes, &count) < 0)
		return -1;

	if (strcmp(name, QUOTA_NAME_STORAGE_BYTES) == 0)
		*value_r = bytes;
	else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0)
		*value_r = count;
	else
		return 0;
	return 1;
}

static int
count_quota_update(struct quota_root *root ATTR_UNUSED,
		   struct quota_transaction_context *ctx ATTR_UNUSED)
{
	if (ctx->recalculate) {
		//FIXME: remove cached values from index
	}
	return 0;
}

struct quota_backend quota_backend_count = {
	"count",

	{
		count_quota_alloc,
		count_quota_init,
		count_quota_deinit,
		NULL,
		NULL,
		NULL,
		count_quota_root_get_resources,
		count_quota_get_resource,
		count_quota_update,
		NULL,
		NULL
	}
};
