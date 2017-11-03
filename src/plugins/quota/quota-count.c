/* Copyright (c) 2006-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mailbox-list-iter.h"
#include "quota-private.h"

struct count_quota_root {
	struct quota_root root;

	struct timeval cache_timeval;
	uint64_t cached_bytes, cached_count;
};

struct quota_mailbox_iter {
	struct quota_root *root;
	struct mail_namespace *ns;
	unsigned int ns_idx;
	struct mailbox_list_iterate_context *iter;
	struct mailbox_info info;
	const char *error;
};

extern struct quota_backend quota_backend_count;

static int
quota_count_mailbox(struct quota_root *root, struct mail_namespace *ns,
		    const char *vname, uint64_t *bytes, uint64_t *count,
		    enum quota_get_result *error_result_r,
		    const char **error_r)
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
	mailbox_set_reason(box, "quota count");
	if ((box->storage->class_flags & MAIL_STORAGE_CLASS_FLAG_NOQUOTA) != 0) {
		/* quota doesn't exist for this mailbox/storage */
		ret = 0;
	} else if (mailbox_get_metadata(box, root->quota->set->vsizes ?
					MAILBOX_METADATA_VIRTUAL_SIZE :
					MAILBOX_METADATA_PHYSICAL_SIZE,
					&metadata) < 0 ||
	    mailbox_get_status(box, STATUS_MESSAGES, &status) < 0) {
		errstr = mailbox_get_last_internal_error(box, &error);
		if (error == MAIL_ERROR_TEMP) {
			*error_r = t_strdup_printf(
				"Couldn't get size of mailbox %s: %s",
				vname, errstr);
			*error_result_r = QUOTA_GET_RESULT_INTERNAL_ERROR;
			ret = -1;
		} else if (error == MAIL_ERROR_INUSE) {
			/* started on background. don't log an error. */
			*error_r = t_strdup_printf(
				"Ongoing quota calculation blocked getting size of %s: %s",
				vname, errstr);
			*error_result_r = QUOTA_GET_RESULT_BACKGROUND_CALC;
			ret = -1;
		} else {
			/* non-temporary error, e.g. ACLs denied access. */
			ret = 0;
		}
	} else {
		ret = 0;
		*bytes += root->quota->set->vsizes ?
			metadata.virtual_size : metadata.physical_size;
		*count += status.messages;
	}
	mailbox_free(&box);
	return ret;
}

static struct quota_mailbox_iter *
quota_mailbox_iter_begin(struct quota_root *root)
{
	struct quota_mailbox_iter *iter;

	iter = i_new(struct quota_mailbox_iter, 1);
	iter->root = root;
	iter->error = "";
	return iter;
}

static int
quota_mailbox_iter_deinit(struct quota_mailbox_iter **_iter,
			  const char **error_r)
{
	struct quota_mailbox_iter *iter = *_iter;
	int ret = *iter->error != '\0' ? -1 : 0;

	*_iter = NULL;

	const char *error2 = "";
	if (iter->iter != NULL) {
		if (mailbox_list_iter_deinit(&iter->iter) < 0) {
			error2 = t_strdup_printf(
				"Listing namespace '%s' failed: %s",
				iter->ns->prefix,
				mailbox_list_get_last_internal_error(iter->ns->list, NULL));
			ret = -1;
		}
	}
	if (ret < 0) {
		const char *separator =
			*iter->error != '\0' && *error2 != '\0' ? " and " : "";
		*error_r = t_strdup_printf("%s%s%s",
					   iter->error, separator, error2);
	}
	i_free(iter);
	return ret;
}

static const struct mailbox_info *
quota_mailbox_iter_next(struct quota_mailbox_iter *iter)
{
	struct mail_namespace *const *namespaces;
	const struct mailbox_info *info;
	unsigned int count;

	if (iter->iter == NULL) {
		namespaces = array_get(&iter->root->quota->namespaces, &count);
		do {
			if (iter->ns_idx >= count)
				return NULL;

			iter->ns = namespaces[iter->ns_idx++];
		} while (!quota_root_is_namespace_visible(iter->root, iter->ns));
		iter->iter = mailbox_list_iter_init(iter->ns->list, "*",
			MAILBOX_LIST_ITER_SKIP_ALIASES |
			MAILBOX_LIST_ITER_RETURN_NO_FLAGS |
			MAILBOX_LIST_ITER_NO_AUTO_BOXES);
	}
	while ((info = mailbox_list_iter_next(iter->iter)) != NULL) {
		if ((info->flags & (MAILBOX_NONEXISTENT |
				    MAILBOX_NOSELECT)) == 0)
			return info;
	}
	if (mailbox_list_iter_deinit(&iter->iter) < 0) {
		iter->error = t_strdup_printf(
			"Listing namespace '%s' failed: %s",
			iter->ns->prefix,
			mailbox_list_get_last_internal_error(iter->ns->list, NULL));
	}
	if (iter->ns->prefix_len > 0 &&
	    (iter->ns->prefix_len != 6 ||
	     strncasecmp(iter->ns->prefix, "INBOX", 5) != 0)) {
		/* if the namespace prefix itself exists, count it also */
		iter->info.ns = iter->ns;
		iter->info.vname = t_strndup(iter->ns->prefix,
					     iter->ns->prefix_len-1);
		return &iter->info;
	}
	/* try the next namespace */
	return quota_mailbox_iter_next(iter);
}

int quota_count(struct quota_root *root, uint64_t *bytes_r, uint64_t *count_r,
		enum quota_get_result *error_result_r, const char **error_r)
{
	struct quota_mailbox_iter *iter;
	const struct mailbox_info *info;
	const char *error1 = "", *error2 = "";
	int ret = 1;

	*bytes_r = *count_r = 0;
	if (root->recounting)
		return 0;
	root->recounting = TRUE;

	iter = quota_mailbox_iter_begin(root);
	while ((info = quota_mailbox_iter_next(iter)) != NULL) {
		if (quota_count_mailbox(root, info->ns, info->vname,
					bytes_r, count_r, error_result_r,
					&error1) < 0) {
			ret = -1;
			break;
		}
	}
	if (quota_mailbox_iter_deinit(&iter, &error2) < 0) {
		*error_result_r = QUOTA_GET_RESULT_INTERNAL_ERROR;
		ret = -1;
	}
	if (ret < 0) {
		const char *separator =
			*error1 != '\0' && *error2 != '\0' ? " and " : "";
		*error_r = t_strdup_printf(
			"quota-count failed: %s%s%s",
			error1, separator, error2);
	}
	root->recounting = FALSE;
	return ret;
}

static enum quota_get_result
quota_count_cached(struct count_quota_root *root,
		   uint64_t *bytes_r, uint64_t *count_r,
		   const char **error_r)
{
	int ret;

	if (root->cache_timeval.tv_usec == ioloop_timeval.tv_usec &&
	    root->cache_timeval.tv_sec == ioloop_timeval.tv_sec &&
	    ioloop_timeval.tv_sec != 0) {
		*bytes_r = root->cached_bytes;
		*count_r = root->cached_count;
		return QUOTA_GET_RESULT_LIMITED;
	}

	enum quota_get_result error_res;
	ret = quota_count(&root->root, bytes_r, count_r, &error_res, error_r);
	if (ret < 0) {
		return error_res;
	} else if (ret > 0) {
		root->cache_timeval = ioloop_timeval;
		root->cached_bytes = *bytes_r;
		root->cached_count = *count_r;
	}
	return QUOTA_GET_RESULT_LIMITED;
}

static struct quota_root *count_quota_alloc(void)
{
	struct count_quota_root *root;

	root = i_new(struct count_quota_root, 1);
	return &root->root;
}

static int count_quota_init(struct quota_root *root, const char *args,
			    const char **error_r)
{
	if (!root->quota->set->vsizes) {
		*error_r = "quota count backend requires quota_vsizes=yes";
		return -1;
	}
	root->auto_updating = TRUE;
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

static enum quota_get_result
count_quota_get_resource(struct quota_root *_root,
			 const char *name, uint64_t *value_r,
			 const char **error_r)
{
	struct count_quota_root *root = (struct count_quota_root *)_root;
	uint64_t bytes, count;
	enum quota_get_result ret;

	ret = quota_count_cached(root, &bytes, &count, error_r);
	if (ret <= QUOTA_GET_RESULT_INTERNAL_ERROR)
		return ret;

	if (strcmp(name, QUOTA_NAME_STORAGE_BYTES) == 0)
		*value_r = bytes;
	else if (strcmp(name, QUOTA_NAME_MESSAGES) == 0)
		*value_r = count;
	else {
		*error_r = QUOTA_UNKNOWN_RESOURCE_ERROR_STRING;
		return QUOTA_GET_RESULT_UNKNOWN_RESOURCE;
	}
	return QUOTA_GET_RESULT_LIMITED;
}

static int quota_count_recalculate_box(struct mailbox *box,
				       const char **error_r)
{
	struct mail_index_transaction *trans;
	struct mailbox_metadata metadata;
	struct mailbox_index_vsize vsize_hdr;
	const char *errstr;
	enum mail_error error;

	if (mailbox_open(box) < 0) {
		errstr = mailbox_get_last_internal_error(box, &error);
		if (error != MAIL_ERROR_TEMP) {
			/* non-temporary error, e.g. ACLs denied access. */
			return 0;
		}
		*error_r = t_strdup_printf(
			"Couldn't open mailbox %s: %s", box->vname, errstr);
		return -1;
	}

	/* reset the vsize header first */
	trans = mail_index_transaction_begin(box->view,
				MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	i_zero(&vsize_hdr);
	mail_index_update_header_ext(trans, box->vsize_hdr_ext_id,
				     0, &vsize_hdr, sizeof(vsize_hdr));
	if (mail_index_transaction_commit(&trans) < 0) {
		*error_r = t_strdup_printf(
			"Couldn't commit mail index transaction for %s: %s",
			box->vname,
			mail_index_get_error_message(box->view->index));
		return -1;
	}
	/* getting the vsize now forces its recalculation */
	if (mailbox_get_metadata(box, MAILBOX_METADATA_VIRTUAL_SIZE,
				 &metadata) < 0) {
		*error_r = t_strdup_printf(
			"Couldn't get mailbox %s vsize: %s", box->vname,
			mailbox_get_last_internal_error(box, NULL));
		return -1;
	}
	/* call sync to write the change to mailbox list index */
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FAST) < 0) {
		*error_r = t_strdup_printf(
			"Couldn't sync mailbox %s: %s", box->vname,
			mailbox_get_last_internal_error(box, NULL));
		return -1;
	}
	return 0;
}

static int quota_count_recalculate(struct quota_root *root,
				   const char **error_r)
{
	struct quota_mailbox_iter *iter;
	const struct mailbox_info *info;
	struct mailbox *box;
	int ret = 0;
	const char *error1 = "", *error2 = "";

	iter = quota_mailbox_iter_begin(root);
	while ((info = quota_mailbox_iter_next(iter)) != NULL) {
		box = mailbox_alloc(info->ns->list, info->vname, 0);
		mailbox_set_reason(box, "quota recalculate");
		if (quota_count_recalculate_box(box, &error1) < 0)
			ret = -1;
		mailbox_free(&box);
	}
	if (quota_mailbox_iter_deinit(&iter, &error2) < 0)
		ret = -1;
	if (ret < 0) {
		const char *separator =
			*error1 != '\0' && *error2 != '\0' ? " and " : "";
		*error_r = t_strdup_printf(
			"quota-count: recalculate failed: %s%s%s",
			error1, separator, error2);
	}
	return ret;
}

static int
count_quota_update(struct quota_root *root,
		   struct quota_transaction_context *ctx,
		   const char **error_r)
{
	struct count_quota_root *croot = (struct count_quota_root *)root;

	croot->cache_timeval.tv_sec = 0;
	if (ctx->recalculate == QUOTA_RECALCULATE_FORCED) {
		if (quota_count_recalculate(root, error_r) < 0)
			return -1;
	}
	return 0;
}

struct quota_backend quota_backend_count = {
	.name = "count",

	.v = {
		.alloc = count_quota_alloc,
		.init = count_quota_init,
		.deinit = count_quota_deinit,
		.get_resources = count_quota_root_get_resources,
		.get_resource = count_quota_get_resource,
		.update = count_quota_update,
	}
};
