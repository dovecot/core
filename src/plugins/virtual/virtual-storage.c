/* Copyright (c) 2008-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "mail-search.h"
#include "virtual-plugin.h"
#include "virtual-transaction.h"
#include "virtual-storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define VIRTUAL_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, virtual_mailbox_list_module)

struct virtual_mailbox_list {
	union mailbox_list_module_context module_ctx;
};

extern struct mail_storage virtual_storage;
extern struct mailbox virtual_mailbox;

struct virtual_storage_module virtual_storage_module =
	MODULE_CONTEXT_INIT(&mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(virtual_mailbox_list_module,
				  &mailbox_list_module_register);

void virtual_box_copy_error(struct mailbox *dest, struct mailbox *src)
{
	const char *str;
	enum mail_error error;

	str = mail_storage_get_last_error(src->storage, &error);
	if ((src->list->ns->flags & NAMESPACE_FLAG_HIDDEN) != 0)
		str = t_strdup_printf("%s (mailbox %s)", str, src->name);
	else {
		str = t_strdup_printf("%s (mailbox %s%s)", str,
				      src->list->ns->prefix, src->name);
	}
	mail_storage_set_error(dest->storage, error, str);
}

static struct mail_storage *virtual_storage_alloc(void)
{
	struct virtual_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("virtual storage", 512+256);
	storage = p_new(pool, struct virtual_storage, 1);
	storage->storage = virtual_storage;
	storage->storage.pool = pool;
	p_array_init(&storage->open_stack, pool, 8);
	return &storage->storage;
}

static void
virtual_storage_get_list_settings(const struct mail_namespace *ns ATTR_UNUSED,
				  struct mailbox_list_settings *set)
{
	if (set->layout == NULL)
		set->layout = MAILBOX_LIST_NAME_FS;
	if (set->subscription_fname == NULL)
		set->subscription_fname = VIRTUAL_SUBSCRIPTION_FILE_NAME;
}

struct virtual_backend_box *
virtual_backend_box_lookup_name(struct virtual_mailbox *mbox, const char *name)
{
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;

	bboxes = array_get(&mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(bboxes[i]->name, name) == 0)
			return bboxes[i];
	}
	return NULL;
}

struct virtual_backend_box *
virtual_backend_box_lookup(struct virtual_mailbox *mbox, uint32_t mailbox_id)
{
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;

	if (mailbox_id == 0)
		return NULL;

	bboxes = array_get(&mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (bboxes[i]->mailbox_id == mailbox_id)
			return bboxes[i];
	}
	return NULL;
}

static bool virtual_mailbox_is_in_open_stack(struct virtual_storage *storage,
					     const char *name)
{
	const char *const *names;
	unsigned int i, count;

	names = array_get(&storage->open_stack, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(names[i], name) == 0)
			return TRUE;
	}
	return FALSE;
}

static int virtual_backend_box_open(struct virtual_mailbox *mbox,
				    struct virtual_backend_box *bbox,
				    enum mailbox_flags flags)
{
	struct mail_user *user = mbox->storage->storage.user;
	struct mail_storage *storage;
	struct mail_namespace *ns;
	enum mail_error error;
	const char *str, *mailbox;

	flags |= MAILBOX_FLAG_KEEP_RECENT;

	mailbox = bbox->name;
	ns = mail_namespace_find(user->namespaces, &mailbox);
	bbox->box = mailbox_alloc(ns->list, mailbox, flags);

	if (mailbox_open(bbox->box) < 0) {
		storage = mailbox_get_storage(bbox->box);
		str = mail_storage_get_last_error(storage, &error);
		mailbox_free(&bbox->box);
		if (bbox->wildcard && (error == MAIL_ERROR_PERM ||
				       error == MAIL_ERROR_NOTFOUND)) {
			/* this mailbox wasn't explicitly specified.
			   just skip it. */
			return 0;
		}
		/* copy the error */
		mail_storage_set_error(mbox->box.storage, error,
			t_strdup_printf("%s (%s)", str, mailbox));
		return -1;
	}
	i_array_init(&bbox->uids, 64);
	i_array_init(&bbox->sync_pending_removes, 64);
	mail_search_args_init(bbox->search_args, bbox->box, FALSE, NULL);
	return 1;
}

static int virtual_mailboxes_open(struct virtual_mailbox *mbox,
				  enum mailbox_flags flags)
{
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;
	int ret;

	bboxes = array_get(&mbox->backend_boxes, &count);
	for (i = 0; i < count; ) {
		ret = virtual_backend_box_open(mbox, bboxes[i], flags);
		if (ret <= 0) {
			if (ret < 0)
				break;
			mail_search_args_unref(&bboxes[i]->search_args);
			array_delete(&mbox->backend_boxes, i, 1);
			bboxes = array_get(&mbox->backend_boxes, &count);
		} else {
			i++;
		}
	}
	if (i == count)
		return 0;
	else {
		/* failed */
		for (; i > 0; i--) {
			mailbox_free(&bboxes[i-1]->box);
			array_free(&bboxes[i-1]->uids);
		}
		return -1;
	}
}

static struct mailbox *
virtual_mailbox_alloc(struct mail_storage *_storage, struct mailbox_list *list,
		      const char *name, enum mailbox_flags flags)
{
	struct virtual_storage *storage = (struct virtual_storage *)_storage;
	struct virtual_mailbox *mbox;
	pool_t pool;

	pool = pool_alloconly_create("virtual mailbox", 1024+512);
	mbox = p_new(pool, struct virtual_mailbox, 1);
	mbox->box = virtual_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = _storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &virtual_mail_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, name, flags,
				    VIRTUAL_INDEX_PREFIX);

	mbox->storage = storage;
	mbox->vseq_lookup_prev_mailbox = i_strdup("");

	mbox->virtual_ext_id =
		mail_index_ext_register(mbox->box.index, "virtual", 0,
			sizeof(struct virtual_mail_index_record),
			sizeof(uint32_t));
	return &mbox->box;
}

static int virtual_mailbox_open(struct mailbox *box)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;
	struct stat st;
	bool failed;

	if (virtual_mailbox_is_in_open_stack(mbox->storage, box->name)) {
		mail_storage_set_critical(box->storage,
			"Virtual mailbox loops: %s", box->name);
		return -1;
	}

	if (stat(box->path, &st) == 0) {
		/* exists, open it */
	} else if (errno == ENOENT) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(box->name));
		return -1;
	} else if (errno == EACCES) {
		mail_storage_set_critical(box->storage, "%s",
			mail_error_eacces_msg("stat", box->path));
		return -1;
	} else {
		mail_storage_set_critical(box->storage,
					  "stat(%s) failed: %m", box->path);
		return -1;
	}

	array_append(&mbox->storage->open_stack, &box->name, 1);
	failed = virtual_config_read(mbox) < 0 ||
		virtual_mailboxes_open(mbox, box->flags) < 0;
	array_delete(&mbox->storage->open_stack,
		     array_count(&mbox->storage->open_stack)-1, 1);
	return failed ? -1 : index_storage_mailbox_open(box, FALSE);
}

static void virtual_mailbox_close(struct mailbox *box)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;
	struct virtual_backend_box **bboxes;
	unsigned int i, count;

	virtual_config_free(mbox);

	bboxes = array_get_modifiable(&mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (bboxes[i]->search_result != NULL)
			mailbox_search_result_free(&bboxes[i]->search_result);

		if (bboxes[i]->box == NULL)
			continue;

		mailbox_free(&bboxes[i]->box);
		if (array_is_created(&bboxes[i]->sync_outside_expunges))
			array_free(&bboxes[i]->sync_outside_expunges);
		array_free(&bboxes[i]->sync_pending_removes);
		array_free(&bboxes[i]->uids);
	}
	array_free(&mbox->backend_boxes);
	i_free(mbox->vseq_lookup_prev_mailbox);

	index_storage_mailbox_close(box);
}

static int
virtual_mailbox_create(struct mailbox *box,
		       const struct mailbox_update *update ATTR_UNUSED,
		       bool directory ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Can't create virtual mailboxes");
	return -1;
}

static int
virtual_mailbox_update(struct mailbox *box,
		       const struct mailbox_update *update ATTR_UNUSED)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Can't update virtual mailboxes");
	return -1;
}

static void virtual_notify_changes(struct mailbox *box ATTR_UNUSED)
{
	/* FIXME: maybe some day */
}

static int
virtual_list_get_mailbox_flags(struct mailbox_list *list,
			       const char *dir, const char *fname,
			       enum mailbox_list_file_type type,
			       struct stat *st_r,
			       enum mailbox_info_flags *flags)
{
	struct virtual_mailbox_list *mlist = VIRTUAL_LIST_CONTEXT(list);
	struct stat st2;
	const char *virtual_path;
	int ret;

	ret = mlist->module_ctx.super.
		get_mailbox_flags(list, dir, fname, type, st_r, flags);
	if (ret <= 0 || MAILBOX_INFO_FLAGS_FINISHED(*flags))
		return ret;

	/* see if it's a selectable mailbox */
	virtual_path = t_strconcat(dir, "/", fname, "/"VIRTUAL_CONFIG_FNAME,
				   NULL);
	if (stat(virtual_path, &st2) < 0)
		*flags |= MAILBOX_NOSELECT;
	return ret;
}

static void virtual_storage_add_list(struct mail_storage *storage ATTR_UNUSED,
				     struct mailbox_list *list)
{
	struct virtual_mailbox_list *mlist;

	mlist = p_new(list->pool, struct virtual_mailbox_list, 1);
	mlist->module_ctx.super = list->v;

	list->ns->flags |= NAMESPACE_FLAG_NOQUOTA;
	list->v.get_mailbox_flags = virtual_list_get_mailbox_flags;

	MODULE_CONTEXT_SET(list, virtual_mailbox_list_module, mlist);
}

static int virtual_backend_uidmap_cmp(const uint32_t *uid,
				      const struct virtual_backend_uidmap *map)
{
	return *uid < map->real_uid ? -1 :
		*uid > map->real_uid ? 1 : 0;
}

static bool
virtual_get_virtual_uid(struct mailbox *box, const char *backend_mailbox,
			uint32_t backend_uidvalidity,
			uint32_t backend_uid, uint32_t *uid_r)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;
	struct virtual_backend_box *bbox;
	struct mailbox_status status;
	const struct virtual_backend_uidmap *uids;

	if (strcmp(mbox->vseq_lookup_prev_mailbox, backend_mailbox) == 0)
		bbox = mbox->vseq_lookup_prev_bbox;
	else {
		i_free(mbox->vseq_lookup_prev_mailbox);
		mbox->vseq_lookup_prev_mailbox = i_strdup(backend_mailbox);

		bbox = virtual_backend_box_lookup_name(mbox, backend_mailbox);
		mbox->vseq_lookup_prev_bbox = bbox;
	}
	if (bbox == NULL)
		return FALSE;

	mailbox_get_status(bbox->box, STATUS_UIDVALIDITY, &status);
	if (status.uidvalidity != backend_uidvalidity)
		return FALSE;

	uids = array_bsearch(&bbox->uids, &backend_uid,
			     virtual_backend_uidmap_cmp);
	if (uids == NULL)
		return FALSE;

	*uid_r = uids->virtual_uid;
	return TRUE;
}

static void
virtual_get_virtual_backend_boxes(struct mailbox *box,
				  ARRAY_TYPE(mailboxes) *mailboxes,
				  bool only_with_msgs)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;

	bboxes = array_get(&mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (!only_with_msgs || array_count(&bboxes[i]->uids) > 0)
			array_append(mailboxes, &bboxes[i]->box, 1);
	}
}

static void
virtual_get_virtual_box_patterns(struct mailbox *box,
				 ARRAY_TYPE(mailbox_virtual_patterns) *includes,
				 ARRAY_TYPE(mailbox_virtual_patterns) *excludes)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;

	array_append_array(includes, &mbox->list_include_patterns);
	array_append_array(excludes, &mbox->list_exclude_patterns);
}

static bool virtual_is_inconsistent(struct mailbox *box)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;

	if (mbox->inconsistent)
		return TRUE;

	return index_storage_is_inconsistent(box);
}

struct mail_storage virtual_storage = {
	.name = VIRTUAL_STORAGE_NAME,
	.class_flags = 0,

	.v = {
		NULL,
		virtual_storage_alloc,
		NULL,
		NULL,
		virtual_storage_add_list,
		virtual_storage_get_list_settings,
		NULL,
		virtual_mailbox_alloc,
		NULL
	}
};

struct mailbox virtual_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_allow_new_keywords,
		index_storage_mailbox_enable,
		virtual_mailbox_open,
		virtual_mailbox_close,
		NULL,
		virtual_mailbox_create,
		virtual_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		index_storage_get_status,
		NULL,
		NULL,
		NULL,
		virtual_storage_sync_init,
		index_mailbox_sync_next,
		index_mailbox_sync_deinit,
		NULL,
		virtual_notify_changes,
		virtual_transaction_begin,
		virtual_transaction_commit,
		virtual_transaction_rollback,
		index_transaction_set_max_modseq,
		index_keywords_create,
		index_keywords_create_from_indexes,
		index_keywords_ref,
		index_keywords_unref,
		index_keyword_is_valid,
		index_storage_get_seq_range,
		index_storage_get_uid_range,
		index_storage_get_expunges,
		virtual_get_virtual_uid,
		virtual_get_virtual_backend_boxes,
		virtual_get_virtual_box_patterns,
		virtual_mail_alloc,
		index_header_lookup_init,
		index_header_lookup_deinit,
		virtual_search_init,
		virtual_search_deinit,
		virtual_search_next_nonblock,
		virtual_search_next_update_seq,
		virtual_save_alloc,
		virtual_save_begin,
		virtual_save_continue,
		virtual_save_finish,
		virtual_save_cancel,
		mail_storage_copy,
		virtual_is_inconsistent
	}
};
