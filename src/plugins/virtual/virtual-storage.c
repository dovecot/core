/* Copyright (c) 2008-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "index-mail.h"
#include "mail-copy.h"
#include "mail-search.h"
#include "mailbox-list-private.h"
#include "virtual-plugin.h"
#include "virtual-transaction.h"
#include "virtual-storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

extern struct mail_storage virtual_storage;
extern struct mailbox virtual_mailbox;
extern struct virtual_mailbox_vfuncs virtual_mailbox_vfuncs;

struct virtual_storage_module virtual_storage_module =
	MODULE_CONTEXT_INIT(&mail_storage_module_register);

static bool ns_is_visible(struct mail_namespace *ns)
{
	return (ns->flags & NAMESPACE_FLAG_LIST_PREFIX) != 0 ||
		(ns->flags & NAMESPACE_FLAG_LIST_CHILDREN) != 0 ||
		(ns->flags & NAMESPACE_FLAG_HIDDEN) == 0;
}

static const char *get_user_visible_mailbox_name(struct mailbox *box)
{
	if (ns_is_visible(box->list->ns))
		return box->vname;
	else {
		return t_strdup_printf("<hidden>%c%s",
				       mail_namespace_get_sep(box->list->ns),
				       box->vname);
	}
}

void virtual_box_copy_error(struct mailbox *dest, struct mailbox *src)
{
	const char *name, *str;
	enum mail_error error;

	name = get_user_visible_mailbox_name(src);
	str = mailbox_get_last_error(src, &error);

	str = t_strdup_printf("%s (for backend mailbox %s)", str, name);
	mail_storage_set_error(dest->storage, error, str);
}

static struct mail_storage *virtual_storage_alloc(void)
{
	struct virtual_storage *storage;
	pool_t pool;

	pool = pool_alloconly_create("virtual storage", 1024);
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

static int virtual_backend_box_open_failed(struct virtual_mailbox *mbox,
					   struct virtual_backend_box *bbox)
{
	enum mail_error error;
	const char *str, *name;

	str = mailbox_get_last_error(bbox->box, &error);
	name = t_strdup(get_user_visible_mailbox_name(bbox->box));
	mailbox_free(&bbox->box);
	if (error == MAIL_ERROR_NOTFOUND) {
		/* ignore this. it could be intentional. */
		if (mbox->storage->storage.user->mail_debug) {
			i_debug("virtual mailbox %s: "
				"Skipping non-existing mailbox %s",
				mbox->box.vname, name);
		}
		return 0;
	}

	if (error == MAIL_ERROR_PERM && bbox->wildcard) {
		/* this mailbox wasn't explicitly specified. just skip it. */
		return 0;
	}
	str = t_strdup_printf(
		"Virtual mailbox open failed because of mailbox %s: %s",
		name, str);
	mail_storage_set_error(mbox->box.storage, error, str);
	return -1;
}

static int virtual_backend_box_open(struct virtual_mailbox *mbox,
				    struct virtual_backend_box *bbox,
				    enum mailbox_flags flags)
{
	struct mail_user *user = mbox->storage->storage.user;
	struct mail_namespace *ns;
	struct mailbox_status status;
	const char *mailbox;

	i_assert(bbox->box == NULL);

	if (bbox->clear_recent)
		flags |= MAILBOX_FLAG_DROP_RECENT;

	mailbox = bbox->name;
	ns = mail_namespace_find(user->namespaces, mailbox);
	bbox->box = mailbox_alloc(ns->list, mailbox, flags);

	if (mailbox_open(bbox->box) < 0)
		return virtual_backend_box_open_failed(mbox, bbox);
	i_array_init(&bbox->uids, 64);
	i_array_init(&bbox->sync_pending_removes, 64);
	mail_search_args_init(bbox->search_args, bbox->box, FALSE, NULL);

	mailbox_get_open_status(bbox->box, 0, &status);
	if (!status.have_guids)
		mbox->have_guids = FALSE;
	if (!status.have_save_guids)
		mbox->have_save_guids = FALSE;
	return 1;
}

static int virtual_mailboxes_open(struct virtual_mailbox *mbox,
				  enum mailbox_flags flags)
{
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;
	int ret;

	mbox->have_guids = TRUE;
	mbox->have_save_guids = TRUE;

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
		      const char *vname, enum mailbox_flags flags)
{
	struct virtual_storage *storage = (struct virtual_storage *)_storage;
	struct virtual_mailbox *mbox;
	pool_t pool;

	pool = pool_alloconly_create("virtual mailbox", 2048);
	mbox = p_new(pool, struct virtual_mailbox, 1);
	mbox->box = virtual_mailbox;
	mbox->box.pool = pool;
	mbox->box.storage = _storage;
	mbox->box.list = list;
	mbox->box.mail_vfuncs = &virtual_mail_vfuncs;
	mbox->vfuncs = virtual_mailbox_vfuncs;

	index_storage_mailbox_alloc(&mbox->box, vname, flags, MAIL_INDEX_PREFIX);

	mbox->storage = storage;
	mbox->virtual_ext_id = (uint32_t)-1;
	return &mbox->box;
}

static void virtual_mailbox_close_internal(struct virtual_mailbox *mbox)
{
	struct virtual_backend_box **bboxes;
	unsigned int i, count;

	bboxes = array_get_modifiable(&mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		if (bboxes[i]->search_result != NULL)
			mailbox_search_result_free(&bboxes[i]->search_result);

		if (bboxes[i]->box == NULL)
			continue;

		mail_search_args_deinit(bboxes[i]->search_args);
		mailbox_free(&bboxes[i]->box);
		if (array_is_created(&bboxes[i]->sync_outside_expunges))
			array_free(&bboxes[i]->sync_outside_expunges);
		array_free(&bboxes[i]->sync_pending_removes);
		array_free(&bboxes[i]->uids);
	}
}

static int
virtual_mailbox_exists(struct mailbox *box, bool auto_boxes ATTR_UNUSED,
		       enum mailbox_existence *existence_r)
{
	return index_storage_mailbox_exists_full(box, VIRTUAL_CONFIG_FNAME,
						 existence_r);
}

static int virtual_mailbox_open(struct mailbox *box)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;
	int ret = 0;

	if (virtual_mailbox_is_in_open_stack(mbox->storage, box->name)) {
		mail_storage_set_critical(box->storage,
			"Virtual mailbox loops: %s", box->name);
		return -1;
	}

	if (!array_is_created(&mbox->backend_boxes))
		ret = virtual_config_read(mbox);
	if (ret == 0) {
		array_append(&mbox->storage->open_stack, &box->name, 1);
		ret = virtual_mailboxes_open(mbox, box->flags);
		array_delete(&mbox->storage->open_stack,
			     array_count(&mbox->storage->open_stack)-1, 1);
	}
	if (ret < 0) {
		virtual_mailbox_close_internal(mbox);
		return -1;
	}
	if (index_storage_mailbox_open(box, FALSE) < 0)
		return -1;

	mbox->virtual_ext_id =
		mail_index_ext_register(mbox->box.index, "virtual", 0,
			sizeof(struct virtual_mail_index_record),
			sizeof(uint32_t));
	return 0;
}

static void virtual_mailbox_close(struct mailbox *box)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;

	virtual_mailbox_close_internal(mbox);
	index_storage_mailbox_close(box);
}

static void virtual_mailbox_free(struct mailbox *box)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;

	virtual_config_free(mbox);
	index_storage_mailbox_free(box);
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

static int
virtual_storage_get_status(struct mailbox *box,
			   enum mailbox_status_items items,
			   struct mailbox_status *status_r)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;

	if ((items & STATUS_LAST_CACHED_SEQ) != 0)
		items |= STATUS_MESSAGES;

	if (index_storage_get_status(box, items, status_r) < 0)
		return -1;

	if ((items & STATUS_LAST_CACHED_SEQ) != 0) {
		/* Virtual mailboxes have no cached data of their own, so the
		   current value is always 0. The most important use for this
		   functionality is for "doveadm index" to do FTS indexing and
		   it doesn't really matter there if we set this value
		   correctly or not. So for now just assume that everything is
		   indexed. */
		status_r->last_cached_seq = status_r->messages;
	}
	if (mbox->have_guids)
		status_r->have_guids = TRUE;
	if (mbox->have_save_guids)
		status_r->have_save_guids = TRUE;
	return 0;
}

static int
virtual_mailbox_get_metadata(struct mailbox *box,
			     enum mailbox_metadata_items items,
			     struct mailbox_metadata *metadata_r)
{
	if (index_mailbox_get_metadata(box, items, metadata_r) < 0)
		return -1;
	if ((items & MAILBOX_METADATA_GUID) != 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
				       "Virtual mailboxes have no GUIDs");
		return -1;
	}
	return 0;
}

static void
virtual_notify_callback(struct mailbox *bbox ATTR_UNUSED, struct mailbox *box)
{
	box->notify_callback(box, box->notify_context);
}

static void virtual_notify_changes(struct mailbox *box)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;
	struct virtual_backend_box *const *bboxes;
	unsigned int i, count;

	bboxes = array_get(&mbox->backend_boxes, &count);
	for (i = 0; i < count; i++) {
		struct mailbox *bbox = bboxes[i]->box;

		if (box->notify_callback == NULL)
			mailbox_notify_changes_stop(bbox);
		else
			mailbox_notify_changes(bbox, virtual_notify_callback, box);
	}
}

static void
virtual_get_virtual_uids(struct mailbox *box,
			 struct mailbox *backend_mailbox,
			 const ARRAY_TYPE(seq_range) *backend_uids,
			 ARRAY_TYPE(seq_range) *virtual_uids_r)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;
	struct virtual_backend_box *bbox;
	const struct virtual_backend_uidmap *uids;
	struct seq_range_iter iter;
	unsigned int n, i, count;
	uint32_t uid;

	if (mbox->lookup_prev_bbox != NULL &&
	    strcmp(mbox->lookup_prev_bbox->box->vname, backend_mailbox->vname) == 0)
		bbox = mbox->lookup_prev_bbox;
	else {
		bbox = virtual_backend_box_lookup_name(mbox, backend_mailbox->vname);
		mbox->lookup_prev_bbox = bbox;
	}
	if (bbox == NULL)
		return;

	uids = array_get(&bbox->uids, &count); i = 0;
	seq_range_array_iter_init(&iter, backend_uids); n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &uid)) {
		while (i < count && uids[i].real_uid < uid) i++;
		if (i < count && uids[i].real_uid == uid) {
			seq_range_array_add(virtual_uids_r, 
					    uids[i].virtual_uid);
			i++;
		}
	}
}

static void
virtual_get_virtual_uid_map(struct mailbox *box,
			    struct mailbox *backend_mailbox,
			    const ARRAY_TYPE(seq_range) *backend_uids,
			    ARRAY_TYPE(uint32_t) *virtual_uids_r)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;
	struct virtual_backend_box *bbox;
	const struct virtual_backend_uidmap *uids;
	struct seq_range_iter iter;
	unsigned int n, i, count;
	uint32_t uid;

	if (mbox->lookup_prev_bbox != NULL &&
	    strcmp(mbox->lookup_prev_bbox->box->vname, backend_mailbox->vname) == 0)
		bbox = mbox->lookup_prev_bbox;
	else {
		bbox = virtual_backend_box_lookup_name(mbox, backend_mailbox->vname);
		mbox->lookup_prev_bbox = bbox;
	}
	if (bbox == NULL)
		return;

	uids = array_get(&bbox->uids, &count); i = 0;
	seq_range_array_iter_init(&iter, backend_uids); n = 0;
	while (seq_range_array_iter_nth(&iter, n++, &uid)) {
		while (i < count && uids[i].real_uid < uid) i++;
		if (i == count || uids[i].real_uid > uid) {
			uint32_t zero = 0;

			array_append(virtual_uids_r, &zero, 1);
		} else {
			array_append(virtual_uids_r, &uids[i].virtual_uid, 1);
			i++;
		}
	}
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

static bool virtual_is_inconsistent(struct mailbox *box)
{
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)box;

	if (mbox->inconsistent)
		return TRUE;

	return index_storage_is_inconsistent(box);
}

struct mail_storage virtual_storage = {
	.name = VIRTUAL_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_NOQUOTA,

	.v = {
		NULL,
		virtual_storage_alloc,
		NULL,
		index_storage_destroy,
		NULL,
		virtual_storage_get_list_settings,
		NULL,
		virtual_mailbox_alloc,
		NULL
	}
};

struct mailbox virtual_mailbox = {
	.v = {
		index_storage_is_readonly,
		index_storage_mailbox_enable,
		virtual_mailbox_exists,
		virtual_mailbox_open,
		virtual_mailbox_close,
		virtual_mailbox_free,
		virtual_mailbox_create,
		virtual_mailbox_update,
		index_storage_mailbox_delete,
		index_storage_mailbox_rename,
		virtual_storage_get_status,
		virtual_mailbox_get_metadata,
		index_storage_set_subscribed,
		index_storage_attribute_set,
		index_storage_attribute_get,
		index_storage_attribute_iter_init,
		index_storage_attribute_iter_next,
		index_storage_attribute_iter_deinit,
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
		NULL,
		virtual_mail_alloc,
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
		NULL,
		NULL,
		NULL,
		virtual_is_inconsistent
	}
};

struct virtual_mailbox_vfuncs virtual_mailbox_vfuncs = {
	virtual_get_virtual_uids,
	virtual_get_virtual_uid_map,
	virtual_get_virtual_backend_boxes
};
