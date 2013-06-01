/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ioloop.h"
#include "str.h"
#include "mkdir-parents.h"
#include "dict.h"
#include "mail-index-alloc-cache.h"
#include "mail-index-private.h"
#include "mail-index-modseq.h"
#include "mailbox-log.h"
#include "mailbox-list-private.h"
#include "mail-search-build.h"
#include "index-storage.h"
#include "index-mail.h"
#include "index-attachment.h"
#include "index-thread-private.h"

#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define LOCK_NOTIFY_INTERVAL 30

struct index_storage_module index_storage_module =
	MODULE_CONTEXT_INIT(&mail_storage_module_register);

static void set_cache_decisions(struct mail_cache *cache,
				const char *set, const char *fields,
				enum mail_cache_decision_type dec)
{
	struct mail_cache_field field;
	const char *const *arr;
	unsigned int idx;

	if (fields == NULL || *fields == '\0')
		return;

	for (arr = t_strsplit_spaces(fields, " ,"); *arr != NULL; arr++) {
		const char *name = *arr;

		idx = mail_cache_register_lookup(cache, name);
		if (idx != UINT_MAX) {
			field = *mail_cache_register_get_field(cache, idx);
		} else if (strncasecmp(name, "hdr.", 4) == 0) {
			memset(&field, 0, sizeof(field));
			field.name = name;
			field.type = MAIL_CACHE_FIELD_HEADER;
		} else {
			i_error("%s: Unknown cache field name '%s', ignoring",
				set, *arr);
			continue;
		}

		field.decision = dec;
		mail_cache_register_fields(cache, &field, 1);
	}
}

static void index_cache_register_defaults(struct mailbox *box)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
	const struct mail_storage_settings *set = box->storage->set;
	struct mail_cache *cache = box->cache;

	ibox->cache_fields = i_malloc(sizeof(global_cache_fields));
	memcpy(ibox->cache_fields, global_cache_fields,
	       sizeof(global_cache_fields));
	mail_cache_register_fields(cache, ibox->cache_fields,
				   MAIL_INDEX_CACHE_FIELD_COUNT);
	set_cache_decisions(cache, "mail_cache_fields",
			    set->mail_cache_fields,
			    MAIL_CACHE_DECISION_TEMP);
	set_cache_decisions(cache, "mail_always_cache_fields",
			    set->mail_always_cache_fields,
			    MAIL_CACHE_DECISION_YES |
			    MAIL_CACHE_DECISION_FORCED);
	set_cache_decisions(cache, "mail_never_cache_fields",
			    set->mail_never_cache_fields,
			    MAIL_CACHE_DECISION_NO |
			    MAIL_CACHE_DECISION_FORCED);
}

void index_storage_lock_notify(struct mailbox *box,
			       enum mailbox_lock_notify_type notify_type,
			       unsigned int secs_left)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
	struct mail_storage *storage = box->storage;
	const char *str;
	time_t now;

	/* if notify type changes, print the message immediately */
	now = time(NULL);
	if (ibox->last_notify_type == MAILBOX_LOCK_NOTIFY_NONE ||
	    ibox->last_notify_type == notify_type) {
		if (ibox->last_notify_type == MAILBOX_LOCK_NOTIFY_NONE &&
		    notify_type == MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE) {
			/* first override notification, show it */
		} else {
			if (now < ibox->next_lock_notify || secs_left < 15)
				return;
		}
	}

	ibox->next_lock_notify = now + LOCK_NOTIFY_INTERVAL;
        ibox->last_notify_type = notify_type;

	switch (notify_type) {
	case MAILBOX_LOCK_NOTIFY_NONE:
		break;
	case MAILBOX_LOCK_NOTIFY_MAILBOX_ABORT:
		if (storage->callbacks.notify_no == NULL)
			break;

		str = t_strdup_printf("Mailbox is locked, will abort in "
				      "%u seconds", secs_left);
		storage->callbacks.
			notify_no(box, str, storage->callback_context);
		break;
	case MAILBOX_LOCK_NOTIFY_MAILBOX_OVERRIDE:
		if (storage->callbacks.notify_ok == NULL)
			break;

		str = t_strdup_printf("Stale mailbox lock file detected, "
				      "will override in %u seconds", secs_left);
		storage->callbacks.
			notify_ok(box, str, storage->callback_context);
		break;
	}
}

void index_storage_lock_notify_reset(struct mailbox *box)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);

	ibox->next_lock_notify = time(NULL) + LOCK_NOTIFY_INTERVAL;
	ibox->last_notify_type = MAILBOX_LOCK_NOTIFY_NONE;
}

static int
index_mailbox_alloc_index(struct mailbox *box, struct mail_index **index_r)
{
	const char *index_dir, *mailbox_path;

	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_MAILBOX,
				&mailbox_path) < 0)
		return -1;
	if ((box->flags & MAILBOX_FLAG_NO_INDEX_FILES) != 0 ||
	    mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX,
				&index_dir) <= 0)
		index_dir = NULL;
	*index_r = mail_index_alloc_cache_get(mailbox_path, index_dir,
					      box->index_prefix);
	return 0;
}

int index_storage_mailbox_exists(struct mailbox *box,
				 bool auto_boxes ATTR_UNUSED,
				 enum mailbox_existence *existence_r)
{
	return index_storage_mailbox_exists_full(box, NULL, existence_r);
}

int index_storage_mailbox_exists_full(struct mailbox *box, const char *subdir,
				      enum mailbox_existence *existence_r)
{
	struct stat st;
	enum mail_error error;
	const char *path, *path2;
	int ret;

	/* see if it's selectable */
	ret = mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_MAILBOX, &path);
	if (ret < 0) {
		mailbox_list_get_last_error(box->list, &error);
		if (error != MAIL_ERROR_NOTFOUND)
			return -1;
		*existence_r = MAILBOX_EXISTENCE_NONE;
		return 0;
	}
	if (ret == 0) {
		/* no mailboxes in this storage? */
		*existence_r = MAILBOX_EXISTENCE_NONE;
		return 0;
	}
	if (subdir != NULL)
		path = t_strconcat(path, "/", subdir, NULL);
	if (stat(path, &st) == 0) {
		*existence_r = MAILBOX_EXISTENCE_SELECT;
		return 0;
	}
	if (!ENOTFOUND(errno) && errno != EACCES) {
		mail_storage_set_critical(box->storage,
					  "stat(%s) failed: %m", path);
		return -1;
	}

	/* see if it's non-selectable */
	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_DIR, &path2) <= 0 ||
	    (strcmp(path, path2) != 0 && stat(path2, &st) == 0)) {
		*existence_r = MAILBOX_EXISTENCE_NOSELECT;
		return 0;
	}
	*existence_r = MAILBOX_EXISTENCE_NONE;
	return 0;
}

int index_storage_mailbox_alloc_index(struct mailbox *box)
{
	if (box->index != NULL)
		return 0;

	if (mailbox_create_missing_dir(box, MAILBOX_LIST_PATH_TYPE_INDEX) < 0)
		return -1;

	if (index_mailbox_alloc_index(box, &box->index) < 0)
		return -1;
	mail_index_set_fsync_mode(box->index,
				  box->storage->set->parsed_fsync_mode, 0);
	mail_index_set_lock_method(box->index,
		box->storage->set->parsed_lock_method,
		mail_storage_get_lock_timeout(box->storage, UINT_MAX));
	return 0;
}

int index_storage_mailbox_open(struct mailbox *box, bool move_to_memory)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
	enum mail_index_open_flags index_flags;
	int ret;

	i_assert(!box->opened);

	index_flags = ibox->index_flags;
	if (move_to_memory)
		ibox->index_flags &= ~MAIL_INDEX_OPEN_FLAG_CREATE;

	if (index_storage_mailbox_alloc_index(box) < 0)
		return -1;

	/* make sure mail_index_set_permissions() has been called */
	(void)mailbox_get_permissions(box);

	ret = mail_index_open(box->index, index_flags);
	if (ret <= 0 || move_to_memory) {
		if ((index_flags & MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY) != 0) {
			i_assert(ret <= 0);
			mailbox_set_index_error(box);
			return -1;
		}

		if (mail_index_move_to_memory(box->index) < 0) {
			/* try opening once more. it should be created
			   directly into memory now. */
			if (mail_index_open_or_create(box->index,
						      index_flags) < 0)
				i_panic("in-memory index creation failed");
		}
	}
	if ((index_flags & MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY) != 0) {
		if (mail_index_is_in_memory(box->index)) {
			mail_storage_set_critical(box->storage,
				"Couldn't create index file");
			mail_index_close(box->index);
			return -1;
		}
	}

	if ((box->flags & MAILBOX_FLAG_OPEN_DELETED) == 0) {
		if (mail_index_is_deleted(box->index)) {
			mailbox_set_deleted(box);
			mail_index_close(box->index);
			return -1;
		}
	}

	box->cache = mail_index_get_cache(box->index);
	index_cache_register_defaults(box);
	box->view = mail_index_view_open(box->index);
	ibox->keyword_names = mail_index_get_keywords(box->index);
	ibox->vsize_hdr_ext_id =
		mail_index_ext_register(box->index, "hdr-vsize",
					sizeof(struct index_vsize_header), 0,
					sizeof(uint64_t));

	box->opened = TRUE;

	if ((box->enabled_features & MAILBOX_FEATURE_CONDSTORE) != 0)
		mail_index_modseq_enable(box->index);

	index_thread_mailbox_opened(box);
	hook_mailbox_opened(box);
	return 0;
}

void index_storage_mailbox_alloc(struct mailbox *box, const char *vname,
				 enum mailbox_flags flags,
				 const char *index_prefix)
{
	static unsigned int mailbox_generation_sequence = 0;
	struct index_mailbox_context *ibox;

	i_assert(vname != NULL);

	box->generation_sequence = ++mailbox_generation_sequence;
	box->vname = p_strdup(box->pool, vname);
	box->name = p_strdup(box->pool,
			     mailbox_list_get_storage_name(box->list, vname));
	box->flags = flags;
	box->index_prefix = p_strdup(box->pool, index_prefix);

	p_array_init(&box->search_results, box->pool, 16);
	array_create(&box->module_contexts,
		     box->pool, sizeof(void *), 5);

	ibox = p_new(box->pool, struct index_mailbox_context, 1);
	ibox->list_index_sync_ext_id = (uint32_t)-1;
	ibox->index_flags = MAIL_INDEX_OPEN_FLAG_CREATE |
		mail_storage_settings_to_index_flags(box->storage->set);
	if ((box->flags & MAILBOX_FLAG_SAVEONLY) != 0)
		ibox->index_flags |= MAIL_INDEX_OPEN_FLAG_SAVEONLY;
	ibox->next_lock_notify = time(NULL) + LOCK_NOTIFY_INTERVAL;
	MODULE_CONTEXT_SET(box, index_storage_module, ibox);

	box->inbox_user = strcmp(box->name, "INBOX") == 0 &&
		(box->list->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0;
	box->inbox_any = strcmp(box->name, "INBOX") == 0 &&
		(box->list->ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0;
}

int index_storage_mailbox_enable(struct mailbox *box,
				 enum mailbox_feature feature)
{
	if ((feature & MAILBOX_FEATURE_CONDSTORE) != 0) {
		box->enabled_features |= MAILBOX_FEATURE_CONDSTORE;
		if (box->opened)
			mail_index_modseq_enable(box->index);
	}
	return 0;
}

void index_storage_mailbox_close(struct mailbox *box)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);

	index_mailbox_check_remove_all(box);
	if (box->input != NULL)
		i_stream_unref(&box->input);

	if (box->view_pvt != NULL)
		mail_index_view_close(&box->view_pvt);
	if (box->index_pvt != NULL)
		mail_index_close(box->index_pvt);
	mail_index_view_close(&box->view);
	mail_index_close(box->index);
	box->cache = NULL;

	ibox->keyword_names = NULL;
	i_free_and_null(ibox->cache_fields);

	if (array_is_created(&ibox->recent_flags))
		array_free(&ibox->recent_flags);
	ibox->recent_flags_prev_uid = 0;
	ibox->recent_flags_count = 0;

	ibox->sync_last_check = 0;
}

void index_storage_mailbox_free(struct mailbox *box)
{
	if (box->index_pvt != NULL)
		mail_index_alloc_cache_unref(&box->index_pvt);
	if (box->index != NULL)
		mail_index_alloc_cache_unref(&box->index);
}

static void
index_storage_mailbox_update_cache(struct mailbox *box,
				   const struct mailbox_update *update)
{
	const struct mailbox_cache_field *updates = update->cache_updates;
	ARRAY(struct mail_cache_field) new_fields;
	const struct mail_cache_field *old_fields;
	struct mail_cache_field field;
	unsigned int i, j, old_count;

	old_fields = mail_cache_register_get_list(box->cache,
						  pool_datastack_create(),
						  &old_count);

	/* There shouldn't be many fields, so don't worry about O(n^2). */
	t_array_init(&new_fields, 32);
	for (i = 0; updates[i].name != NULL; i++) {
		/* see if it's an existing field */
		for (j = 0; j < old_count; j++) {
			if (strcmp(updates[i].name, old_fields[j].name) == 0)
				break;
		}
		if (j != old_count) {
			field = old_fields[j];
		} else if (strncmp(updates[i].name, "hdr.", 4) == 0) {
			/* new header */
			memset(&field, 0, sizeof(field));
			field.name = updates[i].name;
			field.type = MAIL_CACHE_FIELD_HEADER;
		} else {
			/* new unknown field. we can't do anything about
			   this since we don't know its type */
			continue;
		}
		field.decision = updates[i].decision;
		if (updates[i].last_used != (time_t)-1)
			field.last_used = updates[i].last_used;
		array_append(&new_fields, &field, 1);
	}
	if (array_count(&new_fields) > 0) {
		mail_cache_register_fields(box->cache,
					   array_idx_modifiable(&new_fields, 0),
					   array_count(&new_fields));
	}
}

static int
index_storage_mailbox_update_pvt(struct mailbox *box,
				 const struct mailbox_update *update)
{
	struct mail_index_transaction *trans;
	struct mail_index_view *view;
	int ret;

	if ((ret = mailbox_open_index_pvt(box)) <= 0)
		return ret;

	mail_index_refresh(box->index_pvt);
	view = mail_index_view_open(box->index_pvt);
	trans = mail_index_transaction_begin(view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	if (update->min_highest_modseq != 0 &&
	    mail_index_modseq_get_highest(view) < update->min_highest_pvt_modseq) {
		mail_index_modseq_enable(box->index_pvt);
		mail_index_update_highest_modseq(trans,
						 update->min_highest_pvt_modseq);
	}

	if ((ret = mail_index_transaction_commit(&trans)) < 0)
		mailbox_set_index_error(box);
	mail_index_view_close(&view);
	return ret;
}

int index_storage_mailbox_update_common(struct mailbox *box,
					const struct mailbox_update *update)
{
	int ret = 0;

	if (update->cache_updates != NULL)
		index_storage_mailbox_update_cache(box, update);

	if (update->min_highest_pvt_modseq != 0) {
		if (index_storage_mailbox_update_pvt(box, update) < 0)
			ret = -1;
	}
	return ret;
}

int index_storage_mailbox_update(struct mailbox *box,
				 const struct mailbox_update *update)
{
	const struct mail_index_header *hdr;
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	int ret;

	if (mailbox_open(box) < 0)
		return -1;

	/* make sure we get the latest index info */
	mail_index_refresh(box->index);
	view = mail_index_view_open(box->index);
	hdr = mail_index_get_header(view);

	trans = mail_index_transaction_begin(view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	if (update->uid_validity != 0 &&
	    hdr->uid_validity != update->uid_validity) {
		uint32_t uid_validity = update->uid_validity;

		if (hdr->uid_validity != 0) {
			/* UIDVALIDITY change requires index to be reset */
			mail_index_reset(trans);
		}
		mail_index_update_header(trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}
	if (update->min_next_uid != 0 &&
	    hdr->next_uid < update->min_next_uid) {
		uint32_t next_uid = update->min_next_uid;

		mail_index_update_header(trans,
			offsetof(struct mail_index_header, next_uid),
			&next_uid, sizeof(next_uid), FALSE);
	}
	if (update->min_first_recent_uid != 0 &&
	    hdr->first_recent_uid < update->min_first_recent_uid) {
		uint32_t first_recent_uid = update->min_first_recent_uid;

		mail_index_update_header(trans,
			offsetof(struct mail_index_header, first_recent_uid),
			&first_recent_uid, sizeof(first_recent_uid), FALSE);
	}
	if (update->min_highest_modseq != 0 &&
	    mail_index_modseq_get_highest(view) < update->min_highest_modseq) {
		mail_index_modseq_enable(box->index);
		mail_index_update_highest_modseq(trans,
						 update->min_highest_modseq);
	}

	if ((ret = mail_index_transaction_commit(&trans)) < 0)
		mailbox_set_index_error(box);
	mail_index_view_close(&view);
	return ret < 0 ? -1 :
		index_storage_mailbox_update_common(box, update);
}

int index_storage_mailbox_create(struct mailbox *box, bool directory)
{
	const char *path, *p;
	enum mailbox_list_path_type type;
	enum mailbox_existence existence;
	bool create_parent_dir;
	int ret;

	type = directory ? MAILBOX_LIST_PATH_TYPE_DIR :
		MAILBOX_LIST_PATH_TYPE_MAILBOX;
	if ((ret = mailbox_get_path_to(box, type, &path)) < 0)
		return -1;
	if (ret == 0) {
		/* layout=none */
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
				       "Mailbox creation not supported");
		return -1;
	}
	create_parent_dir = !directory &&
		(box->list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) != 0;
	if (create_parent_dir) {
		/* we only need to make sure that the parent directory exists */
		p = strrchr(path, '/');
		if (p == NULL)
			return 1;
		path = t_strdup_until(path, p);
	}

	if ((ret = mailbox_mkdir(box, path, type)) < 0)
		return -1;
	mailbox_refresh_permissions(box);
	if (ret == 0) {
		/* directory already exists */
		if (create_parent_dir)
			return 1;
		if (!directory && *box->list->set.mailbox_dir_name == '\0') {
			/* For example: layout=fs, path=~/Maildir/foo
			   might itself exist, but does it have the
			   cur|new|tmp subdirs? */
			if (mailbox_exists(box, FALSE, &existence) < 0)
				return -1;
			if (existence != MAILBOX_EXISTENCE_SELECT)
				return 1;
		}
		mail_storage_set_error(box->storage, MAIL_ERROR_EXISTS,
				       "Mailbox already exists");
		return -1;
	}

	if (directory &&
	    (box->list->props & MAILBOX_LIST_PROP_NO_NOSELECT) == 0) {
		/* we only wanted to create the directory and it's done now */
		return 0;
	}
	/* the caller should still create the mailbox */
	return 1;
}

int index_storage_mailbox_delete_dir(struct mailbox *box, bool mailbox_deleted)
{
	guid_128_t dir_sha128;
	enum mail_error error;

	if (mailbox_list_delete_dir(box->list, box->name) == 0)
		return 0;

	mailbox_list_get_last_error(box->list, &error);
	if (error != MAIL_ERROR_NOTFOUND || !mailbox_deleted) {
		mail_storage_copy_list_error(box->storage, box->list);
		return -1;
	}
	/* failed directory deletion, but mailbox deletion succeeded.
	   this was probably maildir++, which internally deleted the
	   directory as well. add changelog record about that too. */
	mailbox_name_get_sha128(box->vname, dir_sha128);
	mailbox_list_add_change(box->list, MAILBOX_LOG_RECORD_DELETE_DIR,
				dir_sha128);
	return 0;
}

static int
mailbox_delete_all_attributes(struct mailbox_transaction_context *t,
			      enum mail_attribute_type type)
{
	struct mailbox_attribute_iter *iter;
	const char *key;
	int ret = 0;

	iter = mailbox_attribute_iter_init(t->box, type, "");
	while ((key = mailbox_attribute_iter_next(iter)) != NULL) {
		if (mailbox_attribute_unset(t, type, key) < 0)
			ret = -1;
	}
	if (mailbox_attribute_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

static int mailbox_expunge_all_data(struct mailbox *box)
{
	struct mail_search_context *ctx;
        struct mailbox_transaction_context *t;
	struct mail *mail;
	struct mail_search_args *search_args;

	(void)mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ);

	t = mailbox_transaction_begin(box, 0);

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	ctx = mailbox_search_init(t, search_args, NULL, 0, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(ctx, &mail))
		mail_expunge(mail);

	if (mailbox_search_deinit(&ctx) < 0) {
		mailbox_transaction_rollback(&t);
		return -1;
	}

	if (mailbox_delete_all_attributes(t, MAIL_ATTRIBUTE_TYPE_PRIVATE) < 0 ||
	    mailbox_delete_all_attributes(t, MAIL_ATTRIBUTE_TYPE_SHARED) < 0) {
		mailbox_transaction_rollback(&t);
		return -1;
	}
	return mailbox_transaction_commit(&t);
}

int index_storage_mailbox_delete(struct mailbox *box)
{
	struct mailbox_metadata metadata;
	struct mailbox_status status;
	int ret_guid;

	if (!box->opened) {
		/* \noselect mailbox, try deleting only the directory */
		return index_storage_mailbox_delete_dir(box, FALSE);
	}

	if ((box->list->flags & MAILBOX_LIST_FLAG_MAILBOX_FILES) == 0) {
		/* specifically support symlinked shared mailboxes. a deletion
		   will simply remove the symlink, not actually expunge any
		   mails */
		if (mailbox_list_delete_symlink(box->list, box->name) == 0)
			return 0;
	}

	/* we can't easily atomically delete all mails and the mailbox. so:
	   1) expunge all mails
	   2) mark the mailbox deleted (modifications after this will fail)
	   3) check if a race condition between 1) and 2) added any mails:
	     yes) abort and undelete mailbox
	     no) finish deleting the mailbox
	*/

	if (!box->deleting_must_be_empty) {
		if (mailbox_expunge_all_data(box) < 0)
			return -1;
	}
	if (mailbox_mark_index_deleted(box, TRUE) < 0)
		return -1;

	if (!box->delete_skip_empty_check || box->deleting_must_be_empty) {
		if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0)
			return -1;
		mailbox_get_open_status(box, STATUS_MESSAGES, &status);
		if (status.messages != 0) {
			mail_storage_set_error(box->storage, MAIL_ERROR_EXISTS,
				"New mails were added to mailbox during deletion");
			return -1;
		}
	}

	ret_guid = mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata);

	/* Make sure the indexes are closed before trying to delete the
	   directory that contains them. It can still fail with some NFS
	   implementations if indexes are opened by another session, but
	   that can't really be helped. */
	mailbox_close(box);
	mail_index_alloc_cache_destroy_unrefed();

	if (box->list->v.delete_mailbox(box->list, box->name) < 0) {
		mail_storage_copy_list_error(box->storage, box->list);
		return -1;
	} 

	if (ret_guid == 0) {
		mailbox_list_add_change(box->list,
					MAILBOX_LOG_RECORD_DELETE_MAILBOX,
					metadata.guid);
	}
	if (index_storage_mailbox_delete_dir(box, TRUE) < 0) {
		if (mailbox_get_last_mail_error(box) != MAIL_ERROR_EXISTS)
			return -1;
		/* we deleted the mailbox, but couldn't delete the directory
		   because it has children. that's not an error. */
	}
	return 0;
}

int index_storage_mailbox_rename(struct mailbox *src, struct mailbox *dest)
{
	guid_128_t guid;

	if (src->list->v.rename_mailbox(src->list, src->name,
					dest->list, dest->name) < 0) {
		mail_storage_copy_list_error(src->storage, src->list);
		return -1;
	}

	/* we'll track mailbox names, instead of GUIDs. We may be renaming a
	   non-selectable mailbox (directory), which doesn't even have a GUID */
	mailbox_name_get_sha128(dest->vname, guid);
	mailbox_list_add_change(src->list, MAILBOX_LOG_RECORD_RENAME, guid);
	return 0;
}

bool index_storage_is_readonly(struct mailbox *box)
{
	return (box->flags & MAILBOX_FLAG_READONLY) != 0;
}

bool index_storage_is_inconsistent(struct mailbox *box)
{
	return mail_index_view_is_inconsistent(box->view);
}

void index_save_context_free(struct mail_save_context *ctx)
{
	index_mail_save_finish(ctx);
	i_free_and_null(ctx->data.from_envelope);
	i_free_and_null(ctx->data.guid);
	i_free_and_null(ctx->data.pop3_uidl);
	index_attachment_save_free(ctx);
	memset(&ctx->data, 0, sizeof(ctx->data));

	ctx->unfinished = FALSE;
}

static void
mail_copy_cache_field(struct mail_save_context *ctx, struct mail *src_mail,
		      uint32_t dest_seq, const char *name, buffer_t *buf)
{
	struct mailbox_transaction_context *dest_trans = ctx->transaction;
	const struct mail_cache_field *dest_field;
	unsigned int src_field_idx, dest_field_idx;
	uint32_t t;

	src_field_idx = mail_cache_register_lookup(src_mail->box->cache, name);
	i_assert(src_field_idx != UINT_MAX);

	dest_field_idx = mail_cache_register_lookup(dest_trans->box->cache, name);
	if (dest_field_idx == UINT_MAX) {
		/* unknown field */
		return;
	}
	dest_field = mail_cache_register_get_field(dest_trans->box->cache,
						   dest_field_idx);
	if ((dest_field->decision &
	     ~MAIL_CACHE_DECISION_FORCED) == MAIL_CACHE_DECISION_NO) {
		/* field not wanted in destination mailbox */
		return;
	}

	buffer_set_used_size(buf, 0);
	if (strcmp(name, "date.save") == 0) {
		/* save date must update when mail is copied */
		t = ioloop_time;
		buffer_append(buf, &t, sizeof(t));
	} else {
		if (mail_cache_lookup_field(src_mail->transaction->cache_view, buf,
					    src_mail->seq, src_field_idx) <= 0)
			buffer_set_used_size(buf, 0);
		else if (ctx->dest_mail != NULL &&
			 (strcmp(name, "size.physical") == 0 ||
			  strcmp(name, "size.virtual") == 0)) {
			/* FIXME: until mail_cache_lookup() can read unwritten
			   cached data from buffer, we'll do this optimization
			   to make quota plugin's work faster */
			struct index_mail *imail =
				(struct index_mail *)ctx->dest_mail;
			uoff_t size;

			i_assert(buf->used == sizeof(size));
			memcpy(&size, buf->data, sizeof(size));
			if (strcmp(name, "size.physical") == 0)
				imail->data.physical_size = size;
			else
				imail->data.virtual_size = size;
		}
	}
	if (buf->used > 0) {
		mail_cache_add(dest_trans->cache_trans, dest_seq,
			       dest_field_idx, buf->data, buf->used);
	}
}

void index_copy_cache_fields(struct mail_save_context *ctx,
			     struct mail *src_mail, uint32_t dest_seq)
{
	T_BEGIN {
		struct mailbox_metadata src_metadata, dest_metadata;
		const struct mailbox_cache_field *field;
		buffer_t *buf;

		if (mailbox_get_metadata(src_mail->box,
					 MAILBOX_METADATA_CACHE_FIELDS,
					 &src_metadata) < 0)
			i_unreached();
		/* the only reason we're doing the destination lookup is to
		   make sure that the cache file is opened and the cache
		   decisinos are up to date */
		if (mailbox_get_metadata(ctx->transaction->box,
					 MAILBOX_METADATA_CACHE_FIELDS,
					 &dest_metadata) < 0)
			i_unreached();

		buf = buffer_create_dynamic(pool_datastack_create(), 1024);
		array_foreach(src_metadata.cache_fields, field) {
			mail_copy_cache_field(ctx, src_mail, dest_seq,
					      field->name, buf);
		}
	} T_END;
}

int index_storage_set_subscribed(struct mailbox *box, bool set)
{
	struct mail_namespace *ns;
	struct mailbox_list *list = box->list;
	const char *subs_name;
	guid_128_t guid;

	if ((list->ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) != 0)
		subs_name = box->name;
	else {
		/* subscriptions=no namespace, find another one where we can
		   add the subscription to */
		ns = mail_namespace_find_subscribable(list->ns->user->namespaces,
						      box->vname);
		if (ns == NULL) {
			mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
				"This namespace has no subscriptions");
			return -1;
		}
		/* use <orig ns prefix><orig storage name> as the
		   subscription name */
		subs_name = t_strconcat(list->ns->prefix, box->name, NULL);
		/* drop the common prefix (typically there isn't one) */
		i_assert(strncmp(ns->prefix, subs_name, strlen(ns->prefix)) == 0);
		subs_name += strlen(ns->prefix);

		list = ns->list;
	}
	if (mailbox_list_set_subscribed(list, subs_name, set) < 0) {
		mail_storage_copy_list_error(box->storage, list);
		return -1;
	}

	/* subscriptions are about names, not about mailboxes. it's possible
	   to have a subscription to nonexistent mailbox. renames also don't
	   change subscriptions. so instead of using actual GUIDs, we'll use
	   hash of the name. */
	mailbox_name_get_sha128(box->vname, guid);
	mailbox_list_add_change(list, set ? MAILBOX_LOG_RECORD_SUBSCRIBE :
				MAILBOX_LOG_RECORD_UNSUBSCRIBE, guid);
	return 0;
}

void index_storage_destroy(struct mail_storage *storage)
{
	if (storage->_shared_attr_dict != NULL) {
		(void)dict_wait(storage->_shared_attr_dict);
		dict_deinit(&storage->_shared_attr_dict);
	}
}
