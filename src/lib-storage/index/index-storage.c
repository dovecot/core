/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
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
#include "index-mailbox-size.h"

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
			i_zero(&field);
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

	if (strcmp(set->mail_never_cache_fields, "*") == 0) {
		/* all caching disabled for now */
		box->mail_cache_disabled = TRUE;
		return;
	}

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
	*index_r = mail_index_alloc_cache_get(box->storage->event,
					      mailbox_path, index_dir,
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
	const char *path, *path2, *index_path;
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

	ret = (subdir != NULL || !box->list->set.iter_from_index_dir) ? 0 :
		mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX, &index_path);
	if (ret > 0 && strcmp(path, index_path) != 0) {
		/* index directory is different - prefer looking it up first
		   since it might be on a faster storage. since the directory
		   itself exists also for \NoSelect mailboxes, we'll need to
		   check the dovecot.index.log existence. */
		index_path = t_strconcat(index_path, "/", box->index_prefix,
					 ".log", NULL);
		if (stat(index_path, &st) == 0) {
			*existence_r = MAILBOX_EXISTENCE_SELECT;
			return 0;
		}
	}

	if (subdir != NULL)
		path = t_strconcat(path, "/", subdir, NULL);
	if (stat(path, &st) == 0) {
		*existence_r = MAILBOX_EXISTENCE_SELECT;
		return 0;
	}
	if (!ENOTFOUND(errno) && errno != EACCES) {
		mailbox_set_critical(box, "stat(%s) failed: %m", path);
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
	const char *cache_dir;

	if (box->index != NULL)
		return 0;

	if (mailbox_create_missing_dir(box, MAILBOX_LIST_PATH_TYPE_INDEX) < 0)
		return -1;
	if (index_mailbox_alloc_index(box, &box->index) < 0)
		return -1;

	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX_CACHE,
				&cache_dir) > 0) {
		if (mailbox_create_missing_dir(box, MAILBOX_LIST_PATH_TYPE_INDEX_CACHE) < 0)
			return -1;
		mail_index_set_cache_dir(box->index, cache_dir);
	}
	mail_index_set_fsync_mode(box->index,
				  box->storage->set->parsed_fsync_mode, 0);
	mail_index_set_lock_method(box->index,
		box->storage->set->parsed_lock_method,
		mail_storage_get_lock_timeout(box->storage, UINT_MAX));

	const struct mail_storage_settings *set = box->storage->set;
	struct mail_index_optimization_settings optimization_set = {
		.index = {
			.rewrite_min_log_bytes = set->mail_index_rewrite_min_log_bytes,
			.rewrite_max_log_bytes = set->mail_index_rewrite_max_log_bytes,
		},
		.log = {
			.min_size = set->mail_index_log_rotate_min_size,
			.max_size = set->mail_index_log_rotate_max_size,
			.min_age_secs = set->mail_index_log_rotate_min_age,
			.log2_max_age_secs = set->mail_index_log2_max_age,
		},
		.cache = {
			.unaccessed_field_drop_secs = set->mail_cache_unaccessed_field_drop,
			.record_max_size = set->mail_cache_record_max_size,
			.compress_min_size = set->mail_cache_compress_min_size,
			.compress_delete_percentage = set->mail_cache_compress_delete_percentage,
			.compress_continued_percentage = set->mail_cache_compress_continued_percentage,
			.compress_header_continue_count = set->mail_cache_compress_header_continue_count,
		},
	};
	mail_index_set_optimization_settings(box->index, &optimization_set);
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
		index_flags &= ~MAIL_INDEX_OPEN_FLAG_CREATE;

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
			mailbox_set_critical(box,
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
	if ((box->flags & MAILBOX_FLAG_FSCK) != 0) {
		if (mail_index_fsck(box->index) < 0) {
			mailbox_set_index_error(box);
			return -1;
		}
	}

	box->cache = mail_index_get_cache(box->index);
	index_cache_register_defaults(box);
	box->view = mail_index_view_open(box->index);
	ibox->keyword_names = mail_index_get_keywords(box->index);
	box->vsize_hdr_ext_id =
		mail_index_ext_register(box->index, "hdr-vsize",
					sizeof(struct mailbox_index_vsize), 0,
					sizeof(uint64_t));
	box->pop3_uidl_hdr_ext_id =
		mail_index_ext_register(box->index, "hdr-pop3-uidl",
					sizeof(struct mailbox_index_pop3_uidl), 0, 0);
	box->box_name_hdr_ext_id =
		mail_index_ext_register(box->index, "box-name", 0, 0, 0);

	box->box_last_rename_stamp_ext_id =
		mail_index_ext_register(box->index, "last-rename-stamp",
					sizeof(uint32_t), 0, sizeof(uint32_t));
	box->mail_vsize_ext_id = mail_index_ext_register(box->index, "vsize", 0,
							 sizeof(uint32_t),
							 sizeof(uint32_t));

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
	box->event = event_create(box->storage->event);
	event_add_category(box->event, &event_category_mailbox);
	event_add_str(box->event, "name", box->vname);
	event_set_append_log_prefix(box->event,
		t_strdup_printf("Mailbox %s: ", box->vname));

	p_array_init(&box->search_results, box->pool, 16);
	array_create(&box->module_contexts,
		     box->pool, sizeof(void *), 5);

	ibox = p_new(box->pool, struct index_mailbox_context, 1);
	ibox->list_index_sync_ext_id = (uint32_t)-1;
	ibox->index_flags = MAIL_INDEX_OPEN_FLAG_CREATE |
		mail_storage_settings_to_index_flags(box->storage->set);
	if ((box->flags & MAILBOX_FLAG_SAVEONLY) != 0)
		ibox->index_flags |= MAIL_INDEX_OPEN_FLAG_SAVEONLY;
	if (event_want_debug(box->event))
		ibox->index_flags |= MAIL_INDEX_OPEN_FLAG_DEBUG;
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

	mailbox_watch_remove_all(box);
	i_stream_unref(&box->input);

	if (box->view_pvt != NULL)
		mail_index_view_close(&box->view_pvt);
	if (box->index_pvt != NULL)
		mail_index_close(box->index_pvt);
	if (box->view != NULL) {
		mail_index_view_close(&box->view);
		mail_index_close(box->index);
	}
	box->cache = NULL;

	ibox->keyword_names = NULL;
	i_free_and_null(ibox->cache_fields);

	ibox->sync_last_check = 0;
}

static void index_storage_mailbox_unref_indexes(struct mailbox *box)
{
	if (box->index_pvt != NULL)
		mail_index_alloc_cache_unref(&box->index_pvt);
	if (box->index != NULL)
		mail_index_alloc_cache_unref(&box->index);
}

void index_storage_mailbox_free(struct mailbox *box)
{
	index_storage_mailbox_unref_indexes(box);
	event_unref(&box->event);
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
		} else if (str_begins(updates[i].name, "hdr.")) {
			/* new header */
			i_zero(&field);
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
		array_push_back(&new_fields, &field);
	}
	if (array_count(&new_fields) > 0) {
		mail_cache_register_fields(box->cache,
					   array_front_modifiable(&new_fields),
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

	if ((box->list->props & MAILBOX_LIST_PROP_NO_NOSELECT) != 0) {
		/* Layout doesn't support creating \NoSelect mailboxes.
		   Switch to creating a selectable mailbox. */
		directory = FALSE;
	}

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
	if (box->list->set.iter_from_index_dir) {
		/* need to also create the directory to index path or
		   iteration won't find it. */
		int ret2;

		if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX, &path) <= 0)
			i_unreached();
		if ((ret2 = mailbox_mkdir(box, path, type)) < 0)
			return -1;
		if (ret == 0 && ret2 > 0) {
			/* finish partial creation: existed in mail directory,
			   but not in index directory. */
			ret = 1;
		}
	}
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

	if (directory) {
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
	bool inbox = t->box->inbox_any;

	iter = mailbox_attribute_iter_init(t->box, type, "");
	while ((key = mailbox_attribute_iter_next(iter)) != NULL) {
		if (inbox &&
		    str_begins(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER))
			continue;

		if (mailbox_attribute_unset(t, type, key) < 0) {
			if (mailbox_get_last_mail_error(t->box) != MAIL_ERROR_NOTPOSSIBLE) {
				ret = -1;
				break;
			}
		}
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

	t = mailbox_transaction_begin(box, 0, __func__);

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
	if (mailbox_transaction_commit(&t) < 0)
		return -1;
	/* sync to actually perform the expunges */
	return mailbox_sync(box, 0);
}

int index_storage_mailbox_delete_pre(struct mailbox *box)
{
	struct mailbox_status status;

	if (!box->opened) {
		/* \noselect mailbox, try deleting only the directory */
		if (index_storage_mailbox_delete_dir(box, FALSE) == 0)
			return 0;
		if (mailbox_is_autocreated(box)) {
			/* Return success when trying to delete autocreated
			   mailbox. The client sees it as existing, so we
			   shouldn't be returning an error. */
			return 0;
		}
		return -1;
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
		if (status.messages == 0)
			;
		else if (box->deleting_must_be_empty) {
			mail_storage_set_error(box->storage, MAIL_ERROR_EXISTS,
					       "Mailbox isn't empty");
			return -1;
		} else {
			mail_storage_set_error(box->storage, MAIL_ERROR_EXISTS,
				"New mails were added to mailbox during deletion");
			return -1;
		}
	}
	return 1;
}

int index_storage_mailbox_delete_post(struct mailbox *box)
{
	struct mailbox_metadata metadata;
	int ret_guid;

	ret_guid = mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata);

	/* Make sure the indexes are closed before trying to delete the
	   directory that contains them. It can still fail with some NFS
	   implementations if indexes are opened by another session, but
	   that can't really be helped. */
	mailbox_close(box);
	index_storage_mailbox_unref_indexes(box);
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

int index_storage_mailbox_delete(struct mailbox *box)
{
	int ret;

	if ((ret = index_storage_mailbox_delete_pre(box)) <= 0)
		return ret;
	/* mails have been now successfully deleted. some mailbox formats may
	   at this point do some other deletion that is required for it.
	   the _post() deletion will close the index and delete the
	   directory. */
	return index_storage_mailbox_delete_post(box);
}

int index_storage_mailbox_rename(struct mailbox *src, struct mailbox *dest)
{
	guid_128_t guid;

	if (src->list->v.rename_mailbox(src->list, src->name,
					dest->list, dest->name) < 0) {
		mail_storage_copy_list_error(src->storage, src->list);
		return -1;
	}

	if (mailbox_open(dest) == 0) {
		struct mail_index_transaction *t =
			mail_index_transaction_begin(dest->view, 0);

		uint32_t stamp = ioloop_time;

		mail_index_update_header_ext(t, dest->box_last_rename_stamp_ext_id,
					     0, &stamp, sizeof(stamp));

		/* can't do much if this fails anyways */
		(void)mail_index_transaction_commit(&t);
	}

	/* we'll track mailbox names, instead of GUIDs. We may be renaming a
	   non-selectable mailbox (directory), which doesn't even have a GUID */
	mailbox_name_get_sha128(dest->vname, guid);
	mailbox_list_add_change(src->list, MAILBOX_LOG_RECORD_RENAME, guid);
	return 0;
}

int index_mailbox_update_last_temp_file_scan(struct mailbox *box)
{
	uint32_t last_temp_file_scan = ioloop_time;
	struct mail_index_transaction *trans =
		mail_index_transaction_begin(box->view,
			MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	mail_index_update_header(trans,
		offsetof(struct mail_index_header, last_temp_file_scan),
		&last_temp_file_scan, sizeof(last_temp_file_scan), TRUE);
	if (mail_index_transaction_commit(&trans) < 0) {
		mailbox_set_index_error(box);
		return -1;
	}
	return 0;
}

bool index_storage_is_readonly(struct mailbox *box)
{
	return (box->flags & MAILBOX_FLAG_READONLY) != 0;
}

bool index_storage_is_inconsistent(struct mailbox *box)
{
	return box->view != NULL &&
		mail_index_view_is_inconsistent(box->view);
}

void index_save_context_free(struct mail_save_context *ctx)
{
	index_mail_save_finish(ctx);
	if (ctx->data.keywords != NULL)
		mailbox_keywords_unref(&ctx->data.keywords);
	i_free_and_null(ctx->data.from_envelope);
	i_free_and_null(ctx->data.guid);
	i_free_and_null(ctx->data.pop3_uidl);
	index_attachment_save_free(ctx);
	i_zero(&ctx->data);

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
	bool add = FALSE;

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
		add = TRUE;
	} else if (mail_cache_lookup_field(src_mail->transaction->cache_view, buf,
					   src_mail->seq, src_field_idx) <= 0) {
		/* error / not found */
		buffer_set_used_size(buf, 0);
	} else {
		if (strcmp(name, "size.physical") == 0 ||
		    strcmp(name, "size.virtual") == 0) {
			/* FIXME: until mail_cache_lookup() can read unwritten
			   cached data from buffer, we'll do this optimization
			   to make quota plugin's work faster */
			struct index_mail *imail =
				INDEX_MAIL(ctx->dest_mail);
			uoff_t size;

			i_assert(buf->used == sizeof(size));
			memcpy(&size, buf->data, sizeof(size));
			if (strcmp(name, "size.physical") == 0)
				imail->data.physical_size = size;
			else
				imail->data.virtual_size = size;
		}
		/* NOTE: we'll want to add also nonexistent headers, which
		   will keep the buf empty */
		add = TRUE;
	}
	if (add) {
		mail_cache_add(dest_trans->cache_trans, dest_seq,
			       dest_field_idx, buf->data, buf->used);
	}
}

static void
index_copy_vsize_extension(struct mail_save_context *ctx,
			   struct mail *src_mail, uint32_t dest_seq)
{
	unsigned int idx;
	const uint32_t *vsizep;
	bool expunged ATTR_UNUSED;

	vsizep = index_mail_get_vsize_extension(src_mail);
	if (vsizep == NULL || *vsizep == 0)
		return;
	uint32_t vsize = *vsizep;

	if (mail_index_map_get_ext_idx(ctx->transaction->view->map,
				       ctx->transaction->box->mail_vsize_ext_id,
				       &idx) &&
	    vsize < (uint32_t)-1) {
		uint32_t vsize = src_imail->data.virtual_size+1;
		mail_index_update_ext(ctx->transaction->itrans, dest_seq,
				      ctx->transaction->box->mail_vsize_ext_id,
				      &vsize, NULL);
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
		   decisions are up to date */
		if (mailbox_get_metadata(ctx->transaction->box,
					 MAILBOX_METADATA_CACHE_FIELDS,
					 &dest_metadata) < 0)
			i_unreached();

		buf = t_buffer_create(1024);
		array_foreach(src_metadata.cache_fields, field) {
			mail_copy_cache_field(ctx, src_mail, dest_seq,
					      field->name, buf);
		}
		index_copy_vsize_extension(ctx, src_mail, dest_seq);
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
		i_assert(str_begins(subs_name, ns->prefix));
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
		dict_wait(storage->_shared_attr_dict);
		dict_deinit(&storage->_shared_attr_dict);
	}
}

static void index_storage_expunging_init(struct mailbox *box)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);

	if (ibox->vsize_update != NULL)
		return;

	ibox->vsize_update = index_mailbox_vsize_update_init(box);
	if (!index_mailbox_vsize_want_updates(ibox->vsize_update) ||
	    !index_mailbox_vsize_update_wait_lock(ibox->vsize_update))
		index_mailbox_vsize_update_deinit(&ibox->vsize_update);
}

void index_storage_expunging_deinit(struct mailbox *box)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);

	if (ibox->vsize_update != NULL)
		index_mailbox_vsize_update_deinit(&ibox->vsize_update);
}

static bool index_storage_expunging_want_updates(struct mailbox *box)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
	bool ret;

	i_assert(ibox->vsize_update == NULL);

	ibox->vsize_update = index_mailbox_vsize_update_init(box);
	ret = index_mailbox_vsize_want_updates(ibox->vsize_update);
	index_mailbox_vsize_update_deinit(&ibox->vsize_update);
	return ret;
}

int index_storage_expunged_sync_begin(struct mailbox *box,
				      struct mail_index_sync_ctx **ctx_r,
				      struct mail_index_view **view_r,
				      struct mail_index_transaction **trans_r,
				      enum mail_index_sync_flags flags)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
	int ret;

	/* try to avoid locking vsize updates by checking if we see any
	   expunges */
	if (mail_index_sync_have_any_expunges(box->index))
		index_storage_expunging_init(box);

	ret = mail_index_sync_begin(box->index, ctx_r, view_r,
				    trans_r, flags);
	if (ret <= 0) {
		if (ret < 0)
			mailbox_set_index_error(box);
		index_storage_expunging_deinit(box);
		return ret;
	}
	if (ibox->vsize_update == NULL &&
	    mail_index_sync_has_expunges(*ctx_r) &&
	    index_storage_expunging_want_updates(box)) {
		/* race condition - need to abort the sync and retry with
		   the vsize locked */
		mail_index_sync_rollback(ctx_r);
		index_storage_expunging_deinit(box);
		return index_storage_expunged_sync_begin(box, ctx_r, view_r,
							 trans_r, flags);
	}
	return 1;
}

int index_storage_save_continue(struct mail_save_context *ctx,
				struct istream *input,
				struct mail *cache_dest_mail)
{
	struct mail_storage *storage = ctx->transaction->box->storage;

	do {
		switch (o_stream_send_istream(ctx->data.output, input)) {
		case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
			break;
		case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
			break;
		case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
			i_unreached();
		case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
			/* handle below */
			break;
		case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
			if (!mail_storage_set_error_from_errno(storage)) {
				mail_set_critical(ctx->dest_mail,
					"save: write(%s) failed: %s",
					o_stream_get_name(ctx->data.output),
					o_stream_get_error(ctx->data.output));
			}
			return -1;
		}
		if (cache_dest_mail != NULL)
			index_mail_cache_parse_continue(cache_dest_mail);

		/* both tee input readers may consume data from our primary
		   input stream. we'll have to make sure we don't return with
		   one of the streams still having data in them. */
	} while (i_stream_read(input) > 0);

	if (input->stream_errno != 0) {
		mail_set_critical(ctx->dest_mail, "save: read(%s) failed: %s",
			i_stream_get_name(input), i_stream_get_error(input));
		return -1;
	}
	return 0;
}

void index_storage_save_abort_last(struct mail_save_context *ctx, uint32_t seq)
{
	struct index_mail *imail = INDEX_MAIL(ctx->dest_mail);

	/* Close the mail before it's expunged. This allows it to be
	   reset cleanly. */
	imail->data.no_caching = TRUE;
	imail->mail.v.close(&imail->mail.mail);

	mail_index_expunge(ctx->transaction->itrans, seq);
	/* currently we can't just drop pending cache updates for this one
	   specific record, so we'll reset the whole cache transaction. */
	mail_cache_transaction_reset(ctx->transaction->cache_trans);
}

int index_mailbox_fix_inconsistent_existence(struct mailbox *box,
					     const char *path)
{
	const char *index_path;
	struct stat st;

	/* Could be a race condition or could be because ITERINDEX is used
	   and the index directory exists, but the storage directory doesn't.
	   Handle the existence inconsistency by creating this directory if
	   the index directory exists (don't bother checking if ITERINDEX is
	   set or not - it doesn't matter since either both dirs should exist
	   or not). */
	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX,
				&index_path) < 0)
		return -1;

	if (strcmp(index_path, path) == 0) {
		/* there's no separate index path - mailbox was just deleted */
	} else if (stat(index_path, &st) == 0) {
		/* inconsistency - create also the mail directory */
		return mailbox_mkdir(box, path, MAILBOX_LIST_PATH_TYPE_MAILBOX);
	} else if (errno == ENOENT) {
		/* race condition - mailbox was just deleted */
	} else {
		mailbox_set_critical(box, "stat(%s) failed: %m", index_path);
		return -1;
	}
	mailbox_set_deleted(box);
	return -1;
}
