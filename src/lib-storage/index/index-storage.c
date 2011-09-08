/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ioloop.h"
#include "str.h"
#include "imap-parser.h"
#include "mkdir-parents.h"
#include "mail-index-alloc-cache.h"
#include "mail-index-private.h"
#include "mail-index-modseq.h"
#include "mailbox-log.h"
#include "mailbox-list-private.h"
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

static struct mail_index *
index_storage_alloc(struct mailbox_list *list, const char *name,
		    enum mailbox_flags flags, const char *prefix)
{
	const char *index_dir, *mailbox_path;

	mailbox_path = mailbox_list_get_path(list, name,
					     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	index_dir = (flags & MAILBOX_FLAG_NO_INDEX_FILES) != 0 ? "" :
		mailbox_list_get_path(list, name, MAILBOX_LIST_PATH_TYPE_INDEX);
	if (*index_dir == '\0')
		index_dir = NULL;

	return mail_index_alloc_cache_get(mailbox_path, index_dir, prefix);
}

static void set_cache_decisions(const char *set, const char *fields,
				enum mail_cache_decision_type dec)
{
	const char *const *arr;
	int i;

	if (fields == NULL || *fields == '\0')
		return;

	for (arr = t_strsplit_spaces(fields, " ,"); *arr != NULL; arr++) {
		for (i = 0; i < MAIL_INDEX_CACHE_FIELD_COUNT; i++) {
			if (strcasecmp(global_cache_fields[i].name,
				       *arr) == 0) {
				global_cache_fields[i].decision = dec;
				break;
			}
		}
		if (i == MAIL_INDEX_CACHE_FIELD_COUNT) {
			i_error("%s: Invalid cache field name '%s', ignoring ",
				set, *arr);
		}
	}
}

static void index_cache_register_defaults(struct mailbox *box)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
	const struct mail_storage_settings *set = box->storage->set;
	static bool initialized = FALSE;
	struct mail_cache *cache = box->cache;

	if (!initialized) {
		initialized = TRUE;

		set_cache_decisions("mail_cache_fields",
				    set->mail_cache_fields,
				    MAIL_CACHE_DECISION_TEMP);
		set_cache_decisions("mail_never_cache_fields",
				    set->mail_never_cache_fields,
				    MAIL_CACHE_DECISION_NO |
				    MAIL_CACHE_DECISION_FORCED);
	}

	ibox->cache_fields = i_malloc(sizeof(global_cache_fields));
	memcpy(ibox->cache_fields, global_cache_fields,
	       sizeof(global_cache_fields));
	mail_cache_register_fields(cache, ibox->cache_fields,
				   MAIL_INDEX_CACHE_FIELD_COUNT);
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

int index_storage_mailbox_open(struct mailbox *box, bool move_to_memory)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
	enum mail_index_open_flags index_flags;
	int ret;

	i_assert(!box->opened);

	index_flags = ibox->index_flags;
	if (move_to_memory)
		ibox->index_flags &= ~MAIL_INDEX_OPEN_FLAG_CREATE;

	if ((index_flags & MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY) != 0) {
		if (mail_index_is_in_memory(box->index)) {
			mail_storage_set_critical(box->storage,
				"Couldn't create index file");
			return -1;
		}
	}

	if (mailbox_list_create_missing_index_dir(box->list, box->name) < 0) {
		mail_storage_set_internal_error(box->storage);
		return -1;
	}

	ret = mail_index_open(box->index, index_flags);
	if (ret <= 0 || move_to_memory) {
		if ((index_flags & MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY) != 0) {
			i_assert(ret <= 0);
			mail_storage_set_index_error(box);
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

	box->cache = mail_index_get_cache(box->index);
	index_cache_register_defaults(box);
	box->view = mail_index_view_open(box->index);
	ibox->keyword_names = mail_index_get_keywords(box->index);
	ibox->vsize_hdr_ext_id =
		mail_index_ext_register(box->index, "hdr-vsize",
					sizeof(struct index_vsize_header), 0,
					sizeof(uint64_t));

	box->opened = TRUE;

	index_thread_mailbox_opened(box);
	hook_mailbox_opened(box);

	if ((box->flags & MAILBOX_FLAG_OPEN_DELETED) == 0) {
		if (mail_index_is_deleted(box->index)) {
			mailbox_set_deleted(box);
			return -1;
		}
	}
	return 0;
}

void index_storage_mailbox_alloc(struct mailbox *box, const char *name,
				 enum mailbox_flags flags,
				 const char *index_prefix)
{
	struct index_mailbox_context *ibox;
	const char *path;
	string_t *vname;

	i_assert(name != NULL);

	box->name = p_strdup(box->pool, name);
	vname = t_str_new(128);
	mail_namespace_get_vname(box->list->ns, vname, name);
	box->vname = p_strdup(box->pool, str_c(vname));
	box->flags = flags;

	p_array_init(&box->search_results, box->pool, 16);
	array_create(&box->module_contexts,
		     box->pool, sizeof(void *), 5);

	ibox = p_new(box->pool, struct index_mailbox_context, 1);
	ibox->index_flags = MAIL_INDEX_OPEN_FLAG_CREATE |
		mail_storage_settings_to_index_flags(box->storage->set);
	ibox->next_lock_notify = time(NULL) + LOCK_NOTIFY_INTERVAL;
	MODULE_CONTEXT_SET(box, index_storage_module, ibox);

	path = mailbox_list_get_path(box->list, name,
				     MAILBOX_LIST_PATH_TYPE_MAILBOX);
	box->path = p_strdup(box->pool, path);
	box->index = index_storage_alloc(box->list, name, flags, index_prefix);
	box->inbox_user = strcmp(name, "INBOX") == 0 &&
		(box->list->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0;
	box->inbox_any = strcmp(name, "INBOX") == 0 &&
		(box->list->ns->flags & NAMESPACE_FLAG_INBOX_ANY) != 0;
	if (box->file_create_mode == 0)
		mailbox_refresh_permissions(box);
	mail_index_set_permissions(box->index, box->file_create_mode,
				   box->file_create_gid,
				   box->file_create_gid_origin);
	mail_index_set_fsync_mode(box->index,
				  box->storage->set->parsed_fsync_mode, 0);
	mail_index_set_lock_method(box->index,
		box->storage->set->parsed_lock_method,
		mail_storage_get_lock_timeout(box->storage, -1U));
}

int index_storage_mailbox_enable(struct mailbox *box,
				 enum mailbox_feature feature)
{
	if ((feature & MAILBOX_FEATURE_CONDSTORE) != 0) {
		box->enabled_features |= MAILBOX_FEATURE_CONDSTORE;
		if (mailbox_open(box) < 0)
			return -1;
		T_BEGIN {
			mail_index_modseq_enable(box->index);
		} T_END;
	}
	return 0;
}

void index_storage_mailbox_close(struct mailbox *box)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);

	index_mailbox_check_remove_all(box);
	if (box->input != NULL)
		i_stream_unref(&box->input);

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
	mail_index_alloc_cache_unref(&box->index);
}

void index_storage_mailbox_update_cache_fields(struct mailbox *box,
					       const struct mailbox_update *update)
{
	const char *const *field_names = update->cache_fields;
	ARRAY_DEFINE(new_fields, struct mail_cache_field);
	const struct mail_cache_field *old_fields;
	struct mail_cache_field field;
	unsigned int i, j, old_count;

	old_fields = mail_cache_register_get_list(box->cache,
						  pool_datastack_create(),
						  &old_count);

	/* There shouldn't be many fields, so don't worry about O(n^2). */
	t_array_init(&new_fields, 32);
	for (i = 0; field_names[i] != NULL; i++) {
		/* see if it's an existing field */
		for (j = 0; j < old_count; j++) {
			if (strcmp(field_names[i], old_fields[j].name) == 0)
				break;
		}
		if (j != old_count) {
			field = old_fields[j];
			if (field.decision == MAIL_CACHE_DECISION_NO)
				field.decision = MAIL_CACHE_DECISION_TEMP;
			array_append(&new_fields, &field, 1);
		} else if (strncmp(field_names[i], "hdr.", 4) == 0) {
			/* new header */
			memset(&field, 0, sizeof(field));
			field.name = field_names[i];
			field.type = MAIL_CACHE_FIELD_HEADER;
			field.decision = MAIL_CACHE_DECISION_TEMP;
			array_append(&new_fields, &field, 1);
		} else {
			/* new unknown field. we can't do anything about
			   this since we don't know its type */
		}
	}
	if (array_count(&new_fields) > 0) {
		mail_cache_register_fields(box->cache,
					   array_idx_modifiable(&new_fields, 0),
					   array_count(&new_fields));
	}
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
	if (update->cache_fields != NULL)
		index_storage_mailbox_update_cache_fields(box, update);

	/* make sure we get the latest index info */
	(void)mail_index_refresh(box->index);
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
		mail_storage_set_index_error(box);
	mail_index_view_close(&view);
	return ret;
}

int index_storage_mailbox_delete_dir(struct mailbox *box, bool mailbox_deleted)
{
	uint8_t dir_sha128[MAIL_GUID_128_SIZE];
	enum mail_error error;

	if (mailbox_list_delete_dir(box->list, box->name) == 0)
		return 0;

	(void)mailbox_list_get_last_error(box->list, &error);
	if (error != MAIL_ERROR_NOTFOUND || !mailbox_deleted) {
		mail_storage_copy_list_error(box->storage, box->list);
		return -1;
	}
	/* failed directory deletion, but mailbox deletion succeeded.
	   this was probably maildir++, which internally deleted the
	   directory as well. add changelog record about that too. */
	mailbox_name_get_sha128(box->name, dir_sha128);
	mailbox_list_add_change(box->list, MAILBOX_LOG_RECORD_DELETE_DIR,
				dir_sha128);
	return 0;
}

int index_storage_mailbox_delete(struct mailbox *box)
{
	uint8_t mailbox_guid[MAIL_GUID_128_SIZE];

	if (!box->opened) {
		/* \noselect mailbox, try deleting only the directory */
		return index_storage_mailbox_delete_dir(box, FALSE);
	}

	if (mailbox_mark_index_deleted(box, TRUE) < 0)
		return -1;

	if (mailbox_get_guid(box, mailbox_guid) < 0)
		return -1;

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

	mailbox_list_add_change(box->list, MAILBOX_LOG_RECORD_DELETE_MAILBOX,
				mailbox_guid);
	return index_storage_mailbox_delete_dir(box, TRUE);
}

int index_storage_mailbox_rename(struct mailbox *src, struct mailbox *dest,
				 bool rename_children)
{
	uint8_t guid[MAIL_GUID_128_SIZE];

	if (src->list->v.rename_mailbox(src->list, src->name,
					dest->list, dest->name,
					rename_children) < 0) {
		mail_storage_copy_list_error(src->storage, src->list);
		return -1;
	}

	/* we'll track mailbox names, instead of GUIDs. We may be renaming a
	   non-selectable mailbox (directory), which doesn't even have a GUID */
	mailbox_name_get_sha128(dest->name, guid);
	mailbox_list_add_change(src->list, MAILBOX_LOG_RECORD_RENAME, guid);
	return 0;
}

bool index_storage_is_readonly(struct mailbox *box)
{
	if ((box->flags & MAILBOX_FLAG_READONLY) != 0)
		return TRUE;

	if (box->backend_readonly) {
		/* return read-only only if there are no private flags
		   (that are stored in index files) */
		if (box->private_flags_mask == 0)
			return TRUE;
	}
	return FALSE;
}

bool index_storage_allow_new_keywords(struct mailbox *box)
{
	/* FIXME: return FALSE if we're full */
	return !index_storage_is_readonly(box);
}

bool index_storage_is_inconsistent(struct mailbox *box)
{
	return mail_index_view_is_inconsistent(box->view);
}

bool index_keyword_is_valid(struct mailbox *box, const char *keyword,
			    const char **error_r)
{
	unsigned int i, idx;

	/* if it already exists, skip validity checks */
	if (mail_index_keyword_lookup(box->index, keyword, &idx))
		return TRUE;

	if (*keyword == '\0') {
		*error_r = "Empty keywords not allowed";
		return FALSE;
	}

	/* these are IMAP-specific restrictions, but for now IMAP is all we
	   care about */
	for (i = 0; keyword[i] != '\0'; i++) {
		if (IS_ATOM_SPECIAL((unsigned char)keyword[i])) {
			*error_r = "Invalid characters in keyword";
			return FALSE;
		}
		if ((unsigned char)keyword[i] >= 0x80) {
			*error_r = "8bit characters in keyword";
			return FALSE;
		}
	}
	if (i > box->storage->set->mail_max_keyword_length) {
		*error_r = "Keyword length too long";
		return FALSE;
	}
	return TRUE;
}

static struct mail_keywords *
index_keywords_create_skip(struct mailbox *box,
			   const char *const keywords[])
{
	ARRAY_DEFINE(valid_keywords, const char *);
	const char *error;

	t_array_init(&valid_keywords, 32);
	for (; *keywords != NULL; keywords++) {
		if (mailbox_keyword_is_valid(box, *keywords, &error))
			array_append(&valid_keywords, keywords, 1);
	}
	(void)array_append_space(&valid_keywords); /* NULL-terminate */
	return mail_index_keywords_create(box->index, keywords);
}

int index_keywords_create(struct mailbox *box, const char *const keywords[],
			  struct mail_keywords **keywords_r, bool skip_invalid)
{
	const char *error;
	unsigned int i;

	for (i = 0; keywords[i] != NULL; i++) {
		if (mailbox_keyword_is_valid(box, keywords[i], &error))
			continue;

		if (!skip_invalid) {
			mail_storage_set_error(box->storage,
					       MAIL_ERROR_PARAMS, error);
			return -1;
		}

		/* found invalid keywords, do this the slow way */
		T_BEGIN {
			*keywords_r = index_keywords_create_skip(box, keywords);
		} T_END;
		return 0;
	}

	*keywords_r = mail_index_keywords_create(box->index, keywords);
	return 0;
}

struct mail_keywords *
index_keywords_create_from_indexes(struct mailbox *_box,
				   const ARRAY_TYPE(keyword_indexes) *idx)
{
	return mail_index_keywords_create_from_indexes(_box->index, idx);
}

void index_keywords_ref(struct mail_keywords *keywords)
{
	mail_index_keywords_ref(keywords);
}

void index_keywords_unref(struct mail_keywords *keywords)
{
	mail_index_keywords_unref(&keywords);
}

void index_save_context_free(struct mail_save_context *ctx)
{
	i_free_and_null(ctx->from_envelope);
	i_free_and_null(ctx->guid);
	i_free_and_null(ctx->pop3_uidl);
	index_attachment_save_free(ctx);
}

static void
mail_copy_cache_field(struct mail_save_context *ctx, struct mail *src_mail,
		      uint32_t dest_seq, const char *name, buffer_t *buf)
{
	struct mailbox_transaction_context *dest_trans = ctx->transaction;
	struct index_transaction_context *dest_itrans =
		(struct index_transaction_context *)dest_trans;
	struct index_transaction_context *src_itrans =
		(struct index_transaction_context *)src_mail->transaction;
	const struct mail_cache_field *dest_field;
	unsigned int src_field_idx, dest_field_idx;

	src_field_idx = mail_cache_register_lookup(src_mail->box->cache, name);
	i_assert(src_field_idx != -1U);

	dest_field_idx = mail_cache_register_lookup(dest_trans->box->cache, name);
	if (dest_field_idx == -1U) {
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
	if (mail_cache_lookup_field(src_itrans->cache_view, buf,
				    src_mail->seq, src_field_idx) > 0) {
		mail_cache_add(dest_itrans->cache_trans, dest_seq,
			       dest_field_idx, buf->data, buf->used);
	}
}

void index_copy_cache_fields(struct mail_save_context *ctx,
			     struct mail *src_mail, uint32_t dest_seq)
{
	T_BEGIN {
		struct mailbox_status src_status;
		const char *const *namep;
		buffer_t *buf;

		index_storage_get_status(src_mail->box, STATUS_CACHE_FIELDS,
					 &src_status);

		buf = buffer_create_dynamic(pool_datastack_create(), 1024);
		array_foreach(src_status.cache_fields, namep) {
			mail_copy_cache_field(ctx, src_mail, dest_seq,
					      *namep, buf);
		}
	} T_END;
}
