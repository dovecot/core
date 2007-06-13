/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "write-full.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-index-transaction-private.h"
#include "mail-transaction-log-private.h"
#include "mail-transaction-util.h"
#include "mail-cache.h"

#include <stdio.h>
#include <stdlib.h>

struct mail_index_sync_ctx {
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_index_transaction *sync_trans, *ext_trans;

	const struct mail_transaction_header *hdr;
	const void *data;

	ARRAY_DEFINE(sync_list, struct mail_index_sync_list);
	uint32_t next_uid;
	uint32_t last_mailbox_seq, last_mailbox_offset;

	uint32_t append_uid_first, append_uid_last;

	unsigned int lock_id;

	unsigned int sync_appends:1;
	unsigned int sync_recent:1;
	unsigned int sync_dirty:1;
};

static bool mail_index_sync_check_uid_range(struct mail_index_sync_ctx *ctx,
					    uint32_t uid1, uint32_t uid2)
{
	if (uid1 > uid2 || uid1 == 0) {
		mail_transaction_log_view_set_corrupted(ctx->view->log_view,
			"Broken UID range: %u..%u (type=0x%x)", uid1, uid2,
			ctx->hdr->type & MAIL_TRANSACTION_TYPE_MASK);
		return FALSE;
	}
	return TRUE;
}

static void mail_index_sync_add_expunge(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_expunge *e = ctx->data;
	size_t i, size = ctx->hdr->size / sizeof(*e);
	uint32_t uid;

	for (i = 0; i < size; i++) {
		if (!mail_index_sync_check_uid_range(ctx, e[i].uid1, e[i].uid2))
			break;
		for (uid = e[i].uid1; uid <= e[i].uid2; uid++)
			mail_index_expunge(ctx->sync_trans, uid);
	}
}

static void mail_index_sync_add_flag_update(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_flag_update *u = ctx->data;
	size_t i, size = ctx->hdr->size / sizeof(*u);

	for (i = 0; i < size; i++) {
		if (!mail_index_sync_check_uid_range(ctx, u[i].uid1, u[i].uid2))
			break;
		if (u[i].add_flags != 0) {
			mail_index_update_flags_range(ctx->sync_trans,
						      u[i].uid1, u[i].uid2,
						      MODIFY_ADD,
						      u[i].add_flags);
		}
		if (u[i].remove_flags != 0) {
			mail_index_update_flags_range(ctx->sync_trans,
						      u[i].uid1, u[i].uid2,
						      MODIFY_REMOVE,
						      u[i].remove_flags);
		}
	}
}

static void mail_index_sync_add_keyword_update(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_keyword_update *u = ctx->data;
	const char *keyword_names[2];
	struct mail_keywords *keywords;
	const uint32_t *uids;
	uint32_t uid;
	size_t uidset_offset, i, size;

	uidset_offset = sizeof(*u) + u->name_size;
	if ((uidset_offset % 4) != 0)
		uidset_offset += 4 - (uidset_offset % 4);
	uids = CONST_PTR_OFFSET(u, uidset_offset);

	t_push();
	keyword_names[0] = t_strndup(u + 1, u->name_size);
	keyword_names[1] = NULL;
	keywords = mail_index_keywords_create(ctx->sync_trans, keyword_names);

	size = (ctx->hdr->size - uidset_offset) / sizeof(uint32_t);
	for (i = 0; i < size; i += 2) {
		/* FIXME: mail_index_update_keywords_range() */
		if (!mail_index_sync_check_uid_range(ctx, uids[i], uids[i+1]))
			break;
		for (uid = uids[i]; uid <= uids[i+1]; uid++) {
			mail_index_update_keywords(ctx->sync_trans, uid,
						   u->modify_type, keywords);
		}
	}

	mail_index_keywords_free(&keywords);
	t_pop();
}

static void mail_index_sync_add_keyword_reset(struct mail_index_sync_ctx *ctx)
{
	const struct mail_transaction_keyword_reset *u = ctx->data;
	size_t i, size = ctx->hdr->size / sizeof(*u);
	struct mail_keywords *keywords;
	uint32_t uid;

	keywords = mail_index_keywords_create(ctx->sync_trans, NULL);
	for (i = 0; i < size; i++) {
		if (!mail_index_sync_check_uid_range(ctx, u[i].uid1, u[i].uid2))
			break;
		for (uid = u[i].uid1; uid <= u[i].uid2; uid++) {
			mail_index_update_keywords(ctx->sync_trans, uid,
						   MODIFY_REPLACE, keywords);
		}
	}
	mail_index_keywords_free(&keywords);
}

static void mail_index_sync_add_append(struct mail_index_sync_ctx *ctx)
{
	const struct mail_index_record *rec = ctx->data;

	if (ctx->append_uid_first == 0 || rec->uid < ctx->append_uid_first)
		ctx->append_uid_first = rec->uid;

	rec = CONST_PTR_OFFSET(ctx->data, ctx->hdr->size - sizeof(*rec));
	if (rec->uid > ctx->append_uid_last)
		ctx->append_uid_last = rec->uid;

	ctx->sync_appends = TRUE;
}

static bool mail_index_sync_add_transaction(struct mail_index_sync_ctx *ctx)
{
	switch (ctx->hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_EXPUNGE:
		mail_index_sync_add_expunge(ctx);
		break;
	case MAIL_TRANSACTION_FLAG_UPDATE:
                mail_index_sync_add_flag_update(ctx);
		break;
	case MAIL_TRANSACTION_KEYWORD_UPDATE:
                mail_index_sync_add_keyword_update(ctx);
		break;
	case MAIL_TRANSACTION_KEYWORD_RESET:
                mail_index_sync_add_keyword_reset(ctx);
		break;
	case MAIL_TRANSACTION_APPEND:
		mail_index_sync_add_append(ctx);
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static int mail_index_sync_add_dirty_updates(struct mail_index_sync_ctx *ctx)
{
	struct mail_transaction_flag_update update;
	const struct mail_index_record *rec;
	uint32_t seq, messages_count;

	memset(&update, 0, sizeof(update));

	messages_count = mail_index_view_get_messages_count(ctx->view);
	for (seq = 1; seq <= messages_count; seq++) {
		if (mail_index_lookup(ctx->view, seq, &rec) < 0)
			return -1;

		if ((rec->flags & MAIL_INDEX_MAIL_FLAG_DIRTY) == 0)
			continue;

		mail_index_update_flags(ctx->sync_trans, rec->uid,
					MODIFY_REPLACE, rec->flags);
	}
	return 0;
}

static int mail_index_sync_add_recent_updates(struct mail_index_sync_ctx *ctx)
{
	const struct mail_index_record *rec;
	uint32_t seq, messages_count;
	bool seen_recent = FALSE;

	messages_count = mail_index_view_get_messages_count(ctx->view);
	for (seq = 1; seq <= messages_count; seq++) {
		if (mail_index_lookup(ctx->view, seq, &rec) < 0)
			return -1;

		if ((rec->flags & MAIL_RECENT) != 0) {
			seen_recent = TRUE;
			mail_index_update_flags(ctx->sync_trans, rec->uid,
						MODIFY_REMOVE, MAIL_RECENT);
		}
	}

	if (!seen_recent) {
		/* no recent messages, drop the sync_recent flag so we
		   don't scan through the message again */
		ctx->sync_recent = FALSE;
	}

	return 0;
}

static void
mail_index_sync_update_mailbox_pos(struct mail_index_sync_ctx *ctx)
{
	uint32_t seq;
	uoff_t offset;

	mail_transaction_log_view_get_prev_pos(ctx->view->log_view,
					       &seq, &offset);

	ctx->last_mailbox_seq = seq;
	ctx->last_mailbox_offset = offset + ctx->hdr->size + sizeof(*ctx->hdr);
}

static int
mail_index_sync_read_and_sort(struct mail_index_sync_ctx *ctx)
{
	struct mail_index_transaction *sync_trans = ctx->sync_trans;
	struct mail_index_sync_list *synclist;
        const struct mail_index_transaction_keyword_update *keyword_updates;
	unsigned int i, keyword_count;
	int ret;

	if ((ctx->view->map->hdr.flags & MAIL_INDEX_HDR_FLAG_HAVE_DIRTY) &&
	    ctx->sync_dirty) {
		/* show dirty flags as flag updates */
		if (mail_index_sync_add_dirty_updates(ctx) < 0)
			return -1;
	}

	if (ctx->sync_recent) {
		if (mail_index_sync_add_recent_updates(ctx) < 0)
			return -1;
	}

	/* read all transactions from log into a transaction in memory.
	   skip the external ones, they're already synced to mailbox and
	   included in our view */
	while ((ret = mail_transaction_log_view_next(ctx->view->log_view,
						     &ctx->hdr,
						     &ctx->data, NULL)) > 0) {
		if ((ctx->hdr->type & MAIL_TRANSACTION_EXTERNAL) != 0)
			continue;

		if (mail_index_sync_add_transaction(ctx))
			mail_index_sync_update_mailbox_pos(ctx);
	}

	/* create an array containing all expunge, flag and keyword update
	   arrays so we can easily go through all of the changes. */
	keyword_count = !array_is_created(&sync_trans->keyword_updates) ? 0 :
		array_count(&sync_trans->keyword_updates);
	i_array_init(&ctx->sync_list, keyword_count + 2);

	if (array_is_created(&sync_trans->expunges)) {
		synclist = array_append_space(&ctx->sync_list);
		synclist->array = (void *)&sync_trans->expunges;
	}

	if (array_is_created(&sync_trans->updates)) {
		synclist = array_append_space(&ctx->sync_list);
		synclist->array = (void *)&sync_trans->updates;
	}

	/* we must return resets before keyword additions or they get lost */
	if (array_is_created(&sync_trans->keyword_resets)) {
		synclist = array_append_space(&ctx->sync_list);
		synclist->array = (void *)&sync_trans->keyword_resets;
	}

	keyword_updates = keyword_count == 0 ? NULL :
		array_idx(&sync_trans->keyword_updates, 0);
	for (i = 0; i < keyword_count; i++) {
		if (array_is_created(&keyword_updates[i].add_seq)) {
			synclist = array_append_space(&ctx->sync_list);
			synclist->array = (void *)&keyword_updates[i].add_seq;
			synclist->keyword_idx = i;
		}
		if (array_is_created(&keyword_updates[i].remove_seq)) {
			synclist = array_append_space(&ctx->sync_list);
			synclist->array =
				(void *)&keyword_updates[i].remove_seq;
			synclist->keyword_idx = i;
			synclist->keyword_remove = TRUE;
		}
	}

	return ret;
}

static bool
mail_index_need_sync(struct mail_index *index,
		     const struct mail_index_header *hdr, bool sync_recent,
		     uint32_t log_file_seq, uoff_t log_file_offset)
{
	// FIXME: how's this recent syncing supposed to work?
	if (sync_recent && hdr->recent_messages_count > 0)
		return TRUE;

	if (hdr->log_file_seq < log_file_seq ||
	     (hdr->log_file_seq == log_file_seq &&
	      hdr->log_file_mailbox_offset < log_file_offset))
		return TRUE;

	/* already synced */
	return mail_cache_need_compress(index->cache);
}

static int
mail_index_sync_set_log_view(struct mail_index_view *view,
			     uint32_t start_file_seq, uoff_t start_file_offset)
{
	uint32_t log_seq;
	uoff_t log_offset;
	int ret;

	mail_transaction_log_get_head(view->index->log, &log_seq, &log_offset);

	ret = mail_transaction_log_view_set(view->log_view,
                                            start_file_seq, start_file_offset,
					    log_seq, log_offset,
					    MAIL_TRANSACTION_TYPE_MASK);
	if (ret <= 0) {
		/* either corrupted or the file was deleted for
		   some reason. either way, we can't go forward */
		mail_index_set_error(view->index,
			"Unexpected transaction log desync with index %s",
			view->index->filepath);
		mail_index_set_inconsistent(view->index);
		return -1;
	}
	return 0;
}

int mail_index_sync_begin(struct mail_index *index,
                          struct mail_index_sync_ctx **ctx_r,
			  struct mail_index_view **view_r,
			  struct mail_index_transaction **trans_r,
			  uint32_t log_file_seq, uoff_t log_file_offset,
			  bool sync_recent, bool sync_dirty)
{
	const struct mail_index_header *hdr;
	struct mail_index_sync_ctx *ctx;
	struct mail_index_view *sync_view;
	uint32_t seq;
	uoff_t offset;
	unsigned int lock_id = 0;

	if (mail_transaction_log_sync_lock(index->log, &seq, &offset) < 0)
		return -1;

	/* The view must contain what we expect the mailbox to look like
	   currently. That allows the backend to update external flag
	   changes (etc.) if the view doesn't match the mailbox.

	   We'll update the view to contain everything that exist in the
	   transaction log except for expunges. They're synced in
	   mail_index_sync_commit(). */
	if (mail_index_map(index, MAIL_INDEX_SYNC_HANDLER_HEAD,
			   &lock_id) <= 0) {
		// FIXME: handle ret=0 specially?
		mail_transaction_log_sync_unlock(index->log);
		return -1;
	}
	hdr = index->hdr;

	if (!mail_index_need_sync(index, hdr, sync_recent,
				  log_file_seq, log_file_offset)) {
		mail_index_unlock(index, lock_id);
		mail_transaction_log_sync_unlock(index->log);
		return 0;
	}

	if (hdr->log_file_index_int_offset > hdr->log_file_index_ext_offset ||
	    hdr->log_file_seq > seq ||
	    (hdr->log_file_seq == seq &&
	     (hdr->log_file_index_ext_offset > offset ||
	      hdr->log_file_mailbox_offset > offset))) {
		/* broken sync positions. fix them. */
		mail_index_set_error(index,
			"broken sync positions in index file %s",
			index->filepath);
		if (mail_index_fsck(index) <= 0) {
			mail_index_unlock(index, lock_id);
			mail_transaction_log_sync_unlock(index->log);
			return -1;
		}
	}

	ctx = i_new(struct mail_index_sync_ctx, 1);
	ctx->index = index;
	ctx->lock_id = lock_id;
	ctx->sync_recent = sync_recent;
	ctx->sync_dirty = sync_dirty;
	ctx->last_mailbox_seq = hdr->log_file_seq;
	ctx->last_mailbox_offset = hdr->log_file_mailbox_offset;

	ctx->view = mail_index_view_open(index);

	sync_view = mail_index_dummy_view_open(index);
	ctx->sync_trans = mail_index_transaction_begin(sync_view, FALSE, TRUE);
	mail_index_view_close(&sync_view);

	/* we wish to see all the changes from last mailbox sync position to
	   the end of the transaction log */
	if (mail_index_sync_set_log_view(ctx->view, hdr->log_file_seq,
					 hdr->log_file_mailbox_offset) < 0) {
                mail_index_sync_rollback(&ctx);
		return -1;
	}

	/* we need to have all the transactions sorted to optimize
	   caller's mailbox access patterns */
	if (mail_index_sync_read_and_sort(ctx) < 0) {
                mail_index_sync_rollback(&ctx);
		return -1;
	}

	ctx->view->index_sync_view = TRUE;

	/* create the transaction after the view has been updated with
	   external transactions and marked as sync view */
	ctx->ext_trans = mail_index_transaction_begin(ctx->view, FALSE, TRUE);

	*ctx_r = ctx;
	*view_r = ctx->view;
	*trans_r = ctx->ext_trans;
	return 1;
}

static void
mail_index_sync_get_expunge(struct mail_index_sync_rec *rec,
			    const struct mail_transaction_expunge *exp)
{
	rec->type = MAIL_INDEX_SYNC_TYPE_EXPUNGE;
	rec->uid1 = exp->uid1;
	rec->uid2 = exp->uid2;
}

static void
mail_index_sync_get_update(struct mail_index_sync_rec *rec,
			   const struct mail_transaction_flag_update *update)
{
	rec->type = MAIL_INDEX_SYNC_TYPE_FLAGS;
	rec->uid1 = update->uid1;
	rec->uid2 = update->uid2;

	rec->add_flags = update->add_flags;
	rec->remove_flags = update->remove_flags;
}

static void
mail_index_sync_get_keyword_update(struct mail_index_sync_rec *rec,
				   const struct uid_range *range,
				   struct mail_index_sync_list *sync_list)
{
	rec->type = !sync_list->keyword_remove ?
		MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD :
		MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE;
	rec->uid1 = range->uid1;
	rec->uid2 = range->uid2;
	rec->keyword_idx = sync_list->keyword_idx;
}

static void mail_index_sync_get_keyword_reset(struct mail_index_sync_rec *rec,
					       const struct uid_range *range)
{
	rec->type = MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET;
	rec->uid1 = range->uid1;
	rec->uid2 = range->uid2;
}

int mail_index_sync_next(struct mail_index_sync_ctx *ctx,
			 struct mail_index_sync_rec *sync_rec)
{
	struct mail_index_transaction *sync_trans = ctx->sync_trans;
	struct mail_index_sync_list *sync_list;
	const struct uid_range *uid_range = NULL;
	unsigned int i, count, next_i;
	uint32_t next_found_uid;

	next_i = (unsigned int)-1;
	next_found_uid = (uint32_t)-1;

	/* FIXME: replace with a priority queue so we don't have to go
	   through the whole list constantly. and remember to make sure that
	   keyword resets are sent before adds! */
	sync_list = array_get_modifiable(&ctx->sync_list, &count);
	for (i = 0; i < count; i++) {
		if (!array_is_created(sync_list[i].array) ||
		    sync_list[i].idx == array_count(sync_list[i].array))
			continue;

		uid_range = array_idx(sync_list[i].array, sync_list[i].idx);
		if (uid_range->uid1 == ctx->next_uid) {
			/* use this one. */
			break;
		}
		if (uid_range->uid1 < next_found_uid) {
			next_i = i;
                        next_found_uid = uid_range->uid1;
		}
	}

	if (i == count) {
		if (next_i == (unsigned int)-1) {
			/* nothing left in sync_list */
			if (ctx->sync_appends) {
				ctx->sync_appends = FALSE;
				sync_rec->type = MAIL_INDEX_SYNC_TYPE_APPEND;
				sync_rec->uid1 = ctx->append_uid_first;
				sync_rec->uid2 = ctx->append_uid_last;
				return 1;
			}
			return 0;
		}
                ctx->next_uid = next_found_uid;
		i = next_i;
		uid_range = array_idx(sync_list[i].array, sync_list[i].idx);
	}

	if (sync_list[i].array == (void *)&sync_trans->expunges) {
		mail_index_sync_get_expunge(sync_rec,
			(const struct mail_transaction_expunge *)uid_range);
	} else if (sync_list[i].array == (void *)&sync_trans->updates) {
		mail_index_sync_get_update(sync_rec,
			(const struct mail_transaction_flag_update *)uid_range);
	} else if (sync_list[i].array == (void *)&sync_trans->keyword_resets) {
		mail_index_sync_get_keyword_reset(sync_rec, uid_range);
	} else {
		mail_index_sync_get_keyword_update(sync_rec, uid_range,
						   &sync_list[i]);
	}
	sync_list[i].idx++;
	return 1;
}

bool mail_index_sync_have_more(struct mail_index_sync_ctx *ctx)
{
	const struct mail_index_sync_list *sync_list;
	unsigned int i, count;

	if (ctx->sync_appends)
		return TRUE;

	sync_list = array_get(&ctx->sync_list, &count);
	for (i = 0; i < count; i++) {
		if (array_is_created(sync_list[i].array) &&
		    sync_list[i].idx != array_count(sync_list[i].array))
			return TRUE;
	}
	return FALSE;
}

void mail_index_sync_reset(struct mail_index_sync_ctx *ctx)
{
	struct mail_index_sync_list *sync_list;
	unsigned int i, count;

	ctx->next_uid = 0;

	sync_list = array_get_modifiable(&ctx->sync_list, &count);
	for (i = 0; i < count; i++)
		sync_list[i].idx = 0;
}

static void mail_index_sync_end(struct mail_index_sync_ctx **_ctx)
{
        struct mail_index_sync_ctx *ctx = *_ctx;

	*_ctx = NULL;

	mail_index_unlock(ctx->index, ctx->lock_id);
	mail_transaction_log_sync_unlock(ctx->index->log);

	mail_index_view_close(&ctx->view);
	mail_index_transaction_rollback(&ctx->sync_trans);
	if (array_is_created(&ctx->sync_list))
		array_free(&ctx->sync_list);
	i_free(ctx);
}

static int mail_index_recreate(struct mail_index *index)
{
	struct mail_index_map *map = index->map;
	unsigned int base_size;
	const char *path;
	int ret, fd;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));

	fd = mail_index_create_tmp_file(index, &path);
	if (fd == -1)
		return -1;

	/* write base header */
	base_size = I_MIN(map->hdr.base_header_size, sizeof(map->hdr));
	ret = write_full(fd, &map->hdr, base_size);
	if (ret == 0) {
		/* write extended headers */
		ret = write_full(fd, CONST_PTR_OFFSET(map->hdr_base, base_size),
				 map->hdr.header_size - base_size);
	}
	if (ret == 0) {
		ret = write_full(fd, map->records, map->records_count *
				 map->hdr.record_size);
	}
	if (ret < 0)
		mail_index_file_set_syscall_error(index, path, "write_full()");

	if (ret == 0 && !index->fsync_disable && fsync(fd) < 0) {
		mail_index_file_set_syscall_error(index, path, "fsync()");
		ret = -1;
	}

	if (close(fd) < 0) {
		mail_index_file_set_syscall_error(index, path, "close()");
		ret = -1;
	}

	if (ret == 0 && rename(path, index->filepath) < 0) {
		mail_index_set_error(index, "rename(%s, %s) failed: %m",
				     path, index->filepath);
		ret = -1;
	}

	if (ret < 0) {
		if (unlink(path) < 0) {
			mail_index_set_error(index, "unlink(%s) failed: %m",
					     path);
		}
	}
	return ret;
}

static int mail_index_write_map_over(struct mail_index *index)
{
	struct mail_index_map *map = index->map;
	unsigned int base_size;

	if (MAIL_INDEX_IS_IN_MEMORY(index))
		return 0;

	/* write records. */
	if (map->write_seq_first != 0) {
		size_t rec_offset =
			(map->write_seq_first-1) * map->hdr.record_size;

		if (pwrite_full(index->fd,
				CONST_PTR_OFFSET(map->records, rec_offset),
				(map->write_seq_last -
				 map->write_seq_first + 1) *
				map->hdr.record_size,
				map->hdr.header_size + rec_offset) < 0)
			return -1;
	}

	/* write base header */
	if (map->write_base_header) {
		base_size = I_MIN(map->hdr.base_header_size, sizeof(map->hdr));
		if (pwrite_full(index->fd, &map->hdr, base_size, 0) < 0)
			return -1;
	}

	/* write extended headers */
	if (map->write_ext_header) {
		base_size = map->hdr.base_header_size;
		if (pwrite_full(index->fd,
				CONST_PTR_OFFSET(map->hdr_base, base_size),
				map->hdr.header_size - base_size,
				base_size) < 0)
			return -1;
	}
	return 0;
}

#define mail_index_map_has_changed(map) \
	((map)->write_base_header || (map)->write_ext_header || \
	 (map)->write_seq_first != 0)

static void mail_index_write(struct mail_index *index, bool want_rotate)
{
	struct mail_index_map *map = index->map;
	const struct mail_index_header *hdr = &map->hdr;
	unsigned int lock_id;

	if (!mail_index_map_has_changed(map))
		return;

	if (hdr->base_header_size < sizeof(*hdr)) {
		/* header size growed. we can't update this file anymore. */
		map->write_atomic = TRUE;
	}
	if (index->fd == -1) {
		/* index file doesn't exist, it's corrupted or we haven't
		   opened it for some reason */
		map->write_atomic = TRUE;
	}
	if (!map->write_atomic) {
		if (mail_index_try_lock_exclusive(index, &lock_id) <= 0) {
			/* locking failed, rewrite */
			map->write_atomic = TRUE;
		}
	}

	if (map->write_atomic) {
		if (!MAIL_INDEX_IS_IN_MEMORY(index)) {
			if (mail_index_recreate(index) < 0) {
				mail_index_move_to_memory(index);
				return;
			}
		}
	} else {
		if (mail_index_write_map_over(index) < 0) {
			mail_index_set_error(index,
				"pwrite_full(%s) failed: %m", index->filepath);
			mail_index_set_inconsistent(index);
		}
		mail_index_unlock(index, lock_id);
	}

	index->last_read_log_file_index_offset = hdr->log_file_index_int_offset;

	map->write_atomic = FALSE;
	map->write_seq_first = map->write_seq_last = 0;
	map->write_base_header = FALSE;
	map->write_ext_header = FALSE;

	if (want_rotate &&
	    hdr->log_file_index_int_offset == hdr->log_file_index_ext_offset &&
	    hdr->log_file_index_int_offset == hdr->log_file_mailbox_offset)
		(void)mail_transaction_log_rotate(index->log);
}

static void
mail_index_sync_update_mailbox_offset(struct mail_index_sync_ctx *ctx)
{
	const struct mail_index_header *hdr = &ctx->index->map->hdr;
	uint32_t seq;
	uoff_t offset;

	mail_transaction_log_view_get_prev_pos(ctx->view->log_view,
					       &seq, &offset);
	mail_transaction_log_set_mailbox_sync_pos(ctx->index->log, seq, offset);

	/* This sync may have seen only external transactions, in which case
	   it's not required to write the mailbox sync offset. Otherwise we
	   must update the offset even if nothing else is going to be
	   written. */
	if (hdr->log_file_mailbox_offset != ctx->last_mailbox_offset)
		ctx->ext_trans->log_updates = TRUE;
}

int mail_index_sync_commit(struct mail_index_sync_ctx **_ctx)
{
        struct mail_index_sync_ctx *ctx = *_ctx;
	struct mail_index *index = ctx->index;
	unsigned int lock_id;
	uint32_t seq, diff;
	uoff_t offset;
	bool want_rotate;
	int ret = 0;

	mail_index_sync_update_mailbox_offset(ctx);
	if (mail_cache_need_compress(index->cache)) {
		/* if cache compression fails, we don't really care.
		   the cache offsets are updated only if the compression was
		   successful. */
		(void)mail_cache_compress(index->cache, ctx->ext_trans);
	}

	if (mail_index_transaction_commit(&ctx->ext_trans, &seq, &offset) < 0) {
		mail_index_sync_end(&ctx);
		return -1;
	}

	/* refresh the mapping with newly committed external transactions
	   and the synced expunges. sync using file handler here so that the
	   expunge handlers get called. */
	if (mail_index_map(ctx->index, MAIL_INDEX_SYNC_HANDLER_FILE,
			   &lock_id) <= 0) {
		// FIXME: handle ret=0 specially?
		// FIXME: do we really need to return failure?
		ret = -1;
	}

	/* FIXME: create a better rule? */
	want_rotate = mail_transaction_log_want_rotate(index->log);
	diff = index->map->hdr.log_file_index_int_offset -
		index->last_read_log_file_index_offset;
	if (ret == 0 && (diff > 1024 || want_rotate))
		mail_index_write(index, want_rotate);
	mail_index_sync_end(_ctx);
	return ret;
}

void mail_index_sync_rollback(struct mail_index_sync_ctx **ctx)
{
	if ((*ctx)->ext_trans != NULL)
		mail_index_transaction_rollback(&(*ctx)->ext_trans);
	mail_index_sync_end(ctx);
}

void mail_index_sync_flags_apply(const struct mail_index_sync_rec *sync_rec,
				 uint8_t *flags)
{
	i_assert(sync_rec->type == MAIL_INDEX_SYNC_TYPE_FLAGS);

	*flags = (*flags & ~sync_rec->remove_flags) | sync_rec->add_flags;
}

bool mail_index_sync_keywords_apply(const struct mail_index_sync_rec *sync_rec,
				    ARRAY_TYPE(keyword_indexes) *keywords)
{
	const unsigned int *keyword_indexes;
	unsigned int idx = sync_rec->keyword_idx;
	unsigned int i, count;

	keyword_indexes = array_get(keywords, &count);
	switch (sync_rec->type) {
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		for (i = 0; i < count; i++) {
			if (keyword_indexes[i] == idx)
				return FALSE;
		}

		array_append(keywords, &idx, 1);
		return TRUE;
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
		for (i = 0; i < count; i++) {
			if (keyword_indexes[i] == idx) {
				array_delete(keywords, i, 1);
				return TRUE;
			}
		}
		return FALSE;
	case MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET:
		if (array_count(keywords) == 0)
			return FALSE;

		array_clear(keywords);
		return TRUE;
	default:
		i_unreached();
		return FALSE;
	}
}

void mail_index_sync_set_corrupted(struct mail_index_sync_map_ctx *ctx,
				   const char *fmt, ...)
{
	const char *error;
	va_list va;

	va_start(va, fmt);
	t_push();
	error = t_strdup_vprintf(fmt, va);
	if (ctx->type == MAIL_INDEX_SYNC_HANDLER_FILE) {
		mail_transaction_log_view_set_corrupted(ctx->view->log_view,
							"%s", error);
	} else {
		mail_index_set_error(ctx->view->index,
			"View synchronization from transaction log "
			"for index %s failed: %s", ctx->view->index->filepath,
			error);
	}
	t_pop();
	va_end(va);
}
