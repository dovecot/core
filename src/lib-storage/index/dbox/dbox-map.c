/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ostream.h"
#include "dbox-storage.h"
#include "dbox-file.h"
#include "dbox-map.h"

#define MAX_BACKWARDS_LOOKUPS 10

struct dbox_mail_index_map_header {
	uint32_t highest_file_id;
};

struct dbox_mail_index_map_record {
	uint32_t file_id;
	uint32_t offset;
	uint32_t size;
};

struct dbox_map {
	struct dbox_storage *storage;
	struct mail_index *index;
	struct mail_index_view *view;

	uint32_t map_ext_id, ref_ext_id;
	ARRAY_TYPE(seq_range) ref0_file_ids;
};

struct dbox_map_append {
	struct dbox_file *file;
	uoff_t offset, size;
};

struct dbox_map_append_context {
	struct dbox_mailbox *mbox;
	struct dbox_map *map;

	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;

	ARRAY_DEFINE(files, struct dbox_file *);
	ARRAY_DEFINE(appends, struct dbox_map_append);

	uint32_t first_new_file_id;
	uint32_t orig_next_uid;

	unsigned int files_nonappendable_count;

	unsigned int failed:1;
};

struct dbox_map *dbox_map_init(struct dbox_storage *storage)
{
	struct dbox_map *map;

	map = i_new(struct dbox_map, 1);
	map->storage = storage;
	map->index = mail_index_alloc(storage->storage_dir,
				      DBOX_GLOBAL_INDEX_PREFIX);
	map->map_ext_id = mail_index_ext_register(map->index, "map",
				sizeof(struct dbox_mail_index_map_header),
				sizeof(struct dbox_mail_index_map_record),
				sizeof(uint32_t));
	map->ref_ext_id = mail_index_ext_register(map->index, "ref", 0,
				sizeof(uint16_t), sizeof(uint16_t));
	return map;
}

void dbox_map_deinit(struct dbox_map **_map)
{
	struct dbox_map *map = *_map;

	*_map = NULL;

	if (array_is_created(&map->ref0_file_ids))
		array_free(&map->ref0_file_ids);
	if (map->view != NULL)
		mail_index_view_close(&map->view);
	mail_index_free(&map->index);
	i_free(map);
}

static int dbox_map_open(struct dbox_map *map, bool create)
{
	struct mail_storage *storage = &map->storage->storage;
	enum mail_index_open_flags open_flags;
	int ret;

	if (map->view != NULL) {
		/* already opened */
		return 1;
	}

	open_flags = index_storage_get_index_open_flags(storage);
	if (create)
		open_flags |= MAIL_INDEX_OPEN_FLAG_CREATE;

	ret = mail_index_open(map->index, open_flags, storage->lock_method);
	if (ret <= 0) {
		mail_storage_set_internal_error(storage);
		mail_index_reset_error(map->index);
		return ret;
	}

	map->view = mail_index_view_open(map->index);
	return 1;
}

static int dbox_map_refresh(struct dbox_map *map)
{
	struct mail_index_view_sync_ctx *ctx;
	bool delayed_expunges;

	if (mail_index_refresh(map->view->index) < 0) {
		mail_storage_set_internal_error(&map->storage->storage);
		mail_index_reset_error(map->index);
		return -1;
	}
	ctx = mail_index_view_sync_begin(map->view,
				MAIL_INDEX_VIEW_SYNC_FLAG_FIX_INCONSISTENT);
	if (mail_index_view_sync_commit(&ctx, &delayed_expunges) < 0) {
		mail_storage_set_internal_error(&map->storage->storage);
		mail_index_reset_error(map->index);
		return -1;
	}
	return 0;
}

static int dbox_map_lookup_seq(struct dbox_map *map, uint32_t seq,
			       uint32_t *file_id_r, uoff_t *offset_r,
			       uoff_t *size_r)
{
	const struct dbox_mail_index_map_record *rec;
	const void *data;
	bool expunged;

	mail_index_lookup_ext(map->view, seq, map->map_ext_id,
			      &data, &expunged);
	rec = data;

	if (rec == NULL || rec->file_id == 0) {
		/* corrupted */
		mail_storage_set_critical(&map->storage->storage,
			"dbox map %s corrupted: file_id=0 for seq=%u",
			map->index->filepath, seq);
		return -1;
	}

	*file_id_r = rec->file_id;
	*offset_r = rec->offset;
	*size_r = rec->size;
	return 0;
}

static int
dbox_map_get_seq(struct dbox_map *map, uint32_t map_uid, uint32_t *seq_r)
{
	int ret;

	if ((ret = dbox_map_open(map, FALSE)) <= 0) {
		/* map doesn't exist or is broken */
		return ret;
	}

	if (!mail_index_lookup_seq(map->view, map_uid, seq_r)) {
		/* not found - try again after a refresh */
		if (dbox_map_refresh(map) < 0)
			return -1;
		if (!mail_index_lookup_seq(map->view, map_uid, seq_r))
			return 0;
	}
	return 1;
}

int dbox_map_lookup(struct dbox_map *map, uint32_t map_uid,
		    uint32_t *file_id_r, uoff_t *offset_r)
{
	uint32_t seq;
	uoff_t size;
	int ret;

	if ((ret = dbox_map_get_seq(map, map_uid, &seq)) <= 0)
		return ret;

	if (dbox_map_lookup_seq(map, seq, file_id_r, offset_r, &size) < 0)
		return 0;
	return 1;
}

int dbox_map_get_file_msgs(struct dbox_map *map, uint32_t file_id,
			   ARRAY_TYPE(dbox_map_file_msg) *recs)
{
	const struct mail_index_header *hdr;
	struct dbox_map_file_msg msg;
	const struct dbox_mail_index_map_record *rec;
	const uint16_t *ref16_p;
	unsigned int seq;
	const void *data;
	bool expunged;

	if (dbox_map_refresh(map) < 0)
		return -1;
	hdr = mail_index_get_header(map->view);

	memset(&msg, 0, sizeof(msg));
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		mail_index_lookup_uid(map->view, seq, &msg.map_uid);

		mail_index_lookup_ext(map->view, seq, map->map_ext_id,
				      &data, &expunged);
		if (data == NULL) {
			// FIXME
			break;
		}
		rec = data;
		if (rec->file_id != file_id)
			continue;

		msg.offset = rec->offset;
		mail_index_lookup_ext(map->view, seq, map->ref_ext_id,
				      &data, &expunged);
		if (data == NULL) {
			// FIXME
			break;
		}
		ref16_p = data;
		msg.refcount = *ref16_p;

		array_append(recs, &msg, 1);
	}
	return 0;
}

const ARRAY_TYPE(seq_range) *dbox_map_get_zero_ref_files(struct dbox_map *map)
{
	const struct mail_index_header *hdr;
	const struct dbox_mail_index_map_record *rec;
	const uint16_t *ref16_p;
	const void *data;
	uint32_t seq;
	bool expunged;
	int ret;

	if (array_is_created(&map->ref0_file_ids))
		array_clear(&map->ref0_file_ids);
	else
		i_array_init(&map->ref0_file_ids, 64);

	if ((ret = dbox_map_open(map, FALSE)) <= 0) {
		/* map doesn't exist or is broken */
		return &map->ref0_file_ids;
	}
	(void)dbox_map_refresh(map);

	hdr = mail_index_get_header(map->view);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		mail_index_lookup_ext(map->view, seq, map->ref_ext_id,
				      &data, &expunged);
		if (data != NULL && !expunged) {
			ref16_p = data;
			if (*ref16_p != 0)
				continue;
		}

		mail_index_lookup_ext(map->view, seq, map->map_ext_id,
				      &data, &expunged);
		if (data != NULL && !expunged) {
			rec = data;
			seq_range_array_add(&map->ref0_file_ids, 0,
					    rec->file_id);
		}
	}
	return &map->ref0_file_ids;
}

int dbox_map_update_refcounts(struct dbox_map *map,
			      const ARRAY_TYPE(seq_range) *map_uids, int diff)
{
	struct mail_index_transaction *trans;
	struct seq_range_iter iter;
	unsigned int i;
	uint32_t map_uid, seq;
	int ret = 0;

	trans = mail_index_transaction_begin(map->view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	seq_range_array_iter_init(&iter, map_uids); i = 0;
	while (seq_range_array_iter_nth(&iter, i++, &map_uid)) {
		if ((ret = dbox_map_get_seq(map, map_uid, &seq)) <= 0) {
			if (ret < 0)
				break;
		} else {
			mail_index_atomic_inc_ext(trans, seq,
						  map->ref_ext_id, diff);
		}
	}
	if (ret < 0) {
		mail_index_transaction_rollback(&trans);
		return -1;
	} else {
		uint32_t log_seq;
		uoff_t log_offset;

		if (mail_index_transaction_commit(&trans, &log_seq,
						  &log_offset) < 0) {
			mail_storage_set_internal_error(&map->storage->storage);
			mail_index_reset_error(map->index);
			return -1;
		}
		return 0;
	}
}

int dbox_map_remove_file_id(struct dbox_map *map, uint32_t file_id)
{
	struct mail_index_transaction *trans;
	const struct mail_index_header *hdr;
	const struct dbox_mail_index_map_record *rec;
	const void *data;
	bool expunged;
	uint32_t seq;
	uint32_t log_seq;
	uoff_t log_offset;

	/* make sure the map is refreshed, otherwise we might be expunging
	   messages that have already been moved to other files. */
	if (dbox_map_refresh(map) < 0)
		return -1;

	trans = mail_index_transaction_begin(map->view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	hdr = mail_index_get_header(map->view);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		mail_index_lookup_ext(map->view, seq, map->map_ext_id,
				      &data, &expunged);
		if (data == NULL)
			break;

		rec = data;
		if (rec->file_id == file_id)
			mail_index_expunge(trans, seq);
	}
	if (mail_index_transaction_commit(&trans, &log_seq, &log_offset) < 0) {
		mail_storage_set_internal_error(&map->storage->storage);
		mail_index_reset_error(map->index);
		return -1;
	}
	return 0;
}

struct dbox_map_append_context *
dbox_map_append_begin_storage(struct dbox_storage *storage)
{
	struct dbox_map_append_context *ctx;
	int ret;

	ctx = i_new(struct dbox_map_append_context, 1);
	ctx->map = storage->map;
	ctx->first_new_file_id = (uint32_t)-1;
	i_array_init(&ctx->files, 64);
	i_array_init(&ctx->appends, 128);

	if ((ret = dbox_map_open(ctx->map, TRUE)) <= 0) {
		i_assert(ret != 0);
		ctx->failed = TRUE;
	}
	/* refresh the map so we can try appending to the latest files */
	(void)dbox_map_refresh(ctx->map);
	return ctx;
}

struct dbox_map_append_context *
dbox_map_append_begin(struct dbox_mailbox *mbox)
{
	struct dbox_map_append_context *ctx;

	ctx = dbox_map_append_begin_storage(mbox->storage);
	ctx->mbox = mbox;
	return ctx;
}

static time_t day_begin_stamp(unsigned int days)
{
	struct tm tm;
	time_t stamp;


	if (days == 0)
		return 0;

	/* get beginning of today */
	tm = *localtime(&ioloop_time);
	tm.tm_hour = 0;
	tm.tm_min = 0;
	tm.tm_sec = 0;
	stamp = mktime(&tm);
	if (stamp == (time_t)-1)
		i_panic("mktime(today) failed");

	return stamp - (3600*24 * (days-1));
}

static bool
dbox_map_file_try_append(struct dbox_map_append_context *ctx,
			 uint32_t file_id, time_t stamp, uoff_t mail_size,
			 struct dbox_file **file_r, struct ostream **output_r,
			 bool *retry_later_r)
{
	struct dbox_map *map = ctx->map;
	struct dbox_storage *storage = map->storage;
	const struct mail_index_header *hdr;
	struct dbox_file *file;
	struct stat st;
	uint32_t seq, tmp_file_id;
	uoff_t tmp_offset, tmp_size, last_msg_offset, last_msg_size, new_size;
	bool deleted, file_too_old = FALSE;
	int ret;

	*file_r = NULL;
	*retry_later_r = FALSE;

	file = dbox_file_init_multi(storage, file_id);
	if (dbox_file_open_or_create(file, &deleted) <= 0 || deleted) {
		dbox_file_unref(&file);
		return TRUE;
	}
	if (file->lock != NULL) {
		/* already locked, we're possibly in the middle of cleaning
		   it up in which case we really don't want to write there. */
		dbox_file_unref(&file);
		return TRUE;
	}

	if (file->create_time < stamp)
		file_too_old = TRUE;
	else if ((ret = dbox_file_try_lock(file)) <= 0) {
		/* locking failed */
		*retry_later_r = ret == 0;
	} else if (stat(file->current_path, &st) < 0) {
		if (errno != ENOENT)
			i_error("stat(%s) failed: %m", file->current_path);
		/* the file was unlinked between opening and locking it. */
	} else if (dbox_map_refresh(map) == 0) {
		/* now that the file is locked and map is refreshed, make sure
		   we still have the last msg's offset. we have to go through
		   the whole map, because existing messages may have already
		   been appended to this file. */
		last_msg_offset = 0;
		hdr = mail_index_get_header(map->view);
		for (seq = 1; seq <= hdr->messages_count; seq++) {
			if (dbox_map_lookup_seq(map, seq, &tmp_file_id,
						&tmp_offset, &tmp_size) < 0)
				break;
			if (tmp_file_id == file->file_id &&
			    last_msg_offset < tmp_offset) {
				last_msg_offset = tmp_offset;
				last_msg_size = tmp_size;
			}
		}

		new_size = last_msg_offset + last_msg_size + mail_size;
		if (seq > hdr->messages_count && last_msg_offset > 0 &&
		    new_size <= storage->rotate_size &&
		    dbox_file_get_append_stream(file, last_msg_offset,
						last_msg_size, output_r) > 0) {
			/* success */
			*file_r = file;
			return TRUE;
		}
	}

	/* failure */
	dbox_file_unlock(file);
	dbox_file_unref(&file);
	return !file_too_old;
}

static bool
dbox_map_is_appending(struct dbox_map_append_context *ctx, uint32_t file_id)
{
	struct dbox_file *const *files;
	unsigned int i, count;

	/* there shouldn't be many files open, don't bother with anything
	   faster. */
	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->file_id == file_id)
			return TRUE;
	}
	return FALSE;
}

static int
dbox_map_find_appendable_file(struct dbox_map_append_context *ctx,
			      uoff_t mail_size, struct dbox_file **file_r,
			      struct ostream **output_r, bool *existing_r)
{
	struct dbox_map *map = ctx->map;
	struct dbox_file *const *files;
	const struct mail_index_header *hdr;
	unsigned int i, count, backwards_lookup_count;
	uint32_t seq, seq1, uid, file_id, min_seen_file_id;
	uoff_t offset, append_offset, size;
	time_t stamp;
	bool retry_later;

	*existing_r = FALSE;

	if (mail_size >= map->storage->rotate_size)
		return 0;

	/* first try to use files already used in this append */
	files = array_get(&ctx->files, &count);
	for (i = count; i > ctx->files_nonappendable_count; i--) {
		if (files[i-1]->output == NULL) {
			/* we already decided we can't append to this */
			continue;
		}

		append_offset = dbox_file_get_next_append_offset(files[i-1]);
		if (append_offset + mail_size <= map->storage->rotate_size &&
		    dbox_file_get_append_stream(files[i-1], 0, 0,
						output_r) > 0) {
			*file_r = files[i-1];
			*existing_r = TRUE;
			return 1;
		}
		/* can't append to this file anymore */
#if 0 /* FIXME: we can't close files, otherwise we lose the lock too early */
		if (files[i-1]->fd != -1) {
			/* avoid wasting fds by closing the file, but not if
			   we're also reading from it. */
			if (dbox_file_flush_append(files[i-1]) < 0)
				return -1;
			dbox_file_unlock(files[i-1]);
			if (files[i-1]->refcount == 1)
				dbox_file_close(files[i-1]);
		}
#endif
	}
	ctx->files_nonappendable_count = count;

	/* try to find an existing appendable file */
	stamp = day_begin_stamp(map->storage->rotate_days);
	hdr = mail_index_get_header(map->view);
	min_seen_file_id = (uint32_t)-1;

	ctx->orig_next_uid = hdr->next_uid;
	backwards_lookup_count = 0;
	for (seq = hdr->messages_count; seq > 0; seq--) {
		if (dbox_map_lookup_seq(map, seq, &file_id, &offset, &size) < 0)
			return -1;
		if (file_id >= min_seen_file_id)
			continue;
		min_seen_file_id = file_id;

		if (++backwards_lookup_count > MAX_BACKWARDS_LOOKUPS) {
			/* we've wasted enough time here */
			break;
		}

		/* first lookup: this should be enough usually, but we can't
		   be sure until after locking. also if messages were recently
		   moved, this message might not be the last one in the file. */
		if (offset + size + mail_size >= map->storage->rotate_size)
			continue;

		if (dbox_map_is_appending(ctx, file_id)) {
			/* already checked this */
			continue;
		}

		mail_index_lookup_uid(map->view, seq, &uid);
		if (!dbox_map_file_try_append(ctx, file_id, stamp, mail_size,
					      file_r, output_r, &retry_later)) {
			/* file is too old. the rest of the files are too. */
			break;
		}
		/* NOTE: we've now refreshed map view. there are no guarantees
		   about sequences anymore. */
		if (*file_r != NULL)
			return 1;
		/* FIXME: use retry_later somehow */
		if (uid == 1 ||
		    !mail_index_lookup_seq_range(map->view, 1, uid-1,
						 &seq1, &seq))
			break;
		seq++;
	}
	return 0;
}

int dbox_map_append_next(struct dbox_map_append_context *ctx, uoff_t mail_size,
			 struct dbox_file **file_r, struct ostream **output_r)
{
	struct dbox_file *file = NULL;
	struct dbox_map_append *append;
	bool existing;
	int ret;

	if (ctx->failed)
		return -1;

	ret = dbox_map_find_appendable_file(ctx, mail_size, &file,
					    output_r, &existing);
	if (ret < 0)
		return -1;

	if (ret == 0) {
		/* create a new file */
		file = ctx->map->storage->rotate_size == 0 ?
			dbox_file_init_single(ctx->mbox, 0) :
			dbox_file_init_multi(ctx->map->storage, 0);
		ret = dbox_file_get_append_stream(file, 0, 0, output_r);
		if (ret <= 0) {
			i_assert(ret < 0);
			(void)unlink(file->current_path);
			dbox_file_unref(&file);
			return -1;
		}
	}

	if (file->single_mbox == NULL) {
		append = array_append_space(&ctx->appends);
		append->file = file;
		append->offset = (*output_r)->offset;
		append->size = (uint32_t)-1;
	}
	if (!existing) {
		i_assert(file->output != NULL);
		array_append(&ctx->files, &file, 1);
	}
	*file_r = file;
	return 0;
}

void dbox_map_append_finish_multi_mail(struct dbox_map_append_context *ctx)
{
	struct dbox_map_append *appends;
	unsigned int count;

	appends = array_get_modifiable(&ctx->appends, &count);
	i_assert(count > 0 && appends[count-1].size == (uint32_t)-1);
	appends[count-1].size = appends[count-1].file->output->offset -
		appends[count-1].offset;
}

static int
dbox_map_get_next_file_id(struct dbox_map *map, struct mail_index_view *view,
			  uint32_t *file_id_r)
{
	const struct dbox_mail_index_map_header *hdr;
	const void *data;
	size_t data_size;

	mail_index_get_header_ext(view, map->map_ext_id, &data, &data_size);
	if (data_size != sizeof(*hdr)) {
		if (data_size != 0) {
			mail_storage_set_critical(&map->storage->storage,
				"dbox map %s corrupted: hdr size=%u",
				map->index->filepath, data_size);
			return -1;
		}
		/* first file */
		*file_id_r = 1;
	} else {
		hdr = data;
		*file_id_r = hdr->highest_file_id + 1;
	}
	return 0;
}

static int dbox_map_assign_file_ids(struct dbox_map_append_context *ctx)
{
	struct dbox_file *const *files;
	unsigned int i, count;
	uint32_t first_file_id, file_id;
	int ret;

	/* start the syncing. we'll need it even if there are no file ids to
	   be assigned. */
	ret = mail_index_sync_begin(ctx->map->index, &ctx->sync_ctx,
				    &ctx->sync_view, &ctx->trans, 0);
	if (ret <= 0) {
		i_assert(ret != 0);
		mail_storage_set_internal_error(&ctx->map->storage->storage);
		mail_index_reset_error(ctx->map->index);
		return -1;
	}

	if (dbox_map_get_next_file_id(ctx->map, ctx->sync_view, &file_id) < 0) {
		mail_index_sync_rollback(&ctx->sync_ctx);
		return -1;
	}

	/* assign file_ids for newly created multi-files */
	first_file_id = file_id;
	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->single_mbox != NULL)
			continue;

		if (files[i]->output != NULL) {
			if (dbox_file_flush_append(files[i]) < 0) {
				ret = -1;
				break;
			}
		}

		if (files[i]->file_id == 0) {
			if (dbox_file_assign_id(files[i], file_id++) < 0) {
				ret = -1;
				break;
			}
		}
	}

	if (ret < 0) {
		/* FIXME: we have to rollback the changes we made */
		mail_index_sync_rollback(&ctx->sync_ctx);
		return -1;
	}

	/* update the highest used file_id */
	if (first_file_id != file_id) {
		file_id--;
		mail_index_update_header_ext(ctx->trans, ctx->map->map_ext_id,
					     0, &file_id, sizeof(file_id));
	}
	return 0;
}

int dbox_map_append_assign_map_uids(struct dbox_map_append_context *ctx,
				    uint32_t *first_map_uid_r,
				    uint32_t *last_map_uid_r)
{
	const struct dbox_map_append *appends;
	const struct mail_index_header *hdr;
	struct dbox_mail_index_map_record rec;
	unsigned int i, count;
	uint32_t seq, first_uid, next_uid;
	uint16_t ref16;
	int ret = 0;

	if (array_count(&ctx->appends) == 0) {
		*first_map_uid_r = 0;
		*last_map_uid_r = 0;
		return 0;
	}

	if (dbox_map_assign_file_ids(ctx) < 0)
		return -1;

	/* append map records to index */
	memset(&rec, 0, sizeof(rec));
	ref16 = 1;
	appends = array_get(&ctx->appends, &count);
	for (i = 0; i < count; i++) {
		i_assert(appends[i].offset <= (uint32_t)-1);
		i_assert(appends[i].size <= (uint32_t)-1);

		rec.file_id = appends[i].file->file_id;
		rec.offset = appends[i].offset;
		rec.size = appends[i].size;

		mail_index_append(ctx->trans, 0, &seq);
		mail_index_update_ext(ctx->trans, seq, ctx->map->map_ext_id,
				      &rec, NULL);
		mail_index_update_ext(ctx->trans, seq, ctx->map->ref_ext_id,
				      &ref16, NULL);
	}

	/* assign map UIDs for appended records */
	hdr = mail_index_get_header(ctx->sync_view);
	first_uid = hdr->next_uid;
	mail_index_append_assign_uids(ctx->trans, first_uid, &next_uid);
	i_assert(next_uid - first_uid == count);

	if (hdr->uid_validity == 0) {
		/* we don't really care about uidvalidity, but it can't be 0 */
		uint32_t uid_validity = ioloop_time;
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, uid_validity),
			&uid_validity, sizeof(uid_validity), TRUE);
	}

	if (mail_index_sync_commit(&ctx->sync_ctx) < 0) {
		mail_storage_set_internal_error(&ctx->map->storage->storage);
		mail_index_reset_error(ctx->map->index);
		return -1;
	}

	*first_map_uid_r = first_uid;
	*last_map_uid_r = next_uid - 1;
	return ret;
}

int dbox_map_append_move(struct dbox_map_append_context *ctx,
			 const ARRAY_TYPE(uint32_t) *map_uids,
			 const ARRAY_TYPE(seq_range) *expunge_map_uids)
{
	const struct dbox_map_append *appends;
	struct dbox_mail_index_map_record rec;
	struct seq_range_iter iter;
	const uint32_t *uids;
	unsigned int i, j, map_uids_count, appends_count;
	uint32_t uid, seq;

	if (dbox_map_assign_file_ids(ctx) < 0)
		return -1;

	memset(&rec, 0, sizeof(rec));
	appends = array_get(&ctx->appends, &appends_count);

	uids = array_get(map_uids, &map_uids_count);
	for (i = j = 0; i < map_uids_count; i++) {
		i_assert(j < appends_count);
		rec.file_id = appends[j].file->file_id;
		rec.offset = appends[j].offset;
		rec.size = appends[j].size;
		j++;

		if (!mail_index_lookup_seq(ctx->sync_view, uids[i], &seq))
			i_unreached();
		mail_index_update_ext(ctx->trans, seq, ctx->map->map_ext_id,
				      &rec, NULL);
	}

	seq_range_array_iter_init(&iter, expunge_map_uids); i = 0;
	while (seq_range_array_iter_nth(&iter, i++, &uid)) {
		if (!mail_index_lookup_seq(ctx->sync_view, uid, &seq))
			i_unreached();
		mail_index_expunge(ctx->trans, seq);
	}

	if (mail_index_sync_commit(&ctx->sync_ctx) < 0) {
		mail_storage_set_internal_error(&ctx->map->storage->storage);
		mail_index_reset_error(ctx->map->index);
		return -1;
	}
	return 0;
}

int dbox_map_append_assign_uids(struct dbox_map_append_context *ctx,
				uint32_t first_uid, uint32_t last_uid)
{
	struct dbox_file *const *files;
	unsigned int i, count;
	uint32_t next_uid = first_uid;

	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->single_mbox == NULL)
			continue;

		if (dbox_file_assign_id(files[i], next_uid++) < 0)
			return -1;
	}
	i_assert(next_uid == last_uid + 1);
	return 0;
}

void dbox_map_append_commit(struct dbox_map_append_context **_ctx)
{
	struct dbox_map_append_context *ctx = *_ctx;
	struct dbox_file **files;
	unsigned int i, count;

	*_ctx = NULL;

	files = array_get_modifiable(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		dbox_file_unlock(files[i]);
		dbox_file_unref(&files[i]);
	}

	array_free(&ctx->appends);
	array_free(&ctx->files);
	i_free(ctx);
}

void dbox_map_append_rollback(struct dbox_map_append_context **_ctx)
{
	struct dbox_map_append_context *ctx = *_ctx;
	struct mail_storage *storage = &ctx->map->storage->storage;
	struct dbox_file *const *files, *file;
	unsigned int i, count;

	*_ctx = NULL;

	files = array_get(&ctx->files, &count);
	for (i = 0; i < count; i++) {
		file = files[i];

		if (file->output != NULL) {
			/* flush before truncating */
			(void)o_stream_flush(file->output);
		}

		if (file->file_id != 0) {
			/* FIXME: truncate? */
		} else {
			if (unlink(file->current_path) < 0) {
				mail_storage_set_critical(storage,
					"unlink(%s) failed: %m",
					file->current_path);
			}
		}
		dbox_file_unref(&file);
	}
	array_free(&ctx->appends);
	array_free(&ctx->files);
	i_free(ctx);
}
