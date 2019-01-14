/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "hash.h"
#include "dbox-attachment.h"
#include "mdbox-storage.h"
#include "mdbox-storage-rebuild.h"
#include "mdbox-file.h"
#include "mdbox-map.h"
#include "mdbox-sync.h"

#include <dirent.h>

/*
   Altmoving works like:

   1. Message's DBOX_INDEX_FLAG_ALT flag is changed. This is caught by mdbox
      code and map UID's alt-refcount is updated. It won't be written to disk.
   2. mdbox_purge() is called, which checks if map UID's refcount equals
      to its alt-refcount. If it does, it's moved to alt storage. Moving to
      primary storage is done if _ALT flag was removed from any message.
*/

enum mdbox_msg_action {
	MDBOX_MSG_ACTION_MOVE_TO_ALT = 1,
	MDBOX_MSG_ACTION_MOVE_FROM_ALT
};

struct mdbox_purge_context {
	pool_t pool;
	struct mdbox_storage *storage;

	uint32_t lowest_primary_file_id;
	/* list of file_ids that exist in primary storage. this list is looked
	   up while there is no locking, so it may not be accurate anymore by
	   the time it's used. */
	ARRAY_TYPE(seq_range) primary_file_ids;
	/* list of file_ids that we need to purge */
	ARRAY_TYPE(seq_range) purge_file_ids;

	/* uint32_t map_uid => enum mdbox_msg_action action */
	HASH_TABLE(void *, void *) altmoves;
	bool have_altmoves;

	struct mdbox_map_atomic_context *atomic;
	struct mdbox_map_append_context *append_ctx;
};

static int mdbox_map_file_msg_offset_cmp(const struct mdbox_map_file_msg *m1,
					 const struct mdbox_map_file_msg *m2)
{
	if (m1->offset < m2->offset)
		return -1;
	else if (m1->offset > m2->offset)
		return 1;
	else
		return 0;
}

static int
mdbox_file_read_metadata_hdr(struct dbox_file *file,
			     struct dbox_metadata_header *meta_hdr_r)
{
	const unsigned char *data;
	size_t size;
	int ret;

	ret = i_stream_read_bytes(file->input, &data, &size,
				  sizeof(*meta_hdr_r));
	if (ret <= 0) {
		i_assert(ret == -1);
		if (file->input->stream_errno == 0) {
			dbox_file_set_corrupted(file, "missing metadata");
			return 0;
		}
		mail_storage_set_critical(&file->storage->storage,
			"read(%s) failed: %s", file->cur_path,
			i_stream_get_error(file->input));
		return -1;
	}

	memcpy(meta_hdr_r, data, sizeof(*meta_hdr_r));
	if (memcmp(meta_hdr_r->magic_post, DBOX_MAGIC_POST,
		   sizeof(meta_hdr_r->magic_post)) != 0) {
		dbox_file_set_corrupted(file, "invalid metadata magic");
		return 0;
	}
	i_stream_skip(file->input, sizeof(*meta_hdr_r));
	return 1;
}

static int
mdbox_file_metadata_copy(struct dbox_file *file, struct ostream *output)
{
	struct dbox_metadata_header meta_hdr;
	const char *line;
	size_t buf_size;
	int ret;

	if ((ret = mdbox_file_read_metadata_hdr(file, &meta_hdr)) <= 0)
		return ret;

	o_stream_nsend(output, &meta_hdr, sizeof(meta_hdr));
	buf_size = i_stream_get_max_buffer_size(file->input);
	/* use unlimited line length for metadata */
	i_stream_set_max_buffer_size(file->input, (size_t)-1);
	while ((line = i_stream_read_next_line(file->input)) != NULL) {
		if (*line == '\0') {
			/* end of metadata */
			break;
		}
		o_stream_nsend_str(output, line);
		o_stream_nsend(output, "\n", 1);
	}
	i_stream_set_max_buffer_size(file->input, buf_size);

	if (line == NULL) {
		dbox_file_set_corrupted(file, "missing end-of-metadata line");
		return 0;
	}
	o_stream_nsend(output, "\n", 1);
	return 1;
}

static int
mdbox_metadata_get_extrefs(struct dbox_file *file, pool_t ext_refs_pool,
			   ARRAY_TYPE(mail_attachment_extref) *extrefs)
{
	struct dbox_metadata_header meta_hdr;
	const char *line;
	size_t buf_size;
	int ret;

	/* skip and ignore the header */
	if ((ret = mdbox_file_read_metadata_hdr(file, &meta_hdr)) <= 0)
		return ret;

	buf_size = i_stream_get_max_buffer_size(file->input);
	/* use unlimited line length for metadata */
	i_stream_set_max_buffer_size(file->input, (size_t)-1);
	while ((line = i_stream_read_next_line(file->input)) != NULL) {
		if (*line == '\0') {
			/* end of metadata */
			break;
		}
		if (*line == DBOX_METADATA_EXT_REF) T_BEGIN {
			if (!index_attachment_parse_extrefs(line+1, ext_refs_pool,
							    extrefs)) {
				i_warning("%s: Ignoring corrupted extref: %s",
					  file->cur_path, line);
			}
		} T_END;
	}
	i_stream_set_max_buffer_size(file->input, buf_size);

	if (line == NULL) {
		dbox_file_set_corrupted(file, "missing end-of-metadata line");
		return 0;
	}
	return 1;
}

static bool
mdbox_purge_want_altpath(struct mdbox_purge_context *ctx,
			 struct dbox_file *file, uint32_t map_uid)
{
	enum mdbox_msg_action action;
	void *value;

	if (dbox_file_is_in_alt(file))
		return TRUE;

	if (!ctx->have_altmoves)
		return FALSE;

	value = hash_table_lookup(ctx->altmoves, POINTER_CAST(map_uid));
	action = POINTER_CAST_TO(value, enum mdbox_msg_action);
	return action == MDBOX_MSG_ACTION_MOVE_TO_ALT;
}

static int
mdbox_purge_save_msg(struct mdbox_purge_context *ctx, struct dbox_file *file,
		     const struct mdbox_map_file_msg *msg)
{
	struct dbox_file_append_context *out_file_append;
	struct istream *input;
	struct ostream *output;
	enum mdbox_map_append_flags append_flags;
	uoff_t msg_size;
	int ret;

	if (ctx->append_ctx == NULL)
		ctx->append_ctx = mdbox_map_append_begin(ctx->atomic);

	append_flags = !mdbox_purge_want_altpath(ctx, file, msg->map_uid) ? 0 :
		DBOX_MAP_APPEND_FLAG_ALT;
	msg_size = file->msg_header_size + file->cur_physical_size;
	if (mdbox_map_append_next(ctx->append_ctx, file->cur_physical_size,
				  append_flags, &out_file_append, &output) < 0)
		return -1;

	i_assert(file != out_file_append->file);

	input = i_stream_create_limit(file->input, msg_size);
	o_stream_nsend_istream(output, input);
	if (o_stream_flush(output) < 0) {
		mail_storage_set_critical(&file->storage->storage,
					  "write(%s) failed: %s",
					  out_file_append->file->cur_path,
					  o_stream_get_error(output));
		ret = -1;
	} else if (input->v_offset != msg_size) {
		i_assert(input->v_offset < msg_size);
		i_assert(i_stream_read_eof(file->input));

		dbox_file_set_corrupted(file, "truncated message at EOF");
		ret = 0;
	} else {
		ret = 1;
	}
	i_stream_unref(&input);

	if (ret > 0) {
		/* copy metadata */
		if ((ret = mdbox_file_metadata_copy(file, output)) <= 0)
			return ret;

		mdbox_map_append_finish(ctx->append_ctx);
	}
	return ret;
}

static int
mdbox_file_purge_check_refcounts(struct mdbox_purge_context *ctx,
				 const ARRAY_TYPE(mdbox_map_file_msg) *msgs_arr)
{
	struct mdbox_map *map = ctx->storage->map;
	struct mdbox_map_mail_index_record rec;
	uint16_t refcount;
	const struct mdbox_map_file_msg *msgs;
	unsigned int i, count;
	int ret;

	if (mdbox_map_atomic_lock(ctx->atomic, "purging check") < 0)
		return -1;

	msgs = array_get(msgs_arr, &count);
	for (i = 0; i < count; i++) {
		if (msgs[i].refcount != 0)
			continue;

		ret = mdbox_map_lookup_full(map, msgs[i].map_uid, &rec,
					    &refcount);
		if (ret <= 0) {
			if (ret < 0)
				return -1;
			mdbox_map_set_corrupted(map,
				"Purging unexpectedly lost map_uid=%u",
				msgs[i].map_uid);
			return -1;
		}
		if (refcount > 0)
			return 0;
	}
	return 1;
}

static int
mdbox_purge_attachments(struct mdbox_purge_context *ctx,
			const ARRAY_TYPE(mail_attachment_extref) *extrefs_arr)
{
	struct dbox_storage *storage = &ctx->storage->storage;
	const struct mail_attachment_extref *extref;
	int ret = 0;

	array_foreach(extrefs_arr, extref) {
		if (index_attachment_delete(&storage->storage,
					    storage->attachment_fs,
					    extref->path) < 0)
			ret = -1;
	}
	return ret;
}

static int
mdbox_file_purge(struct mdbox_purge_context *ctx, struct dbox_file *file,
		 uint32_t file_id)
{
	struct mdbox_storage *dstorage = (struct mdbox_storage *)file->storage;
	struct stat st;
	ARRAY_TYPE(mdbox_map_file_msg) msgs_arr;
	const struct mdbox_map_file_msg *msgs;
	ARRAY_TYPE(seq_range) expunged_map_uids;
	ARRAY_TYPE(uint32_t) copied_map_uids;
	ARRAY_TYPE(mail_attachment_extref) ext_refs;
	pool_t ext_refs_pool;
	unsigned int i, count;
	uoff_t offset;
	int ret;

	i_assert(ctx->atomic == NULL);
	i_assert(ctx->append_ctx == NULL);

	if ((ret = dbox_file_try_lock(file)) <= 0)
		return ret;

	/* make sure the file still exists. another process may have already
	   deleted it. */
	if (stat(file->cur_path, &st) < 0) {
		dbox_file_unlock(file);
		if (errno == ENOENT)
			return 0;

		mail_storage_set_critical(&file->storage->storage,
			"stat(%s) failed: %m", file->cur_path);
		return -1;
	}

	/* get list of map UIDs that exist in this file (again has to be done
	   after locking) */
	i_array_init(&msgs_arr, 128);
	if (mdbox_map_get_file_msgs(dstorage->map, file_id,
				    &msgs_arr) < 0) {
		array_free(&msgs_arr);
		dbox_file_unlock(file);
		return -1;
	}
	/* sort messages by their offset */
	array_sort(&msgs_arr, mdbox_map_file_msg_offset_cmp);

	ext_refs_pool = pool_alloconly_create("mdbox purge ext refs", 1024);
	ctx->atomic = mdbox_map_atomic_begin(ctx->storage->map);
	msgs = array_get(&msgs_arr, &count);
	i_array_init(&ext_refs, 32);
	i_array_init(&copied_map_uids, I_MIN(count, 1));
	i_array_init(&expunged_map_uids, I_MIN(count, 1));
	offset = file->file_header_size;
	for (i = 0; i < count; i++) {
		if ((ret = dbox_file_seek(file, offset)) <= 0)
			break;

		if (msgs[i].offset != offset) {
			/* map doesn't match file's actual contents */
			dbox_file_set_corrupted(file,
				"purging found mismatched offsets "
				"(%"PRIuUOFF_T" vs %u, %u/%u)",
				offset, msgs[i].offset, i, count);
			ret = 0;
			break;
		}

		if (msgs[i].refcount == 0) {
			/* skip over expunged message */
			i_stream_seek(file->input, offset +
				      file->msg_header_size +
				      file->cur_physical_size);
			/* skip metadata */
			ret = mdbox_metadata_get_extrefs(file, ext_refs_pool,
							 &ext_refs);
			if (ret <= 0)
				break;
			seq_range_array_add(&expunged_map_uids,
					    msgs[i].map_uid);
		} else {
			/* non-expunged message. write it to output file. */
			i_stream_seek(file->input, offset);
			ret = mdbox_purge_save_msg(ctx, file, &msgs[i]);
			if (ret <= 0)
				break;
			array_push_back(&copied_map_uids, &msgs[i].map_uid);
		}
		offset = file->input->v_offset;
	}
	if (offset != (uoff_t)st.st_size && ret > 0) {
		/* file has more messages than what map tells us */
		dbox_file_set_corrupted(file,
			"more messages available than in map "
			"(%"PRIuUOFF_T" < %"PRIuUOFF_T")", offset, st.st_size);
		ret = 0;
	}
	if (ret > 0 && ctx->append_ctx != NULL) {
		/* flush writes before locking the map */
		if (mdbox_map_append_flush(ctx->append_ctx) < 0)
			ret = -1;
	}

	if (ret <= 0)
		ret = -1;
	else {
		/* it's possible that one of the messages we purged was
		   just copied to another mailbox. the only way to prevent that
		   would be to keep map locked during the purge, but that could
		   keep it locked for too long. instead we'll check here if
		   there are such copies, and if there are cancel this file's
		   purge. */
		ret = mdbox_file_purge_check_refcounts(ctx, &msgs_arr);
	}
	array_free(&msgs_arr); msgs = NULL;

	if (ret <= 0) {
		/* failed */
	} else if (ctx->append_ctx == NULL) {
		/* everything purged from this file */
		ret = 1;
	} else {
		/* assign new file_id + offset to moved messages */
		if (mdbox_map_append_move(ctx->append_ctx, &copied_map_uids,
					  &expunged_map_uids) < 0 ||
		    mdbox_map_append_commit(ctx->append_ctx) < 0)
			ret = -1;
		else
			ret = 1;
	}
	if (ctx->append_ctx != NULL)
		mdbox_map_append_free(&ctx->append_ctx);
	(void)mdbox_map_atomic_finish(&ctx->atomic);

	/* unlink only after unlocking map, so readers don't see it
	   temporarily vanished */
	if (ret > 0) {
		(void)dbox_file_unlink(file);
		if (mdbox_map_remove_file_id(ctx->storage->map, file_id) < 0)
			ret = -1;
	} else {
		dbox_file_unlock(file);
	}
	array_free(&copied_map_uids);
	array_free(&expunged_map_uids);

	(void)mdbox_purge_attachments(ctx, &ext_refs);
	array_free(&ext_refs);
	pool_unref(&ext_refs_pool);
	return ret;
}

void mdbox_purge_alt_flag_change(struct mail *mail, bool move_to_alt)
{
	struct mdbox_mailbox *mbox = MDBOX_MAILBOX(mail->box);
	ARRAY_TYPE(uint32_t) *dest;
	uint32_t map_uid;

	/* we'll assume here that alt flag won't be changed multiple times
	   for the same mail. it shouldn't happen with current code, and
	   checking for it would just slow down the code.

	   so the way it works currently is just that map_uids are added to
	   an array, which is later sorted and processed further. note that
	   it's still possible that the same map_uid exists in the array
	   multiple times. */
	if (mdbox_mail_lookup(mbox, mbox->box.view, mail->seq, &map_uid) < 0)
		return;

	dest = move_to_alt ? &mbox->storage->move_to_alt_map_uids :
		&mbox->storage->move_from_alt_map_uids;

	if (!array_is_created(dest))
		i_array_init(dest, 256);
	array_push_back(dest, &map_uid);
}

static struct mdbox_purge_context *
mdbox_purge_alloc(struct mdbox_storage *storage)
{
	struct mdbox_purge_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create("mdbox purge context", 1024*32);
	ctx = p_new(pool, struct mdbox_purge_context, 1);
	ctx->pool = pool;
	ctx->storage = storage;
	ctx->lowest_primary_file_id = (uint32_t)-1;
	i_array_init(&ctx->primary_file_ids, 64);
	i_array_init(&ctx->purge_file_ids, 64);
	hash_table_create_direct(&ctx->altmoves, pool, 0);
	return ctx;
}

static void mdbox_purge_free(struct mdbox_purge_context **_ctx)
{
	struct mdbox_purge_context *ctx = *_ctx;

	*_ctx = NULL;

	hash_table_destroy(&ctx->altmoves);
	array_free(&ctx->primary_file_ids);
	array_free(&ctx->purge_file_ids);
	pool_unref(&ctx->pool);
}

static int mdbox_purge_get_primary_files(struct mdbox_purge_context *ctx)
{
	struct mdbox_storage *dstorage = ctx->storage;
	struct mail_storage *storage = &dstorage->storage.storage;
	DIR *dir;
	struct dirent *d;
	string_t *path;
	unsigned int file_id;
	size_t dir_len;
	int ret = 0;

	if (!array_is_created(&dstorage->move_to_alt_map_uids) &&
	    !array_is_created(&dstorage->move_from_alt_map_uids)) {
		/* we don't need to do alt moving, don't bother getting list
		   of primary files */
		return 0;
	}

	dir = opendir(dstorage->storage_dir);
	if (dir == NULL) {
		if (errno == ENOENT) {
			/* no storage directory at all yet */
			return 0;
		}
		mail_storage_set_critical(storage,
			"opendir(%s) failed: %m", dstorage->storage_dir);
		return -1;
	}

	path = t_str_new(256);
	str_append(path, dstorage->storage_dir);
	str_append_c(path, '/');
	dir_len = str_len(path);

	for (errno = 0; (d = readdir(dir)) != NULL; errno = 0) {
		if (!str_begins(d->d_name, MDBOX_MAIL_FILE_PREFIX))
			continue;
		if (str_to_uint32(d->d_name + strlen(MDBOX_MAIL_FILE_PREFIX),
				  &file_id) < 0)
			continue;

		str_truncate(path, dir_len);
		str_append(path, d->d_name);
		seq_range_array_add(&ctx->primary_file_ids, file_id);
	}
	if (array_count(&ctx->primary_file_ids) > 0) {
		const struct seq_range *range =
			array_front(&ctx->primary_file_ids);
		ctx->lowest_primary_file_id = range[0].seq1;
	}
	if (errno != 0) {
		mail_storage_set_critical(storage,
			"readdir(%s) failed: %m", dstorage->storage_dir);
		ret = -1;
	}
	if (closedir(dir) < 0) {
		mail_storage_set_critical(storage,
			"closedir(%s) failed: %m", dstorage->storage_dir);
		ret = -1;
	}
	return ret;
}

static int uint32_t_cmp(const uint32_t *u1, const uint32_t *u2)
{
	if (*u1 < *u2)
		return -1;
	if (*u1 > *u2)
		return 1;
	return 0;
}

static int mdbox_altmove_add_files(struct mdbox_purge_context *ctx)
{
	struct mdbox_storage *dstorage = ctx->storage;
	const uint32_t *map_uids;
	unsigned int i, count, alt_refcount = 0;
	struct mdbox_map_mail_index_record cur_rec;
	enum mdbox_msg_action action;
	uint32_t cur_map_uid;
	uint16_t cur_refcount = 0;
	uoff_t offset;
	int ret = 0;

	/* first add move-to-alt actions */
	if (array_is_created(&dstorage->move_to_alt_map_uids)) {
		array_sort(&dstorage->move_to_alt_map_uids, uint32_t_cmp);
		map_uids = array_get(&dstorage->move_to_alt_map_uids, &count);
	} else {
		map_uids = NULL;
		count = 0;
	}
	cur_map_uid = 0;
	for (i = 0; i < count; i++) {
		if (cur_map_uid != map_uids[i]) {
			cur_map_uid = map_uids[i];
			if (mdbox_map_lookup_full(dstorage->map, cur_map_uid,
						  &cur_rec, &cur_refcount) < 0) {
				cur_refcount = (uint16_t)-1;
				ret = -1;
			}
			alt_refcount = 1;
		} else {
			alt_refcount++;
		}

		if (alt_refcount == cur_refcount &&
		    seq_range_exists(&ctx->primary_file_ids, cur_rec.file_id)) {
			/* all instances marked as moved to alt storage */
			action = MDBOX_MSG_ACTION_MOVE_TO_ALT;
			hash_table_insert(ctx->altmoves,
					  POINTER_CAST(cur_map_uid),
					  POINTER_CAST(action));
			seq_range_array_add(&ctx->purge_file_ids,
					    cur_rec.file_id);
		}
	}

	/* next add move-from-alt actions. they override move-to-alt actions
	   in case there happen to be any conflicts (shouldn't). only a single
	   move-from-alt record is needed to do the move. */
	if (array_is_created(&dstorage->move_from_alt_map_uids))
		map_uids = array_get(&dstorage->move_from_alt_map_uids, &count);
	else {
		map_uids = NULL;
		count = 0;
	}
	cur_map_uid = 0;
	for (i = 0; i < count; i++) {
		if (cur_map_uid == map_uids[i])
			continue;
		cur_map_uid = map_uids[i];

		if (mdbox_map_lookup(dstorage->map, cur_map_uid,
				     &cur_rec.file_id, &offset) < 0) {
			ret = -1;
			continue;
		}
		if (seq_range_exists(&ctx->primary_file_ids, cur_rec.file_id)) {
			/* already in primary storage */
			continue;
		}

		action = MDBOX_MSG_ACTION_MOVE_FROM_ALT;
		hash_table_update(ctx->altmoves, POINTER_CAST(cur_map_uid),
				  POINTER_CAST(action));
		seq_range_array_add(&ctx->purge_file_ids, cur_rec.file_id);
	}
	ctx->have_altmoves = hash_table_count(ctx->altmoves) > 0;
	return ret;
}

int mdbox_purge(struct mail_storage *_storage)
{
	struct mdbox_storage *storage = (struct mdbox_storage *)_storage;
	struct mdbox_purge_context *ctx;
	struct dbox_file *file;
	struct seq_range_iter iter;
	unsigned int i = 0;
	uint32_t file_id;
	bool deleted;
	int ret;

	ctx = mdbox_purge_alloc(storage);
	ret = mdbox_map_get_zero_ref_files(storage->map, &ctx->purge_file_ids);
	if (storage->alt_storage_dir != NULL) {
		if (mdbox_purge_get_primary_files(ctx) < 0)
			ret = -1;
		else {
			/* add files that can be altmoved */
			if (mdbox_altmove_add_files(ctx) < 0)
				ret = -1;
		}
	}

	seq_range_array_iter_init(&iter, &ctx->purge_file_ids); i = 0;
	while (ret == 0 &&
	       seq_range_array_iter_nth(&iter, i++, &file_id)) T_BEGIN {
		file = mdbox_file_init(storage, file_id);
		if (dbox_file_open(file, &deleted) > 0 && !deleted) {
			if (mdbox_file_purge(ctx, file, file_id) < 0)
				ret = -1;
		} else {
			if (mdbox_map_remove_file_id(storage->map, file_id) < 0)
				ret = -1;
		}
		dbox_file_unref(&file);
	} T_END;
	mdbox_purge_free(&ctx);

	if (storage->corrupted) {
		/* purging found corrupted files */
		(void)mdbox_storage_rebuild(storage);
		ret = -1;
	}
	return ret;
}
