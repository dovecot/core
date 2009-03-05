/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "dbox-storage.h"
#include "dbox-file.h"
#include "dbox-map.h"
#include "dbox-sync.h"

struct dbox_mail_move {
	struct dbox_file *file;
	uint32_t offset;
};
ARRAY_DEFINE_TYPE(dbox_mail_move, struct dbox_mail_move);

static int dbox_sync_file_unlink(struct dbox_file *file)
{
	const char *path, *primary_path;
	bool alt = FALSE;

	path = primary_path = dbox_file_get_primary_path(file);
	while (unlink(path) < 0) {
		if (errno != ENOENT) {
			mail_storage_set_critical(&file->storage->storage,
				"unlink(%s) failed: %m", path);
			return -1;
		}
		if (file->storage->alt_storage_dir == NULL || alt) {
			/* not found */
			i_warning("dbox: File unexpectedly lost: %s/%s",
				  primary_path, file->fname);
			return 0;
		}

		/* try the alternative path */
		path = dbox_file_get_alt_path(file);
		alt = TRUE;
	}
	return 1;
}

int dbox_sync_file_cleanup(struct dbox_file *file)
{
	struct dbox_file *out_file;
	struct istream *input;
	struct ostream *output = NULL;
	struct dbox_metadata_header meta_hdr;
	struct dbox_map_append_context *append_ctx;
	ARRAY_TYPE(dbox_map_file_msg) msgs_arr;
	const struct dbox_map_file_msg *msgs;
	ARRAY_TYPE(seq_range) copied_map_uids, expunged_map_uids;
	unsigned int i, count;
	uoff_t physical_size, msg_size;
	const unsigned char *data;
	size_t size;
	const char *line;
	bool expunged;
	int ret;

	if ((ret = dbox_file_try_lock(file)) <= 0)
		return ret;

	append_ctx = dbox_map_append_begin_storage(file->storage);

	t_array_init(&msgs_arr, 128);
	if (dbox_map_get_file_msgs(file->storage->map, file->file_id,
				   &msgs_arr) < 0) {
		// FIXME
		return -1;
	}
	msgs = array_get(&msgs_arr, &count);
	t_array_init(&copied_map_uids, I_MIN(count, 1));
	t_array_init(&expunged_map_uids, I_MIN(count, 1));
	for (i = 0; i < count; i++) {
		if (msgs[i].refcount == 0) {
			seq_range_array_add(&expunged_map_uids, 0,
					    msgs[i].map_uid);
			continue;
		}
		ret = dbox_file_get_mail_stream(file, msgs[i].offset,
						&physical_size,
						NULL, &expunged);
		if (ret <= 0) {
			/* FIXME: handle corruption? */
			ret = -1;
			break;
		}

		/* non-expunged message. write it to output file. */
		if (dbox_map_append_next(append_ctx, physical_size,
					 &out_file, &output) < 0) {
			// FIXME
			ret = -1;
			break;
		}
		i_assert(file->file_id != out_file->file_id);

		i_stream_seek(file->input, msgs[i].offset);
		msg_size = file->msg_header_size + physical_size;
		input = i_stream_create_limit(file->input, msg_size);
		ret = o_stream_send_istream(output, input);
		i_stream_unref(&input);
		if (ret != (off_t)(file->msg_header_size + physical_size)) {
			// FIXME
			ret = -1;
			break;
		}

		/* copy metadata */
		i_stream_seek(file->input, msgs[i].offset + msg_size);
		ret = i_stream_read_data(file->input, &data, &size,
					 sizeof(meta_hdr));
		if (ret <= 0) {
			// FIXME
			i_assert(ret != -2);
			ret = -1;
			break;
		}
		memcpy(&meta_hdr, data, sizeof(meta_hdr));
		if (memcmp(meta_hdr.magic_post, DBOX_MAGIC_POST,
			   sizeof(meta_hdr.magic_post)) != 0) {
			// FIXME
			ret = -1;
			break;
		}
		i_stream_skip(file->input, sizeof(meta_hdr));
		o_stream_send(output, &meta_hdr, sizeof(meta_hdr));
		while ((line = i_stream_read_next_line(file->input)) != NULL) {
			if (*line == DBOX_METADATA_OLDV1_SPACE || *line == '\0') {
				/* end of metadata */
				break;
			}
			o_stream_send_str(output, line);
			o_stream_send(output, "\n", 1);
		}
		if (line == NULL) {
			// FIXME
			ret = -1;
			break;
		}
		o_stream_send(output, "\n", 1);
		dbox_map_append_finish_multi_mail(append_ctx);
		seq_range_array_add(&copied_map_uids, 0, msgs[i].map_uid);
	}

	if (ret < 0) {
		dbox_map_append_rollback(&append_ctx);
		return -1;
	}

	if (output == NULL) {
		/* everything expunged in this file, unlink it */
		dbox_map_append_rollback(&append_ctx);
		if (dbox_sync_file_unlink(file) < 0)
			return -1;
		return 0;
	}

	/* assign new file_id + offset to moved messages */
	if (dbox_map_append_move(append_ctx, &copied_map_uids,
				 &expunged_map_uids) < 0) {
		// FIXME
		return -1;
	}
	dbox_map_append_commit(&append_ctx);
	(void)dbox_sync_file_unlink(file);
	return 1;
}

static void
dbox_sync_file_move_if_needed(struct dbox_file *file,
			      const struct dbox_sync_file_entry *entry)
{
	if (!entry->move_to_alt && !entry->move_from_alt)
		return;

	if (entry->move_to_alt != file->alt_path) {
		/* move the file. if it fails, nothing broke so
		   don't worry about it. */
		(void)dbox_file_move(file, !file->alt_path);
	}
}

static void
dbox_sync_mark_expunges(struct dbox_sync_context *ctx,
			const ARRAY_TYPE(seq_range) *seqs)
{
	struct mailbox *box = &ctx->mbox->ibox.box;
	struct seq_range_iter iter;
	unsigned int i;
	uint32_t seq, uid;

	seq_range_array_iter_init(&iter, seqs); i = 0;
	while (seq_range_array_iter_nth(&iter, i++, &seq)) {
		mail_index_expunge(ctx->trans, seq);
		if (box->v.sync_notify != NULL) {
			mail_index_lookup_uid(ctx->sync_view, seq, &uid);
			box->v.sync_notify(box, uid, MAILBOX_SYNC_TYPE_EXPUNGE);
		}
	}
}

int dbox_sync_file(struct dbox_sync_context *ctx,
		   const struct dbox_sync_file_entry *entry)
{
	struct dbox_file *file;
	int ret;

	file = entry->file_id != 0 ?
		dbox_file_init_multi(ctx->mbox->storage, entry->file_id) :
		dbox_file_init_single(ctx->mbox, entry->uid);
	if (!array_is_created(&entry->expunge_map_uids)) {
		/* no expunges - we want to move it */
		dbox_sync_file_move_if_needed(file, entry);
	} else if (entry->uid != 0) {
		/* fast path to expunging the whole file */
		if ((ret = dbox_sync_file_unlink(file)) == 0) {
			/* file was lost, delete it */
			dbox_sync_mark_expunges(ctx, &entry->expunge_seqs);
			ret = 1;
		}
	} else {
		if (dbox_map_update_refcounts(ctx->mbox->storage->map,
					      &entry->expunge_map_uids, -1) < 0)
			return -1;

		dbox_sync_mark_expunges(ctx, &entry->expunge_seqs);
	}
	dbox_file_unref(&file);
	return ret;
}
