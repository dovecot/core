/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "dbox-storage.h"
#include "dbox-file.h"
#include "dbox-sync.h"

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

static int
dbox_sync_file_expunge(struct dbox_sync_context *ctx, struct dbox_file *file,
		       const struct dbox_sync_file_entry *entry)
{
#if 0 //FIXME
	const struct seq_range *expunges;
	struct dbox_file *out_file = NULL;
	struct istream *input;
	struct ostream *output;
	uint32_t file_id, seq, uid;
	uoff_t first_offset, offset, physical_size;
	const char *out_path;
	unsigned int i, count;
	bool expunged;
	int ret;

	/* FIXME: lock the file first */

	expunges = array_get(&entry->expunges, &count);
	if (!dbox_file_lookup(ctx->mbox, ctx->sync_view, expunges[0].seq1,
			      &file_id, &first_offset))
		return 0;
	i_assert(file_id == file->file_id);
	mail_index_expunge(ctx->trans, expunges[0].seq1);

	offset = first_offset;
	for (i = 0;;) {
		if ((ret = dbox_file_seek_next(file, &offset,
					       &physical_size)) <= 0)
			break;
		if (physical_size == 0) {
			/* EOF */
			break;
		}

		if (i < count) {
			mail_index_lookup_seq(ctx->sync_view, uid, &seq);
			while (seq > expunges[i].seq2) {
				if (++i == count)
					break;
			}
		}
		if (seq == 0 || (i < count && seq >= expunges[i].seq1 &&
				 seq <= expunges[i].seq2)) {
			/* this message gets expunged */
			if (seq != 0)
				mail_index_expunge(ctx->trans, seq);
			continue;
		}

		/* non-expunged message. write it to output file. */
		if (out_file == NULL) {
			out_file = dbox_file_init(ctx->mbox, 0);
			ret = dbox_file_get_append_stream(out_file,
							  physical_size,
							  &output);
			if (ret <= 0)
				break;
		}

		i_stream_seek(file->input, offset);
		input = i_stream_create_limit(file->input,
					      file->msg_header_size +
					      physical_size);
		ret = o_stream_send_istream(output, input) < 0 ? -1 : 0;
		i_stream_unref(&input);
		if (ret < 0)
			break;

		/* write metadata */
		(void)dbox_file_metadata_seek_mail_offset(file, offset,
							  &expunged);
		if ((ret = dbox_file_metadata_write_to(file, output)) < 0)
			break;

		mail_index_update_flags(ctx->trans, seq, MODIFY_REMOVE,
			(enum mail_flags)MAIL_INDEX_MAIL_FLAG_DIRTY);
	}

	out_path = out_file == NULL ? NULL :
		dbox_file_get_path(out_file);
	if (ret <= 0) {
		if (out_file != NULL) {
			if (unlink(out_path) < 0)
				i_error("unlink(%s) failed: %m", out_path);
			o_stream_unref(&output);
		}
	} else if (out_file != NULL) {
		/* FIXME: rename out_file and add to index */
		o_stream_unref(&output);
	}

	if (ret <= 0)
		;
	else if (first_offset == file->file_header_size) {
		/* nothing exists in this file anymore */
		ret = dbox_sync_file_unlink(file);
	} else {
		if (ftruncate(file->fd, first_offset) < 0) {
			dbox_file_set_syscall_error(file, "ftruncate()");
			ret = -1;
		}
	}

	if (out_file != NULL)
		dbox_file_unref(&out_file);
	return ret;
#endif
	return -1;
}

#if 0
static int
dbox_sync_file_split(struct dbox_sync_context *ctx, struct dbox_file *in_file,
		     uoff_t offset, uint32_t seq)
{
	static enum dbox_metadata_key maildir_metadata_keys[] = {
		DBOX_METADATA_VIRTUAL_SIZE,
		DBOX_METADATA_RECEIVED_TIME,
		DBOX_METADATA_SAVE_TIME,
		DBOX_METADATA_POP3_UIDL
	};
	struct dbox_index_append_context *append_ctx;
	struct dbox_file *out_file;
	struct istream *input;
	struct ostream *output;
	struct dbox_message_header dbox_msg_hdr;
	struct dbox_mail_index_record rec;
	const char *out_path, *value;
	uoff_t size, append_offset;
	unsigned int i;
	int ret;
	bool expunged;

	/* FIXME: for now we handle only maildir file conversion */
	i_assert(in_file->maildir_file);

	ret = dbox_file_get_mail_stream(in_file, offset,
					&size, &input, &expunged);
	if (ret <= 0)
		return ret;
	if (expunged) {
		mail_index_expunge(ctx->trans, seq);
		return 1;
	}

	append_ctx = dbox_index_append_begin(ctx->mbox->dbox_index);
	if (dbox_index_append_next(append_ctx, size, &out_file, &output) < 0 ||
	    dbox_file_metadata_seek(out_file, 0, &expunged) < 0) {
		dbox_index_append_rollback(&append_ctx);
		i_stream_unref(&input);
		return -1;
	}
	append_offset = output->offset;
	dbox_msg_header_fill(&dbox_msg_hdr, size);

	/* set static metadata */
	for (i = 0; i < N_ELEMENTS(maildir_metadata_keys); i++) {
		value = dbox_file_metadata_get(in_file,
					       maildir_metadata_keys[i]);
		if (value != NULL) {
			dbox_file_metadata_set(out_file,
					       maildir_metadata_keys[i], value);
		}
	}

	/* copy the message */
	out_path = dbox_file_get_path(out_file);
	o_stream_cork(output);
	if (o_stream_send(output, &dbox_msg_hdr, sizeof(dbox_msg_hdr)) < 0 ||
	    o_stream_send_istream(output, input) < 0 ||
	    dbox_file_metadata_write_to(out_file, output) < 0 ||
	    o_stream_flush(output) < 0) {
		mail_storage_set_critical(&ctx->mbox->storage->storage,
			"write(%s) failed: %m", out_path);
		ret = -1;
	} else {
		dbox_file_finish_append(out_file);
		out_file->last_append_uid = uid;

		ret = dbox_index_append_assign_file_ids(append_ctx);
	}

	if (ret < 0)
		dbox_index_append_rollback(&append_ctx);
	else
		ret = dbox_index_append_commit(&append_ctx);
	i_stream_unref(&input);

	if (ret == 0) {
		/* update message position in index file */
		memset(&rec, 0, sizeof(rec));
		if ((rec.file_id & DBOX_FILE_ID_FLAG_UID) == 0) {
			rec.file_id = out_file->file_id;
			rec.offset = append_offset;
		}
		mail_index_update_ext(ctx->trans, seq, ctx->mbox->dbox_ext_id,
				      &rec, NULL);

		/* when everything is done, unlink the old file */
		ret = dbox_sync_file_unlink(in_file);
	}
	return ret < 0 ? -1 : 1;
}
#endif

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
dbox_sync_mark_single_file_expunged(struct dbox_sync_context *ctx,
				    const struct dbox_sync_file_entry *entry)
{
	struct mailbox *box = &ctx->mbox->ibox.box;
	const struct seq_range *expunges;
	unsigned int count;
	uint32_t uid;

	expunges = array_get(&entry->expunges, &count);
	i_assert(count == 1 && expunges[0].seq1 == expunges[0].seq2);
	mail_index_expunge(ctx->trans, expunges[0].seq1);

	if (box->v.sync_notify != NULL) {
		mail_index_lookup_uid(ctx->sync_view, expunges[0].seq1, &uid);
		box->v.sync_notify(box, uid, MAILBOX_SYNC_TYPE_EXPUNGE);
	}
}

int dbox_sync_file(struct dbox_sync_context *ctx,
		   const struct dbox_sync_file_entry *entry)
{
	struct dbox_file *file;
	bool deleted;
	int ret;

	file = entry->file_id != 0 ?
		dbox_file_init_multi(ctx->mbox->storage, entry->file_id) :
		dbox_file_init_single(ctx->mbox, entry->uid);
	if (entry->uid != 0 && array_is_created(&entry->expunges)) {
		/* fast path to expunging the whole file */
		if ((ret = dbox_sync_file_unlink(file)) == 0) {
			/* file was lost, delete it */
			dbox_sync_mark_single_file_expunged(ctx, entry);
			ret = 1;
		}
	} else {
		ret = dbox_file_open_or_create(file, &deleted);
		if (ret > 0 && !deleted) {
			dbox_sync_file_move_if_needed(file, entry);
			if (array_is_created(&entry->expunges))
				ret = dbox_sync_file_expunge(ctx, file, entry);
		}
	}
	dbox_file_unref(&file);
	return ret;
}
