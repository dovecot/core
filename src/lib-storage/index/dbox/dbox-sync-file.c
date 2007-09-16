/* Copyright (c) 2007-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "dbox-storage.h"
#include "dbox-index.h"
#include "dbox-file.h"
#include "dbox-sync.h"

static int dbox_sync_file_unlink(struct dbox_file *file)
{
	if (unlink(file->path) < 0) {
		dbox_file_set_syscall_error(file, "unlink");
		if (errno != ENOENT)
			return -1;
	}
	return 0;
}

static void
dbox_sync_update_metadata(struct dbox_sync_context *ctx, struct dbox_file *file,
			  const struct dbox_sync_file_entry *entry,
			  uint32_t seq)
{
	const struct mail_index_record *rec;
	ARRAY_TYPE(keyword_indexes) keyword_indexes;
	struct mail_keywords *keywords;
	string_t *value;
	const char *old_value;

	t_push();
	value = t_str_new(256);

	/* flags */
	rec = mail_index_lookup(ctx->sync_view, seq);
	dbox_mail_metadata_flags_append(value, rec->flags);
	dbox_file_metadata_set(file, DBOX_METADATA_FLAGS, str_c(value));

	/* keywords */
	t_array_init(&keyword_indexes, 32);
	mail_index_lookup_keywords(ctx->sync_view, seq, &keyword_indexes);
	old_value = dbox_file_metadata_get(file, DBOX_METADATA_KEYWORDS);
	if (array_count(&keyword_indexes) > 0 ||
	    (old_value != NULL && *old_value != '\0' &&
	     array_count(&keyword_indexes) == 0)) {
		str_truncate(value, 0);
		keywords = mail_index_keywords_create_from_indexes(
				ctx->mbox->ibox.index, &keyword_indexes);
		dbox_mail_metadata_keywords_append(ctx->mbox, value, keywords);
		mail_index_keywords_free(&keywords);

		dbox_file_metadata_set(file, DBOX_METADATA_KEYWORDS,
				       str_c(value));
	}

	/* expunge state */
	if (array_is_created(&entry->expunges) &&
	    seq_range_exists(&entry->expunges, seq)) {
		dbox_file_metadata_set(file, DBOX_METADATA_EXPUNGED, "1");
		mail_index_expunge(ctx->trans, seq);
	}
	t_pop();
}

static int
dbox_sync_file_expunge(struct dbox_sync_context *ctx, struct dbox_file *file,
		       const struct dbox_sync_file_entry *entry)
{
	const struct seq_range *expunges;
	struct dbox_file *out_file = NULL;
	struct istream *input;
	struct ostream *output;
	uint32_t file_id, seq, uid;
	uoff_t first_offset, offset, physical_size, metadata_offset;
	unsigned int i, count;
	bool expunged;
	int ret;

	expunges = array_get(&entry->expunges, &count);
	if (!dbox_file_lookup(ctx->mbox, ctx->sync_view, expunges[0].seq1,
			      &file_id, &first_offset))
		return 0;
	i_assert(file_id == file->file_id);
	mail_index_expunge(ctx->trans, expunges[0].seq1);

	offset = first_offset;
	for (;;) {
		if ((ret = dbox_file_seek_next(file, &offset, &uid,
					       &physical_size)) <= 0)
			break;
		if (uid == 0) {
			/* EOF */
			break;
		}

		if (i < count) {
			mail_index_lookup_uid_range(ctx->sync_view, uid, uid,
						    &seq, &seq);
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

		input = i_stream_create_limit(file->input, offset,
					      file->msg_header_size +
					      physical_size);
		o_stream_send_istream(output, input);
		i_stream_unref(&input);

		/* write metadata */
		metadata_offset = dbox_file_get_metadata_offset(file, offset,
								physical_size);
		(void)dbox_file_metadata_seek(file, metadata_offset, &expunged);
		dbox_sync_update_metadata(ctx, file, entry, seq);
		dbox_file_metadata_write_to(file, output);
		mail_index_update_flags(ctx->trans, seq, MODIFY_REMOVE,
			(enum mail_flags)MAIL_INDEX_MAIL_FLAG_DIRTY);
	}

	if (ret <= 0) {
		if (out_file != NULL) {
			if (unlink(out_file->path) < 0) {
				i_error("unlink(%s) failed: %m",
					out_file->path);
			}
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
			dbox_file_set_syscall_error(file, "ftruncate");
			ret = -1;
		}
	}

	if (out_file != NULL)
		dbox_file_unref(&out_file);
	return ret;
}

static int
dbox_sync_file_changes(struct dbox_sync_context *ctx, struct dbox_file *file,
		       const struct dbox_sync_file_entry *entry, uint32_t seq)
{
	uint32_t file_id;
	uoff_t offset;
	bool expunged;
	int ret;

	if (!dbox_file_lookup(ctx->mbox, ctx->sync_view, seq,
			      &file_id, &offset))
		return 0;
	i_assert(file_id == file->file_id);

	ret = dbox_file_metadata_seek_mail_offset(file, offset, &expunged);
	if (ret <= 0)
		return ret;
	if (expunged) {
		mail_index_expunge(ctx->trans, seq);
		return 1;
	}

	dbox_sync_update_metadata(ctx, file, entry, seq);
	ret = dbox_file_metadata_write(file);
	if (ret <= 0) {
		/* FIXME: handle ret=0 case by splitting the file */
		return ret;
	}

	mail_index_update_flags(ctx->trans, seq, MODIFY_REMOVE,
				(enum mail_flags)MAIL_INDEX_MAIL_FLAG_DIRTY);
	return 1;
}

static int
dbox_sync_file_int(struct dbox_sync_context *ctx, struct dbox_file *file,
		   const struct dbox_sync_file_entry *entry, bool full_expunge)
{
	const struct seq_range *seqs;
	unsigned int i, count;
	uint32_t seq, first_expunge_seq;
	int ret;

	if (array_is_created(&entry->expunges) && full_expunge) {
		seqs = array_idx(&entry->expunges, 0);
		first_expunge_seq = seqs->seq1;
	} else {
		first_expunge_seq = (uint32_t)-1;
	}

	seqs = array_get(&entry->changes, &count);
	for (i = 0; i < count; ) {
		for (seq = seqs[i].seq1; seq <= seqs[i].seq2; seq++) {
			if (seq >= first_expunge_seq)
				return dbox_sync_file_expunge(ctx, file, entry);

			ret = dbox_sync_file_changes(ctx, file, entry, seq);
			if (ret <= 0)
				return ret;
		}
		i++;
	}
	if (first_expunge_seq != (uint32_t)-1)
		return dbox_sync_file_expunge(ctx, file, entry);
	return 1;
}

static void
dbox_sync_mark_single_file_expunged(struct dbox_sync_context *ctx,
				    const struct dbox_sync_file_entry *entry)
{
	const struct seq_range *expunges;
	unsigned int count;

	expunges = array_get(&entry->expunges, &count);
	i_assert(count == 1 && expunges[0].seq1 == expunges[0].seq2);
	mail_index_expunge(ctx->trans, expunges[0].seq1);
}

int dbox_sync_file(struct dbox_sync_context *ctx,
		   const struct dbox_sync_file_entry *entry)
{
	struct dbox_file *file;
	struct dbox_index_record *rec;
	enum dbox_index_file_status status;
	bool locked, deleted;
	int ret;

	if ((entry->file_id & DBOX_FILE_ID_FLAG_UID) != 0) {
		locked = TRUE;
		status = DBOX_INDEX_FILE_STATUS_SINGLE_MESSAGE;
	} else {
		rec = dbox_index_record_lookup(ctx->mbox->dbox_index,
					       entry->file_id);
		if (rec == NULL ||
		    rec->status == DBOX_INDEX_FILE_STATUS_UNLINKED) {
			/* file doesn't exist, nothing to do */
			return 1;
		}
		locked = rec->locked;
		status = rec->status;
	}

	file = dbox_file_init(ctx->mbox, entry->file_id);
	if (status == DBOX_INDEX_FILE_STATUS_SINGLE_MESSAGE &&
	    array_is_created(&entry->expunges)) {
		/* fast path to expunging the whole file */
		if (dbox_sync_file_unlink(file) < 0)
			ret = -1;
		else {
			dbox_sync_mark_single_file_expunged(ctx, entry);
			ret = 1;
		}
	} else {
		ret = dbox_file_open_or_create(file, TRUE, &deleted);
		if (ret > 0 && !deleted)
			ret = dbox_sync_file_int(ctx, file, entry, locked);
	}
	dbox_file_unref(&file);
	return ret;
}
