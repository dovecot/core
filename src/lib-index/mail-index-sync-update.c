/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "file-set-size.h"
#include "mmap-util.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-transaction-log.h"

struct mail_index_update_ctx {
	struct mail_index *index;
	struct mail_index_header hdr;
	struct mail_transaction_log_view *log_view;
};

void mail_index_header_update_counts(struct mail_index_header *hdr,
				     uint8_t old_flags, uint8_t new_flags)
{
	if (((old_flags ^ new_flags) & MAIL_SEEN) != 0) {
		/* different seen-flag */
		if ((old_flags & MAIL_SEEN) == 0)
			hdr->seen_messages_count++;
		else
			hdr->seen_messages_count--;
	}

	if (((old_flags ^ new_flags) & MAIL_DELETED) != 0) {
		/* different deleted-flag */
		if ((old_flags & MAIL_DELETED) == 0)
			hdr->deleted_messages_count++;
		else
			hdr->deleted_messages_count--;
	}
}

void mail_index_header_update_lowwaters(struct mail_index_header *hdr,
					const struct mail_index_record *rec)
{
	if ((rec->flags & MAIL_RECENT) != 0 &&
	    rec->uid < hdr->first_recent_uid_lowwater)
		hdr->first_recent_uid_lowwater = rec->uid;
	if ((rec->flags & MAIL_SEEN) == 0 &&
	    rec->uid < hdr->first_unseen_uid_lowwater)
		hdr->first_unseen_uid_lowwater = rec->uid;
	if ((rec->flags & MAIL_DELETED) != 0 &&
	    rec->uid < hdr->first_deleted_uid_lowwater)
		hdr->first_deleted_uid_lowwater = rec->uid;
}

static void mail_index_sync_update_expunges(struct mail_index_update_ctx *ctx,
					    uint32_t seq1, uint32_t seq2)
{
	struct mail_index_record *rec;

	rec = &ctx->index->map->records[seq1-1];
	for (; seq1 <= seq2; seq1++, rec++)
		mail_index_header_update_counts(&ctx->hdr, rec->flags, 0);
}

static void mail_index_sync_update_flags(struct mail_index_update_ctx *ctx,
					 struct mail_index_sync_rec *syncrec)
{
	struct mail_index_record *rec, *end;
	uint8_t flag_mask, old_flags;
	custom_flags_mask_t custom_mask;
	int i, update_custom;

	update_custom = FALSE;
	for (i = 0; i < INDEX_CUSTOM_FLAGS_BYTE_COUNT; i++) {
		if (syncrec->add_custom_flags[i] != 0)
			update_custom = TRUE;
		if (syncrec->remove_custom_flags[i] != 0)
			update_custom = TRUE;
		custom_mask[i] = ~syncrec->remove_custom_flags[i];
	}

	flag_mask = ~syncrec->remove_flags;
	rec = &ctx->index->map->records[syncrec->seq1-1];
	end = rec + (syncrec->seq2 - syncrec->seq1) + 1;
	for (; rec != end; rec++) {
		old_flags = rec->flags;
		rec->flags = (rec->flags & flag_mask) | syncrec->add_flags;
		if (update_custom) {
			for (i = 0; i < INDEX_CUSTOM_FLAGS_BYTE_COUNT; i++) {
				rec->custom_flags[i] =
					(rec->custom_flags[i]&custom_mask[i]) |
					syncrec->add_custom_flags[i];
			}
		}

		mail_index_header_update_counts(&ctx->hdr,
						old_flags, rec->flags);
                mail_index_header_update_lowwaters(&ctx->hdr, rec);
	}
}

static int mail_index_grow(struct mail_index *index, unsigned int count)
{
	struct mail_index_map *map = index->map;
	size_t size, file_used_size;
	unsigned int records_count;

	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map)) {
		(void)buffer_append_space_unsafe(map->buffer,
			count * sizeof(struct mail_index_record));
		return 0;
	}

	// FIXME: grow exponentially
	size = map->file_used_size +
		count * sizeof(struct mail_index_record);
	if (file_set_size(index->fd, (off_t)size) < 0)
		return mail_index_set_syscall_error(index, "file_set_size()");

	records_count = map->records_count;
	file_used_size = map->file_used_size;

	if (mail_index_map(index, TRUE) <= 0)
		return -1;

	i_assert(map->file_size >= size);
	map->records_count = records_count;
	map->file_used_size = file_used_size;
	return 0;
}

static int mail_index_sync_appends(struct mail_index_update_ctx *ctx,
				   const struct mail_index_record *appends,
				   unsigned int count)
{
	struct mail_index_map *map = ctx->index->map;
	unsigned int i;
	size_t space;
	uint32_t next_uid;

	space = (map->file_size - map->file_used_size) / sizeof(*appends);
	if (space < count) {
		if (mail_index_grow(ctx->index, count) < 0)
			return -1;
	}

	next_uid = ctx->hdr.next_uid;
	for (i = 0; i < count; i++) {
		mail_index_header_update_counts(&ctx->hdr, 0, appends[i].flags);
                mail_index_header_update_lowwaters(&ctx->hdr, &appends[i]);

		if (appends[i].uid < next_uid) {
			/* FIXME: should we rather just update the record?
			   this can actually happen if append was written to
			   transaction log but index wasn't updated, then
			   another sync wrote it again.. */
			mail_transaction_log_view_set_corrupted(ctx->log_view,
				"Append with UID %u, but next_uid = %u",
				appends[i].uid, next_uid);
			return -1;
		}
		next_uid = appends[i].uid+1;
	}
	ctx->hdr.next_uid = next_uid;

	memcpy(map->records + map->records_count, appends,
	       count * sizeof(*appends));
	map->records_count += count;
	map->file_used_size += count * sizeof(struct mail_index_record);
	return 0;
}

int mail_index_sync_update_index(struct mail_index_sync_ctx *sync_ctx)
{
	struct mail_index *index = sync_ctx->index;
	struct mail_index_map *map = index->map;
        struct mail_index_update_ctx ctx;
	struct mail_index_sync_rec rec;
	const struct mail_index_record *appends;
	unsigned int append_count;
	uint32_t count, file_seq, src_idx, dest_idx;
	uoff_t file_offset;
	unsigned int lock_id;
	int ret;

	/* rewind */
	sync_ctx->update_idx = sync_ctx->expunge_idx = 0;
	sync_ctx->sync_appends =
		buffer_get_used_size(sync_ctx->appends_buf) != 0;

	if (!mail_index_sync_have_more(sync_ctx)) {
		/* nothing to sync */
		return 0;
	}

	if (mail_index_lock_exclusive(index, &lock_id) < 0)
		return -1;

	if (MAIL_INDEX_MAP_IS_IN_MEMORY(map))
		map->write_to_disk = TRUE;

	memset(&ctx, 0, sizeof(ctx));
	ctx.index = index;
	ctx.hdr = *index->hdr;
	ctx.log_view = sync_ctx->view->log_view;

	src_idx = dest_idx = 0;
	append_count = 0; appends = NULL;
	while (mail_index_sync_next(sync_ctx, &rec) > 0) {
		switch (rec.type) {
		case MAIL_INDEX_SYNC_TYPE_APPEND:
			i_assert(appends == NULL);
			append_count = rec.seq2 - rec.seq1 + 1;
			appends = rec.appends;
			break;
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			if (src_idx == 0) {
				/* expunges have to be atomic. so we'll have
				   to copy the mapping, do the changes there
				   and then finally replace the whole index
				   file. to avoid extra disk I/O we copy the
				   index into memory rather than to temporary
				   file */
				map = mail_index_map_to_memory(map);
				mail_index_unmap(index, index->map);
				index->map = map;
				index->hdr = map->hdr;
				map->write_to_disk = TRUE;

				dest_idx = rec.seq1-1;
			} else {
				count = (rec.seq1-1) - src_idx;
				memmove(map->records + dest_idx,
					map->records + src_idx,
					count * sizeof(*map->records));
				dest_idx += count;
			}

			mail_index_sync_update_expunges(&ctx, rec.seq1,
							rec.seq2);
			src_idx = rec.seq2;
			break;
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
			mail_index_sync_update_flags(&ctx, &rec);
			break;
		}
	}

	if (src_idx != 0) {
		count = map->records_count - src_idx;
		memmove(map->records + dest_idx,
			map->records + src_idx,
			count * sizeof(*map->records));
		dest_idx += count;

		map->records_count = dest_idx;
		map->file_used_size = index->hdr->header_size +
			map->records_count * sizeof(struct mail_index_record);
	}

	ret = 0;
	if (append_count > 0)
		ret = mail_index_sync_appends(&ctx, appends, append_count);

	mail_transaction_log_get_head(index->log, &file_seq, &file_offset);

	ctx.hdr.messages_count = map->records_count;
	ctx.hdr.log_file_seq = file_seq;
	ctx.hdr.log_file_offset = file_offset;

	if (!MAIL_INDEX_MAP_IS_IN_MEMORY(map)) {
		memcpy(map->mmap_base, &ctx.hdr, sizeof(ctx.hdr));
		if (msync(map->mmap_base, map->file_used_size, MS_SYNC) < 0) {
			mail_index_set_syscall_error(index, "msync()");
			ret = -1;
		}
	} else {
		map->hdr_copy = ctx.hdr;
		map->hdr = &map->hdr_copy;
	}

	mail_index_unlock(index, lock_id);
	return ret;
}
