/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-index-private.h"
#include "mail-index-modseq.h"
#include "mail-transaction-log-private.h"

static struct modseq_cache *
modseq_cache_hit(struct mail_transaction_log_file *file, unsigned int idx)
{
	struct modseq_cache cache;

	if (idx > 0) {
		/* @UNSAFE: move it to top */
		cache = file->modseq_cache[idx];
		memmove(file->modseq_cache + 1, file->modseq_cache,
			sizeof(*file->modseq_cache) * idx);
		file->modseq_cache[0] = cache;
	}
	return &file->modseq_cache[0];
}

static struct modseq_cache *
modseq_cache_get_offset(struct mail_transaction_log_file *file, uoff_t offset)
{
	unsigned int i, best = UINT_MAX;

	for (i = 0; i < N_ELEMENTS(file->modseq_cache); i++) {
		if (offset < file->modseq_cache[i].offset)
			continue;

		if (file->modseq_cache[i].offset == 0)
			return NULL;

		if (offset == file->modseq_cache[i].offset) {
			/* exact cache hit */
			return modseq_cache_hit(file, i);
		}

		if (best == UINT_MAX ||
		    file->modseq_cache[i].offset <
		    file->modseq_cache[best].offset)
			best = i;
	}
	if (best == UINT_MAX)
		return NULL;
	return &file->modseq_cache[best];
}

static struct modseq_cache *
modseq_cache_get_modseq(struct mail_transaction_log_file *file, uint64_t modseq)
{
	unsigned int i, best = UINT_MAX;

	for (i = 0; i < N_ELEMENTS(file->modseq_cache); i++) {
		if (modseq < file->modseq_cache[i].highest_modseq)
			continue;

		if (file->modseq_cache[i].offset == 0)
			return NULL;

		if (modseq == file->modseq_cache[i].highest_modseq) {
			/* exact cache hit */
			return modseq_cache_hit(file, i);
		}

		if (best == UINT_MAX ||
		    file->modseq_cache[i].highest_modseq <
		    file->modseq_cache[best].highest_modseq)
			best = i;
	}
	if (best == UINT_MAX)
		return NULL;
	return &file->modseq_cache[best];
}

static int
log_get_synced_record(struct mail_transaction_log_file *file, uoff_t *offset,
		      const struct mail_transaction_header **hdr_r,
		      const char **error_r)
{
	const struct mail_transaction_header *hdr;
	uint32_t trans_size;

	hdr = CONST_PTR_OFFSET(file->buffer->data,
			       *offset - file->buffer_offset);

	/* we've already synced this record at some point. it should
	   be valid. */
	trans_size = mail_index_offset_to_uint32(hdr->size);
	if (trans_size < sizeof(*hdr) ||
	    *offset - file->buffer_offset + trans_size > file->buffer->used) {
		*error_r = t_strdup_printf(
			"Transaction log corrupted unexpectedly at "
			"%"PRIuUOFF_T": Invalid size %u (type=%x)",
			*offset, trans_size, hdr->type);
		mail_transaction_log_file_set_corrupted(file, "%s", *error_r);
		return -1;
	}
	*offset += trans_size;
	*hdr_r = hdr;
	return 0;
}

int mail_transaction_log_file_get_highest_modseq_at(
		struct mail_transaction_log_file *file,
		uoff_t offset, uint64_t *highest_modseq_r,
		const char **error_r)
{
	const struct mail_transaction_header *hdr;
	struct modseq_cache *cache;
	uoff_t cur_offset;
	uint64_t cur_modseq;
	const char *reason;
	int ret;

	i_assert(offset <= file->sync_offset);

	if (offset == file->sync_offset) {
		*highest_modseq_r = file->sync_highest_modseq;
		return 1;
	}

	cache = modseq_cache_get_offset(file, offset);
	if (cache == NULL) {
		/* nothing usable in cache - scan from beginning */
		cur_offset = file->hdr.hdr_size;
		cur_modseq = file->hdr.initial_modseq;
	} else if (cache->offset == offset) {
		/* exact cache hit */
		*highest_modseq_r = cache->highest_modseq;
		return 1;
	} else {
		/* use cache to skip over some records */
		cur_offset = cache->offset;
		cur_modseq = cache->highest_modseq;
	}

	/* See if we can use the "modseq" header in dovecot.index to further
	   reduce how much we have to scan. */
	const struct mail_index_modseq_header *modseq_hdr =
		file->log->index->map == NULL ? NULL :
		&file->log->index->map->modseq_hdr_snapshot;
	if (modseq_hdr != NULL &&
	    modseq_hdr->log_seq == file->hdr.file_seq &&
	    modseq_hdr->log_offset <= offset &&
	    modseq_hdr->log_offset >= cur_offset) {
		cur_offset = modseq_hdr->log_offset;
		cur_modseq = modseq_hdr->highest_modseq;
	}

	ret = mail_transaction_log_file_map(file, cur_offset, offset, &reason);
	if (ret <= 0) {
		*error_r = t_strdup_printf(
			"Failed to map transaction log %s for getting modseq "
			"at offset=%"PRIuUOFF_T" with start_offset=%"PRIuUOFF_T": %s",
			file->filepath, offset, cur_offset, reason);
		return ret;
	}

	i_assert(cur_offset >= file->buffer_offset);
	i_assert(cur_offset + file->buffer->used >= offset);
	while (cur_offset < offset) {
		if (log_get_synced_record(file, &cur_offset, &hdr, error_r) < 0)
			return 0;
		mail_transaction_update_modseq(hdr, hdr + 1, &cur_modseq,
			MAIL_TRANSACTION_LOG_HDR_VERSION(&file->hdr));
	}

	/* @UNSAFE: cache the value */
	memmove(file->modseq_cache + 1, file->modseq_cache,
		sizeof(*file->modseq_cache) *
		(N_ELEMENTS(file->modseq_cache) - 1));
	file->modseq_cache[0].offset = cur_offset;
	file->modseq_cache[0].highest_modseq = cur_modseq;

	*highest_modseq_r = cur_modseq;
	return 1;
}

static int
get_modseq_next_offset_at(struct mail_transaction_log_file *file,
			  uint64_t modseq, bool use_highest,
			  uoff_t *cur_offset, uint64_t *cur_modseq,
			  uoff_t *next_offset_r)
{
	const struct mail_transaction_header *hdr;
	const char *reason;
	int ret;

	/* make sure we've read until end of file. this is especially important
	   with non-head logs which might only have been opened without being
	   synced. */
	ret = mail_transaction_log_file_map(file, *cur_offset, UOFF_T_MAX, &reason);
	if (ret <= 0) {
		mail_index_set_error(file->log->index,
			"Failed to map transaction log %s for getting offset "
			"for modseq=%"PRIu64" with start_offset=%"PRIuUOFF_T": %s",
			file->filepath, modseq, *cur_offset, reason);
		return -1;
	}

	/* check sync_highest_modseq again in case sync_offset was updated */
	if (modseq >= file->sync_highest_modseq && use_highest) {
		*next_offset_r = file->sync_offset;
		return 0;
	}

	i_assert(*cur_offset >= file->buffer_offset);
	while (*cur_offset < file->sync_offset) {
		if (log_get_synced_record(file, cur_offset, &hdr, &reason) < 0) {
			mail_index_set_error(file->log->index,
				"%s: %s", file->filepath, reason);
			return -1;
		}
		mail_transaction_update_modseq(hdr, hdr + 1, cur_modseq,
			MAIL_TRANSACTION_LOG_HDR_VERSION(&file->hdr));
		if (*cur_modseq >= modseq)
			break;
	}
	return 1;
}

int mail_transaction_log_file_get_modseq_next_offset(
		struct mail_transaction_log_file *file,
		uint64_t modseq, uoff_t *next_offset_r)
{
	struct modseq_cache *cache;
	uoff_t cur_offset;
	uint64_t cur_modseq;
	int ret;

	if (modseq == file->sync_highest_modseq) {
		*next_offset_r = file->sync_offset;
		return 0;
	}
	if (modseq == file->hdr.initial_modseq) {
		*next_offset_r = file->hdr.hdr_size;
		return 0;
	}

	cache = modseq_cache_get_modseq(file, modseq);
	if (cache == NULL) {
		/* nothing usable in cache - scan from beginning */
		cur_offset = file->hdr.hdr_size;
		cur_modseq = file->hdr.initial_modseq;
	} else if (cache->highest_modseq == modseq) {
		/* exact cache hit */
		*next_offset_r = cache->offset;
		return 0;
	} else {
		/* use cache to skip over some records */
		cur_offset = cache->offset;
		cur_modseq = cache->highest_modseq;
	}

	if ((ret = get_modseq_next_offset_at(file, modseq, TRUE, &cur_offset,
					     &cur_modseq, next_offset_r)) <= 0)
		return ret;
	if (cur_offset == file->sync_offset) {
		/* if we got to sync_offset, cur_modseq should be
		   sync_highest_modseq */
		mail_index_set_error(file->log->index,
			"%s: Transaction log modseq tracking is corrupted - fixing",
			file->filepath);
		/* retry getting the offset by reading from the beginning
		   of the file */
		cur_offset = file->hdr.hdr_size;
		cur_modseq = file->hdr.initial_modseq;
		ret = get_modseq_next_offset_at(file, modseq, FALSE,
						&cur_offset, &cur_modseq,
						next_offset_r);
		if (ret < 0)
			return -1;
		i_assert(ret != 0);
		/* get it fixed on the next sync */
		if (file->log->index->need_recreate == NULL) {
			file->log->index->need_recreate =
				i_strdup("modseq tracking is corrupted");
		}
		if (file->need_rotate == NULL) {
			file->need_rotate =
				i_strdup("modseq tracking is corrupted");
		}
		/* clear cache, since it's unreliable */
		memset(file->modseq_cache, 0, sizeof(file->modseq_cache));
	}

	/* @UNSAFE: cache the value */
	memmove(file->modseq_cache + 1, file->modseq_cache,
		sizeof(*file->modseq_cache) *
		(N_ELEMENTS(file->modseq_cache) - 1));
	file->modseq_cache[0].offset = cur_offset;
	file->modseq_cache[0].highest_modseq = cur_modseq;

	*next_offset_r = cur_offset;
	return 0;
}
