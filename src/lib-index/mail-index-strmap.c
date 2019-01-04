/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "istream.h"
#include "ostream.h"
#include "file-lock.h"
#include "file-dotlock.h"
#include "crc32.h"
#include "safe-mkstemp.h"
#include "str.h"
#include "mail-index-private.h"
#include "mail-index-strmap.h"

#include <stdio.h>

struct mail_index_strmap {
	struct mail_index *index;
	char *path;
	int fd;
	struct istream *input;

	struct file_lock *file_lock;
	struct dotlock *dotlock;
	struct dotlock_settings dotlock_settings;
};

struct mail_index_strmap_view {
	struct mail_index_strmap *strmap;
	struct mail_index_view *view;

	ARRAY_TYPE(mail_index_strmap_rec) recs;
	ARRAY(uint32_t) recs_crc32;
	struct hash2_table *hash;

	mail_index_strmap_key_cmp_t *key_compare;
	mail_index_strmap_rec_cmp_t *rec_compare;
	mail_index_strmap_remap_t *remap_cb;
	void *cb_context;

	uoff_t last_read_block_offset;
	uint32_t last_read_uid;
	uint32_t last_added_uid;
	uint32_t total_ref_count;

	uint32_t last_ref_index;
	uint32_t next_str_idx;
	uint32_t lost_expunged_uid;

	bool desynced:1;
};

struct mail_index_strmap_read_context {
	struct mail_index_strmap_view *view;

	struct istream *input;
	uoff_t end_offset;
	uint32_t highest_str_idx;
	uint32_t uid_lookup_seq;
	uint32_t lost_expunged_uid;

	const unsigned char *data, *end, *str_idx_base;
	struct mail_index_strmap_rec rec;
	uint32_t next_ref_index;
	unsigned int rec_size;

	bool too_large_uids:1;
};

struct mail_index_strmap_view_sync {
	struct mail_index_strmap_view *view;
};

struct mail_index_strmap_hash_key {
	const char *str;
	uint32_t crc32;
};

/* number of bytes required to store one string idx */
#define STRMAP_FILE_STRIDX_SIZE (sizeof(uint32_t)*2)

/* renumber the string indexes when highest string idx becomes larger than
   <number of indexes>*STRMAP_FILE_MAX_STRIDX_MULTIPLIER */
#define STRMAP_FILE_MAX_STRIDX_MULTIPLIER 2

#define STRIDX_MUST_RENUMBER(highest_idx, n_unique_indexes) \
	(highest_idx > n_unique_indexes * STRMAP_FILE_MAX_STRIDX_MULTIPLIER)

#define MAIL_INDEX_STRMAP_TIMEOUT_SECS 10

static const struct dotlock_settings default_dotlock_settings = {
	.timeout = MAIL_INDEX_STRMAP_TIMEOUT_SECS,
	.stale_timeout = 30
};

struct mail_index_strmap *
mail_index_strmap_init(struct mail_index *index, const char *suffix)
{
	struct mail_index_strmap *strmap;

	i_assert(index->open_count > 0);

	strmap = i_new(struct mail_index_strmap, 1);
	strmap->index = index;
	strmap->path = i_strconcat(index->filepath, suffix, NULL);
	strmap->fd = -1;

	strmap->dotlock_settings = default_dotlock_settings;
	strmap->dotlock_settings.use_excl_lock =
		(index->flags & MAIL_INDEX_OPEN_FLAG_DOTLOCK_USE_EXCL) != 0;
	strmap->dotlock_settings.nfs_flush =
		(index->flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) != 0;
	return strmap;
}

static bool
mail_index_strmap_read_rec_next(struct mail_index_strmap_read_context *ctx,
				uint32_t *crc32_r);

static void
mail_index_strmap_set_syscall_error(struct mail_index_strmap *strmap,
				    const char *function)
{
	i_assert(function != NULL);

	if (ENOSPACE(errno)) {
		strmap->index->nodiskspace = TRUE;
		if ((strmap->index->flags &
		     MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY) == 0)
			return;
	}

	mail_index_set_error(strmap->index,
			     "%s failed with strmap index file %s: %m",
			     function, strmap->path);
}

static void mail_index_strmap_close(struct mail_index_strmap *strmap)
{
	if (strmap->file_lock != NULL)
		file_lock_free(&strmap->file_lock);
	else if (strmap->dotlock != NULL)
		file_dotlock_delete(&strmap->dotlock);

	if (strmap->fd != -1) {
		if (close(strmap->fd) < 0)
			mail_index_strmap_set_syscall_error(strmap, "close()");
		strmap->fd = -1;
	}
	i_stream_unref(&strmap->input);
}

void mail_index_strmap_deinit(struct mail_index_strmap **_strmap)
{
	struct mail_index_strmap *strmap = *_strmap;

	*_strmap = NULL;
	mail_index_strmap_close(strmap);
	i_free(strmap->path);
	i_free(strmap);
}

static unsigned int mail_index_strmap_hash_key(const void *_key)
{
	const struct mail_index_strmap_hash_key *key = _key;

	return key->crc32;
}

static bool
mail_index_strmap_hash_cmp(const void *_key, const void *_value, void *context)
{
	const struct mail_index_strmap_hash_key *key = _key;
	const struct mail_index_strmap_rec *rec = _value;
	struct mail_index_strmap_view *view = context;

	return view->key_compare(key->str, rec, view->cb_context);
}

struct mail_index_strmap_view *
mail_index_strmap_view_open(struct mail_index_strmap *strmap,
			    struct mail_index_view *idx_view,
			    mail_index_strmap_key_cmp_t *key_compare_cb,
			    mail_index_strmap_rec_cmp_t *rec_compare_cb,
			    mail_index_strmap_remap_t *remap_cb,
			    void *context,
			    const ARRAY_TYPE(mail_index_strmap_rec) **recs_r,
			    const struct hash2_table **hash_r)
{
	struct mail_index_strmap_view *view;

	view = i_new(struct mail_index_strmap_view, 1);
	view->strmap = strmap;
	view->view = idx_view;
	view->key_compare = key_compare_cb;
	view->rec_compare = rec_compare_cb;
	view->remap_cb = remap_cb;
	view->cb_context = context;
	view->next_str_idx = 1;

	i_array_init(&view->recs, 64);
	i_array_init(&view->recs_crc32, 64);
	view->hash = hash2_create(0, sizeof(struct mail_index_strmap_rec),
				  mail_index_strmap_hash_key,
				  mail_index_strmap_hash_cmp, view);
	*recs_r = &view->recs;
	*hash_r = view->hash;
	return view;
}

void mail_index_strmap_view_close(struct mail_index_strmap_view **_view)
{
	struct mail_index_strmap_view *view = *_view;

	*_view = NULL;
	array_free(&view->recs);
	array_free(&view->recs_crc32);
	hash2_destroy(&view->hash);
	i_free(view);
}

uint32_t mail_index_strmap_view_get_highest_idx(struct mail_index_strmap_view *view)
{
	return view->next_str_idx-1;
}

static void mail_index_strmap_view_reset(struct mail_index_strmap_view *view)
{
	view->remap_cb(NULL, 0, 0, view->cb_context);
	array_clear(&view->recs);
	array_clear(&view->recs_crc32);
	hash2_clear(view->hash);

	view->last_added_uid = 0;
	view->lost_expunged_uid = 0;
	view->desynced = FALSE;
}

void mail_index_strmap_view_set_corrupted(struct mail_index_strmap_view *view)
{
	mail_index_set_error(view->strmap->index,
			     "Corrupted strmap index file: %s",
			     view->strmap->path);
	i_unlink(view->strmap->path);
	mail_index_strmap_close(view->strmap);
	mail_index_strmap_view_reset(view);
}

static int mail_index_strmap_open(struct mail_index_strmap_view *view)
{
	struct mail_index_strmap *strmap = view->strmap;
	const struct mail_index_header *idx_hdr;
	struct mail_index_strmap_header hdr;
	const unsigned char *data;
	size_t size;
	int ret;

	i_assert(strmap->fd == -1);

	strmap->fd = open(strmap->path, O_RDWR);
	if (strmap->fd == -1) {
		if (errno == ENOENT)
			return 0;
		mail_index_strmap_set_syscall_error(strmap, "open()");
		return -1;
	}
	strmap->input = i_stream_create_fd(strmap->fd, (size_t)-1);
	ret = i_stream_read_bytes(strmap->input, &data, &size, sizeof(hdr));
	if (ret <= 0) {
		if (ret < 0) {
			mail_index_strmap_set_syscall_error(strmap, "read()");
			mail_index_strmap_close(strmap);
		} else {
			i_assert(ret == 0);
			mail_index_strmap_view_set_corrupted(view);
		}
		return ret;
	}
	memcpy(&hdr, data, sizeof(hdr));

	idx_hdr = mail_index_get_header(view->view);
	if (hdr.version != MAIL_INDEX_STRMAP_VERSION ||
	    hdr.uid_validity != idx_hdr->uid_validity) {
		/* need to rebuild. if we already had something in the strmap,
		   we can keep it. */
		i_unlink(strmap->path);
		mail_index_strmap_close(strmap);
		return 0;
	}

	/* we'll read the entire file from the beginning */
	view->last_added_uid = 0;
	view->last_read_uid = 0;
	view->total_ref_count = 0;
	view->last_read_block_offset = sizeof(struct mail_index_strmap_header);
	view->next_str_idx = 1;

	mail_index_strmap_view_reset(view);
	return 0;
}

static bool mail_index_strmap_need_reopen(struct mail_index_strmap *strmap)
{
	struct stat st1, st2;

	/* FIXME: nfs flush */
	if (fstat(strmap->fd, &st1) < 0) {
		if (!ESTALE_FSTAT(errno))
			mail_index_strmap_set_syscall_error(strmap, "fstat()");
		return TRUE;
	}
	if (stat(strmap->path, &st2) < 0) {
		mail_index_strmap_set_syscall_error(strmap, "stat()");
		return TRUE;
	}
	return st1.st_ino != st2.st_ino || !CMP_DEV_T(st1.st_dev, st2.st_dev);
}

static int mail_index_strmap_refresh(struct mail_index_strmap_view *view)
{
	uint32_t seq;

	if (MAIL_INDEX_IS_IN_MEMORY(view->strmap->index))
		return -1;

	if (view->strmap->fd != -1) {
		if (!mail_index_strmap_need_reopen(view->strmap)) {
			if (view->lost_expunged_uid != 0) {
				/* last read failed because view had a message
				   that didn't exist in the strmap (because it
				   was expunged by another session). if the
				   message still isn't expunged in this view,
				   just continue using the current strmap. */
				if (mail_index_lookup_seq(view->view,
						view->lost_expunged_uid, &seq))
					return -1;
			} else if (view->desynced) {
				/* our view isn't synced with the disk, we
				   can't read strmap without first resetting
				   the view */
			} else {
				i_stream_sync(view->strmap->input);
				return 0;
			}
		}
		mail_index_strmap_close(view->strmap);
	}

	return mail_index_strmap_open(view);
}

static int
mail_index_strmap_read_packed(struct mail_index_strmap_read_context *ctx,
			      uint32_t *num_r)
{
	const unsigned char *data;
	const uint8_t *bytes, *p, *end;
	size_t size;
	int ret;

	ret = i_stream_read_bytes(ctx->input, &data, &size, sizeof(*num_r));
	if (ret <= 0)
		return ret;

	if (ctx->input->v_offset + size > ctx->end_offset)
		size = ctx->end_offset - ctx->input->v_offset;
	bytes = p = (const uint8_t *)data;
	end = bytes + size;

	if (mail_index_unpack_num(&p, end, num_r) <  0)
		return -1;
	i_stream_skip(ctx->input, p - bytes);
	return 1;
}

static int
mail_index_strmap_uid_exists(struct mail_index_strmap_read_context *ctx,
			     uint32_t uid)
{
	const struct mail_index_record *rec;

	i_assert(ctx->uid_lookup_seq > 0);

	if (ctx->uid_lookup_seq > ctx->view->view->map->hdr.messages_count) {
		if (uid >= ctx->view->view->map->hdr.next_uid) {
			/* thread index has larger UIDs than what we've seen
			   in our view. we'll have to read them again later
			   when we know about them */
			ctx->too_large_uids = TRUE;
		}
		return 0;
	}

	rec = MAIL_INDEX_REC_AT_SEQ(ctx->view->view->map, ctx->uid_lookup_seq);
	if (rec->uid == uid) {
		ctx->uid_lookup_seq++;
		return 1;
	} else if (rec->uid > uid) {
		return 0;
	} else {
		/* record that exists in index is missing from strmap.
		   see if it's because the strmap is corrupted or because
		   our current view is a bit stale and the message has already
		   been expunged. */
		mail_index_refresh(ctx->view->view->index);
		if (mail_index_is_expunged(ctx->view->view,
					   ctx->uid_lookup_seq))
			ctx->lost_expunged_uid = rec->uid;
		return -1;
	}
}

static int
mail_index_strmap_read_rec_first(struct mail_index_strmap_read_context *ctx,
				 uint32_t *crc32_r)
{
	size_t size;
	uint32_t n, i, count, str_idx;
	int ret;

	/* <uid> <n> <crc32>*count <str_idx>*count
	   where
	     n = 0 -> count=1 (only Message-ID:)
	     n = 1 -> count=2 (Message-ID: + In-Reply-To:)
	     n = 2+ -> count=n (Message-ID: + References:)
	*/
	if (mail_index_strmap_read_packed(ctx, &n) <= 0)
		return -1;
	count = n < 2 ? n + 1 : n;
	ctx->view->total_ref_count += count;

	ctx->rec_size = count * (sizeof(ctx->rec.str_idx) + sizeof(*crc32_r));
	ret = mail_index_strmap_uid_exists(ctx, ctx->rec.uid);
	if (ret < 0)
		return -1;
	if (i_stream_read_bytes(ctx->view->strmap->input, &ctx->data, &size, ctx->rec_size) <= 0)
		return -1;
	ctx->str_idx_base = ctx->data + count * sizeof(uint32_t);

	if (ret == 0) {
		/* this message has already been expunged, ignore it.
		   update highest string indexes anyway. */
		for (i = 0; i < count; i++) {
			memcpy(&str_idx, ctx->str_idx_base, sizeof(str_idx));
			if (ctx->highest_str_idx < str_idx)
				ctx->highest_str_idx = str_idx;
			ctx->str_idx_base += sizeof(str_idx);
		}
		i_stream_skip(ctx->view->strmap->input, ctx->rec_size);
		return 0;
	}

	/* everything exists. save it. FIXME: these ref_index values
	   are thread index specific, perhaps something more generic
	   should be used some day */
	ctx->end = ctx->data + count * sizeof(*crc32_r);

	ctx->next_ref_index = 0;
	if (!mail_index_strmap_read_rec_next(ctx, crc32_r))
		i_unreached();
	ctx->next_ref_index = n == 1 ? 1 : 2;
	return 1;
}

static bool
mail_index_strmap_read_rec_next(struct mail_index_strmap_read_context *ctx,
				uint32_t *crc32_r)
{
	if (ctx->data == ctx->end) {
		i_stream_skip(ctx->view->strmap->input, ctx->rec_size);
		return FALSE;
	}

	/* FIXME: str_idx could be stored as packed relative values
	   (first relative to highest_idx, the rest relative to the
	   previous str_idx) */

	/* read the record contents */
	memcpy(&ctx->rec.str_idx, ctx->str_idx_base, sizeof(ctx->rec.str_idx));
	memcpy(crc32_r, ctx->data, sizeof(*crc32_r));

	ctx->rec.ref_index = ctx->next_ref_index++;

	if (ctx->highest_str_idx < ctx->rec.str_idx)
		ctx->highest_str_idx = ctx->rec.str_idx;

	/* get to the next record */
	ctx->data += sizeof(*crc32_r);
	ctx->str_idx_base += sizeof(ctx->rec.str_idx);
	return TRUE;
}

static int
strmap_read_block_init(struct mail_index_strmap_view *view,
		       struct mail_index_strmap_read_context *ctx)
{
	struct mail_index_strmap *strmap = view->strmap;
	const unsigned char *data;
	size_t size;
	uint32_t block_size, seq1, seq2;
	int ret;

	if (view->last_read_uid + 1 >= view->view->map->hdr.next_uid) {
		/* come back later when we know about the new UIDs */
		return 0;
	}

	i_zero(ctx);
	ret = i_stream_read_bytes(strmap->input, &data, &size,
				  sizeof(block_size));
	if (ret <= 0) {
		if (strmap->input->stream_errno == 0) {
			/* no new data */
			return 0;
		}
		mail_index_strmap_set_syscall_error(strmap, "read()");
		return -1;
	}
	memcpy(&block_size, data, sizeof(block_size));
	block_size = mail_index_offset_to_uint32(block_size) >> 2;
	if (block_size == 0) {
		/* the rest of the file is either not written, or the previous
		   write didn't finish */
		return 0;
	}
	i_stream_skip(strmap->input, sizeof(block_size));

	ctx->view = view;
	ctx->input = strmap->input;
	ctx->end_offset = strmap->input->v_offset + block_size;
	if (ctx->end_offset < strmap->input->v_offset) {
		/* block size too large */
		mail_index_strmap_view_set_corrupted(view);
		return -1;
	}
	ctx->rec.uid = view->last_read_uid + 1;

	/* FIXME: when reading multiple blocks we shouldn't have to calculate
	   this every time */
	if (!mail_index_lookup_seq_range(view->view, ctx->rec.uid, (uint32_t)-1,
					 &seq1, &seq2))
		seq1 = mail_index_view_get_messages_count(view->view) + 1;
	ctx->uid_lookup_seq = seq1;
	return 1;
}

static int
strmap_read_block_next(struct mail_index_strmap_read_context *ctx,
		       uint32_t *crc32_r)
{
	uint32_t uid_diff;
	int ret;

	if (mail_index_strmap_read_rec_next(ctx, crc32_r))
		return 1;

	/* get next UID */
	do {
		if (ctx->input->v_offset == ctx->end_offset) {
			/* this block is done */
			return 0;
		}
		if (mail_index_strmap_read_packed(ctx, &uid_diff) <= 0)
			return -1;

		ctx->rec.uid += uid_diff;
		ret = mail_index_strmap_read_rec_first(ctx, crc32_r);
	} while (ret == 0);
	return ret;
}

static int
strmap_read_block_deinit(struct mail_index_strmap_read_context *ctx, int ret,
			 bool update_block_offset)
{
	struct mail_index_strmap_view *view = ctx->view;
	struct mail_index_strmap *strmap = view->strmap;

	if (ctx->highest_str_idx > view->total_ref_count) {
		/* if all string indexes are unique, highest_str_index equals
		   total_ref_count. otherwise it's always lower. */
		mail_index_set_error(strmap->index,
				     "Corrupted strmap index file %s: "
				     "String indexes too high "
				     "(highest=%u max=%u)",
				     strmap->path, ctx->highest_str_idx,
				     view->total_ref_count);
		mail_index_strmap_view_set_corrupted(view);
		return -1;
	}
	if (ctx->lost_expunged_uid != 0) {
		/* our view contained a message that had since been expunged. */
		i_assert(ret < 0);
		view->lost_expunged_uid = ctx->lost_expunged_uid;
	} else if (ret < 0) {
		if (strmap->input->stream_errno != 0)
			mail_index_strmap_set_syscall_error(strmap, "read()");
		else
			mail_index_strmap_view_set_corrupted(view);
		return -1;
	} else if (update_block_offset && !ctx->too_large_uids) {
		view->last_read_block_offset = strmap->input->v_offset;
		view->last_read_uid = ctx->rec.uid;
	}
	if (view->next_str_idx <= ctx->highest_str_idx)
		view->next_str_idx = ctx->highest_str_idx + 1;
	return ret;
}

static bool
strmap_view_sync_handle_conflict(struct mail_index_strmap_read_context *ctx,
				 const struct mail_index_strmap_rec *hash_rec,
				 struct hash2_iter *iter)
{
	uint32_t seq;

	/* hopefully it's a message that has since been expunged */
	if (!mail_index_lookup_seq(ctx->view->view, hash_rec->uid, &seq)) {
		/* message is no longer in our view. remove it completely. */
		hash2_remove_iter(ctx->view->hash, iter);
		return TRUE;
	}
	if (mail_index_is_expunged(ctx->view->view, seq)) {
		/* it's quite likely a conflict. we may not be able to verify
		   it, so just assume it is. nothing breaks even if we guess
		   wrong, the performance just suffers a bit. */
		return FALSE;
	}

	/* 0 means "doesn't match", which is the only acceptable case */
	return ctx->view->rec_compare(&ctx->rec, hash_rec,
				      ctx->view->cb_context) == 0;
}

static int
strmap_view_sync_block_check_conflicts(struct mail_index_strmap_read_context *ctx,
				       uint32_t crc32)
{
	struct mail_index_strmap_rec *hash_rec;
	struct hash2_iter iter;

	if (crc32 == 0) {
		/* unique string - there are no conflicts */
		return 0;
	}

	/* check for conflicting string indexes. they may happen if

	1) msgid exists only for a message X that has been expunged
	2) another process doesn't see X, but sees msgid for another
	   message and writes it using a new string index
	3) if we still see X, we now see the same msgid with two
	   string indexes.

	if we detect such a conflict, we can't continue using the
	strmap index until X has been expunged. */
	i_zero(&iter);
	while ((hash_rec = hash2_iterate(ctx->view->hash,
					 crc32, &iter)) != NULL &&
	       hash_rec->str_idx != ctx->rec.str_idx) {
		/* CRC32 matches, but string index doesn't */
		if (!strmap_view_sync_handle_conflict(ctx, hash_rec, &iter)) {
			ctx->lost_expunged_uid = hash_rec->uid;
			return -1;
		}
	}
	return 0;
}

static int
mail_index_strmap_view_sync_block(struct mail_index_strmap_read_context *ctx)
{
	struct mail_index_strmap_rec *hash_rec;
	uint32_t crc32, prev_uid = 0;
	int ret;

	while ((ret = strmap_read_block_next(ctx, &crc32)) > 0) {
		if (ctx->rec.uid <= ctx->view->last_added_uid) {
			if (ctx->rec.uid < ctx->view->last_added_uid ||
			    prev_uid != ctx->rec.uid) {
				/* we've already added this */
				continue;
			}
		}
		prev_uid = ctx->rec.uid;

		if (strmap_view_sync_block_check_conflicts(ctx, crc32) < 0) {
			ret = -1;
			break;
		}
		ctx->view->last_added_uid = ctx->rec.uid;

		/* add the record to records array */
		array_push_back(&ctx->view->recs, &ctx->rec);
		array_push_back(&ctx->view->recs_crc32, &crc32);

		/* add a separate copy of the record to hash */
		hash_rec = hash2_insert_hash(ctx->view->hash, crc32);
		memcpy(hash_rec, &ctx->rec, sizeof(*hash_rec));
	}
	return strmap_read_block_deinit(ctx, ret, TRUE);
}

struct mail_index_strmap_view_sync *
mail_index_strmap_view_sync_init(struct mail_index_strmap_view *view,
				 uint32_t *last_uid_r)
{
	struct mail_index_strmap_view_sync *sync;
	struct mail_index_strmap_read_context ctx;
	int ret;

	sync = i_new(struct mail_index_strmap_view_sync, 1);
	sync->view = view;

	if (mail_index_strmap_refresh(view) < 0) {
		/* reading the strmap failed - just ignore and do
		   this in-memory based on whatever we knew last */
	} else if (view->strmap->input != NULL) {
		i_stream_seek(view->strmap->input,
			      view->last_read_block_offset);
		while ((ret = strmap_read_block_init(view, &ctx)) > 0) {
			if (mail_index_strmap_view_sync_block(&ctx) < 0) {
				ret = -1;
				break;
			}
			if (ctx.too_large_uids)
				break;
		}

		if (ret < 0) {
			/* something failed - we can still use the strmap as far
			   as we managed to read it, but our view is now out
			   of sync */
			view->desynced = TRUE;
		} else {
			i_assert(view->lost_expunged_uid == 0);
		}
	}
	*last_uid_r = view->last_added_uid;
	return sync;
}

static inline uint32_t crc32_str_nonzero(const char *str)
{
	/* we'll flip the bits because of a bug in our old crc32 code.
	   this keeps the index format backwards compatible with the new fixed
	   crc32 code. */
	uint32_t value = crc32_str(str) ^ 0xffffffffU;
	return value == 0 ? 1 : value;
}

void mail_index_strmap_view_sync_add(struct mail_index_strmap_view_sync *sync,
				     uint32_t uid, uint32_t ref_index,
				     const char *key)
{
	struct mail_index_strmap_view *view = sync->view;
	struct mail_index_strmap_rec *rec, *old_rec;
	struct mail_index_strmap_hash_key hash_key;
	uint32_t str_idx;

	i_assert(uid > view->last_added_uid ||
		 (uid == view->last_added_uid &&
		  ref_index > view->last_ref_index));

	hash_key.str = key;
	hash_key.crc32 = crc32_str_nonzero(key);

	old_rec = hash2_lookup(view->hash, &hash_key);
	if (old_rec != NULL) {
		/* The string already exists, use the same unique idx */
		str_idx = old_rec->str_idx;
	} else {
		/* Newly seen string, assign a new unique idx to it */
		str_idx = view->next_str_idx++;
	}
	i_assert(str_idx != 0);

	rec = hash2_insert(view->hash, &hash_key);
	rec->uid = uid;
	rec->ref_index = ref_index;
	rec->str_idx = str_idx;
	array_push_back(&view->recs, rec);
	array_push_back(&view->recs_crc32, &hash_key.crc32);

	view->last_added_uid = uid;
	view->last_ref_index = ref_index;
}

void mail_index_strmap_view_sync_add_unique(struct mail_index_strmap_view_sync *sync,
					    uint32_t uid, uint32_t ref_index)
{
	struct mail_index_strmap_view *view = sync->view;
	struct mail_index_strmap_rec rec;

	i_assert(uid > view->last_added_uid ||
		 (uid == view->last_added_uid &&
		  ref_index > view->last_ref_index));

	i_zero(&rec);
	rec.uid = uid;
	rec.ref_index = ref_index;
	rec.str_idx = view->next_str_idx++;
	array_push_back(&view->recs, &rec);
	array_append_zero(&view->recs_crc32);

	view->last_added_uid = uid;
	view->last_ref_index = ref_index;
}

static void
mail_index_strmap_zero_terminate(struct mail_index_strmap_view *view)
{
	/* zero-terminate the records array */
	array_append_zero(&view->recs);
	array_delete(&view->recs, array_count(&view->recs)-1, 1);
}

static void mail_index_strmap_view_renumber(struct mail_index_strmap_view *view)
{
	struct mail_index_strmap_read_context ctx;
	struct mail_index_strmap_rec *recs, *hash_rec;
	uint32_t prev_uid, str_idx, *recs_crc32, *renumber_map;
	unsigned int i, dest, count, count2;
	int ret;

	i_zero(&ctx);
	ctx.view = view;
	ctx.uid_lookup_seq = 1;

	/* create a map of old -> new index and remove records of
	   expunged messages */
	renumber_map = i_new(uint32_t, view->next_str_idx);
	str_idx = 0; prev_uid = 0;
	recs = array_get_modifiable(&view->recs, &count);
	recs_crc32 = array_get_modifiable(&view->recs_crc32, &count2);
	i_assert(count == count2);

	for (i = dest = 0; i < count; ) {
		if (prev_uid != recs[i].uid) {
			/* see if this record should be removed */
			prev_uid = recs[i].uid;
			ret = mail_index_strmap_uid_exists(&ctx, prev_uid);
			i_assert(ret >= 0);
			if (ret == 0) {
				/* message expunged */
				do {
					i++;
				} while (i < count && recs[i].uid == prev_uid);
				continue;
			}
		}

		i_assert(recs[i].str_idx < view->next_str_idx);
		if (renumber_map[recs[i].str_idx] == 0)
			renumber_map[recs[i].str_idx] = ++str_idx;
		if (i != dest) {
			recs[dest] = recs[i];
			recs_crc32[dest] = recs_crc32[i];
		}
		i++; dest++;
	}
	i_assert(renumber_map[0] == 0);
	array_delete(&view->recs, dest, i-dest);
	array_delete(&view->recs_crc32, dest, i-dest);
	mail_index_strmap_zero_terminate(view);

	/* notify caller of the renumbering */
	i_assert(str_idx <= view->next_str_idx);
	view->remap_cb(renumber_map, view->next_str_idx, str_idx + 1,
		       view->cb_context);

	/* renumber the indexes in-place and recreate the hash */
	recs = array_get_modifiable(&view->recs, &count);
	hash2_clear(view->hash);
	for (i = 0; i < count; i++) {
		recs[i].str_idx = renumber_map[recs[i].str_idx];
		hash_rec = hash2_insert_hash(view->hash, recs_crc32[i]);
		memcpy(hash_rec, &recs[i], sizeof(*hash_rec));
	}

	/* update the new next_str_idx only after remapping */
	view->next_str_idx = str_idx + 1;
	i_free(renumber_map);
}

static void mail_index_strmap_write_block(struct mail_index_strmap_view *view,
					  struct ostream *output,
					  unsigned int i, uint32_t base_uid)
{
	const struct mail_index_strmap_rec *recs;
	const uint32_t *crc32;
	unsigned int j, n, count, count2, uid_rec_count;
	uint32_t block_size;
	uint8_t *p, packed[MAIL_INDEX_PACK_MAX_SIZE*2];
	uoff_t block_offset, end_offset;

	/* skip over the block size for now, we don't know it yet */
	block_offset = output->offset;
	block_size = 0;
	o_stream_nsend(output, &block_size, sizeof(block_size));

	/* write records */
	recs = array_get(&view->recs, &count);
	crc32 = array_get(&view->recs_crc32, &count2);
	i_assert(count == count2);
	while (i < count) {
		/* @UNSAFE: <uid diff> */
		p = packed;
		mail_index_pack_num(&p, recs[i].uid - base_uid);
		base_uid = recs[i].uid;

		/* find how many records belong to this UID */
		uid_rec_count = 1;
		for (j = i + 1; j < count; j++) {
			if (recs[j].uid != base_uid)
				break;
			uid_rec_count++;
		}
		view->total_ref_count += uid_rec_count;

		/* <n> <crc32>*count <str_idx>*count -
		   FIXME: thread index specific code */
		i_assert(recs[i].ref_index == 0);
		if (uid_rec_count == 1) {
			/* Only Message-ID: header */
			n = 0;
		} else if (recs[i+1].ref_index == 1) {
			/* In-Reply-To: header */
			n = 1;
			i_assert(uid_rec_count == 2);
		} else {
			/* References: header */
			n = uid_rec_count;
			i_assert(recs[i+1].ref_index == 2);
		}

		mail_index_pack_num(&p, n);
		o_stream_nsend(output, packed, p-packed);
		for (j = 0; j < uid_rec_count; j++)
			o_stream_nsend(output, &crc32[i+j], sizeof(crc32[i+j]));
		for (j = 0; j < uid_rec_count; j++) {
			i_assert(j < 2 || recs[i+j].ref_index == j+1);
			o_stream_nsend(output, &recs[i+j].str_idx,
				       sizeof(recs[i+j].str_idx));
		}
		i += uid_rec_count;
	}

	/* we know the block size now - write it */
	block_size = output->offset - (block_offset + sizeof(block_size));
	block_size = mail_index_uint32_to_offset(block_size << 2);
	i_assert(block_size != 0);

	end_offset = output->offset;
	(void)o_stream_seek(output, block_offset);
	o_stream_nsend(output, &block_size, sizeof(block_size));
	(void)o_stream_seek(output, end_offset);

	if (output->stream_errno != 0)
		return;

	i_assert(view->last_added_uid == recs[count-1].uid);
	view->last_read_uid = recs[count-1].uid;
	view->last_read_block_offset = output->offset;
}

static void
mail_index_strmap_recreate_write(struct mail_index_strmap_view *view,
				 struct ostream *output)
{
	const struct mail_index_header *idx_hdr;
	struct mail_index_strmap_header hdr;

	idx_hdr = mail_index_get_header(view->view);

	/* write header */
	i_zero(&hdr);
	hdr.version = MAIL_INDEX_STRMAP_VERSION;
	hdr.uid_validity = idx_hdr->uid_validity;
	o_stream_nsend(output, &hdr, sizeof(hdr));

	view->total_ref_count = 0;
	mail_index_strmap_write_block(view, output, 0, 1);
}

static int mail_index_strmap_recreate(struct mail_index_strmap_view *view)
{
	struct mail_index_strmap *strmap = view->strmap;
	string_t *str;
	struct ostream *output;
	const char *temp_path;
	int fd, ret = 0;

	if (array_count(&view->recs) == 0) {
		/* everything expunged - just unlink the existing index */
		if (unlink(strmap->path) < 0 && errno != ENOENT)
			mail_index_strmap_set_syscall_error(strmap, "unlink()");
		return 0;
	}

	str = t_str_new(256);
	str_append(str, strmap->path);
	fd = safe_mkstemp_hostpid_group(str, view->view->index->mode,
					view->view->index->gid,
					view->view->index->gid_origin);
	temp_path = str_c(str);

	if (fd == -1) {
		mail_index_set_error(strmap->index,
				     "safe_mkstemp_hostpid(%s) failed: %m",
				     temp_path);
		return -1;
	}
	output = o_stream_create_fd(fd, 0);
	o_stream_cork(output);
	mail_index_strmap_recreate_write(view, output);
	if (o_stream_finish(output) < 0) {
		mail_index_set_error(strmap->index, "write(%s) failed: %s",
				     temp_path, o_stream_get_error(output));
		ret = -1;
	}
	o_stream_destroy(&output);
	if (close(fd) < 0) {
		mail_index_set_error(strmap->index,
				     "close(%s) failed: %m", temp_path);
		ret = -1;
	} else if (ret == 0 && rename(temp_path, strmap->path) < 0) {
		mail_index_set_error(strmap->index,
				     "rename(%s, %s) failed: %m",
				     temp_path, strmap->path);
		ret = -1;
	}
	if (ret < 0)
		i_unlink(temp_path);
	return ret;
}

static int mail_index_strmap_lock(struct mail_index_strmap *strmap)
{
	unsigned int timeout_secs;
	int ret;

	i_assert(strmap->fd != -1);

	if (strmap->index->lock_method != FILE_LOCK_METHOD_DOTLOCK) {
		i_assert(strmap->file_lock == NULL);

		timeout_secs = I_MIN(MAIL_INDEX_STRMAP_TIMEOUT_SECS,
				     strmap->index->max_lock_timeout_secs);
		ret = file_wait_lock(strmap->fd, strmap->path, F_WRLCK,
				     strmap->index->lock_method, timeout_secs,
				     &strmap->file_lock);
		if (ret <= 0) {
			mail_index_strmap_set_syscall_error(strmap,
							    "file_wait_lock()");
		}
	} else {
		i_assert(strmap->dotlock == NULL);

		ret = file_dotlock_create(&strmap->dotlock_settings,
					  strmap->path, 0, &strmap->dotlock);
		if (ret <= 0) {
			mail_index_strmap_set_syscall_error(strmap,
				"file_dotlock_create()");
		}
	}
	return ret;
}

static void mail_index_strmap_unlock(struct mail_index_strmap *strmap)
{
	if (strmap->file_lock != NULL)
		file_unlock(&strmap->file_lock);
	else if (strmap->dotlock != NULL)
		file_dotlock_delete(&strmap->dotlock);
}

static int
strmap_rec_cmp(const uint32_t *uid, const struct mail_index_strmap_rec *rec)
{
	return *uid < rec->uid ? -1 :
		(*uid > rec->uid ? 1 : 0);
}

static int
mail_index_strmap_write_append(struct mail_index_strmap_view *view)
{
	struct mail_index_strmap_read_context ctx;
	const struct mail_index_strmap_rec *old_recs;
	unsigned int i, old_count;
	struct ostream *output;
	uint32_t crc32, next_uid;
	bool full_block;
	int ret;

	/* Check first if another process had written new records to the file.
	   If there are any, hopefully they're the same as what we would be
	   writing. There are two problematic cases when messages have been
	   expunged recently:

	   1) The file contains UIDs that we don't have. This means the string
	   indexes won't be compatible anymore, so we'll have to renumber ours
	   to match the ones in the strmap file.

	   Currently we don't bother handling 1) case. If indexes don't match
	   what we have, we just don't write anything.

	   2) We have UIDs that don't exist in the file. We can't simply skip
	   those records, because other records may have pointers to them using
	   different string indexes than we have. Even if we renumbered those,
	   future appends by other processes might cause the same problem (they
	   see the string for the first time and assign it a new index, but we
	   already have internally given it another index). So the only
	   sensible choice is to write nothing and hope that the message goes
	   away soon. */
	next_uid = view->last_read_uid + 1;
	(void)array_bsearch_insert_pos(&view->recs, &next_uid,
				       strmap_rec_cmp, &i);

	old_recs = array_get(&view->recs, &old_count);
	if (i < old_count) {
		while (i > 0 && old_recs[i-1].uid == old_recs[i].uid)
			i--;
	}

	i_stream_sync(view->strmap->input);
	i_stream_seek(view->strmap->input, view->last_read_block_offset);
	full_block = TRUE; ret = 0;
	while (i < old_count &&
	       (ret = strmap_read_block_init(view, &ctx)) > 0) {
		while ((ret = strmap_read_block_next(&ctx, &crc32)) > 0) {
			if (ctx.rec.uid != old_recs[i].uid ||
			    ctx.rec.str_idx != old_recs[i].str_idx) {
				/* mismatch */
				if (ctx.rec.uid > old_recs[i].uid) {
					/* 1) case */
					ctx.lost_expunged_uid = ctx.rec.uid;
				} else if (ctx.rec.uid < old_recs[i].uid) {
					/* 2) case */
					ctx.lost_expunged_uid = old_recs[i].uid;
				} else {
					/* string index mismatch,
					   shouldn't happen */
				}
				ret = -1;
				break;
			}
			if (++i == old_count) {
				full_block = FALSE;
				break;
			}
		}
		if (strmap_read_block_deinit(&ctx, ret, full_block) < 0) {
			ret = -1;
			break;
		}
	}
	if (ret < 0)
		return -1;
	if (i == old_count) {
		/* nothing new to write */
		return 0;
	}
	i_assert(full_block);
	i_assert(old_recs[i].uid > view->last_read_uid);

	/* write the new records */
	output = o_stream_create_fd(view->strmap->fd, 0);
	(void)o_stream_seek(output, view->last_read_block_offset);
	o_stream_cork(output);
	mail_index_strmap_write_block(view, output, i,
				      view->last_read_uid + 1);
	if (o_stream_finish(output) < 0) {
		mail_index_strmap_set_syscall_error(view->strmap, "write()");
		ret = -1;
	}
	o_stream_destroy(&output);
	return ret;
}

static int mail_index_strmap_write(struct mail_index_strmap_view *view)
{
	int ret;

	/* FIXME: this renumbering doesn't work well when running for a long
	   time since records aren't removed from hash often enough */
	if (STRIDX_MUST_RENUMBER(view->next_str_idx - 1,
				 hash2_count(view->hash))) {
		mail_index_strmap_view_renumber(view);
		if (!MAIL_INDEX_IS_IN_MEMORY(view->strmap->index)) {
			if (mail_index_strmap_recreate(view) < 0) {
				view->desynced = TRUE;
				return -1;
			}
		}
		return 0;
	}

	if (MAIL_INDEX_IS_IN_MEMORY(view->strmap->index) || view->desynced)
		return 0;

	if (view->strmap->fd == -1) {
		/* initial file creation */
		if (mail_index_strmap_recreate(view) < 0) {
			view->desynced = TRUE;
			return -1;
		}
		return 0;
	}

	/* append the new records to the strmap file */
	if (mail_index_strmap_lock(view->strmap) <= 0) {
		/* timeout / error */
		ret = -1;
	} else if (mail_index_strmap_need_reopen(view->strmap)) {
		/* the file was already recreated - leave the syncing as it is
		   for now and let the next sync re-read the file. */
		ret = 0;
	} else {
		ret = mail_index_strmap_write_append(view);
	}
	mail_index_strmap_unlock(view->strmap);
	if (ret < 0)
		view->desynced = TRUE;
	return ret;
}

void mail_index_strmap_view_sync_commit(struct mail_index_strmap_view_sync **_sync)
{
	struct mail_index_strmap_view_sync *sync = *_sync;
	struct mail_index_strmap_view *view = sync->view;

	*_sync = NULL;
	i_free(sync);

	(void)mail_index_strmap_write(view);
	mail_index_strmap_zero_terminate(view);

	/* zero-terminate the records array */
	array_append_zero(&view->recs);
	array_delete(&view->recs, array_count(&view->recs)-1, 1);
}

void mail_index_strmap_view_sync_rollback(struct mail_index_strmap_view_sync **_sync)
{
	struct mail_index_strmap_view_sync *sync = *_sync;

	*_sync = NULL;

	mail_index_strmap_view_reset(sync->view);
	mail_index_strmap_zero_terminate(sync->view);
	i_free(sync);
}
