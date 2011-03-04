/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "crc32.h"
#include "file-cache.h"
#include "file-set-size.h"
#include "mmap-util.h"
#include "nfs-workarounds.h"
#include "ostream.h"
#include "mail-index-private.h"
#include "mailbox-list-index-private.h"

#include <stddef.h>

#define ROOT_INIT_COUNT 128
#define DIR_ALLOC_MORE_COUNT 4
#define MAILBOX_LIST_INDEX_GROW_PERCENTAGE 10
#define MAILBOX_LIST_INDEX_MIN_SIZE 512

struct mailbox_list_sync_record {
	uint32_t name_hash;
	uint32_t seq;
	uint32_t uid;
	const char *name;

	/* dir is used if it's non-NULL, otherwise dir_offset is used */
	struct mailbox_list_sync_dir *dir;
	uint32_t dir_offset;

	uint32_t created:1;
	/* This record was seen while syncing, either as parent or as leaf */
	uint32_t seen:1;
	/* This record was seen as leaf while syncing, so it exists */
	uint32_t exists:1;
};

struct mailbox_list_sync_dir {
	/* The records are sorted by their name_hash */
	ARRAY_DEFINE(records, struct mailbox_list_sync_record);

	/* Offset to the original location in the index, or 0 for new dirs */
	uint32_t offset;
	unsigned int seen_records_count;
	unsigned int new_records_count;
};

struct mailbox_list_index_sync_ctx {
	struct mailbox_list_index *index;
	struct mailbox_list_index_view *view;
	pool_t pool;

	enum mailbox_list_sync_flags flags;
	const char *sync_path;
	struct mail_index_sync_ctx *mail_sync_ctx;
	struct mail_index_view *mail_view;
	struct mail_index_transaction *trans;

	struct mailbox_list_index_header hdr;
	struct mailbox_list_sync_dir *root, *sync_root;

	struct ostream *output;
	buffer_t *output_buf;

	unsigned int failed:1;
	unsigned int changed:1;
	unsigned int restart:1;
	unsigned int partial:1;
	unsigned int seen_sync_root:1;
};

struct mailbox_list_sync_lookup_key {
	uint32_t name_hash;
	const char *name;
};

static bool mailbox_list_index_need_compress(struct mailbox_list_index *index);
static int mailbox_list_index_compress(struct mailbox_list_index_sync_ctx *ctx);

static struct mailbox_list_sync_dir *
mailbox_list_alloc_sync_dir(struct mailbox_list_index_sync_ctx *ctx,
			    unsigned int initial_count)
{
	struct mailbox_list_sync_dir *sync_dir;

	sync_dir = p_new(ctx->pool, struct mailbox_list_sync_dir, 1);
	p_array_init(&sync_dir->records, ctx->pool, initial_count);
	return sync_dir;
}

static int
mailbox_list_copy_sync_dir(struct mailbox_list_index_sync_ctx *ctx,
			   uint32_t offset,
			   struct mailbox_list_sync_dir **sync_dir_r)
{
	const struct mailbox_list_dir_record *dir;
	const struct mailbox_list_record *recs;
	struct mailbox_list_sync_dir *sync_dir;
	struct mailbox_list_sync_record *sync_rec;
	const char *name;
	size_t max_len;
	unsigned int i;

	if (mailbox_list_index_get_dir(ctx->view, &offset, &dir) < 0)
		return -1;

	sync_dir = mailbox_list_alloc_sync_dir(ctx, dir->count +
					       DIR_ALLOC_MORE_COUNT);
	sync_dir->offset = offset;

	recs = MAILBOX_LIST_RECORDS(dir);
	for (i = 0; i < dir->count; i++) {
		if (recs[i].deleted)
			continue;

		if (recs[i].uid == 0) {
			return mailbox_list_index_set_corrupted(ctx->index,
							"Record with UID=0");
		}

		sync_rec = array_append_space(&sync_dir->records);
		sync_rec->name_hash = recs[i].name_hash;
		sync_rec->uid = recs[i].uid;
		sync_rec->dir_offset =
			mail_index_offset_to_uint32(recs[i].dir_offset);

		max_len = ctx->index->mmap_size - recs[i].name_offset;
		name = CONST_PTR_OFFSET(ctx->index->const_mmap_base,
					recs[i].name_offset);

		sync_rec->name = p_strndup(ctx->pool, name, max_len);
	}

	*sync_dir_r = sync_dir;
	return 0;
}

static int
mailbox_list_sync_record_cmp(const struct mailbox_list_sync_lookup_key *key,
			     const struct mailbox_list_sync_record *rec)
{
	if (key->name_hash < rec->name_hash)
		return -1;
	if (key->name_hash > rec->name_hash)
		return 1;

	return strcmp(key->name, rec->name);
}

static struct mailbox_list_sync_record *
mailbox_list_sync_dir_lookup(struct mailbox_list_sync_dir *dir,
			     const char *name, unsigned int *idx_r)
{
	struct mailbox_list_sync_lookup_key key;

	/* binary search the current hierarchy level name. the values are
	   sorted primarily by their hash value and secondarily by the actual
	   name */
	key.name = name;
	key.name_hash = crc32_str(name);

	if (!array_bsearch_insert_pos(&dir->records, &key,
				      mailbox_list_sync_record_cmp, idx_r))
		return NULL;

	return array_idx_modifiable(&dir->records, *idx_r);
}

static struct mailbox_list_sync_record *
mailbox_list_alloc_add_record(struct mailbox_list_index_sync_ctx *ctx,
			      struct mailbox_list_sync_dir *dir,
			      const char *name, unsigned int idx)
{
	struct mailbox_list_sync_record *rec;

	ctx->changed = TRUE;

	rec = array_insert_space(&dir->records, idx);
	rec->name_hash = crc32_str(name);
	rec->name = p_strdup(ctx->pool, name);
	rec->uid = ctx->hdr.next_uid++;
	rec->created = TRUE;
	mail_index_append(ctx->trans, rec->uid, &rec->seq);

	dir->new_records_count++;
	return rec;
}

static int
mailbox_list_index_sync_get_seq(struct mailbox_list_index_sync_ctx *ctx,
				struct mailbox_list_sync_record *rec)
{
	const struct mail_index_header *mail_hdr;

	if (rec->uid == 0) {
		return mailbox_list_index_set_corrupted(ctx->index,
							"Record with UID=0");
	}
	if (!mail_index_lookup_seq(ctx->mail_view, rec->uid, &rec->seq)) {
		mail_hdr = mail_index_get_header(ctx->mail_view);
		if (rec->uid < mail_hdr->next_uid) {
			i_warning("%s: Desync: Record uid=%u "
				  "expunged from mail index",
				  ctx->index->mail_index->filepath, rec->uid);
			ctx->restart = TRUE;
			return -1;
		}
		mail_index_append(ctx->trans, rec->uid, &rec->seq);
	}
	return 0;
}

static int
mailbox_list_index_sync_int(struct mailbox_list_index_sync_ctx *ctx,
			    const char *name,
			    struct mailbox_list_sync_dir **dir_r,
			    uint32_t *seq_r)
{
	const char *p, *hier_name;
	struct mailbox_list_sync_dir *dir;
	struct mailbox_list_sync_record *rec = NULL;
	unsigned int idx, rec_flags;

	if (ctx->failed)
		return -1;

	dir = ctx->sync_root;
	rec_flags = MAILBOX_LIST_INDEX_FLAG_CHILDREN;

	for (;;) {
		p = strchr(name, ctx->index->separator);
		hier_name = p == NULL ? name : t_strdup_until(name, p);

		if (*hier_name == '\0') {
			if (p == NULL) {
				/* name ended with a separator */
				break;
			}
			/* two separators adjacently, skip this */
			name = p + 1;
			continue;
		}

		if (rec != NULL) {
			/* add CHILDREN flag to the parent and remove
			   NOCHILDREN flag. if we happened to create the
			   parent ourself, also add NONEXISTENT flag. */
			mail_index_update_flags(ctx->trans, rec->seq,
						MODIFY_ADD, rec_flags);
			mail_index_update_flags(ctx->trans, rec->seq,
					MODIFY_REMOVE,
					(enum mail_flags)
					MAILBOX_LIST_INDEX_FLAG_NOCHILDREN);
		}

		rec = mailbox_list_sync_dir_lookup(dir, hier_name, &idx);
		if (rec == NULL) {
			/* new record */
			rec_flags |= MAILBOX_LIST_INDEX_FLAG_NONEXISTENT;
			rec = mailbox_list_alloc_add_record(ctx, dir,
							    hier_name, idx);
		} else if (rec->seq == 0) {
			/* this record was copied from existing index.
			   the uid is known, but the sequence isn't. */
			if (mailbox_list_index_sync_get_seq(ctx, rec) < 0) {
				ctx->failed = TRUE;
				break;
			}
		}
		*seq_r = rec->seq;

		/* remember that we've seen this record */
		if (!rec->seen) {
			rec->seen = TRUE;
			dir->seen_records_count++;
		}

		if (p == NULL) {
			/* leaf */
			rec->exists = TRUE;
			mail_index_update_flags(ctx->trans, rec->seq,
				MODIFY_REMOVE,
				(enum mail_flags)
				MAILBOX_LIST_INDEX_FLAG_NONEXISTENT);
			break;
		}

		/* we were handling a parent, continue with its child */
		if (!rec->exists) {
			/* Mark this mailbox non-existent for now. If it
			   exists, this flag is removed later. */
			mail_index_update_flags(ctx->trans, rec->seq,
				MODIFY_ADD,
				(enum mail_flags)
				MAILBOX_LIST_INDEX_FLAG_NONEXISTENT);
		}

		if (rec->dir == NULL) {
			if (rec->dir_offset != 0) {
				if (mailbox_list_copy_sync_dir(ctx,
							       rec->dir_offset,
							       &rec->dir) < 0) {
					ctx->failed = TRUE;
					break;
				}
			} else {
				rec->dir = mailbox_list_alloc_sync_dir(ctx,
						1 + DIR_ALLOC_MORE_COUNT);
			}
		}

		name = p + 1;
		dir = rec->dir;
	}

	i_assert(dir != NULL);
	*dir_r = dir;
	return ctx->failed ? -1 : 0;
}

static int mailbox_list_index_get_root(struct mailbox_list_index_sync_ctx *ctx)
{
	uint32_t seq;
	int ret;

	i_assert(ctx->index->mmap_size > 0);

	if (ctx->index->mmap_size == sizeof(*ctx->index->hdr)) {
		/* root doesn't exist in the file yet */
		ctx->root = mailbox_list_alloc_sync_dir(ctx,
							ROOT_INIT_COUNT);
	} else {
		if (mailbox_list_copy_sync_dir(ctx, sizeof(*ctx->index->hdr),
					       &ctx->root) < 0)
			return -1;
	}

	/* keep sync_root=root until we've built the sync_root path. */
	ctx->sync_root = ctx->root;

	if (*ctx->sync_path != '\0') {
		if (mailbox_list_index_sync_more(ctx, ctx->sync_path, &seq) < 0)
			return -1;
	}

	T_BEGIN {
		ret = mailbox_list_index_sync_int(ctx, ctx->sync_path,
						  &ctx->sync_root, &seq);
	} T_END;
	return ret;
}

static int sync_mail_sync_init(struct mailbox_list_index_sync_ctx *ctx)
{
	struct mail_index_sync_rec sync_rec;

	if (mail_index_sync_begin(ctx->index->mail_index, &ctx->mail_sync_ctx,
				  &ctx->mail_view, &ctx->trans,
				  MAIL_INDEX_SYNC_FLAG_AVOID_FLAG_UPDATES) < 0)
		return -1;

	mail_index_flush_read_cache(ctx->index->mail_index, ctx->index->filepath,
				    ctx->index->fd, FALSE);

	/* we should have only external transactions in here, for which we
	   don't need to do anything but write them to the index */
	while (mail_index_sync_next(ctx->mail_sync_ctx, &sync_rec))
		;
	return 0;
}

static int sync_mail_sync_init2(struct mailbox_list_index_sync_ctx *ctx)
{
	const struct mail_index_header *mail_hdr;
	uint32_t uid_validity;

	ctx->hdr = *ctx->index->hdr;
	mail_hdr = mail_index_get_header(ctx->mail_view);
	uid_validity = mail_hdr->uid_validity;

	if (uid_validity != 0 || mail_hdr->next_uid != 1) {
		if (uid_validity != ctx->hdr.uid_validity) {
			i_warning("%s: Desync: uid_validity changed %u -> %u",
				  ctx->index->mail_index->filepath,
				  uid_validity, ctx->hdr.uid_validity);
			uid_validity = 0;
			mail_index_reset(ctx->trans);
		}
	}

	if (uid_validity != ctx->hdr.uid_validity ) {
		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, uid_validity),
			&ctx->hdr.uid_validity, sizeof(ctx->hdr.uid_validity),
			TRUE);
	}

	return 0;
}

int mailbox_list_index_sync_init(struct mailbox_list_index *index,
				 const char *path,
				 enum mailbox_list_sync_flags flags,
				 struct mailbox_list_index_sync_ctx **ctx_r)
{
	struct mailbox_list_index_sync_ctx *ctx;
	struct mailbox_list_index_view *view;
	pool_t pool;
	size_t len;

	if (mailbox_list_index_view_init(index, NULL, &view) < 0)
		return -1;

	/* add separator to end of path if it isn't there */
	len = strlen(path);
	if (len > 0 && path[len-1] != index->separator)
		path = t_strdup_printf("%s%c", path, index->separator);

	pool = pool_alloconly_create(MEMPOOL_GROWING"mailbox list index sync",
				     1024*32);

	ctx = p_new(pool, struct mailbox_list_index_sync_ctx, 1);
	ctx->pool = pool;
	ctx->index = index;
	ctx->view = view;
	ctx->sync_path = p_strdup(pool, path);
	ctx->flags = flags;

	/* mail index syncing acts as the only locking for us */
	if (sync_mail_sync_init(ctx) < 0 ||
	    mailbox_list_index_refresh(index) < 0 ||
	    sync_mail_sync_init2(ctx) < 0 ||
	    mailbox_list_index_get_root(ctx) < 0) {
		mailbox_list_index_sync_rollback(&ctx);
		return -1;
	}

	*ctx_r = ctx;
	return 0;
}

struct mail_index_view *
mailbox_list_index_sync_get_view(struct mailbox_list_index_sync_ctx *ctx)
{
	return ctx->mail_view;
}

struct mail_index_transaction *
mailbox_list_index_sync_get_transaction(struct mailbox_list_index_sync_ctx *ctx)
{
	return ctx->trans;
}

int mailbox_list_index_sync_more(struct mailbox_list_index_sync_ctx *ctx,
				 const char *name, uint32_t *seq_r)
{
	struct mailbox_list_sync_dir *dir;
	int ret;

	T_BEGIN {
		ret = mailbox_list_index_sync_int(ctx, name, &dir, seq_r);
	} T_END;
	return ret;
}

static int
mailbox_list_index_sync_grow(struct mailbox_list_index_sync_ctx *ctx,
			     uint32_t size)
{
	struct mailbox_list_index *index = ctx->index;
	uoff_t new_fsize, grow_size;

	new_fsize = ctx->hdr.used_space + size;
	grow_size = new_fsize / 100 * MAILBOX_LIST_INDEX_GROW_PERCENTAGE;
	if (grow_size < MAILBOX_LIST_INDEX_MIN_SIZE)
		grow_size = MAILBOX_LIST_INDEX_MIN_SIZE;
	new_fsize += grow_size;
	new_fsize &= ~(512-1);

	i_assert(new_fsize >= ctx->hdr.used_space + size);

	if (file_set_size(index->fd, (off_t)new_fsize) < 0) {
		mailbox_list_index_set_syscall_error(index, "file_set_size()");
		return -1;
	}

	return mailbox_list_index_map(index);
}

static int
mailbox_list_index_sync_alloc_space(struct mailbox_list_index_sync_ctx *ctx,
				    uint32_t size, void **base_r,
				    uint32_t *base_offset_r)
{
	size_t pos = ctx->hdr.used_space;

	/* all allocations must be 32bit aligned */
	pos = (pos + 3) & ~3;

	if (ctx->index->mmap_base == NULL) {
		/* write the data into temporary buffer first */
		buffer_reset(ctx->output_buf);
		*base_r = buffer_append_space_unsafe(ctx->output_buf, size);
	} else {
		if (pos + size > ctx->index->mmap_size) {
			if (mailbox_list_index_sync_grow(ctx, size + 3) < 0)
				return -1;

			i_assert(pos + size < ctx->index->mmap_size);
		}
		*base_r = PTR_OFFSET(ctx->index->mmap_base, pos);
		memset(*base_r, 0, size);
	}

	*base_offset_r = pos;
	ctx->hdr.used_space = pos + size;
	ctx->changed = TRUE;
	return 0;
}

static int
mailbox_list_index_sync_recreate_dir(struct mailbox_list_index_sync_ctx *ctx,
				     struct mailbox_list_sync_dir *sync_dir,
				     uint32_t offset_pos, bool partial)
{
	struct mailbox_list_index *index = ctx->index;
	const struct mailbox_list_dir_record *dir;
	const struct mailbox_list_record *recs;
	struct mailbox_list_dir_record *new_dir;
	struct mailbox_list_record *new_recs;
	struct mailbox_list_sync_record *sync_recs;
	unsigned int src, dest, orig, count, nondeleted_count;
	unsigned int space_needed, deleted_space;
	uint32_t base_offset, name_pos, size;
	void *base;

	i_assert((offset_pos % sizeof(uint32_t)) == 0);
	i_assert(offset_pos < index->mmap_size);

	/* count how much space we need and how much we wasted for deleted
	   records */
	nondeleted_count = 0; space_needed = 0;
	sync_recs = array_get_modifiable(&sync_dir->records, &count);
	for (src = 0; src < count; src++) {
		if (sync_recs[src].seen || partial) {
			nondeleted_count++;
			if (sync_recs[src].created) {
				/* new record */
				space_needed += strlen(sync_recs[src].name) + 1;
			}
		}
	}

	/* @UNSAFE */
	space_needed += sizeof(*dir) + nondeleted_count * sizeof(*new_recs);
	if (mailbox_list_index_sync_alloc_space(ctx, space_needed,
						&base, &base_offset) < 0)
		return -1;
	/* NOTE: any pointers to the index file may have been invalidated
	   as a result of growing the the memory area */

	if (sync_dir->offset == 0) {
		dir = NULL;
		recs = NULL;
		deleted_space = 0;
	} else {
		/* the offset should have been verified already to be valid */
		i_assert(sync_dir->offset == offset_pos);
		i_assert(sync_dir->offset < index->mmap_size);
		dir = CONST_PTR_OFFSET(index->const_mmap_base,
				       sync_dir->offset);
		recs = MAILBOX_LIST_RECORDS(dir);

		/* approximate deleted_space. some of the mailbox names will be
		   reused, but don't bother calculating them. */
		deleted_space = sizeof(*dir) + dir->dir_size;
	}

	new_dir = base;
	new_dir->count = nondeleted_count;
	new_dir->dir_size = space_needed;

	new_recs = MAILBOX_LIST_RECORDS_MODIFIABLE(new_dir);
	name_pos = (const char *)(new_recs + nondeleted_count) -
		(const char *)base;
	for (src = dest = 0; src < count;) {
		if (!sync_recs[src].seen && !partial) {
			/* expunge from mail index */
			uint32_t seq;

			if (mail_index_lookup_seq(ctx->mail_view,
						  sync_recs[src].uid, &seq))
				mail_index_expunge(ctx->trans, seq);
			// FIXME: expunge also NONEXISTENT parents

			/* If we compress the file, the record must be removed
			   from the array. */
			array_delete(&sync_dir->records, src, 1);
			sync_recs = array_get_modifiable(&sync_dir->records,
							 &count);
			continue;
		}

		new_recs[dest].name_hash = sync_recs[src].name_hash;
		new_recs[dest].dir_offset =
			mail_index_uint32_to_offset(sync_recs[src].dir_offset);
		if (sync_recs[src].created) {
			/* new record */
			new_recs[dest].uid = sync_recs[src].uid;
			new_recs[dest].name_offset = base_offset + name_pos;
			size = strlen(sync_recs[src].name) + 1;
			memcpy(PTR_OFFSET(base, name_pos), sync_recs[src].name,
			       size);
			name_pos += size;
		} else {
			/* existing record. need to find its name_offset */
			i_assert(dir != NULL);
			for (orig = 0; orig < dir->count; orig++) {
				if (recs[orig].uid == sync_recs[src].uid)
					break;
			}
			i_assert(orig < dir->count);

			new_recs[dest].uid = sync_recs[src].uid;
			new_recs[dest].name_offset = recs[orig].name_offset;
		}
		src++; dest++;
	}
	i_assert(dest == nondeleted_count);
	i_assert(name_pos == space_needed);

	if (index->mmap_base == NULL) {
		file_cache_write(index->file_cache, ctx->output_buf->data,
				 ctx->output_buf->used, ctx->output->offset);
		o_stream_send(ctx->output, ctx->output_buf->data,
			      ctx->output_buf->used);
	}

	if (offset_pos == 0) {
		/* we're writing the root directory */
		i_assert(base_offset == sizeof(*index->hdr));
	} else {
		/* add a link to this newly created directory. */
		uint32_t data = mail_index_uint32_to_offset(base_offset);

		if (index->mmap_base != NULL)  {
			uint32_t *pos;

			pos = PTR_OFFSET(index->mmap_base, offset_pos);
			i_assert(mail_index_offset_to_uint32(*pos) == 0);
			*pos = data;
		} else {
			uoff_t old_offset = ctx->output->offset;

			file_cache_write(index->file_cache,
					 &data, sizeof(data), offset_pos);

			o_stream_seek(ctx->output, offset_pos);
			o_stream_send(ctx->output, &data, sizeof(data));
			o_stream_seek(ctx->output, old_offset);
		}
	}

	if (index->mmap_base == NULL) {
		/* file_cache_write() calls may have moved mmaping */
		index->const_mmap_base = file_cache_get_map(index->file_cache,
							    &index->mmap_size);
		index->hdr = index->const_mmap_base;
	}

	ctx->hdr.deleted_space += deleted_space;
	ctx->changed = TRUE;
	sync_dir->offset = base_offset;
	return 0;
}

static int
mailbox_list_index_sync_update_dir(struct mailbox_list_index_sync_ctx *ctx,
				   struct mailbox_list_sync_dir *sync_dir)
{
	const struct mailbox_list_dir_record *dir;
	struct mailbox_list_record *recs;
	const struct mailbox_list_sync_record *sync_recs;
	unsigned int i, j, count;
	uint32_t seq;

	i_assert(sync_dir->offset != 0);

	if (mailbox_list_index_get_dir(ctx->view, &sync_dir->offset, &dir) < 0)
		return -1;

	sync_recs = array_get(&sync_dir->records, &count);
	i_assert(count <= dir->count);
	i_assert(sync_dir->seen_records_count < count);

	if (ctx->index->mmap_base != NULL)
		recs = MAILBOX_LIST_RECORDS_MODIFIABLE(dir);
	else {
		/* @UNSAFE: copy the records into a temporary buffer that
		   we modify and then write back to disk */
		recs = t_new(struct mailbox_list_record, dir->count);
		memcpy(recs, MAILBOX_LIST_RECORDS(dir),
		       sizeof(struct mailbox_list_record) * dir->count);
	}

	/* records marked with deleted have been removed from sync_recs, so
	   we need to skip those */
	for (i = j = 0; i < count; ) {
		while (recs[j].uid != sync_recs[i].uid) {
			j++;
			i_assert(j < dir->count);
		}

		if (!sync_recs[i].seen) {
			recs[j].deleted = TRUE;

			/* expunge from mail index */
			if (mail_index_lookup_seq(ctx->mail_view,
						  sync_recs[i].uid, &seq))
				mail_index_expunge(ctx->trans, seq);

			/* If we compress the file, the record must be removed
			   from the array. */
			array_delete(&sync_dir->records, i, 1);
			sync_recs = array_get(&sync_dir->records, &count);
		} else {
			i++;
		}
	}
	if (ctx->index->mmap_base == NULL) {
		uoff_t offset, old_offset;
		size_t size = sizeof(struct mailbox_list_record) * dir->count;

		offset = sync_dir->offset +
			sizeof(struct mailbox_list_dir_record);
		file_cache_write(ctx->index->file_cache, recs, size, offset);

		old_offset = ctx->output->offset;
		o_stream_seek(ctx->output, offset);
		o_stream_send(ctx->output, recs, size);
		o_stream_seek(ctx->output, old_offset);
	}
	ctx->changed = TRUE;
	return 0;
}

static int
mailbox_list_index_sync_write_dir(struct mailbox_list_index_sync_ctx *ctx,
				  struct mailbox_list_sync_dir *sync_dir,
				  uint32_t offset_pos, bool partial)
{
	const struct mailbox_list_dir_record *dir;
	const struct mailbox_list_record *recs;
	const struct mailbox_list_sync_record *sync_recs;
	uint32_t child_offset_pos;
	unsigned int i, j, count;
	int ret;

	if (!ctx->seen_sync_root && ctx->sync_root == sync_dir) {
		i_assert(partial);
		ctx->seen_sync_root = TRUE;
		partial = (ctx->flags & MAILBOX_LIST_SYNC_FLAG_PARTIAL) != 0;
	}

	if (sync_dir->offset != 0) {
		/* point to latest dir entry's next_offset */
		offset_pos = sync_dir->offset +
			offsetof(struct mailbox_list_dir_record, next_offset);
	}

	if (sync_dir->new_records_count > 0) {
		/* need to recreate the dir record */
		if (mailbox_list_index_sync_recreate_dir(ctx, sync_dir,
							 offset_pos,
							 partial) < 0)
			return -1;
		/* NOTE: index may have been remaped here */
	} else if (sync_dir->seen_records_count !=
		   array_count(&sync_dir->records) && !partial) {
		/* just mark the records deleted */
		T_BEGIN {
			ret = mailbox_list_index_sync_update_dir(ctx, sync_dir);
		} T_END;
		if (ret < 0)
			return -1;
	}

	if (!partial && (ctx->flags & MAILBOX_LIST_SYNC_FLAG_RECURSIVE) == 0) {
		/* we're doing a full sync only for the root */
		partial = TRUE;
	}

	/* update child mailboxes */
	sync_recs = array_get(&sync_dir->records, &count);
	if (count == 0)
		return 0;

	i_assert(sync_dir->offset != 0 &&
		 sync_dir->offset < ctx->index->mmap_size);
	for (i = j = 0; i < count; i++) {
		if (sync_recs[i].dir == NULL)
			continue;

		/* these may change after each sync_write_dir() call */
		dir = CONST_PTR_OFFSET(ctx->index->const_mmap_base,
				       sync_dir->offset);
		recs = MAILBOX_LIST_RECORDS(dir);

		/* child_offset_pos needs to point to record's dir_offset */
		for (; j < dir->count; j++) {
			if (recs[j].uid == sync_recs[i].uid)
				break;
		}
		i_assert(j < dir->count);

		child_offset_pos = (const char *)&recs[j].dir_offset -
			(const char *)ctx->index->const_mmap_base;
		if (mailbox_list_index_sync_write_dir(ctx, sync_recs[i].dir,
						      child_offset_pos,
						      partial) < 0)
			return -1;
	}
	return 0;
}

static int
mailbox_list_index_sync_write(struct mailbox_list_index_sync_ctx *ctx)
{
	struct mailbox_list_index_header *hdr;
	bool partial;
	int ret = 0;

	if (ctx->index->mmap_base == NULL) {
		ctx->output = o_stream_create_fd_file(ctx->index->fd, 0, FALSE);
		ctx->output_buf = buffer_create_dynamic(default_pool, 4096);
		o_stream_seek(ctx->output, ctx->hdr.used_space);
	}

	if (ctx->sync_root == ctx->root) {
		ctx->seen_sync_root = TRUE;
		partial = (ctx->flags & MAILBOX_LIST_SYNC_FLAG_PARTIAL) != 0;
	} else {
		/* until we've seen the sync root, we're doing only partial
		   syncing */
		partial = TRUE;
	}

	if (mailbox_list_index_sync_write_dir(ctx, ctx->root, 0, partial) < 0)
		ret = -1;

	if (!ctx->changed) {
		/* nothing written */
	} else if (ctx->index->mmap_base != NULL) {
		/* update header */
		hdr = ctx->index->mmap_base;
		if (ret == 0)
			memcpy(hdr, &ctx->hdr, sizeof(*hdr));

		if (msync(ctx->index->mmap_base,
			  hdr->used_space, MS_SYNC) < 0) {
			mailbox_list_index_set_syscall_error(ctx->index,
							     "msync()");
			ret = -1;
		}
	} else {
		if (ret == 0) {
			o_stream_seek(ctx->output, 0);
			o_stream_send(ctx->output, &ctx->hdr, sizeof(ctx->hdr));
		}

		if (o_stream_flush(ctx->output) < 0) {
			mailbox_list_index_set_syscall_error(ctx->index,
							"o_stream_flush()");
			ret = -1;
		}
		if (ret == 0 &&
		    ctx->index->mail_index->fsync_mode == FSYNC_MODE_ALWAYS &&
		    fdatasync(ctx->index->fd) < 0) {
			mailbox_list_index_set_syscall_error(ctx->index,
							     "fdatasync()");
			ret = -1;
		}
	}
	if (ctx->index->mmap_base == NULL) {
		o_stream_destroy(&ctx->output);
		buffer_free(&ctx->output_buf);
	}
	return ret;
}

int mailbox_list_index_sync_commit(struct mailbox_list_index_sync_ctx **_ctx)
{
	struct mailbox_list_index_sync_ctx *ctx = *_ctx;
	int ret = ctx->failed ? -1 : 0;

	*_ctx = NULL;

	if (!ctx->failed) {
		/* write all the changes to the index */
		ret = mailbox_list_index_sync_write(ctx);
		if (ret == 0 && mailbox_list_index_need_compress(ctx->index))
			ret = mailbox_list_index_compress(ctx);
	}

	if (ctx->mail_sync_ctx != NULL) {
		if (ret < 0 && !ctx->restart)
			mail_index_sync_rollback(&ctx->mail_sync_ctx);
		else {
			if (ctx->restart)
				mail_index_reset(ctx->trans);
			if (mail_index_sync_commit(&ctx->mail_sync_ctx) < 0)
				ret = -1;
		}
	}

	mailbox_list_index_view_deinit(&ctx->view);
	pool_unref(&ctx->pool);
	return ret;
}

void mailbox_list_index_sync_rollback(struct mailbox_list_index_sync_ctx **ctx)
{
	(*ctx)->failed = TRUE;
	(void)mailbox_list_index_sync_commit(ctx);
}

static bool mailbox_list_index_need_compress(struct mailbox_list_index *index)
{
	uoff_t max_del_space;

	max_del_space = index->hdr->used_space / 100 *
		MAILBOX_LIST_COMPRESS_PERCENTAGE;
	if (index->hdr->deleted_space >= max_del_space &&
	    index->hdr->used_space >= MAILBOX_LIST_COMPRESS_MIN_SIZE)
		return TRUE;

	return FALSE;
}

static int mailbox_list_copy_to_mem_all(struct mailbox_list_index_sync_ctx *ctx,
					struct mailbox_list_sync_dir *dir)
{
	struct mailbox_list_sync_record *recs;
	unsigned int i, count;

	/* mark the directories as new */
	dir->offset = 0;
	dir->new_records_count = 1;

	recs = array_get_modifiable(&dir->records, &count);
	for (i = 0; i < count; i++) {
		recs[i].created = TRUE;
		recs[i].seen = TRUE;

		if (recs[i].dir == NULL) {
			if (recs[i].dir_offset == 0)
				continue;

			if (mailbox_list_copy_sync_dir(ctx, recs[i].dir_offset,
						       &recs[i].dir) < 0)
				return -1;
		}
		recs[i].dir_offset = 0;

		if (mailbox_list_copy_to_mem_all(ctx, recs[i].dir) < 0)
			return -1;
	}
	return 0;
}

static int mailbox_list_index_compress(struct mailbox_list_index_sync_ctx *ctx)
{
	/* first read everything to memory */
	if (mailbox_list_copy_to_mem_all(ctx, ctx->root) < 0)
		return -1;

	/* truncate the index file */
	mailbox_list_index_file_close(ctx->index);
	if (mailbox_list_index_file_create(ctx->index,
					   ctx->hdr.uid_validity) < 0)
		return -1;

	/* reset header */
	ctx->hdr.file_seq++;
	ctx->hdr.used_space = sizeof(ctx->hdr);
	ctx->hdr.deleted_space = 0;

	/* and write everything back */
	return mailbox_list_index_sync_write(ctx);
}
