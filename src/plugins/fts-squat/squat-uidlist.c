/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "ostream.h"
#include "mmap-util.h"
#include "write-full.h"
#include "squat-trie.h"
#include "squat-uidlist.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define UIDLIST_COMPRESS_PERCENTAGE 30
#define UIDLIST_UID_COMPRESS_PERCENTAGE 20
#define UIDLIST_COMPRESS_MIN_SIZE (1024*8)

#define UID_NODE_PREV_FLAG_OLD 0x00000001
#define UID_LIST_IDX_FLAG_SINGLE 0x80000000

struct squat_uidlist_header {
	uint32_t uidvalidity; // FIXME
	uint32_t header_size;
	uint32_t used_file_size;
	uint32_t deleted_space;

	uint32_t uid_max;
	uint32_t uid_count;
	uint32_t uids_expunged;
	uint32_t node_count;
};

struct uid_node {
	struct uid_node *prev;
	uint32_t uid;
};

struct squat_uidlist_get_context {
	struct squat_uidlist *uidlist;

	ARRAY_TYPE(seq_range) *result;

	uint32_t filter_pos;
};

struct squat_uidlist {
	struct squat_trie *trie;

	char *filepath;
	int fd;
	struct ostream *output;

	void *mmap_base;
	size_t mmap_size;
	struct squat_uidlist_header hdr;

	ARRAY_DEFINE(lists, struct uid_node);
	uint32_t first_new_list_idx;

	pool_t node_pool;
	buffer_t *tmp_buf, *list_buf;

	unsigned int check_expunges:1;
	unsigned int write_failed:1;
};

struct squat_uidlist_compress_ctx {
	struct squat_uidlist *uidlist;
	const ARRAY_TYPE(seq_range) *existing_uids;

	struct ostream *output;
	char *tmp_path;

	pool_t node_pool;
	struct uid_node *last_node;
	ARRAY_TYPE(seq_range) seen_uids;

	struct squat_uidlist_header hdr;

	unsigned int seen_expunged:1;
	unsigned int failed:1;
};

static void
squat_uidlist_set_syscall_error(struct squat_uidlist *uidlist,
				const char *function)
{
	i_error("%s failed with index search uidlist file %s: %m",
		function, uidlist->filepath);
}

static int squat_uidlist_map(struct squat_uidlist *uidlist)
{
	struct stat st;

	if (fstat(uidlist->fd, &st) < 0) {
		squat_uidlist_set_syscall_error(uidlist, "fstat()");
		return -1;
	}

	if (st.st_size <= sizeof(uidlist->hdr)) {
		memset(&uidlist->hdr, 0, sizeof(uidlist->hdr));
		uidlist->hdr.header_size = sizeof(uidlist->hdr);
		uidlist->hdr.used_file_size = sizeof(uidlist->hdr);
		return 0;
	}

	if (uidlist->mmap_base != NULL) {
		if (munmap(uidlist->mmap_base, uidlist->mmap_size) < 0)
			squat_uidlist_set_syscall_error(uidlist, "munmap()");
	}
	uidlist->mmap_size = st.st_size;

	uidlist->mmap_base =
		mmap(NULL, uidlist->mmap_size, PROT_READ | PROT_WRITE,
		     MAP_SHARED, uidlist->fd, 0);
	if (uidlist->mmap_base == MAP_FAILED) {
		uidlist->mmap_size = 0;
		uidlist->mmap_base = NULL;
		squat_uidlist_set_syscall_error(uidlist, "mmap()");
		return -1;
	}

	memcpy(&uidlist->hdr, uidlist->mmap_base, sizeof(uidlist->hdr));
	// FIXME: verify header

	if (uidlist->hdr.uids_expunged)
		uidlist->check_expunges = TRUE;

	uidlist->first_new_list_idx = uidlist->mmap_size;
	return 1;
}

static int squat_uidlist_open(struct squat_uidlist *uidlist)
{
	i_assert(uidlist->fd == -1);

	uidlist->fd = open(uidlist->filepath, O_RDWR | O_CREAT, 0600);
	if (uidlist->fd == -1) {
		squat_uidlist_set_syscall_error(uidlist, "open()");
		return -1;
	}

	return squat_uidlist_map(uidlist);
}

static void squat_uidlist_close(struct squat_uidlist *uidlist)
{
	if (uidlist->mmap_base != NULL) {
		if (munmap(uidlist->mmap_base, uidlist->mmap_size) < 0)
			squat_uidlist_set_syscall_error(uidlist, "munmap()");
		uidlist->mmap_base = NULL;
	}
	uidlist->mmap_size = 0;

	if (uidlist->fd != -1) {
		if (close(uidlist->fd) < 0)
			squat_uidlist_set_syscall_error(uidlist, "close()");
		uidlist->fd = -1;
	}
}

struct squat_uidlist *
squat_uidlist_init(struct squat_trie *trie, const char *path)
{
	struct squat_uidlist *uidlist;

	uidlist = i_new(struct squat_uidlist, 1);
	uidlist->trie = trie;
	uidlist->filepath = i_strdup(path);
	uidlist->fd = -1;
	uidlist->first_new_list_idx = 1;
	i_array_init(&uidlist->lists, 65536);
	uidlist->node_pool =
		pool_alloconly_create("squat uidlist node pool", 65536);
	uidlist->tmp_buf = buffer_create_dynamic(default_pool, 16);
	uidlist->list_buf = buffer_create_dynamic(default_pool, 256);
	(void)squat_uidlist_open(uidlist);
	return uidlist;
}

void squat_uidlist_deinit(struct squat_uidlist *uidlist)
{
	squat_uidlist_close(uidlist);

	pool_unref(uidlist->node_pool);
	array_free(&uidlist->lists);
	buffer_free(uidlist->tmp_buf);
	buffer_free(uidlist->list_buf);
	i_free(uidlist);
}

int squat_uidlist_add(struct squat_uidlist *uidlist, uint32_t *_uid_list_idx,
		      uint32_t uid)
{
	uint32_t uid_list_idx = *_uid_list_idx;
	struct uid_node *node, *old_node;

	i_assert(uid >= uidlist->hdr.uid_max);

	if (uid_list_idx == 0) {
		*_uid_list_idx = uid | UID_LIST_IDX_FLAG_SINGLE;
		return 0;
	}

	if (uid > uidlist->hdr.uid_max) {
		uidlist->hdr.uid_max = uid;
		uidlist->hdr.uid_count++;
	}

	if (uid_list_idx < uidlist->first_new_list_idx) {
		/* continue an existing list in the uidlist file */
		old_node = POINTER_CAST((uid_list_idx << 1) |
					UID_NODE_PREV_FLAG_OLD);
		uid_list_idx = uidlist->first_new_list_idx +
			array_count(&uidlist->lists);
		node = array_append_space(&uidlist->lists);

		uidlist->hdr.node_count++;
	} else if ((uid_list_idx & UID_LIST_IDX_FLAG_SINGLE) != 0) {
		uint32_t old_uid = uid_list_idx & ~UID_LIST_IDX_FLAG_SINGLE;

		if (uid == old_uid) {
			/* trying to add the same uid again */
			return 0;
		}

		/* convert single UID to a list */
		old_node = p_new(uidlist->node_pool, struct uid_node, 1);
		old_node->uid = old_uid;

		uid_list_idx = uidlist->first_new_list_idx +
			array_count(&uidlist->lists);
		node = array_append_space(&uidlist->lists);

		uidlist->hdr.node_count++;
	} else {
		/* update an in-memory list */
		uint32_t arr_idx = uid_list_idx - uidlist->first_new_list_idx;
		if (arr_idx >= array_count(&uidlist->lists)) {
			/* broken */
			squat_trie_set_corrupted(uidlist->trie,
				"corrupted uidlist index (adding)");
			return -1;
		}

		node = array_idx_modifiable(&uidlist->lists, arr_idx);
		if (node->uid == uid) {
			/* trying to add the same uid again */
			return 0;
		}

		old_node = p_new(uidlist->node_pool, struct uid_node, 1);
		*old_node = *node;
	}

	node->prev = old_node;
	node->uid = uid;
	*_uid_list_idx = uid_list_idx;
	return 0;
}

static int
squat_uidlist_copy_existing(struct squat_uidlist *uidlist,  size_t offset,
			    uint32_t *prev_uid_r, uint32_t *written_uid_r)
{
	const uint8_t *data, *data_start, *end, *p = NULL;
	uint32_t size, num, prev_uid, next_uid;

	if (offset >= uidlist->mmap_size)
		return -1;

	data = CONST_PTR_OFFSET(uidlist->mmap_base, offset);
	end = CONST_PTR_OFFSET(uidlist->mmap_base, uidlist->mmap_size);

	size = _squat_trie_unpack_num(&data, end);
	if (data + size > end)
		return -1;

	data_start = data;
	end = data + size;

	prev_uid = next_uid = _squat_trie_unpack_num(&data, end);
	p = data;
	while (data != end) {
		num = _squat_trie_unpack_num(&data, end);
		next_uid = prev_uid + (num >> 1) + 1;

		if ((num & 1) != 0) {
			/* prev_uid..next_uid */
			if (data == end) {
				/* try to increase this range */
				break;
			}

			/* beginning a new uid/range */
			num = _squat_trie_unpack_num(&data, end);
			next_uid += num + 1;

			prev_uid = next_uid;
			p = data;
		}

		prev_uid = next_uid;
		p = data;
	}

	*written_uid_r = prev_uid;
	*prev_uid_r = next_uid;

	uidlist->hdr.deleted_space +=
		(end - (const uint8_t *)uidlist->mmap_base) - offset;

	buffer_append(uidlist->list_buf, data_start, p - data_start);
	return 0;
}

static int
squat_uidlist_write_range(struct squat_uidlist *uidlist,
			  const struct uid_node *node,
			  uint32_t *prev_uid_r, uint32_t *written_uid_r,
			  int level)
{
	buffer_t *buffer = uidlist->list_buf;
	uint32_t written_uid, prev_uid;
	uint32_t prev_idx = POINTER_CAST_TO(node->prev, uint32_t);

	*prev_uid_r = node->uid;

	if (node->prev == NULL) {
		/* first UID */
		_squat_trie_pack_num(buffer, node->uid);
	} else {
		if ((prev_idx & UID_NODE_PREV_FLAG_OLD) != 0) {
			prev_idx >>= 1;
			if (squat_uidlist_copy_existing(uidlist, prev_idx,
							&prev_uid,
							&written_uid) < 0 ||
			    prev_uid >= node->uid) {
				squat_trie_set_corrupted(uidlist->trie,
					"corrupted continued uidlist index");
				return -1;
			}
		} else {
			if (squat_uidlist_write_range(uidlist, node->prev,
						      &prev_uid, &written_uid,
						      level+1) < 0)
				return -1;
		}

		/* prev_uid contains the previous node's UID.
		   written_uid contains the last written UID. */
		if (prev_uid + 1 == node->uid) {
			if (level != 0) {
				/* this node continue the range */
				*written_uid_r = written_uid;
				return 0;
			} else {
				/* finishing range */
				_squat_trie_pack_num(buffer, 1 |
					((node->uid - written_uid - 1) << 1));
				return 0;
			}
		}
		i_assert(prev_uid < node->uid);
		if (written_uid != prev_uid) {
			i_assert(written_uid < prev_uid);

			/* range ends at prev_uid */
			_squat_trie_pack_num(buffer, 1 |
				((prev_uid - written_uid - 1) << 1));
			/* next uid/range */
			_squat_trie_pack_num(buffer, node->uid - prev_uid - 1);
		} else {
			/* no range */
			_squat_trie_pack_num(buffer,
					     ((node->uid - prev_uid - 1) << 1));
		}
	}

	*written_uid_r = node->uid;
	return 0;
}

static void squat_uidlist_write_init(struct squat_uidlist *uidlist)
{
	i_assert(uidlist->output == NULL);

	uidlist->output = o_stream_create_file(uidlist->fd, default_pool,
					       0, FALSE);
	if (uidlist->hdr.used_file_size < sizeof(uidlist->hdr)) {
		/* creating a new file, write a dummy header */
		o_stream_seek(uidlist->output, 0);
		o_stream_send(uidlist->output, &uidlist->hdr,
			      sizeof(uidlist->hdr));
	} else {
		o_stream_seek(uidlist->output,
			      uidlist->hdr.used_file_size);
	}
}

static int squat_uidlist_write_listbuf(struct squat_uidlist *uidlist,
				       struct ostream *output)
{
	/* write size + buffer */
	buffer_set_used_size(uidlist->tmp_buf, 0);
	_squat_trie_pack_num(uidlist->tmp_buf, uidlist->list_buf->used);

	if (o_stream_send(output, uidlist->tmp_buf->data,
			  uidlist->tmp_buf->used) < 0 ||
	    o_stream_send(output, uidlist->list_buf->data,
			  uidlist->list_buf->used) < 0) {
		return -1;
	}
	return 0;
}

int squat_uidlist_finish_list(struct squat_uidlist *uidlist,
			      uint32_t *_uid_list_idx)
{
	uint32_t uid_list_idx = *_uid_list_idx;
	const struct uid_node *node;
	uint32_t prev_uid, written_uid;

	if ((uid_list_idx & UID_LIST_IDX_FLAG_SINGLE) != 0) {
		/* this is a single UID "list" */
		return 0;
	}
	if (uid_list_idx < uidlist->first_new_list_idx) {
		/* the list hasn't changed */
		return 0;
	}

	uid_list_idx -= uidlist->first_new_list_idx;
	if (uid_list_idx >= array_count(&uidlist->lists)) {
		/* broken */
		squat_trie_set_corrupted(uidlist->trie,
					 "corrupted uidlist index (finishing)");
		return -1;
	}

	/* write the uidlist into a buffer */
	node = array_idx(&uidlist->lists, uid_list_idx);
	buffer_set_used_size(uidlist->list_buf, 0);
	if (squat_uidlist_write_range(uidlist, node,
				      &prev_uid, &written_uid, 0) < 0) {
		uidlist->write_failed = TRUE;
		return -1;
	}

	if (uidlist->output == NULL)
		squat_uidlist_write_init(uidlist);

	/* new uidlist index is the offset in uidlist file */
	*_uid_list_idx = uidlist->output->offset;

	if (squat_uidlist_write_listbuf(uidlist, uidlist->output) < 0)
		uidlist->write_failed = TRUE;
	return 0;
}

static void squat_uidlist_write_header(struct squat_uidlist *uidlist)
{
	uidlist->hdr.used_file_size = uidlist->output->offset;

	o_stream_seek(uidlist->output, 0);
	o_stream_send(uidlist->output, &uidlist->hdr, sizeof(uidlist->hdr));
}

int squat_uidlist_flush(struct squat_uidlist *uidlist, uint32_t uid_validity)
{
	int ret = uidlist->write_failed ? -1 : 0;

	if (uidlist->output != NULL) {
		if (ret == 0) {
			uidlist->hdr.uidvalidity = uid_validity;
			squat_uidlist_write_header(uidlist);
		}
		o_stream_destroy(&uidlist->output);
	}

	array_clear(&uidlist->lists);
	p_clear(uidlist->node_pool);

	uidlist->write_failed = FALSE;

	(void)squat_uidlist_map(uidlist);
	return ret;
}

bool squat_uidlist_need_compress(struct squat_uidlist *uidlist,
				 unsigned int current_message_count)
{
	uint32_t max_del_space, max_uid_del_count;

	if (uidlist->hdr.used_file_size >= UIDLIST_COMPRESS_MIN_SIZE) {
		/* see if we've reached the max. deleted space in file */
		max_del_space = uidlist->hdr.used_file_size / 100 *
			UIDLIST_COMPRESS_PERCENTAGE;
		if (uidlist->hdr.deleted_space > max_del_space)
			return TRUE;
	}
	if (uidlist->hdr.uid_count > current_message_count) {
		if (current_message_count == 0)
			return TRUE;

		max_uid_del_count = uidlist->hdr.uid_count *
			UIDLIST_UID_COMPRESS_PERCENTAGE / 100;
		if ((uidlist->hdr.uid_count - current_message_count) >
		    max_uid_del_count)
			return TRUE;
	}
	return FALSE;
}

int squat_uidlist_mark_having_expunges(struct squat_uidlist *uidlist,
				       bool update_disk)
{
	uidlist->check_expunges = TRUE;

	if (update_disk) {
		uidlist->hdr.uids_expunged = TRUE;

		// FIXME: make sure uidlist.hdr is in updated state
		if (pwrite_full(uidlist->fd, &uidlist->hdr,
				sizeof(uidlist->hdr), 0) < 0) {
			squat_uidlist_set_syscall_error(uidlist,
							"pwrite_full()");
			return -1;
		}
	}
	return 0;
}

struct squat_uidlist_compress_ctx *
squat_uidlist_compress_begin(struct squat_uidlist *uidlist,
			     const ARRAY_TYPE(seq_range) *existing_uids)
{
	struct squat_uidlist_compress_ctx *ctx;
	int fd;

	ctx = i_new(struct squat_uidlist_compress_ctx, 1);
	ctx->uidlist = uidlist;
	ctx->tmp_path = i_strconcat(uidlist->filepath, ".tmp", NULL);

	if (existing_uids != NULL) {
		ctx->node_pool = pool_alloconly_create("compress node pool",
						       1024);
		ctx->existing_uids = existing_uids;
		i_array_init(&ctx->seen_uids,
			     I_MIN(128, array_count(existing_uids)));
	}

	fd = open(ctx->tmp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd == -1) {
		ctx->failed = TRUE;
		i_error("open(%s) failed: %m", ctx->tmp_path);
	} else {
		ctx->output = o_stream_create_file(fd, default_pool, 0, TRUE);
		o_stream_send(ctx->output, &ctx->hdr, sizeof(ctx->hdr));
	}
	return ctx;
}

static bool
squat_uidlist_is_expunged(struct squat_uidlist_compress_ctx *ctx, uint32_t uid)
{
	if (ctx->existing_uids == NULL)
		return FALSE;

	return !seq_range_exists(ctx->existing_uids, uid);
}

static void
squat_uidlist_compress_add_uid(struct squat_uidlist_compress_ctx *ctx,
			       uint32_t uid)
{
	struct uid_node *node;

	if (squat_uidlist_is_expunged(ctx, uid)) {
		ctx->seen_expunged = TRUE;
		return;
	}

	if (!seq_range_exists(&ctx->seen_uids, uid)) {
		if (uid > ctx->hdr.uid_max)
			ctx->hdr.uid_max = uid;
		ctx->hdr.uid_count++;
		seq_range_array_add(&ctx->seen_uids, 0, uid);
	}

	node = p_new(ctx->node_pool, struct uid_node, 1);
	node->prev = ctx->last_node;
	node->uid = uid;

	ctx->last_node = node;
}

static int
squat_uidlist_remove_expunged(struct squat_uidlist_compress_ctx *ctx,
			      const uint8_t *data, size_t size,
			      bool *all_expunged_r)
{
	const uint8_t *end;
	uint32_t num, prev_uid, next_uid, written_uid;

	end = data + size;

	p_clear(ctx->node_pool);
	ctx->seen_expunged = FALSE;
	ctx->last_node = NULL;

	prev_uid = _squat_trie_unpack_num(&data, end);
	squat_uidlist_compress_add_uid(ctx, prev_uid);

	while (data != end) {
		num = _squat_trie_unpack_num(&data, end);
		next_uid = prev_uid + (num >> 1) + 1;
		if ((num & 1) != 0) {
			for (prev_uid++; prev_uid <= next_uid; prev_uid++)
				squat_uidlist_compress_add_uid(ctx, prev_uid);

			if (data == end)
				break;
			num = _squat_trie_unpack_num(&data, end);
			next_uid += num + 1;
		}
		squat_uidlist_compress_add_uid(ctx, next_uid);
		prev_uid = next_uid;
	}

	if (!ctx->seen_expunged) {
		/* no changes */
		return 0;
	}
	if (ctx->last_node == NULL) {
		/* everything expunged */
		*all_expunged_r = TRUE;
		return 1;
	}

	/* recreate the list and write it */
	buffer_set_used_size(ctx->uidlist->list_buf, 0);
	if (squat_uidlist_write_range(ctx->uidlist, ctx->last_node,
				      &prev_uid, &written_uid, 0) < 0)
		return -1;
	if (squat_uidlist_write_listbuf(ctx->uidlist, ctx->output) < 0)
		return -1;
	*all_expunged_r = FALSE;
	return 1;
}

int squat_uidlist_compress_next(struct squat_uidlist_compress_ctx *ctx,
				uint32_t *uid_list_idx)
{
	struct squat_uidlist *uidlist = ctx->uidlist;
	const uint8_t *data, *p, *end;
	uint32_t size;
	int ret;

	if ((*uid_list_idx & UID_LIST_IDX_FLAG_SINGLE) != 0) {
		uint32_t uid = *uid_list_idx & ~UID_LIST_IDX_FLAG_SINGLE;

		if (ctx->uidlist->check_expunges) {
			if (squat_uidlist_is_expunged(ctx, uid))
				return 0;
		}
		return 1;
	}

	if (ctx->output == NULL)
		return -1;

	if (*uid_list_idx >= uidlist->mmap_size) {
		squat_trie_set_corrupted(uidlist->trie,
			"uidlist index points outside file (compressing)");
		return -1;
	}

	data = p = CONST_PTR_OFFSET(uidlist->mmap_base, *uid_list_idx);
	end = CONST_PTR_OFFSET(uidlist->mmap_base, uidlist->mmap_size);

	size = _squat_trie_unpack_num(&p, end);
	if (data + size > end) {
		squat_trie_set_corrupted(uidlist->trie,
			"corrupted uidlist index (compressing)");
		return -1;
	}

	*uid_list_idx = ctx->output->offset;

	if (!ctx->uidlist->check_expunges)
		ret = 0;
	else {
		bool all_expunged;

		ret = squat_uidlist_remove_expunged(ctx, p, size,
						    &all_expunged);
		if (ret < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		if (ret > 0 && all_expunged)
			return 0;
	}

	if (ret == 0) {
		if (o_stream_send(ctx->output, data, p - data + size) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
	}

	ctx->hdr.node_count++;
	return 1;
}

void squat_uidlist_compress_rollback(struct squat_uidlist_compress_ctx **_ctx)
{
	struct squat_uidlist_compress_ctx *ctx = *_ctx;

	*_ctx = NULL;

	if (ctx->node_pool != NULL)
		pool_unref(ctx->node_pool);
	if (array_is_created(&ctx->seen_uids))
		array_free(&ctx->seen_uids);
	if (ctx->output != NULL) {
		if (ctx->failed)
			(void)unlink(ctx->tmp_path);
		o_stream_destroy(&ctx->output);
	}
	i_free(ctx->tmp_path);
	i_free(ctx);
}

int squat_uidlist_compress_commit(struct squat_uidlist_compress_ctx **_ctx)
{
	struct squat_uidlist_compress_ctx *ctx = *_ctx;
	int ret = 0;

	if (ctx->failed) {
		squat_uidlist_compress_rollback(_ctx);
		return -1;
	}

	/* write the header */
	ctx->hdr.uidvalidity = ctx->uidlist->hdr.uidvalidity;
	ctx->hdr.header_size = sizeof(ctx->hdr);
	ctx->hdr.used_file_size = ctx->output->offset;

	if (ctx->existing_uids == NULL) {
		ctx->hdr.uid_max = ctx->uidlist->hdr.uid_max;
		ctx->hdr.uid_count = ctx->uidlist->hdr.uid_count;
	}

	o_stream_seek(ctx->output, 0);
	if (o_stream_send(ctx->output, &ctx->hdr, sizeof(ctx->hdr)) < 0)
		ret = -1;

	if (ret == 0) {
		if (rename(ctx->tmp_path, ctx->uidlist->filepath) < 0) {
			i_error("rename(%s, %s) failed: %m",
				ctx->tmp_path, ctx->uidlist->filepath);
			ret = -1;
		} else {
			/* reopen */
			ctx->uidlist->check_expunges = FALSE;
			squat_uidlist_close(ctx->uidlist);
			(void)squat_uidlist_open(ctx->uidlist);
		}
	}

	if (ret < 0)
		ctx->failed = TRUE;

	squat_uidlist_compress_rollback(_ctx);
	return ret;
}

static void
squat_uidlist_get_add_uid(struct squat_uidlist_get_context *ctx, uint32_t uid)
{
	if (ctx->filter_pos == 0) {
		seq_range_array_add(ctx->result, 0, uid);
		return;
	}

	for (; ctx->filter_pos < uid; ctx->filter_pos++)
		seq_range_array_remove(ctx->result, ctx->filter_pos);
	ctx->filter_pos++;
}

static int
squat_uidlist_get_range_list(struct squat_uidlist_get_context *ctx,
			     size_t offset)
{
	const uint8_t *data, *end;
	uint32_t size, num, prev_uid, next_uid;

	if (offset >= ctx->uidlist->mmap_size)
		return -1;

	data = CONST_PTR_OFFSET(ctx->uidlist->mmap_base, offset);
	end = CONST_PTR_OFFSET(ctx->uidlist->mmap_base,
			       ctx->uidlist->mmap_size);

	size = _squat_trie_unpack_num(&data, end);
	if (data + size > end)
		return -1;

	end = data + size;

	prev_uid = _squat_trie_unpack_num(&data, end);
	squat_uidlist_get_add_uid(ctx, prev_uid);

	while (data != end) {
		num = _squat_trie_unpack_num(&data, end);
		next_uid = prev_uid + (num >> 1) + 1;
		if ((num & 1) != 0) {
			for (prev_uid++; prev_uid <= next_uid; prev_uid++)
				squat_uidlist_get_add_uid(ctx, prev_uid);

			if (data == end)
				break;
			num = _squat_trie_unpack_num(&data, end);
			next_uid += num + 1;
		}
		squat_uidlist_get_add_uid(ctx, next_uid);
		prev_uid = next_uid;
	}
	return 0;
}

static int
squat_uidlist_get_ctx(struct squat_uidlist_get_context *ctx,
		      uint32_t uid_list_idx)
{
	if ((uid_list_idx & UID_LIST_IDX_FLAG_SINGLE) != 0) {
		uint32_t uid = uid_list_idx & ~UID_LIST_IDX_FLAG_SINGLE;
		squat_uidlist_get_add_uid(ctx, uid);
		return 0;
	}

	return squat_uidlist_get_range_list(ctx, uid_list_idx);
}

int squat_uidlist_get(struct squat_uidlist *uidlist, uint32_t uid_list_idx,
		      ARRAY_TYPE(seq_range) *result)
{
	struct squat_uidlist_get_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.uidlist = uidlist;
	ctx.result = result;

	return squat_uidlist_get_ctx(&ctx, uid_list_idx);
}

int squat_uidlist_filter(struct squat_uidlist *uidlist, uint32_t uid_list_idx,
			 ARRAY_TYPE(seq_range) *result)
{
	struct squat_uidlist_get_context ctx;
	const struct seq_range *range;
	unsigned int count;

	memset(&ctx, 0, sizeof(ctx));
	ctx.uidlist = uidlist;
	ctx.result = result;
	ctx.filter_pos = 1;

	return squat_uidlist_get_ctx(&ctx, uid_list_idx);

	range = array_get(ctx.result, &count);
	if (count > 0) {
		for (; ctx.filter_pos <= range[count-1].seq2; ctx.filter_pos++)
			seq_range_array_remove(result, ctx.filter_pos);
	}
}

size_t squat_uidlist_mem_used(struct squat_uidlist *uidlist,
			      unsigned int *count_r)
{
	*count_r = uidlist->hdr.node_count;

	return uidlist->hdr.used_file_size;
}
