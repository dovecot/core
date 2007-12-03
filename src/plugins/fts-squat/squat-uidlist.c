/* Copyright (c) 2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "file-lock.h"
#include "ostream.h"
#include "write-full.h"
#include "squat-trie-private.h"
#include "squat-uidlist.h"

#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define UIDLIST_LIST_SIZE 31
#define UIDLIST_BLOCK_LIST_COUNT 100
#define UID_LIST_MASK_RANGE 0x80000000

/* set = points to uidlist index number, unset = points to uidlist offset */
#define UID_LIST_POINTER_MASK_LIST_IDX 0x80000000

#define UIDLIST_PACKED_FLAG_BITMASK 1
#define UIDLIST_PACKED_FLAG_BEGINS_WITH_POINTER 2

struct uidlist_list {
	uint32_t uid_count:31;
	uint32_t uid_begins_with_pointer:1;
	uint32_t uid_list[UIDLIST_LIST_SIZE];
};

struct squat_uidlist {
	struct squat_trie *trie;

	char *path;
	struct ostream *output;
	int fd;

	struct file_lock *file_lock;
	uoff_t locked_file_size;

	ARRAY_DEFINE(lists, struct uidlist_list);
	ARRAY_TYPE(uint32_t) block_offsets;
	ARRAY_TYPE(uint32_t) block_end_indexes;
	uint32_t list_start_idx;

	void *mmap_base;
	size_t mmap_size;
	struct squat_uidlist_file_header hdr;
	struct squat_uidlist_file_header build_hdr;

	unsigned int cur_block_count;
	const uint32_t *cur_block_offsets;
	const uint32_t *cur_block_end_indexes;

	size_t max_size;
	unsigned int corrupted:1;
};

struct squat_uidlist_rebuild_context {
	struct squat_uidlist *uidlist;
	int fd;
	struct ostream *output;

	ARRAY_TYPE(uint32_t) new_block_offsets, new_block_end_indexes;
	uoff_t cur_block_start_offset;

	uint32_t list_sizes[UIDLIST_BLOCK_LIST_COUNT];
	unsigned int list_idx;
	unsigned int new_count;
};

void squat_uidlist_delete(struct squat_uidlist *uidlist)
{
	if (unlink(uidlist->path) < 0 && errno != ENOENT)
		i_error("unlink(%s) failed: %m", uidlist->path);
}

static void squat_uidlist_set_corrupted(struct squat_uidlist *uidlist,
					const char *reason)
{
	if (uidlist->corrupted)
		return;
	uidlist->corrupted = TRUE;

	i_error("Corrupted squat uidlist file %s: %s", uidlist->path, reason);
	squat_trie_delete(uidlist->trie);
}

static uint32_t
uidlist_write_array(struct ostream *output, const uint32_t *uid_list,
		    unsigned int uid_count, uint32_t packed_flags,
		    uint32_t offset, bool write_size)
{
	uint8_t *uidbuf, *bufp, sizebuf[SQUAT_PACK_MAX_SIZE], *sizebufp;
	uint8_t listbuf[SQUAT_PACK_MAX_SIZE], *listbufp = listbuf;
	uint32_t uid, uid2, prev, base_uid, size_value;
	unsigned int i, bitmask_len, uid_list_len;
	unsigned int idx, max_idx, mask;
	bool datastack;
	int num;

	if ((packed_flags & UIDLIST_PACKED_FLAG_BEGINS_WITH_POINTER) != 0)
		squat_pack_num(&listbufp, offset);

	/* @UNSAFE */
	t_push();
	base_uid = uid_list[0] & ~UID_LIST_MASK_RANGE;
	datastack = uid_count < 1024*8/SQUAT_PACK_MAX_SIZE;
	if (datastack)
		uidbuf = t_malloc(SQUAT_PACK_MAX_SIZE * uid_count);
	else
		uidbuf = i_malloc(SQUAT_PACK_MAX_SIZE * uid_count);
	bufp = uidbuf;
	squat_pack_num(&bufp, base_uid);

	bitmask_len = (uid_list[uid_count-1] - base_uid + 7) / 8 +
		(bufp - uidbuf);
	if (bitmask_len < uid_count) {
	bitmask_build:
		i_assert(bitmask_len < SQUAT_PACK_MAX_SIZE*uid_count);

		memset(bufp, 0, bitmask_len - (bufp - uidbuf));
		if ((uid_list[0] & UID_LIST_MASK_RANGE) == 0) {
			i = 1;
			uid = i == uid_count ? 0 : uid_list[i];
		} else {
			i = 0;
			uid = uid_list[0] + 1;
		}
		base_uid++;

		for (; i < uid_count; i++) {
			if ((uid & UID_LIST_MASK_RANGE) == 0) {
				uid -= base_uid;
				uid2 = uid;
			} else {
				uid &= ~UID_LIST_MASK_RANGE;
				uid -= base_uid;
				uid2 = uid_list[i+1] - base_uid;
				i++;
			}

			if (uid2 - uid < 3*8) {
				for (; uid <= uid2; uid++)
					bufp[uid / 8] |= 1 << (uid % 8);
			} else {
				/* first byte */
				idx = uid / 8;
				num = uid % 8;
				if (num != 0) {
					uid += 8 - num;
					for (mask = 0; num < 8; num++)
						mask |= 1 << num;
					bufp[idx++] |= mask;
				}

				/* middle bytes */
				num = uid2 % 8;
				max_idx = idx + (uid2 - num - uid)/8;
				for (; idx < max_idx; idx++, uid += 8)
					bufp[idx] = 0xff;

				/* last byte */
				for (mask = 0; num >= 0; num--)
					mask |= 1 << num;
				bufp[idx] |= mask;
			}
			uid = i+1 == uid_count ? 0 : uid_list[i+1];
		}
		uid_list_len = bitmask_len;
		packed_flags |= UIDLIST_PACKED_FLAG_BITMASK;
	} else {
		bufp = uidbuf;
		prev = 0;
		for (i = 0; i < uid_count; i++) {
			uid = uid_list[i];
			i_assert((uid & ~UID_LIST_MASK_RANGE) >= prev);
			if ((uid & UID_LIST_MASK_RANGE) == 0) {
				squat_pack_num(&bufp, (uid - prev) << 1);
				prev = uid + 1;
			} else {
				uid &= ~UID_LIST_MASK_RANGE;
				squat_pack_num(&bufp, 1 | (uid - prev) << 1);
				squat_pack_num(&bufp, uid_list[i+1] - uid - 1);
				prev = uid_list[i+1] + 1;
				i++;
			}
		}
		uid_list_len = bufp - uidbuf;
		if (uid_list_len > bitmask_len) {
			bufp = uidbuf;
			squat_pack_num(&bufp, base_uid);
			goto bitmask_build;
		}
	}

	size_value = ((uid_list_len +
		       (listbufp - listbuf)) << 2) | packed_flags;
	if (write_size) {
		sizebufp = sizebuf;
		squat_pack_num(&sizebufp, size_value);
		o_stream_send(output, sizebuf, sizebufp - sizebuf);
	}
	o_stream_send(output, listbuf, listbufp - listbuf);
	o_stream_send(output, uidbuf, uid_list_len);
	if (!datastack)
		i_free(uidbuf);
	t_pop();

	return size_value;
}

static uint32_t
uidlist_write(struct ostream *output, const struct uidlist_list *list,
	      bool write_size)
{
	const uint32_t *uid_list = list->uid_list;
	uint8_t buf[SQUAT_PACK_MAX_SIZE], *bufp;
	uint32_t uid_count = list->uid_count;
	uint32_t packed_flags = 0;
	uint32_t offset = 0;

	if (list->uid_begins_with_pointer) {
		/* continued UID list */
		packed_flags |= UIDLIST_PACKED_FLAG_BEGINS_WITH_POINTER;
		if ((uid_list[0] & UID_LIST_POINTER_MASK_LIST_IDX) != 0) {
			offset = ((uid_list[0] & ~UID_LIST_POINTER_MASK_LIST_IDX) << 1) | 1;
			if (list->uid_count == 1) {
				bufp = buf;
				squat_pack_num(&bufp, offset);
				o_stream_send(output, buf, bufp - buf);
				return (bufp - buf) << 2 | packed_flags;
			}
		} else {
			i_assert(list->uid_count > 1);
			i_assert(output->offset > uid_list[0]);
			offset = (output->offset - uid_list[0]) << 1;
		}
		uid_list++;
		uid_count--;
	}

	return uidlist_write_array(output, uid_list, uid_count,
				   packed_flags, offset, write_size);
}

static int node_uidlist_map_blocks(struct squat_uidlist *uidlist)
{
	const struct squat_uidlist_file_header *hdr = &uidlist->hdr;
	const void *base;
	uint32_t block_count, block_end_offset, i, verify_count;

	block_end_offset = hdr->block_list_offset + sizeof(block_count);
	if (block_end_offset > uidlist->mmap_size) {
		squat_uidlist_set_corrupted(uidlist, "block list outside file");
		return -1;
	}

	base = CONST_PTR_OFFSET(uidlist->mmap_base, hdr->block_list_offset);
	memcpy(&block_count, base, sizeof(block_count));
	base = CONST_PTR_OFFSET(base, sizeof(block_count));

	block_end_offset += block_count * sizeof(uint32_t)*2;
	if (block_end_offset > uidlist->mmap_size) {
		squat_uidlist_set_corrupted(uidlist, "block list outside file");
		return -1;
	}

	uidlist->cur_block_count = block_count;
	uidlist->cur_block_end_indexes = base;
	uidlist->cur_block_offsets =
		CONST_PTR_OFFSET(base, block_count * sizeof(uint32_t));

	/* verify just a couple of the end indexes to make sure they
	   look correct */
	verify_count = I_MIN(block_count, 8);
	for (i = 1; i < verify_count; i++) {
		if (unlikely(uidlist->cur_block_end_indexes[i-1] >=
			     uidlist->cur_block_end_indexes[i])) {
			squat_uidlist_set_corrupted(uidlist,
				"block list corrupted");
			return -1;
		}
	}
	return 0;
}

static int squat_uidlist_map(struct squat_uidlist *uidlist, uoff_t offset)
{
	struct stat st;

	if (uidlist->mmap_size > offset)
		return 0;

	if (fstat(uidlist->fd, &st) < 0) {
		i_error("fstat(%s) failed: %m", uidlist->path);
		return -1;
	}
	if (st.st_size < (off_t)sizeof(uidlist->hdr)) {
		squat_uidlist_set_corrupted(uidlist, "File too small");
		return -1;
	}
	if (offset >= (uoff_t)st.st_size && offset != (uoff_t)-1) {
		squat_uidlist_set_corrupted(uidlist,
					    "Offset points outside file");
		return -1;
	}

	if (uidlist->mmap_size != 0) {
		if (munmap(uidlist->mmap_base, uidlist->mmap_size) < 0)
			i_error("munmap(%s) failed: %m", uidlist->path);
	}
	uidlist->mmap_size = st.st_size;
	uidlist->mmap_base = mmap(NULL, uidlist->mmap_size,
				  PROT_READ | PROT_WRITE,
				  MAP_SHARED, uidlist->fd, 0);
	if (uidlist->mmap_base == MAP_FAILED) {
		uidlist->mmap_base = NULL;
		uidlist->mmap_size = 0;
		i_error("mmap(%s) failed: %m", uidlist->path);
		return -1;
	}
	memcpy(&uidlist->hdr, uidlist->mmap_base, sizeof(uidlist->hdr));

	if (uidlist->hdr.indexid != uidlist->trie->hdr.indexid) {
		squat_uidlist_set_corrupted(uidlist, "wrong indexid");
		return -1;
	}
	if (uidlist->hdr.used_file_size < sizeof(uidlist->hdr) ||
	    uidlist->hdr.used_file_size > uidlist->mmap_size) {
		squat_uidlist_set_corrupted(uidlist, "broken used_file_size");
		return -1;
	}
	if (node_uidlist_map_blocks(uidlist) < 0)
		return -1;
	return 0;
}

struct squat_uidlist *squat_uidlist_init(struct squat_trie *trie)
{
	struct squat_uidlist *uidlist;

	uidlist = i_new(struct squat_uidlist, 1);
	uidlist->trie = trie;
	uidlist->path = i_strconcat(trie->path, ".uids", NULL);
	uidlist->fd = -1;

	return uidlist;
}

void squat_uidlist_deinit(struct squat_uidlist *uidlist)
{
	squat_uidlist_close(uidlist);

	if (array_is_created(&uidlist->block_offsets))
		array_free(&uidlist->block_offsets);
	if (array_is_created(&uidlist->block_end_indexes))
		array_free(&uidlist->block_end_indexes);
	if (array_is_created(&uidlist->lists))
		array_free(&uidlist->lists);
	i_free(uidlist->path);
	i_free(uidlist);
}

int squat_uidlist_open(struct squat_uidlist *uidlist)
{
	squat_uidlist_close(uidlist);

	uidlist->fd = open(uidlist->path, O_RDWR);
	if (uidlist->fd == -1) {
		if (errno == ENOENT) {
			memset(&uidlist->hdr, 0, sizeof(uidlist->hdr));
			return 0;
		}
		i_error("open(%s) failed: %m", uidlist->path);
		return -1;
	}
	return squat_uidlist_map(uidlist, 0);
}

static int squat_uidlist_is_file_stale(struct squat_uidlist *uidlist)
{
	struct stat st, st2;

	if (stat(uidlist->path, &st) < 0) {
		if (errno == ENOENT)
			return 1;

		i_error("stat(%s) failed: %m", uidlist->path);
		return -1;
	}
	if (fstat(uidlist->fd, &st2) < 0) {
		i_error("fstat(%s) failed: %m", uidlist->path);
		return -1;
	}
	uidlist->locked_file_size = st2.st_size;

	return st.st_ino == st2.st_ino &&
		CMP_DEV_T(st.st_dev, st2.st_dev) ? 0 : 1;
}

static int squat_uidlist_lock(struct squat_uidlist *uidlist)
{
	int ret;

	for (;;) {
		i_assert(uidlist->file_lock == NULL);

		ret = file_wait_lock(uidlist->fd, uidlist->path, F_WRLCK,
				     uidlist->trie->lock_method,
				     SQUAT_TRIE_LOCK_TIMEOUT,
				     &uidlist->file_lock);
		if (ret == 0) {
			i_error("file_wait_lock(%s) failed: %m", uidlist->path);
			return 0;
		}
		if (ret < 0)
			return -1;

		ret = squat_uidlist_is_file_stale(uidlist);
		if (ret == 0)
			break;

		file_unlock(&uidlist->file_lock);
		if (ret < 0)
			return -1;

		squat_uidlist_close(uidlist);
		uidlist->fd = open(uidlist->path, O_RDWR | O_CREAT, 0600);
		if (uidlist->fd == -1) {
			i_error("open(%s) failed: %m", uidlist->path);
			return -1;
		}
	}
	return 1;
}

static int squat_uidlist_open_or_create(struct squat_uidlist *uidlist)
{
	if (uidlist->fd == -1) {
		uidlist->fd = open(uidlist->path, O_RDWR | O_CREAT, 0600);
		if (uidlist->fd == -1) {
			i_error("creat(%s) failed: %m", uidlist->path);
			return -1;
		}
	}
	if (squat_uidlist_lock(uidlist) <= 0)
		return -1;

	if (uidlist->locked_file_size != 0) {
		if (squat_uidlist_map(uidlist, 0) < 0) {
			/* broken file, truncate */
			if (ftruncate(uidlist->fd, 0) < 0) {
				i_error("ftruncate(%s) failed: %m",
					uidlist->path);
				return -1;
			}
			uidlist->locked_file_size = 0;
		}
	}
	if (uidlist->locked_file_size == 0) {
		/* write using 0 until we're finished */
		uidlist->hdr.indexid = 0;
		uidlist->hdr.used_file_size = sizeof(uidlist->hdr);
		if (write_full(uidlist->fd, &uidlist->hdr,
			       sizeof(uidlist->hdr)) < 0) {
			i_error("write(%s) failed: %m", uidlist->path);
			return -1;
		}
	}
	return 0;
}

void squat_uidlist_close(struct squat_uidlist *uidlist)
{
	if (uidlist->file_lock != NULL)
		file_lock_free(&uidlist->file_lock);
	if (uidlist->mmap_size != 0) {
		if (munmap(uidlist->mmap_base, uidlist->mmap_size) < 0)
			i_error("munmap(%s) failed: %m", uidlist->path);
		uidlist->mmap_size = 0;
	}
	if (uidlist->output != NULL)
		o_stream_unref(&uidlist->output);
	if (uidlist->fd != -1) {
		if (close(uidlist->fd) < 0)
			i_error("close(%s) failed: %m", uidlist->path);
		uidlist->fd = -1;
	}
	uidlist->corrupted = FALSE;
}

int squat_uidlist_build_init(struct squat_uidlist *uidlist)
{
	if (squat_uidlist_open_or_create(uidlist) < 0) {
		if (uidlist->file_lock != NULL)
			file_unlock(&uidlist->file_lock);
		return -1;
	}
	if (lseek(uidlist->fd, uidlist->hdr.used_file_size, SEEK_SET) < 0) {
		i_error("lseek(%s) failed: %m", uidlist->path);
		if (uidlist->file_lock != NULL)
			file_unlock(&uidlist->file_lock);
		return -1;
	}

	uidlist->output = o_stream_create_fd(uidlist->fd, 0, FALSE);
	if (uidlist->output->offset == 0) {
		struct squat_uidlist_file_header hdr;

		memset(&hdr, 0, sizeof(hdr));
		o_stream_send(uidlist->output, &hdr, sizeof(hdr));
	}
	o_stream_cork(uidlist->output);
	i_array_init(&uidlist->lists, 10240);
	i_array_init(&uidlist->block_offsets, 128);
	i_array_init(&uidlist->block_end_indexes, 128);
	uidlist->list_start_idx = uidlist->hdr.count;
	uidlist->build_hdr = uidlist->hdr;
	return 0;
}

static int
uidlist_write_block_list_and_header(struct squat_uidlist *uidlist,
				    struct ostream *output,
				    ARRAY_TYPE(uint32_t) *block_offsets,
				    ARRAY_TYPE(uint32_t) *block_end_indexes,
				    bool write_old_blocks)
{
	unsigned int align, old_block_count, new_block_count;
	uint32_t block_offset_count;
	uoff_t block_list_offset;

	align = output->offset % sizeof(uint32_t);
	if (align != 0) {
		static char null[sizeof(uint32_t)-1] = { 0, };

		o_stream_send(output, null, sizeof(uint32_t) - align);
	}
	block_list_offset = output->offset;

	new_block_count = array_count(block_offsets);
	old_block_count = write_old_blocks ? uidlist->cur_block_count : 0;

	block_offset_count = new_block_count + old_block_count;
	o_stream_send(output, &block_offset_count, sizeof(block_offset_count));
	/* write end indexes */
	o_stream_send(output, uidlist->cur_block_end_indexes,
		      old_block_count * sizeof(uint32_t));
	o_stream_send(output, array_idx(block_end_indexes, 0),
		      new_block_count * sizeof(uint32_t));
	/* write offsets */
	o_stream_send(output, uidlist->cur_block_offsets,
		      old_block_count * sizeof(uint32_t));
	o_stream_send(output, array_idx(block_offsets, 0),
		      new_block_count * sizeof(uint32_t));

	/* write header */
	uidlist->build_hdr.indexid = uidlist->trie->hdr.indexid;
	uidlist->build_hdr.block_list_offset = block_list_offset;
	uidlist->build_hdr.used_file_size = output->offset;
	uidlist->hdr = uidlist->build_hdr;

	o_stream_seek(output, 0);
	o_stream_send(output, &uidlist->build_hdr, sizeof(uidlist->build_hdr));
	o_stream_seek(output, uidlist->build_hdr.used_file_size);
	o_stream_flush(output);
	return 0;
}

static int squat_uidlist_build_flush(struct squat_uidlist *uidlist)
{
	struct uidlist_list *lists;
	uint8_t buf[SQUAT_PACK_MAX_SIZE], *bufp;
	unsigned int i, j, count, max;
	uint32_t block_offset, block_end_idx, start_offset;
	uint32_t list_sizes[UIDLIST_BLOCK_LIST_COUNT];
	size_t mem_size;

	if (uidlist->corrupted)
		return -1;

	lists = array_get_modifiable(&uidlist->lists, &count);
	if (count == 0)
		return 0;

	/* write the lists and save the written sizes to uid_list[0] */
	for (i = 0; i < count; i += UIDLIST_BLOCK_LIST_COUNT) {
		start_offset = uidlist->output->offset;
		max = I_MIN(count - i, UIDLIST_BLOCK_LIST_COUNT);
		for (j = 0; j < max; j++) {
			list_sizes[j] = uidlist_write(uidlist->output,
						      &lists[i+j], FALSE);
		}

		block_offset = uidlist->output->offset;
		block_end_idx = uidlist->list_start_idx + i + max;
		array_append(&uidlist->block_offsets, &block_offset, 1);
		array_append(&uidlist->block_end_indexes, &block_end_idx, 1);

		/* write the full size of the uidlists */
		bufp = buf;
		squat_pack_num(&bufp, block_offset - start_offset);
		o_stream_send(uidlist->output, buf, bufp - buf);

		/* write the sizes/flags */
		for (j = 0; j < max; j++) {
			bufp = buf;
			squat_pack_num(&bufp, list_sizes[j]);
			o_stream_send(uidlist->output, buf, bufp - buf);
		}
	}

	mem_size = uidlist->lists.arr.buffer->used +
		uidlist->block_offsets.arr.buffer->used +
		uidlist->block_end_indexes.arr.buffer->used;
	if (uidlist->max_size < mem_size)
		uidlist->max_size = mem_size;

	uidlist->list_start_idx += count;
	array_clear(&uidlist->lists);

	if (uidlist_write_block_list_and_header(uidlist, uidlist->output,
						&uidlist->block_offsets,
						&uidlist->block_end_indexes,
						TRUE) < 0)
		return -1;
	if (uidlist->output->last_failed_errno != 0) {
		errno = uidlist->output->last_failed_errno;
		i_error("write() to %s failed: %m", uidlist->path);
		return -1;
	}

	(void)squat_uidlist_map(uidlist, (uoff_t)-1);

	array_clear(&uidlist->block_offsets);
	array_clear(&uidlist->block_end_indexes);
	return 0;
}

int squat_uidlist_build_deinit(struct squat_uidlist *uidlist)
{
	int ret;

	ret = squat_uidlist_build_flush(uidlist);
	file_unlock(&uidlist->file_lock);
	return ret;
}

int squat_uidlist_rebuild_init(struct squat_uidlist *uidlist, bool finish,
			       struct squat_uidlist_rebuild_context **ctx_r)
{
	struct squat_uidlist_rebuild_context *ctx;
	struct squat_uidlist_file_header hdr;
	const char *temp_path;
	int fd;

	if (uidlist->hdr.link_count == 0)
		return 0;

	if (!finish) {
		if (uidlist->hdr.link_count < uidlist->hdr.count*2/3)
			return 0;
	}

	temp_path = t_strconcat(uidlist->path, ".tmp", NULL);
	fd = open(temp_path, O_RDWR | O_TRUNC | O_CREAT, 0600);
	if (fd < 0) {
		i_error("open(%s) failed: %m", temp_path);
		return -1;
	}

	ctx = i_new(struct squat_uidlist_rebuild_context, 1);
	ctx->uidlist = uidlist;
	ctx->fd = fd;
	ctx->output = o_stream_create_fd(ctx->fd, 0, FALSE);
	o_stream_cork(ctx->output);

	memset(&hdr, 0, sizeof(hdr));
	o_stream_send(ctx->output, &hdr, sizeof(hdr));

	ctx->cur_block_start_offset = ctx->output->offset;
	i_array_init(&ctx->new_block_offsets,
		     uidlist->build_hdr.count / UIDLIST_BLOCK_LIST_COUNT);
	i_array_init(&ctx->new_block_end_indexes,
		     uidlist->build_hdr.count / UIDLIST_BLOCK_LIST_COUNT);
	*ctx_r = ctx;
	return 1;
}

static void
uidlist_rebuild_flush_block(struct squat_uidlist_rebuild_context *ctx)
{
	uint8_t buf[SQUAT_PACK_MAX_SIZE], *bufp;
	uint32_t block_offset, block_end_idx;
	unsigned int i;

	ctx->new_count += ctx->list_idx;

	block_offset = ctx->output->offset;
	block_end_idx = ctx->new_count;
	array_append(&ctx->new_block_offsets, &block_offset, 1);
	array_append(&ctx->new_block_end_indexes, &block_end_idx, 1);

	/* this block's contents started from cur_block_start_offset and
	   ended to current offset. write the size of this area. */
	bufp = buf;
	squat_pack_num(&bufp, block_offset - ctx->cur_block_start_offset);
	o_stream_send(ctx->output, buf, bufp - buf);

	/* write the sizes/flags */
	for (i = 0; i < ctx->list_idx; i++) {
		bufp = buf;
		squat_pack_num(&bufp, ctx->list_sizes[i]);
		o_stream_send(ctx->output, buf, bufp - buf);
	}
	ctx->cur_block_start_offset = ctx->output->offset;
}

void squat_uidlist_rebuild_next(struct squat_uidlist_rebuild_context *ctx,
				const ARRAY_TYPE(uint32_t) *uids)
{
	ctx->list_sizes[ctx->list_idx] =
		uidlist_write_array(ctx->output, array_idx(uids, 0),
				    array_count(uids), 0, 0, FALSE);
	if (++ctx->list_idx == UIDLIST_BLOCK_LIST_COUNT) {
		uidlist_rebuild_flush_block(ctx);
		ctx->list_idx = 0;
	}
}

int squat_uidlist_rebuild_finish(struct squat_uidlist_rebuild_context *ctx,
				 bool cancel)
{
	struct squat_uidlist *uidlist = ctx->uidlist;
	const char *temp_path;
	int ret = 1;

	if (ctx->list_idx != 0)
		uidlist_rebuild_flush_block(ctx);
	if (array_count(&ctx->new_block_end_indexes) == 0 || cancel)
		ret = 0;

	temp_path = t_strconcat(ctx->uidlist->path, ".tmp", NULL);
	squat_uidlist_close(ctx->uidlist);

	if (ret > 0) {
		uidlist->build_hdr.count = ctx->new_count;
		uidlist->build_hdr.link_count = 0;
		uidlist_write_block_list_and_header(uidlist, ctx->output,
						    &ctx->new_block_offsets,
						    &ctx->new_block_end_indexes,
						    FALSE);
		if (ctx->output->last_failed_errno != 0) {
			errno = ctx->output->last_failed_errno;
			i_error("write() to %s failed: %m", temp_path);
			ret = -1;
		} else if (rename(temp_path, uidlist->path) < 0) {
			i_error("rename(%s, %s) failed: %m",
				temp_path, uidlist->path);
			ret = -1;
		}
	}

	if (ret <= 0) {
		o_stream_unref(&ctx->output);
		if (close(ctx->fd) < 0)
			i_error("close(%s) failed: %m", temp_path);
		if (unlink(temp_path) < 0)
			i_error("unlink(%s) failed: %m", temp_path);
	} else {
		array_clear(&uidlist->block_offsets);
		array_clear(&uidlist->block_end_indexes);
		uidlist->fd = ctx->fd;
		uidlist->output = ctx->output;
		uidlist->list_start_idx = ctx->new_count;

		i_assert(array_count(&uidlist->lists) == 0);
		i_assert(uidlist->mmap_size == 0);

		(void)squat_uidlist_map(uidlist, (uoff_t)-1);
	}
	array_free(&ctx->new_block_offsets);
	array_free(&ctx->new_block_end_indexes);
	i_free(ctx);
	return ret < 0 ? -1 : 0;
}

static int uidlist_rebuild(struct squat_uidlist *uidlist)
{
	struct squat_uidlist_rebuild_context *ctx;
	unsigned int i;
	ARRAY_TYPE(uint32_t) uids;
	int ret = 0;

	if (uidlist->hdr.link_count == 0)
		return 0;

	if (squat_uidlist_rebuild_init(uidlist, TRUE, &ctx) < 0)
		return -1;

	i_array_init(&uids, 1024);
	for (i = 0; i < uidlist->hdr.count; i++) {
		array_clear(&uids);
		if (squat_uidlist_get(uidlist, (i + 0x100) << 1, &uids) < 0) {
			ret = -1;
			break;
		}
		squat_uidlist_rebuild_next(ctx, &uids);
	}
	array_free(&uids);

	return squat_uidlist_rebuild_finish(ctx, ret < 0);
}

static void
uidlist_flush(struct squat_uidlist *uidlist, struct uidlist_list *list,
	      uint32_t uid)
{
	uint32_t offset = uidlist->output->offset;

	uidlist->build_hdr.link_count++;
	uidlist_write(uidlist->output, list, TRUE);

	list->uid_count = 2;
	list->uid_begins_with_pointer = TRUE;

	list->uid_list[0] = offset;
	list->uid_list[1] = uid;
}

static struct uidlist_list *
uidlist_add_new(struct squat_uidlist *uidlist, unsigned int count,
		uint32_t *uid_list_idx_r)
{
	struct uidlist_list *list;

	i_assert(array_count(&uidlist->lists) +
		 uidlist->list_start_idx == uidlist->build_hdr.count);
	*uid_list_idx_r = (uidlist->build_hdr.count + 0x100) << 1;
	list = array_append_space(&uidlist->lists);
	uidlist->build_hdr.count++;

	list->uid_count = count;
	return list;
}

uint32_t squat_uidlist_build_add_uid(struct squat_uidlist *uidlist,
				     uint32_t uid_list_idx, uint32_t uid)
{
	struct uidlist_list *list;
	unsigned int idx, mask;
	uint32_t *p;

	if ((uid_list_idx & 1) != 0) {
		/* adding second UID */
		uint32_t prev_uid = uid_list_idx >> 1;

		i_assert(prev_uid != uid);
		list = uidlist_add_new(uidlist, 2, &uid_list_idx);
		list->uid_list[0] = prev_uid;
		if (prev_uid + 1 == uid)
			list->uid_list[0] |= UID_LIST_MASK_RANGE;
		list->uid_list[1] = uid;
		return uid_list_idx;
	} else if (uid_list_idx < (0x100 << 1)) {
		uint32_t old_list_idx;

		if (uid < 8) {
			/* UID lists containing only UIDs 0-7 are saved as
			   uidlist values 2..511. think of it as a bitmask. */
			uid_list_idx |= 1 << (uid + 1);
			i_assert((uid_list_idx & 1) == 0);
			return uid_list_idx;
		}

		if (uid_list_idx == 0) {
			/* first UID */
			return (uid << 1) | 1;
		}

		/* create a new list */
		old_list_idx = uid_list_idx >> 1;
		list = uidlist_add_new(uidlist, 1, &uid_list_idx);
		/* add the first UID ourself */
		idx = 0;
		i_assert((old_list_idx & 0xff) != 0);
		for (mask = 1; mask <= 128; mask <<= 1, idx++) {
			if ((old_list_idx & mask) != 0) {
				list->uid_list[0] = idx;
				idx++; mask <<= 1;
				break;
			}
		}
		for (; mask <= 128; mask <<= 1, idx++) {
			if ((old_list_idx & mask) != 0) {
				squat_uidlist_build_add_uid(uidlist,
							    uid_list_idx, idx);
			}
		}
	}

	/* add to existing list */
	idx = (uid_list_idx >> 1) - 0x100;
	if (idx < uidlist->list_start_idx) {
		list = uidlist_add_new(uidlist, 2, &uid_list_idx);
		list->uid_list[0] = UID_LIST_POINTER_MASK_LIST_IDX | idx;
		list->uid_list[1] = uid;
		list->uid_begins_with_pointer = TRUE;
		uidlist->build_hdr.link_count++;
		return uid_list_idx;
	}

	idx -= uidlist->list_start_idx;
	if (idx >= array_count(&uidlist->lists)) {
		squat_uidlist_set_corrupted(uidlist, "missing/broken uidlist");
		return 0;
	}
	list = array_idx_modifiable(&uidlist->lists, idx);
	i_assert(list->uid_count > 0);

	p = &list->uid_list[list->uid_count-1];
	i_assert(uid != *p || uidlist->corrupted ||
		 (list->uid_count == 1 && list->uid_begins_with_pointer));
	if (uid == *p + 1 &&
	    (list->uid_count > 1 || !list->uid_begins_with_pointer)) {
		/* use a range */
		if (list->uid_count > 1 && (p[-1] & UID_LIST_MASK_RANGE) != 0 &&
		   (list->uid_count > 2 || !list->uid_begins_with_pointer)) {
			/* increase the existing range */
			*p += 1;
			return uid_list_idx;
		}

		if (list->uid_count == UIDLIST_LIST_SIZE) {
			uidlist_flush(uidlist, list, uid);
			return uid_list_idx;
		}
		/* create a new range */
		*p |= UID_LIST_MASK_RANGE;
	}

	if (list->uid_count == UIDLIST_LIST_SIZE) {
		uidlist_flush(uidlist, list, uid);
		return uid_list_idx;
	}

	p++;
	list->uid_count++;

	*p = uid;
	return uid_list_idx;
}

static void uidlist_array_append(ARRAY_TYPE(uint32_t) *uids, uint32_t uid)
{
	uint32_t *uidlist;
	unsigned int count;

	uidlist = array_get_modifiable(uids, &count);
	if (count == 0) {
		array_append(uids, &uid, 1);
		return;
	}
	if (uidlist[count-1] + 1 == uid) {
		if (count > 1 && (uidlist[count-2] &
				  UID_LIST_MASK_RANGE) != 0) {
			uidlist[count-1]++;
			return;
		}
		uidlist[count-1] |= UID_LIST_MASK_RANGE;
	}
	array_append(uids, &uid, 1);
}

static void uidlist_array_append_range(ARRAY_TYPE(uint32_t) *uids,
				       uint32_t uid1, uint32_t uid2)
{
	uint32_t *uidlist;
	unsigned int count;

	i_assert(uid1 < uid2);

	uidlist = array_get_modifiable(uids, &count);
	if (count == 0) {
		uid1 |= UID_LIST_MASK_RANGE;
		array_append(uids, &uid1, 1);
		array_append(uids, &uid2, 1);
		return;
	}
	if (uidlist[count-1] + 1 == uid1) {
		if (count > 1 && (uidlist[count-2] &
				  UID_LIST_MASK_RANGE) != 0) {
			uidlist[count-1] = uid2;
			return;
		}
		uidlist[count-1] |= UID_LIST_MASK_RANGE;
	} else {
		uid1 |= UID_LIST_MASK_RANGE;
		array_append(uids, &uid1, 1);
	}
	array_append(uids, &uid2, 1);
}

static int
node_uidlist_get_at_offset(struct squat_uidlist *uidlist, uoff_t offset,
			   uint32_t num, ARRAY_TYPE(uint32_t) *uids)
{
	const uint8_t *p, *end;
	uint32_t size, base_uid;
	unsigned int i, j, extra = 0;

	if (squat_uidlist_map(uidlist, offset) < 0)
		return -1;
	p = CONST_PTR_OFFSET(uidlist->mmap_base, offset);
	end = CONST_PTR_OFFSET(uidlist->mmap_base, uidlist->mmap_size);

	if (num == 0) {
		/* not given, read it */
		num = squat_unpack_num(&p, end);
	}
	size = num >> 2;
	if (p + size > end) {
		squat_uidlist_set_corrupted(uidlist,
					    "size points outside file");
		return -1;
	}
	end = p + size;

	if ((num & UIDLIST_PACKED_FLAG_BEGINS_WITH_POINTER) != 0) {
		/* link to the file */
		uint32_t prev = squat_unpack_num(&p, end);

		if ((prev & 1) != 0) {
			/* pointer to uidlist */
			prev = ((prev >> 1) + 0x100) << 1;
			if (squat_uidlist_get(uidlist, prev, uids) < 0)
				return -1;
		} else {
			prev = offset - (prev >> 1);
			if (node_uidlist_get_at_offset(uidlist, prev,
						       0, uids) < 0)
				return -1;
		}
	}

	if ((num & UIDLIST_PACKED_FLAG_BITMASK) != 0) {
		/* bitmask */
		base_uid = squat_unpack_num(&p, end);
		size = end - p;

		uidlist_array_append(uids, base_uid++);
		for (i = 0; i < size; i++) {
			for (j = 0; j < 8; j++, base_uid++) {
				if ((p[i] & (1 << j)) != 0)
					uidlist_array_append(uids, base_uid);
			}
		}
	} else {
		/* range */
		base_uid = 0;
		while (p < end) {
			num = squat_unpack_num(&p, end);
			base_uid += (num >> 1) + extra;
			if ((num & 1) == 0) {
				uidlist_array_append(uids, base_uid);
			} else {
				/* range */
				uint32_t seq1 = base_uid;
				base_uid += squat_unpack_num(&p, end) + 1;
				uidlist_array_append_range(uids, seq1,
							   base_uid);
			}
			extra = 1;
		}
	}
	return 0;
}

static int uint32_cmp(const void *key, const void *data)
{
	const uint32_t *i1 = key, *i2 = data;

	return (int)*i1 - (int)*i2;
}

static int
node_uidlist_get_offset(struct squat_uidlist *uidlist, uint32_t uid_list_idx,
			uint32_t *offset_r, uint32_t *num_r)
{
	const uint8_t *p, *end;
	unsigned int idx;
	uint32_t num, skip_bytes, uidlists_offset;

	if (bsearch_insert_pos(&uid_list_idx, uidlist->cur_block_end_indexes,
			       uidlist->cur_block_count,
			       sizeof(uint32_t), uint32_cmp, &idx))
		idx++;
	if (unlikely(idx == uidlist->cur_block_count)) {
		squat_uidlist_set_corrupted(uidlist, "uidlist not found");
		return -1;
	}
	if (unlikely(idx > 0 &&
		     uidlist->cur_block_end_indexes[idx-1] > uid_list_idx)) {
		squat_uidlist_set_corrupted(uidlist, "broken block list");
		return -1;
	}

	/* find the uidlist inside the block */
	p = CONST_PTR_OFFSET(uidlist->mmap_base,
			     uidlist->cur_block_offsets[idx]);
	end = CONST_PTR_OFFSET(uidlist->mmap_base, uidlist->mmap_size);

	uidlists_offset = uidlist->cur_block_offsets[idx] -
		squat_unpack_num(&p, end);
	uid_list_idx -= idx == 0 ? 0 : uidlist->cur_block_end_indexes[idx-1];
	for (skip_bytes = 0; uid_list_idx > 0; uid_list_idx--) {
		num = squat_unpack_num(&p, end);
		skip_bytes += num >> 2;
	}
	*offset_r = uidlists_offset + skip_bytes;
	*num_r = squat_unpack_num(&p, end);

	if (unlikely(*offset_r > uidlist->mmap_size)) {
		squat_uidlist_set_corrupted(uidlist, "broken offset");
		return -1;
	}
	return 0;
}

int squat_uidlist_get(struct squat_uidlist *uidlist, uint32_t uid_list_idx,
		      ARRAY_TYPE(uint32_t) *uids)
{
	unsigned int mask;
	uint32_t uid, offset, num;

	if ((uid_list_idx & 1) != 0) {
		/* single UID */
		uid = uid_list_idx >> 1;
		uidlist_array_append(uids, uid);
		return 0;
	} else if (uid_list_idx < (0x100 << 1)) {
		/* bitmask */
		for (uid = 0, mask = 2; mask <= 256; mask <<= 1, uid++) {
			if ((uid_list_idx & mask) != 0)
				uidlist_array_append(uids, uid);
		}
		return 0;
	}

	uid_list_idx = (uid_list_idx >> 1) - 0x100;
	if (node_uidlist_get_offset(uidlist, uid_list_idx, &offset, &num) < 0)
		return -1;
	return node_uidlist_get_at_offset(uidlist, offset, num, uids);
}

uint32_t squat_uidlist_singleton_last_uid(uint32_t uid_list_idx)
{
	unsigned int idx, mask;

	if ((uid_list_idx & 1) != 0) {
		/* single UID */
		return uid_list_idx >> 1;
	} else if (uid_list_idx < (0x100 << 1)) {
		/* bitmask */
		if (uid_list_idx == 2) {
			/* just a quick optimization */
			return 0;
		}
		for (idx = 7, mask = 256; mask > 2; mask >>= 1, idx--) {
			if ((uid_list_idx & mask) != 0)
				return idx;
		}
	}

	i_unreached();
	return 0;
}

int squat_uidlist_get_seqrange(struct squat_uidlist *uidlist,
			       uint32_t uid_list_idx,
			       ARRAY_TYPE(seq_range) *seq_range_arr)
{
	ARRAY_TYPE(uint32_t) tmp_uid_arr;
	struct seq_range range;
	const uint32_t *tmp_uids;
	unsigned int i, count;

	t_array_init(&tmp_uid_arr, 128);
	if (squat_uidlist_get(uidlist, uid_list_idx, &tmp_uid_arr) < 0) {
		t_pop();
		return -1;
	}

	tmp_uids = array_get(&tmp_uid_arr, &count);
	for (i = 0; i < count; i++) {
		if ((tmp_uids[i] & UID_LIST_MASK_RANGE) == 0)
			range.seq1 = range.seq2 = tmp_uids[i];
		else {
			range.seq1 = tmp_uids[i] & ~UID_LIST_MASK_RANGE;
			range.seq2 = tmp_uids[++i];
		}
		array_append(seq_range_arr, &range, 1);
	}
	return 0;
}

int squat_uidlist_filter(struct squat_uidlist *uidlist, uint32_t uid_list_idx,
			 ARRAY_TYPE(seq_range) *uids)
{
	const struct seq_range *parent_range;
	ARRAY_TYPE(seq_range) dest_uids;
	ARRAY_TYPE(uint32_t) relative_uids;
	const uint32_t *rel_range;
	unsigned int i, rel_count, parent_idx, parent_count, diff, parent_uid;
	uint32_t prev_seq, seq1, seq2;

	parent_range = array_get(uids, &parent_count);
	if (parent_count == 0)
		return 0;

	i_array_init(&relative_uids, 128);
	i_array_init(&dest_uids, 128);
	squat_uidlist_get(uidlist, uid_list_idx, &relative_uids);

	parent_idx = 0;
	rel_range = array_get(&relative_uids, &rel_count);
	prev_seq = 0; parent_uid = parent_range[0].seq1;
	for (i = 0; i < rel_count; i++) {
		if (unlikely(parent_uid == (uint32_t)-1)) {
			i_error("broken UID ranges");
			return -1;
		}
		if ((rel_range[i] & UID_LIST_MASK_RANGE) == 0)
			seq1 = seq2 = rel_range[i];
		else {
			seq1 = (rel_range[i] & ~UID_LIST_MASK_RANGE);
			seq2 = rel_range[++i];
		}
		i_assert(seq1 >= prev_seq);
		diff = seq1 - prev_seq;
		while (diff > 0) {
			if (unlikely(parent_uid == (uint32_t)-1)) {
				i_error("broken UID ranges");
				return -1;
			}

			for (; parent_idx < parent_count; parent_idx++) {
				if (parent_range[parent_idx].seq2 <= parent_uid)
					continue;
				if (parent_uid < parent_range[parent_idx].seq1)
					parent_uid = parent_range[parent_idx].seq1;
				else
					parent_uid++;
				break;
			}
			diff--;
		}
		diff = seq2 - seq1 + 1;
		while (diff > 0) {
			if (unlikely(parent_uid == (uint32_t)-1)) {
				i_error("broken UID ranges");
				return -1;
			}
			seq_range_array_add(&dest_uids, 0, parent_uid);
			for (; parent_idx < parent_count; parent_idx++) {
				if (parent_range[parent_idx].seq2 <= parent_uid)
					continue;
				if (parent_uid < parent_range[parent_idx].seq1)
					parent_uid = parent_range[parent_idx].seq1;
				else
					parent_uid++;
				break;
			}
			diff--;
		}

		prev_seq = seq2 + 1;
	}

	buffer_set_used_size(uids->arr.buffer, 0);
	array_append_array(uids, &dest_uids);

	array_free(&relative_uids);
	array_free(&dest_uids);
	return 0;
}

size_t squat_uidlist_mem_used(struct squat_uidlist *uidlist,
			      unsigned int *count_r)
{
	*count_r = uidlist->hdr.count;
	return uidlist->max_size;
}
