/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "sort.h"
#include "bsearch-insert-pos.h"
#include "file-cache.h"
#include "file-lock.h"
#include "read-full.h"
#include "write-full.h"
#include "ostream.h"
#include "mmap-util.h"
#include "squat-trie-private.h"
#include "squat-uidlist.h"

#include <stdio.h>
#include <sys/stat.h>

#define UIDLIST_LIST_SIZE 31
#define UIDLIST_BLOCK_LIST_COUNT 100
#define UID_LIST_MASK_RANGE 0x80000000

/* set = points to uidlist index number, unset = points to uidlist offset */
#define UID_LIST_POINTER_MASK_LIST_IDX 0x80000000

#define UIDLIST_PACKED_FLAG_BITMASK 1
#define UIDLIST_PACKED_FLAG_BEGINS_WITH_POINTER 2

struct uidlist_list {
	unsigned int uid_count:31;
	bool uid_begins_with_pointer:1;
	uint32_t uid_list[UIDLIST_LIST_SIZE];
};

struct squat_uidlist {
	struct squat_trie *trie;

	char *path;
	int fd;
	struct file_cache *file_cache;

	struct file_lock *file_lock;
	struct dotlock *dotlock;
	uoff_t locked_file_size;

	void *mmap_base;
	size_t mmap_size;
	struct squat_uidlist_file_header hdr;

	const void *data;
	size_t data_size;

	unsigned int cur_block_count;
	const uint32_t *cur_block_offsets;
	const uint32_t *cur_block_end_indexes;

	size_t max_size;
	bool corrupted:1;
	bool building:1;
};

struct squat_uidlist_build_context {
	struct squat_uidlist *uidlist;
	struct ostream *output;

	ARRAY_TYPE(uint32_t) block_offsets;
	ARRAY_TYPE(uint32_t) block_end_indexes;

	ARRAY(struct uidlist_list) lists;
	uint32_t list_start_idx;

	struct squat_uidlist_file_header build_hdr;
	bool need_reopen:1;
};

struct squat_uidlist_rebuild_context {
	struct squat_uidlist *uidlist;
	struct squat_uidlist_build_context *build_ctx;

	int fd;
	struct ostream *output;

	ARRAY_TYPE(uint32_t) new_block_offsets, new_block_end_indexes;
	uoff_t cur_block_start_offset;

	uint32_t list_sizes[UIDLIST_BLOCK_LIST_COUNT];
	uint32_t next_uid_list_idx;
	unsigned int list_idx;
	unsigned int new_count;
};

static void squat_uidlist_close(struct squat_uidlist *uidlist);

void squat_uidlist_delete(struct squat_uidlist *uidlist)
{
	i_unlink_if_exists(uidlist->path);
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

static int
uidlist_write_array(struct ostream *output, const uint32_t *uid_list,
		    unsigned int uid_count, uint32_t packed_flags,
		    uint32_t offset, bool write_size, uint32_t *size_r)
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
	base_uid = uid_list[0] & ~UID_LIST_MASK_RANGE;
	datastack = uid_count < 1024*8/SQUAT_PACK_MAX_SIZE;
	if (datastack)
		uidbuf = t_malloc_no0(SQUAT_PACK_MAX_SIZE * uid_count);
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
			i_assert((uid & ~UID_LIST_MASK_RANGE) >= base_uid);
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
			if (unlikely((uid & ~UID_LIST_MASK_RANGE) < prev)) {
				if (!datastack)
					i_free(uidbuf);
				return -1;
			}
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
		o_stream_nsend(output, sizebuf, sizebufp - sizebuf);
	}
	o_stream_nsend(output, listbuf, listbufp - listbuf);
	o_stream_nsend(output, uidbuf, uid_list_len);
	if (!datastack)
		i_free(uidbuf);

	*size_r = size_value;
	return 0;
}

static int
uidlist_write(struct ostream *output, const struct uidlist_list *list,
	      bool write_size, uint32_t *size_r)
{
	const uint32_t *uid_list = list->uid_list;
	uint8_t buf[SQUAT_PACK_MAX_SIZE], *bufp;
	uint32_t uid_count = list->uid_count;
	uint32_t packed_flags = 0;
	uint32_t offset = 0;
	int ret;

	if (list->uid_begins_with_pointer) {
		/* continued UID list */
		packed_flags |= UIDLIST_PACKED_FLAG_BEGINS_WITH_POINTER;
		if ((uid_list[0] & UID_LIST_POINTER_MASK_LIST_IDX) != 0) {
			offset = ((uid_list[0] & ~UID_LIST_POINTER_MASK_LIST_IDX) << 1) | 1;
			if (list->uid_count == 1) {
				bufp = buf;
				squat_pack_num(&bufp, offset);
				o_stream_nsend(output, buf, bufp - buf);
				*size_r = (bufp - buf) << 2 | packed_flags;
				return 0;
			}
		} else if (unlikely(output->offset <= uid_list[0])) {
			i_assert(output->closed);
			return -1;
		} else {
			i_assert(list->uid_count > 1);
			offset = (output->offset - uid_list[0]) << 1;
		}
		uid_list++;
		uid_count--;
	}

	T_BEGIN {
		ret = uidlist_write_array(output, uid_list, uid_count,
					  packed_flags, offset,
					  write_size, size_r);
	} T_END;
	return ret;
}

static void squat_uidlist_map_blocks_set_pointers(struct squat_uidlist *uidlist)
{
	const void *base;
	size_t end_index_size, end_size;

	base = CONST_PTR_OFFSET(uidlist->data, uidlist->hdr.block_list_offset +
				sizeof(uint32_t));

	end_index_size = uidlist->cur_block_count * sizeof(uint32_t);
	end_size = end_index_size + uidlist->cur_block_count * sizeof(uint32_t);
	if (end_size <= uidlist->data_size) {
		uidlist->cur_block_end_indexes = base;
		uidlist->cur_block_offsets =
			CONST_PTR_OFFSET(base, end_index_size);
	} else {
		uidlist->cur_block_end_indexes = NULL;
		uidlist->cur_block_offsets = NULL;
	}
}

static int uidlist_file_cache_read(struct squat_uidlist *uidlist,
				   size_t offset, size_t size)
{
	if (uidlist->file_cache == NULL)
		return 0;

	if (file_cache_read(uidlist->file_cache, offset, size) < 0) {
		i_error("read(%s) failed: %m", uidlist->path);
		return -1;
	}
	uidlist->data = file_cache_get_map(uidlist->file_cache,
					   &uidlist->data_size);
	squat_uidlist_map_blocks_set_pointers(uidlist);
	return 0;
}

static int squat_uidlist_map_blocks(struct squat_uidlist *uidlist)
{
	const struct squat_uidlist_file_header *hdr = &uidlist->hdr;
	const void *base;
	uint32_t block_count, blocks_offset, blocks_size, i, verify_count;

	if (hdr->block_list_offset == 0) {
		/* empty file */
		uidlist->cur_block_count = 0;
		return 1;
	}

	/* get number of blocks */
	if (uidlist_file_cache_read(uidlist, hdr->block_list_offset,
				    sizeof(block_count)) < 0)
		return -1;
	blocks_offset = hdr->block_list_offset + sizeof(block_count);
	if (blocks_offset > uidlist->data_size) {
		squat_uidlist_set_corrupted(uidlist, "block list outside file");
		return 0;
	}

	i_assert(uidlist->data != NULL);
	base = CONST_PTR_OFFSET(uidlist->data, hdr->block_list_offset);
	memcpy(&block_count, base, sizeof(block_count));

	/* map the blocks */
	blocks_size = block_count * sizeof(uint32_t)*2;
	if (uidlist_file_cache_read(uidlist, blocks_offset, blocks_size) < 0)
		return -1;
	if (blocks_offset + blocks_size > uidlist->data_size) {
		squat_uidlist_set_corrupted(uidlist, "block list outside file");
		return 0;
	}

	uidlist->cur_block_count = block_count;
	squat_uidlist_map_blocks_set_pointers(uidlist);

	i_assert(uidlist->cur_block_end_indexes != NULL);

	/* verify just a couple of the end indexes to make sure they
	   look correct */
	verify_count = I_MIN(block_count, 8);
	for (i = 1; i < verify_count; i++) {
		if (unlikely(uidlist->cur_block_end_indexes[i-1] >=
			     uidlist->cur_block_end_indexes[i])) {
			squat_uidlist_set_corrupted(uidlist,
				"block list corrupted");
			return 0;
		}
	}
	return 1;
}

static int squat_uidlist_map_header(struct squat_uidlist *uidlist)
{
	if (uidlist->hdr.indexid == 0) {
		/* still being built */
		return 1;
	}
	if (uidlist->hdr.indexid != uidlist->trie->hdr.indexid) {
		/* see if trie was recreated */
		(void)squat_trie_open(uidlist->trie);
	}
	if (uidlist->hdr.indexid != uidlist->trie->hdr.indexid) {
		squat_uidlist_set_corrupted(uidlist, "wrong indexid");
		return 0;
	}
	if (uidlist->hdr.used_file_size < sizeof(uidlist->hdr) ||
	    (uidlist->hdr.used_file_size > uidlist->mmap_size &&
	     uidlist->mmap_base != NULL)) {
		squat_uidlist_set_corrupted(uidlist, "broken used_file_size");
		return 0;
	}
	return squat_uidlist_map_blocks(uidlist);
}

static void squat_uidlist_unmap(struct squat_uidlist *uidlist)
{
	if (uidlist->mmap_size != 0) {
		if (munmap(uidlist->mmap_base, uidlist->mmap_size) < 0)
			i_error("munmap(%s) failed: %m", uidlist->path);
		uidlist->mmap_base = NULL;
		uidlist->mmap_size = 0;
	}
	uidlist->cur_block_count = 0;
	uidlist->cur_block_end_indexes = NULL;
	uidlist->cur_block_offsets = NULL;
}

static int squat_uidlist_mmap(struct squat_uidlist *uidlist)
{
	struct stat st;

	if (fstat(uidlist->fd, &st) < 0) {
		i_error("fstat(%s) failed: %m", uidlist->path);
		return -1;
	}
	if (st.st_size < (off_t)sizeof(uidlist->hdr)) {
		squat_uidlist_set_corrupted(uidlist, "File too small");
		return -1;
	}

	squat_uidlist_unmap(uidlist);
	uidlist->mmap_size = st.st_size;
	uidlist->mmap_base = mmap(NULL, uidlist->mmap_size,
				  PROT_READ | PROT_WRITE,
				  MAP_SHARED, uidlist->fd, 0);
	if (uidlist->mmap_base == MAP_FAILED) {
		uidlist->data = uidlist->mmap_base = NULL;
		uidlist->data_size = uidlist->mmap_size = 0;
		i_error("mmap(%s) failed: %m", uidlist->path);
		return -1;
	}
	uidlist->data = uidlist->mmap_base;
	uidlist->data_size = uidlist->mmap_size;
	return 0;
}

static int squat_uidlist_map(struct squat_uidlist *uidlist)
{
	const struct squat_uidlist_file_header *mmap_hdr = uidlist->mmap_base;
	int ret;

	if (mmap_hdr != NULL && !uidlist->building &&
	    uidlist->hdr.block_list_offset == mmap_hdr->block_list_offset) {
		/* file hasn't changed */
		return 1;
	}

	if ((uidlist->trie->flags & SQUAT_INDEX_FLAG_MMAP_DISABLE) == 0) {
		if (mmap_hdr == NULL || uidlist->building ||
		    uidlist->mmap_size < mmap_hdr->used_file_size) {
			if (squat_uidlist_mmap(uidlist) < 0)
				return -1;
		}

		if (!uidlist->building) {
			memcpy(&uidlist->hdr, uidlist->mmap_base,
			       sizeof(uidlist->hdr));
		}
	} else if (uidlist->building) {
		/* we want to update blocks mapping, but using the header
		   in memory */
	} else {
		ret = pread_full(uidlist->fd, &uidlist->hdr,
				 sizeof(uidlist->hdr), 0);
		if (ret <= 0) {
			if (ret < 0) {
				i_error("pread(%s) failed: %m", uidlist->path);
				return -1;
			}
			i_error("Corrupted %s: File too small", uidlist->path);
			return 0;
		}
		uidlist->data = NULL;
		uidlist->data_size = 0;
	}
	if (uidlist->file_cache == NULL &&
	    (uidlist->trie->flags & SQUAT_INDEX_FLAG_MMAP_DISABLE) != 0)
		uidlist->file_cache = file_cache_new_path(uidlist->fd, uidlist->path);
	return squat_uidlist_map_header(uidlist);
}

static int squat_uidlist_read_to_memory(struct squat_uidlist *uidlist)
{
	size_t i, page_size = mmap_get_page_size();

	if (uidlist->file_cache != NULL) {
		return uidlist_file_cache_read(uidlist, 0,
					       uidlist->hdr.used_file_size);
	}
	/* Tell the kernel we're going to use the uidlist data, so it loads
	   it into memory and keeps it there. */
	(void)madvise(uidlist->mmap_base, uidlist->mmap_size, MADV_WILLNEED);
	/* It also speeds up a bit for us to sequentially load everything
	   into memory, although at least Linux catches up quite fast even
	   without this code. Compiler can quite easily optimize away this
	   entire for loop, but volatile seems to help with gcc 4.2. */
	for (i = 0; i < uidlist->mmap_size; i += page_size)
		((const volatile char *)uidlist->data)[i];
	return 0;
}

static void squat_uidlist_free_from_memory(struct squat_uidlist *uidlist)
{
	size_t page_size = mmap_get_page_size();

	if (uidlist->file_cache != NULL) {
		file_cache_invalidate(uidlist->file_cache,
				      page_size, (uoff_t)-1);
	} else {
		(void)madvise(uidlist->mmap_base, uidlist->mmap_size,
			      MADV_DONTNEED);
	}
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

	i_free(uidlist->path);
	i_free(uidlist);
}

static int squat_uidlist_open(struct squat_uidlist *uidlist)
{
	squat_uidlist_close(uidlist);

	uidlist->fd = open(uidlist->path, O_RDWR);
	if (uidlist->fd == -1) {
		if (errno == ENOENT) {
			i_zero(&uidlist->hdr);
			return 0;
		}
		i_error("open(%s) failed: %m", uidlist->path);
		return -1;
	}
	return squat_uidlist_map(uidlist) <= 0 ? -1 : 0;
}

static void squat_uidlist_close(struct squat_uidlist *uidlist)
{
	i_assert(!uidlist->building);

	squat_uidlist_unmap(uidlist);
	if (uidlist->file_cache != NULL)
		file_cache_free(&uidlist->file_cache);
	file_lock_free(&uidlist->file_lock);
	if (uidlist->dotlock != NULL)
		file_dotlock_delete(&uidlist->dotlock);
	i_close_fd_path(&uidlist->fd, uidlist->path);
	uidlist->corrupted = FALSE;
}

int squat_uidlist_refresh(struct squat_uidlist *uidlist)
{
	/* we assume here that trie is locked, so that we don't need to worry
	   about it when reading the header */
	if (uidlist->fd == -1 ||
	    uidlist->hdr.indexid != uidlist->trie->hdr.indexid) {
		if (squat_uidlist_open(uidlist) < 0)
			return -1;
	} else {
		if (squat_uidlist_map(uidlist) <= 0)
			return -1;
	}
	return 0;
}

static int squat_uidlist_is_file_stale(struct squat_uidlist *uidlist)
{
	struct stat st, st2;

	i_assert(uidlist->fd != -1);

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
		i_assert(uidlist->fd != -1);
		i_assert(uidlist->file_lock == NULL);
		i_assert(uidlist->dotlock == NULL);

		if (uidlist->trie->lock_method != FILE_LOCK_METHOD_DOTLOCK) {
			ret = file_wait_lock(uidlist->fd, uidlist->path,
					     F_WRLCK,
					     uidlist->trie->lock_method,
					     SQUAT_TRIE_LOCK_TIMEOUT,
					     &uidlist->file_lock);
		} else {
			ret = file_dotlock_create(&uidlist->trie->dotlock_set,
						  uidlist->path, 0,
						  &uidlist->dotlock);
		}
		if (ret == 0) {
			i_error("squat uidlist %s: Locking timed out",
				uidlist->path);
			return 0;
		}
		if (ret < 0)
			return -1;

		ret = squat_uidlist_is_file_stale(uidlist);
		if (ret == 0)
			break;

		if (uidlist->file_lock != NULL)
			file_unlock(&uidlist->file_lock);
		else
			file_dotlock_delete(&uidlist->dotlock);
		if (ret < 0)
			return -1;

		squat_uidlist_close(uidlist);
		uidlist->fd = squat_trie_create_fd(uidlist->trie,
						   uidlist->path, 0);
		if (uidlist->fd == -1)
			return -1;
	}
	return 1;
}

static int squat_uidlist_open_or_create(struct squat_uidlist *uidlist)
{
	int ret;

	if (uidlist->fd == -1) {
		uidlist->fd = squat_trie_create_fd(uidlist->trie,
						   uidlist->path, 0);
		if (uidlist->fd == -1)
			return -1;
	}
	if (squat_uidlist_lock(uidlist) <= 0)
		return -1;

	if (uidlist->locked_file_size != 0) {
		if ((ret = squat_uidlist_map(uidlist)) < 0)
			return -1;
		if (ret == 0) {
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
		i_zero(&uidlist->hdr);
		if (write_full(uidlist->fd, &uidlist->hdr,
			       sizeof(uidlist->hdr)) < 0) {
			i_error("write(%s) failed: %m", uidlist->path);
			return -1;
		}
	}
	return 0;
}

int squat_uidlist_build_init(struct squat_uidlist *uidlist,
			     struct squat_uidlist_build_context **ctx_r)
{
	struct squat_uidlist_build_context *ctx;
	int ret;

	i_assert(!uidlist->building);

	ret = squat_uidlist_open_or_create(uidlist);
	if (ret == 0 &&
	    lseek(uidlist->fd, uidlist->hdr.used_file_size, SEEK_SET) < 0) {
		i_error("lseek(%s) failed: %m", uidlist->path);
		ret = -1;
	}

	if (ret < 0) {
		if (uidlist->file_lock != NULL)
			file_unlock(&uidlist->file_lock);
		if (uidlist->dotlock != NULL)
			file_dotlock_delete(&uidlist->dotlock);
		return -1;
	}

	ctx = i_new(struct squat_uidlist_build_context, 1);
	ctx->uidlist = uidlist;
	ctx->output = o_stream_create_fd(uidlist->fd, 0);
	if (ctx->output->offset == 0) {
		struct squat_uidlist_file_header hdr;

		i_zero(&hdr);
		o_stream_nsend(ctx->output, &hdr, sizeof(hdr));
	}
	o_stream_cork(ctx->output);
	i_array_init(&ctx->lists, 10240);
	i_array_init(&ctx->block_offsets, 128);
	i_array_init(&ctx->block_end_indexes, 128);
	ctx->list_start_idx = uidlist->hdr.count;
	ctx->build_hdr = uidlist->hdr;

	uidlist->building = TRUE;
	*ctx_r = ctx;
	return 0;
}

static void
uidlist_write_block_list_and_header(struct squat_uidlist_build_context *ctx,
				    struct ostream *output,
				    ARRAY_TYPE(uint32_t) *block_offsets,
				    ARRAY_TYPE(uint32_t) *block_end_indexes,
				    bool write_old_blocks)
{
	struct squat_uidlist *uidlist = ctx->uidlist;
	unsigned int align, old_block_count, new_block_count;
	uint32_t block_offset_count;
	uoff_t block_list_offset;

	i_assert(uidlist->trie->hdr.indexid != 0);
	ctx->build_hdr.indexid = uidlist->trie->hdr.indexid;

	if (array_count(block_end_indexes) == 0) {
		ctx->build_hdr.used_file_size = output->offset;
		ctx->build_hdr.block_list_offset = 0;
		uidlist->hdr = ctx->build_hdr;
		return;
	}

	align = output->offset % sizeof(uint32_t);
	if (align != 0) {
		static char null[sizeof(uint32_t)-1] = { 0, };

		o_stream_nsend(output, null, sizeof(uint32_t) - align);
	}
	block_list_offset = output->offset;

	new_block_count = array_count(block_offsets);
	old_block_count = write_old_blocks ? uidlist->cur_block_count : 0;

	block_offset_count = new_block_count + old_block_count;
	o_stream_nsend(output, &block_offset_count, sizeof(block_offset_count));
	/* write end indexes */
	o_stream_nsend(output, uidlist->cur_block_end_indexes,
		       old_block_count * sizeof(uint32_t));
	o_stream_nsend(output, array_front(block_end_indexes),
		       new_block_count * sizeof(uint32_t));
	/* write offsets */
	o_stream_nsend(output, uidlist->cur_block_offsets,
		       old_block_count * sizeof(uint32_t));
	o_stream_nsend(output, array_front(block_offsets),
		       new_block_count * sizeof(uint32_t));
	(void)o_stream_flush(output);

	/* update header - it's written later when trie is locked */
	ctx->build_hdr.block_list_offset = block_list_offset;
	ctx->build_hdr.used_file_size = output->offset;
	uidlist->hdr = ctx->build_hdr;
}

void squat_uidlist_build_flush(struct squat_uidlist_build_context *ctx)
{
	struct uidlist_list *lists;
	uint8_t buf[SQUAT_PACK_MAX_SIZE], *bufp;
	unsigned int i, j, count, max;
	uint32_t block_offset, block_end_idx, start_offset;
	uint32_t list_sizes[UIDLIST_BLOCK_LIST_COUNT];
	size_t mem_size;

	if (ctx->uidlist->corrupted)
		return;

	lists = array_get_modifiable(&ctx->lists, &count);
	if (count == 0)
		return;

	/* write the lists and save the written sizes to uid_list[0] */
	for (i = 0; i < count; i += UIDLIST_BLOCK_LIST_COUNT) {
		start_offset = ctx->output->offset;
		max = I_MIN(count - i, UIDLIST_BLOCK_LIST_COUNT);
		for (j = 0; j < max; j++) {
			if (uidlist_write(ctx->output, &lists[i+j],
					  FALSE, &list_sizes[j]) < 0) {
				squat_uidlist_set_corrupted(ctx->uidlist,
							    "Broken uidlists");
				return;
			}
		}

		block_offset = ctx->output->offset;
		block_end_idx = ctx->list_start_idx + i + max;
		array_push_back(&ctx->block_offsets, &block_offset);
		array_push_back(&ctx->block_end_indexes, &block_end_idx);

		/* write the full size of the uidlists */
		bufp = buf;
		squat_pack_num(&bufp, block_offset - start_offset);
		o_stream_nsend(ctx->output, buf, bufp - buf);

		/* write the sizes/flags */
		for (j = 0; j < max; j++) {
			bufp = buf;
			squat_pack_num(&bufp, list_sizes[j]);
			o_stream_nsend(ctx->output, buf, bufp - buf);
		}
	}

	mem_size = ctx->lists.arr.buffer->used +
		ctx->block_offsets.arr.buffer->used +
		ctx->block_end_indexes.arr.buffer->used;
	if (ctx->uidlist->max_size < mem_size)
		ctx->uidlist->max_size = mem_size;

	ctx->list_start_idx += count;
	array_clear(&ctx->lists);

	uidlist_write_block_list_and_header(ctx, ctx->output,
					    &ctx->block_offsets,
					    &ctx->block_end_indexes, TRUE);

	(void)squat_uidlist_map(ctx->uidlist);

	array_clear(&ctx->block_offsets);
	array_clear(&ctx->block_end_indexes);
}

int squat_uidlist_build_finish(struct squat_uidlist_build_context *ctx)
{
	if (ctx->uidlist->corrupted)
		return -1;

	if (!ctx->output->closed) {
		(void)o_stream_seek(ctx->output, 0);
		o_stream_nsend(ctx->output,
			       &ctx->build_hdr, sizeof(ctx->build_hdr));
		(void)o_stream_seek(ctx->output, ctx->build_hdr.used_file_size);
	}

	if (o_stream_finish(ctx->output) < 0) {
		i_error("write() to %s failed: %s", ctx->uidlist->path,
			o_stream_get_error(ctx->output));
		return -1;
	}
	return 0;
}

void squat_uidlist_build_deinit(struct squat_uidlist_build_context **_ctx)
{
	struct squat_uidlist_build_context *ctx = *_ctx;

	*_ctx = NULL;

	i_assert(array_count(&ctx->lists) == 0 || ctx->uidlist->corrupted);
	i_assert(ctx->uidlist->building);
	ctx->uidlist->building = FALSE;

	if (ctx->uidlist->file_lock != NULL)
		file_unlock(&ctx->uidlist->file_lock);
	else
		file_dotlock_delete(&ctx->uidlist->dotlock);

	if (ctx->need_reopen)
		(void)squat_uidlist_open(ctx->uidlist);

	array_free(&ctx->block_offsets);
	array_free(&ctx->block_end_indexes);
	array_free(&ctx->lists);
	o_stream_ignore_last_errors(ctx->output);
	o_stream_unref(&ctx->output);
	i_free(ctx);
}

int squat_uidlist_rebuild_init(struct squat_uidlist_build_context *build_ctx,
			       bool compress,
			       struct squat_uidlist_rebuild_context **ctx_r)
{
	struct squat_uidlist_rebuild_context *ctx;
	struct squat_uidlist_file_header hdr;
	const char *temp_path;
	int fd;

	if (build_ctx->build_hdr.link_count == 0)
		return 0;

	if (!compress) {
		if (build_ctx->build_hdr.link_count <
		    build_ctx->build_hdr.count*2/3)
			return 0;
	}

	/* make sure the entire uidlist is in memory before beginning,
	   otherwise the pages are faulted to memory in random order which
	   takes forever. */
	if (squat_uidlist_read_to_memory(build_ctx->uidlist) < 0)
		return -1;

	temp_path = t_strconcat(build_ctx->uidlist->path, ".tmp", NULL);
	fd = squat_trie_create_fd(build_ctx->uidlist->trie, temp_path, O_TRUNC);
	if (fd == -1)
		return -1;

	ctx = i_new(struct squat_uidlist_rebuild_context, 1);
	ctx->uidlist = build_ctx->uidlist;
	ctx->build_ctx = build_ctx;
	ctx->fd = fd;
	ctx->output = o_stream_create_fd(ctx->fd, 0);
	ctx->next_uid_list_idx = 0x100;
	o_stream_cork(ctx->output);

	i_zero(&hdr);
	o_stream_nsend(ctx->output, &hdr, sizeof(hdr));

	ctx->cur_block_start_offset = ctx->output->offset;
	i_array_init(&ctx->new_block_offsets,
		     build_ctx->build_hdr.count / UIDLIST_BLOCK_LIST_COUNT);
	i_array_init(&ctx->new_block_end_indexes,
		     build_ctx->build_hdr.count / UIDLIST_BLOCK_LIST_COUNT);
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
	array_push_back(&ctx->new_block_offsets, &block_offset);
	array_push_back(&ctx->new_block_end_indexes, &block_end_idx);

	/* this block's contents started from cur_block_start_offset and
	   ended to current offset. write the size of this area. */
	bufp = buf;
	squat_pack_num(&bufp, block_offset - ctx->cur_block_start_offset);
	o_stream_nsend(ctx->output, buf, bufp - buf);

	/* write the sizes/flags */
	for (i = 0; i < ctx->list_idx; i++) {
		bufp = buf;
		squat_pack_num(&bufp, ctx->list_sizes[i]);
		o_stream_nsend(ctx->output, buf, bufp - buf);
	}
	ctx->cur_block_start_offset = ctx->output->offset;
}

uint32_t squat_uidlist_rebuild_next(struct squat_uidlist_rebuild_context *ctx,
				    const ARRAY_TYPE(uint32_t) *uids)
{
	int ret;

	T_BEGIN {
		ret = uidlist_write_array(ctx->output, array_front(uids),
					  array_count(uids), 0, 0, FALSE,
					  &ctx->list_sizes[ctx->list_idx]);
	} T_END;
	if (ret < 0)
		squat_uidlist_set_corrupted(ctx->uidlist, "Broken uidlists");

	if (++ctx->list_idx == UIDLIST_BLOCK_LIST_COUNT) {
		uidlist_rebuild_flush_block(ctx);
		ctx->list_idx = 0;
	}
	return ctx->next_uid_list_idx++ << 1;
}

uint32_t squat_uidlist_rebuild_nextu(struct squat_uidlist_rebuild_context *ctx,
				     const ARRAY_TYPE(seq_range) *uids)
{
	const struct seq_range *range;
	ARRAY_TYPE(uint32_t) tmp_uids;
	uint32_t seq, uid1, ret;
	unsigned int i, count;

	range = array_get(uids, &count);
	if (count == 0)
		return 0;

	if (range[count-1].seq2 < 8) {
		/* we can use a singleton bitmask */
		ret = 0;
		for (i = 0; i < count; i++) {
			for (seq = range[i].seq1; seq <= range[i].seq2; seq++)
				ret |= 1 << (seq+1);
		}
		return ret;
	}
	if (count == 1 && range[0].seq1 == range[0].seq2) {
		/* single UID */
		return (range[0].seq1 << 1) | 1;
	}

	/* convert seq range to our internal representation and use the
	   normal _rebuild_next() to write it */
	i_array_init(&tmp_uids, 128);
	for (i = 0; i < count; i++) {
		if (range[i].seq1 == range[i].seq2)
			array_push_back(&tmp_uids, &range[i].seq1);
		else {
			uid1 = range[i].seq1 | UID_LIST_MASK_RANGE;
			array_push_back(&tmp_uids, &uid1);
			array_push_back(&tmp_uids, &range[i].seq2);
		}
	}
	ret = squat_uidlist_rebuild_next(ctx, &tmp_uids);
	array_free(&tmp_uids);
	return ret;
}

int squat_uidlist_rebuild_finish(struct squat_uidlist_rebuild_context *ctx,
				 bool cancel)
{
	const char *temp_path;
	int ret = 1;

	if (ctx->list_idx != 0)
		uidlist_rebuild_flush_block(ctx);
	if (cancel || ctx->uidlist->corrupted)
		ret = 0;

	temp_path = t_strconcat(ctx->uidlist->path, ".tmp", NULL);
	if (ret > 0) {
		ctx->build_ctx->build_hdr.indexid =
			ctx->uidlist->trie->hdr.indexid;
		ctx->build_ctx->build_hdr.count = ctx->new_count;
		ctx->build_ctx->build_hdr.link_count = 0;
		uidlist_write_block_list_and_header(ctx->build_ctx, ctx->output,
						    &ctx->new_block_offsets,
						    &ctx->new_block_end_indexes,
						    FALSE);
		(void)o_stream_seek(ctx->output, 0);
		o_stream_nsend(ctx->output, &ctx->build_ctx->build_hdr,
			       sizeof(ctx->build_ctx->build_hdr));
		(void)o_stream_seek(ctx->output,
				    ctx->build_ctx->build_hdr.used_file_size);

		if (ctx->uidlist->corrupted)
			ret = -1;
		else if (o_stream_finish(ctx->output) < 0) {
			i_error("write(%s) failed: %s", temp_path,
				o_stream_get_error(ctx->output));
			ret = -1;
		} else if (rename(temp_path, ctx->uidlist->path) < 0) {
			i_error("rename(%s, %s) failed: %m",
				temp_path, ctx->uidlist->path);
			ret = -1;
		}
		ctx->build_ctx->need_reopen = TRUE;
	} else {
		o_stream_abort(ctx->output);
	}

	/* we no longer require the entire uidlist to be in memory,
	   let it be used for something more useful. */
	squat_uidlist_free_from_memory(ctx->uidlist);

	o_stream_unref(&ctx->output);
	if (close(ctx->fd) < 0)
		i_error("close(%s) failed: %m", temp_path);

	if (ret <= 0)
		i_unlink(temp_path);
	array_free(&ctx->new_block_offsets);
	array_free(&ctx->new_block_end_indexes);
	i_free(ctx);
	return ret < 0 ? -1 : 0;
}

static void
uidlist_flush(struct squat_uidlist_build_context *ctx,
	      struct uidlist_list *list, uint32_t uid)
{
	uint32_t size, offset = ctx->output->offset;

	ctx->build_hdr.link_count++;
	if (uidlist_write(ctx->output, list, TRUE, &size) < 0)
		squat_uidlist_set_corrupted(ctx->uidlist, "Broken uidlists");

	list->uid_count = 2;
	list->uid_begins_with_pointer = TRUE;

	list->uid_list[0] = offset;
	list->uid_list[1] = uid;
}

static struct uidlist_list *
uidlist_add_new(struct squat_uidlist_build_context *ctx, unsigned int count,
		uint32_t *uid_list_idx_r)
{
	struct uidlist_list *list;

	i_assert(array_count(&ctx->lists) +
		 ctx->list_start_idx == ctx->build_hdr.count);
	*uid_list_idx_r = (ctx->build_hdr.count + 0x100) << 1;
	list = array_append_space(&ctx->lists);
	ctx->build_hdr.count++;

	list->uid_count = count;
	return list;
}

uint32_t squat_uidlist_build_add_uid(struct squat_uidlist_build_context *ctx,
				     uint32_t uid_list_idx, uint32_t uid)
{
	struct uidlist_list *list;
	unsigned int idx, mask;
	uint32_t *p;

	if ((uid_list_idx & 1) != 0) {
		/* adding second UID */
		uint32_t prev_uid = uid_list_idx >> 1;

		i_assert(prev_uid != uid);
		list = uidlist_add_new(ctx, 2, &uid_list_idx);
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
		list = uidlist_add_new(ctx, 1, &uid_list_idx);
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
				(void)squat_uidlist_build_add_uid(ctx,
							uid_list_idx, idx);
			}
		}
	}

	/* add to existing list */
	idx = (uid_list_idx >> 1) - 0x100;
	if (idx < ctx->list_start_idx) {
		list = uidlist_add_new(ctx, 2, &uid_list_idx);
		list->uid_list[0] = UID_LIST_POINTER_MASK_LIST_IDX | idx;
		list->uid_list[1] = uid;
		list->uid_begins_with_pointer = TRUE;
		ctx->build_hdr.link_count++;
		return uid_list_idx;
	}

	idx -= ctx->list_start_idx;
	if (idx >= array_count(&ctx->lists)) {
		squat_uidlist_set_corrupted(ctx->uidlist,
					    "missing/broken uidlist");
		return 0;
	}
	list = array_idx_modifiable(&ctx->lists, idx);
	i_assert(list->uid_count > 0);

	p = &list->uid_list[list->uid_count-1];
	i_assert(uid != *p || ctx->uidlist->corrupted ||
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
			uidlist_flush(ctx, list, uid);
			return uid_list_idx;
		}
		/* create a new range */
		*p |= UID_LIST_MASK_RANGE;
	} else {
		if (list->uid_count == UIDLIST_LIST_SIZE) {
			uidlist_flush(ctx, list, uid);
			return uid_list_idx;
		}
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
		array_push_back(uids, &uid);
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
	array_push_back(uids, &uid);
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
		array_push_back(uids, &uid1);
		array_push_back(uids, &uid2);
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
		array_push_back(uids, &uid1);
	}
	array_push_back(uids, &uid2);
}

static int
squat_uidlist_get_at_offset(struct squat_uidlist *uidlist, uoff_t offset,
			    uint32_t num, ARRAY_TYPE(uint32_t) *uids)
{
	const uint32_t *uid_list;
	const uint8_t *p, *end;
	uint32_t size, base_uid, next_uid, flags, prev;
	uoff_t uidlist_data_offset;
	unsigned int i, j, count;

	if (num != 0)
		uidlist_data_offset = offset;
	else {
		/* not given, read it */
		if (uidlist_file_cache_read(uidlist, offset,
					    SQUAT_PACK_MAX_SIZE) < 0)
			return -1;

		p = CONST_PTR_OFFSET(uidlist->data, offset);
		end = CONST_PTR_OFFSET(uidlist->data, uidlist->data_size);
		num = squat_unpack_num(&p, end);
		uidlist_data_offset = p - (const uint8_t *)uidlist->data;
	}
	size = num >> 2;

	if (uidlist_file_cache_read(uidlist, uidlist_data_offset, size) < 0)
		return -1;
	if (uidlist_data_offset + size > uidlist->data_size) {
		squat_uidlist_set_corrupted(uidlist,
					    "size points outside file");
		return -1;
	}

	p = CONST_PTR_OFFSET(uidlist->data, uidlist_data_offset);
	end = p + size;

	flags = num;
	if ((flags & UIDLIST_PACKED_FLAG_BEGINS_WITH_POINTER) != 0) {
		/* link to the file */
		prev = squat_unpack_num(&p, end);

		if ((prev & 1) != 0) {
			/* pointer to uidlist */
			prev = ((prev >> 1) + 0x100) << 1;
			if (squat_uidlist_get(uidlist, prev, uids) < 0)
				return -1;
		} else {
			prev = offset - (prev >> 1);
			if (squat_uidlist_get_at_offset(uidlist, prev,
							0, uids) < 0)
				return -1;
		}
		uid_list = array_get(uids, &count);
		next_uid = count == 0 ? 0 : uid_list[count-1] + 1;
	} else {
		next_uid = 0;
	}

	num = base_uid = squat_unpack_num(&p, end);
	if ((flags & UIDLIST_PACKED_FLAG_BITMASK) == 0)
		base_uid >>= 1;
	if (base_uid < next_uid) {
		squat_uidlist_set_corrupted(uidlist,
					    "broken continued uidlist");
		return -1;
	}

	if ((flags & UIDLIST_PACKED_FLAG_BITMASK) != 0) {
		/* bitmask */
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
		for (;;) {
			if ((num & 1) == 0) {
				uidlist_array_append(uids, base_uid);
			} else {
				/* range */
				uint32_t seq1 = base_uid;
				base_uid += squat_unpack_num(&p, end) + 1;
				uidlist_array_append_range(uids, seq1,
							   base_uid);
			}
			if (p == end)
				break;

			num = squat_unpack_num(&p, end);
			base_uid += (num >> 1) + 1;
		}
	}
	return 0;
}

static int
squat_uidlist_get_offset(struct squat_uidlist *uidlist, uint32_t uid_list_idx,
			 uint32_t *offset_r, uint32_t *num_r)
{
	const uint8_t *p, *end;
	unsigned int idx;
	uint32_t num, skip_bytes, uidlists_offset;
	size_t max_map_size;

	if (uidlist->fd == -1) {
		squat_uidlist_set_corrupted(uidlist, "no uidlists");
		return -1;
	}

	if (bsearch_insert_pos(&uid_list_idx, uidlist->cur_block_end_indexes,
			       uidlist->cur_block_count,
			       sizeof(uint32_t), uint32_cmp, &idx))
		idx++;
	if (unlikely(idx == uidlist->cur_block_count)) {
		squat_uidlist_set_corrupted(uidlist, "uidlist not found");
		return -1;
	}
	i_assert(uidlist->cur_block_end_indexes != NULL);
	if (unlikely(idx > 0 &&
		     uidlist->cur_block_end_indexes[idx-1] > uid_list_idx)) {
		squat_uidlist_set_corrupted(uidlist, "broken block list");
		return -1;
	}

	/* make sure everything is mapped */
	uid_list_idx -= idx == 0 ? 0 : uidlist->cur_block_end_indexes[idx-1];
	max_map_size = SQUAT_PACK_MAX_SIZE * (1+uid_list_idx);
	if (uidlist_file_cache_read(uidlist, uidlist->cur_block_offsets[idx],
				    max_map_size) < 0)
		return -1;

	/* find the uidlist inside the block */
	i_assert(uidlist->cur_block_offsets != NULL);
	p = CONST_PTR_OFFSET(uidlist->data, uidlist->cur_block_offsets[idx]);
	end = CONST_PTR_OFFSET(uidlist->data, uidlist->data_size);

	uidlists_offset = uidlist->cur_block_offsets[idx] -
		squat_unpack_num(&p, end);
	for (skip_bytes = 0; uid_list_idx > 0; uid_list_idx--) {
		num = squat_unpack_num(&p, end);
		skip_bytes += num >> 2;
	}
	*offset_r = uidlists_offset + skip_bytes;
	*num_r = squat_unpack_num(&p, end);

	if (unlikely(p == end)) {
		squat_uidlist_set_corrupted(uidlist, "broken file");
		return -1;
	}
	if (unlikely(*offset_r > uidlist->mmap_size &&
		     uidlist->mmap_base != NULL)) {
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
	if (squat_uidlist_get_offset(uidlist, uid_list_idx, &offset, &num) < 0)
		return -1;
	return squat_uidlist_get_at_offset(uidlist, offset, num, uids);
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
	int ret;

	i_array_init(&tmp_uid_arr, 128);
	ret = squat_uidlist_get(uidlist, uid_list_idx, &tmp_uid_arr);
	if (ret == 0) {
		tmp_uids = array_get(&tmp_uid_arr, &count);
		for (i = 0; i < count; i++) {
			if ((tmp_uids[i] & UID_LIST_MASK_RANGE) == 0)
				range.seq1 = range.seq2 = tmp_uids[i];
			else {
				range.seq1 = tmp_uids[i] & ~UID_LIST_MASK_RANGE;
				range.seq2 = tmp_uids[++i];
			}
			array_push_back(seq_range_arr, &range);
		}
	}
	array_free(&tmp_uid_arr);
	return ret;
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
	int ret = 0;

	parent_range = array_get(uids, &parent_count);
	if (parent_count == 0)
		return 0;

	i_array_init(&relative_uids, 128);
	i_array_init(&dest_uids, 128);
	if (squat_uidlist_get(uidlist, uid_list_idx, &relative_uids) < 0)
		ret = -1;

	parent_idx = 0;
	rel_range = array_get(&relative_uids, &rel_count);
	prev_seq = 0; parent_uid = parent_range[0].seq1;
	for (i = 0; i < rel_count; i++) {
		if (unlikely(parent_uid == (uint32_t)-1)) {
			i_error("broken UID ranges");
			ret = -1;
			break;
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
				ret = -1;
				break;
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
				ret = -1;
				break;
			}
			seq_range_array_add(&dest_uids, parent_uid);
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
	return ret;
}

size_t squat_uidlist_mem_used(struct squat_uidlist *uidlist,
			      unsigned int *count_r)
{
	*count_r = uidlist->hdr.count;
	return uidlist->max_size;
}
