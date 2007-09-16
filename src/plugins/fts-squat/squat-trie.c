/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "file-cache.h"
#include "file-lock.h"
#include "istream.h"
#include "ostream.h"
#include "read-full.h"
#include "write-full.h"
#include "mmap-util.h"
#include "unichar.h"
#include "squat-uidlist.h"
#include "squat-trie.h"
#include "squat-trie-private.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>

/* 8bit character counter holds only 255, so we can't use 256. */
#define MAX_8BIT_CHAR_COUNT 255

#define FAST_8BIT_LEVEL 2

#define TRIE_COMPRESS_PERCENTAGE 30
#define TRIE_COMPRESS_MIN_SIZE (1024*50)

#define SQUAT_TRIE_VERSION 1
#define SQUAT_TRIE_LOCK_TIMEOUT 60

/* for non-x86 use memcpy() when accessing unaligned int* addresses */
#if defined(__i386__) || defined(__x86_64__)
#  define ALLOW_UNALIGNED_ACCESS
#endif

#define BLOCK_SIZE 4

#define ALIGN(size) \
	(((size) + sizeof(void *)-1) & ~((unsigned int) sizeof(void *)-1))

struct squat_trie {
	char *filepath;
	int fd;
	dev_t dev;
	ino_t ino;

	enum file_lock_method lock_method;
	struct file_lock *file_lock;
	int lock_count;
	int lock_type; /* F_RDLCK / F_WRLCK */

	struct file_cache *file_cache;
	uint32_t file_cache_modify_counter;

	void *mmap_base; /* NULL with mmap_disable=yes */
	const uint8_t *const_mmap_base;
	size_t mmap_size;

	const struct squat_trie_header *hdr;
	uint32_t uidvalidity;

	char *uidlist_filepath;
	struct squat_uidlist *uidlist;
	struct trie_node *root;
	buffer_t *buf;

	unsigned int corrupted:1;
	unsigned int mmap_disable:1;
};

struct squat_trie_build_context {
	struct squat_trie *trie;

	struct ostream *output;

	uint32_t prev_uid;
	unsigned int prev_added_size;
	uint16_t prev_added[BLOCK_SIZE-1];

	unsigned int node_count;
	unsigned int deleted_space;

	unsigned int modified:1;
	unsigned int failed:1;
	unsigned int locked:1;
};

struct squat_trie_compress_context {
	struct squat_trie *trie;

	const char *tmp_path;
	struct ostream *output;
	int fd;

	struct squat_uidlist_compress_ctx *uidlist_ctx;

	unsigned int node_count;
};

struct trie_node {
	/* new characters have been added to this node */
	uint8_t resized:1;
	/* idx pointers have been updated */
	uint8_t modified:1;
	uint8_t chars_8bit_count;
	uint16_t chars_16bit_count;

	uint32_t file_offset;
	uint32_t orig_size;

	/* the node pointers are valid as long as their lowest bit is 0,
	   otherwise they're offsets to the trie file (>> 1).

	   in leaf nodes the children pointers are uint32_t uid_list_idx[]; */
	/* uint8_t 8bit_chars[chars_8bit_count]; */
	/* struct trie_node *children[chars_8bit_count]; */
	/* uint16_t 16bit_chars[chars_16bit_count]; */
	/* struct trie_node *children[chars_16bit_count]; */
};
#define NODE_CHARS8(node) \
	(uint8_t *)(node + 1)
#define NODE_CHILDREN8(node) \
	(struct trie_node **) \
		((char *)((node) + 1) + \
		 ALIGN(sizeof(uint8_t) * ((node)->chars_8bit_count)))
#define NODE_CHARS16(node, level) \
	(uint16_t *)((char *)NODE_CHILDREN8(node) + \
		((node)->chars_8bit_count) * \
		((level) == BLOCK_SIZE ? \
		 sizeof(uint32_t) : sizeof(struct trie_node *)))
#define NODE_CHILDREN16(node, level) \
	(struct trie_node **) \
		((char *)NODE_CHARS16(node, level) + \
		 ALIGN(sizeof(uint16_t) * ((node)->chars_16bit_count)))

static void free_node(struct trie_node *node, unsigned int level);
static void squat_trie_compress_chars8(struct trie_node *node);
static int
squat_trie_compress_node(struct squat_trie_compress_context *ctx,
			 struct trie_node *node, unsigned int level);
static int trie_write_node(struct squat_trie_build_context *ctx,
			   unsigned int level, struct trie_node *node);
static int
squat_trie_build_flush(struct squat_trie_build_context *ctx, bool finish);

static int chr_8bit_cmp(const void *_key, const void *_chr)
{
	const uint16_t *key = _key;
	const uint8_t *chr = _chr;

	return *key - *chr;
}

static int chr_16bit_cmp(const void *_key, const void *_chr)
{
	const uint16_t *key = _key, *chr = _chr;

	return *key - *chr;
}

void squat_trie_pack_num(buffer_t *buffer, uint32_t num)
{
	uint8_t c;

	/* number continues as long as the highest bit is set */
	while (num >= 0x80) {
		c = (num & 0x7f) | 0x80;
		num >>= 7;

		buffer_append(buffer, &c, 1);
	}

	c = num;
	buffer_append(buffer, &c, 1);
}

uint32_t squat_trie_unpack_num(const uint8_t **p, const uint8_t *end)
{
	const uint8_t *c = *p;
	uint32_t value = 0;
	unsigned int bits = 0;

	while (c != end && *c >= 0x80) {
		value |= (*c & 0x7f) << bits;
		bits += 7;
		c++;
	}

	if (c == end) {
		/* last number shouldn't end with high bit */
		return 0;
	}
	if (bits > 32-7) {
		/* we have only 32bit numbers */
		return 0;
	}

	value |= (*c & 0x7f) << bits;
	*p = c + 1;
	return value;
}

static const uint16_t *
data_normalize(const void *data, size_t size, buffer_t *dest)
{
	const unsigned char *src = data;
	size_t i;

	buffer_set_used_size(dest, 0);
	for (i = 0; i < size; i++) {
		uint16_t chr;

		if (src[i] <= 32)
			chr = 0;
		else if (src[i] <= 'z')
			chr = i_toupper(src[i]) - 32;
		else if (src[i] < 128)
			chr = src[i] - 32 - 26;
		else {
			/* UTF-8 input */
			unichar_t uchr;

			/* FIXME: can we do anything better than just
			   truncate with >16bit values? */
			if (uni_utf8_get_char_n(src+i, size-i, &uchr) <= 0)
				chr = 0;
			else {
				uchr -= 32 - 26;
				chr = uchr < (uint16_t)-1 ? uchr : 0;
			}
			i += uni_utf8_char_bytes(src[i]) - 1;
		}
		buffer_append(dest, &chr, sizeof(chr));
	}

	return dest->data;
}

static void
squat_trie_set_syscall_error(struct squat_trie *trie, const char *function)
{
	i_error("%s failed with index search file %s: %m",
		function, trie->filepath);
}

void squat_trie_set_corrupted(struct squat_trie *trie, const char *reason)
{
	i_error("Corrupted index search file %s: %s", trie->filepath, reason);

	(void)unlink(trie->filepath);
	(void)unlink(trie->uidlist_filepath);
	trie->corrupted = TRUE;
}

static void
trie_map_node_save_leaf(const uint32_t *src_idx, unsigned int count,
			uint32_t *children)
{
	unsigned int i;

#ifndef ALLOW_UNALIGNED_ACCESS
	if ((POINTER_CAST_TO(src_idx, size_t) & (sizeof(uint32_t)-1)) == 0) {
#endif
		for (i = 0; i < count; i++)
			children[i] = src_idx[i];
#ifndef ALLOW_UNALIGNED_ACCESS
	} else {
		/* unaligned access */
		const uint8_t *src_idx8 = (const uint8_t *)src_idx;

		for (i = 0; i < count; i++) {
			memcpy(&children[i], src_idx8 + i * sizeof(uint32_t),
			       sizeof(children[i]));
		}
	}
#endif
}

static void
trie_map_node_save_children(unsigned int level, const uint32_t *src_idx,
			    unsigned int count, struct trie_node **children)
{
	unsigned int i;

	if (level == BLOCK_SIZE) {
		trie_map_node_save_leaf(src_idx, count, (uint32_t *)children);
		return;
	}

#ifndef ALLOW_UNALIGNED_ACCESS
	if ((POINTER_CAST_TO(src_idx, size_t) & (sizeof(uint32_t)-1)) == 0) {
#endif
		for (i = 0; i < count; i++) {
			children[i] = src_idx[i] == 0 ? NULL :
				POINTER_CAST(src_idx[i] | 1);
		}
#ifndef ALLOW_UNALIGNED_ACCESS
	} else {
		/* unaligned access */
		const uint8_t *src_idx8 = (const uint8_t *)src_idx;
		uint32_t idx;

		for (i = 0; i < count; i++) {
			memcpy(&idx, src_idx8 + i * sizeof(uint32_t),
			       sizeof(idx));
			children[i] = idx == 0 ? NULL : POINTER_CAST(idx | 1);
		}
	}
#endif
}

static int trie_map_area(struct squat_trie *trie, uoff_t offset, size_t len)
{
	ssize_t ret;

	if (trie->file_cache == NULL)
		return 0;

	ret = file_cache_read(trie->file_cache, offset, len);
	if (ret < 0) {
		squat_trie_set_syscall_error(trie, "file_cache_read()");
		return -1;
	}
	trie->const_mmap_base =
		file_cache_get_map(trie->file_cache, &trie->mmap_size);
	trie->hdr = (const void *)trie->const_mmap_base;
	return 0;
}

static void
trie_map_fix_fast_node(struct trie_node *node, unsigned int chars8_count)
{
	uint8_t *chars = NODE_CHARS8(node);
	struct trie_node **children = NODE_CHILDREN8(node);
	int i, j;

	i_assert(node->chars_8bit_count == MAX_8BIT_CHAR_COUNT);

	j = chars8_count - 1;
	for (i = node->chars_8bit_count - 1; i >= 0; i--) {
		if (j >= 0 && i == chars[j])
			children[i] = children[j--];
		else
			children[i] = NULL;
		chars[i] = i;
	}
}

static int
trie_map_node(struct squat_trie *trie, uint32_t offset, unsigned int level,
	      struct trie_node **node_r)
{
	struct trie_node *node;
	const uint8_t *p, *end, *chars8_src, *chars16_src;
	uint32_t num, chars8_count, chars16_count;
	unsigned int chars8_offset, chars8_size, chars8_memsize;
	unsigned int chars16_offset, chars16_size, chars16_memsize;
	unsigned int idx_size, alloced_chars8_count;

	i_assert(trie->fd != -1);

	if (trie_map_area(trie, offset, 2+256) < 0)
		return -1;

	if (offset >= trie->mmap_size) {
		squat_trie_set_corrupted(trie, "trie offset too large");
		return -1;
	}

	p = trie->const_mmap_base + offset;
	end = trie->const_mmap_base + trie->mmap_size;

	/* get 8bit char count and check that it's valid */
	num = squat_trie_unpack_num(&p, end);
	chars8_count = num >> 1;

	chars8_offset = p - trie->const_mmap_base;
	chars8_size = chars8_count * (sizeof(uint8_t) + sizeof(uint32_t));

	if (trie_map_area(trie, chars8_offset, chars8_size + 8) < 0)
		return -1;

	if (chars8_count > MAX_8BIT_CHAR_COUNT ||
	    chars8_offset + chars8_size > trie->mmap_size) {
		squat_trie_set_corrupted(trie, "trie offset broken");
		return -1;
	}

	idx_size = level == BLOCK_SIZE ?
		sizeof(uint32_t) : sizeof(struct trie_node *);

	alloced_chars8_count = level <= FAST_8BIT_LEVEL ?
		MAX_8BIT_CHAR_COUNT : chars8_count;
	chars8_memsize = ALIGN(alloced_chars8_count * sizeof(uint8_t)) +
		alloced_chars8_count * idx_size;

	if ((num & 1) == 0) {
		/* no 16bit chars */
		chars16_count = 0;
		chars16_memsize = 0;
		chars16_offset = 0;
	} else {
		/* get the 16bit char count */
		p = trie->const_mmap_base + chars8_offset + chars8_size;
		end = trie->const_mmap_base + trie->mmap_size;

		chars16_count = squat_trie_unpack_num(&p, end);
		if (chars16_count > 65536) {
			squat_trie_set_corrupted(trie, "trie offset broken");
			return -1;
		}
		chars16_offset = p - trie->const_mmap_base;

		/* map the required area size and make sure it exists */
		chars16_size = chars16_count *
			(sizeof(uint16_t) + sizeof(uint32_t));
		if (trie_map_area(trie, chars16_offset, chars16_size) < 0)
			return -1;

		if (chars16_offset + chars16_size > trie->mmap_size) {
			squat_trie_set_corrupted(trie, "trie offset broken");
			return -1;
		}

		chars16_memsize = ALIGN(chars16_count * sizeof(uint16_t)) +
			chars16_count * idx_size;
	}

	node = i_malloc(sizeof(*node) + chars8_memsize + chars16_memsize);
	node->chars_8bit_count = alloced_chars8_count;
	node->chars_16bit_count = chars16_count;
	node->file_offset = offset;

	{
		uint8_t *chars8 = NODE_CHARS8(node);
		uint16_t *chars16 = NODE_CHARS16(node, level);
		struct trie_node **children8 = NODE_CHILDREN8(node);
		struct trie_node **children16 = NODE_CHILDREN16(node, level);
		const uint32_t *src_idx;
		const void *end_offset;

		chars8_src = trie->const_mmap_base + chars8_offset;
		chars16_src = trie->const_mmap_base + chars16_offset;

		memcpy(chars8, chars8_src, sizeof(uint8_t) * chars8_count);
		memcpy(chars16, chars16_src, sizeof(uint16_t) * chars16_count);

		src_idx = CONST_PTR_OFFSET(chars8_src, chars8_count);
		trie_map_node_save_children(level, src_idx, chars8_count,
					    children8);

		if (alloced_chars8_count != chars8_count)
			trie_map_fix_fast_node(node, chars8_count);
		if (chars16_count == 0)
			end_offset = &src_idx[chars8_count];
		else {
			src_idx = CONST_PTR_OFFSET(chars16_src,
						   chars16_count *
						   sizeof(uint16_t));
			trie_map_node_save_children(level, src_idx,
						    chars16_count, children16);
			end_offset = &src_idx[chars16_count];
		}

		node->orig_size = ((const uint8_t *)end_offset -
				   trie->const_mmap_base) - offset;
	}

	*node_r = node;
	return 0;
}

static void free_children(unsigned int level, struct trie_node **children,
			  unsigned int count)
{
	unsigned int i;
	uint32_t child_idx;

	for (i = 0; i < count; i++) {
		child_idx = POINTER_CAST_TO(children[i], size_t);
		if ((child_idx & 1) == 0 && children[i] != NULL)
			free_node(children[i], level);
	}
}

static void free_node(struct trie_node *node, unsigned int level)
{
	if (level < BLOCK_SIZE) {
		struct trie_node **children8 = NODE_CHILDREN8(node);
		struct trie_node **children16 = NODE_CHILDREN16(node, level);

		free_children(level + 1, children8, node->chars_8bit_count);
		free_children(level + 1, children16, node->chars_16bit_count);
	}
	i_free(node);
}

static void squat_trie_unmap(struct squat_trie *trie)
{
	if (trie->file_cache != NULL)
		file_cache_invalidate(trie->file_cache, 0, (uoff_t)-1);

	if (trie->mmap_base != NULL) {
		if (munmap(trie->mmap_base, trie->mmap_size) < 0)
			squat_trie_set_syscall_error(trie, "munmap()");
		trie->mmap_base = NULL;
	}

	trie->mmap_size = 0;
	trie->hdr = NULL;
	trie->const_mmap_base = NULL;

	if (trie->root != NULL) {
		free_node(trie->root, 1);
		trie->root = NULL;
	}
}

static void trie_file_close(struct squat_trie *trie)
{
	if (trie->file_cache != NULL)
		file_cache_free(&trie->file_cache);
	if (trie->file_lock != NULL)
		file_lock_free(&trie->file_lock);

	squat_trie_unmap(trie);
	if (trie->fd != -1) {
		if (close(trie->fd) < 0)
			squat_trie_set_syscall_error(trie, "close()");
		trie->fd = -1;
	}

	trie->hdr = NULL;
	trie->corrupted = FALSE;
}

static int
trie_map_check_header(struct squat_trie *trie,
		      const struct squat_trie_header *hdr, uoff_t file_size)
{
	if (hdr->version != SQUAT_TRIE_VERSION)
		return -1;

	if (hdr->used_file_size > file_size) {
		squat_trie_set_corrupted(trie, "used_file_size too large");
		return -1;
	}
	if (hdr->root_offset != 0 &&
	    (hdr->root_offset > file_size ||
	     hdr->root_offset < sizeof(*hdr))) {
		squat_trie_set_corrupted(trie, "invalid root_offset");
		return -1;
	}
	if (hdr->uidvalidity != trie->uidvalidity) {
		squat_trie_set_corrupted(trie, "uidvalidity changed");
		return -1;
	}

	return 0;
}

static int squat_trie_file_was_modified(struct squat_trie *trie)
{
	struct squat_trie_header hdr;
	int ret;

	ret = pread_full(trie->fd, &hdr.modify_counter,
			 sizeof(hdr.modify_counter),
			 offsetof(struct squat_trie_header, modify_counter));
	if (ret < 0) {
		squat_trie_set_syscall_error(trie, "pread_full()");
		return -1;
	}
	if (ret == 0) {
		/* broken file, treat as modified */
		return 1;
	}
	return hdr.modify_counter == trie->file_cache_modify_counter ? 0 : 1;
}

static int squat_trie_map(struct squat_trie *trie)
{
	const struct squat_trie_header *hdr;
	struct stat st;
	ssize_t ret;

	if (trie->hdr != NULL) {
		if (!trie->mmap_disable) {
			if (trie->hdr->used_file_size <= trie->mmap_size) {
				/* everything is already mapped */
				return 1;
			}
		} else {
			ret = squat_trie_file_was_modified(trie);
			if (ret <= 0)
				return ret < 0 ? -1 : 1;
		}
	}

	if (fstat(trie->fd, &st) < 0) {
		squat_trie_set_syscall_error(trie, "fstat()");
		return -1;
	}
	trie->dev = st.st_dev;
	trie->ino = st.st_ino;

	squat_trie_unmap(trie);

	if (!trie->mmap_disable) {
		trie->mmap_size = st.st_size;
		trie->mmap_base = mmap(NULL, trie->mmap_size,
				       PROT_READ | PROT_WRITE,
				       MAP_SHARED, trie->fd, 0);
		if (trie->mmap_base == MAP_FAILED) {
			trie->mmap_size = 0;
			trie->mmap_base = NULL;
			squat_trie_set_syscall_error(trie, "mmap()");
			return -1;
		}
		trie->const_mmap_base = trie->mmap_base;
	} else {
		ret = file_cache_read(trie->file_cache, 0, sizeof(*trie->hdr));
		if (ret < 0) {
			squat_trie_set_syscall_error(trie, "file_cache_read()");
			return -1;
		}
		if ((size_t)ret < sizeof(*trie->hdr)) {
			squat_trie_set_corrupted(trie, "file too small");
			return -1;
		}
		trie->const_mmap_base =
			file_cache_get_map(trie->file_cache, &trie->mmap_size);
	}

	hdr = (const void *)trie->const_mmap_base;
	if (trie_map_check_header(trie, hdr, st.st_size) < 0)
		return -1;
	trie->hdr = hdr;
	trie->file_cache_modify_counter = trie->hdr->modify_counter;

	if (trie->hdr->root_offset != 0) {
		if (trie_map_node(trie, trie->hdr->root_offset,
				  1, &trie->root) < 0)
			return 0;
	}
	return 1;
}

static void trie_file_open_fd(struct squat_trie *trie, int fd)
{
	struct stat st;

	if (fstat(fd, &st) < 0) {
		/* don't bother adding complexity by trying to handle this
		   error here. we'll break later anyway in easier error
		   handling paths. */
		squat_trie_set_syscall_error(trie, "fstat()");
		trie->ino = 0;
	} else {
		trie->dev = st.st_dev;
		trie->ino = st.st_ino;
	}
	trie->fd = fd;

	if (trie->mmap_disable)
		trie->file_cache = file_cache_new(trie->fd);
}

static int trie_file_open(struct squat_trie *trie, bool create)
{
	int fd;

	i_assert(trie->fd == -1);

	fd = open(trie->filepath, O_RDWR | (create ? O_CREAT : 0), 0660);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;

		squat_trie_set_syscall_error(trie, "open()");
		return -1;
	}
	trie_file_open_fd(trie, fd);
	return 1;
}

static int trie_file_create_finish(struct squat_trie *trie)
{
	struct squat_trie_header hdr;
	struct stat st;

	if (fstat(trie->fd, &st) < 0) {
		squat_trie_set_syscall_error(trie, "fstat()");
		return -1;
	}

	if (st.st_size <= (off_t)sizeof(hdr)) {
		memset(&hdr, 0, sizeof(hdr));
		hdr.version = SQUAT_TRIE_VERSION;
		hdr.uidvalidity = trie->uidvalidity;
		hdr.used_file_size = sizeof(hdr);

		if (pwrite_full(trie->fd, &hdr, sizeof(hdr), 0) < 0) {
			squat_trie_set_syscall_error(trie, "pwrite_full()");
			return -1;
		}
	}

	return 0;
}

struct squat_trie *
squat_trie_open(const char *path, uint32_t uidvalidity,
		enum file_lock_method lock_method, bool mmap_disable)
{
	struct squat_trie *trie;

	trie = i_new(struct squat_trie, 1);
	trie->fd = -1;
	trie->filepath = i_strdup(path);
	trie->uidvalidity = uidvalidity;
	trie->lock_method = lock_method;
	trie->mmap_disable = mmap_disable;
	trie->buf = buffer_create_dynamic(default_pool, 1024);

	trie->uidlist_filepath = i_strconcat(path, ".uids", NULL);
	trie->uidlist =
		squat_uidlist_init(trie, trie->uidlist_filepath,
				   uidvalidity, mmap_disable);
	return trie;
}

void squat_trie_close(struct squat_trie *trie)
{
	squat_trie_unmap(trie);
	buffer_free(&trie->buf);
	squat_uidlist_deinit(trie->uidlist);
	i_free(trie->uidlist_filepath);
	i_free(trie->filepath);
	i_free(trie);
}

int squat_trie_get_last_uid(struct squat_trie *trie, uint32_t *uid_r)
{
	int ret;

	if (trie->fd == -1) {
		if ((ret = trie_file_open(trie, FALSE)) < 0)
			return ret;
		if (ret == 0) {
			*uid_r = 0;
			return 0;
		}
	}

	if (squat_trie_lock(trie, F_RDLCK) <= 0)
		return -1;

	ret = squat_uidlist_get_last_uid(trie->uidlist, uid_r);
	squat_trie_unlock(trie);
	return ret;
}

static int squat_trie_is_file_stale(struct squat_trie *trie)
{
	struct stat st;

	if (stat(trie->filepath, &st) < 0) {
		if (errno == ENOENT)
			return 1;

		squat_trie_set_syscall_error(trie, "stat()");
		return -1;
	}

	return st.st_ino == trie->ino &&
		CMP_DEV_T(st.st_dev, trie->dev) ? 0 : 1;
}

static int
squat_trie_file_lock(struct squat_trie *trie, int fd, const char *path,
		     int lock_type, struct file_lock **lock_r)
{
	int ret;

	ret = file_wait_lock(fd, path, lock_type, trie->lock_method,
			     SQUAT_TRIE_LOCK_TIMEOUT, lock_r);
	if (ret == 0)
		squat_trie_set_syscall_error(trie, "file_wait_lock()");
	return ret;
}

int squat_trie_lock(struct squat_trie *trie, int lock_type)
{
	bool created = FALSE;
	int ret;

	i_assert(lock_type == F_RDLCK || lock_type == F_WRLCK);

	if (trie->lock_count > 0) {
		/* read lock -> write lock would deadlock */
		i_assert(trie->lock_type == lock_type || lock_type == F_RDLCK);

		trie->lock_count++;
		return 1;
	}

	if (trie->fd == -1 || trie->corrupted) {
		trie_file_close(trie);
		if (lock_type == F_WRLCK) {
			if ((ret = trie_file_open(trie, FALSE)) < 0)
				return -1;
			if (ret == 0) {
				if (trie_file_open(trie, TRUE) < 0)
					return -1;
				created = TRUE;
			}
		} else {
			if (trie_file_open(trie, FALSE) <= 0)
				return -1;
		}
	}

	for (;;) {
		i_assert(trie->file_lock == NULL);
		ret = squat_trie_file_lock(trie, trie->fd, trie->filepath,
					   lock_type, &trie->file_lock);
		if (ret <= 0)
			return ret;

		/* if the trie has been compressed, we need to reopen the
		   file and try to lock again */
		ret = squat_trie_is_file_stale(trie);
		if (ret == 0)
			break;

		file_unlock(&trie->file_lock);
		if (ret < 0)
			return -1;

		trie_file_close(trie);
		if (trie_file_open(trie, FALSE) <= 0)
			return -1;
	}

	if (created) {
		/* we possibly created this file. now that we've locked the
		   file, we can safely check if someone else already wrote the
		   header or if we should do it now */
		if (trie_file_create_finish(trie) < 0) {
			file_unlock(&trie->file_lock);
			return -1;
		}
	}

	if (squat_trie_map(trie) <= 0) {
		file_unlock(&trie->file_lock);
		return -1;
	}
	if (squat_uidlist_refresh(trie->uidlist) < 0) {
		file_unlock(&trie->file_lock);
		return -1;
	}

	trie->lock_count++;
	trie->lock_type = lock_type;
	return 1;
}

void squat_trie_unlock(struct squat_trie *trie)
{
	i_assert(trie->lock_count > 0);

	if (--trie->lock_count > 0)
		return;

	file_unlock(&trie->file_lock);
}

static struct trie_node *
node_alloc(uint16_t chr, unsigned int level)
{
	struct trie_node *node;
	unsigned int i, idx_size, idx_offset = sizeof(*node);

	idx_size = level < BLOCK_SIZE ?
		sizeof(struct trie_node *) : sizeof(uint32_t);

	if (level <= FAST_8BIT_LEVEL) {
		uint8_t *chars;
		unsigned int chars16_count = chr >= MAX_8BIT_CHAR_COUNT ? 1 : 0;

		node = i_malloc(sizeof(*node) +
				ALIGN(MAX_8BIT_CHAR_COUNT) +
				ALIGN(sizeof(uint16_t) * chars16_count) +
				(MAX_8BIT_CHAR_COUNT + chars16_count) *
				idx_size);
		node->chars_8bit_count = MAX_8BIT_CHAR_COUNT;

		chars = NODE_CHARS8(node);
		for (i = 0; i < MAX_8BIT_CHAR_COUNT; i++)
			chars[i] = i;

		if (chars16_count > 0) {
			uint16_t *chars16 = NODE_CHARS16(node, 0);

			node->chars_16bit_count = chars16_count;
			chars16[0] = chr;
		}
	} else if (chr < MAX_8BIT_CHAR_COUNT) {
		uint8_t *chrp;

		idx_offset += ALIGN(sizeof(*chrp));
		node = i_malloc(idx_offset + idx_size);
		node->chars_8bit_count = 1;

		chrp = PTR_OFFSET(node, sizeof(*node));
		*chrp = chr;
	} else {
		uint16_t *chrp;

		idx_offset += ALIGN(sizeof(*chrp));
		node = i_malloc(idx_offset + idx_size);
		node->chars_16bit_count = 1;

		chrp = PTR_OFFSET(node, sizeof(*node));
		*chrp = chr;
	}

	node->modified = TRUE;
	node->resized = TRUE;
	return node;
}

static struct trie_node *
node_realloc(struct trie_node *node, uint32_t char_idx, uint16_t chr,
	     unsigned int level)
{
	struct trie_node *new_node;
	unsigned int old_size_8bit, old_size_16bit, old_idx_offset;
	unsigned int idx_size, old_size, new_size, new_idx_offset;
	unsigned int hole1_pos, hole2_pos, skip;

	idx_size = level < BLOCK_SIZE ?
		sizeof(struct trie_node *) : sizeof(uint32_t);

	old_size_8bit = ALIGN(node->chars_8bit_count) +
		node->chars_8bit_count * idx_size;
	old_size_16bit = ALIGN(sizeof(uint16_t) * node->chars_16bit_count) +
		node->chars_16bit_count * idx_size;
	old_size = sizeof(*node) + old_size_8bit + old_size_16bit;

	if (chr < MAX_8BIT_CHAR_COUNT) {
		new_idx_offset = sizeof(*node) +
			ALIGN(node->chars_8bit_count + 1);
		new_size = new_idx_offset + old_size_16bit +
			(node->chars_8bit_count + 1) * idx_size;
	} else {
		new_idx_offset = sizeof(*node) + old_size_8bit +
			ALIGN((node->chars_16bit_count + 1) * sizeof(uint16_t));
		new_size = new_idx_offset +
			(node->chars_16bit_count + 1) * idx_size;
	}

	new_node = t_buffer_get(new_size);
	if (chr < MAX_8BIT_CHAR_COUNT) {
		hole1_pos = sizeof(*node) + char_idx;
		old_idx_offset = sizeof(*node) + ALIGN(node->chars_8bit_count);
	} else {
		hole1_pos = sizeof(*node) + old_size_8bit +
			char_idx * sizeof(uint16_t);
		old_idx_offset = sizeof(*node) + old_size_8bit +
			ALIGN(node->chars_16bit_count * sizeof(uint16_t));
	}
	hole2_pos = old_idx_offset + idx_size * char_idx;

	/* 0..character position */
	memcpy(new_node, node, hole1_pos);
	if (chr < MAX_8BIT_CHAR_COUNT) {
		uint8_t *chrp = PTR_OFFSET(new_node, hole1_pos);
		*chrp = chr;
		new_node->chars_8bit_count++;

		/* rest of the characters */
		memcpy(PTR_OFFSET(new_node, hole1_pos + sizeof(uint8_t)),
		       PTR_OFFSET(node, hole1_pos), old_idx_offset - hole1_pos);
	} else {
		uint16_t *chrp = PTR_OFFSET(new_node, hole1_pos);
		*chrp = chr;
		new_node->chars_16bit_count++;

		/* rest of the characters */
		memcpy(PTR_OFFSET(new_node, hole1_pos + sizeof(uint16_t)),
		       PTR_OFFSET(node, hole1_pos), old_idx_offset - hole1_pos);
	}

	/* indexes from 0 to character position */
	memcpy(PTR_OFFSET(new_node, new_idx_offset),
	       PTR_OFFSET(node, old_idx_offset),
	       hole2_pos - old_idx_offset);

	/* zero the inserted character index */
	skip = char_idx * idx_size;
	memset(PTR_OFFSET(new_node, new_idx_offset + skip), 0, idx_size);

	/* rest of the indexes */
	skip += idx_size;
	memcpy(PTR_OFFSET(new_node, new_idx_offset + skip),
	       PTR_OFFSET(node, hole2_pos),
	       old_size - hole2_pos);

	new_node->resized = TRUE;

	node = i_realloc(node, 0, new_size);
	memcpy(node, new_node, new_size);
	return node;
}

static int
trie_insert_node(struct squat_trie_build_context *ctx,
		 struct trie_node **parent,
		 const uint16_t *data, uint32_t uid, unsigned int level)
{
	struct squat_trie *trie = ctx->trie;
	struct trie_node *node = *parent;
	struct trie_node **children;
	uint32_t char_idx;
	bool match, modified = FALSE;
	int ret;

	if (*data < MAX_8BIT_CHAR_COUNT) {
		unsigned int count;

		if (node == NULL) {
			ctx->node_count++;
			node = *parent = node_alloc(*data, level);
			char_idx = level <= FAST_8BIT_LEVEL ? *data : 0;
			modified = TRUE;
		} else if (level <= FAST_8BIT_LEVEL) {
			char_idx = *data;
		} else {
			uint8_t *chars = NODE_CHARS8(node);

			count = node->chars_8bit_count;
			match = bsearch_insert_pos(data, chars, count,
						   sizeof(chars[0]),
						   chr_8bit_cmp,
						   &char_idx);
			if (!match) {
				node = node_realloc(node, char_idx,
						    *data, level);
				*parent = node;
				modified = TRUE;
			}
		}
		children = NODE_CHILDREN8(node);
	} else {
		unsigned int offset = sizeof(*node);
		unsigned int count;

		if (node == NULL) {
			ctx->node_count++;
			node = *parent = node_alloc(*data, level);
			char_idx = 0;
			modified = TRUE;
		} else {
			unsigned int idx_size;
			uint16_t *chars;

			idx_size = level < BLOCK_SIZE ?
				sizeof(struct trie_node *) : sizeof(uint32_t);
			offset += ALIGN(node->chars_8bit_count) +
				idx_size * node->chars_8bit_count;
			chars = PTR_OFFSET(node, offset);

			count = node->chars_16bit_count;
			match = bsearch_insert_pos(data, chars, count,
						   sizeof(chars[0]),
						   chr_16bit_cmp,
						   &char_idx);
			if (!match) {
				node = node_realloc(node, char_idx,
						    *data, level);
				*parent = node;
				modified = TRUE;
			}
		}

		children = NODE_CHILDREN16(node, level);
	}

	if (level < BLOCK_SIZE) {
		size_t child_idx = POINTER_CAST_TO(children[char_idx], size_t);

		if ((child_idx & 1) != 0) {
			if (trie_map_node(trie, child_idx & ~1, level + 1,
					  &children[char_idx]) < 0)
				return -1;
		}

		if (children[char_idx] == NULL)
			node->resized = TRUE;

		ret = trie_insert_node(ctx, &children[char_idx],
				       data + 1, uid, level + 1);
		if (ret < 0)
			return -1;
		if (ret > 0)
			node->modified = TRUE;
	} else {
		uint32_t *uid_lists = (uint32_t *)children;

		if (uid_lists[char_idx] == 0)
			node->resized = TRUE;

		if (squat_uidlist_add(trie->uidlist, &uid_lists[char_idx],
				      uid) < 0)
			return -1;

		node->modified = TRUE;
	}
	return modified ? 1 : 0;
}

static uint32_t
trie_lookup_node(struct squat_trie *trie, struct trie_node *node,
		 const uint16_t *data, unsigned int level)
{
	struct trie_node **children;
	uint32_t char_idx;

	if (node == NULL)
		return 0;

	if (*data < MAX_8BIT_CHAR_COUNT) {
		if (level <= FAST_8BIT_LEVEL)
			char_idx = *data;
		else {
			const uint8_t *chars, *pos;
			chars = NODE_CHARS8(node);
			pos = bsearch(data, chars, node->chars_8bit_count,
				      sizeof(chars[0]), chr_8bit_cmp);
			if (pos == NULL || *pos != *data)
				return 0;

			char_idx = pos - chars;
		}
		children = NODE_CHILDREN8(node);
	} else {
		const uint16_t *chars, *pos;

		chars = NODE_CHARS16(node, level);
		pos = bsearch(data, chars, node->chars_16bit_count,
			      sizeof(chars[0]), chr_16bit_cmp);
		if (pos == NULL || *pos != *data)
			return 0;

		char_idx = pos - chars;
		children = NODE_CHILDREN16(node, level);
	}

	if (level < BLOCK_SIZE) {
		size_t child_idx = POINTER_CAST_TO(children[char_idx], size_t);

		if ((child_idx & 1) != 0) {
			/* not mapped to memory yet. do it. */
			if (trie_map_node(trie, child_idx & ~1, level + 1,
					  &children[char_idx]) < 0)
				return -1;
		}

		return trie_lookup_node(trie, children[char_idx],
					data + 1, level + 1);
	} else {
		const uint32_t *uid_lists = (const uint32_t *)children;

		return uid_lists[char_idx];
	}
}

static bool block_want_add(const uint16_t *data)
{
	unsigned int i;

	/* skip all blocks that contain spaces or control characters.
	   no-one searches them anyway */
	for (i = 0; i < BLOCK_SIZE; i++) {
		if (data[i] == 0)
			return FALSE;
	}
	return TRUE;
}

struct squat_trie_build_context *
squat_trie_build_init(struct squat_trie *trie, uint32_t *last_uid_r)
{
	struct squat_trie_build_context *ctx;

	ctx = i_new(struct squat_trie_build_context, 1);
	ctx->trie = trie;

	if (squat_trie_lock(trie, F_WRLCK) <= 0)
		ctx->failed = TRUE;
	else {
		ctx->locked = TRUE;
		ctx->node_count = trie->hdr->node_count;

		if (squat_uidlist_get_last_uid(trie->uidlist, last_uid_r) < 0)
			ctx->failed = TRUE;
	}

	if (ctx->failed)
		*last_uid_r = 0;
	return ctx;
}

int squat_trie_build_deinit(struct squat_trie_build_context *ctx)
{
	int ret = ctx->failed ? -1 : 0;

	if (ret == 0)
		ret = squat_trie_build_flush(ctx, TRUE);

	if (ctx->locked)
		squat_trie_unlock(ctx->trie);

	i_free(ctx);
	return ret;
}

int squat_trie_build_more(struct squat_trie_build_context *ctx, uint32_t uid,
			  const unsigned char *data, size_t size)
{
	const uint16_t *str;
	uint16_t buf[(BLOCK_SIZE-1)*2];
	unsigned int i, tmp_size, str_len;

	if (ctx->failed)
		return -1;

	t_push();
	str = data_normalize(data, size, ctx->trie->buf);
	str_len = ctx->trie->buf->used / sizeof(*str);

	if (uid == ctx->prev_uid) {
		/* @UNSAFE: continue from last block */
		memcpy(buf, ctx->prev_added,
		       sizeof(buf[0]) * ctx->prev_added_size);
		tmp_size = I_MIN(str_len, BLOCK_SIZE-1);
		memcpy(buf + ctx->prev_added_size, str,
		       sizeof(buf[0]) * tmp_size);

		tmp_size += ctx->prev_added_size;
		for (i = 0; i + BLOCK_SIZE <= tmp_size; i++) {
			if (block_want_add(buf+i)) {
				if (trie_insert_node(ctx,
						     &ctx->trie->root,
						     buf + i, uid, 1) < 0) {
					t_pop();
					return -1;
				}
			}
		}

		if (str_len < BLOCK_SIZE) {
			ctx->prev_added_size = I_MIN(tmp_size, BLOCK_SIZE-1);
			memcpy(ctx->prev_added, buf + i,
			       sizeof(buf[0]) * ctx->prev_added_size);
			t_pop();
			return 0;
		}
	} else if (squat_uidlist_want_flush(ctx->trie->uidlist)) {
		if (squat_trie_build_flush(ctx, FALSE) < 0) {
			ctx->failed = TRUE;
			t_pop();
			return -1;
		}
		str = data_normalize(data, size, ctx->trie->buf);
		str_len = ctx->trie->buf->used / sizeof(*str);
	}

	ctx->prev_uid = uid;
	for (i = 0; i + BLOCK_SIZE <= str_len; i++) {
		if (block_want_add(str+i)) {
			if (trie_insert_node(ctx, &ctx->trie->root,
					     str + i, uid, 1) < 0) {
				t_pop();
				return -1;
			}
		}
	}
	ctx->prev_added_size = I_MIN(str_len - i, BLOCK_SIZE-1);
	memcpy(ctx->prev_added, str + i,
	       sizeof(ctx->prev_added[0]) * ctx->prev_added_size);

	t_pop();
	return 0;
}

static void node_pack_children(buffer_t *buf, struct trie_node **children,
			       unsigned int count)
{
	unsigned int i;
	size_t child_idx;
	uint32_t idx;

	for (i = 0; i < count; i++) {
		if (children[i] == NULL)
			continue;

		child_idx = POINTER_CAST_TO(children[i], size_t);
		if ((child_idx & 1) != 0)
			idx = child_idx & ~1;
		else
			idx = children[i]->file_offset;
		buffer_append(buf, &idx, sizeof(idx));
	}
}

static void node_pack(buffer_t *buf, struct trie_node *node)
{
	uint8_t *chars8 = NODE_CHARS8(node);
	uint16_t *chars16 = NODE_CHARS16(node, 0);
	struct trie_node **children8 = NODE_CHILDREN8(node);
	struct trie_node **children16 = NODE_CHILDREN16(node, 0);

	buffer_set_used_size(buf, 0);
	squat_trie_pack_num(buf, (node->chars_8bit_count << 1) |
			    (node->chars_16bit_count > 0 ? 1 : 0));
	buffer_append(buf, chars8, node->chars_8bit_count);
	node_pack_children(buf, children8, node->chars_8bit_count);

	if (node->chars_16bit_count > 0) {
		squat_trie_pack_num(buf, node->chars_16bit_count);
		buffer_append(buf, chars16,
			      sizeof(*chars16) * node->chars_16bit_count);
		node_pack_children(buf, children16, node->chars_16bit_count);
	}
}

static int node_leaf_finish(struct squat_trie *trie, struct trie_node *node)
{
	uint32_t *idx8 = (uint32_t *)NODE_CHILDREN8(node);
	uint32_t *idx16 = (uint32_t *)NODE_CHILDREN16(node, BLOCK_SIZE);
	unsigned int i;

	for (i = 0; i < node->chars_8bit_count; i++) {
		if (squat_uidlist_finish_list(trie->uidlist, &idx8[i]) < 0)
			return -1;
	}
	for (i = 0; i < node->chars_16bit_count; i++) {
		if (squat_uidlist_finish_list(trie->uidlist, &idx16[i]) < 0)
			return -1;
	}
	return 0;
}

static void node_pack_leaf(buffer_t *buf, struct trie_node *node)
{
	uint8_t *chars8 = NODE_CHARS8(node);
	uint16_t *chars16 = NODE_CHARS16(node, BLOCK_SIZE);
	uint32_t *idx8 = (uint32_t *)NODE_CHILDREN8(node);
	uint32_t *idx16 = (uint32_t *)NODE_CHILDREN16(node, BLOCK_SIZE);

	buffer_set_used_size(buf, 0);
	squat_trie_pack_num(buf, (node->chars_8bit_count << 1) |
			    (node->chars_16bit_count > 0 ? 1 : 0));
	buffer_append(buf, chars8, node->chars_8bit_count);
	buffer_append(buf, idx8, sizeof(*idx8) * node->chars_8bit_count);

	if (node->chars_16bit_count > 0) {
		squat_trie_pack_num(buf, node->chars_16bit_count);
		buffer_append(buf, chars16,
			      sizeof(*chars16) * node->chars_16bit_count);
		buffer_append(buf, idx16,
			      sizeof(*idx16) * node->chars_16bit_count);
	}
}

static int
trie_write_node_children(struct squat_trie_build_context *ctx,
			 unsigned int level, struct trie_node **children,
			 unsigned int count)
{
	unsigned int i;
	size_t child_idx;

	for (i = 0; i < count; i++) {
		child_idx = POINTER_CAST_TO(children[i], size_t);
		if ((child_idx & 1) == 0 && children[i] != NULL) {
			if (trie_write_node(ctx, level, children[i]) < 0)
				return -1;
		}
	}
	return 0;
}

static int trie_write_node(struct squat_trie_build_context *ctx,
			   unsigned int level, struct trie_node *node)
{
	struct squat_trie *trie = ctx->trie;
	uoff_t offset;

	if (level < BLOCK_SIZE) {
		struct trie_node **children8 = NODE_CHILDREN8(node);
		struct trie_node **children16 = NODE_CHILDREN16(node, level);

		if (trie_write_node_children(ctx, level + 1,
					     children8,
					     node->chars_8bit_count) < 0)
			return -1;
		if (trie_write_node_children(ctx, level + 1,
					     children16,
					     node->chars_16bit_count) < 0)
			return -1;
	}

	if (!node->modified)
		return 0;

	if (level < BLOCK_SIZE) {
		if (level <= FAST_8BIT_LEVEL)
			squat_trie_compress_chars8(node);
		node_pack(trie->buf, node);
	} else {
		if (node_leaf_finish(trie, node) < 0)
			return -1;

		node_pack_leaf(trie->buf, node);
	}

	offset = ctx->output->offset;
	if ((offset & 1) != 0) {
		o_stream_send(ctx->output, "", 1);
		offset++;
	}

	if (node->resized && node->orig_size < trie->buf->used) {
		/* append to end of file. the parent node is written later. */
		node->file_offset = offset;
		o_stream_send(ctx->output, trie->buf->data, trie->buf->used);

		ctx->deleted_space += node->orig_size;
	} else {
		/* overwrite node's contents */
		i_assert(node->file_offset != 0);
		i_assert(trie->buf->used <= node->orig_size);

		/* FIXME: write only the indexes if !node->resized */
		o_stream_seek(ctx->output, node->file_offset);
		o_stream_send(ctx->output, trie->buf->data, trie->buf->used);
		o_stream_seek(ctx->output, offset);

		ctx->deleted_space += trie->buf->used - node->orig_size;
	}

	ctx->modified = TRUE;
	return 0;
}

static int
trie_nodes_write(struct squat_trie_build_context *ctx, uint32_t *uidvalidity_r)
{
	struct squat_trie *trie = ctx->trie;
	struct squat_trie_header hdr;

	hdr = *trie->hdr;
	ctx->output = o_stream_create_fd_file(trie->fd, (uoff_t)-1, FALSE);
	o_stream_seek(ctx->output, hdr.used_file_size);
	o_stream_cork(ctx->output);
	if (hdr.used_file_size == 0) {
		o_stream_send(ctx->output, &hdr, sizeof(hdr));
		ctx->modified = TRUE;
	}

	ctx->deleted_space = 0;
	if (trie_write_node(ctx, 1, trie->root) < 0)
		return -1;

	if (ctx->modified) {
		/* update the header */
		hdr.root_offset = trie->root->file_offset;
		hdr.used_file_size = ctx->output->offset;
		hdr.deleted_space += ctx->deleted_space;
		hdr.node_count = ctx->node_count;
		hdr.modify_counter++;
		o_stream_seek(ctx->output, 0);
		o_stream_send(ctx->output, &hdr, sizeof(hdr));
	}

	o_stream_destroy(&ctx->output);
	*uidvalidity_r = hdr.uidvalidity;
	return 0;
}

static bool squat_trie_need_compress(struct squat_trie *trie,
				     unsigned int current_message_count)
{
	uint32_t max_del_space;

	if (trie->hdr->used_file_size >= TRIE_COMPRESS_MIN_SIZE) {
		/* see if we've reached the max. deleted space in file */
		max_del_space = trie->hdr->used_file_size / 100 *
			TRIE_COMPRESS_PERCENTAGE;
		if (trie->hdr->deleted_space > max_del_space)
			return TRUE;
	}

	return squat_uidlist_need_compress(trie->uidlist,
					   current_message_count);
}

static int
squat_trie_build_flush(struct squat_trie_build_context *ctx, bool finish)
{
	struct squat_trie *trie = ctx->trie;
	uint32_t uidvalidity;

	if (trie->root == NULL) {
		/* nothing changed */
		return 0;
	}

	if (trie->corrupted)
		return -1;

	if (trie_nodes_write(ctx, &uidvalidity) < 0)
		return -1;
	if (squat_uidlist_flush(trie->uidlist, uidvalidity) < 0)
		return -1;

	squat_trie_unmap(trie);
	if (squat_trie_map(trie) <= 0)
		return -1;

	if (squat_trie_need_compress(trie, (unsigned int)-1)) {
		if (ctx->locked && finish) {
			squat_trie_unlock(ctx->trie);
			ctx->locked = FALSE;
		}

		if (squat_trie_compress(trie, NULL) < 0)
			return -1;
	}
	return 0;
}

static void squat_trie_compress_chars8(struct trie_node *node)
{
	uint8_t *chars = NODE_CHARS8(node);
	uint16_t *chars16, *old_chars16 = NODE_CHARS16(node, 0);
	struct trie_node **child_src = NODE_CHILDREN8(node);
	struct trie_node **child_dest;
	unsigned int i, j, old_count;

	old_count = node->chars_8bit_count;
	for (i = j = 0; i < old_count; i++) {
		if (child_src[i] != NULL)
			chars[j++] = chars[i];
	}

	node->chars_8bit_count = j;
	child_dest = NODE_CHILDREN8(node);

	for (i = j = 0; i < old_count; i++) {
		if (child_src[i] != NULL)
			child_dest[j++] = child_src[i];
	}

	if (node->chars_16bit_count > 0) {
		chars16 = NODE_CHARS16(node, 0);
		memmove(chars16, old_chars16,
			ALIGN(sizeof(*chars16) * node->chars_16bit_count) +
			sizeof(*child_src) * node->chars_16bit_count);
	}
}

static void squat_trie_compress_chars16(struct trie_node *node)
{
	uint16_t *chars = NODE_CHARS16(node, 0);
	struct trie_node **child_src = NODE_CHILDREN16(node, 0);
	struct trie_node **child_dest;
	unsigned int i, j, old_count;

	old_count = node->chars_16bit_count;
	for (i = j = 0; i < old_count; i++) {
		if (child_src[i] != NULL)
			chars[j++] = chars[i];
	}

	node->chars_16bit_count = j;
	child_dest = NODE_CHILDREN16(node, 0);

	for (i = j = 0; i < old_count; i++) {
		if (child_src[i] != NULL)
			child_dest[j++] = child_src[i];
	}
}

static void squat_trie_compress_leaf_chars8(struct trie_node *node)
{
	uint8_t *chars = NODE_CHARS8(node);
	uint32_t *child_src = (uint32_t *)NODE_CHILDREN8(node);
	uint32_t *child_dest;
	unsigned int i, j, old_count;

	old_count = node->chars_8bit_count;
	for (i = j = 0; i < old_count; i++) {
		if (child_src[i] != 0)
			chars[j++] = chars[i];
	}

	node->chars_8bit_count = j;
	child_dest = (uint32_t *)NODE_CHILDREN8(node);

	for (i = j = 0; i < old_count; i++) {
		if (child_src[i] != 0)
			child_dest[j++] = child_src[i];
	}
}

static void squat_trie_compress_leaf_chars16(struct trie_node *node)
{
	uint16_t *chars = NODE_CHARS16(node, BLOCK_SIZE);
	uint32_t *child_src = (uint32_t *)NODE_CHILDREN16(node, BLOCK_SIZE);
	uint32_t *child_dest;
	unsigned int i, j, old_count;

	old_count = node->chars_16bit_count;
	for (i = j = 0; i < old_count; i++) {
		if (child_src[i] != 0)
			chars[j++] = chars[i];
	}

	node->chars_16bit_count = j;
	child_dest = (uint32_t *)NODE_CHILDREN16(node, BLOCK_SIZE);

	for (i = j = 0; i < old_count; i++) {
		if (child_src[i] != 0)
			child_dest[j++] = child_src[i];
	}
}

static int
squat_trie_compress_children(struct squat_trie_compress_context *ctx,
			     struct trie_node **children, unsigned int count,
			     unsigned int level)
{
	struct trie_node *child_node;
	size_t child_idx;
	unsigned int i;
	int ret = 0;
	bool need_char_compress = FALSE;

	for (i = 0; i < count; i++) {
		if (children[i] == NULL) {
			need_char_compress = TRUE;
			continue;
		}

		child_idx = POINTER_CAST_TO(children[i], size_t);
		i_assert((child_idx & 1) != 0);
		child_idx &= ~1;

		if (trie_map_node(ctx->trie, child_idx, level, &child_node) < 0)
			return -1;

		ret = squat_trie_compress_node(ctx, child_node, level);
		if (child_node->file_offset != 0)
			children[i] = POINTER_CAST(child_node->file_offset | 1);
		else {
			children[i] = NULL;
			need_char_compress = TRUE;
		}
		i_free(child_node);

		if (ret < 0)
			return -1;
	}
	return need_char_compress ? 0 : 1;
}

static int
squat_trie_compress_leaf_uidlist(struct squat_trie_compress_context *ctx,
				 struct trie_node *node)
{
	uint32_t *idx8 = (uint32_t *)NODE_CHILDREN8(node);
	uint32_t *idx16 = (uint32_t *)NODE_CHILDREN16(node, BLOCK_SIZE);
	unsigned int i;
	int ret;
	bool compress_chars = FALSE;

	for (i = 0; i < node->chars_8bit_count; i++) {
		ret = squat_uidlist_compress_next(ctx->uidlist_ctx, &idx8[i]);
		if (ret < 0)
			return -1;
		if (ret == 0) {
			idx8[i] = 0;
			compress_chars = TRUE;
		}
	}
	if (compress_chars) {
		squat_trie_compress_leaf_chars8(node);
		compress_chars = FALSE;
	}
	for (i = 0; i < node->chars_16bit_count; i++) {
		ret = squat_uidlist_compress_next(ctx->uidlist_ctx, &idx16[i]);
		if (ret < 0)
			return -1;
		if (ret == 0) {
			idx16[i] = 0;
			compress_chars = TRUE;
		}
	}
	if (compress_chars) {
		squat_trie_compress_leaf_chars16(node);
		node->chars_16bit_count = i;
	}
	return 0;
}

static int
squat_trie_compress_node(struct squat_trie_compress_context *ctx,
			 struct trie_node *node, unsigned int level)
{
	struct squat_trie *trie = ctx->trie;
	int ret;

	if (level == BLOCK_SIZE) {
		if (squat_trie_compress_leaf_uidlist(ctx, node))
			return -1;

		if (node->chars_8bit_count == 0 &&
		    node->chars_16bit_count == 0) {
			/* everything expunged */
			ctx->node_count--;
			node->file_offset = 0;
			return 0;
		}
		node_pack_leaf(trie->buf, node);
	} else {
		struct trie_node **children8 = NODE_CHILDREN8(node);
		struct trie_node **children16;

		if ((ret = squat_trie_compress_children(ctx, children8,
							node->chars_8bit_count,
							level + 1)) < 0)
			return -1;
		if (ret == 0)
			squat_trie_compress_chars8(node);

		children16 = NODE_CHILDREN16(node, 0);
		if ((ret = squat_trie_compress_children(ctx, children16,
							node->chars_16bit_count,
							level + 1)) < 0)
			return -1;
		if (ret == 0)
			squat_trie_compress_chars16(node);

		if (node->chars_8bit_count == 0 &&
		    node->chars_16bit_count == 0) {
			/* everything expunged */
			ctx->node_count--;
			node->file_offset = 0;
			return 0;
		}

		node_pack(trie->buf, node);
	}

	if ((ctx->output->offset & 1) != 0)
		o_stream_send(ctx->output, "", 1);
	node->file_offset = ctx->output->offset;

	o_stream_send(ctx->output, trie->buf->data, trie->buf->used);
	return 0;
}

static int squat_trie_compress_init(struct squat_trie_compress_context *ctx,
				    struct squat_trie *trie)
{
	struct squat_trie_header hdr;

	memset(ctx, 0, sizeof(*ctx));

	ctx->tmp_path = t_strconcat(trie->filepath, ".tmp", NULL);
	ctx->fd = open(ctx->tmp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (ctx->fd == -1) {
		i_error("open(%s, O_CREAT) failed: %m", ctx->tmp_path);
		return -1;
	}

	ctx->trie = trie;
	ctx->output = o_stream_create_fd_file(ctx->fd, 0, FALSE);
	ctx->node_count = trie->hdr->node_count;

	/* write a dummy header first */
	memset(&hdr, 0, sizeof(hdr));
	o_stream_send(ctx->output, &hdr, sizeof(hdr));
	return 0;
}

static void
squat_trie_compress_write_header(struct squat_trie_compress_context *ctx,
				 struct trie_node *root_node)
{
	struct squat_trie_header hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.version = SQUAT_TRIE_VERSION;
	hdr.uidvalidity = ctx->trie->uidvalidity;
	hdr.root_offset = root_node->file_offset;
	hdr.used_file_size = ctx->output->offset;
	hdr.node_count = ctx->node_count;

	o_stream_seek(ctx->output, 0);
	o_stream_send(ctx->output, &hdr, sizeof(hdr));
}

int squat_trie_compress(struct squat_trie *trie,
			const ARRAY_TYPE(seq_range) *existing_uids)
{
	struct squat_trie_compress_context ctx;
	struct trie_node *node;
	struct file_lock *file_lock = NULL;
	unsigned int orig_lock_count;
	int ret;

	orig_lock_count = trie->lock_count;
	if (squat_trie_lock(trie, F_WRLCK) <= 0)
		return -1;

	if (squat_trie_compress_init(&ctx, trie) < 0) {
		squat_trie_unlock(trie);
		return -1;
	}

	ret = trie_map_node(trie, trie->hdr->root_offset, 1, &node);
	if (ret == 0) {
		/* do the compression */
		ctx.uidlist_ctx = squat_uidlist_compress_begin(trie->uidlist,
							       existing_uids);
		if ((ret = squat_trie_compress_node(&ctx, node, 1)) < 0)
			squat_uidlist_compress_rollback(&ctx.uidlist_ctx);
		else {
			ret = squat_uidlist_compress_commit(&ctx.uidlist_ctx);

			squat_trie_compress_write_header(&ctx, node);
		}
	}

	if (ret == 0 && orig_lock_count > 0) {
		/* lock the file before renaming so we can keep it locked. */
		if (squat_trie_file_lock(trie, ctx.fd, ctx.tmp_path, F_WRLCK,
					 &file_lock) <= 0)
			ret = -1;
	}

	if (ret == 0) {
		if (rename(ctx.tmp_path, trie->filepath) < 0) {
			i_error("rename(%s, %s) failed: %m",
				ctx.tmp_path, trie->filepath);
			ret = -1;
		}
	}

	o_stream_destroy(&ctx.output);
	squat_trie_unlock(trie);

	if (ret < 0) {
		if (file_lock != NULL)
			file_lock_free(&file_lock);
		(void)close(ctx.fd);
		(void)unlink(ctx.tmp_path);
	} else {
		trie_file_close(trie);
		trie_file_open_fd(trie, ctx.fd);

		trie->file_lock = file_lock;
		if (squat_trie_map(trie) <= 0)
			return -1;
	}
	return ret;
}

int squat_trie_mark_having_expunges(struct squat_trie *trie,
				    const ARRAY_TYPE(seq_range) *existing_uids,
				    unsigned int current_message_count)
{
	bool compress;
	int ret;

	if ((ret = squat_trie_lock(trie, F_RDLCK)) <= 0)
		return ret;
	compress = squat_trie_need_compress(trie, current_message_count);
	squat_trie_unlock(trie);

	ret = squat_uidlist_mark_having_expunges(trie->uidlist, compress);

	if (compress)
		ret = squat_trie_compress(trie, existing_uids);
	return ret;
}

size_t squat_trie_mem_used(struct squat_trie *trie, unsigned int *count_r)
{
	*count_r = trie->hdr == NULL ? 0 : trie->hdr->node_count;

	return trie->mmap_size;
}

static int squat_trie_lookup_init(struct squat_trie *trie, const char *str,
				  const uint16_t **data_r, unsigned int *len_r)
{
	const uint16_t *data;
	unsigned int len = strlen(str);

	if (len < BLOCK_SIZE)
		return -1;

	data = data_normalize(str, len, trie->buf);

	/* skip the blocks that can't exist */
	while (!block_want_add(data + len - BLOCK_SIZE)) {
		if (--len < BLOCK_SIZE)
			return -1;
	}

	if (squat_trie_lock(trie, F_RDLCK) <= 0)
		return -1;

	*data_r = data;
	*len_r = len;
	return 0;
}

static int
squat_trie_lookup_locked(struct squat_trie *trie, ARRAY_TYPE(seq_range) *result,
			 const uint16_t *data, unsigned int len)
{
	uint32_t list;

	list = trie_lookup_node(trie, trie->root, data + len - BLOCK_SIZE, 1);
	if (list == 0)
		return 0;

	if (squat_uidlist_get(trie->uidlist, list, result) < 0) {
		squat_trie_set_corrupted(trie, "uidlist offset broken");
		return -1;
	}
	while (len > BLOCK_SIZE) {
		len--;

		if (!block_want_add(data + len - BLOCK_SIZE))
			continue;

		list = trie_lookup_node(trie, trie->root,
					data + len - BLOCK_SIZE, 1);
		if (list == 0) {
			array_clear(result);
			return 0;
		}
		if (squat_uidlist_filter(trie->uidlist, list, result) < 0) {
			squat_trie_set_corrupted(trie, "uidlist offset broken");
			return -1;
		}
	}
	return array_count(result) > 0 ? 1 : 0;
}

int squat_trie_lookup(struct squat_trie *trie, ARRAY_TYPE(seq_range) *result,
		      const char *str)
{
	const uint16_t *data;
	unsigned int len;
	int ret;

	if (squat_trie_lookup_init(trie, str, &data, &len) < 0)
		return -1;

	ret = squat_trie_lookup_locked(trie, result, data, len);
	squat_trie_unlock(trie);
	return ret;
}

static int
squat_trie_filter_locked(struct squat_trie *trie, ARRAY_TYPE(seq_range) *result,
			 const uint16_t *data, unsigned int len)
{
	uint32_t list;

	for (; len >= BLOCK_SIZE; len--) {
		if (!block_want_add(data + len - BLOCK_SIZE))
			continue;

		list = trie_lookup_node(trie, trie->root,
					data + len - BLOCK_SIZE, 1);
		if (list == 0) {
			array_clear(result);
			return 0;
		}
		if (squat_uidlist_filter(trie->uidlist, list, result) < 0) {
			squat_trie_set_corrupted(trie, "uidlist offset broken");
			return -1;
		}
	}
	return array_count(result) > 0 ? 1 : 0;
}

int squat_trie_filter(struct squat_trie *trie, ARRAY_TYPE(seq_range) *result,
		      const char *str)
{
	const uint16_t *data;
	unsigned int len;
	int ret;

	if (squat_trie_lookup_init(trie, str, &data, &len) < 0)
		return -1;
	ret = squat_trie_filter_locked(trie, result, data, len);
	squat_trie_unlock(trie);
	return ret;
}

struct squat_uidlist *squat_trie_get_uidlist(struct squat_trie *trie)
{
	return trie->uidlist;
}
