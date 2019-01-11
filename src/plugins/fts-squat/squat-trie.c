/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "read-full.h"
#include "istream.h"
#include "ostream.h"
#include "unichar.h"
#include "nfs-workarounds.h"
#include "file-cache.h"
#include "seq-range-array.h"
#include "squat-uidlist.h"
#include "squat-trie-private.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#define DEFAULT_NORMALIZE_MAP_CHARS \
	"EOTIRSACDNLMVUGPHBFWYXKJQZ0123456789@.-+#$%_&"
#define DEFAULT_PARTIAL_LEN 4
#define DEFAULT_FULL_LEN 4

#define MAX_FAST_LEVEL 3
#define SEQUENTIAL_COUNT 46

#define TRIE_BYTES_LEFT(n) \
	((n) * SQUAT_PACK_MAX_SIZE)
#define TRIE_READAHEAD_SIZE \
	I_MAX(4096, 1 + 256 + TRIE_BYTES_LEFT(256))

struct squat_trie_build_context {
	struct squat_trie *trie;
	struct ostream *output;
	struct squat_uidlist_build_context *uidlist_build_ctx;

	struct file_lock *file_lock;
	struct dotlock *dotlock;

	uint32_t first_uid;
	bool compress_nodes:1;
};

struct squat_trie_iterate_node {
	struct squat_node *node;
	ARRAY_TYPE(seq_range) shifts;
	unsigned int idx;
};

struct squat_trie_iterate_context {
	struct squat_trie *trie;
	struct squat_trie_iterate_node cur;
	ARRAY(struct squat_trie_iterate_node) parents;
	bool failed;
};

static int squat_trie_map(struct squat_trie *trie, bool building);

void squat_trie_delete(struct squat_trie *trie)
{
	i_unlink_if_exists(trie->path);
	squat_uidlist_delete(trie->uidlist);
}

static void squat_trie_set_corrupted(struct squat_trie *trie)
{
	trie->corrupted = TRUE;
	i_error("Corrupted file %s", trie->path);
	squat_trie_delete(trie);
}

static void squat_trie_normalize_map_build(struct squat_trie *trie)
{
	static unsigned char valid_chars[] =
		DEFAULT_NORMALIZE_MAP_CHARS;
	unsigned int i, j;

	memset(trie->default_normalize_map, 0,
	       sizeof(trie->default_normalize_map));

#if 1
	for (i = 0, j = 1; i < sizeof(valid_chars)-1; i++) {
		unsigned char chr = valid_chars[i];

		if (chr >= 'A' && chr <= 'Z')
			trie->default_normalize_map[chr-'A'+'a'] = j;
		trie->default_normalize_map[chr] = j++;
	}
	i_assert(j <= SEQUENTIAL_COUNT);

	for (i = 128; i < 256; i++)
		trie->default_normalize_map[i] = j++;
#else
	for (i = 0; i < sizeof(valid_chars)-1; i++) {
		unsigned char chr = valid_chars[i];

		if (chr >= 'A' && chr <= 'Z')
			trie->default_normalize_map[chr-'A'+'a'] = chr;
		trie->default_normalize_map[chr] = chr;
	}
	for (i = 128; i < 256; i++)
		trie->default_normalize_map[i] = i_toupper(i);
#endif
}

static void node_free(struct squat_trie *trie, struct squat_node *node)
{
	struct squat_node *children;
	unsigned int i;

	if (node->leaf_string_length > 0) {
		if (NODE_IS_DYNAMIC_LEAF(node))
			i_free(node->children.leaf_string);
	} else if (!node->children_not_mapped) {
		children = NODE_CHILDREN_NODES(node);

		trie->node_alloc_size -=
			NODE_CHILDREN_ALLOC_SIZE(node->child_count);
		for (i = 0; i < node->child_count; i++)
			node_free(trie, &children[i]);

		i_free(node->children.data);
	}
}

struct squat_trie *
squat_trie_init(const char *path, uint32_t uidvalidity,
		enum file_lock_method lock_method, enum squat_index_flags flags,
		mode_t mode, gid_t gid)
{
	struct squat_trie *trie;

	trie = i_new(struct squat_trie, 1);
	trie->path = i_strdup(path);
	trie->uidlist = squat_uidlist_init(trie);
	trie->fd = -1;
	trie->lock_method = lock_method;
	trie->uidvalidity = uidvalidity;
	trie->flags = flags;
	trie->create_mode = mode;
	trie->create_gid = gid;
	squat_trie_normalize_map_build(trie);

	trie->dotlock_set.use_excl_lock =
		(flags & SQUAT_INDEX_FLAG_DOTLOCK_USE_EXCL) != 0;
	trie->dotlock_set.nfs_flush = (flags & SQUAT_INDEX_FLAG_NFS_FLUSH) != 0;
	trie->dotlock_set.timeout = SQUAT_TRIE_LOCK_TIMEOUT;
	trie->dotlock_set.stale_timeout = SQUAT_TRIE_DOTLOCK_STALE_TIMEOUT;
	trie->default_partial_len = DEFAULT_PARTIAL_LEN;
	trie->default_full_len = DEFAULT_FULL_LEN;
	return trie;
}

static void squat_trie_close_fd(struct squat_trie *trie)
{
	trie->data = NULL;
	trie->data_size = 0;

	if (trie->mmap_size != 0) {
		if (munmap(trie->mmap_base, trie->mmap_size) < 0)
			i_error("munmap(%s) failed: %m", trie->path);
		trie->mmap_base = NULL;
		trie->mmap_size = 0;
	}
	i_close_fd_path(&trie->fd, trie->path);
}

static void squat_trie_close(struct squat_trie *trie)
{
	trie->corrupted = FALSE;
	node_free(trie, &trie->root);
	i_zero(&trie->root);
	i_zero(&trie->hdr);

	squat_trie_close_fd(trie);
	if (trie->file_cache != NULL)
		file_cache_free(&trie->file_cache);
	trie->locked_file_size = 0;
}

void squat_trie_deinit(struct squat_trie **_trie)
{
	struct squat_trie *trie = *_trie;

	*_trie = NULL;
	squat_trie_close(trie);
	squat_uidlist_deinit(trie->uidlist);
	i_free(trie->path);
	i_free(trie);
}

void squat_trie_set_partial_len(struct squat_trie *trie, unsigned int len)
{
	trie->default_partial_len = len;
}

void squat_trie_set_full_len(struct squat_trie *trie, unsigned int len)
{
	trie->default_full_len = len;
}

static void squat_trie_header_init(struct squat_trie *trie)
{
	i_zero(&trie->hdr);
	trie->hdr.version = SQUAT_TRIE_VERSION;
	trie->hdr.indexid = time(NULL);
	trie->hdr.uidvalidity = trie->uidvalidity;
	trie->hdr.partial_len = trie->default_partial_len;
	trie->hdr.full_len = trie->default_full_len;

	i_assert(sizeof(trie->hdr.normalize_map) ==
		 sizeof(trie->default_normalize_map));
	memcpy(trie->hdr.normalize_map, trie->default_normalize_map,
	       sizeof(trie->hdr.normalize_map));
}

static int squat_trie_open_fd(struct squat_trie *trie)
{
	trie->fd = open(trie->path, O_RDWR);
	if (trie->fd == -1) {
		if (errno == ENOENT) {
			squat_trie_header_init(trie);
			return 0;
		}
		i_error("open(%s) failed: %m", trie->path);
		return -1;
	}
	if (trie->file_cache != NULL)
		file_cache_set_fd(trie->file_cache, trie->fd);
	return 0;
}

int squat_trie_open(struct squat_trie *trie)
{
	squat_trie_close(trie);

	if (squat_trie_open_fd(trie) < 0)
		return -1;
	return squat_trie_map(trie, FALSE);
}

static int squat_trie_is_file_stale(struct squat_trie *trie)
{
	struct stat st, st2;

	if ((trie->flags & SQUAT_INDEX_FLAG_NFS_FLUSH) != 0)
		nfs_flush_file_handle_cache(trie->path);
	if (nfs_safe_stat(trie->path, &st) < 0) {
		if (errno == ENOENT)
			return 1;

		i_error("stat(%s) failed: %m", trie->path);
		return -1;
	}
	if (fstat(trie->fd, &st2) < 0) {
		if (errno == ESTALE)
			return 1;
		i_error("fstat(%s) failed: %m", trie->path);
		return -1;
	}
	trie->locked_file_size = st2.st_size;

	if (st.st_ino == st2.st_ino && CMP_DEV_T(st.st_dev, st2.st_dev)) {
		i_assert(trie->locked_file_size >= trie->data_size);
		return 0;
	}
	return 1;
}

int squat_trie_refresh(struct squat_trie *trie)
{
	int ret;

	ret = squat_trie_is_file_stale(trie);
	if (ret > 0)
		ret = squat_trie_open(trie);
	return ret;
}

static int squat_trie_lock(struct squat_trie *trie, int lock_type,
			   struct file_lock **file_lock_r,
			   struct dotlock **dotlock_r)
{
	int ret;

	i_assert(trie->fd != -1);

	*file_lock_r = NULL;
	*dotlock_r = NULL;

	for (;;) {
		if (trie->lock_method != FILE_LOCK_METHOD_DOTLOCK) {
			ret = file_wait_lock(trie->fd, trie->path, lock_type,
					     trie->lock_method,
					     SQUAT_TRIE_LOCK_TIMEOUT,
					     file_lock_r);
		} else {
			ret = file_dotlock_create(&trie->dotlock_set,
						  trie->path, 0, dotlock_r);
		}
		if (ret == 0) {
			i_error("squat trie %s: Locking timed out", trie->path);
			return 0;
		}
		if (ret < 0)
			return -1;

		/* if the trie has been compressed, we need to reopen the
		   file and try to lock again */
		ret = squat_trie_is_file_stale(trie);
		if (ret == 0)
			break;

		if (*file_lock_r != NULL)
			file_unlock(file_lock_r);
		else
			file_dotlock_delete(dotlock_r);
		if (ret < 0)
			return -1;

		squat_trie_close(trie);
		if (squat_trie_open_fd(trie) < 0)
			return -1;
		if (trie->fd == -1)
			return 0;
	}

	if ((trie->flags & SQUAT_INDEX_FLAG_NFS_FLUSH) != 0)
		nfs_flush_read_cache_locked(trie->path, trie->fd);
	return 1;
}

static void
node_make_sequential(struct squat_trie *trie, struct squat_node *node, int level)
{
	const unsigned int alloc_size =
		NODE_CHILDREN_ALLOC_SIZE(SEQUENTIAL_COUNT);
	struct squat_node *children;
	unsigned char *chars;
	unsigned int i;

	i_assert(node->child_count == 0);

	trie->node_alloc_size += alloc_size;

	node->want_sequential = FALSE;
	node->have_sequential = TRUE;

	node->child_count = SEQUENTIAL_COUNT;
	node->children.data = i_malloc(alloc_size);

	chars = NODE_CHILDREN_CHARS(node);
	for (i = 0; i < SEQUENTIAL_COUNT; i++)
		chars[i] = i;

	if (level < MAX_FAST_LEVEL) {
		children = NODE_CHILDREN_NODES(node);
		for (i = 0; i < SEQUENTIAL_COUNT; i++)
			children[i].want_sequential = TRUE;
	}
}

static unsigned int
node_add_child(struct squat_trie *trie, struct squat_node *node,
	       unsigned char chr, int level)
{
	unsigned int old_child_count = node->child_count;
	struct squat_node *children, *old_children;
	unsigned char *chars;
	size_t old_size, new_size;

	i_assert(node->leaf_string_length == 0);

	if (node->want_sequential) {
		node_make_sequential(trie, node, level);

		if (chr < SEQUENTIAL_COUNT)
			return chr;
		old_child_count = SEQUENTIAL_COUNT;
	}

	node->child_count++;
	new_size = NODE_CHILDREN_ALLOC_SIZE(node->child_count);

	if (old_child_count == 0) {
		/* first child */
		node->children.data = i_malloc(new_size);
		trie->node_alloc_size += new_size;
	} else {
		old_size = NODE_CHILDREN_ALLOC_SIZE(old_child_count);
		if (old_size != new_size) {
			trie->node_alloc_size += new_size - old_size;
			node->children.data = i_realloc(node->children.data,
							old_size, new_size);
		}

		children = NODE_CHILDREN_NODES(node);
		old_children = (void *)(NODE_CHILDREN_CHARS(node) +
					MEM_ALIGN(old_child_count));
		if (children != old_children) {
			memmove(children, old_children,
				old_child_count * sizeof(struct squat_node));
		}
	}

	chars = NODE_CHILDREN_CHARS(node);
	i_assert(chars != NULL);
	chars[node->child_count - 1] = chr;
	return node->child_count - 1;
}

static int
trie_file_cache_read(struct squat_trie *trie, size_t offset, size_t size)
{
	if (trie->file_cache == NULL)
		return 0;

	if (file_cache_read(trie->file_cache, offset, size) < 0) {
		i_error("read(%s) failed: %m", trie->path);
		return -1;
	}
	trie->data = file_cache_get_map(trie->file_cache, &trie->data_size);
	return 0;
}

static int
node_read_children(struct squat_trie *trie, struct squat_node *node, int level)
{
	const uint8_t *data, *end;
	const unsigned char *child_chars;
	struct squat_node *child, *children = NULL;
	uoff_t node_offset;
	unsigned int i, child_idx, child_count;
	uoff_t base_offset;
	uint32_t num;

	i_assert(node->children_not_mapped);
	i_assert(!node->have_sequential);
	i_assert(trie->unmapped_child_count > 0);
	i_assert(trie->data_size <= trie->locked_file_size);

	trie->unmapped_child_count--;
	node_offset = node->children.offset;
	node->children_not_mapped = FALSE;
	node->children.data = NULL;

	if (trie_file_cache_read(trie, node_offset, TRIE_READAHEAD_SIZE) < 0)
		return -1;
	if (unlikely(node_offset >= trie->data_size)) {
		squat_trie_set_corrupted(trie);
		return -1;
	}

	data = CONST_PTR_OFFSET(trie->data, node_offset);
	end = CONST_PTR_OFFSET(trie->data, trie->data_size);
	child_count = *data++;
	if (unlikely(node_offset + child_count >= trie->data_size)) {
		squat_trie_set_corrupted(trie);
		return -1;
	}

	if (child_count == 0)
		return 0;

	child_chars = data;
	data += child_count;

	/* get child offsets */
	base_offset = node_offset;
	for (i = 0; i < child_count; i++) {
		/* we always start with !have_sequential, so at i=0 this
		   check always goes to add the first child */
		if (node->have_sequential && child_chars[i] < SEQUENTIAL_COUNT)
			child_idx = child_chars[i];
		else {
			child_idx = node_add_child(trie, node, child_chars[i],
						   level);
			children = NODE_CHILDREN_NODES(node);
		}

		i_assert(children != NULL);

		child = &children[child_idx];

		/* 1) child offset */
		num = squat_unpack_num(&data, end);
		if (num == 0) {
			/* no children */
		} else {
			if ((num & 1) != 0) {
				base_offset += num >> 1;
			} else {
				base_offset -= num >> 1;
			}
			if (base_offset >= trie->locked_file_size) {
				squat_trie_set_corrupted(trie);
				return -1;
			}
			trie->unmapped_child_count++;
			child->children_not_mapped = TRUE;
			child->children.offset = base_offset;
		}

		/* 2) uidlist */
		child->uid_list_idx = squat_unpack_num(&data, end);
		if (child->uid_list_idx == 0) {
			/* we don't write nodes with empty uidlists */
			squat_trie_set_corrupted(trie);
			return -1;
		}
		if (!UIDLIST_IS_SINGLETON(child->uid_list_idx)) {
			/* 3) next uid */
			child->next_uid = squat_unpack_num(&data, end) + 1;
		} else {
			uint32_t idx = child->uid_list_idx;

			child->next_uid = 1 +
				squat_uidlist_singleton_last_uid(idx);
		}

		/* 4) unused uids + leaf string flag */
		num = squat_unpack_num(&data, end);
		child->unused_uids = num >> 1;
		if ((num & 1) != 0) {
			/* leaf string */
			unsigned int len;
			unsigned char *dest;

			/* 5) leaf string length */
			len = child->leaf_string_length =
				squat_unpack_num(&data, end) + 1;
			if (!NODE_IS_DYNAMIC_LEAF(child))
				dest = child->children.static_leaf_string;
			else {
				dest = child->children.leaf_string =
					i_malloc(len);
			}

			if (trie->file_cache != NULL) {
				/* the string may be long -
				   recalculate the end pos */
				size_t offset, size;

				offset = (const char *)data -
					(const char *)trie->data;
				size = len + TRIE_BYTES_LEFT(child_count - i);

				if (trie_file_cache_read(trie, offset,
							 size) < 0)
					return -1;
				data = CONST_PTR_OFFSET(trie->data, offset);
				end = CONST_PTR_OFFSET(trie->data,
						       trie->data_size);
				child_chars = CONST_PTR_OFFSET(trie->data,
							       node_offset + 1);
			}

			if ((size_t)(end - data) < len) {
				squat_trie_set_corrupted(trie);
				return -1;
			}
			memcpy(dest, data, len);
			data += len;
		}
	}
	if (unlikely(data == end)) {
		/* we should never get this far */
		squat_trie_set_corrupted(trie);
		return -1;
	}
	return 0;
}

static void
node_write_children(struct squat_trie_build_context *ctx,
		    struct squat_node *node, const uoff_t *node_offsets)
{
	struct squat_node *children;
	const unsigned char *chars;
	uint8_t child_count, buf[SQUAT_PACK_MAX_SIZE * 5], *bufp;
	uoff_t base_offset;
	unsigned int i;

	chars = NODE_CHILDREN_CHARS(node);
	children = NODE_CHILDREN_NODES(node);

	base_offset = ctx->output->offset;
	child_count = node->child_count;
	o_stream_nsend(ctx->output, &child_count, 1);
	o_stream_nsend(ctx->output, chars, child_count);

	for (i = 0; i < child_count; i++) {
		bufp = buf;
		/* 1) child offset */
		if (node_offsets[i] == 0)
			*bufp++ = 0;
		else if (node_offsets[i] >= base_offset) {
			squat_pack_num(&bufp,
				((node_offsets[i] - base_offset) << 1) | 1);
			base_offset = node_offsets[i];
		} else {
			squat_pack_num(&bufp,
				       (base_offset - node_offsets[i]) << 1);
			base_offset = node_offsets[i];
		}

		/* 2) uidlist */
		squat_pack_num(&bufp, children[i].uid_list_idx);
		if (!UIDLIST_IS_SINGLETON(children[i].uid_list_idx)) {
			/* 3) next uid */
			squat_pack_num(&bufp, children[i].next_uid - 1);
		}

		if (children[i].leaf_string_length == 0) {
			/* 4a) unused uids */
			squat_pack_num(&bufp, children[i].unused_uids << 1);
			o_stream_nsend(ctx->output, buf, bufp - buf);
		} else {
			i_assert(node_offsets[i] == 0);
			/* 4b) unused uids + flag */
			squat_pack_num(&bufp, (children[i].unused_uids << 1) | 1);
			/* 5) leaf string length */
			squat_pack_num(&bufp, children[i].leaf_string_length - 1);
			o_stream_nsend(ctx->output, buf, bufp - buf);
			o_stream_nsend(ctx->output,
				       NODE_LEAF_STRING(&children[i]),
				       children[i].leaf_string_length);
		}
	}
}

static inline void
node_add_uid(struct squat_trie_build_context *ctx, uint32_t uid,
	     struct squat_node *node)
{
	if (uid < node->next_uid) {
		/* duplicate */
		return;
	}
	node->unused_uids += uid - node->next_uid;
	node->next_uid = uid + 1;

	node->uid_list_idx =
		squat_uidlist_build_add_uid(ctx->uidlist_build_ctx,
					    node->uid_list_idx, uid);
}

static void
node_split_string(struct squat_trie_build_context *ctx, struct squat_node *node)
{
	struct squat_node *child;
	unsigned char *str;
	unsigned int uid, idx, leafstr_len = node->leaf_string_length;

	i_assert(leafstr_len > 0);

	/* make a copy of the leaf string and convert to normal node by
	   removing it. */
	str = t_malloc_no0(leafstr_len);
	if (!NODE_IS_DYNAMIC_LEAF(node))
		memcpy(str, node->children.static_leaf_string, leafstr_len);
	else {
		memcpy(str, node->children.leaf_string, leafstr_len);
		i_free(node->children.leaf_string);
	}
	node->leaf_string_length = 0;

	/* create a new child node for the rest of the string */
	idx = node_add_child(ctx->trie, node, str[0], MAX_FAST_LEVEL);
	child = NODE_CHILDREN_NODES(node) + idx;

	/* update uidlist to contain all of parent's UIDs */
	child->next_uid =  node->next_uid - node->unused_uids;
	for (uid = 0; uid < child->next_uid; uid++) {
		child->uid_list_idx =
			squat_uidlist_build_add_uid(ctx->uidlist_build_ctx,
						    child->uid_list_idx, uid);
	}

	i_assert(!child->have_sequential && child->children.data == NULL);
	if (leafstr_len > 1) {
		/* make the child a leaf string */
		leafstr_len--;
		child->leaf_string_length = leafstr_len;
		if (!NODE_IS_DYNAMIC_LEAF(child)) {
			memcpy(child->children.static_leaf_string,
			       str + 1, leafstr_len);
		} else {
			child->children.leaf_string = i_malloc(leafstr_len);
			memcpy(child->children.leaf_string,
			       str + 1, leafstr_len);
		}
	}
}

static bool
node_leaf_string_add_or_split(struct squat_trie_build_context *ctx,
			      struct squat_node *node,
			      const unsigned char *data, unsigned int data_len)
{
	const unsigned char *str = NODE_LEAF_STRING(node);
	const unsigned int leafstr_len = node->leaf_string_length;
	unsigned int i;

	if (data_len != leafstr_len) {
		/* different lengths, can't match */
		T_BEGIN {
			node_split_string(ctx, node);
		} T_END;
		return FALSE;
	}

	for (i = 0; i < data_len; i++) {
		if (data[i] != str[i]) {
			/* non-match */
			T_BEGIN {
				node_split_string(ctx, node);
			} T_END;
			return FALSE;
		}
	}
	return TRUE;
}

static int squat_build_add(struct squat_trie_build_context *ctx, uint32_t uid,
			   const unsigned char *data, unsigned int size)
{
	struct squat_trie *trie = ctx->trie;
	struct squat_node *node = &trie->root;
	const unsigned char *end = data + size;
	unsigned char *chars;
	unsigned int idx;
	int level = 0;

	for (;;) {
		if (node->children_not_mapped) {
			if (unlikely(node_read_children(trie, node, level) < 0))
				return -1;
		}

		if (node->leaf_string_length != 0) {
			/* the whole string must match or we need to split
			   the node */
			if (node_leaf_string_add_or_split(ctx, node, data,
							  end - data)) {
				node_add_uid(ctx, uid, node);
				return 0;
			}
		}

		node_add_uid(ctx, uid, node);

		if (unlikely(uid < node->unused_uids)) {
			squat_trie_set_corrupted(trie);
			return -1;
		}
		/* child node's UIDs are relative to ours. so for example if
		   we're adding UID 4 and this node now has [2,4] UIDs,
		   unused_uids=3 and so the child node will be adding
		   UID 4-3 = 1. */
		uid -= node->unused_uids;

		if (data == end)
			return 0;
		level++;

		if (node->have_sequential) {
			i_assert(node->child_count >= SEQUENTIAL_COUNT);
			if (*data < SEQUENTIAL_COUNT) {
				idx = *data;
				goto found;
			}
			idx = SEQUENTIAL_COUNT;
		} else {
			idx = 0;
		}
		chars = NODE_CHILDREN_CHARS(node);
		for (; idx < node->child_count; idx++) {
			if (chars[idx] == *data)
				goto found;
		}
		break;
	found:
		data++;
		node = NODE_CHILDREN_NODES(node) + idx;
	}

	/* create new children */
	i_assert(node->leaf_string_length == 0);

	for (;;) {
		idx = node_add_child(trie, node, *data,
				     size - (end - data) + 1);
		node = NODE_CHILDREN_NODES(node) + idx;

		node_add_uid(ctx, uid, node);
		uid = 0;

		if (++data == end)
			break;

		if (!node->have_sequential) {
			/* convert the node into a leaf string */
			unsigned int len = end - data;

			i_assert(node->children.data == NULL);
			node->leaf_string_length = len;
			if (!NODE_IS_DYNAMIC_LEAF(node)) {
				memcpy(node->children.static_leaf_string,
				       data, len);
			} else {
				node->children.leaf_string = i_malloc(len);
				memcpy(node->children.leaf_string, data, len);
			}
			break;
		}
	}
	return 0;
}

static int
squat_build_word_bytes(struct squat_trie_build_context *ctx, uint32_t uid,
		       const unsigned char *data, unsigned int size)
{
	struct squat_trie *trie = ctx->trie;
	unsigned int i;

	if (trie->hdr.full_len <= trie->hdr.partial_len)
		i = 0;
	else {
		/* the first word is longer than others */
		if (squat_build_add(ctx, uid, data,
				    I_MIN(size, trie->hdr.full_len)) < 0)
			return -1;
		i = 1;
	}

	for (; i < size; i++) {
		if (squat_build_add(ctx, uid, data + i,
				    I_MIN(trie->hdr.partial_len, size-i)) < 0)
			return -1;
	}
	return 0;
}

static int
squat_build_word(struct squat_trie_build_context *ctx, uint32_t uid,
		 const unsigned char *data, const uint8_t *char_lengths,
		 unsigned int size)
{
	struct squat_trie *trie = ctx->trie;
	unsigned int i, j, bytelen;

	if (char_lengths == NULL) {
		/* optimization path: all characters are bytes */
		return squat_build_word_bytes(ctx, uid, data, size);
	}

	if (trie->hdr.full_len <= trie->hdr.partial_len)
		i = 0;
	else {
		/* the first word is longer than others */
		bytelen = 0;
		for (j = 0; j < trie->hdr.full_len && bytelen < size; j++)
			bytelen += char_lengths[bytelen];
		i_assert(bytelen <= size);

		if (squat_build_add(ctx, uid, data, bytelen) < 0)
			return -1;
		i = char_lengths[0];
	}

	for (; i < size; i += char_lengths[i]) {
		bytelen = 0;
		for (j = 0; j < trie->hdr.partial_len && i+bytelen < size; j++)
			bytelen += char_lengths[i + bytelen];
		i_assert(i + bytelen <= size);

		if (squat_build_add(ctx, uid, data + i, bytelen) < 0)
			return -1;
	}
	return 0;
}

static unsigned char *
squat_data_normalize(struct squat_trie *trie, const unsigned char *data,
		     unsigned int size)
{
	static const unsigned char replacement_utf8[] = { 0xef, 0xbf, 0xbd };
	unsigned char *dest;
	unsigned int i;

	dest = t_malloc_no0(size);
	for (i = 0; i < size; i++) {
		if (data[i] == replacement_utf8[0] && i + 2 < size &&
		    data[i+1] == replacement_utf8[1] &&
		    data[i+2] == replacement_utf8[2]) {
			/* Don't index replacement character */
			dest[i++] = 0;
			dest[i++] = 0;
			dest[i] = 0;
		} else {
			dest[i] = trie->hdr.normalize_map[data[i]];
		}
	}
	return dest;
}

static int
squat_trie_build_more_real(struct squat_trie_build_context *ctx,
			   uint32_t uid, enum squat_index_type type,
			   const unsigned char *input, unsigned int size)
{
	struct squat_trie *trie = ctx->trie;
	const unsigned char *data;
	uint8_t *char_lengths;
	unsigned int i, start = 0;
	bool multibyte_chars = FALSE;
	int ret = 0;

	uid = uid * 2 + (type == SQUAT_INDEX_TYPE_HEADER ? 1 : 0);

	char_lengths = t_malloc_no0(size);
	data = squat_data_normalize(trie, input, size);
	for (i = 0; i < size; i++) {
		char_lengths[i] = uni_utf8_char_bytes(input[i]);
		if (char_lengths[i] != 1)
			multibyte_chars = TRUE;
		if (data[i] != '\0')
			continue;

		while (start < i && data[start] == '\0')
			start++;
		if (i != start) {
			if (squat_build_word(ctx, uid, data + start,
					     !multibyte_chars ? NULL :
					     char_lengths + start,
					     i - start) < 0) {
				ret = -1;
				start = i;
				break;
			}
		}
		start = i + 1;
	}
	while (start < i && data[start] == '\0')
		start++;
	if (i != start) {
		if (squat_build_word(ctx, uid, data + start,
				     !multibyte_chars ? NULL :
				     char_lengths + start, i - start) < 0)
			ret = -1;
	}
	return ret;
}

int squat_trie_build_more(struct squat_trie_build_context *ctx,
			  uint32_t uid, enum squat_index_type type,
			  const unsigned char *input, unsigned int size)
{
	int ret = 0;

	if (size != 0) T_BEGIN {
		ret = squat_trie_build_more_real(ctx, uid, type, input, size);
	} T_END;
	return ret;
}

static void
node_drop_unused_children(struct squat_trie *trie, struct squat_node *node)
{
	unsigned char *chars;
	struct squat_node *children_src, *children_dest;
	unsigned int i, j, orig_child_count = node->child_count;

	chars = NODE_CHILDREN_CHARS(node);
	children_src = NODE_CHILDREN_NODES(node);

	/* move chars */
	for (i = j = 0; i < orig_child_count; i++) {
		if (children_src[i].next_uid != 0)
			chars[j++] = chars[i];
	}
	node->child_count = j;

	/* move children. note that children_dest may point to different
	   location than children_src, although they both point to the
	   same node. */
	children_dest = NODE_CHILDREN_NODES(node);
	for (i = j = 0; i < orig_child_count; i++) {
		if (children_src[i].next_uid != 0)
			children_dest[j++] = children_src[i];
		else
			node_free(trie, &children_src[i]);
	}
}

static int
squat_write_node(struct squat_trie_build_context *ctx, struct squat_node *node,
		 uoff_t *node_offset_r, int level)
{
	struct squat_trie *trie = ctx->trie;
	struct squat_node *children;
	unsigned int i;
	uoff_t *node_offsets;
	uint8_t child_count;
	int ret;

	i_assert(node->next_uid != 0);

	if (node->children_not_mapped && ctx->compress_nodes) {
		if (node_read_children(trie, node, MAX_FAST_LEVEL) < 0)
			return -1;
	}

	node->have_sequential = FALSE;
	node_drop_unused_children(trie, node);

	child_count = node->child_count;
	if (child_count == 0) {
		i_assert(!node->children_not_mapped ||
			 node->leaf_string_length == 0);
		*node_offset_r = !node->children_not_mapped ? 0 :
			node->children.offset;
		return 0;
	}
	i_assert(!node->children_not_mapped);

	trie->hdr.node_count++;

	children = NODE_CHILDREN_NODES(node);
	node_offsets = t_new(uoff_t, child_count);
	for (i = 0; i < child_count; i++) {
		T_BEGIN {
			ret = squat_write_node(ctx, &children[i],
					       &node_offsets[i], level + 1);
		} T_END;
		if (ret < 0)
			return -1;
	}

	*node_offset_r = ctx->output->offset;
	node_write_children(ctx, node, node_offsets);
	return 0;
}

static int squat_write_nodes(struct squat_trie_build_context *ctx)
{
	struct squat_trie *trie = ctx->trie;
	uoff_t node_offset;
	int ret;

	if (ctx->trie->root.next_uid == 0)
		return 0;

	T_BEGIN {
		ret = squat_write_node(ctx, &ctx->trie->root, &node_offset, 0);
	} T_END;
	if (ret < 0)
		return -1;

	trie->hdr.root_offset = node_offset;
	trie->hdr.root_unused_uids = trie->root.unused_uids;
	trie->hdr.root_next_uid = trie->root.next_uid;
	trie->hdr.root_uidlist_idx = trie->root.uid_list_idx;
	return 0;
}

static struct squat_trie_iterate_context *
squat_trie_iterate_init(struct squat_trie *trie)
{
	struct squat_trie_iterate_context *ctx;

	ctx = i_new(struct squat_trie_iterate_context, 1);
	ctx->trie = trie;
	ctx->cur.node = &trie->root;
	i_array_init(&ctx->parents, trie->hdr.partial_len*2);
	return ctx;
}

static int
squat_trie_iterate_deinit(struct squat_trie_iterate_context *ctx)
{
	struct squat_trie_iterate_node *node;
	int ret = ctx->failed ? -1 : 0;

	if (array_is_created(&ctx->cur.shifts)) {
		array_foreach_modifiable(&ctx->parents, node)
			array_free(&node->shifts);
		array_free(&ctx->cur.shifts);
	}
	array_free(&ctx->parents);
	i_free(ctx);
	return ret;
}

static struct squat_node *
squat_trie_iterate_first(struct squat_trie_iterate_context *ctx)
{
	if (ctx->cur.node->children_not_mapped) {
		if (node_read_children(ctx->trie, ctx->cur.node, 1) < 0) {
			ctx->failed = TRUE;
			return NULL;
		}
	}
	return ctx->cur.node;
}

static struct squat_node *
squat_trie_iterate_next(struct squat_trie_iterate_context *ctx,
			ARRAY_TYPE(seq_range) *shifts_r)
{
	struct squat_trie_iterate_node *iter_nodes;
	struct squat_node *children;
	unsigned int count, shift_count = 0;

	while (ctx->cur.idx == ctx->cur.node->child_count ||
	       ctx->cur.node->uid_list_idx == 0)
	{
		iter_nodes = array_get_modifiable(&ctx->parents, &count);
		if (count == 0)
			return NULL;

		if (array_is_created(&ctx->cur.shifts))
			array_free(&ctx->cur.shifts);
		ctx->cur = iter_nodes[count-1];
		array_delete(&ctx->parents, count-1, 1);
	}

	*shifts_r = ctx->cur.shifts;
	if (array_is_created(&ctx->cur.shifts))
		shift_count = array_count(&ctx->cur.shifts);

	children = NODE_CHILDREN_NODES(ctx->cur.node);
	while (children[ctx->cur.idx++].uid_list_idx == 0) {
		if (ctx->cur.idx == ctx->cur.node->child_count) {
			/* no more non-empty children in this node */
			return squat_trie_iterate_next(ctx, shifts_r);
		}
	}
	array_push_back(&ctx->parents, &ctx->cur);
	ctx->cur.node = &children[ctx->cur.idx-1];
	ctx->cur.idx = 0;
	if (shift_count != 0)
		i_array_init(&ctx->cur.shifts, shift_count);
	else
		i_zero(&ctx->cur.shifts);
	return squat_trie_iterate_first(ctx);
}

static void
squat_uidlist_update_expunged_uids(const ARRAY_TYPE(seq_range) *shifts_arr,
				   ARRAY_TYPE(seq_range) *child_shifts,
				   ARRAY_TYPE(seq_range) *uids_arr,
				   struct squat_trie *trie,
				   struct squat_node *node, bool do_shifts)
{
	const struct seq_range *shifts;
	struct seq_range *uids, shift;
	unsigned int i, uid_idx, uid_count, shift_count;
	uint32_t child_shift_seq1, child_shift_count, seq_high;
	unsigned int shift_sum = 0, child_sum = 0;

	if (!array_is_created(shifts_arr)) {
		i_assert(node->uid_list_idx != 0 || node->child_count == 0);
		return;
	}

	/* we'll recalculate this */
	node->unused_uids = 0;

	uids = array_get_modifiable(uids_arr, &uid_count);
	shifts = array_get(shifts_arr, &shift_count);
	for (i = 0, uid_idx = 0, seq_high = 0;; ) {
		/* skip UID ranges until we skip/overlap shifts */
		while (uid_idx < uid_count &&
		       (i == shift_count ||
			I_MAX(shifts[i].seq1, seq_high) > uids[uid_idx].seq2))
		{
			i_assert(uids[uid_idx].seq1 >= shift_sum);
			uids[uid_idx].seq1 -= shift_sum;
			uids[uid_idx].seq2 -= shift_sum;
			child_sum += uids[uid_idx].seq2 -
				uids[uid_idx].seq1 + 1;

			if (uid_idx > 0 &&
			    uids[uid_idx-1].seq2 >= uids[uid_idx].seq1 - 1) {
				/* we can merge this and the previous range */
				i_assert(uids[uid_idx-1].seq2 ==
					 uids[uid_idx].seq1 - 1);
				uids[uid_idx-1].seq2 = uids[uid_idx].seq2;
				array_delete(uids_arr, uid_idx, 1);
				uids = array_get_modifiable(uids_arr,
							    &uid_count);
			} else {
				if (uid_idx == 0)
					node->unused_uids += uids[0].seq1;
				else {
					node->unused_uids +=
						uids[uid_idx].seq1 -
						uids[uid_idx-1].seq2 - 1;
				}
				uid_idx++;
			}
		}
		if (uid_idx == uid_count)
			break;

		shift.seq1 = I_MAX(shifts[i].seq1, seq_high);
		shift.seq2 = shifts[i].seq2;
		if (shift.seq2 < uids[uid_idx].seq1) {
			/* shift is entirely before UID range */
			shift_sum += shift.seq2 - shift.seq1 + 1;
			i++;
		} else {
			/* handle shifts before UID range */
			if (shift.seq1 < uids[uid_idx].seq1) {
				shift_sum += uids[uid_idx].seq1 - shift.seq1;
				shift.seq1 = uids[uid_idx].seq1;
			}
			/* update child shifts */
			child_shift_seq1 = child_sum +
				shift.seq1 - uids[uid_idx].seq1;
			child_shift_count =
				I_MIN(shift.seq2, uids[uid_idx].seq2) -
				shift.seq1 + 1;
			seq_range_array_add_range(child_shifts,
						  child_shift_seq1,
						  child_shift_seq1 +
						  child_shift_count - 1);
			child_sum += child_shift_count;

			/* if the shifts continue after the UID range,
			   treat it in the next loop iteration */
			if (shift.seq2 <= uids[uid_idx].seq2)
				i++;
			else
				seq_high = uids[uid_idx].seq2 + 1;

			/* update UIDs - no matter where within the UID range
			   the shifts happened, the result is the same:
			   shift number of UIDs are removed, and the rest
			   are decreased by shift_sum.

			      123     uids child_shifts
			   a) s    -> 12   1
			   b)  s   -> 12   2
			   c)   s  -> 12   3
			*/
			if (uids[uid_idx].seq1 +
			    child_shift_count > uids[uid_idx].seq2) {
				/* removed completely */
				array_delete(uids_arr, uid_idx, 1);
				uids = array_get_modifiable(uids_arr,
							    &uid_count);
			} else if (do_shifts) {
				/* the next loop iteration fixes the UIDs */
				uids[uid_idx].seq1 += child_shift_count;
			} else {
				seq_range_array_remove_range(uids_arr,
					shift.seq1,
					I_MIN(shift.seq2, uids[uid_idx].seq2));
				uids = array_get_modifiable(uids_arr,
							    &uid_count);
			}
			shift_sum += child_shift_count;
		}
		if (!do_shifts) {
			/* root node - UIDs are only removed, not shifted */
			shift_sum = 0;
		}
	}

	if (uid_count == 0) {
		/* no UIDs left, delete the node's children and mark it
		   unused */
		if (!NODE_IS_DYNAMIC_LEAF(node))
			node_free(trie, node);

		node->child_count = 0;
		node->have_sequential = FALSE;
		node->next_uid = 0;
	} else {
		if (do_shifts)
			node->next_uid = uids[uid_count-1].seq2 + 1;
		else {
			node->unused_uids += (node->next_uid - 1) -
				uids[uid_count-1].seq2;
		}
	}
}

static int
squat_trie_expunge_uidlists(struct squat_trie_build_context *ctx,
			    struct squat_uidlist_rebuild_context *rebuild_ctx,
			    struct squat_trie_iterate_context *iter,
			    const ARRAY_TYPE(seq_range) *expunged_uids)
{
	struct squat_node *node;
	ARRAY_TYPE(seq_range) uid_range, root_shifts, shifts;
	bool shift = FALSE;
	int ret = 0;

	node = squat_trie_iterate_first(iter);
	if (node->uid_list_idx == 0)
		return 0;

	i_array_init(&uid_range, 1024);
	i_array_init(&root_shifts, array_count(expunged_uids));
	array_append_array(&root_shifts, expunged_uids);

	if (array_count(expunged_uids) > 0)
		i_array_init(&iter->cur.shifts, array_count(expunged_uids));

	shifts = root_shifts;
	do {
		i_assert(node->uid_list_idx != 0);
		array_clear(&uid_range);
		if (squat_uidlist_get_seqrange(ctx->trie->uidlist,
					       node->uid_list_idx,
					       &uid_range) < 0) {
			ret = -1;
			break;
		}
		squat_uidlist_update_expunged_uids(&shifts, &iter->cur.shifts,
						   &uid_range, ctx->trie, node,
						   shift);
		node->uid_list_idx =
			squat_uidlist_rebuild_nextu(rebuild_ctx, &uid_range);
		i_assert(node->uid_list_idx != 0 || node->next_uid == 0);

		node = squat_trie_iterate_next(iter, &shifts);
		shift = TRUE;
	} while (node != NULL);
	array_free(&uid_range);
	array_free(&root_shifts);
	return ret;
}

static int
squat_trie_renumber_uidlists2(struct squat_trie_build_context *ctx,
			      struct squat_uidlist_rebuild_context *rebuild_ctx,
			      struct squat_trie_iterate_context *iter)
{
	struct squat_node *node;
	ARRAY_TYPE(seq_range) shifts;
	ARRAY_TYPE(uint32_t) uids;
	int ret = 0;

	node = squat_trie_iterate_first(iter);
	if (node->uid_list_idx == 0)
		return 0;

	i_array_init(&uids, 1024);
	while (node != NULL) {
		i_assert(node->uid_list_idx != 0);
		if (!UIDLIST_IS_SINGLETON(node->uid_list_idx)) {
			/* rebuild the uidlist */
			array_clear(&uids);
			if (squat_uidlist_get(ctx->trie->uidlist,
					      node->uid_list_idx, &uids) < 0) {
				ret = -1;
				break;
			}
			node->uid_list_idx =
				squat_uidlist_rebuild_next(rebuild_ctx, &uids);
		}
		node = squat_trie_iterate_next(iter, &shifts);
	}
	array_free(&uids);
	return ret;
}

static int
squat_trie_renumber_uidlists(struct squat_trie_build_context *ctx,
			     const ARRAY_TYPE(seq_range) *expunged_uids,
			     bool compress)
{
	struct squat_trie_iterate_context *iter;
	struct squat_uidlist_rebuild_context *rebuild_ctx;
	time_t now;
	int ret = 0;

	if ((ret = squat_uidlist_rebuild_init(ctx->uidlist_build_ctx,
					      compress, &rebuild_ctx)) <= 0)
		return ret;

	now = time(NULL);
	ctx->trie->hdr.indexid =
		I_MAX((unsigned int)now, ctx->trie->hdr.indexid + 1);

	iter = squat_trie_iterate_init(ctx->trie);
	if (expunged_uids != NULL) {
		ret = squat_trie_expunge_uidlists(ctx, rebuild_ctx, iter,
						  expunged_uids);
	} else {
		ret = squat_trie_renumber_uidlists2(ctx, rebuild_ctx, iter);
	}
	if (squat_trie_iterate_deinit(iter) < 0)
		ret = -1;

	/* lock the trie before we rename uidlist */
	i_assert(ctx->file_lock == NULL && ctx->dotlock == NULL);
	if (squat_trie_lock(ctx->trie, F_WRLCK,
			    &ctx->file_lock, &ctx->dotlock) <= 0)
		ret = -1;
	return squat_uidlist_rebuild_finish(rebuild_ctx, ret < 0);
}

static bool squat_trie_check_header(struct squat_trie *trie)
{
	if (trie->hdr.version != SQUAT_TRIE_VERSION ||
	    trie->hdr.uidvalidity != trie->uidvalidity)
		return FALSE;

	if (trie->hdr.partial_len > trie->hdr.full_len) {
		i_error("Corrupted %s: partial len > full len", trie->path);
		return FALSE;
	}
	if (trie->hdr.full_len == 0) {
		i_error("Corrupted %s: full len=0", trie->path);
		return FALSE;
	}
	return TRUE;
}

static int squat_trie_map_header(struct squat_trie *trie)
{
	int ret;

	if (trie->locked_file_size == 0) {
		/* newly created file */
		squat_trie_header_init(trie);
		return 1;
	}
	i_assert(trie->fd != -1);

	if ((trie->flags & SQUAT_INDEX_FLAG_MMAP_DISABLE) != 0) {
		ret = pread_full(trie->fd, &trie->hdr, sizeof(trie->hdr), 0);
		if (ret <= 0) {
			if (ret < 0) {
				i_error("pread(%s) failed: %m", trie->path);
				return -1;
			}
			i_error("Corrupted %s: File too small", trie->path);
			return 0;
		}
		trie->data = NULL;
		trie->data_size = 0;
	} else {
		if (trie->locked_file_size < sizeof(trie->hdr)) {
			i_error("Corrupted %s: File too small", trie->path);
			return 0;
		}
		if (trie->mmap_size != 0) {
			if (munmap(trie->mmap_base, trie->mmap_size) < 0)
				i_error("munmap(%s) failed: %m", trie->path);
		}

		trie->mmap_size = trie->locked_file_size;
		trie->mmap_base = mmap(NULL, trie->mmap_size,
				       PROT_READ | PROT_WRITE,
				       MAP_SHARED, trie->fd, 0);
		if (trie->mmap_base == MAP_FAILED) {
			trie->data = trie->mmap_base = NULL;
			trie->data_size = trie->mmap_size = 0;
			i_error("mmap(%s) failed: %m", trie->path);
			return -1;
		}
		memcpy(&trie->hdr, trie->mmap_base, sizeof(trie->hdr));
		trie->data = trie->mmap_base;
		trie->data_size = trie->mmap_size;
	}

	return squat_trie_check_header(trie) ? 1 : 0;
}

static int squat_trie_map(struct squat_trie *trie, bool building)
{
	struct file_lock *file_lock = NULL;
	struct dotlock *dotlock = NULL;
	bool changed;
	int ret;

	if (trie->fd != -1) {
		if (squat_trie_lock(trie, F_RDLCK, &file_lock, &dotlock) <= 0)
			return -1;
		if ((trie->flags & SQUAT_INDEX_FLAG_MMAP_DISABLE) != 0 &&
		    trie->file_cache == NULL)
			trie->file_cache = file_cache_new_path(trie->fd, trie->path);
	}

	ret = squat_trie_map_header(trie);
	if (ret == 0) {
		if (file_lock != NULL)
			file_unlock(&file_lock);
		else
			file_dotlock_delete(&dotlock);
		squat_trie_delete(trie);
		squat_trie_close(trie);
		squat_trie_header_init(trie);
	}
	changed = trie->root.children.offset != trie->hdr.root_offset;

	if (changed || trie->hdr.root_offset == 0) {
		node_free(trie, &trie->root);
		i_zero(&trie->root);
		trie->root.want_sequential = TRUE;
		trie->root.unused_uids = trie->hdr.root_unused_uids;
		trie->root.next_uid = trie->hdr.root_next_uid;
		trie->root.uid_list_idx = trie->hdr.root_uidlist_idx;
		trie->root.children.offset = trie->hdr.root_offset;

		if (trie->hdr.root_offset == 0) {
			trie->unmapped_child_count = 0;
			trie->root.children_not_mapped = FALSE;
		} else {
			trie->unmapped_child_count = 1;
			trie->root.children_not_mapped = TRUE;
		}
	}

	if (ret >= 0 && !building) {
		/* do this while we're still locked */
		ret = squat_uidlist_refresh(trie->uidlist);
	}

	if (file_lock != NULL)
		file_unlock(&file_lock);
	if (dotlock != NULL)
		file_dotlock_delete(&dotlock);
	if (ret < 0)
		return -1;

	return trie->hdr.root_offset == 0 || !changed ? 0 :
		node_read_children(trie, &trie->root, 1);
}

int squat_trie_create_fd(struct squat_trie *trie, const char *path, int flags)
{
	mode_t old_mask;
	int fd;

	old_mask = umask(0);
	fd = open(path, O_RDWR | O_CREAT | flags, trie->create_mode);
	umask(old_mask);
	if (fd == -1) {
		i_error("creat(%s) failed: %m", path);
		return -1;
	}
	if (trie->create_gid != (gid_t)-1) {
		if (fchown(fd, (uid_t)-1, trie->create_gid) < 0) {
			i_error("fchown(%s, -1, %ld) failed: %m",
				path, (long)trie->create_gid);
			i_close_fd(&fd);
			return -1;
		}
	}
	return fd;
}

int squat_trie_build_init(struct squat_trie *trie,
			  struct squat_trie_build_context **ctx_r)
{
	struct squat_trie_build_context *ctx;
	struct squat_uidlist_build_context *uidlist_build_ctx;

	if (trie->fd == -1) {
		trie->fd = squat_trie_create_fd(trie, trie->path, 0);
		if (trie->fd == -1)
			return -1;

		if (trie->file_cache != NULL)
			file_cache_set_fd(trie->file_cache, trie->fd);
		i_assert(trie->locked_file_size == 0);
	}

	/* uidlist locks building */
	if (squat_uidlist_build_init(trie->uidlist, &uidlist_build_ctx) < 0)
		return -1;

	if (squat_trie_map(trie, TRUE) < 0) {
		squat_uidlist_build_deinit(&uidlist_build_ctx);
		return -1;
	}

	ctx = i_new(struct squat_trie_build_context, 1);
	ctx->trie = trie;
	ctx->uidlist_build_ctx = uidlist_build_ctx;
	ctx->first_uid = trie->root.next_uid;

	*ctx_r = ctx;
	return 0;
}

static int squat_trie_write_lock(struct squat_trie_build_context *ctx)
{
	if (ctx->file_lock != NULL || ctx->dotlock != NULL)
		return 0;

	if (squat_trie_lock(ctx->trie, F_WRLCK,
			    &ctx->file_lock, &ctx->dotlock) <= 0)
		return -1;
	return 0;
}

static int squat_trie_write(struct squat_trie_build_context *ctx)
{
	struct squat_trie *trie = ctx->trie;
	struct file_lock *file_lock = NULL;
	struct ostream *output;
	const char *path;
	int fd = -1, ret = 0;

	if ((trie->hdr.used_file_size > sizeof(trie->hdr) &&
	    trie->unmapped_child_count < trie->hdr.node_count/4) || 1) {
		/* we might as well recreate the file */
		ctx->compress_nodes = TRUE;

		path = t_strconcat(trie->path, ".tmp", NULL);
		fd = squat_trie_create_fd(trie, path, O_TRUNC);
		if (fd == -1)
			return -1;

		if (trie->lock_method != FILE_LOCK_METHOD_DOTLOCK) {
			ret = file_wait_lock(fd, path, F_WRLCK,
					     trie->lock_method,
					     SQUAT_TRIE_LOCK_TIMEOUT,
					     &file_lock);
			if (ret <= 0) {
				if (ret == 0) {
					i_error("file_wait_lock(%s) failed: %m",
						path);
				}
				i_close_fd(&fd);
				return -1;
			}
		}

		output = o_stream_create_fd(fd, 0);
		o_stream_cork(output);
		o_stream_nsend(output, &trie->hdr, sizeof(trie->hdr));
	} else {
		/* we need to lock only while header is being written */
		path = trie->path;
		ctx->compress_nodes =
			trie->hdr.used_file_size == sizeof(trie->hdr);

		if (trie->hdr.used_file_size == 0) {
			/* lock before opening the file, in case we reopen it */
			if (squat_trie_write_lock(ctx) < 0)
				return -1;
		}
		output = o_stream_create_fd(trie->fd, 0);
		o_stream_cork(output);

		if (trie->hdr.used_file_size != 0)
			(void)o_stream_seek(output, trie->hdr.used_file_size);
		else
			o_stream_nsend(output, &trie->hdr, sizeof(trie->hdr));
	}

	ctx->output = output;
	ret = squat_write_nodes(ctx);
	ctx->output = NULL;

	/* write 1 byte guard at the end of file, so that we can verify broken
	   squat_unpack_num() input by checking if data==end */
	o_stream_nsend(output, "", 1);

	if (trie->corrupted)
		ret = -1;
	if (ret == 0)
		ret = squat_trie_write_lock(ctx);
	if (ret == 0) {
		trie->hdr.used_file_size = output->offset;
		(void)o_stream_seek(output, 0);
		o_stream_nsend(output, &trie->hdr, sizeof(trie->hdr));
	}
	if (o_stream_finish(output) < 0) {
		i_error("write(%s) failed: %s", path,
			o_stream_get_error(output));
		ret = -1;
	}
	o_stream_destroy(&output);

	if (fd == -1) {
		/* appended to the existing file */
		i_assert(file_lock == NULL);
		return ret;
	}

	/* recreating the trie file */
	if (ret < 0) {
		if (close(fd) < 0)
			i_error("close(%s) failed: %m", path);
		fd = -1;
	} else if (rename(path, trie->path) < 0) {
		i_error("rename(%s, %s) failed: %m", path, trie->path);
		ret = -1;
	}

	if (ret < 0) {
		i_unlink_if_exists(path);
		file_lock_free(&file_lock);
	} else {
		squat_trie_close_fd(trie);
		trie->fd = fd;
		trie->locked_file_size = trie->hdr.used_file_size;
		if (trie->file_cache != NULL)
			file_cache_set_fd(trie->file_cache, trie->fd);

		file_lock_free(&ctx->file_lock);
		ctx->file_lock = file_lock;
	}
	return ret;
}

int squat_trie_build_deinit(struct squat_trie_build_context **_ctx,
			    const ARRAY_TYPE(seq_range) *expunged_uids)
{
	struct squat_trie_build_context *ctx = *_ctx;
	bool compress, unlock = TRUE;
	int ret;

	*_ctx = NULL;

	compress = (ctx->trie->root.next_uid - ctx->first_uid) > 10;

	/* keep trie locked while header is being written and when files are
	   being renamed, so that while trie is read locked, uidlist can't
	   change under. */
	squat_uidlist_build_flush(ctx->uidlist_build_ctx);
	ret = squat_trie_renumber_uidlists(ctx, expunged_uids, compress);
	if (ret == 0) {
		ret = squat_trie_write(ctx);
		if (ret < 0)
			unlock = FALSE;
	}

	if (ret == 0)
		ret = squat_uidlist_build_finish(ctx->uidlist_build_ctx);
	if (ctx->file_lock != NULL) {
		if (unlock)
			file_unlock(&ctx->file_lock);
		else
			file_lock_free(&ctx->file_lock);
	}
	if (ctx->dotlock != NULL)
		file_dotlock_delete(&ctx->dotlock);
	squat_uidlist_build_deinit(&ctx->uidlist_build_ctx);

	i_free(ctx);
	return ret;
}

int squat_trie_get_last_uid(struct squat_trie *trie, uint32_t *last_uid_r)
{
	if (trie->fd == -1) {
		if (squat_trie_open(trie) < 0)
			return -1;
	}

	*last_uid_r = I_MAX((trie->root.next_uid+1)/2, 1) - 1;
	return 0;
}

static int
squat_trie_lookup_data(struct squat_trie *trie, const unsigned char *data,
		       unsigned int size, ARRAY_TYPE(seq_range) *uids)
{
	struct squat_node *node = &trie->root;
	unsigned char *chars;
	unsigned int idx;
	int level = 0;

	array_clear(uids);

	for (;;) {
		if (node->children_not_mapped) {
			if (node_read_children(trie, node, level) < 0)
				return -1;
		}
		if (node->leaf_string_length != 0) {
			unsigned int len = node->leaf_string_length;
			const unsigned char *str;

			if (len > sizeof(node->children.static_leaf_string))
				str = node->children.leaf_string;
			else
				str = node->children.static_leaf_string;

			if (size > len || memcmp(data, str, size) != 0)
				return 0;

			/* match */
			break;
		}

		if (size == 0)
			break;
		level++;

		if (node->have_sequential) {
			if (*data < SEQUENTIAL_COUNT) {
				idx = *data;
				goto found;
			}
			idx = SEQUENTIAL_COUNT;
		} else {
			idx = 0;
		}
		chars = NODE_CHILDREN_CHARS(node);
		for (; idx < node->child_count; idx++) {
			if (chars[idx] == *data)
				goto found;
		}
		return 0;
	found:
		/* follow to children */
		if (level == 1) {
			/* root level, add all UIDs */
			if (squat_uidlist_get_seqrange(trie->uidlist,
						       node->uid_list_idx,
						       uids) < 0)
				return -1;
		} else {
			if (squat_uidlist_filter(trie->uidlist,
						 node->uid_list_idx, uids) < 0)
				return -1;
		}
		data++;
		size--;
		node = NODE_CHILDREN_NODES(node) + idx;
	}

	if (squat_uidlist_filter(trie->uidlist, node->uid_list_idx, uids) < 0)
		return -1;
	return 1;
}

static void
squat_trie_filter_type(enum squat_index_type type,
		       const ARRAY_TYPE(seq_range) *src,
		       ARRAY_TYPE(seq_range) *dest)
{
	const struct seq_range *src_range;
	struct seq_range new_range;
	unsigned int i, count, mask;
	uint32_t next_seq, uid;

	array_clear(dest);
	src_range = array_get(src, &count);
	if (count == 0)
		return;

	if ((type & SQUAT_INDEX_TYPE_HEADER) != 0 &&
	    (type & SQUAT_INDEX_TYPE_BODY) != 0) {
		/* everything is fine, just fix the UIDs */
		new_range.seq1 = src_range[0].seq1 / 2;
		new_range.seq2 = src_range[0].seq2 / 2;
		for (i = 1; i < count; i++) {
			next_seq = src_range[i].seq1 / 2;
			if (next_seq == new_range.seq2 + 1) {
				/* we can continue the previous range */
			} else {
				array_push_back(dest, &new_range);
				new_range.seq1 = src_range[i].seq1 / 2;
			}
			new_range.seq2 = src_range[i].seq2 / 2;
		}
		array_push_back(dest, &new_range);
		return;
	}

	/* we'll have to drop either header or body UIDs */
	mask = (type & SQUAT_INDEX_TYPE_HEADER) != 0 ? 1 : 0;
	for (i = 0; i < count; i++) {
		for (uid = src_range[i].seq1; uid <= src_range[i].seq2; uid++) {
			if ((uid & 1) == mask)
				seq_range_array_add(dest, uid/2);
		}
	}
}

struct squat_trie_lookup_context {
	struct squat_trie *trie;
	enum squat_index_type type;

	ARRAY_TYPE(seq_range) *definite_uids, *maybe_uids;
	ARRAY_TYPE(seq_range) tmp_uids, tmp_uids2;
	bool first;
};

static int
squat_trie_lookup_partial(struct squat_trie_lookup_context *ctx,
			  const unsigned char *data, uint8_t *char_lengths,
			  unsigned int size)
{
	const unsigned int partial_len = ctx->trie->hdr.partial_len;
	unsigned int char_idx, max_chars, i, j, bytelen;
	int ret;

	for (i = 0, max_chars = 0; i < size; max_chars++)
		i += char_lengths[i];
	i_assert(max_chars > 0);

	i = 0; char_idx = 0;
	do {
		bytelen = 0;
		for (j = 0; j < partial_len && i+bytelen < size; j++)
			bytelen += char_lengths[i + bytelen];

		ret = squat_trie_lookup_data(ctx->trie, data + i, bytelen,
					     &ctx->tmp_uids);
		if (ret <= 0) {
			array_clear(ctx->maybe_uids);
			return ret;
		}

		if (ctx->first) {
			squat_trie_filter_type(ctx->type, &ctx->tmp_uids,
					       ctx->maybe_uids);
			ctx->first = FALSE;
		} else {
			squat_trie_filter_type(ctx->type, &ctx->tmp_uids,
					       &ctx->tmp_uids2);
			seq_range_array_intersect(ctx->maybe_uids,
						  &ctx->tmp_uids2);
		}
		i += char_lengths[i];
		char_idx++;
	} while (max_chars - char_idx >= partial_len);
	return 1;
}

static void squat_trie_add_unknown(struct squat_trie *trie,
				   ARRAY_TYPE(seq_range) *maybe_uids)
{
	struct seq_range *range, new_range;
	unsigned int count;
	uint32_t last_uid;

	last_uid = I_MAX((trie->root.next_uid+1)/2, 1) - 1;

	range = array_get_modifiable(maybe_uids, &count);
	if (count > 0 && range[count-1].seq2 == last_uid) {
		/* increase the range */
		range[count-1].seq2 = (uint32_t)-1;
	} else {
		new_range.seq1 = last_uid + 1;
		new_range.seq2 = (uint32_t)-1;
		array_push_back(maybe_uids, &new_range);
	}
}

static int
squat_trie_lookup_real(struct squat_trie *trie, const char *str,
		       enum squat_index_type type,
		       ARRAY_TYPE(seq_range) *definite_uids,
		       ARRAY_TYPE(seq_range) *maybe_uids)
{
	struct squat_trie_lookup_context ctx;
	unsigned char *data;
	uint8_t *char_lengths;
	unsigned int i, start, bytes, str_bytelen, str_charlen;
	bool searched = FALSE;
	int ret = 0;

	array_clear(definite_uids);
	array_clear(maybe_uids);

	i_zero(&ctx);
	ctx.trie = trie;
	ctx.type = type;
	ctx.definite_uids = definite_uids;
	ctx.maybe_uids = maybe_uids;
	i_array_init(&ctx.tmp_uids, 128);
	i_array_init(&ctx.tmp_uids2, 128);
	ctx.first = TRUE;

	str_bytelen = strlen(str);
	char_lengths = str_bytelen == 0 ? NULL : t_malloc0(str_bytelen);
	for (i = 0, str_charlen = 0; i < str_bytelen; str_charlen++) {
		bytes = uni_utf8_char_bytes(str[i]);
		char_lengths[i] = bytes;
		i += bytes;
	}
	data = squat_data_normalize(trie, (const unsigned char *)str,
				    str_bytelen);

	for (i = start = 0; i < str_bytelen && ret >= 0; i += char_lengths[i]) {
		if (data[i] != '\0')
			continue;

		/* string has nonindexed characters.
		   search it in parts. */
		if (i != start) {
			ret = squat_trie_lookup_partial(&ctx, data + start,
							char_lengths + start,
							i - start);
			searched = TRUE;
		}
		start = i + char_lengths[i];
	}

	if (start == 0) {
		if (str_charlen <= trie->hdr.partial_len ||
		    trie->hdr.full_len > trie->hdr.partial_len) {
			ret = squat_trie_lookup_data(trie, data, str_bytelen,
						     &ctx.tmp_uids);
			if (ret > 0) {
				squat_trie_filter_type(type, &ctx.tmp_uids,
						       definite_uids);
			}
		} else {
			array_clear(definite_uids);
		}

		if (str_charlen <= trie->hdr.partial_len ||
		    trie->hdr.partial_len == 0) {
			/* we have the result */
			array_clear(maybe_uids);
		} else {
			ret = squat_trie_lookup_partial(&ctx, data + start,
							char_lengths + start,
							i - start);
		}
	} else if (str_bytelen > 0) {
		/* string has nonindexed characters. finish the search. */
		array_clear(definite_uids);
		if (i != start && ret >= 0) {
			ret = squat_trie_lookup_partial(&ctx, data + start,
							char_lengths + start,
							i - start);
		} else if (!searched) {
			/* string has only nonindexed chars,
			   list all root UIDs as maybes */
			ret = squat_uidlist_get_seqrange(trie->uidlist,
							trie->root.uid_list_idx,
							&ctx.tmp_uids);
			squat_trie_filter_type(type, &ctx.tmp_uids,
					       maybe_uids);
		}
	} else {
		/* zero string length - list all root UIDs as definite
		   answers */
#if 0 /* FIXME: this code is never actually reached now. */
		ret = squat_uidlist_get_seqrange(trie->uidlist,
						 trie->root.uid_list_idx,
						 &ctx.tmp_uids);
		squat_trie_filter_type(type, &ctx.tmp_uids,
				       definite_uids);
#else
		i_unreached();
#endif
	}
	seq_range_array_remove_seq_range(maybe_uids, definite_uids);
	squat_trie_add_unknown(trie, maybe_uids);
	array_free(&ctx.tmp_uids);
	array_free(&ctx.tmp_uids2);
	return ret < 0 ? -1 : 0;
}

int squat_trie_lookup(struct squat_trie *trie, const char *str,
		      enum squat_index_type type,
		      ARRAY_TYPE(seq_range) *definite_uids,
		      ARRAY_TYPE(seq_range) *maybe_uids)
{
	int ret;

	T_BEGIN {
		ret = squat_trie_lookup_real(trie, str, type,
					     definite_uids, maybe_uids);
	} T_END;
	return ret;
}

struct squat_uidlist *squat_trie_get_uidlist(struct squat_trie *trie)
{
	return trie->uidlist;
}

size_t squat_trie_mem_used(struct squat_trie *trie, unsigned int *count_r)
{
	*count_r = trie->hdr.node_count;
	return trie->node_alloc_size;
}
