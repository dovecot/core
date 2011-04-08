/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "crc32.h"
#include "ioloop.h"
#include "str.h"
#include "file-cache.h"
#include "file-dotlock.h"
#include "mmap-util.h"
#include "write-full.h"
#include "nfs-workarounds.h"
#include "mail-index-private.h"
#include "mailbox-list-index-private.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

struct mailbox_list_iter_path {
	const struct mailbox_list_dir_record *dir;
	unsigned int pos;
	unsigned int name_path_len;
};

struct mailbox_list_index_view {
	struct mailbox_list_index *index;
	struct mail_index_view *mail_view;
};

struct mailbox_list_iter_ctx {
	struct mailbox_list_index_view *view;
	unsigned int recurse_level;
	uint32_t max_uid;

	struct mailbox_list_iter_path cur;
	ARRAY_DEFINE(path, struct mailbox_list_iter_path);
	string_t *name_path;

	unsigned int failed:1;
};

static const struct dotlock_settings default_dotlock_set = {
	.timeout = 60,
	.stale_timeout = 30
};

int mailbox_list_index_set_syscall_error(struct mailbox_list_index *index,
					 const char *function)
{
	i_error("%s failed with file %s: %m", function, index->filepath);
	return -1;
}

static void mailbox_list_index_unmap(struct mailbox_list_index *index)
{
	if (index->file_cache != NULL)
		file_cache_invalidate(index->file_cache, 0, (uoff_t)-1);

	if (index->mmap_base != NULL) {
		if (munmap(index->mmap_base, index->mmap_size) < 0)
			mailbox_list_index_set_syscall_error(index, "munmap()");
		index->mmap_base = NULL;
	}
	index->const_mmap_base = NULL;
	index->mmap_size = 0;

	index->hdr = NULL;
}

void mailbox_list_index_file_close(struct mailbox_list_index *index)
{
	mailbox_list_index_unmap(index);

	if (index->file_cache != NULL)
		file_cache_free(&index->file_cache);
	if (index->fd != -1) {
		if (close(index->fd) < 0)
			mailbox_list_index_set_syscall_error(index, "close()");
		index->fd = -1;
	}
}

int mailbox_list_index_set_corrupted(struct mailbox_list_index *index,
				     const char *str)
{
	if (!index->mail_index->readonly)
		(void)unlink(index->filepath);
	mailbox_list_index_file_close(index);

	i_error("Corrupted mailbox list index file %s: %s",
		index->filepath, str);
	return -1;
}

static int
mailbox_list_index_check_header(struct mailbox_list_index *index,
				const struct mailbox_list_index_header *hdr)
{
	if (hdr->major_version != MAILBOX_LIST_INDEX_MAJOR_VERSION)
		return -1;

	if (hdr->header_size < sizeof(*hdr)) {
		return mailbox_list_index_set_corrupted(index,
			"header_size is too small");
	}
	if (hdr->header_size > index->mmap_size) {
		return mailbox_list_index_set_corrupted(index,
			"header_size is too large");
	}

	if (hdr->uid_validity == 0) {
		return mailbox_list_index_set_corrupted(index,
							"uid_validity is 0");
	}
	if (hdr->next_uid == 0)
		return mailbox_list_index_set_corrupted(index, "next_uid is 0");

	if (index->mail_index->map == NULL) {
		/* index already marked as corrupted */
		return -1;
	}
	return 0;
}

int mailbox_list_index_map(struct mailbox_list_index *index)
{
	const struct mailbox_list_index_header *hdr;
	struct stat st;
	ssize_t ret;

	mailbox_list_index_unmap(index);

	if (!index->mmap_disable) {
		if (fstat(index->fd, &st) < 0) {
			mailbox_list_index_set_syscall_error(index, "fstat()");
			return -1;
		}
	}

	if (!index->mmap_disable &&
	    st.st_size >= MAILBOX_LIST_INDEX_MMAP_MIN_SIZE) {
		index->mmap_size = st.st_size;
		index->mmap_base = mmap(NULL, index->mmap_size,
					PROT_READ | PROT_WRITE,
					MAP_SHARED, index->fd, 0);
		if (index->mmap_base == MAP_FAILED) {
			index->mmap_base = NULL;
			mailbox_list_index_set_syscall_error(index, "mmap()");
			return -1;
		}

		index->const_mmap_base = index->mmap_base;
	} else {
		if (index->file_cache == NULL)
			index->file_cache = file_cache_new(index->fd);

		ret = file_cache_read(index->file_cache, 0, SSIZE_T_MAX);
		if (ret < 0) {
			mailbox_list_index_set_syscall_error(index,
				"file_cache_read()");
			return -1;
		}
		index->const_mmap_base = file_cache_get_map(index->file_cache,
							    &index->mmap_size);
	}

	if (index->mmap_size < sizeof(*hdr)) {
		mailbox_list_index_set_corrupted(index, "File too small");
		index->const_mmap_base = NULL;
		return 0;
	}

	hdr = index->const_mmap_base;
	if (mailbox_list_index_check_header(index, hdr) < 0) {
		index->const_mmap_base = NULL;
		return 0;
	}

	index->hdr = hdr;
	return 1;
}

static int mailbox_list_index_map_area(struct mailbox_list_index *index,
				       uoff_t offset, size_t size)
{
	if (offset < index->mmap_size && size <= index->mmap_size - offset)
		return 1;

	if (mailbox_list_index_map(index) <= 0)
		return -1;

	if (offset < index->mmap_size && size <= index->mmap_size - offset)
		return 1;
	/* outside the file */
	return 0;
}

static void
mailbox_list_index_init_header(struct mailbox_list_index *index,
			       struct mailbox_list_index_header *hdr,
			       uint32_t uid_validity)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->major_version = MAILBOX_LIST_INDEX_MAJOR_VERSION;
	hdr->minor_version = MAILBOX_LIST_INDEX_MINOR_VERSION;

	hdr->file_seq = index->hdr == NULL ? 1 : index->hdr->file_seq + 1;
	hdr->header_size = sizeof(*hdr);
	hdr->used_space = hdr->header_size;

	hdr->uid_validity = uid_validity;
	hdr->next_uid = 1;
}

static int mailbox_list_index_is_recreated(struct mailbox_list_index *index)
{
	struct stat st1, st2;

	if (index->fd == -1)
		return 1;

	if ((index->mail_index->flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) != 0)
		nfs_flush_file_handle_cache(index->filepath);

	if (nfs_safe_stat(index->filepath, &st1) < 0) {
		if (errno == ENOENT || errno == ESTALE)
			return 1;

		mailbox_list_index_set_syscall_error(index, "stat()");
		return -1;
	}
	if (fstat(index->fd, &st2) < 0) {
		if (ESTALE_FSTAT(errno))
			return 1;
		mailbox_list_index_set_syscall_error(index, "fstat()");
		return -1;
	}

	return st1.st_ino != st2.st_ino ||
		!CMP_DEV_T(st1.st_dev, st2.st_dev);
}

int mailbox_list_index_file_create(struct mailbox_list_index *index,
				   uint32_t uid_validity)
{
	struct mailbox_list_index_header hdr;
	struct dotlock *dotlock;
	int fd, ret;

	fd = file_dotlock_open(&index->dotlock_set, index->filepath,
			       0, &dotlock);
	if (fd == -1) {
		mailbox_list_index_set_syscall_error(index,
						     "file_dotlock_open()");
		return -1;
	}

	if (index->fd != -1) {
		/* if the file has been recreated by someone else,
		   retry opening it */
		ret = mailbox_list_index_is_recreated(index);
		if (ret != 0) {
			(void)file_dotlock_delete(&dotlock);
			return ret < 0 ? -1 : 0;
		}
	}

	mailbox_list_index_init_header(index, &hdr, uid_validity);
	if (write_full(fd, &hdr, sizeof(hdr)) < 0) {
		mailbox_list_index_set_syscall_error(index, "write_full()");
		(void)file_dotlock_delete(&dotlock);
		return -1;
	}

	if (index->mail_index->fsync_mode == FSYNC_MODE_ALWAYS &&
	    fdatasync(fd) < 0) {
		mailbox_list_index_set_syscall_error(index, "fdatasync()");
		(void)file_dotlock_delete(&dotlock);
		return -1;
	}

	if (file_dotlock_replace(&dotlock,
				 DOTLOCK_REPLACE_FLAG_DONT_CLOSE_FD) < 0) {
		mailbox_list_index_set_syscall_error(index,
						     "file_dotlock_replace()");
		(void)close(fd);
		return -1;
	}

	if (index->fd != -1)
		mailbox_list_index_file_close(index);
	index->fd = fd;

	ret = mailbox_list_index_map(index);
	if (ret == 0) {
		i_error("Self-created mailbox list index file %s was corrupted",
			index->filepath);
		return -1;
	}
	return ret;
}

static int
mailbox_list_index_file_try_open_or_create(struct mailbox_list_index *index)
{
	int ret;

	i_assert(index->fd == -1);

	index->fd = open(index->filepath, O_RDWR);
	if (index->fd == -1) {
		if (errno != ENOENT) {
			mailbox_list_index_set_syscall_error(index, "open()");
			return -1;
		}
	} else {
		ret = mailbox_list_index_map(index);
		if (ret != 0) {
			if (ret < 0)
				mailbox_list_index_file_close(index);
			return ret;
		}
	}

	ret = mailbox_list_index_file_create(index, ioloop_time);
	if (ret <= 0)
		mailbox_list_index_file_close(index);
	return ret;
}

int mailbox_list_index_open_or_create(struct mailbox_list_index *index)
{
	int ret;

	while ((ret = mailbox_list_index_file_try_open_or_create(index)) == 0) {
		/* file was recreated by someone else, try reopening */
	}
	return ret < 0 ? -1 : 0;
}

struct mailbox_list_index *
mailbox_list_index_alloc(const char *path, char separator,
			 struct mail_index *mail_index)
{
	struct mailbox_list_index *index;

	index = i_new(struct mailbox_list_index, 1);
	index->filepath = i_strdup(path);
	index->separator = separator;
	index->mail_index = mail_index;
	index->fd = -1;
	index->mmap_disable =
		(mail_index->flags & MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE) != 0;
	index->dotlock_set = default_dotlock_set;
	index->dotlock_set.use_excl_lock =
		(mail_index->flags & MAIL_INDEX_OPEN_FLAG_DOTLOCK_USE_EXCL) != 0;
	index->dotlock_set.nfs_flush =
		(mail_index->flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) != 0;
	return index;
}

void mailbox_list_index_free(struct mailbox_list_index **_index)
{
	struct mailbox_list_index *index = *_index;

	*_index = NULL;

	mailbox_list_index_file_close(index);
	i_free(index->filepath);
	i_free(index);
}

struct mailbox_list_index_lookup_key {
	uint32_t name_hash;

	struct mailbox_list_index *index;
	const char *name;

	bool *failed;
};

static int
mailbox_list_get_name(struct mailbox_list_index *index, pool_t pool,
		      const struct mailbox_list_record *rec,
		      const char **name_r)
{
	size_t max_len;
	const char *name;

	if (rec->name_offset >= index->mmap_size) {
		mailbox_list_index_set_corrupted(index, t_strdup_printf(
			"record name_offset (%u) points outside file "
			"(%"PRIuSIZE_T")", rec->name_offset, index->mmap_size));
		return -1;
	}
	max_len = index->mmap_size - rec->name_offset;
	name = CONST_PTR_OFFSET(index->const_mmap_base, rec->name_offset);
	/* get name length. don't bother checking if it's not NUL-terminated,
	   because practically it always is even if the file is corrupted.
	   just make sure we don't crash if it happens. */
	*name_r = p_strndup(pool, name, max_len);
	if (*name_r == '\0') {
		mailbox_list_index_set_corrupted(index, "Empty mailbox name");
		return -1;
	}
	return 0;
}

int mailbox_list_index_get_dir(struct mailbox_list_index_view *view,
			       uint32_t *offset,
			       const struct mailbox_list_dir_record **dir_r)
{
	struct mailbox_list_index *index = view->index;
	const struct mailbox_list_dir_record *dir;
	uint32_t next_offset, cur_offset = *offset;
	int ret;

	i_assert(index->mmap_size > 0);

	do {
		ret = mailbox_list_index_map_area(index, cur_offset,
						  sizeof(*dir));
		if (ret <= 0) {
			if (ret < 0)
				return -1;
			return mailbox_list_index_set_corrupted(index,
				"dir_offset points outside file");
		}
		if ((cur_offset % 4) != 0) {
			return mailbox_list_index_set_corrupted(index,
				"dir_offset not 32bit aligned");
		}

		dir = CONST_PTR_OFFSET(index->const_mmap_base, cur_offset);
		next_offset = mail_index_offset_to_uint32(dir->next_offset);
		if (next_offset != 0 && next_offset <= cur_offset) {
			return mailbox_list_index_set_corrupted(index,
				"next_offset points backwards");
		}

		if (dir->count >
		    index->mmap_size / sizeof(struct mailbox_list_record)) {
			return mailbox_list_index_set_corrupted(index,
				"dir count too large");
		}
		if (dir->dir_size < sizeof(*dir) +
		    dir->count * sizeof(struct mailbox_list_record)) {
			return mailbox_list_index_set_corrupted(index,
				"dir_size is smaller than record count");
		}
		cur_offset = next_offset;
	} while (cur_offset != 0);

	cur_offset = (const char *)dir - (const char *)index->const_mmap_base;
	ret = mailbox_list_index_map_area(index, cur_offset, dir->dir_size);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		return mailbox_list_index_set_corrupted(index,
			"dir points outside file");
	}

	*offset = cur_offset;
	*dir_r = dir;
	return 0;
}

static int mailbox_list_record_cmp(const void *_key, const void *_rec)
{
	const struct mailbox_list_index_lookup_key *key = _key;
	const struct mailbox_list_record *rec = _rec;
	int ret;

	if (key->name_hash < rec->name_hash)
		return -1;
	if (key->name_hash > rec->name_hash)
		return 1;

	T_BEGIN {
		const char *name;

		if (mailbox_list_get_name(key->index, unsafe_data_stack_pool,
					  rec, &name) < 0) {
			*key->failed = TRUE;
			ret = 0;
		} else {
			ret = strcmp(key->name, name);
		}
	} T_END;
	return ret;
}

int mailbox_list_index_dir_lookup_rec(struct mailbox_list_index *index,
				      const struct mailbox_list_dir_record *dir,
				      const char *name,
				      const struct mailbox_list_record **rec_r)
{
	const struct mailbox_list_record *rec;
	struct mailbox_list_index_lookup_key key;
	bool failed = FALSE;

	/* binary search the current hierarchy level name. the values are
	   sorted primarily by their hash value and secondarily by the actual
	   name */
	memset(&key, 0, sizeof(key));
	key.index = index;
	key.name = name;
	key.name_hash = crc32_str(name);
	key.failed = &failed;

	rec = bsearch(&key, MAILBOX_LIST_RECORDS(dir), dir->count, sizeof(*rec),
		      mailbox_list_record_cmp);
	if (failed)
		return -1;
	if (rec == NULL)
		return 0;

	*rec_r = rec;
	return 1;
}

static int
mailbox_list_index_lookup_rec(struct mailbox_list_index_view *view,
			      uint32_t dir_offset, const char *name,
			      const struct mailbox_list_record **rec_r)
{
	struct mailbox_list_index *index = view->index;
	const struct mailbox_list_dir_record *dir;
	const char *p, *hier_name;
	int ret;

	if (dir_offset == sizeof(*index->hdr) &&
	    index->mmap_size <= sizeof(*index->hdr)) {
		/* root doesn't exist in the file yet */
		return 0;
	}

	if (mailbox_list_index_get_dir(view, &dir_offset, &dir) < 0)
		return -1;

	p = strchr(name, index->separator);
	hier_name = p == NULL ? name : t_strdup_until(name, p);

	ret = mailbox_list_index_dir_lookup_rec(index, dir, hier_name, rec_r);
	if (ret <= 0)
		return ret;

	if (p == NULL) {
		/* found it */
		return 1;
	}

	/* recurse to children */
	dir_offset = mail_index_offset_to_uint32((*rec_r)->dir_offset);
	if (dir_offset == 0)
		return 0;

	return mailbox_list_index_lookup_rec(view, dir_offset, p + 1, rec_r);
}

int mailbox_list_index_refresh(struct mailbox_list_index *index)
{
	int ret;

	if ((ret = mailbox_list_index_is_recreated(index)) <= 0) {
		if (ret < 0)
			return -1;

		if (mailbox_list_index_map(index) < 0)
			ret = -1;
		return ret;
	}

	mailbox_list_index_file_close(index);
	return mailbox_list_index_open_or_create(index);
}

int mailbox_list_index_view_init(struct mailbox_list_index *index,
				 struct mail_index_view *mail_view,
				 struct mailbox_list_index_view **view_r)
{
	struct mailbox_list_index_view *view;
	const struct mail_index_header *mail_hdr;

	mail_hdr = mail_view != NULL ? mail_index_get_header(mail_view) : NULL;
	if (mail_hdr != NULL && mail_hdr->uid_validity != 0 &&
	    index->hdr != NULL &&
	    mail_hdr->uid_validity != index->hdr->uid_validity) {
		mail_index_set_error(index->mail_index,
			"uid_validity mismatch in file %s: %u != %u",
			index->filepath, index->hdr->uid_validity,
			mail_hdr->uid_validity);
		return -1;
	}

	view = *view_r = i_new(struct mailbox_list_index_view, 1);
	view->index = index;
	view->mail_view = mail_view;
	return 0;
}

void mailbox_list_index_view_deinit(struct mailbox_list_index_view **_view)
{
	struct mailbox_list_index_view *view = *_view;

	*_view = NULL;
	i_free(view);
}

int mailbox_list_index_lookup(struct mailbox_list_index_view *view,
			      const char *name, uint32_t *uid_r)
{
	const struct mailbox_list_record *rec;
	uint32_t offset = sizeof(*view->index->hdr);
	int ret;

	ret = mailbox_list_index_lookup_rec(view, offset, name, &rec);
	if (ret == 0) {
		/* not found, see if it's found after a refresh */
		if ((ret = mailbox_list_index_refresh(view->index)) <= 0)
			return ret;

		ret = mailbox_list_index_lookup_rec(view, offset, name, &rec);
	}

	*uid_r = ret <= 0 ? 0 : rec->uid;
	return ret;
}

struct mailbox_list_iter_ctx *
mailbox_list_index_iterate_init(struct mailbox_list_index_view *view,
				const char *path, int recurse_level)
{
	struct mailbox_list_iter_ctx *ctx;
	const struct mail_index_header *mail_hdr;
	const struct mailbox_list_record *rec;
	uint32_t offset = sizeof(*view->index->hdr);
	int ret;

	ctx = i_new(struct mailbox_list_iter_ctx, 1);
	ctx->view = view;
	ctx->recurse_level = recurse_level < 0 ? (unsigned int)-1 :
		(unsigned int)recurse_level;
	ctx->name_path = str_new(default_pool, 512);

	if (view->mail_view != NULL) {
		mail_hdr = mail_index_get_header(view->mail_view);
		ctx->max_uid = mail_hdr->next_uid - 1;
	} else {
		ctx->max_uid = (uint32_t)-1;
	}

	if (mailbox_list_index_refresh(view->index) < 0)
		ctx->failed = TRUE;
	if (!ctx->failed && *path != '\0') {
		ret = mailbox_list_index_lookup_rec(view, offset, path, &rec);
		if (ret < 0)
			ctx->failed = TRUE;
		else {
			offset = ret == 0 ? 0 :
				mail_index_offset_to_uint32(rec->dir_offset);
		}
	}

	if (view->index->mmap_size <= sizeof(*view->index->hdr)) {
		/* root doesn't exist */
	} else if (!ctx->failed && offset != 0) {
		if (mailbox_list_index_get_dir(view, &offset,
					       &ctx->cur.dir) < 0)
			ctx->failed = TRUE;
	}
	i_array_init(&ctx->path, I_MIN(ctx->recurse_level, 16));
	return ctx;
}

int mailbox_list_index_iterate_next(struct mailbox_list_iter_ctx *ctx,
				    struct mailbox_list_index_info *info_r)
{
	const struct mailbox_list_iter_path *cur;
	const struct mailbox_list_record *recs;
	uint32_t dir_offset;
	unsigned int count;

	if (ctx->failed)
		return -1;

	if (ctx->cur.dir == NULL) {
		/* no mailboxes */
		i_assert(array_count(&ctx->path) == 0);
		return 0;
	}

	for (;;) {
		if (ctx->cur.pos == ctx->cur.dir->count) {
			count = array_count(&ctx->path);
			if (count == 0) {
				/* we're done */
				return 0;
			}

			/* go back to parent path */
			cur = array_idx(&ctx->path, count-1);
			ctx->cur = *cur;
			array_delete(&ctx->path, count-1, 1);

			ctx->cur.pos++;
		} else {
			recs = MAILBOX_LIST_RECORDS(ctx->cur.dir);
			recs += ctx->cur.pos;

			if (!recs->deleted && recs->uid <= ctx->max_uid)
				break;

			ctx->cur.pos++;
		}
	}

	T_BEGIN {
		const char *name;

		if (mailbox_list_get_name(ctx->view->index,
					  unsafe_data_stack_pool,
					  recs, &name) < 0)
			ctx->failed = TRUE;
		else {
			str_truncate(ctx->name_path, ctx->cur.name_path_len);
			if (ctx->cur.name_path_len > 0) {
				str_append_c(ctx->name_path,
					     ctx->view->index->separator);
			}
			str_append(ctx->name_path, name);
		}
	} T_END;
	if (ctx->failed)
		return -1;

	info_r->name = str_c(ctx->name_path);
	info_r->uid = recs->uid;

	dir_offset = mail_index_offset_to_uint32(recs->dir_offset);
	if (dir_offset != 0 && array_count(&ctx->path) < ctx->recurse_level) {
		/* recurse into children */
		array_append(&ctx->path, &ctx->cur, 1);

		ctx->cur.name_path_len = str_len(ctx->name_path);
		ctx->cur.pos = 0;
		if (mailbox_list_index_get_dir(ctx->view, &dir_offset,
					       &ctx->cur.dir) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		recs = NULL; /* don't use anymore */
	} else {
		ctx->cur.pos++;
	}
	info_r->has_children = dir_offset != 0;
	return 1;
}

void mailbox_list_index_iterate_deinit(struct mailbox_list_iter_ctx **_ctx)
{
	struct mailbox_list_iter_ctx *ctx = *_ctx;

	*_ctx = NULL;
	array_free(&ctx->path);
	str_free(&ctx->name_path);
	i_free(ctx);
}
