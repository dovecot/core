/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "buffer.h"
#include "eacces-error.h"
#include "hash.h"
#include "str-sanitize.h"
#include "mmap-util.h"
#include "nfs-workarounds.h"
#include "read-full.h"
#include "write-full.h"
#include "mail-index-alloc-cache.h"
#include "mail-index-private.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-index-modseq.h"
#include "mail-transaction-log-private.h"
#include "mail-transaction-log-view-private.h"
#include "mail-cache.h"

#include <stdio.h>
#include <stddef.h>
#include <time.h>
#include <sys/stat.h>

struct mail_index_module_register mail_index_module_register = { 0 };

struct event_category event_category_index = {
	.name = "index",
};

static void mail_index_close_nonopened(struct mail_index *index);

static const struct mail_index_optimization_settings default_optimization_set = {
	.index = {
		.rewrite_min_log_bytes = 8 * 1024,
		.rewrite_max_log_bytes = 128 * 1024,
	},
	.log = {
		.min_size = 32 * 1024,
		.max_size = 1024 * 1024,
		.min_age_secs = 5 * 60,
		.log2_max_age_secs = 3600 * 24 * 2,
	},
	.cache = {
		.unaccessed_field_drop_secs = 3600 * 24 * 30,
		.record_max_size = 64 * 1024,
		.max_size = 1024 * 1024 * 1024,
		.compress_min_size = 32 * 1024,
		.compress_delete_percentage = 20,
		.compress_continued_percentage = 200,
		.compress_header_continue_count = 4,
	},
};

struct mail_index *mail_index_alloc(struct event *parent_event,
				    const char *dir, const char *prefix)
{
	struct mail_index *index;

	index = i_new(struct mail_index, 1);
	index->dir = i_strdup(dir);
	index->prefix = i_strdup(prefix);
	index->fd = -1;
	index->event = event_create(parent_event);
	event_add_category(index->event, &event_category_index);

	index->extension_pool =
		pool_alloconly_create(MEMPOOL_GROWING"index extension", 1024);
	p_array_init(&index->extensions, index->extension_pool, 5);
	i_array_init(&index->sync_lost_handlers, 4);
	i_array_init(&index->module_contexts,
		     I_MIN(5, mail_index_module_register.id));

	index->mode = 0600;
	index->gid = (gid_t)-1;
	index->lock_method = FILE_LOCK_METHOD_FCNTL;
	index->max_lock_timeout_secs = UINT_MAX;
	index->optimization_set = default_optimization_set;

	index->keywords_ext_id =
		mail_index_ext_register(index, MAIL_INDEX_EXT_KEYWORDS,
					128, 2, 1);
	index->keywords_pool = pool_alloconly_create("keywords", 512);
	i_array_init(&index->keywords, 16);
	hash_table_create(&index->keywords_hash, index->keywords_pool, 0,
			  strcase_hash, strcasecmp);
	index->log = mail_transaction_log_alloc(index);
	mail_index_modseq_init(index);
	return index;
}

void mail_index_free(struct mail_index **_index)
{
	struct mail_index *index = *_index;

	*_index = NULL;

	i_assert(index->open_count == 0);

	mail_transaction_log_free(&index->log);
	hash_table_destroy(&index->keywords_hash);
	pool_unref(&index->extension_pool);
	pool_unref(&index->keywords_pool);

	array_free(&index->sync_lost_handlers);
	array_free(&index->keywords);
	array_free(&index->module_contexts);

	event_unref(&index->event);
	i_free(index->cache_dir);
	i_free(index->ext_hdr_init_data);
	i_free(index->gid_origin);
	i_free(index->error);
	i_free(index->dir);
	i_free(index->prefix);
	i_free(index->need_recreate);
	i_free(index);
}

void mail_index_set_cache_dir(struct mail_index *index, const char *dir)
{
	i_free(index->cache_dir);
	index->cache_dir = i_strdup(dir);
}

void mail_index_set_fsync_mode(struct mail_index *index,
			       enum fsync_mode mode,
			       enum mail_index_fsync_mask mask)
{
	index->fsync_mode = mode;
	index->fsync_mask = mask;
}

bool mail_index_use_existing_permissions(struct mail_index *index)
{
	struct stat st;

	if (MAIL_INDEX_IS_IN_MEMORY(index))
		return FALSE;

	if (stat(index->dir, &st) < 0) {
		if (errno != ENOENT)
			e_error(index->event, "stat(%s) failed: %m", index->dir);
		return FALSE;
	}

	index->mode = st.st_mode & 0666;
	if (S_ISDIR(st.st_mode) && (st.st_mode & S_ISGID) != 0) {
		/* directory's GID is used automatically for new files */
		index->gid = (gid_t)-1;
	} else if ((st.st_mode & 0070) >> 3 == (st.st_mode & 0007)) {
		/* group has same permissions as world, so don't bother
		   changing it */
		index->gid = (gid_t)-1;
	} else if (getegid() == st.st_gid) {
		/* using our own gid, no need to change it */
		index->gid = (gid_t)-1;
	} else {
		index->gid = st.st_gid;
	}

	i_free(index->gid_origin);
	if (index->gid != (gid_t)-1)
		index->gid_origin = i_strdup("preserved existing GID");
	return TRUE;
}

void mail_index_set_permissions(struct mail_index *index,
				mode_t mode, gid_t gid, const char *gid_origin)
{
	index->mode = mode & 0666;
	index->gid = gid;

	i_free(index->gid_origin);
	index->gid_origin = i_strdup(gid_origin);
}

void mail_index_set_lock_method(struct mail_index *index,
				enum file_lock_method lock_method,
				unsigned int max_timeout_secs)
{
	index->lock_method = lock_method;
	index->max_lock_timeout_secs = max_timeout_secs;
}

void mail_index_set_optimization_settings(struct mail_index *index,
	const struct mail_index_optimization_settings *set)
{
	struct mail_index_optimization_settings *dest =
		&index->optimization_set;

	/* index */
	if (set->index.rewrite_min_log_bytes != 0)
		dest->index.rewrite_min_log_bytes = set->index.rewrite_min_log_bytes;
	if (set->index.rewrite_max_log_bytes != 0)
		dest->index.rewrite_max_log_bytes = set->index.rewrite_max_log_bytes;

	/* log */
	if (set->log.min_size != 0)
		dest->log.min_size = set->log.min_size;
	if (set->log.max_size != 0)
		dest->log.max_size = set->log.max_size;
	if (set->log.min_age_secs != 0)
		dest->log.min_age_secs = set->log.min_age_secs;
	if (set->log.log2_max_age_secs != 0)
		dest->log.log2_max_age_secs = set->log.log2_max_age_secs;

	/* cache */
	if (set->cache.unaccessed_field_drop_secs != 0)
		dest->cache.unaccessed_field_drop_secs =
			set->cache.unaccessed_field_drop_secs;
	if (set->cache.max_size != 0)
		dest->cache.max_size = set->cache.max_size;
	if (set->cache.compress_min_size != 0)
		dest->cache.compress_min_size = set->cache.compress_min_size;
	if (set->cache.compress_delete_percentage != 0)
		dest->cache.compress_delete_percentage =
			set->cache.compress_delete_percentage;
	if (set->cache.compress_continued_percentage != 0)
		dest->cache.compress_continued_percentage =
			set->cache.compress_continued_percentage;
	if (set->cache.compress_header_continue_count != 0)
		dest->cache.compress_header_continue_count =
			set->cache.compress_header_continue_count;
	if (set->cache.record_max_size != 0)
		dest->cache.record_max_size = set->cache.record_max_size;
}

void mail_index_set_ext_init_data(struct mail_index *index, uint32_t ext_id,
				  const void *data, size_t size)
{
	const struct mail_index_registered_ext *rext;

	i_assert(index->ext_hdr_init_data == NULL ||
		 index->ext_hdr_init_id == ext_id);

	rext = array_idx(&index->extensions, ext_id);
	i_assert(rext->hdr_size == size);

	index->ext_hdr_init_id = ext_id;
	i_free(index->ext_hdr_init_data);
	index->ext_hdr_init_data = i_malloc(size);
	memcpy(index->ext_hdr_init_data, data, size);
}

uint32_t mail_index_ext_register(struct mail_index *index, const char *name,
				 uint32_t default_hdr_size,
				 uint16_t default_record_size,
				 uint16_t default_record_align)
{
	struct mail_index_registered_ext rext;
	uint32_t ext_id;

	if (*name == '\0' || strcmp(name, str_sanitize(name, -1)) != 0)
		i_panic("mail_index_ext_register(%s): Invalid name", name);

	if (default_record_size != 0 && default_record_align == 0) {
		i_panic("mail_index_ext_register(%s): "
			"Invalid record alignment", name);
	}

	if (mail_index_ext_lookup(index, name, &ext_id))
		return ext_id;

	i_zero(&rext);
	rext.name = p_strdup(index->extension_pool, name);
	rext.index_idx = array_count(&index->extensions);
	rext.hdr_size = default_hdr_size;
	rext.record_size = default_record_size;
	rext.record_align = default_record_align;

	array_push_back(&index->extensions, &rext);
	return rext.index_idx;
}

void mail_index_ext_register_resize_defaults(struct mail_index *index,
					     uint32_t ext_id,
					     uint32_t default_hdr_size,
					     uint16_t default_record_size,
					     uint16_t default_record_align)
{
	struct mail_index_registered_ext *rext;

	rext = array_idx_modifiable(&index->extensions, ext_id);
	rext->hdr_size = default_hdr_size;
	rext->record_size = default_record_size;
	rext->record_align = default_record_align;
}

bool mail_index_ext_lookup(struct mail_index *index, const char *name,
			   uint32_t *ext_id_r)
{
        const struct mail_index_registered_ext *extensions;
	unsigned int i, count;

	extensions = array_get(&index->extensions, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(extensions[i].name, name) == 0) {
			*ext_id_r = i;
			return TRUE;
		}
	}

	*ext_id_r = (uint32_t)-1;
	return FALSE;
}

void mail_index_register_expunge_handler(struct mail_index *index,
					 uint32_t ext_id, bool call_always,
					 mail_index_expunge_handler_t *cb,
					 void *context)
{
	struct mail_index_registered_ext *rext;

	rext = array_idx_modifiable(&index->extensions, ext_id);
	i_assert(rext->expunge_handler == NULL || rext->expunge_handler == cb);

	rext->expunge_handler = cb;
	rext->expunge_context = context;
	rext->expunge_handler_call_always = call_always;
}

void mail_index_unregister_expunge_handler(struct mail_index *index,
					   uint32_t ext_id)
{
	struct mail_index_registered_ext *rext;

	rext = array_idx_modifiable(&index->extensions, ext_id);
	i_assert(rext->expunge_handler != NULL);

	rext->expunge_handler = NULL;
}

void mail_index_register_sync_lost_handler(struct mail_index *index,
					   mail_index_sync_lost_handler_t *cb)
{
	array_push_back(&index->sync_lost_handlers, &cb);
}

void mail_index_unregister_sync_lost_handler(struct mail_index *index,
					     mail_index_sync_lost_handler_t *cb)
{
	mail_index_sync_lost_handler_t *const *handlers;
	unsigned int i, count;

	handlers = array_get(&index->sync_lost_handlers, &count);
	for (i = 0; i < count; i++) {
		if (handlers[i] == cb) {
			array_delete(&index->sync_lost_handlers, i, 1);
			break;
		}
	}
}

bool mail_index_keyword_lookup(struct mail_index *index,
			       const char *keyword, unsigned int *idx_r)
{
	char *key;
	void *value;

	/* keywords_hash keeps a name => index mapping of keywords.
	   Keywords are never removed from it, so the index values are valid
	   for the lifetime of the mail_index. */
	if (hash_table_lookup_full(index->keywords_hash, keyword,
				   &key, &value)) {
		*idx_r = POINTER_CAST_TO(value, unsigned int);
		return TRUE;
	}

	*idx_r = UINT_MAX;
	return FALSE;
}

void mail_index_keyword_lookup_or_create(struct mail_index *index,
					 const char *keyword,
					 unsigned int *idx_r)
{
	char *keyword_dup;

	i_assert(*keyword != '\0');

	if (mail_index_keyword_lookup(index, keyword, idx_r))
		return;

	keyword = keyword_dup = p_strdup(index->keywords_pool, keyword);
	*idx_r = array_count(&index->keywords);

	hash_table_insert(index->keywords_hash, keyword_dup,
			  POINTER_CAST(*idx_r));
	array_push_back(&index->keywords, &keyword);

	/* keep the array NULL-terminated, but the NULL itself invisible */
	array_append_zero(&index->keywords);
	array_pop_back(&index->keywords);
}

const ARRAY_TYPE(keywords) *mail_index_get_keywords(struct mail_index *index)
{
	return &index->keywords;
}

struct mail_keywords *
mail_index_keywords_create(struct mail_index *index,
			   const char *const keywords[])
{
	struct mail_keywords *k;
	unsigned int src, dest, i, count;

	count = str_array_length(keywords);
	if (count == 0) {
		k = i_new(struct mail_keywords, 1);
		k->index = index;
		k->refcount = 1;
		return k;
	}

	/* @UNSAFE */
	k = i_malloc(MALLOC_ADD(sizeof(struct mail_keywords),
				MALLOC_MULTIPLY(sizeof(k->idx[0]), count)));
	k->index = index;
	k->refcount = 1;

	/* look up the keywords from index. they're never removed from there
	   so we can permanently store indexes to them. */
	for (src = dest = 0; src < count; src++) {
		mail_index_keyword_lookup_or_create(index, keywords[src],
						    &k->idx[dest]);
		/* ignore if this is a duplicate */
		for (i = 0; i < src; i++) {
			if (k->idx[i] == k->idx[dest])
				break;
		}
		if (i == src)
			dest++;
	}
	k->count = dest;
	return k;
}

struct mail_keywords *
mail_index_keywords_create_from_indexes(struct mail_index *index,
					const ARRAY_TYPE(keyword_indexes)
						*keyword_indexes)
{
	struct mail_keywords *k;
	const unsigned int *indexes;
	unsigned int src, dest, i, count;

	indexes = array_get(keyword_indexes, &count);
	if (count == 0) {
		k = i_new(struct mail_keywords, 1);
		k->index = index;
		k->refcount = 1;
		return k;
	}

	/* @UNSAFE */
	k = i_malloc(MALLOC_ADD(sizeof(struct mail_keywords),
				MALLOC_MULTIPLY(sizeof(k->idx[0]), count)));
	k->index = index;
	k->refcount = 1;

	/* copy but skip duplicates */
	for (src = dest = 0; src < count; src++) {
		for (i = 0; i < src; i++) {
			if (k->idx[i] == indexes[src])
				break;
		}
		if (i == src)
			k->idx[dest++] = indexes[src];
	}
	k->count = dest;
	return k;
}

void mail_index_keywords_ref(struct mail_keywords *keywords)
{
	keywords->refcount++;
}

void mail_index_keywords_unref(struct mail_keywords **_keywords)
{
	struct mail_keywords *keywords = *_keywords;

	i_assert(keywords->refcount > 0);

	*_keywords = NULL;
	if (--keywords->refcount == 0)
		i_free(keywords);
}

int mail_index_try_open_only(struct mail_index *index)
{
	i_assert(index->fd == -1);
	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));

        /* Note that our caller must close index->fd by itself. */
	if (index->readonly)
		errno = EACCES;
	else {
		index->fd = nfs_safe_open(index->filepath, O_RDWR);
		index->readonly = FALSE;
	}

	if (index->fd == -1 && errno == EACCES) {
		index->fd = open(index->filepath, O_RDONLY);
		index->readonly = TRUE;
	}

	if (index->fd == -1) {
		if (errno != ENOENT) {
			mail_index_set_syscall_error(index, "open()");
			return -1;
		}

		/* have to create it */
		return 0;
	}
	return 1;
}

static int
mail_index_try_open(struct mail_index *index)
{
	int ret;

        i_assert(index->fd == -1);

	if (MAIL_INDEX_IS_IN_MEMORY(index))
		return 0;

	ret = mail_index_map(index, MAIL_INDEX_SYNC_HANDLER_HEAD);
	if (ret == 0) {
		/* it's corrupted - recreate it */
		if (index->fd != -1) {
			if (close(index->fd) < 0)
				mail_index_set_syscall_error(index, "close()");
			index->fd = -1;
		}
	}
	return ret;
}

int mail_index_create_tmp_file(struct mail_index *index,
			       const char *path_prefix, const char **path_r)
{
        mode_t old_mask;
	const char *path;
	int fd;

	i_assert(!MAIL_INDEX_IS_IN_MEMORY(index));

	path = *path_r = t_strconcat(path_prefix, ".tmp", NULL);
	old_mask = umask(0);
	fd = open(path, O_RDWR|O_CREAT|O_EXCL, index->mode);
	umask(old_mask);
	if (fd == -1 && errno == EEXIST) {
		/* stale temp file. unlink and recreate rather than overwriting,
		   just to make sure locking problems won't cause corruption */
		if (i_unlink(path) < 0)
			return -1;
		old_mask = umask(0);
		fd = open(path, O_RDWR|O_CREAT|O_EXCL, index->mode);
		umask(old_mask);
	}
	if (fd == -1) {
		mail_index_file_set_syscall_error(index, path, "creat()");
		return -1;
	}

	mail_index_fchown(index, fd, path);
	return fd;
}

static const char *mail_index_get_cache_path(struct mail_index *index)
{
	const char *dir;

	if (index->cache_dir != NULL)
		dir = index->cache_dir;
	else if (index->dir != NULL)
		dir = index->dir;
	else
		return NULL;
	return t_strconcat(dir, "/", index->prefix,
			   MAIL_CACHE_FILE_SUFFIX, NULL);
}

static int mail_index_open_files(struct mail_index *index,
				 enum mail_index_open_flags flags)
{
	int ret;

	ret = mail_transaction_log_open(index->log);
	if (ret == 0) {
		if ((flags & MAIL_INDEX_OPEN_FLAG_CREATE) == 0)
			return 0;

		/* if dovecot.index exists, read it first so that we can get
		   the correct indexid and log sequence */
		(void)mail_index_try_open(index);

		if (index->indexid == 0) {
			/* Create a new indexid for us. If we're opening index
			   into memory, index->map doesn't exist yet. */
			index->indexid = ioloop_time;
			index->initial_create = TRUE;
			if (index->map != NULL)
				index->map->hdr.indexid = index->indexid;
		}

		ret = mail_transaction_log_create(index->log, FALSE);
		if (index->map != NULL) {
			/* log creation could have changed it if someone else
			   just created it. */
			index->map->hdr.indexid = index->indexid;
		}
		index->initial_create = FALSE;
	}
	if (ret >= 0) {
		ret = index->map != NULL ? 1 : mail_index_try_open(index);
		if (ret == 0) {
			/* corrupted */
			mail_transaction_log_close(index->log);
			ret = mail_transaction_log_create(index->log, TRUE);
			if (ret == 0) {
				if (index->map != NULL)
					mail_index_unmap(&index->map);
				index->map = mail_index_map_alloc(index);
			}
		}
	}
	if (ret < 0) {
		/* open/create failed, fallback to in-memory indexes */
		if ((flags & MAIL_INDEX_OPEN_FLAG_CREATE) == 0)
			return -1;

		if (mail_index_move_to_memory(index) < 0)
			return -1;
	}

	if (index->cache == NULL) {
		const char *path = mail_index_get_cache_path(index);
		index->cache = mail_cache_open_or_create_path(index, path);
	}
	return 1;
}

static int
mail_index_open_opened(struct mail_index *index,
		       enum mail_index_open_flags flags)
{
	int ret;

	i_assert(index->map != NULL);

	if ((index->map->hdr.flags & MAIL_INDEX_HDR_FLAG_CORRUPTED) != 0) {
		/* index was marked corrupted. we'll probably need to
		   recreate the files. */
		mail_index_unmap(&index->map);
		mail_index_close_file(index);
		mail_transaction_log_close(index->log);
		if ((ret = mail_index_open_files(index, flags)) <= 0)
			return ret;
	}

	index->open_count++;
	return 1;
}

int mail_index_open(struct mail_index *index, enum mail_index_open_flags flags)
{
	int ret;

	if (index->open_count > 0) {
		if ((ret = mail_index_open_opened(index, flags)) <= 0) {
			/* doesn't exist and create flag not used */
		}
		return ret;
	}

	index->filepath = MAIL_INDEX_IS_IN_MEMORY(index) ?
		i_strdup("(in-memory index)") :
		i_strconcat(index->dir, "/", index->prefix, NULL);

	index->readonly = FALSE;
	index->nodiskspace = FALSE;
	index->index_lock_timeout = FALSE;
	index->log_sync_locked = FALSE;
	index->flags = flags;
	index->readonly = (flags & MAIL_INDEX_OPEN_FLAG_READONLY) != 0;
	if ((flags & MAIL_INDEX_OPEN_FLAG_DEBUG) != 0)
		event_set_forced_debug(index->event, TRUE);
	else
		event_unset_forced_debug(index->event);

	if ((flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) != 0 &&
	    index->fsync_mode != FSYNC_MODE_ALWAYS)
		i_fatal("nfs flush requires mail_fsync=always");
	if ((flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) != 0 &&
	    (flags & MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE) == 0)
		i_fatal("nfs flush requires mmap_disable=yes");

	/* NOTE: increase open_count only after mail_index_open_files().
	   it's used elsewhere to check if we're doing an initial opening
	   of the index files */
	if ((ret = mail_index_open_files(index, flags)) <= 0) {
		/* doesn't exist and create flag not used */
		mail_index_close_nonopened(index);
		return ret;
	}

	index->open_count++;

	if (index->log->head == NULL) {
		mail_index_close(index);
		mail_index_set_error(index, "Index is corrupted "
					    "(log->view->head == NULL)");
		return -1;
	}

	i_assert(index->map != NULL);
	mail_index_alloc_cache_index_opened(index);
	return 1;
}

int mail_index_open_or_create(struct mail_index *index,
			      enum mail_index_open_flags flags)
{
	int ret;

	flags |= MAIL_INDEX_OPEN_FLAG_CREATE;
	ret = mail_index_open(index, flags);
	i_assert(ret != 0);
	return ret < 0 ? -1 : 0;
}

void mail_index_close_file(struct mail_index *index)
{
	if (index->fd != -1) {
		if (close(index->fd) < 0)
			mail_index_set_syscall_error(index, "close()");
		index->fd = -1;
	}
}

static void mail_index_close_nonopened(struct mail_index *index)
{
	i_assert(!index->syncing);

	if (index->views != NULL) {
		i_panic("Leaked view for index %s: Opened in %s:%u",
			index->filepath, index->views->source_filename,
			index->views->source_linenum);
	}
	i_assert(index->views == NULL);

	if (index->map != NULL)
		mail_index_unmap(&index->map);

	mail_index_close_file(index);
	mail_transaction_log_close(index->log);
	if (index->cache != NULL)
		mail_cache_free(&index->cache);

	i_free_and_null(index->filepath);

	index->indexid = 0;
}

void mail_index_close(struct mail_index *index)
{
	i_assert(index->open_count > 0);

	mail_index_alloc_cache_index_closing(index);
	if (--index->open_count == 0)
		mail_index_close_nonopened(index);
}

int mail_index_unlink(struct mail_index *index)
{
	const char *path;
	int last_errno = 0;

	if (MAIL_INDEX_IS_IN_MEMORY(index) || index->readonly)
		return 0;

	/* main index */
	if (unlink(index->filepath) < 0 && errno != ENOENT)
		last_errno = errno;

	/* logs */
	path = t_strconcat(index->filepath, MAIL_TRANSACTION_LOG_SUFFIX, NULL);
	if (unlink(path) < 0 && errno != ENOENT)
		last_errno = errno;

	path = t_strconcat(index->filepath,
			   MAIL_TRANSACTION_LOG_SUFFIX".2", NULL);
	if (unlink(path) < 0 && errno != ENOENT)
		last_errno = errno;

	/* cache */
	path = t_strconcat(index->filepath, MAIL_CACHE_FILE_SUFFIX, NULL);
	if (unlink(path) < 0 && errno != ENOENT)
		last_errno = errno;

	if (last_errno == 0)
		return 0;
	else {
		errno = last_errno;
		return -1;
	}
}

int mail_index_reopen_if_changed(struct mail_index *index,
				 const char **reason_r)
{
	struct stat st1, st2;
	int ret;

	if (MAIL_INDEX_IS_IN_MEMORY(index)) {
		*reason_r = "in-memory index";
		return 0;
	}

	if (index->fd == -1)
		goto final;

	if ((index->flags & MAIL_INDEX_OPEN_FLAG_NFS_FLUSH) != 0)
		nfs_flush_file_handle_cache(index->filepath);
	if (nfs_safe_stat(index->filepath, &st2) < 0) {
		if (errno == ENOENT) {
			*reason_r = "index not found via stat()";
			return 0;
		}
		mail_index_set_syscall_error(index, "stat()");
		return -1;
	}

	if (fstat(index->fd, &st1) < 0) {
		if (!ESTALE_FSTAT(errno)) {
			mail_index_set_syscall_error(index, "fstat()");
			return -1;
		}
		/* deleted/recreated, reopen */
		*reason_r = "index is stale";
	} else if (st1.st_ino == st2.st_ino &&
		   CMP_DEV_T(st1.st_dev, st2.st_dev)) {
		/* the same file */
		*reason_r = "index unchanged";
		return 1;
	} else {
		*reason_r = "index inode changed";
	}

	/* new file, new locks. the old fd can keep its locks, they don't
	   matter anymore as no-one's going to modify the file. */
	mail_index_close_file(index);

final:
	if ((ret = mail_index_try_open_only(index)) == 0)
		*reason_r = "index not found via open()";
	else if (ret > 0)
		*reason_r = "index opened";
	return ret;
}

int mail_index_refresh(struct mail_index *index)
{
	int ret;

	ret = mail_index_map(index, MAIL_INDEX_SYNC_HANDLER_HEAD);
	return ret <= 0 ? -1 : 0;
}

struct mail_cache *mail_index_get_cache(struct mail_index *index)
{
	return index->cache;
}

void mail_index_set_error(struct mail_index *index, const char *fmt, ...)
{
	va_list va;

	i_free(index->error);

	if (fmt == NULL)
		index->error = NULL;
	else {
		va_start(va, fmt);
		index->error = i_strdup_vprintf(fmt, va);
		va_end(va);

		e_error(index->event, "%s", index->error);
	}
}

void mail_index_set_error_nolog(struct mail_index *index, const char *str)
{
	i_assert(str != NULL);

	char *old_error = index->error;
	index->error = i_strdup(str);
	i_free(old_error);
}

bool mail_index_is_in_memory(struct mail_index *index)
{
	return MAIL_INDEX_IS_IN_MEMORY(index);
}

static void mail_index_set_as_in_memory(struct mail_index *index)
{
	i_free_and_null(index->dir);

	i_free(index->filepath);
	index->filepath = i_strdup("(in-memory index)");
}

int mail_index_move_to_memory(struct mail_index *index)
{
	struct mail_index_map *map;

	if (MAIL_INDEX_IS_IN_MEMORY(index))
		return index->map == NULL ? -1 : 0;

	if ((index->flags & MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY) != 0)
		return -1;

	if (index->map == NULL) {
		/* index was never even opened. just mark it as being in
		   memory and let the caller re-open the index. */
		i_assert(index->fd == -1);
		mail_index_set_as_in_memory(index);
		return -1;
	}

	/* move index map to memory */
	if (!MAIL_INDEX_MAP_IS_IN_MEMORY(index->map)) {
		map = mail_index_map_clone(index->map);
		mail_index_unmap(&index->map);
		index->map = map;
	}

	if (index->log != NULL) {
		/* move transaction log to memory */
		if (mail_transaction_log_move_to_memory(index->log) < 0)
			return -1;
	}

	if (index->fd != -1) {
		if (close(index->fd) < 0)
			mail_index_set_syscall_error(index, "close()");
		index->fd = -1;
	}
	mail_index_set_as_in_memory(index);
	return 0;
}

void mail_index_mark_corrupted(struct mail_index *index)
{
	index->indexid = 0;

	index->map->hdr.flags |= MAIL_INDEX_HDR_FLAG_CORRUPTED;
	if (!index->readonly) {
		if (unlink(index->filepath) < 0 &&
		    errno != ENOENT && errno != ESTALE)
			mail_index_set_syscall_error(index, "unlink()");
		(void)mail_transaction_log_unlink(index->log);
	}
}

bool mail_index_is_deleted(struct mail_index *index)
{
	return index->index_delete_requested || index->index_deleted;
}

int mail_index_get_modification_time(struct mail_index *index, time_t *mtime_r)
{
	struct stat st;
	const char *path;

	*mtime_r = 0;
	if (MAIL_INDEX_IS_IN_MEMORY(index)) {
		/* this function doesn't make sense for in-memory indexes */
		return 0;
	}

	/* index may not be open, so index->filepath may be NULL */
	path = t_strconcat(index->dir, "/", index->prefix,
			   MAIL_TRANSACTION_LOG_SUFFIX, NULL);
	if (stat(path, &st) < 0) {
		if (errno == ENOENT) {
			/* .log is always supposed to exist - don't bother
			   trying to stat(dovecot.index) */
			return 0;
		}
		mail_index_file_set_syscall_error(index, path, "stat()");
		return -1;
	}
	*mtime_r = st.st_mtime;
	return 0;
}

void mail_index_fchown(struct mail_index *index, int fd, const char *path)
{
	mode_t mode;

	if (index->gid == (gid_t)-1) {
		/* no gid changing */
		return;
	} else if (fchown(fd, (uid_t)-1, index->gid) == 0) {
		/* success */
		return;
	} if ((index->mode & 0060) >> 3 == (index->mode & 0006)) {
		/* group and world permissions are the same, so group doesn't
		   really matter. ignore silently. */
		return;
	}
	if (errno != EPERM)
		mail_index_file_set_syscall_error(index, path, "fchown()");
	else {
		mail_index_set_error(index, "%s",
			eperm_error_get_chgrp("fchown", path, index->gid,
					      index->gid_origin));
	}

	/* continue, but change permissions so that only the common
	   subset of group and world is used. this makes sure no one
	   gets any extra permissions. */
	mode = ((index->mode & 0060) >> 3) & (index->mode & 0006);
	mode |= (mode << 3) | (index->mode & 0600);
	if (fchmod(fd, mode) < 0)
		mail_index_file_set_syscall_error(index, path, "fchmod()");
}

void mail_index_set_syscall_error(struct mail_index *index,
				  const char *function)
{
	mail_index_file_set_syscall_error(index, index->filepath, function);
}

void mail_index_file_set_syscall_error(struct mail_index *index,
				       const char *filepath,
				       const char *function)
{
	const char *errstr;

	i_assert(filepath != NULL);
	i_assert(function != NULL);

	if (errno == ENOENT) {
		struct stat st;
		int old_errno = errno;
		i_assert(index->log->filepath != NULL);
		if (nfs_safe_stat(index->log->filepath, &st) < 0 &&
		    errno == ENOENT) {
			/* the index log has gone away */
			index->index_deleted = TRUE;
			errno = old_errno;
			return;
		}
		errno = old_errno;
	}

	if (ENOSPACE(errno)) {
		index->nodiskspace = TRUE;
		if ((index->flags & MAIL_INDEX_OPEN_FLAG_NEVER_IN_MEMORY) == 0)
			return;
	}

	if (errno == EACCES) {
		function = t_strcut(function, '(');
		if (strcmp(function, "creat") == 0 ||
		    str_begins(function, "file_dotlock_"))
			errstr = eacces_error_get_creating(function, filepath);
		else
			errstr = eacces_error_get(function, filepath);
		mail_index_set_error(index, "%s", errstr);
	} else {
		const char *suffix = errno != EFBIG ? "" :
			" (process was started with ulimit -f limit)";
		mail_index_set_error(index, "%s failed with file %s: "
				     "%m%s", function, filepath, suffix);
	}
}

const char *mail_index_get_error_message(struct mail_index *index)
{
	return index->error;
}

void mail_index_reset_error(struct mail_index *index)
{
	if (index->error != NULL) {
		i_free(index->error);
		index->error = NULL;
	}

	index->nodiskspace = FALSE;
        index->index_lock_timeout = FALSE;
}
