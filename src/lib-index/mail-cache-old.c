static const char *
mail_cache_get_header_fields_str(struct mail_cache *cache, unsigned int idx);
static int mail_cache_write(struct mail_cache_transaction_ctx *ctx);
static struct mail_cache_record *
mail_cache_lookup(struct mail_cache *cache,
		  const struct mail_index_record *rec,
		  enum mail_cache_field fields);

static void mail_cache_file_close(struct mail_cache *cache)
{
	if (cache->mmap_base != NULL) {
		if (munmap(cache->mmap_base, cache->mmap_length) < 0)
			mail_cache_set_syscall_error(cache, "munmap()");
	}

	cache->mmap_base = NULL;
	cache->hdr = NULL;
	cache->mmap_length = 0;

	if (cache->fd != -1) {
		if (close(cache->fd) < 0)
			mail_cache_set_syscall_error(cache, "close()");
		cache->fd = -1;
	}
}

static int mail_cache_file_reopen(struct mail_cache *cache)
{
	int fd;

	fd = open(cache->filepath, O_RDWR);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "open()");
		return -1;
	}

	mail_cache_file_close(cache);

	cache->fd = fd;
	return 0;
}

static int mmap_verify_header(struct mail_cache *cache)
{
	struct mail_cache_header *hdr;

	/* check that the header is still ok */
	if (cache->mmap_length < sizeof(struct mail_cache_header)) {
		mail_cache_set_corrupted(cache, "File too small");
		return 0;
	}
	cache->hdr = hdr = cache->mmap_base;

	if (cache->hdr->indexid != cache->index->indexid) {
		/* index id changed */
		if (cache->hdr->indexid != 0)
			mail_cache_set_corrupted(cache, "indexid changed");
		return 0;
	}

	if (cache->trans_ctx != NULL) {
		/* we've updated used_file_size, do nothing */
		return 1;
	}

	cache->used_file_size = nbo_to_uint32(hdr->used_file_size);

	/* only check the header if we're locked */
	if (cache->locks == 0)
		return 1;

	if (cache->used_file_size < sizeof(struct mail_cache_header)) {
		mail_cache_set_corrupted(cache, "used_file_size too small");
		return 0;
	}
	if ((cache->used_file_size % sizeof(uint32_t)) != 0) {
		mail_cache_set_corrupted(cache, "used_file_size not aligned");
		return 0;
	}

	if (cache->used_file_size > cache->mmap_length) {
		/* maybe a crash truncated the file - just fix it */
		hdr->used_file_size = uint32_to_nbo(cache->mmap_length & ~3);
		if (msync(cache->mmap_base, sizeof(*hdr), MS_SYNC) < 0) {
			mail_cache_set_syscall_error(cache, "msync()");
			return -1;
		}
	}
	return 1;
}

static int mmap_update_nocheck(struct mail_cache *cache,
			       size_t offset, size_t size)
{
	struct stat st;

	/* if sequence has changed, the file has to be reopened.
	   note that if main index isn't locked, it may change again */
	if (cache->hdr->file_seq != cache->index->hdr->cache_file_seq &&
	    cache->mmap_base != NULL) {
		if (!mail_cache_file_reopen(cache))
			return -1;
	}

	if (offset < cache->mmap_length &&
	    size <= cache->mmap_length - offset &&
	    !cache->mmap_refresh) {
		/* already mapped */
		if (size != 0 || cache->anon_mmap)
			return 1;

		/* requesting the whole file - see if we need to
		   re-mmap */
		if (fstat(cache->fd, &st) < 0) {
			mail_cache_set_syscall_error(cache, "fstat()");
			return -1;
		}
		if ((uoff_t)st.st_size == cache->mmap_length)
			return 1;
	}
	cache->mmap_refresh = FALSE;

	if (cache->anon_mmap)
		return 1;

	if (cache->mmap_base != NULL) {
		if (cache->locks != 0) {
			/* in the middle of transaction - write the changes */
			if (msync(cache->mmap_base, cache->mmap_length,
				  MS_SYNC) < 0) {
				mail_cache_set_syscall_error(cache, "msync()");
				return -1;
			}
		}

		if (munmap(cache->mmap_base, cache->mmap_length) < 0)
			mail_cache_set_syscall_error(cache, "munmap()");
	}

	i_assert(cache->fd != -1);

	/* map the whole file */
	cache->hdr = NULL;
	cache->mmap_length = 0;

	cache->mmap_base = mmap_rw_file(cache->fd, &cache->mmap_length);
	if (cache->mmap_base == MAP_FAILED) {
		cache->mmap_base = NULL;
		mail_cache_set_syscall_error(cache, "mmap()");
		return -1;
	}

	/* re-mmaped, check header */
	return 0;
}

static int mmap_update(struct mail_cache *cache, size_t offset, size_t size)
{
	int synced, ret;

	for (synced = FALSE;; synced = TRUE) {
		ret = mmap_update_nocheck(cache, offset, size);
		if (ret > 0)
			return TRUE;
		if (ret < 0)
			return FALSE;

		if (!mmap_verify_header(cache))
			return FALSE;

		/* see if cache file was rebuilt - do it only once to avoid
		   infinite looping */
		if (cache->hdr->sync_id == cache->index->cache_sync_id ||
		    synced)
			break;

		if (!mail_cache_file_reopen(cache))
			return FALSE;
	}
	return TRUE;
}

static int mail_cache_open_and_verify(struct mail_cache *cache, int silent)
{
	struct stat st;

	mail_cache_file_close(cache);

	cache->fd = open(cache->filepath, O_RDWR);
	if (cache->fd == -1) {
		if (errno == ENOENT)
			return 0;

		mail_cache_set_syscall_error(cache, "open()");
		return -1;
	}

	if (fstat(cache->fd, &st) < 0) {
		mail_cache_set_syscall_error(cache, "fstat()");
		return -1;
	}

	if (st.st_size < sizeof(struct mail_cache_header))
		return 0;

	cache->mmap_refresh = TRUE;
	if (mmap_update_nocheck(cache, 0, sizeof(struct mail_cache_header)) < 0)
		return -1;

	/* verify that this really is the cache for wanted index */
	cache->silent = silent;
	if (!mmap_verify_header(cache)) {
		cache->silent = FALSE;
		return 0;
	}

	cache->silent = FALSE;
	return 1;
}

static int mail_cache_open_or_create_file(struct mail_cache *cache,
					  struct mail_cache_header *hdr)
{
	int ret, fd;

	cache->filepath = i_strconcat(cache->index->filepath,
				      MAIL_CACHE_FILE_PREFIX, NULL);

	ret = mail_cache_open_and_verify(cache, FALSE);
	if (ret != 0)
		return ret > 0;

	/* we'll have to clear cache_offsets which requires exclusive lock */
	if (!mail_index_set_lock(cache->index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* maybe a rebuild.. */
	fd = file_dotlock_open(cache->filepath, NULL, MAIL_CACHE_LOCK_TIMEOUT,
			       MAIL_CACHE_LOCK_CHANGE_TIMEOUT,
			       MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "file_dotlock_open()");
		return FALSE;
	}

	/* see if someone else just created the cache file */
	ret = mail_cache_open_and_verify(cache, TRUE);
	if (ret != 0) {
		(void)file_dotlock_delete(cache->filepath, fd);
		return ret > 0;
	}

	/* rebuild then */
	if (write_full(fd, hdr, sizeof(*hdr)) < 0) {
		mail_cache_set_syscall_error(cache, "write_full()");
		(void)file_dotlock_delete(cache->filepath, fd);
		return FALSE;
	}
	if (file_set_size(fd, MAIL_CACHE_INITIAL_SIZE) < 0) {
		mail_cache_set_syscall_error(cache, "file_set_size()");
		(void)file_dotlock_delete(cache->filepath, fd);
		return FALSE;
	}

	if (cache->index->hdr.cache_file_seq != 0) {
		// FIXME: recreate index file with cache_offsets cleared
	}

	mail_cache_file_close(cache);
	cache->fd = dup(fd);

	if (file_dotlock_replace(cache->filepath, fd, FALSE) < 0) {
		mail_cache_set_syscall_error(cache, "file_dotlock_replace()");
		return FALSE;
	}

	if (!mmap_update(cache, 0, sizeof(struct mail_cache_header)))
		return FALSE;

	return TRUE;
}

int mail_cache_open_or_create(struct mail_index *index)
{
        struct mail_cache_header hdr;
	struct mail_cache *cache;

	memset(&hdr, 0, sizeof(hdr));
	hdr.indexid = index->indexid;
	hdr.sync_id = index->hdr->cache_file_seq; // FIXME
	hdr.used_file_size = uint32_to_nbo(sizeof(hdr));

	cache = i_new(struct mail_cache, 1);
	cache->index = index;
	cache->fd = -1;
        cache->split_header_pool = pool_alloconly_create("Headers", 512);

	index->cache = cache;

	/* we'll do anon-mmaping only if initially requested. if we fail
	   because of out of disk space, we'll just let the main index code
	   know it and fail. */
	if (!mail_cache_open_or_create_file(cache, &hdr)) {
		mail_cache_free(cache);
		return FALSE;
	}

	return TRUE;
}

void mail_cache_free(struct mail_cache *cache)
{
	i_assert(cache->trans_ctx == NULL);

	cache->index->cache = NULL;

	mail_cache_file_close(cache);

	pool_unref(cache->split_header_pool);
	i_free(cache->filepath);
	i_free(cache);
}

void mail_cache_set_defaults(struct mail_cache *cache,
			     enum mail_cache_field default_cache_fields,
			     enum mail_cache_field never_cache_fields)
{
	cache->default_cache_fields = default_cache_fields;
	cache->never_cache_fields = never_cache_fields;
}

int mail_cache_reset(struct mail_cache *cache)
{
	struct mail_cache_header hdr;
	int ret, fd;

	i_assert(cache->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	memset(&hdr, 0, sizeof(hdr));
	hdr.indexid = cache->index->indexid;
	hdr.sync_id = cache->sync_id = cache->index->cache_sync_id =
		++cache->index->hdr->cache_sync_id;
	hdr.used_file_size = uint32_to_nbo(sizeof(hdr));
	cache->used_file_size = sizeof(hdr);

	fd = file_dotlock_open(cache->filepath, NULL, MAIL_CACHE_LOCK_TIMEOUT,
			       MAIL_CACHE_LOCK_CHANGE_TIMEOUT,
			       MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "file_dotlock_open()");
		return -1;
	}

	if (write_full(fd, &hdr, sizeof(hdr)) < 0) {
		mail_cache_set_syscall_error(cache, "write_full()");
		(void)file_dotlock_delete(cache->filepath, fd);
		return -1;
	}
	if (file_set_size(fd, MAIL_CACHE_INITIAL_SIZE) < 0) {
		mail_cache_set_syscall_error(cache, "file_set_size()");
		(void)file_dotlock_delete(cache->filepath, fd);
		return -1;
	}

	mail_cache_file_close(cache);
	cache->fd = dup(fd);

	if (file_dotlock_replace(cache->filepath, fd, FALSE) < 0) {
		mail_cache_set_syscall_error(cache, "file_dotlock_replace()");
		return -1;
	}

	cache->mmap_refresh = TRUE;
	if (!mmap_update(cache, 0, sizeof(struct mail_cache_header)))
		return -1;

	return 0;
}

int mail_cache_lock(struct mail_cache *cache, int nonblock)
{
	int ret;

	if (cache->locks++ != 0)
		return TRUE;

	if (cache->anon_mmap)
		return TRUE;

	if (nonblock) {
		ret = file_try_lock(cache->fd, F_WRLCK);
		if (ret < 0)
			mail_cache_set_syscall_error(cache, "file_try_lock()");
	} else {
		ret = file_wait_lock(cache->fd, F_WRLCK);
		if (ret <= 0)
			mail_cache_set_syscall_error(cache, "file_wait_lock()");
	}

	if (ret > 0) {
		if (!mmap_update(cache, 0, 0)) {
			(void)mail_cache_unlock(cache);
			return -1;
		}
		if (cache->sync_id != cache->index->cache_sync_id) {
			/* we have the cache file locked and sync_id still
			   doesn't match. it means we crashed between updating
			   cache file and updating sync_id in index header.
			   just update the sync_ids so they match. */
			i_warning("Updating broken sync_id in cache file %s",
				  cache->filepath);
			cache->sync_id = cache->hdr->sync_id =
				cache->index->cache_sync_id;
		}
	}
	return ret;
}

int mail_cache_unlock(struct mail_cache *cache)
{
	if (--cache->locks > 0)
		return TRUE;

	if (cache->anon_mmap)
		return TRUE;

	if (file_wait_lock(cache->fd, F_UNLCK) <= 0) {
		mail_cache_set_syscall_error(cache, "file_wait_lock(F_UNLCK)");
		return FALSE;
	}

	return TRUE;
}

int mail_cache_is_locked(struct mail_cache *cache)
{
	return cache->locks > 0;
}

struct mail_cache_view *
mail_cache_view_open(struct mail_cache *cache, struct mail_index_view *view)
{
	struct mail_cache_view *view;

	view = i_new(struct mail_cache_view, 1);
	view->cache = cache;
	view->view = view;
	return view;
}

void mail_cache_view_close(struct mail_cache_view *view)
{
	i_free(view);
}

static const char *
mail_cache_get_header_fields_str(struct mail_cache *cache, unsigned int idx)
{
	uint32_t offset, data_size;
	unsigned char *buf;

	offset = offset_to_uint32(cache->hdr->header_offsets[idx]);

	if (offset == 0)
		return NULL;

	if (!mmap_update(cache, offset, 1024))
		return NULL;

	if (offset + sizeof(data_size) > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "Header %u points outside file",
					 idx);
		return NULL;
	}

	buf = cache->mmap_base;
	memcpy(&data_size, buf + offset, sizeof(data_size));
	data_size = nbo_to_uint32(data_size);
	offset += sizeof(data_size);

	if (data_size == 0) {
		mail_cache_set_corrupted(cache,
			"Header %u points to empty string", idx);
		return NULL;
	}

	if (!mmap_update(cache, offset, data_size))
		return NULL;

	if (offset + data_size > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "Header %u points outside file",
					 idx);
		return NULL;
	}

	buf = cache->mmap_base;
	if (buf[offset + data_size - 1] != '\0') {
		mail_cache_set_corrupted(cache,
			"Header %u points to invalid string", idx);
		return NULL;
	}

	return buf + offset;
}

static const char *const *
split_header(struct mail_cache *cache, const char *header)
{
	const char *const *arr, *const *tmp;
	const char *null = NULL;
	char *str;
	buffer_t *buf;

	if (header == NULL)
		return NULL;

	arr = t_strsplit(header, "\n");
	buf = buffer_create_dynamic(cache->split_header_pool, 32, (size_t)-1);
	for (tmp = arr; *tmp != NULL; tmp++) {
		str = p_strdup(cache->split_header_pool, *tmp);
		buffer_append(buf, &str, sizeof(str));
	}
	buffer_append(buf, &null, sizeof(null));

	return buffer_get_data(buf, NULL);
}

const char *const *mail_cache_get_header_fields(struct mail_cache *cache,
						unsigned int idx)
{
	const char *str;
	int i;

	i_assert(idx < MAIL_CACHE_HEADERS_COUNT);

	/* t_strsplit() is a bit slow, so we cache it */
	if (cache->hdr->header_offsets[idx] != cache->split_offsets[idx]) {
		p_clear(cache->split_header_pool);

		t_push();
		for (i = 0; i < MAIL_CACHE_HEADERS_COUNT; i++) {
			cache->split_offsets[i] =
				cache->hdr->header_offsets[i];

			str = mail_cache_get_header_fields_str(cache, i);
			cache->split_headers[i] = split_header(cache, str);
		}
		t_pop();
	}

	return cache->split_headers[idx];
}

static const char *write_header_string(const char *const headers[],
				       uint32_t *size_r)
{
	buffer_t *buffer;
	size_t size;

	buffer = buffer_create_dynamic(pool_datastack_create(),
				       512, (size_t)-1);

	while (*headers != NULL) {
		if (buffer_get_used_size(buffer) != 0)
			buffer_append(buffer, "\n", 1);
		buffer_append(buffer, *headers, strlen(*headers));
		headers++;
	}
	buffer_append(buffer, null4, 1);

	size = buffer_get_used_size(buffer);
	if ((size & 3) != 0) {
		buffer_append(buffer, null4, 4 - (size & 3));
		size += 4 - (size & 3);
	}
	*size_r = size;
	return buffer_get_data(buffer, NULL);
}

int mail_cache_set_header_fields(struct mail_cache_transaction_ctx *ctx,
				 unsigned int idx, const char *const headers[])
{
	struct mail_cache *cache = ctx->cache;
	uint32_t offset, update_offset, size;
	const char *header_str, *prev_str;

	i_assert(*headers != NULL);
	i_assert(idx < MAIL_CACHE_HEADERS_COUNT);
	i_assert(idx >= ctx->next_unused_header_lowwater);
	i_assert(offset_to_uint32(cache->hdr->header_offsets[idx]) == 0);

	t_push();

	header_str = write_header_string(headers, &size);
	if (idx != 0) {
		prev_str = mail_cache_get_header_fields_str(cache, idx-1);
		if (prev_str == NULL) {
			t_pop();
			return FALSE;
		}

		i_assert(strcmp(header_str, prev_str) != 0);
	}

	offset = mail_cache_append_space(ctx, size + sizeof(uint32_t));
	if (offset != 0) {
		memcpy((char *) cache->mmap_base + offset + sizeof(uint32_t),
		       header_str, size);

		size = uint32_to_nbo(size);
		memcpy((char *) cache->mmap_base + offset,
		       &size, sizeof(uint32_t));

		/* update cached headers */
		cache->split_offsets[idx] = cache->hdr->header_offsets[idx];
		cache->split_headers[idx] = split_header(cache, header_str);

		/* mark used-bit to be updated later. not really needed for
		   read-safety, but if transaction get rolled back we can't let
		   this point to invalid location. */
		update_offset = (char *) &cache->hdr->header_offsets[idx] -
			(char *) cache->mmap_base;
		mark_update(&ctx->cache_marks, update_offset,
			    uint32_to_offset(offset));

		/* make sure get_header_fields() still works for this header
		   while the transaction isn't yet committed. */
		ctx->next_unused_header_lowwater = idx + 1;
	}

	t_pop();
	return offset > 0;
}

static struct mail_cache_record *
cache_get_record(struct mail_cache *cache, uint32_t offset)
{
#define CACHE_PREFETCH 1024
	struct mail_cache_record *cache_rec;
	size_t size;

	offset = offset_to_uint32(offset);
	if (offset == 0)
		return NULL;

	if (!mmap_update(cache, offset, sizeof(*cache_rec) + CACHE_PREFETCH))
		return NULL;

	if (offset + sizeof(*cache_rec) > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "record points outside file");
		return NULL;
	}
	cache_rec = CACHE_RECORD(cache, offset);

	size = nbo_to_uint32(cache_rec->size);
	if (size < sizeof(*cache_rec)) {
		mail_cache_set_corrupted(cache, "invalid record size");
		return NULL;
	}
	if (size > CACHE_PREFETCH) {
		if (!mmap_update(cache, offset, size))
			return NULL;
	}

	if (offset + size > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "record points outside file");
		return NULL;
	}
	return cache_rec;
}

static struct mail_cache_record *
cache_get_next_record(struct mail_cache *cache, struct mail_cache_record *rec)
{
	struct mail_cache_record *next;

	next = cache_get_record(cache, rec->next_offset);
	if (next != NULL && next <= rec) {
		mail_cache_set_corrupted(cache, "next_offset points backwards");
		return NULL;
	}
	return next;
}

static struct mail_cache_record *
mail_cache_lookup(struct mail_cache *cache, const struct mail_index_record *rec,
		  enum mail_cache_field fields)
{
	struct mail_cache_record *cache_rec;
	unsigned int idx;

	if (cache->trans_ctx != NULL &&
	    cache->trans_ctx->first_uid <= rec->uid &&
	    cache->trans_ctx->last_uid >= rec->uid &&
	    (cache->trans_ctx->prev_uid != rec->uid || fields == 0 ||
	     (cache->trans_ctx->prev_fields & fields) != 0)) {
		/* we have to auto-commit since we're not capable of looking
		   into uncommitted records. it would be possible by checking
		   index_marks and cache_marks, but it's just more trouble
		   than worth. */
		idx = INDEX_RECORD_INDEX(cache->index, rec);
		if (cache->trans_ctx->last_idx == idx) {
			if (!mail_cache_write(cache->trans_ctx))
				return NULL;
		}

		if (!mail_cache_transaction_commit(cache->trans_ctx))
			return NULL;
	}

	cache_rec = cache_get_record(cache, rec->cache_offset);
	if (cache_rec == NULL)
		return NULL;

	return cache_rec;
}

enum mail_cache_field
mail_cache_get_fields(struct mail_cache *cache,
		      const struct mail_index_record *rec)
{
	struct mail_cache_record *cache_rec;
        enum mail_cache_field fields = 0;

	cache_rec = mail_cache_lookup(cache, rec, 0);
	while (cache_rec != NULL) {
		fields |= cache_rec->fields;
		cache_rec = cache_get_next_record(cache, cache_rec);
	}

	return fields;
}

static int cache_get_field(struct mail_cache *cache,
			   struct mail_cache_record *cache_rec,
			   enum mail_cache_field field,
			   void **data_r, size_t *size_r)
{
	unsigned char *buf;
	unsigned int mask;
	uint32_t rec_size, data_size;
	size_t offset, next_offset;
	int i;

	rec_size = nbo_to_uint32(cache_rec->size);
	buf = (unsigned char *) cache_rec;
	offset = sizeof(*cache_rec);

	for (i = 0, mask = 1; i < 31; i++, mask <<= 1) {
		if ((cache_rec->fields & mask) == 0)
			continue;

		/* all records are at least 32bit. we have to check this
		   before getting data_size. */
		if (offset + sizeof(uint32_t) > rec_size) {
			mail_cache_set_corrupted(cache,
				"Record continues outside it's allocated size");
			return FALSE;
		}

		if ((mask & MAIL_CACHE_FIXED_MASK) != 0)
			data_size = mail_cache_field_sizes[i];
		else {
			memcpy(&data_size, buf + offset, sizeof(data_size));
			data_size = nbo_to_uint32(data_size);
			offset += sizeof(data_size);
		}

		next_offset = offset + ((data_size + 3) & ~3);
		if (next_offset > rec_size) {
			mail_cache_set_corrupted(cache,
				"Record continues outside it's allocated size");
			return FALSE;
		}

		if (field == mask) {
			if (data_size == 0) {
				mail_cache_set_corrupted(cache,
							 "Field size is 0");
				return FALSE;
			}
			*data_r = buf + offset;
			*size_r = data_size;
			return TRUE;
		}
		offset = next_offset;
	}

	i_unreached();
	return FALSE;
}

static int cache_lookup_field(struct mail_cache *cache,
			      const struct mail_index_record *rec,
			      enum mail_cache_field field,
			      void **data_r, size_t *size_r)
{
	struct mail_cache_record *cache_rec;

	cache_rec = mail_cache_lookup(cache, rec, field);
	while (cache_rec != NULL) {
		if ((cache_rec->fields & field) != 0) {
			return cache_get_field(cache, cache_rec, field,
					       data_r, size_r);
		}
		cache_rec = cache_get_next_record(cache, cache_rec);
	}

	return FALSE;
}

int mail_cache_lookup_field(struct mail_cache *cache,
			    const struct mail_index_record *rec,
			    enum mail_cache_field field,
			    const void **data_r, size_t *size_r)
{
	void *data;

	if (!cache_lookup_field(cache, rec, field, &data, size_r))
		return FALSE;

	*data_r = data;
	return TRUE;
}

const char *mail_cache_lookup_string_field(struct mail_cache *cache,
					   const struct mail_index_record *rec,
					   enum mail_cache_field field)
{
	const void *data;
	size_t size;

	i_assert((field & MAIL_CACHE_STRING_MASK) != 0);

	if (!mail_cache_lookup_field(cache, rec, field, &data, &size))
		return NULL;

	if (((const char *) data)[size-1] != '\0') {
		mail_cache_set_corrupted(cache,
			"String field %x doesn't end with NUL", field);
		return NULL;
	}
	return data;
}

int mail_cache_copy_fixed_field(struct mail_cache *cache,
				const struct mail_index_record *rec,
				enum mail_cache_field field,
				void *buffer, size_t buffer_size)
{
	const void *data;
	size_t size;

	i_assert((field & MAIL_CACHE_FIXED_MASK) != 0);

	if (!mail_cache_lookup_field(cache, rec, field, &data, &size))
		return FALSE;

	if (buffer_size != size) {
		i_panic("cache: fixed field %x wrong size "
			"(%"PRIuSIZE_T" vs %"PRIuSIZE_T")",
			field, size, buffer_size);
	}

	memcpy(buffer, data, buffer_size);
	return TRUE;
}

void mail_cache_mark_missing(struct mail_cache *cache,
			     enum mail_cache_field fields)
{
	// FIXME: count these
}

enum mail_index_record_flag
mail_cache_get_index_flags(struct mail_cache *cache,
			   const struct mail_index_record *rec)
{
	enum mail_index_record_flag flags;

	if (!mail_cache_copy_fixed_field(cache, rec, MAIL_CACHE_INDEX_FLAGS,
					 &flags, sizeof(flags)))
		return 0;

	return flags;
}

int mail_cache_update_index_flags(struct mail_cache *cache,
				  const struct mail_index_record *rec,
				  enum mail_index_record_flag flags)
{
	void *data;
	size_t size;

	i_assert(cache->locks > 0);

	if (!cache_lookup_field(cache, rec, MAIL_CACHE_INDEX_FLAGS,
				&data, &size)) {
		mail_cache_set_corrupted(cache,
			"Missing index flags for record %u", rec->uid);
		return FALSE;
	}

	memcpy(data, &flags, sizeof(flags));
	return TRUE;
}

int mail_cache_update_location_offset(struct mail_cache *cache,
				      const struct mail_index_record *rec,
				      uoff_t offset)
{
	void *data;
	size_t size;

	i_assert(cache->locks > 0);

	if (!cache_lookup_field(cache, rec, MAIL_CACHE_LOCATION_OFFSET,
				&data, &size)) {
		mail_cache_set_corrupted(cache,
			"Missing location offset for record %u", rec->uid);
		return FALSE;
	}

	memcpy(data, &offset, sizeof(offset));
	return TRUE;
}

void *mail_cache_get_mmaped(struct mail_cache *cache, size_t *size)
{
	if (!mmap_update(cache, 0, 0))
		return NULL;

	*size = cache->mmap_length;
	return cache->mmap_base;
}
