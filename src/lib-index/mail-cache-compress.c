static const struct mail_cache_record *
mail_cache_compress_record(struct mail_cache *cache,
			   struct mail_index_record *rec, int header_idx,
			   uint32_t *size_r)
{
	enum mail_cache_field orig_cached_fields, cached_fields, field;
	struct mail_cache_record cache_rec;
	buffer_t *buffer;
	const void *data;
	size_t size, pos;
	uint32_t nb_size;
	int i;

	memset(&cache_rec, 0, sizeof(cache_rec));
	buffer = buffer_create_dynamic(pool_datastack_create(),
				       4096, (size_t)-1);

        orig_cached_fields = mail_cache_get_fields(cache, rec);
	cached_fields = orig_cached_fields & ~MAIL_CACHE_HEADERS_MASK;
	buffer_append(buffer, &cache_rec, sizeof(cache_rec));
	for (i = 0, field = 1; i < 31; i++, field <<= 1) {
		if ((cached_fields & field) == 0)
			continue;

		if (!mail_cache_lookup_field(cache, rec, field, &data, &size)) {
			cached_fields &= ~field;
			continue;
		}

		nb_size = uint32_to_nbo((uint32_t)size);

		if ((field & MAIL_CACHE_FIXED_MASK) == 0)
			buffer_append(buffer, &nb_size, sizeof(nb_size));
		buffer_append(buffer, data, size);
		if ((size & 3) != 0)
			buffer_append(buffer, null4, 4 - (size & 3));
	}

	/* now merge all the headers if we have them all */
	if ((orig_cached_fields & mail_cache_header_fields[header_idx]) != 0) {
		nb_size = 0;
		pos = buffer_get_used_size(buffer);
		buffer_append(buffer, &nb_size, sizeof(nb_size));

		for (i = 0; i <= header_idx; i++) {
			field = mail_cache_header_fields[i];
			if (mail_cache_lookup_field(cache, rec, field,
						    &data, &size) && size > 1) {
				size--; /* terminating \0 */
				buffer_append(buffer, data, size);
				nb_size += size;
			}
		}
		buffer_append(buffer, "", 1);
		nb_size++;
		if ((nb_size & 3) != 0)
			buffer_append(buffer, null4, 4 - (nb_size & 3));

		nb_size = uint32_to_nbo(nb_size);
		buffer_write(buffer, pos, &nb_size, sizeof(nb_size));

		cached_fields |= MAIL_CACHE_HEADERS1;
	}

	cache_rec.fields = cached_fields;
	cache_rec.size = uint32_to_nbo(buffer_get_used_size(buffer));
	buffer_write(buffer, 0, &cache_rec, sizeof(cache_rec));

	data = buffer_get_data(buffer, &size);
	*size_r = size;
	return data;
}

static int mail_cache_copy(struct mail_cache *cache, int fd)
{
#if 0
	struct mail_cache_header *hdr;
	const struct mail_cache_record *cache_rec;
	struct mail_index_record *rec;
        enum mail_cache_field used_fields;
	unsigned char *mmap_base;
	const char *str;
	uint32_t new_file_size, offset, size, nb_size;
	int i, header_idx;

	/* pick some reasonably good file size */
	new_file_size = cache->used_file_size -
		nbo_to_uint32(cache->hdr->deleted_space);
	new_file_size = (new_file_size + 1023) & ~1023;
	if (new_file_size < MAIL_CACHE_INITIAL_SIZE)
		new_file_size = MAIL_CACHE_INITIAL_SIZE;

	if (file_set_size(fd, new_file_size) < 0)
		return mail_cache_set_syscall_error(cache, "file_set_size()");

	mmap_base = mmap(NULL, new_file_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED, fd, 0);
	if (mmap_base == MAP_FAILED)
		return mail_cache_set_syscall_error(cache, "mmap()");

	/* skip file's header */
	hdr = (struct mail_cache_header *) mmap_base;
	offset = sizeof(*hdr);

	/* merge all the header pieces into one. if some message doesn't have
	   all the required pieces, we'll just have to drop them all. */
	for (i = MAIL_CACHE_HEADERS_COUNT-1; i >= 0; i--) {
		str = mail_cache_get_header_fields_str(cache, i);
		if (str != NULL)
			break;
	}

	if (str == NULL)
		header_idx = -1;
	else {
		hdr->header_offsets[0] = uint32_to_offset(offset);
		header_idx = i;

		size = strlen(str) + 1;
		nb_size = uint32_to_nbo(size);

		memcpy(mmap_base + offset, &nb_size, sizeof(nb_size));
		offset += sizeof(nb_size);
		memcpy(mmap_base + offset, str, size);
		offset += (size + 3) & ~3;
	}

	// FIXME: recreate index file with new cache_offsets

	used_fields = 0;
	rec = cache->index->lookup(cache->index, 1);
	while (rec != NULL) {
		cache_rec = mail_cache_lookup(cache, rec, 0);
		if (cache_rec == NULL)
			rec->cache_offset = 0;
		else if (offset_to_uint32(cache_rec->next_offset) == 0) {
			/* just one unmodified block, copy it */
			size = nbo_to_uint32(cache_rec->size);
			i_assert(offset + size <= new_file_size);

			memcpy(mmap_base + offset, cache_rec, size);
			rec->cache_offset = uint32_to_offset(offset);

			size = (size + 3) & ~3;
			offset += size;
		} else {
			/* multiple blocks, sort them into buffer */
			t_push();
			cache_rec = mail_cache_compress_record(cache, rec,
							       header_idx,
							       &size);
			i_assert(offset + size <= new_file_size);
			memcpy(mmap_base + offset, cache_rec, size);
			used_fields |= cache_rec->fields;
			t_pop();

			rec->cache_offset = uint32_to_offset(offset);
			offset += size;
		}

		rec = cache->index->next(cache->index, rec);
	}

	/* update header */
	hdr->indexid = cache->index->indexid;
	hdr->file_seq = cache->index->hdr->cache_sync_id+1;
	hdr->used_file_size = uint32_to_nbo(offset);
	hdr->used_fields = used_fields;
	hdr->field_usage_start = uint32_to_nbo(ioloop_time);

	/* write everything to disk */
	if (msync(mmap_base, offset, MS_SYNC) < 0)
		return mail_cache_set_syscall_error(cache, "msync()");

	if (munmap(mmap_base, new_file_size) < 0)
		return mail_cache_set_syscall_error(cache, "munmap()");

	if (fdatasync(fd) < 0)
		return mail_cache_set_syscall_error(cache, "fdatasync()");
	return TRUE;
#endif
}

int mail_cache_compress(struct mail_cache *cache)
{
	int fd, ret = TRUE;

	i_assert(cache->trans_ctx == NULL);

	if (cache->anon_mmap)
		return TRUE;

	if (!cache->index->set_lock(cache->index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (mail_cache_lock(cache, TRUE) <= 0)
		return FALSE;

#ifdef DEBUG
	i_warning("Compressing cache file %s", cache->filepath);
#endif

	fd = file_dotlock_open(cache->filepath, NULL, MAIL_CACHE_LOCK_TIMEOUT,
			       MAIL_CACHE_LOCK_CHANGE_TIMEOUT,
			       MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "file_dotlock_open()");
		return FALSE;
	}

	/* now we'll begin the actual moving. keep rebuild-flag on
	   while doing it. */
	cache->index->hdr->flags |= MAIL_INDEX_HDR_FLAG_REBUILD;
	if (!mail_index_fmdatasync(cache->index, cache->index->hdr_size))
		return FALSE;

	if (!mail_cache_copy(cache, fd)) {
		(void)file_dotlock_delete(cache->filepath, fd);
		ret = FALSE;
	} else {
		mail_cache_file_close(cache);
		cache->fd = dup(fd);

		if (file_dotlock_replace(cache->filepath, fd, FALSE) < 0) {
			mail_cache_set_syscall_error(cache,
						     "file_dotlock_replace()");
			ret = FALSE;
		}

		if (!mmap_update(cache, 0, 0))
			ret = FALSE;
	}

	/* headers could have changed, reread them */
	memset(cache->split_offsets, 0, sizeof(cache->split_offsets));
	memset(cache->split_headers, 0, sizeof(cache->split_headers));

	if (ret) {
		cache->index->hdr->flags &=
			~(MAIL_INDEX_HDR_FLAG_REBUILD |
			  MAIL_INDEX_HDR_FLAG_COMPRESS_CACHE);
	}

	if (mail_cache_unlock(cache) < 0)
		ret = FALSE;

	return ret;
}
