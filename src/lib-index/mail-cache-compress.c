/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "byteorder.h"
#include "ostream.h"
#include "mail-cache-private.h"

static unsigned char null4[4] = { 0, 0, 0, 0 };

static const struct mail_cache_record *
mail_cache_compress_record(struct mail_cache_view *view, uint32_t seq,
			   enum mail_cache_field orig_cached_fields,
			   int header_idx, uint32_t *size_r)
{
	enum mail_cache_field cached_fields, field;
	struct mail_cache_record cache_rec;
	buffer_t *buffer;
	const void *data;
	size_t size, pos;
	uint32_t nb_size;
	int i;

	memset(&cache_rec, 0, sizeof(cache_rec));
	buffer = buffer_create_dynamic(pool_datastack_create(),
				       4096, (size_t)-1);

	cached_fields = orig_cached_fields & ~MAIL_CACHE_HEADERS_MASK;
	buffer_append(buffer, &cache_rec, sizeof(cache_rec));
	for (i = 0, field = 1; i < 31; i++, field <<= 1) {
		if ((cached_fields & field) == 0)
			continue;

		if (!mail_cache_lookup_field(view, seq, field, &data, &size)) {
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
			if (mail_cache_lookup_field(view, seq, field,
						    &data, &size) && size > 1) {
				size--; /* terminating \0 */
				buffer_append(buffer, data, size);
				nb_size += size;
			}
		}
		buffer_append(buffer, null4, 1);
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

static int
mail_cache_copy(struct mail_cache *cache, struct mail_index_view *view, int fd)
{
	struct mail_cache_view *cache_view;
	struct mail_index_transaction *t;
	const struct mail_index_header *idx_hdr;
	const struct mail_cache_record *cache_rec;
	struct mail_cache_header hdr;
	struct ostream *output;
	enum mail_cache_field keep_fields, temp_fields;
	enum mail_cache_field cached_fields, new_fields;
	const char *str;
	uint32_t size, nb_size, message_count, seq, first_new_seq;
	uoff_t offset;
	int i, header_idx, ret;

	/* get sequence of first message which doesn't need it's temp fields
	   removed. */
	if (mail_index_get_header(view, &idx_hdr) < 0)
		return -1;
	if (mail_index_lookup_uid_range(view, idx_hdr->day_first_uid[7],
					(uint32_t)-1, &first_new_seq,
					&message_count) < 0)
		return -1;
	if (first_new_seq == 0)
		first_new_seq = message_count+1;

	cache_view = mail_cache_view_open(cache, view);
	t = mail_index_transaction_begin(view, FALSE);
	output = o_stream_create_file(fd, default_pool, 0, FALSE);

	memset(&hdr, 0, sizeof(hdr));
	hdr.indexid = cache->hdr->indexid;
	hdr.file_seq = cache->hdr->file_seq + 1;

	memcpy(hdr.field_usage_decision_type,
	       cache->hdr->field_usage_decision_type,
	       sizeof(hdr.field_usage_decision_type));
	memcpy(hdr.field_usage_last_used,
	       cache->hdr->field_usage_last_used,
	       sizeof(hdr.field_usage_last_used));

        keep_fields = temp_fields = 0;
	for (i = 0; i < 32; i++) {
		if (cache->hdr->field_usage_decision_type[i] &
		    MAIL_CACHE_DECISION_YES)
			keep_fields |= 1 << i;
		else if (cache->hdr->field_usage_decision_type[i] &
			 MAIL_CACHE_DECISION_TEMP)
			temp_fields |= 1 << i;
	}

	offset = sizeof(hdr);

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
		hdr.header_offsets[0] = mail_cache_uint32_to_offset(offset);
		header_idx = i;

		size = strlen(str) + 1;
		nb_size = uint32_to_nbo(size);

		o_stream_send(output, &nb_size, sizeof(nb_size));
		o_stream_send(output, str, size);
		if ((size & 3) != 0)
			o_stream_send(output, null4, 4 - (size & 3));
	}

	mail_index_reset_cache(t, hdr.file_seq);

	ret = 0;
	for (seq = 1; seq <= message_count; seq++) {
		cache_rec = mail_cache_lookup(cache_view, seq, 0);
		if (cache_rec == NULL)
			continue;

		cached_fields = mail_cache_get_fields(cache_view, seq);
                new_fields = cached_fields & keep_fields;
		if ((cached_fields & temp_fields) != 0 &&
		    seq >= first_new_seq) {
			/* new message, keep temp fields */
			new_fields |= cached_fields & temp_fields;
		}

		if (keep_fields == cached_fields &&
		    mail_cache_offset_to_uint32(cache_rec->next_offset) == 0) {
			/* just one unmodified block, save it */
			size = nbo_to_uint32(cache_rec->size);
                        mail_index_update_cache(t, seq, output->offset);
			o_stream_send(output, cache_rec, size);

			if ((size & 3) != 0)
				o_stream_send(output, null4, 4 - (size & 3));
		} else {
			/* a) dropping fields
			   b) multiple blocks, sort them into buffer */
                        mail_index_update_cache(t, seq, output->offset);

			t_push();
			cache_rec = mail_cache_compress_record(cache_view, seq,
							       keep_fields,
							       header_idx,
							       &size);
			o_stream_send(output, cache_rec, size);
			t_pop();
		}
	}
	hdr.used_file_size = uint32_to_nbo(output->offset);

	o_stream_unref(output);
	mail_cache_view_close(cache_view);

	if (fdatasync(fd) < 0) {
		mail_cache_set_syscall_error(cache, "fdatasync()");
		(void)mail_index_transaction_rollback(t);
		return -1;
	}

	return mail_index_transaction_commit(t, &seq, &offset);
}

int mail_cache_compress(struct mail_cache *cache, struct mail_index_view *view)
{
	int fd, ret;

	i_assert(cache->trans_ctx == NULL);

	if ((ret = mail_cache_lock(cache, TRUE)) <= 0)
		return ret;

#ifdef DEBUG
	i_warning("Compressing cache file %s", cache->filepath);
#endif

	fd = file_dotlock_open(cache->filepath, NULL, NULL,
			       MAIL_CACHE_LOCK_TIMEOUT,
			       MAIL_CACHE_LOCK_CHANGE_TIMEOUT,
			       MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "file_dotlock_open()");
		return -1;
	}

	if (mail_cache_copy(cache, view, fd) < 0) {
		(void)file_dotlock_delete(cache->filepath, NULL, fd);
		ret = -1;
	} else {
		if (file_dotlock_replace(cache->filepath, NULL,
					 -1, FALSE) < 0) {
			mail_cache_set_syscall_error(cache,
						     "file_dotlock_replace()");
			(void)close(fd);
			ret = -1;
		} else {
			mail_cache_file_close(cache);
			cache->fd = fd;

			if (mail_cache_mmap_update(cache, 0, 0) < 0)
				ret = -1;
		}
	}

	/* headers could have changed, reread them */
	memset(cache->split_offsets, 0, sizeof(cache->split_offsets));
	memset(cache->split_headers, 0, sizeof(cache->split_headers));

	if (mail_cache_unlock(cache) < 0)
		return -1;

	if (ret == 0)
                cache->need_compress = FALSE;
	return ret;
}

int mail_cache_need_compress(struct mail_cache *cache)
{
	return cache->need_compress;
}
