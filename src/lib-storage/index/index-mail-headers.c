/* Copyright (C) 2003 Timo Sirainen */

/*
   Headers are stored in 1-4 pieces. There's a list of header names that each
   piece contains, so if piece doesn't actually contain some listed header,
   it's known not to exist in the mail at all.

   Header name lists are stored in sorted order, so we can use binary
   searching.

   We have to be able to do 3 things:
    - Get value for one header
    - Get a list of headers, possibly containing more than requested
    - Save some of the uncached headers into cache

   First is easy. Second means that we have to store the wanted headers in
   a single string which we can directly return.

   Third is a bit tricky if we want to avoid parsing and copying the data
   uselessly. It's possible if we want to cache all requested uncached
   headers. That should be the common case, so I'll optimize for that.
   Another even more common case is that everything is already cached. So:

   - If we request only cached headers, parse them and copy only wanted
     headers to header_data.
   - If we request a non-cached header, trash the header_data and all
     pointers to it. Copy all cached headers to beginning if it and save
     a marker where it ends.
   - If we again request single cached header, we'll have to parse the
     header_data up to the marker again.
   - When saving the uncached headers, we know that they all come after the
     marker. If we want to save them all, it's directly there in a string.
     Otherwise we have to parse them and copy the wanted headers, but it's
     still less work.
*/

#include "lib.h"
#include "istream.h"
#include "buffer.h"
#include "str.h"
#include "message-date.h"
#include "imap-envelope.h"
#include "imap-bodystructure.h"
#include "index-storage.h"
#include "index-mail.h"

#include <stdlib.h>

struct cached_header {
	const char *name;
	size_t value_idx; /* in header_data */

	unsigned int parsing:1;
	unsigned int fully_saved:1;
};

static struct cached_header *
cached_header_find(struct index_mail *mail, const char *name,
		   unsigned int *idx_r)
{
	struct cached_header **data;
	size_t size;
	unsigned int idx, left_idx, right_idx;
	int ret;

	data = buffer_get_modifyable_data(mail->data.headers, &size);

	idx = left_idx = 0;
	right_idx = size / sizeof(struct cached_header *);

	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		ret = strcasecmp(data[idx]->name, name);
		if (ret < 0)
			left_idx = ++idx;
		else if (ret > 0)
			right_idx = idx;
		else {
			if (idx_r != NULL)
				*idx_r = idx;
			return data[idx];
		}
	}

	if (idx_r != NULL)
		*idx_r = idx;
	return NULL;
}

static struct cached_header *
cached_header_add(struct index_mail *mail, const char *name)
{
	struct cached_header *hdr;
	unsigned int idx;

	hdr = cached_header_find(mail, name, &idx);
	if (hdr != NULL)
		return hdr;

	hdr = p_new(mail->pool, struct cached_header, 1);
	hdr->name = p_strdup(mail->pool, name);

	buffer_insert(mail->data.headers, idx * sizeof(hdr), &hdr, sizeof(hdr));
	return hdr;
}

static int strcasecmp_p(const void *p1, const void *p2)
{
	char *const *s1 = p1, *const *s2 = p2;

	return strcasecmp(*s1, *s2);
}

static const char *const *sort_array(const char *const *arr)
{
	static const char *null = NULL;
	buffer_t *buffer;
	const char **data;
	int i, already_sorted;

	/* copy the wanted_headers array */
	buffer = buffer_create_dynamic(data_stack_pool, 256, (size_t)-1);
	already_sorted = TRUE;
	for (i = 0; arr[i] != NULL; i++) {
		if (i > 0 && already_sorted &&
		    strcasecmp(arr[i], arr[i-1]) <= 0)
			already_sorted = FALSE;
		buffer_append(buffer, &arr[i], sizeof(const char *));
	}
	buffer_append(buffer, &null, sizeof(const char *));

	/* and sort it */
	data = buffer_get_modifyable_data(buffer, NULL);
	if (!already_sorted)
		qsort(data, i, sizeof(const char *), strcasecmp_p);
	return data;
}

static int find_wanted_headers(struct mail_cache *cache,
			       const char *const wanted_headers[])
{
	const char *const *headers, *const *tmp;
	int i, ret, cmp;

	if (wanted_headers == NULL || *wanted_headers == NULL)
		return -1;

	wanted_headers = sort_array(wanted_headers);

	ret = -1;
	for (i = MAIL_CACHE_HEADERS_COUNT-1; i >= 0; i--) {
		headers = mail_cache_get_header_fields(cache, i);
		if (headers == NULL)
			continue;

		for (tmp = wanted_headers; *headers != NULL; headers++) {
			cmp = strcasecmp(*tmp, *headers);
			if (cmp == 0) {
				if (*++tmp == NULL)
					break;
			} else {
				if (cmp < 0)
					break;
			}
		}

		if (*tmp != NULL)
			return ret;

		/* find the minimum matching header number */
		ret = i;
	}

	return ret;
}

static int mail_find_wanted_headers(struct index_mail *mail,
				    const char *const wanted_headers[])
{
	int idx;

	idx = find_wanted_headers(mail->ibox->index->cache, wanted_headers);
	if (idx < 0)
		return -1;

	for (; idx < MAIL_CACHE_HEADERS_COUNT; idx++) {
		if ((mail->data.cached_fields &
		     mail_cache_header_fields[idx]) != 0)
			return idx;
	}

	return -1;
}

static const char *const *cached_header_get_names(struct index_mail *mail)
{
	const struct cached_header **data;
	const char *null = NULL;
	buffer_t *buffer;
	size_t i, size;

	data = buffer_get_modifyable_data(mail->data.headers, &size);
	size /= sizeof(struct cached_header *);

	buffer = buffer_create_dynamic(data_stack_pool, 128, (size_t)-1);
	for (i = 0; i < size; i++)
		buffer_append(buffer, &data[i]->name, sizeof(const char *));
	buffer_append(buffer, &null, sizeof(const char *));

	return buffer_get_data(buffer, NULL);
}

static void cached_headers_mark_fully_saved(struct index_mail *mail)
{
	struct cached_header **data;
	size_t i, size;

	data = buffer_get_modifyable_data(mail->data.headers, &size);
	size /= sizeof(struct cached_header *);

	for (i = 0; i < size; i++) {
		if (data[i]->parsing) {
			data[i]->parsing = FALSE;
			data[i]->fully_saved = TRUE;
		}
	}
}

void index_mail_parse_header_init(struct index_mail *mail,
				  const char *const headers[])
{
	struct cached_header **data;
	size_t i, size;
	int cmp;

	if (mail->data.header_data == NULL)
		mail->data.header_data = str_new(mail->pool, 4096);

	data = buffer_get_modifyable_data(mail->data.headers, &size);
	size /= sizeof(struct cached_header *);

	if (headers == NULL) {
		/* parsing all headers */
		for (i = 0; i < size; i++)
			data[i]->parsing = TRUE;
	} else {
		t_push();
		headers = sort_array(headers);
		for (i = 0; i < size && *headers != NULL;) {
			cmp = strcasecmp(*headers, data[i]->name);
			if (cmp <= 0) {
				if (cmp == 0) {
					data[i]->parsing = TRUE;
					i++;
				}
				headers++;
			} else {
				i++;
			}
		}
		t_pop();
	}
}

void index_mail_parse_header(struct message_part *part,
			     struct message_header_line *hdr, void *context)
{
	struct index_mail *mail = context;
	struct index_mail_data *data = &mail->data;
	struct cached_header *cached_hdr;
	int timezone;

	if (data->bodystructure_header_parse)
		imap_bodystructure_parse_header(mail->pool, part, hdr);

	if (part != NULL && part->parent != NULL)
		return;

	if (data->save_envelope) {
		imap_envelope_parse_header(mail->pool,
					   &data->envelope_data, hdr);

		if (hdr == NULL) {
			/* finalize the envelope */
			string_t *str;

			str = str_new(mail->pool, 256);
			imap_envelope_write_part_data(data->envelope_data, str);
			data->envelope = str_c(str);
		}
	}

	if (hdr == NULL) {
		/* end of headers */
		if (data->save_sent_date) {
			/* not found */
			data->sent_date.time = 0;
			data->sent_date.timezone = 0;
			data->save_sent_date = FALSE;
		}
		if (data->sent_date.time != (time_t)-1) {
			index_mail_cache_add(mail, MAIL_CACHE_SENT_DATE,
					     &data->sent_date,
					     sizeof(data->sent_date));
		}

		cached_headers_mark_fully_saved(mail);
		return;
	}

	if (data->save_sent_date && strcasecmp(hdr->name, "Date") == 0) {
		if (hdr->continues)
			hdr->use_full_value = TRUE;
		else {
			if (!message_date_parse(hdr->full_value,
						hdr->full_value_len,
						&data->sent_date.time,
						&timezone)) {
				/* 0 == parse error */
				data->sent_date.time = 0;
				timezone = 0;
			}
                        data->sent_date.timezone = timezone;
			data->save_sent_date = FALSE;
		}
	}

	cached_hdr = cached_header_find(mail, hdr->name, NULL);
	if (cached_hdr != NULL && !cached_hdr->fully_saved) {
		if (data->header_stream == NULL) {
			if (!hdr->continued) {
				str_append(data->header_data, hdr->name);
				str_append(data->header_data, ": ");
			}
			if (cached_hdr->value_idx == 0) {
				cached_hdr->value_idx =
					str_len(data->header_data);
			}
			str_append_n(data->header_data,
				     hdr->value, hdr->value_len);
			if (!hdr->no_newline)
				str_append(data->header_data, "\n");
		} else {
			/* it's already in header_data. */
			if (cached_hdr->value_idx == 0) {
				cached_hdr->value_idx =
					data->header_stream->v_offset;
			}
		}
	}
}

static int index_mail_can_cache_headers(struct index_mail *mail)
{
	if ((mail->data.cached_fields &
	     mail_cache_header_fields[MAIL_CACHE_HEADERS_COUNT-1]) != 0)
		return FALSE; /* all headers used */

	/* FIXME: add some smart checks here. we don't necessarily want to
	   cache everything.. */

	if (!index_mail_cache_transaction_begin(mail))
		return FALSE;

	return TRUE;
}

static void cached_headers_clear_values(struct index_mail *mail)
{
	struct cached_header **data;
	size_t i, size, clear_offset;

	clear_offset = str_len(mail->data.header_data);
	data = buffer_get_modifyable_data(mail->data.headers, &size);
	size /= sizeof(struct cached_header *);

	for (i = 0; i < size; i++) {
		if (data[i]->value_idx >= clear_offset)
			data[i]->value_idx = 0;
	}
}

static int parse_cached_headers(struct index_mail *mail, int idx)
{
	struct index_mail_data *data = &mail->data;
	struct istream *istream;
	const char *str, *const *idx_headers;

	t_push();
	if (idx < data->header_data_cached) {
		/* it's already in header_data. */
		istream = i_stream_create_from_data(data_stack_pool,
						    str_data(data->header_data),
						    str_len(data->header_data));
		/* we might be parsing a bit more.. */
		idx = data->header_data_cached-1;
		data->header_stream = istream;
	} else {
		str = mail_cache_lookup_string_field(
			mail->ibox->index->cache, data->rec,
			mail_cache_header_fields[idx]);
		if (str == NULL) {
			/* broken - we expected the header to exist */
			t_pop();
			return FALSE;
		}

		data->header_data_cached_partial = TRUE;
		istream = i_stream_create_from_data(data_stack_pool,
						    str, strlen(str));
	}

	idx_headers = mail_cache_get_header_fields(mail->ibox->index->cache,
						   idx);
	if (idx_headers == NULL) {
		mail_cache_set_corrupted(mail->ibox->index->cache,
			"Headers %d names not found", idx);
		t_pop();
		return FALSE;
	}

	index_mail_parse_header_init(mail, idx_headers);
	message_parse_header(NULL, istream, NULL,
			     index_mail_parse_header, mail);

	data->header_stream = NULL;
	i_stream_unref(istream);
	t_pop();

	return TRUE;
}

int index_mail_parse_headers(struct index_mail *mail)
{
	struct mail_cache *cache = mail->ibox->index->cache;
	struct index_mail_data *data = &mail->data;
	const char *str, *const *headers;
	int idx, max;

	if (!index_mail_open_stream(mail, 0))
		return FALSE;

	if (mail->data.header_data == NULL)
		mail->data.header_data = str_new(mail->pool, 4096);

	/* can_cache_headers() locks the cache file. it must be done before
	   we can expect cached headers to stay the same. it's not a good idea
	   to cache some headers twice because of race conditions.. */
	if (!data->header_fully_parsed && index_mail_can_cache_headers(mail)) {
		if (data->header_data_cached_partial) {
			/* too difficult to handle efficiently, trash it */
			data->header_data_cached_partial = FALSE;
			data->header_data_cached =
				data->header_data_cached_contiguous;

			str_truncate(data->header_data,
				     data->header_data_uncached_offset);
			cached_headers_clear_values(mail);
		}

		/* add all cached headers to beginning of header_data */
                idx = data->header_data_cached; max = idx-1;
		for (; idx < MAIL_CACHE_HEADERS_COUNT; idx++) {
			str = mail_cache_lookup_string_field(cache, data->rec,
						mail_cache_header_fields[idx]);
			if (str == NULL)
				continue;

			max = idx;
			str_append(mail->data.header_data, str);
		}
		data->header_data_cached = max+1;
		data->header_data_uncached_offset =
			str_len(mail->data.header_data);

		/* make sure we cache everything */
		for (idx = MAIL_CACHE_HEADERS_COUNT-1; idx >= 0; idx--) {
			headers = mail_cache_get_header_fields(cache, idx);
			if (headers != NULL)
				break;
		}

		if (headers != NULL) {
			while (*headers != NULL) {
				cached_header_add(mail, *headers);
				headers++;
			}
		}

		if (max >= 0) {
			/* now we'll have to set value_idx for all headers that
			   are already cached */
			if (!parse_cached_headers(mail, max))
				return FALSE;
		}

		data->header_save = TRUE;
		data->header_save_idx = idx;
	}

	data->bodystructure_header_parse = data->bodystructure_header_want;
	index_mail_parse_header_init(mail, NULL);

	if (data->parts != NULL || data->parser_ctx != NULL) {
		message_parse_header(data->parts, data->stream, &data->hdr_size,
				     index_mail_parse_header, mail);
	} else {
		data->parser_ctx =
			message_parser_init(mail->pool, data->stream);
		message_parser_parse_header(data->parser_ctx, &data->hdr_size,
					    index_mail_parse_header, mail);
	}
	data->hdr_size_set = TRUE;

	if (data->bodystructure_header_want) {
		data->bodystructure_header_want = FALSE;
		data->bodystructure_header_parse = FALSE;
		data->bodystructure_header_parsed = TRUE;
	}

	data->parse_header = FALSE;
	data->header_fully_parsed = TRUE;

	return TRUE;
}

const char *index_mail_get_header(struct mail *_mail, const char *field)
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct cached_header *hdr;
	const char *arr[2];
	int idx;

	hdr = cached_header_add(mail, field);
	if (!hdr->fully_saved) {
		if (mail->data.parse_header) {
			/* we need to parse header anyway */
			idx = -1;
		} else {
			arr[0] = field; arr[1] = NULL;
			idx = mail_find_wanted_headers(mail, arr);

			if (idx >= 0) {
				if (!parse_cached_headers(mail, idx))
					return NULL;
			}
		}

		if (idx < 0) {
			if (!index_mail_parse_headers(mail))
				return NULL;

			/* might have been moved in memory, get it again */
			hdr = cached_header_find(mail, field, NULL);
		}
	}

	return hdr->value_idx == 0 ? NULL :
		t_strcut(str_c(mail->data.header_data) + hdr->value_idx, '\n');
}

struct istream *index_mail_get_headers(struct mail *_mail,
				       const char *const minimum_fields[])
{
	struct index_mail *mail = (struct index_mail *) _mail;
	struct index_mail_data *data = &mail->data;
	struct cached_header *hdr;
	const char *const *tmp, *str;
	int i, idx, all_saved;

	i_assert(*minimum_fields != NULL);

	if (mail->data.header_data == NULL)
		mail->data.header_data = str_new(mail->pool, 4096);

	idx = mail_find_wanted_headers(mail, minimum_fields);
	if (idx >= 0) {
		/* copy from cache to header_data */
		for (i = data->header_data_cached; i <= idx; i++) {
			str = mail_cache_lookup_string_field(
					mail->ibox->index->cache, data->rec,
					mail_cache_header_fields[i]);
			if (str == NULL)
				continue;

			str_append(data->header_data, str);
		}
		data->header_data_cached = idx+1;
		if (!data->header_data_cached_partial) {
			data->header_data_uncached_offset =
				str_len(data->header_data);
			data->header_data_cached_contiguous = idx+1;
		}
	} else {
		/* it's not cached yet - see if we have them parsed */
		all_saved = TRUE;
		for (tmp = minimum_fields; *tmp != NULL; tmp++) {
			hdr = cached_header_add(mail, *tmp);
			if (!hdr->fully_saved)
				all_saved = FALSE;
		}

		if (!all_saved) {
			if (!index_mail_parse_headers(mail))
				return NULL;
		}
	}

	return i_stream_create_from_data(mail->pool,
					 str_data(data->header_data),
					 str_len(data->header_data));
}

void index_mail_headers_init(struct index_mail *mail)
{
	struct mail_cache *cache = mail->ibox->index->cache;
	int idx = -2, idx2 = -2;

	if (mail->wanted_headers != NULL && *mail->wanted_headers != NULL)
		idx = find_wanted_headers(cache, mail->wanted_headers);

	if (idx != -1 && (mail->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE))
		idx2 = find_wanted_headers(cache, imap_envelope_headers);

	mail->wanted_headers_idx = idx == -1 || idx2 == -1 ? -1 :
		idx > idx2 ? idx : idx2;
}

void index_mail_headers_init_next(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;
	const char *const *tmp;
	int idx;

	mail->data.headers = buffer_create_dynamic(mail->pool, 64, (size_t)-1);

	idx = mail->wanted_headers_idx;
	if (mail->wanted_headers != NULL) {
		const char *const *tmp;

		for (tmp = mail->wanted_headers; *tmp != NULL; tmp++)
			cached_header_add(mail, *tmp);
	}

	if (mail->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE) {
		for (tmp = imap_envelope_headers; *tmp != NULL; tmp++)
			cached_header_add(mail, *tmp);
	} else if ((mail->wanted_fields & MAIL_FETCH_DATE) &&
		   data->sent_date.time == (time_t)-1) {
		cached_header_add(mail, "Date");
		if (idx != -1) {
			/* see if it's cached */
			const char *headers[] = { "Date", NULL };
			idx = mail_find_wanted_headers(mail, headers);
		}
	}

	/* See if we're going to have to parse the header */
	if (idx != -2) {
		if (idx >= 0) {
			for (; idx < MAIL_CACHE_HEADERS_COUNT; idx++) {
				if ((data->cached_fields &
				     mail_cache_header_fields[idx]) != 0)
					break;
			}
		}
		if (idx < 0 || idx >= MAIL_CACHE_HEADERS_COUNT)
			data->parse_header = TRUE;
	}
}

static int find_unused_header_idx(struct mail_cache *cache)
{
	int i;

	for (i = 0; i < MAIL_CACHE_HEADERS_COUNT; i++) {
		if (mail_cache_get_header_fields(cache, i) == NULL)
			return i;
	}

	return -1;
}

void index_mail_headers_close(struct index_mail *mail)
{
	struct index_mail_data *data = &mail->data;
	const char *str, *const *headers;
	size_t len;
	int idx;

	if (!data->header_save)
		return;

	/* FIXME: this breaks if fetch_uid() and fetch/search are both
	   accessing headers from same message. index_mails should probably be
	   shared.. */
	headers = cached_header_get_names(mail);
	idx = find_wanted_headers(mail->ibox->index->cache, headers);
	if (idx >= 0) {
		/* all headers found */
                i_assert(idx == mail->data.header_save_idx);
	} else {
		/* there's some new headers */
		idx = find_unused_header_idx(mail->ibox->index->cache);
		if (idx < 0)
			return;

		if (!mail_cache_set_header_fields(mail->ibox->trans_ctx,
						  idx, headers))
			return;
	}

	str = str_c(mail->data.header_data) + data->header_data_uncached_offset;
	len = str_len(mail->data.header_data) -
		data->header_data_uncached_offset;

	mail_cache_add(mail->ibox->trans_ctx, data->rec,
		       mail_cache_header_fields[idx], str, len+1);
	data->header_save = FALSE;
}
