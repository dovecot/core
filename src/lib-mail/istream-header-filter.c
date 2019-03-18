/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "sort.h"
#include "message-parser.h"
#include "istream-private.h"
#include "istream-header-filter.h"


struct header_filter_istream {
	struct istream_private istream;
	pool_t pool;

	struct message_header_parser_ctx *hdr_ctx;

	const char **headers;
	unsigned int headers_count;

	header_filter_callback *callback;
	void *context;

	buffer_t *hdr_buf;
	struct message_size header_size;
	uoff_t skip_count;
	uoff_t last_lf_offset;

	unsigned int cur_line, parsed_lines;
	ARRAY(unsigned int) match_change_lines;

	bool header_read:1;
	bool seen_eoh:1;
	bool header_parsed:1;
	bool headers_edited:1;
	bool exclude:1;
	bool crlf:1;
	bool crlf_preserve:1;
	bool hide_body:1;
	bool add_missing_eoh:1;
	bool end_body_with_lf:1;
	bool last_lf_added:1;
	bool last_orig_crlf:1;
	bool last_added_newline:1;
	bool eoh_not_matched:1;
	bool callbacks_called:1;
	bool prev_matched:1;
};

header_filter_callback *null_header_filter_callback = NULL;

static ssize_t i_stream_header_filter_read(struct istream_private *stream);

static void i_stream_header_filter_destroy(struct iostream_private *stream)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;

	if (mstream->hdr_ctx != NULL)
		message_parse_header_deinit(&mstream->hdr_ctx);
	if (array_is_created(&mstream->match_change_lines))
		array_free(&mstream->match_change_lines);
	pool_unref(&mstream->pool);
}

static ssize_t
read_mixed(struct header_filter_istream *mstream, size_t body_highwater_size)
{
	const unsigned char *data;
	size_t pos;
	ssize_t ret;

	if (mstream->hide_body) {
		mstream->istream.istream.eof = TRUE;
		return -1;
	}

	data = i_stream_get_data(mstream->istream.parent, &pos);
	if (pos <= body_highwater_size) {
		i_assert(pos == body_highwater_size ||
			 (mstream->end_body_with_lf &&
			  pos+1 == body_highwater_size));

		ret = i_stream_read_memarea(mstream->istream.parent);
		mstream->istream.istream.stream_errno =
			mstream->istream.parent->stream_errno;
		mstream->istream.istream.eof = mstream->istream.parent->eof;

		if (ret <= 0) {
			data = mstream->hdr_buf->data;
			pos = mstream->hdr_buf->used;
			i_assert(pos > 0);

			if (mstream->end_body_with_lf && data[pos-1] != '\n' &&
			    ret == -1 && mstream->istream.istream.eof) {
				/* add missing trailing LF to body */
				if (mstream->crlf)
					buffer_append_c(mstream->hdr_buf, '\r');
				buffer_append_c(mstream->hdr_buf, '\n');
				mstream->istream.buffer = mstream->hdr_buf->data;
				mstream->istream.pos = mstream->hdr_buf->used;
				return mstream->hdr_buf->used - pos;
			}
			return ret;
		}

		data = i_stream_get_data(mstream->istream.parent, &pos);
	}
	buffer_append(mstream->hdr_buf, data + body_highwater_size,
		      pos - body_highwater_size);

	mstream->istream.buffer = buffer_get_data(mstream->hdr_buf, &pos);
	ret = (ssize_t)(pos - mstream->istream.pos - mstream->istream.skip);
	i_assert(ret > 0);
	mstream->istream.pos = pos;
	return ret;
}

static int cmp_uint(const unsigned int *i1, const unsigned int *i2)
{
	return *i1 < *i2 ? -1 :
		(*i1 > *i2 ? 1 : 0);
}

static bool match_line_changed(struct header_filter_istream *mstream)
{
	if (!array_is_created(&mstream->match_change_lines))
		return FALSE;

	return array_bsearch(&mstream->match_change_lines, &mstream->cur_line,
			     cmp_uint) != NULL;
}

static void add_eol(struct header_filter_istream *mstream, bool orig_crlf)
{
	if (mstream->crlf || (orig_crlf && mstream->crlf_preserve))
		buffer_append(mstream->hdr_buf, "\r\n", 2);
	else
		buffer_append_c(mstream->hdr_buf, '\n');
	mstream->last_orig_crlf = orig_crlf;
	mstream->last_added_newline = TRUE;
}

static ssize_t hdr_stream_update_pos(struct header_filter_istream *mstream)
{
	ssize_t ret;
	size_t pos;

	mstream->istream.buffer = buffer_get_data(mstream->hdr_buf, &pos);
	ret = (ssize_t)(pos - mstream->istream.pos - mstream->istream.skip);
	i_assert(ret >= 0);
	mstream->istream.pos = pos;
	return ret;
}

static ssize_t read_header(struct header_filter_istream *mstream)
{
	struct message_header_line *hdr;
	uoff_t highwater_offset;
	size_t max_buffer_size;
	ssize_t ret, ret2;
	int hdr_ret;

	if (mstream->hdr_ctx == NULL) {
		mstream->hdr_ctx =
			message_parse_header_init(mstream->istream.parent,
						  NULL, 0);
	}

	/* remove skipped data from hdr_buf */
	buffer_copy(mstream->hdr_buf, 0,
		    mstream->hdr_buf, mstream->istream.skip, (size_t)-1);

        mstream->istream.pos -= mstream->istream.skip;
	mstream->istream.skip = 0;
	buffer_set_used_size(mstream->hdr_buf, mstream->istream.pos);

	if (mstream->header_read) {
		i_assert(mstream->istream.skip == 0);
		highwater_offset = mstream->istream.istream.v_offset +
			mstream->istream.pos;
		if (highwater_offset >= mstream->header_size.virtual_size) {
			/* we want to return mixed headers and body */
			size_t body_highwater_size = highwater_offset -
				mstream->header_size.virtual_size;
			return read_mixed(mstream, body_highwater_size);
		}
	}

	max_buffer_size = i_stream_get_max_buffer_size(&mstream->istream.istream);
	if (mstream->hdr_buf->used >= max_buffer_size) {
		i_assert(max_buffer_size > 0);
		return -2;
	}

	while ((hdr_ret = message_parse_header_next(mstream->hdr_ctx,
						    &hdr)) > 0) {
		bool matched;

		if (!hdr->continued)
			mstream->cur_line++;
		if (hdr->eoh) {
			mstream->seen_eoh = TRUE;
			matched = FALSE;
			if (mstream->header_parsed && !mstream->headers_edited) {
				if (mstream->eoh_not_matched)
					matched = !matched;
			} else if (mstream->callback != NULL) {
				mstream->callback(mstream, hdr, &matched,
						  mstream->context);
				mstream->callbacks_called = TRUE;
			}

			if (matched) {
				mstream->eoh_not_matched = TRUE;
				continue;
			}

			add_eol(mstream, hdr->crlf_newline);
			continue;
		}

		if (hdr->continued) {
			/* Header line continued - use only the first line's
			   matched-result. Otherwise multiline headers might
			   end up being only partially picked, which wouldn't
			   be very good. However, allow callbacks to modify
			   the headers in any way they want. */
			matched = mstream->prev_matched;
		} else if (mstream->headers_count == 0) {
			/* no include/exclude headers - default matching */
			matched = FALSE;
		} else {
			matched = i_bsearch(hdr->name, mstream->headers,
					    mstream->headers_count,
					    sizeof(*mstream->headers),
					    bsearch_strcasecmp) != NULL;
		}
		if (mstream->callback == NULL) {
			/* nothing gets excluded */
		} else if (!mstream->header_parsed || mstream->headers_edited) {
			/* first time in this line or we have actually modified
			   the header so we always want to call the callbacks */
			bool orig_matched = matched;

			mstream->parsed_lines = mstream->cur_line;
			mstream->callback(mstream, hdr, &matched,
					  mstream->context);
			mstream->callbacks_called = TRUE;
			if (matched != orig_matched &&
			    !hdr->continued && !mstream->headers_edited) {
				if (!array_is_created(&mstream->match_change_lines))
					i_array_init(&mstream->match_change_lines, 8);
				array_push_back(&mstream->match_change_lines,
						&mstream->cur_line);
			}
		} else if (!hdr->continued) {
			/* second time in this line. was it excluded by the
			   callback the first time? */
			if (match_line_changed(mstream))
				matched = !matched;
		}
		mstream->prev_matched = matched;

		if (matched == mstream->exclude) {
			/* ignore */
		} else {
			if (!hdr->continued) {
				buffer_append(mstream->hdr_buf,
					      hdr->name, hdr->name_len);
				buffer_append(mstream->hdr_buf,
					      hdr->middle, hdr->middle_len);
			}
			buffer_append(mstream->hdr_buf,
				      hdr->value, hdr->value_len);
			if (!hdr->no_newline)
				add_eol(mstream, hdr->crlf_newline);

			if (mstream->skip_count >= mstream->hdr_buf->used) {
				/* we need more */
				mstream->skip_count -= mstream->hdr_buf->used;
				buffer_set_used_size(mstream->hdr_buf, 0);
			} else {
				if (mstream->skip_count > 0) {
					mstream->istream.skip =
						mstream->skip_count;
					mstream->skip_count = 0;
				}
				break;
			}
		}
		if (mstream->hdr_buf->used >= max_buffer_size)
			break;
	}
	if (mstream->hdr_buf->used > 0) {
		const unsigned char *data = mstream->hdr_buf->data;
		mstream->last_added_newline =
			data[mstream->hdr_buf->used-1] == '\n';
	}

	if (hdr_ret < 0) {
		if (mstream->istream.parent->stream_errno != 0) {
			mstream->istream.istream.stream_errno =
				mstream->istream.parent->stream_errno;
			mstream->istream.istream.eof =
				mstream->istream.parent->eof;
			return -1;
		}
		if (!mstream->seen_eoh && mstream->add_missing_eoh) {
			bool matched = FALSE;

			mstream->seen_eoh = TRUE;

			if (!mstream->last_added_newline)
				add_eol(mstream, mstream->last_orig_crlf);

			if (mstream->header_parsed && !mstream->headers_edited) {
				if (mstream->eoh_not_matched)
					matched = !matched;
			} else if (mstream->callback != NULL) {
				struct message_header_line fake_eoh_hdr = {
					.eoh = TRUE,
					.name = "",
				};
				mstream->callback(mstream, &fake_eoh_hdr,
						  &matched, mstream->context);
				mstream->callbacks_called = TRUE;
			}

			if (matched) {
				mstream->seen_eoh = FALSE;
			} else {
				add_eol(mstream, mstream->last_orig_crlf);
			}
		}
	}

	/* don't copy eof here because we're only returning headers here.
	   the body will be returned in separate read() call. */
	ret = hdr_stream_update_pos(mstream);

	if (hdr_ret == 0) {
		/* need more data to finish parsing headers. we may have some
		   data already available though. */
		return ret;
	}

	if (hdr == NULL) {
		/* finished */
		message_parse_header_deinit(&mstream->hdr_ctx);
		mstream->hdr_ctx = NULL;

		if ((!mstream->header_parsed || mstream->headers_edited ||
		     mstream->callbacks_called) &&
		    mstream->callback != NULL) {
			bool matched = FALSE;
			mstream->callback(mstream, NULL,
					  &matched, mstream->context);
			/* check if the callback added more headers.
			   this is allowed only if EOH wasn't added yet. */
			ret2 = hdr_stream_update_pos(mstream);
			if (!mstream->seen_eoh)
				ret += ret2;
			else {
				i_assert(ret2 == 0);
			}
		}
		mstream->header_parsed = TRUE;
		mstream->header_read = TRUE;
		mstream->callbacks_called = FALSE;

		mstream->header_size.physical_size =
			mstream->istream.parent->v_offset;
		mstream->header_size.virtual_size =
			mstream->istream.istream.v_offset +
			mstream->istream.pos;
	}

	if (ret == 0) {
		/* we're at the end of headers. */
		i_assert(hdr == NULL);
		i_assert(mstream->istream.istream.v_offset +
			 mstream->istream.pos ==
			 mstream->header_size.virtual_size);

		return i_stream_header_filter_read(&mstream->istream);
	}

	return ret;
}

static ssize_t
handle_end_body_with_lf(struct header_filter_istream *mstream, ssize_t ret)
{
	struct istream_private *stream = &mstream->istream;
	const unsigned char *data;
	size_t size, last_offset;
	bool last_lf;

	data = i_stream_get_data(stream->parent, &size);
	last_offset = stream->parent->v_offset + size-1;

	if (mstream->last_lf_offset == last_offset)
		last_lf = TRUE;
	else if (size > 0)
		last_lf = data[size-1] == '\n';
	else
		last_lf = FALSE;

	if (ret == -1 && stream->parent->eof && !last_lf) {
		/* missing LF, need to add it */
		i_assert(!mstream->last_lf_added);
		i_assert(size == 0 || data[size-1] != '\n');

		buffer_set_used_size(mstream->hdr_buf, 0);
		buffer_append(mstream->hdr_buf, data, size);
		if (mstream->crlf)
			buffer_append_c(mstream->hdr_buf, '\r');
		buffer_append_c(mstream->hdr_buf, '\n');
		mstream->last_lf_offset = last_offset;
		mstream->last_lf_added = TRUE;

		stream->skip = 0;
		stream->pos = mstream->hdr_buf->used;
		stream->buffer = mstream->hdr_buf->data;
		return mstream->crlf ? 2 : 1;
	} else {
		mstream->last_lf_offset = last_lf ? last_offset : (uoff_t)-1;
	}
	return ret;
}

static ssize_t i_stream_header_filter_read(struct istream_private *stream)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;
	uoff_t v_offset;
	ssize_t ret;

	if (mstream->last_lf_added) {
		stream->istream.eof = TRUE;
		return -1;
	}

	if (!mstream->header_read ||
	    stream->istream.v_offset < mstream->header_size.virtual_size)
		return read_header(mstream);

	if (mstream->hide_body) {
		stream->istream.eof = TRUE;
		return -1;
	}

	v_offset = stream->parent_start_offset + stream->istream.v_offset -
		mstream->header_size.virtual_size +
		mstream->header_size.physical_size;
	i_stream_seek(stream->parent, v_offset);
	ret = i_stream_read_copy_from_parent(&stream->istream);
	if (mstream->end_body_with_lf)
		ret = handle_end_body_with_lf(mstream, ret);
	return ret;
}

static void
i_stream_header_filter_seek_to_header(struct header_filter_istream *mstream,
				      uoff_t v_offset)
{
	i_stream_seek(mstream->istream.parent,
		      mstream->istream.parent_start_offset);
	mstream->istream.parent_expected_offset =
		mstream->istream.parent_start_offset;
	mstream->istream.access_counter =
		mstream->istream.parent->real_stream->access_counter;

	if (mstream->hdr_ctx != NULL)
		message_parse_header_deinit(&mstream->hdr_ctx);
	mstream->skip_count = v_offset;
	mstream->cur_line = 0;
	mstream->prev_matched = FALSE;
	mstream->header_read = FALSE;
	mstream->seen_eoh = FALSE;
	mstream->last_added_newline = TRUE;
}

static int skip_header(struct header_filter_istream *mstream)
{
	size_t pos;

	if (mstream->header_read)
		return 0;

	if (mstream->istream.access_counter !=
	    mstream->istream.parent->real_stream->access_counter) {
		/* need to re-parse headers */
		i_stream_header_filter_seek_to_header(mstream, 0);
	}

	while (!mstream->header_read &&
	       i_stream_read_memarea(&mstream->istream.istream) != -1) {
		pos = i_stream_get_data_size(&mstream->istream.istream);
		i_stream_skip(&mstream->istream.istream, pos);
	}
	return mstream->istream.istream.stream_errno != 0 ? -1 : 0;
}

static void
stream_reset_to(struct header_filter_istream *mstream, uoff_t v_offset)
{
	mstream->istream.istream.v_offset = v_offset;
	mstream->istream.skip = mstream->istream.pos = 0;
	mstream->istream.buffer = NULL;
	buffer_set_used_size(mstream->hdr_buf, 0);
}

static void i_stream_header_filter_seek(struct istream_private *stream,
					uoff_t v_offset, bool mark ATTR_UNUSED)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;

	if (stream->istream.v_offset == v_offset) {
		/* just reset the input buffer */
		stream_reset_to(mstream, v_offset);
		i_stream_seek(mstream->istream.parent,
			      mstream->istream.parent_expected_offset);
		return;
	}
	/* if last_lf_added=TRUE, we're currently at EOF. So reset it only if
	   we're seeking backwards, otherwise we would just add a duplicate */
	mstream->last_lf_added = FALSE;

	if (v_offset == 0) {
		/* seeking to beginning of headers. */
		stream_reset_to(mstream, 0);
		i_stream_header_filter_seek_to_header(mstream, 0);
		return;
	}

	/* if we haven't parsed the whole header yet, we don't know if we
	   want to seek inside header or body. so make sure we've parsed the
	   header. */
	if (skip_header(mstream) < 0)
		return;
	stream_reset_to(mstream, v_offset);

	if (v_offset < mstream->header_size.virtual_size) {
		/* seek into headers. we'll have to re-parse them, use
		   skip_count to set the wanted position */
		i_stream_header_filter_seek_to_header(mstream, v_offset);
	} else {
		/* body */
		v_offset += mstream->header_size.physical_size -
			mstream->header_size.virtual_size;
		i_stream_seek(stream->parent,
			      stream->parent_start_offset + v_offset);
	}
}

static void ATTR_NORETURN
i_stream_header_filter_sync(struct istream_private *stream ATTR_UNUSED)
{
	i_panic("istream-header-filter sync() not implemented");
}

static int
i_stream_header_filter_stat(struct istream_private *stream, bool exact)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;
	const struct stat *st;
	uoff_t old_offset;

	if (i_stream_stat(stream->parent, exact, &st) < 0) {
		stream->istream.stream_errno = stream->parent->stream_errno;
		return -1;
	}
	stream->statbuf = *st;
	if (stream->statbuf.st_size == -1 || !exact)
		return 0;

	/* fix the filtered header size */
	old_offset = stream->istream.v_offset;
	if (skip_header(mstream) < 0)
		return -1;

	if (mstream->hide_body) {
		/* no body */
		stream->statbuf.st_size = mstream->header_size.physical_size;
	} else if (!mstream->end_body_with_lf) {
		/* no last-LF */
	} else if (mstream->last_lf_added) {
		/* yes, we have added LF */
		stream->statbuf.st_size += mstream->crlf ? 2 : 1;
	} else if (mstream->last_lf_offset != (uoff_t)-1) {
		/* no, we didn't need to add LF */
	} else {
		/* check if we need to add LF */
		i_stream_seek(stream->parent, st->st_size - 1);
		(void)i_stream_read_memarea(stream->parent);
		if (stream->parent->stream_errno != 0) {
			stream->istream.stream_errno =
				stream->parent->stream_errno;
			return -1;
		}
		i_assert(stream->parent->eof);
		ssize_t ret = handle_end_body_with_lf(mstream, -1);
		if (ret > 0)
			stream->statbuf.st_size += ret;
	}

	stream->statbuf.st_size -=
		(off_t)mstream->header_size.physical_size -
		(off_t)mstream->header_size.virtual_size;
	i_stream_seek(&stream->istream, old_offset);
	return 0;
}

#undef i_stream_create_header_filter
struct istream *
i_stream_create_header_filter(struct istream *input,
                              enum header_filter_flags flags,
			      const char *const *headers,
			      unsigned int headers_count,
			      header_filter_callback *callback, void *context)
{
	struct header_filter_istream *mstream;
	unsigned int i, j;
	int ret;

	i_assert((flags & (HEADER_FILTER_INCLUDE|HEADER_FILTER_EXCLUDE)) != 0);

	mstream = i_new(struct header_filter_istream, 1);
	mstream->pool = pool_alloconly_create(MEMPOOL_GROWING
					      "header filter stream", 4096);
	mstream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	mstream->headers = headers_count == 0 ? NULL :
		p_new(mstream->pool, const char *, headers_count);
	for (i = j = 0; i < headers_count; i++)  {
		ret = j == 0 ? -1 :
			strcasecmp(mstream->headers[j-1], headers[i]);
		if (ret == 0) {
			/* drop duplicate */
			continue;
		} 
		i_assert(ret < 0);
		mstream->headers[j++] = p_strdup(mstream->pool, headers[i]);
	}
	mstream->headers_count = j;
	mstream->hdr_buf = buffer_create_dynamic(mstream->pool, 1024);

	mstream->callback = callback;
	mstream->context = context;
	mstream->exclude = (flags & HEADER_FILTER_EXCLUDE) != 0;
	if ((flags & HEADER_FILTER_CRLF_PRESERVE) != 0)
		mstream->crlf_preserve = TRUE;
	else if ((flags & HEADER_FILTER_NO_CR) != 0)
		mstream->crlf = FALSE;
	else
		mstream->crlf = TRUE;
	mstream->hide_body = (flags & HEADER_FILTER_HIDE_BODY) != 0;
	mstream->add_missing_eoh = (flags & HEADER_FILTER_ADD_MISSING_EOH) != 0;
	mstream->end_body_with_lf =
		(flags & HEADER_FILTER_END_BODY_WITH_LF) != 0;
	mstream->last_lf_offset = (uoff_t)-1;
	mstream->last_added_newline = TRUE;

	mstream->istream.iostream.destroy = i_stream_header_filter_destroy;
	mstream->istream.read = i_stream_header_filter_read;
	mstream->istream.seek = i_stream_header_filter_seek;
	mstream->istream.sync = i_stream_header_filter_sync;
	mstream->istream.stat = i_stream_header_filter_stat;

	mstream->istream.istream.readable_fd = FALSE;
	mstream->istream.istream.blocking = input->blocking;
	mstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&mstream->istream, input, -1, 0);
}

void i_stream_header_filter_add(struct header_filter_istream *input,
				const void *data, size_t size)
{
	buffer_append(input->hdr_buf, data, size);
	input->headers_edited = TRUE;
}
