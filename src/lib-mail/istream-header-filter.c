/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "message-parser.h"
#include "istream-internal.h"
#include "istream-header-filter.h"

#include <stdlib.h>

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
	ARRAY_DEFINE(match_change_lines, unsigned int);

	unsigned int header_read:1;
	unsigned int seen_eoh:1;
	unsigned int header_parsed:1;
	unsigned int exclude:1;
	unsigned int crlf:1;
	unsigned int hide_body:1;
	unsigned int add_missing_eoh:1;
	unsigned int end_body_with_lf:1;
	unsigned int last_lf_added:1;
};

header_filter_callback *null_header_filter_callback = NULL;

static ssize_t i_stream_header_filter_read(struct istream_private *stream);

static void i_stream_header_filter_destroy(struct iostream_private *stream)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;

	if (mstream->hdr_ctx != NULL)
		message_parse_header_deinit(&mstream->hdr_ctx);
	i_stream_unref(&mstream->istream.parent);
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

		ret = i_stream_read(mstream->istream.parent);
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
				mstream->istream.buffer =
					buffer_get_data(mstream->hdr_buf,
							&mstream->istream.pos);
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

static void add_eol(struct header_filter_istream *mstream)
{
	if (mstream->crlf)
		buffer_append(mstream->hdr_buf, "\r\n", 2);
	else
		buffer_append_c(mstream->hdr_buf, '\n');
}

static ssize_t read_header(struct header_filter_istream *mstream)
{
	struct message_header_line *hdr;
	uoff_t highwater_offset;
	size_t pos;
	ssize_t ret;
	bool matched;
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

	while ((hdr_ret = message_parse_header_next(mstream->hdr_ctx,
						    &hdr)) > 0) {
		mstream->cur_line++;

		if (hdr->eoh) {
			mstream->seen_eoh = TRUE;
			matched = TRUE;
			if (!mstream->header_parsed &&
			    mstream->callback != NULL) {
				mstream->callback(hdr, &matched,
						  mstream->context);
			}

			if (!matched)
				continue;

			add_eol(mstream);
			continue;
		}

		matched = mstream->headers_count == 0 ? FALSE :
			bsearch(hdr->name, mstream->headers,
				mstream->headers_count,
				sizeof(*mstream->headers),
				bsearch_strcasecmp) != NULL;
		if (mstream->callback == NULL) {
			/* nothing gets excluded */
		} else if (mstream->cur_line > mstream->parsed_lines) {
			/* first time in this line */
			bool orig_matched = matched;

			mstream->parsed_lines = mstream->cur_line;
			mstream->callback(hdr, &matched, mstream->context);
			if (matched != orig_matched) {
				i_array_init(&mstream->match_change_lines, 8);
				array_append(&mstream->match_change_lines,
					     &mstream->cur_line, 1);
			}
		} else {
			/* second time in this line. was it excluded by the
			   callback the first time? */
			if (match_line_changed(mstream))
				matched = !matched;
		}

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
				add_eol(mstream);

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
			mstream->seen_eoh = TRUE;
			add_eol(mstream);
		}
	}

	/* don't copy eof here because we're only returning headers here.
	   the body will be returned in separate read() call. */
	mstream->istream.buffer = buffer_get_data(mstream->hdr_buf, &pos);
	ret = (ssize_t)(pos - mstream->istream.pos - mstream->istream.skip);
	i_assert(ret >= 0);
	mstream->istream.pos = pos;

	if (hdr_ret == 0) {
		/* need more data to finish parsing headers. we may have some
		   data already available though. */
		return ret;
	}

	if (hdr == NULL) {
		/* finished */
		message_parse_header_deinit(&mstream->hdr_ctx);
		mstream->hdr_ctx = NULL;

		if (!mstream->header_parsed && mstream->callback != NULL)
			mstream->callback(NULL, &matched, mstream->context);
		mstream->header_parsed = TRUE;
		mstream->header_read = TRUE;

		mstream->header_size.physical_size =
			mstream->istream.parent->v_offset;
		mstream->header_size.virtual_size =
			mstream->istream.istream.v_offset + pos;
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

		buffer_reset(mstream->hdr_buf);
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
	    stream->istream.v_offset < mstream->header_size.virtual_size) {
		ret = read_header(mstream);
		if (ret != -2 || stream->pos != stream->skip)
			return ret;
	}

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
	mstream->header_read = FALSE;
	mstream->seen_eoh = FALSE;
}

static void skip_header(struct header_filter_istream *mstream)
{
	size_t pos;

	if (mstream->header_read)
		return;

	if (mstream->istream.access_counter !=
	    mstream->istream.parent->real_stream->access_counter) {
		/* need to re-parse headers */
		i_stream_header_filter_seek_to_header(mstream, 0);
	}

	while (!mstream->header_read &&
	       i_stream_read(&mstream->istream.istream) != -1) {
		(void)i_stream_get_data(&mstream->istream.istream, &pos);
		i_stream_skip(&mstream->istream.istream, pos);
	}
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
	skip_header(mstream);
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

static const struct stat *
i_stream_header_filter_stat(struct istream_private *stream, bool exact)
{
	struct header_filter_istream *mstream =
		(struct header_filter_istream *)stream;
	const struct stat *st;
	uoff_t old_offset;

	st = i_stream_stat(stream->parent, exact);
	if (st == NULL || st->st_size == -1 || !exact)
		return st;

	old_offset = stream->istream.v_offset;
	skip_header(mstream);

	stream->statbuf = *st;
	stream->statbuf.st_size -=
		(off_t)mstream->header_size.physical_size -
		(off_t)mstream->header_size.virtual_size;
	i_stream_seek(&stream->istream, old_offset);
	return &stream->statbuf;
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
	mstream->crlf = (flags & HEADER_FILTER_NO_CR) == 0;
	mstream->hide_body = (flags & HEADER_FILTER_HIDE_BODY) != 0;
	mstream->add_missing_eoh = (flags & HEADER_FILTER_ADD_MISSING_EOH) != 0;
	mstream->end_body_with_lf =
		(flags & HEADER_FILTER_END_BODY_WITH_LF) != 0;

	mstream->istream.iostream.destroy = i_stream_header_filter_destroy;
	mstream->istream.read = i_stream_header_filter_read;
	mstream->istream.seek = i_stream_header_filter_seek;
	mstream->istream.sync = i_stream_header_filter_sync;
	mstream->istream.stat = i_stream_header_filter_stat;

	mstream->istream.istream.readable_fd = FALSE;
	mstream->istream.istream.blocking = input->blocking;
	mstream->istream.istream.seekable = input->seekable;

	return i_stream_create(&mstream->istream, input, -1);
}
