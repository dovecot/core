/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-dec.h"
#include "unichar.h"
#include "istream-private.h"
#include "istream-jsonstr.h"

#define MAX_UTF8_LEN 6

struct jsonstr_istream {
	struct istream_private istream;

	/* The end '"' was found */
	unsigned int str_end:1;
};

static int
i_stream_jsonstr_read_parent(struct jsonstr_istream *jstream,
			     unsigned int min_bytes)
{
	struct istream_private *stream = &jstream->istream;
	size_t size, avail;
	ssize_t ret;

	size = i_stream_get_data_size(stream->parent);
	while (size < min_bytes) {
		ret = i_stream_read(stream->parent);
		if (ret <= 0 && (ret != -2 || stream->skip == 0)) {
			stream->istream.stream_errno =
				stream->parent->stream_errno;
			stream->istream.eof = stream->parent->eof;
			return ret;
		}
		size = i_stream_get_data_size(stream->parent);
	}

	if (!i_stream_try_alloc(stream, size, &avail))
		return -2;
	return 1;
}

static int
i_stream_json_unescape(const unsigned char *src, unsigned char *dest,
		       unsigned int *src_size_r, unsigned int *dest_size_r)
{
	switch (*src) {
	case '"':
	case '\\':
	case '/':
		*dest = *src;
		break;
	case 'b':
		*dest = '\b';
		break;
	case 'f':
		*dest = '\f';
		break;
	case 'n':
		*dest = '\n';
		break;
	case 'r':
		*dest = '\r';
		break;
	case 't':
		*dest = '\t';
		break;
	case 'u': {
		buffer_t buf;

		buffer_create_from_data(&buf, dest, MAX_UTF8_LEN);
		uni_ucs4_to_utf8_c(hex2dec(src+1, 4), &buf);
		*src_size_r = 5;
		*dest_size_r = buf.used;
		return 0;
	}
	default:
		return -1;
	}
	*src_size_r = 1;
	*dest_size_r = 1;
	return 0;
}

static ssize_t i_stream_jsonstr_read(struct istream_private *stream)
{
	struct jsonstr_istream *jstream = (struct jsonstr_istream *)stream;
	const unsigned char *data;
	unsigned int srcskip, destskip, extra;
	size_t i, dest, size;
	ssize_t ret;

	if (jstream->str_end) {
		stream->istream.eof = TRUE;
		return -1;
	}

	ret = i_stream_jsonstr_read_parent(jstream, 1);
	if (ret <= 0)
		return ret;

	/* @UNSAFE */
	dest = stream->pos;
	extra = 0;

	data = i_stream_get_data(stream->parent, &size);
	for (i = 0; i < size && dest < stream->buffer_size; ) {
		if (data[i] == '"') {
			jstream->str_end = TRUE;
			if (dest == stream->pos) {
				stream->istream.eof = TRUE;
				return -1;
			}
			break;
		} else if (data[i] == '\\') {
			if (i+1 == size) {
				/* not enough input for \x */
				extra = 1;
				break;
			}
			if ((data[i+1] == 'u' && i+1+4 >= size)) {
				/* not enough input for \u0000 */
				extra = 5;
				break;
			}
			if (data[i+1] == 'u' && stream->buffer_size - dest < MAX_UTF8_LEN) {
				/* UTF8 output is max. 6 chars */
				if (dest == stream->pos)
					return -2;
				break;
			}
			i++;
			if (i_stream_json_unescape(data + i,
						   stream->w_buffer + dest,
						   &srcskip, &destskip) < 0) {
				/* invalid string */
				stream->istream.stream_errno = EINVAL;
				return -1;
			}
			i += srcskip;
			i_assert(i <= size);
			dest += destskip;
			i_assert(dest <= stream->buffer_size);
		} else {
			stream->w_buffer[dest++] = data[i];
			i++;
		}
	}
	i_stream_skip(stream->parent, i);

	ret = dest - stream->pos;
	if (ret == 0) {
		/* not enough input */
		i_assert(extra > 0);
		ret = i_stream_jsonstr_read_parent(jstream, i+extra+1);
		if (ret <= 0)
			return ret;
		return i_stream_jsonstr_read(stream);
	}
	i_assert(ret > 0);
	stream->pos = dest;
	return ret;
}

struct istream *i_stream_create_jsonstr(struct istream *input)
{
	struct jsonstr_istream *dstream;

	dstream = i_new(struct jsonstr_istream, 1);
	dstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	dstream->istream.read = i_stream_jsonstr_read;

	dstream->istream.istream.readable_fd = FALSE;
	dstream->istream.istream.blocking = input->blocking;
	dstream->istream.istream.seekable = FALSE;
	return i_stream_create(&dstream->istream, input,
			       i_stream_get_fd(input));
}
