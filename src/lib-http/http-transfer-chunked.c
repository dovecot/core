/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "ostream-private.h"
#include "http-parser.h"
#include "http-header-parser.h"

#include "http-transfer.h"

#define MIN_CHUNK_SIZE_WITH_EXTRA 6

/*
 * Chunked input stream
 */

enum http_transfer_chunked_parse_state {
	HTTP_CHUNKED_PARSE_STATE_INIT,
	HTTP_CHUNKED_PARSE_STATE_SIZE,
	HTTP_CHUNKED_PARSE_STATE_EXT,
	HTTP_CHUNKED_PARSE_STATE_EXT_NAME,
	HTTP_CHUNKED_PARSE_STATE_EXT_EQ,
	HTTP_CHUNKED_PARSE_STATE_EXT_VALUE,
	HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_STRING,
	HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_ESCAPE,
	HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_TOKEN,
	HTTP_CHUNKED_PARSE_STATE_CR,
	HTTP_CHUNKED_PARSE_STATE_LF,
	HTTP_CHUNKED_PARSE_STATE_DATA,
	HTTP_CHUNKED_PARSE_STATE_DATA_READY,
	HTTP_CHUNKED_PARSE_STATE_DATA_CR,
	HTTP_CHUNKED_PARSE_STATE_DATA_LF,
	HTTP_CHUNKED_PARSE_STATE_TRAILER,
	HTTP_CHUNKED_PARSE_STATE_FINISHED,
};

struct http_transfer_chunked_istream {
	struct istream_private istream;
	struct stat statbuf;

	const unsigned char *begin, *cur, *end;
	enum http_transfer_chunked_parse_state state;
	unsigned int parsed_chars;

	uoff_t chunk_size, chunk_v_offset, chunk_pos;
	uoff_t size, max_size;

	struct http_header_parser *header_parser;

	bool finished:1;
};

/* Chunk parser */

static inline const char *_chr_sanitize(unsigned char c)
{
	if (c >= 0x20 && c < 0x7F)
		return t_strdup_printf("'%c'", c);
	return t_strdup_printf("0x%02x", c);
}

static int
http_transfer_chunked_parse_size(struct http_transfer_chunked_istream *tcstream)
{
	uoff_t size = 0, prev;

	/* chunk-size     = 1*HEXDIG */

	while (tcstream->cur < tcstream->end) {
		prev = tcstream->chunk_size;

		if (*tcstream->cur >= '0' && *tcstream->cur <= '9')
			size = *tcstream->cur-'0';
		else if (*tcstream->cur >= 'A' && *tcstream->cur <= 'F')
			size = *tcstream->cur-'A' + 10;
		else if (*tcstream->cur >= 'a' && *tcstream->cur <= 'f')
			size = *tcstream->cur-'a' + 10;
		else {
			if (tcstream->parsed_chars == 0) {
				io_stream_set_error(
					&tcstream->istream.iostream,
					"Expected chunk size digit, "
					"but found %s",
					_chr_sanitize(*tcstream->cur));
				return -1;
			}
			tcstream->parsed_chars = 0;
			return 1;
		}
		tcstream->chunk_size <<= 4;
		tcstream->chunk_size += size;
		if (tcstream->chunk_size < prev) {
			io_stream_set_error(&tcstream->istream.iostream,
					    "Chunk size exceeds integer limit");
			return -1;
		}
		tcstream->parsed_chars++;
		tcstream->cur++;
	}

	return 0;
}

static int
http_transfer_chunked_skip_token(struct http_transfer_chunked_istream *tcstream)
{
	const unsigned char *first = tcstream->cur;

	/* token          = 1*tchar */
	while (tcstream->cur < tcstream->end &&
	       http_char_is_token(*tcstream->cur))
		tcstream->cur++;

	tcstream->parsed_chars += (tcstream->cur-first);
	if (tcstream->cur == tcstream->end)
		return 0;
	if (tcstream->parsed_chars == 0)
		return -1;
	return 1;
}

static int
http_transfer_chunked_skip_qdtext(
	struct http_transfer_chunked_istream *tcstream)
{
	/* qdtext      = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text */
	while (tcstream->cur < tcstream->end &&
	       http_char_is_qdtext(*tcstream->cur))
		tcstream->cur++;
	if (tcstream->cur == tcstream->end)
		return 0;
	return 1;
}

static int
http_transfer_chunked_parse(struct http_transfer_chunked_istream *tcstream)
{
	int ret;

	/* RFC 7230, Section 4.1: Chunked Transfer Encoding

	   chunked-body   = *chunk
	   	                last-chunk
		                  trailer-part
		                  CRLF

	   chunk          = chunk-size [ chunk-ext ] CRLF
	                    chunk-data CRLF
	   chunk-size     = 1*HEXDIG
	   last-chunk     = 1*("0") [ chunk-ext ] CRLF

	   chunk-ext      = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
	   chunk-ext-name = token
	   chunk-ext-val  = token / quoted-string
	   chunk-data     = 1*OCTET ; a sequence of chunk-size octets
	   trailer-part   = *( header-field CRLF )
	*/

	for (;;) {
		switch (tcstream->state) {
		case HTTP_CHUNKED_PARSE_STATE_INIT:
			tcstream->chunk_size = 0;
			tcstream->chunk_pos = 0;
			tcstream->parsed_chars = 0;
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_SIZE;
			/* fall through */
		case HTTP_CHUNKED_PARSE_STATE_SIZE:
			ret = http_transfer_chunked_parse_size(tcstream);
			if (ret <= 0)
				return ret;
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT;
			/* fall through */
		case HTTP_CHUNKED_PARSE_STATE_EXT:
			if (*tcstream->cur != ';') {
				tcstream->state = HTTP_CHUNKED_PARSE_STATE_CR;
				break;
			}
			/* chunk-ext */
			tcstream->cur++;
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT_NAME;
			if (tcstream->cur >= tcstream->end)
				return 0;
			/* fall through */
		case HTTP_CHUNKED_PARSE_STATE_EXT_NAME:
			/* chunk-ext-name = token */
			ret = http_transfer_chunked_skip_token(tcstream);
			if (ret <= 0) {
				if (ret < 0) {
					io_stream_set_error(
						&tcstream->istream.iostream,
						"Invalid chunked extension name");
				}
				return ret;
			}
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT_EQ;
			/* fall through */
		case HTTP_CHUNKED_PARSE_STATE_EXT_EQ:
			if (*tcstream->cur != '=') {
				tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT;
				break;
			}
			tcstream->cur++;
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT_VALUE;
			if (tcstream->cur >= tcstream->end)
				return 0;
			/* fall through */
		case HTTP_CHUNKED_PARSE_STATE_EXT_VALUE:
			/* chunk-ext-val  = token / quoted-string */
			if (*tcstream->cur != '"') {
				tcstream->state =
					HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_TOKEN;
				break;
			}
			tcstream->cur++;
			tcstream->state =
				HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_STRING;
			if (tcstream->cur >= tcstream->end)
				return 0;
			/* fall through */
		case HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_STRING:
			if (*tcstream->cur == '"') {
				tcstream->cur++;
				tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT;
				if (tcstream->cur >= tcstream->end)
					return 0;
			} else if ((ret = http_transfer_chunked_skip_qdtext(tcstream)) <= 0) {
				if (ret < 0) {
					io_stream_set_error(
						&tcstream->istream.iostream,
						"Invalid chunked extension value");
				}
				return ret;
			} else if (*tcstream->cur == '\\') {
				tcstream->cur++;
				tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_ESCAPE;
				if (tcstream->cur >= tcstream->end)
					return 0;
			} else {
				io_stream_set_error(
					&tcstream->istream.iostream,
					"Invalid character %s in chunked extension value string",
					_chr_sanitize(*tcstream->cur));
				return -1;
			}
			break;
		case HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_ESCAPE:
			/* ( HTAB / SP / VCHAR / obs-text ) */
			if (!http_char_is_text(*tcstream->cur)) {
				io_stream_set_error(
					&tcstream->istream.iostream,
					"Escaped invalid character %s in chunked extension value string",
					_chr_sanitize(*tcstream->cur));
				return -1;
			}
			tcstream->state =
				HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_STRING;
			if (tcstream->cur >= tcstream->end)
				return 0;
			break;
		case HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_TOKEN:
			ret = http_transfer_chunked_skip_token(tcstream);
			if (ret <= 0) {
				if (ret < 0) {
					io_stream_set_error(
						&tcstream->istream.iostream,
						"Invalid chunked extension value");
				}
				return ret;
			}
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT;
			break;
		case HTTP_CHUNKED_PARSE_STATE_CR:
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_LF;
			if (*tcstream->cur == '\r') {
				tcstream->cur++;
				if (tcstream->cur >= tcstream->end)
					return 0;
			}
			/* fall through */
		case HTTP_CHUNKED_PARSE_STATE_LF:
			if (*tcstream->cur != '\n') {
				io_stream_set_error(
					&tcstream->istream.iostream,
					"Expected new line after chunk size, "
					"but found %s",
					_chr_sanitize(*tcstream->cur));
				return -1;
			}
			tcstream->cur++;
			if (tcstream->chunk_size > 0)
				tcstream->state = HTTP_CHUNKED_PARSE_STATE_DATA;
			else
				tcstream->state = HTTP_CHUNKED_PARSE_STATE_TRAILER;
			return 1;
		case HTTP_CHUNKED_PARSE_STATE_DATA_READY:
			/* fall through */
		case HTTP_CHUNKED_PARSE_STATE_DATA_CR:
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_DATA_LF;
			if (*tcstream->cur == '\r') {
				tcstream->cur++;
				if (tcstream->cur >= tcstream->end)
					return 0;
			}
			/* fall through */
		case HTTP_CHUNKED_PARSE_STATE_DATA_LF:
			if (*tcstream->cur != '\n') {
				io_stream_set_error(
					&tcstream->istream.iostream,
					"Expected new line after chunk data, but found %s",
					_chr_sanitize(*tcstream->cur));
				return -1;
			}
			tcstream->cur++;
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_INIT;
			break;
		default:
			i_unreached();
		}
	}

	i_unreached();
	return -1;
}

static int
http_transfer_chunked_parse_next(struct http_transfer_chunked_istream *tcstream)
{
	struct istream_private *stream = &tcstream->istream;
	struct istream *input = tcstream->istream.parent;
	size_t size;
	int ret;

	while ((ret = i_stream_read_more(input, &tcstream->begin, &size)) > 0) {
		tcstream->cur = tcstream->begin;
		tcstream->end = tcstream->cur + size;

		if ((ret = http_transfer_chunked_parse(tcstream)) < 0) {
			stream->istream.stream_errno = EIO;
			return -1;
		}

		i_stream_skip(input, tcstream->cur - tcstream->begin);

		if (ret > 0) {
			if (tcstream->state == HTTP_CHUNKED_PARSE_STATE_DATA) {
				tcstream->chunk_v_offset = input->v_offset;

				tcstream->size += tcstream->chunk_size;
				if (tcstream->max_size > 0 &&
				    tcstream->size > tcstream->max_size) {
					io_stream_set_error(
						&tcstream->istream.iostream,
						"Total chunked payload size exceeds maximum");
					stream->istream.stream_errno = EMSGSIZE;
					return -1;
				}
			}
			return ret;
		}
	}

	i_assert(ret != -2);

	if (ret < 0) {
		if (stream->parent->eof &&
		    stream->parent->stream_errno == 0) {
			/* unexpected EOF */
			io_stream_set_error(&tcstream->istream.iostream,
					    "Unexpected end of payload");
			stream->istream.stream_errno = EIO;
		} else {
			/* parent stream error */
			stream->istream.stream_errno =
				stream->parent->stream_errno;
		}
	}
	return ret;
}

/* Input stream */

static ssize_t
http_transfer_chunked_istream_read_data(
	struct http_transfer_chunked_istream *tcstream)
{
	struct istream_private *stream = &tcstream->istream;
	const unsigned char *data;
	size_t size, avail;
	ssize_t ret = 0;

	i_assert(tcstream->chunk_pos <= tcstream->chunk_size);
	if (tcstream->chunk_pos == tcstream->chunk_size) {
		tcstream->state = HTTP_CHUNKED_PARSE_STATE_DATA_READY;
		return 0;
	}

	// FIXME: is this even necessary?
	i_stream_seek(stream->parent,
		      tcstream->chunk_v_offset + tcstream->chunk_pos);

	/* read from parent if necessary */
	data = i_stream_get_data(stream->parent, &size);
	if (size == 0) {
		ret = i_stream_read_memarea(stream->parent);
		if (ret <= 0) {
			i_assert(ret != -2); /* 0 sized buffer can't be full */
			if (stream->parent->eof &&
			    stream->parent->stream_errno == 0) {
				/* unexpected EOF */
				io_stream_set_error(
					&tcstream->istream.iostream,
					"Unexpected end of payload");
				stream->istream.stream_errno = EIO;
			} else {
				/* parent stream error */
				stream->istream.stream_errno =
					stream->parent->stream_errno;
			}
			return ret;
		}
		data = i_stream_get_data(stream->parent, &size);
		i_assert(size != 0);
	}

	size = (size > (tcstream->chunk_size - tcstream->chunk_pos) ?
		(tcstream->chunk_size - tcstream->chunk_pos) : size);

	/* Allocate buffer space */
	if (!i_stream_try_alloc(stream, size, &avail))
		return -2;

	/* Copy payload */
	size = size > avail ? avail : size;
	memcpy(&stream->w_buffer[stream->pos], data, size);

	i_stream_skip(stream->parent, size);

	tcstream->chunk_pos += size;
	i_assert(tcstream->chunk_pos <= tcstream->chunk_size);
	if (tcstream->chunk_pos == tcstream->chunk_size)
		tcstream->state = HTTP_CHUNKED_PARSE_STATE_DATA_READY;

	ret = size;
	stream->pos = stream->pos+size;
	return ret;
}

static int
http_transfer_chunked_parse_trailer(
	struct http_transfer_chunked_istream *tcstream)
{
	struct istream_private *stream = &tcstream->istream;
	const char *field_name, *error;
	const unsigned char *field_data;
	size_t field_size;
	int ret;

	if (tcstream->header_parser == NULL) {
		/* NOTE: trailer is currently ignored */
		/* FIXME: limit trailer size */
		tcstream->header_parser =
			http_header_parser_init(tcstream->istream.parent,
						NULL, 0);
	}

	while ((ret = http_header_parse_next_field(tcstream->header_parser,
						   &field_name, &field_data,
						   &field_size, &error)) > 0) {
		if (field_name == NULL)
			break;
	}

	if (ret <= 0) {
		if (ret < 0) {
			io_stream_set_error(
				&stream->iostream,
				"Failed to parse chunked trailer: %s", error);
			stream->istream.stream_errno = EIO;
		}
		return ret;
	}
	return 1;
}

static ssize_t
http_transfer_chunked_istream_read(struct istream_private *stream)
{
	struct http_transfer_chunked_istream *tcstream =
		(struct http_transfer_chunked_istream *)stream;
	ssize_t ret = 0;

	for (;;) {
		switch (tcstream->state) {
		case HTTP_CHUNKED_PARSE_STATE_FINISHED:
			tcstream->istream.istream.eof = TRUE;
			return -1;
		case 	HTTP_CHUNKED_PARSE_STATE_DATA:
			ret = http_transfer_chunked_istream_read_data(tcstream);
			if (ret != 0)
				return ret;
			if (tcstream->state !=
			    HTTP_CHUNKED_PARSE_STATE_DATA_READY)
				return 0;
			break;
		case HTTP_CHUNKED_PARSE_STATE_TRAILER:
			ret = http_transfer_chunked_parse_trailer(tcstream);
			if (ret <= 0)
				return ret;
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_FINISHED;
			tcstream->istream.istream.eof = TRUE;
			return -1;
		default:
			ret = http_transfer_chunked_parse_next(tcstream);
			if (ret <= 0)
				return ret;
		}
	}

	return -1;
}

static void
http_transfer_chunked_istream_destroy(struct iostream_private *stream)
{
	struct http_transfer_chunked_istream *tcstream =
		(struct http_transfer_chunked_istream *)stream;

	if (tcstream->header_parser != NULL)
		http_header_parser_deinit(&tcstream->header_parser);

	// FIXME: copied from istream.c; there's got to be a better way.
	i_stream_free_buffer(&tcstream->istream);
}

struct istream *
http_transfer_chunked_istream_create(struct istream *input, uoff_t max_size)
{
	struct http_transfer_chunked_istream *tcstream;

	tcstream = i_new(struct http_transfer_chunked_istream, 1);
	tcstream->max_size = max_size;

	tcstream->istream.max_buffer_size =
		input->real_stream->max_buffer_size;

	tcstream->istream.iostream.destroy =
		http_transfer_chunked_istream_destroy;
	tcstream->istream.read = http_transfer_chunked_istream_read;

	tcstream->istream.istream.readable_fd = FALSE;
	tcstream->istream.istream.blocking = input->blocking;
	tcstream->istream.istream.seekable = FALSE;
	return i_stream_create(&tcstream->istream, input,
			       i_stream_get_fd(input), 0);
}

/*
 * Chunked output stream
 */

// FIXME: provide support for corking the stream. This means that we'll have
// to buffer sent data here rather than in the parent steam; we need to know
// the size of the chunks before we can send them.

#define DEFAULT_MAX_BUFFER_SIZE (1024*32)

struct http_transfer_chunked_ostream {
	struct ostream_private ostream;

	size_t chunk_size, chunk_pos;

	bool chunk_active:1;
	bool sent_trailer:1;
};

static size_t _log16(size_t in)
{
	size_t res = 0;

	while (in > 0) {
		in >>= 4;
		res++;
	}
	return res;
}

static size_t _max_chunk_size(size_t avail)
{
	size_t chunk_extra = 2*2;

	/* Make sure we have room for both chunk data and overhead

	   chunk          = chunk-size [ chunk-ext ] CRLF
	                    chunk-data CRLF
	   chunk-size     = 1*HEXDIG
	 */
	chunk_extra += _log16(avail);
	return (avail < chunk_extra ? 0 : avail - chunk_extra);
}

static int
http_transfer_chunked_ostream_send_trailer(
	struct http_transfer_chunked_ostream *tcstream)
{
	struct ostream_private *stream = &tcstream->ostream;
	ssize_t sent;

	if (tcstream->sent_trailer)
		return 1;

	if (o_stream_get_buffer_avail_size(stream->parent) < 5) {
		if (o_stream_flush_parent(stream) < 0)
			return -1;
		if (o_stream_get_buffer_avail_size(stream->parent) < 5)
			return 0;
	}

	sent = o_stream_send(tcstream->ostream.parent, "0\r\n\r\n", 5);
	if (sent < 0) {
		o_stream_copy_error_from_parent(stream);
		return -1;
	}
	i_assert(sent == 5);

	tcstream->sent_trailer = TRUE;
	return 1;
}

static void
http_transfer_chunked_ostream_close(struct iostream_private *stream,
				    bool close_parent)
{
	struct http_transfer_chunked_ostream *tcstream =
		(struct http_transfer_chunked_ostream *)stream;

	i_assert(tcstream->ostream.finished ||
		 tcstream->ostream.ostream.stream_errno != 0 ||
		 tcstream->ostream.error_handling_disabled);
	if (close_parent)
		o_stream_close(tcstream->ostream.parent);
}

static int
http_transfer_chunked_ostream_flush(struct ostream_private *stream)
{
	struct http_transfer_chunked_ostream *tcstream =
		(struct http_transfer_chunked_ostream *)stream;
	int ret;

	if (stream->finished &&
	    (ret = http_transfer_chunked_ostream_send_trailer(tcstream)) <= 0)
		return ret;

	return o_stream_flush_parent(stream);
}

static ssize_t
http_transfer_chunked_ostream_sendv(struct ostream_private *stream,
				    const struct const_iovec *iov,
				    unsigned int iov_count)
{
	struct http_transfer_chunked_ostream *tcstream =
		(struct http_transfer_chunked_ostream *)stream;
	struct const_iovec *iov_new;
	unsigned int iov_count_new, i;
	size_t bytes = 0, max_bytes;
	ssize_t ret;
	const char *prefix;

	i_assert(stream->parent->real_stream->max_buffer_size >=
		 MIN_CHUNK_SIZE_WITH_EXTRA);

	if ((ret = o_stream_flush(stream->parent)) <= 0) {
		/* error / we still couldn't flush existing data to
		   parent stream. */
		o_stream_copy_error_from_parent(stream);
		return ret;
	}

	/* check how many bytes we want to send */
	bytes = 0;
	for (i = 0; i < iov_count; i++)
		bytes += iov[i].iov_len;

	/* check if we have room to send at least one byte */
	max_bytes = o_stream_get_buffer_avail_size(stream->parent);
	max_bytes = _max_chunk_size(max_bytes);
	if (max_bytes < MIN_CHUNK_SIZE_WITH_EXTRA)
		return 0;

	tcstream->chunk_size = (bytes > max_bytes ? max_bytes : bytes);

	/* determine what to send */
	bytes = tcstream->chunk_size;
	iov_count_new = 1;
	for (i = 0; i < iov_count && bytes > 0; i++) {
		if (bytes <= iov[i].iov_len)
			break;
		bytes -= iov[i].iov_len;
		iov_count_new++;
	}

	/* create new iovec */
	prefix = t_strdup_printf("%llx\r\n",
				 (unsigned long long)tcstream->chunk_size);
	iov_count = iov_count_new + 2;
	iov_new = t_new(struct const_iovec, iov_count);
	iov_new[0].iov_base = prefix;
	iov_new[0].iov_len = strlen(prefix);
	memcpy(&iov_new[1], iov, sizeof(struct const_iovec) * iov_count_new);
	iov_new[iov_count-2].iov_len = bytes;
	iov_new[iov_count-1].iov_base = "\r\n";
	iov_new[iov_count-1].iov_len = 2;

	/* send */
	if ((ret = o_stream_sendv(stream->parent, iov_new, iov_count)) <= 0) {
		i_assert(ret < 0);
		o_stream_copy_error_from_parent(stream);
		return -1;
	}

	/* all must be sent */
	i_assert((size_t)ret == (tcstream->chunk_size + iov_new[0].iov_len +
				 iov_new[iov_count-1].iov_len));

	stream->ostream.offset += tcstream->chunk_size;
	return tcstream->chunk_size;
}

struct ostream *
http_transfer_chunked_ostream_create(struct ostream *output)
{
	struct http_transfer_chunked_ostream *tcstream;
	size_t max_size;

	tcstream = i_new(struct http_transfer_chunked_ostream, 1);
	tcstream->ostream.sendv = http_transfer_chunked_ostream_sendv;
	tcstream->ostream.flush = http_transfer_chunked_ostream_flush;
	tcstream->ostream.iostream.close = http_transfer_chunked_ostream_close;
	if (output->real_stream->max_buffer_size > 0)
		max_size = output->real_stream->max_buffer_size;
	else
		max_size = DEFAULT_MAX_BUFFER_SIZE;

	tcstream->ostream.max_buffer_size = _max_chunk_size(max_size);
	return o_stream_create(&tcstream->ostream, output,
			       o_stream_get_fd(output));
}
