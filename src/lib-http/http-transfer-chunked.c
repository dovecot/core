/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "ostream-private.h"
#include "http-parser.h"
#include "http-header-parser.h"

#include "http-transfer.h"

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
	const char *error;

	struct http_header_parser *header_parser;

	unsigned int finished:1;
};

/* Chunk parser */

static inline const char *_chr_sanitize(unsigned char c)
{
	if (c >= 0x20 && c < 0x7F)
		return t_strdup_printf("'%c'", c);
	return t_strdup_printf("0x%02x", c);
}

static int http_transfer_chunked_parse_size
(struct http_transfer_chunked_istream *tcstream)
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
				tcstream->error = t_strdup_printf(
					"Expected chunk size digit, but found %s",
					_chr_sanitize(*tcstream->cur));
				return -1;
			}
			tcstream->parsed_chars = 0;
			return 1;
		}
		tcstream->chunk_size <<= 4;
		tcstream->chunk_size += size;
		if (tcstream->chunk_size < prev) {
			tcstream->error = "Chunk size exceeds integer limit";
			return -1;
		}
		tcstream->parsed_chars++;
		tcstream->cur++;
	}

	return 0;
}

static int http_transfer_chunked_skip_token
(struct http_transfer_chunked_istream *tcstream)
{
	const unsigned char *first = tcstream->cur;

	/* token          = 1*tchar */
	while (tcstream->cur < tcstream->end && http_char_is_token(*tcstream->cur))
		tcstream->cur++;

	tcstream->parsed_chars += (tcstream->cur-first);
	if (tcstream->cur == tcstream->end)
		return 0;
	if (tcstream->parsed_chars == 0)
		return -1;
	return 1;
}

static int http_transfer_chunked_skip_qdtext
(struct http_transfer_chunked_istream *tcstream)
{
	/* qdtext-nf      = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text */
	while (tcstream->cur < tcstream->end && http_char_is_qdtext(*tcstream->cur))
		tcstream->cur++;
	if (tcstream->cur == tcstream->end)
		return 0;
	return 1;
}

static int
http_transfer_chunked_parse(struct http_transfer_chunked_istream *tcstream)
{
	int ret;

	/* http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-21;
		   Section 4.1:

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
		 chunk-ext-val  = token / quoted-str-nf
		 chunk-data     = 1*OCTET ; a sequence of chunk-size octets
		 trailer-part   = *( header-field CRLF )

		 quoted-str-nf  = DQUOTE *( qdtext-nf / quoted-pair ) DQUOTE
		                ; like quoted-string, but disallowing line folding
		 qdtext-nf      = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
	   quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
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
			if ((ret=http_transfer_chunked_parse_size(tcstream)) <= 0)
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
			if ((ret=http_transfer_chunked_skip_token(tcstream)) <= 0) {
				if (ret < 0)
					tcstream->error = "Invalid chunked extension name";
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
			/* chunk-ext-val  = token / quoted-str-nf */
			if (*tcstream->cur != '"') {
				tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_TOKEN;
				break;
			} 
			tcstream->cur++;
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_STRING;
			if (tcstream->cur >= tcstream->end)
				return 0;
			/* fall through */
		case HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_STRING:
			for (;;) {
				if (*tcstream->cur == '"') {
					tcstream->cur++;
					tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT;
					if (tcstream->cur >= tcstream->end)
						return 0;
					break;
				} else if ((ret=http_transfer_chunked_skip_qdtext(tcstream)) <= 0) {
					if (ret < 0)
						tcstream->error = "Invalid chunked extension value";
					return ret;	
				} else if (*tcstream->cur == '\\') {
					tcstream->cur++;
					tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_ESCAPE;
					if (tcstream->cur >= tcstream->end)						
						return 0;
					break;
				} else {
					tcstream->error = t_strdup_printf(
						"Invalid character %s in chunked extension value string",
						_chr_sanitize(*tcstream->cur));
					return -1;
				}
			}
			break;
		case HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_ESCAPE:
			/* ( HTAB / SP / VCHAR / obs-text ) */
			if (!http_char_is_text(*tcstream->cur)) {
				tcstream->error = t_strdup_printf(
					"Escaped invalid character %s in chunked extension value string",
					_chr_sanitize(*tcstream->cur));
				return -1;
			}
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_STRING;
			if (tcstream->cur >= tcstream->end)						
				return 0;
			break;
		case HTTP_CHUNKED_PARSE_STATE_EXT_VALUE_TOKEN:
			if ((ret=http_transfer_chunked_skip_token(tcstream)) <= 0) {
				if (ret < 0)
					tcstream->error = "Invalid chunked extension value";
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
				tcstream->error = t_strdup_printf(
					"Expected new line after chunk size, but found %s",
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
				tcstream->error = t_strdup_printf(
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

static int http_transfer_chunked_parse_next(
	struct http_transfer_chunked_istream *tcstream)
{
	struct istream *input = tcstream->istream.parent;
	size_t size;
	int ret;

	while ((ret=i_stream_read_data
		(input, &tcstream->begin, &size, 0)) > 0) {
		tcstream->cur = tcstream->begin;
		tcstream->end = tcstream->cur + size;

		if ((ret=http_transfer_chunked_parse(tcstream)) < 0)
			return -1;

		i_stream_skip(input, tcstream->cur - tcstream->begin);

		if (ret > 0) {
			if (tcstream->state == HTTP_CHUNKED_PARSE_STATE_DATA)
				tcstream->chunk_v_offset = input->v_offset;
			return ret;
		}
	}

	i_assert(ret != -2);
	return ret;
}

static ssize_t
http_transfer_chunked_istream_read_data(
	struct http_transfer_chunked_istream *tcstream)
{
	struct istream_private *stream = &tcstream->istream;
	const unsigned char *data;
	size_t size, avail;
	ssize_t ret = 0;

	if (tcstream->chunk_pos >= tcstream->chunk_size) {
		tcstream->state = HTTP_CHUNKED_PARSE_STATE_DATA_READY;
		return 0;
	}

	// FIXME: is this even necessary?
	i_stream_seek(stream->parent, tcstream->chunk_v_offset + tcstream->chunk_pos);

	/* read from parent if necessary */
	data = i_stream_get_data(stream->parent, &size);
	if (size == 0) {
		ret = i_stream_read(stream->parent);
		if (ret <= 0 && (ret != -2 || stream->skip == 0)) {
			if ( stream->parent->eof && stream->parent->stream_errno == 0 ) {
				/* unexpected EOF */
				tcstream->error = "Unexpected end of payload";
				stream->istream.stream_errno = EIO;
			} else {
				/* parent stream error */
				tcstream->error = "Stream error";
				stream->istream.stream_errno = stream->parent->stream_errno;
			}
			return ret;
		}
		data = i_stream_get_data(stream->parent, &size);
		i_assert(size != 0);
	}

	size = size > (tcstream->chunk_size - tcstream->chunk_pos) ? 
		(tcstream->chunk_size - tcstream->chunk_pos) : size;

	/* Allocate buffer space */
	if (!i_stream_try_alloc(stream, size, &avail))
		return -2;

	/* Copy payload */
	size = size > avail ? avail : size;
	memcpy(&stream->w_buffer[stream->pos], data, size);

	i_stream_skip(stream->parent, size);

	tcstream->chunk_pos += size;
	if (tcstream->chunk_pos >= tcstream->chunk_size)
		tcstream->state = HTTP_CHUNKED_PARSE_STATE_DATA_READY;

	if ( ret < 0 ) {
		stream->pos = stream->pos+size;
		return ret;
	}

	ret = size;
	stream->pos = stream->pos+size;
	return ret;
}

static int http_transfer_chunked_parse_trailer(
	struct http_transfer_chunked_istream *tcstream)
{
	const char *field_name, *error;
	const unsigned char *field_data;
	size_t field_size;
	int ret;

	if (tcstream->header_parser == NULL) {
		tcstream->header_parser = http_header_parser_init(tcstream->istream.parent);
	}

	while ((ret=http_header_parse_next_field(tcstream->header_parser,
		&field_name, &field_data, &field_size, &error)) > 0) {
		if (field_name == NULL) break;
	}

	if (ret <= 0) {
		if (ret < 0) {
			tcstream->error = t_strdup_printf
				("Failed to parse chunked trailer: %s", error);
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
			if ((ret=http_transfer_chunked_istream_read_data(tcstream)) != 0)
				return ret;
			if (tcstream->state != HTTP_CHUNKED_PARSE_STATE_DATA_READY)
				return 0;
			break;
		case HTTP_CHUNKED_PARSE_STATE_TRAILER:
			if ((ret=http_transfer_chunked_parse_trailer(tcstream)) <= 0)
				return ret;
			tcstream->state = HTTP_CHUNKED_PARSE_STATE_FINISHED;
			tcstream->istream.istream.eof = TRUE;
			return -1;
		default:
			if ((ret=http_transfer_chunked_parse_next(tcstream)) <= 0)
				return ret;
		}
	}

	return -1;
}

struct istream *
http_transfer_chunked_istream_create(struct istream *input)
{
	struct http_transfer_chunked_istream *tcstream;

	tcstream = i_new(struct http_transfer_chunked_istream, 1);

	tcstream->istream.max_buffer_size =
		input->real_stream->max_buffer_size;

	tcstream->istream.read = http_transfer_chunked_istream_read;

	tcstream->istream.istream.readable_fd = FALSE;
	tcstream->istream.istream.blocking = input->blocking;
	tcstream->istream.istream.seekable = FALSE;
	return i_stream_create(&tcstream->istream, input, i_stream_get_fd(input));
}




