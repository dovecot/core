/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "http-parser.h"
#include "http-header-parser.h"
#include "http-date.h"
#include "http-transfer.h"
#include "http-message-parser.h"

#include <ctype.h>

void http_message_parser_init(struct http_message_parser *parser,
			      struct istream *input)
{
	memset(parser, 0, sizeof(*parser));
	parser->input = input;
}

void http_message_parser_deinit(struct http_message_parser *parser)
{
	if (parser->header_parser != NULL)
		http_header_parser_deinit(&parser->header_parser);
	if (parser->msg_pool != NULL)
		pool_unref(&parser->msg_pool);
	if (parser->payload != NULL)
		i_stream_unref(&parser->payload);
}

void http_message_parser_restart(struct http_message_parser *parser)
{
	i_assert(parser->payload == NULL);

	if (parser->header_parser == NULL)
		parser->header_parser = http_header_parser_init(parser->input);
	else
		http_header_parser_reset(parser->header_parser);

	if (parser->msg_pool != NULL)
		pool_unref(&parser->msg_pool);
	parser->msg_pool = pool_alloconly_create("http_message", 4096);
	memset(&parser->msg, 0, sizeof(parser->msg));
	parser->msg.date = (time_t)-1;
	p_array_init(&parser->msg.headers, parser->msg_pool, 32);
}

int http_message_parse_version(struct http_message_parser *parser)
{
	const unsigned char *p = parser->cur;
	const size_t size = parser->end - parser->cur;

	/* HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
	   HTTP-name     = %x48.54.54.50 ; "HTTP", case-sensitive
	 */
	if (size < 8)
		return 0;
	if (memcmp(p, "HTTP/", 5) != 0 ||
	    !i_isdigit(p[5]) || p[6] != '.' || !i_isdigit(p[7]))
		return -1;
	parser->msg.version_major = p[5] - '0';
	parser->msg.version_minor = p[7] - '0';
	parser->cur += 8;
	return 1;
}

int http_message_parse_finish_payload(struct http_message_parser *parser,
				      const char **error_r)
{
	const unsigned char *data;
	size_t size;
	int ret;

	if (parser->payload == NULL)
		return 1;

	while ((ret = i_stream_read_data(parser->payload, &data, &size, 0)) > 0)
		i_stream_skip(parser->payload, size);
	if (ret == 0 || parser->payload->stream_errno != 0) {
		if (ret < 0)
			*error_r = "Stream error while skipping payload";
		return ret;
	}
	i_stream_unref(&parser->payload);
	return 1;
}

static int
http_message_parse_header(struct http_message_parser *parser, const char *name,
			  const unsigned char *data, size_t size,
			  const char **error_r)
{
	struct http_response_header *hdr;
	struct http_parser hparser;
	void *value;

	hdr = array_append_space(&parser->msg.headers);
	hdr->key = p_strdup(parser->msg_pool, name);
	hdr->value = value = p_malloc(parser->msg_pool, size+1);
	memcpy(value, data, size);
	hdr->size = size;

	switch (name[0]) {
	case 'C': case 'c':
		if (strcasecmp(name, "Connection") == 0) {
			const char *option;

			/* Connection        = 1#connection-option
				 connection-option = token
			*/
			http_parser_init(&hparser, data, size);
			for (;;) {
				if (http_parse_token_list_next(&hparser, &option) <= 0)
					break;
				if (strcasecmp(option, "close") == 0) {
					parser->msg.connection_close = TRUE;
					break; // not interested in any other options
				}
			}
			return 0;
		}
		if (strcasecmp(name, "Content-Length") == 0) {
			/* Content-Length = 1*DIGIT */
			if (str_to_uoff(hdr->value, &parser->msg.content_length) < 0) {
				*error_r = "Invalid Content-Length header";
				return -1;
			}
			return 0;
		}
		break;
	case 'D': case 'd':
		if (strcasecmp(name, "Date") == 0) {
			/* Date = HTTP-date */
			(void)http_date_parse(data, size, &parser->msg.date);
			return 0;
		}
		break;
	case 'L': case 'l':
		if (strcasecmp(name, "Location") == 0) {
			/* Location = URI-reference (not parsed here) */
			parser->msg.location = hdr->value;
			return 0;
		}
		break;
	case 'T': case 't':
		if (strcasecmp(name, "Transfer-Encoding") == 0) {
			/* Transfer-Encoding = 1#transfer-coding */
			parser->msg.transfer_encoding = hdr->value;
			return 0;
		}
		break;
	default:
		break;
	}
	return 0;
}

int http_message_parse_headers(struct http_message_parser *parser,
			       const char **error_r)
{
	const char *field_name, *error;
	const unsigned char *field_data;
	size_t field_size;
	int ret;

	/* *( header-field CRLF ) CRLF */
	while ((ret=http_header_parse_next_field
		(parser->header_parser, &field_name, &field_data, &field_size, &error)) > 0) {
		if (field_name == NULL) {
			/* EOH */
			return 1;
		}
		if (http_message_parse_header(parser, field_name, field_data,
					      field_size, error_r) < 0)
			return -1;
	}

	if (ret < 0) {
		*error_r = t_strdup_printf(
			"Failed to parse response header: %s", error);
	}
	return ret;
}

int http_message_parse_body(struct http_message_parser *parser,
			    const char **error_r)
{
	struct http_parser hparser;

	if (parser->msg.content_length > 0) {
		/* Got explicit message size from Content-Length: header */
		parser->payload =
			i_stream_create_limit(parser->input,
					      parser->msg.content_length);
	} else if (parser->msg.transfer_encoding != NULL) {
		const char *tenc;

		/* Transfer-Encoding = 1#transfer-coding
		   transfer-coding    = "chunked" / "compress" / "deflate" / "gzip"
				      / transfer-extension       ;  [FIXME]
		   transfer-extension = token *( OWS ";" OWS transfer-parameter )
		*/
		http_parser_init(&hparser,
				 (const unsigned char *)parser->msg.transfer_encoding,
				 strlen(parser->msg.transfer_encoding));
		for (;;) {
			if (http_parse_token_list_next(&hparser, &tenc) <= 0)
				break;
			if (strcasecmp(tenc, "chunked") == 0) {
				parser->payload =
					http_transfer_chunked_istream_create(parser->input);
				break; // FIXME
			} else {
				*error_r = t_strdup_printf(
					"Unknown Transfer-Encoding `%s'", tenc);
				return -1;
			}
		}
	}
	return 0;
}
