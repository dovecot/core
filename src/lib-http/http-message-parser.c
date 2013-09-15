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
	if (parser->msg.pool != NULL)
		pool_unref(&parser->msg.pool);
	if (parser->payload != NULL)
		i_stream_unref(&parser->payload);
}

void http_message_parser_restart(struct http_message_parser *parser,
	pool_t pool)
{
	i_assert(parser->payload == NULL);

	if (parser->header_parser == NULL)
		parser->header_parser = http_header_parser_init(parser->input);
	else
		http_header_parser_reset(parser->header_parser);

	if (parser->msg.pool != NULL)
		pool_unref(&parser->msg.pool);
	memset(&parser->msg, 0, sizeof(parser->msg));
	if (pool == NULL) {
		parser->msg.pool = pool_alloconly_create("http_message", 4096);
	} else {
		parser->msg.pool = pool;
		pool_ref(pool);
	}
	parser->msg.date = (time_t)-1;
	p_array_init(&parser->msg.headers, parser->msg.pool, 32);
	p_array_init(&parser->msg.connection_options, parser->msg.pool, 4);
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
	hdr->key = p_strdup(parser->msg.pool, name);
	hdr->value = value = p_malloc(parser->msg.pool, size+1);
	memcpy(value, data, size);
	hdr->size = size;

	/* https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-23
	     Section 3.2.2:

	   A sender MUST NOT generate multiple header fields with the same field
	   name in a message unless either the entire field value for that
	   header field is defined as a comma-separated list [i.e., #(values)]
	   or the header field is a well-known exception.
	 */

	switch (name[0]) {
	case 'C': case 'c':
		/* Connection: */
		if (strcasecmp(name, "Connection") == 0) {
			const char **opt_idx;
			const char *option;
			unsigned int num_tokens = 0;

			/* Multiple Connection headers are allowed and combined into one */

			/* Connection        = 1#connection-option
				 connection-option = token
			*/
			http_parser_init(&hparser, data, size);
			for (;;) {
				if (http_parse_token_list_next(&hparser, &option) <= 0)
					break;
				num_tokens++;
				if (strcasecmp(option, "close") == 0)
					parser->msg.connection_close = TRUE;
				opt_idx = array_append_space(&parser->msg.connection_options);
				*opt_idx = p_strdup(parser->msg.pool, option);
			}

			if (hparser.cur < hparser.end || num_tokens == 0) {
				*error_r = "Invalid Connection header";
				return -1;
			}

			return 0;
		}
		/* Content-Length: */
		if (strcasecmp(name, "Content-Length") == 0) {
			if (parser->msg.have_content_length) {
				*error_r = "Duplicate Content-Length header";
				return -1;
			}
			/* Content-Length = 1*DIGIT */
			if (str_to_uoff(hdr->value, &parser->msg.content_length) < 0) {
				*error_r = "Invalid Content-Length header";
				return -1;
			}
			parser->msg.have_content_length = TRUE;
			return 0;
		}
		break;
	case 'D': case 'd':
		if (strcasecmp(name, "Date") == 0) {
			if (parser->msg.date != (time_t)-1) {
				*error_r = "Duplicate Date header";
				return -1;
			}

			/* Date = HTTP-date */
			(void)http_date_parse(data, size, &parser->msg.date);
			return 0;
		}
		break;
	case 'L': case 'l':
		if (strcasecmp(name, "Location") == 0) {
			/* FIXME: move this to response parser */
			/* Location = URI-reference (not parsed here) */
			parser->msg.location = hdr->value;
			return 0;
		}
		break;
	case 'T': case 't':
		/* Transfer-Encoding: */
		if (strcasecmp(name, "Transfer-Encoding") == 0) {
			const char *trenc = NULL;
	
			/* Multiple Transfer-Encoding headers are allowed and combined into one */
			if (!array_is_created(&parser->msg.transfer_encoding))
				p_array_init(&parser->msg.transfer_encoding, parser->msg.pool, 4);

			/* Transfer-Encoding  = 1#transfer-coding 
				 transfer-coding    = "chunked" / "compress" / "deflate" / "gzip"
				                      / transfer-extension
				 transfer-extension = token *( OWS ";" OWS transfer-parameter )
				 transfer-parameter = attribute BWS "=" BWS value
				 attribute          = token
				 value              = word
			*/
			http_parser_init(&hparser, data, size);
			for (;;) {
				/* transfer-coding */
				if (http_parse_token(&hparser, &trenc) > 0) {
					struct http_transfer_coding *coding;
					bool parse_error;

					coding = array_append_space(&parser->msg.transfer_encoding);
					coding->name = p_strdup(parser->msg.pool, trenc);
		
					/* *( OWS ";" OWS transfer-parameter ) */
					parse_error = FALSE;
					for (;;) {
						struct http_transfer_param *param;
						const char *attribute, *value;

						/* OWS ";" OWS */
						http_parse_ows(&hparser);
						if (hparser.cur >= hparser.end || *hparser.cur != ';')
							break;
						hparser.cur++;
						http_parse_ows(&hparser);

						/* attribute */
						if (http_parse_token(&hparser, &attribute) <= 0) {
							parse_error = TRUE;
							break;
						}

						/* BWS "=" BWS */
						http_parse_ows(&hparser);
						if (hparser.cur >= hparser.end || *hparser.cur != '=') {
							parse_error = TRUE;
							break;
						}
						hparser.cur++;
						http_parse_ows(&hparser);

						/* value */
						if (http_parse_word(&hparser, &value) <= 0) {
							parse_error = TRUE;
							break;
						}
		
						if (!array_is_created(&coding->parameters))
							p_array_init(&coding->parameters, parser->msg.pool, 2);
						param = array_append_space(&coding->parameters);
						param->attribute = p_strdup(parser->msg.pool, attribute);
						param->value = p_strdup(parser->msg.pool, value);
					}
					if (parse_error)
						break;
					
				} else {
					/* http://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-23
							 Appendix B:

						 For compatibility with legacy list rules, recipients SHOULD accept
						 empty list elements.
					 */
				}
				http_parse_ows(&hparser);
				if (hparser.cur >= hparser.end || *hparser.cur != ',')
					break;
				hparser.cur++;
				http_parse_ows(&hparser);
			}

			if (hparser.cur < hparser.end ||
				array_count(&parser->msg.transfer_encoding) == 0) {
				*error_r = "Invalid Transfer-Encoding header";
				return -1;
			}
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


int http_message_parse_body(struct http_message_parser *parser, bool request,
			    const char **error_r)
{
	*error_r = NULL;

	if (array_is_created(&parser->msg.transfer_encoding)) {
		const struct http_transfer_coding *coding;

		bool chunked_last = FALSE;

		array_foreach(&parser->msg.transfer_encoding, coding) {
			if (strcasecmp(coding->name, "chunked") == 0) {
				chunked_last = TRUE;
		
				if (*error_r == NULL && array_is_created(&coding->parameters) &&
					array_count(&coding->parameters) > 0) {
					const struct http_transfer_param *param =
						array_idx(&coding->parameters, 0);
					
					*error_r = t_strdup_printf("Unexpected parameter `%s' specified"
						"for the `%s' transfer coding", param->attribute, coding->name);
				}
			} else if (chunked_last) {
				*error_r = "Chunked Transfer-Encoding must be last";
				return -1;
			} else if (*error_r == NULL) {
 				*error_r = t_strdup_printf(
  				"Unknown transfer coding `%s'", coding->name);
  		}
  	}

		if (chunked_last) {	
			parser->payload =
				http_transfer_chunked_istream_create(parser->input);
		} else if (!request) {
			/*  https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-23
			      Section 3.3.3.:

			    If a Transfer-Encoding header field is present in a response and
			    the chunked transfer coding is not the final encoding, the
			    message body length is determined by reading the connection until
			    it is closed by the server.
			 */
			parser->payload =
					i_stream_create_limit(parser->input, (size_t)-1);
		} else {
			/* https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-23
			      Section 3.3.3.:

			   If a Transfer-Encoding header field is present in a request and the
			   chunked transfer coding is not the final encoding, the message body
			   length cannot be determined reliably; the server MUST respond with
			   the 400 (Bad Request) status code and then close the connection.
			 */
			*error_r = "Final Transfer-Encoding in request is not `chunked'";
			return -1;
		}

		/* https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-23
		     Section 3.3.3.:

			 If a message is received with both a Transfer-Encoding and a
       Content-Length header field, the Transfer-Encoding overrides the
       Content-Length.  Such a message might indicate an attempt to
       perform request or response smuggling (bypass of security-related
       checks on message routing or content) and thus ought to be
       handled as an error.  A sender MUST remove the received Content-
       Length field prior to forwarding such a message downstream.
		 */
		if (parser->msg.have_content_length) {
			ARRAY_TYPE(http_response_header) *headers = &parser->msg.headers;
			const struct http_response_header *hdr;

			array_foreach(headers, hdr) {
				if (strcasecmp(hdr->key, "Content-Length") == 0) {
					array_delete(headers, array_foreach_idx(headers, hdr), 1);
					break;
				}
			}
		}
	} else if (parser->msg.content_length > 0) {
		/* Got explicit message size from Content-Length: header */
		parser->payload =
			i_stream_create_limit(parser->input,
					      parser->msg.content_length);
	} else if (!parser->msg.have_content_length && !request) {
		/* https://tools.ietf.org/html/draft-ietf-httpbis-p1-messaging-23
		     Section 3.3.3.:

		   If this is a request message and none of the above are true, then
		   the message body length is zero (no message body is present).

		   Otherwise, this is a response message without a declared message
		   body length, so the message body length is determined by the
		   number of octets received prior to the server closing the connection.
		 */
		parser->payload =
			i_stream_create_limit(parser->input, (size_t)-1);
	}
	return 0;
}
