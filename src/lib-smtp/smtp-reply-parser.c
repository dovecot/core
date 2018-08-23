/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strfuncs.h"
#include "istream.h"
#include "smtp-parser.h"

#include "smtp-reply-parser.h"

#include <ctype.h>

/* From RFC 5321:

   Reply-line     = *( Reply-code "-" [ textstring ] CRLF )
                      Reply-code [ SP textstring ] CRLF
   Reply-code     = %x32-35 %x30-35 %x30-39
   textstring     = 1*(%d09 / %d32-126) ; HT, SP, Printable US-ASCII

   Greeting       = ( "220 " (Domain / address-literal)
                      [ SP textstring ] CRLF ) /
                    ( "220-" (Domain / address-literal)
                        [ SP textstring ] CRLF
                      *( "220-" [ textstring ] CRLF )
                        "220" [ SP textstring ] CRLF )

   ehlo-ok-rsp    = ( "250" SP Domain [ SP ehlo-greet ] CRLF )
                    / ( "250-" Domain [ SP ehlo-greet ] CRLF
                      *( "250-" ehlo-line CRLF )
                    "250" SP ehlo-line CRLF )
   ehlo-greet     = 1*(%d0-9 / %d11-12 / %d14-127)
                    ; string of any characters other than CR or LF
   ehlo-line      = ehlo-keyword *( SP ehlo-param )
   ehlo-keyword   = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
                    ; additional syntax of ehlo-params depends on
                    ; ehlo-keyword
   ehlo-param     = 1*(%d33-126)
                    ; any CHAR excluding <SP> and all
                    ; control characters (US-ASCII 0-31 and 127
                    ; inclusive)

   From RFC 2034:

   status-code  ::= class "." subject "." detail
   class        ::= "2" / "4" / "5"
   subject      ::= 1*3digit
   detail       ::= 1*3digit
 */

enum smtp_reply_parser_state {
	SMTP_REPLY_PARSE_STATE_INIT = 0,
	SMTP_REPLY_PARSE_STATE_CODE,
	SMTP_REPLY_PARSE_STATE_SEP,
	SMTP_REPLY_PARSE_STATE_TEXT,
	SMTP_REPLY_PARSE_STATE_EHLO_SPACE,
	SMTP_REPLY_PARSE_STATE_EHLO_GREET,
	SMTP_REPLY_PARSE_STATE_CR,
	SMTP_REPLY_PARSE_STATE_CRLF,
	SMTP_REPLY_PARSE_STATE_LF
};

struct smtp_reply_parser_state_data {
	enum smtp_reply_parser_state state;
	unsigned int line;

	struct smtp_reply *reply;
	ARRAY_TYPE(const_string) reply_lines;
	size_t reply_size;

	bool last_line:1;
};

struct smtp_reply_parser {
	struct istream *input;

	size_t max_reply_size;

	const unsigned char *begin, *cur, *end;

	string_t *strbuf;

	struct smtp_reply_parser_state_data state;
	pool_t reply_pool;

	char *error;

	bool enhanced_codes:1;
	bool ehlo:1;
};

static inline void ATTR_FORMAT(2, 3)
smtp_reply_parser_error(struct smtp_reply_parser *parser,
			const char *format, ...)
{
	va_list args;

	i_free(parser->error);

	va_start(args, format);
	parser->error = i_strdup_vprintf(format, args);
	va_end(args);
}

struct smtp_reply_parser *
smtp_reply_parser_init(struct istream *input, size_t max_reply_size)
{
	struct smtp_reply_parser *parser;

	parser = i_new(struct smtp_reply_parser, 1);
	parser->max_reply_size =
		(max_reply_size > 0 ? max_reply_size : (size_t)-1);
	parser->input = input;
	i_stream_ref(input);
	parser->strbuf = str_new(default_pool, 128);
	return parser;
}

void smtp_reply_parser_deinit(struct smtp_reply_parser **_parser)
{
	struct smtp_reply_parser *parser = *_parser;

	*_parser = NULL;

	str_free(&parser->strbuf);
	pool_unref(&parser->reply_pool);
	i_stream_unref(&parser->input);
	i_free(parser->error);
	i_free(parser);
}

void smtp_reply_parser_set_stream(struct smtp_reply_parser *parser,
				  struct istream *input)
{
	i_stream_unref(&parser->input);
	if (input != NULL) {
		parser->input = input;
		i_stream_ref(parser->input);
	}
}

static void
smtp_reply_parser_restart(struct smtp_reply_parser *parser)
{
	str_truncate(parser->strbuf, 0);
	pool_unref(&parser->reply_pool);
	i_zero(&parser->state);

	parser->reply_pool = pool_alloconly_create("smtp_reply", 1024);
	parser->state.reply = p_new(parser->reply_pool, struct smtp_reply, 1);
	p_array_init(&parser->state.reply_lines, parser->reply_pool, 8);

}

static int smtp_reply_parse_code
(struct smtp_reply_parser *parser, unsigned int *code_r)
{
	const unsigned char *first = parser->cur;
	const unsigned char *p;

	/* Reply-code     = %x32-35 %x30-35 %x30-39
	 */
	while (parser->cur < parser->end && i_isdigit(*parser->cur))
		parser->cur++;

	if (str_len(parser->strbuf) + (parser->cur-first) > 3)
		return -1;

	str_append_data(parser->strbuf, first, parser->cur - first);
	if (parser->cur == parser->end)
		return 0;
	if (str_len(parser->strbuf) != 3)
		return -1;
	p = str_data(parser->strbuf);
	if (p[0] < '2' || p[0] > '5' || p[1] > '5')
		return -1;
	*code_r = (p[0] - '0')*100 + (p[1] - '0')*10 + (p[2] - '0');
	str_truncate(parser->strbuf, 0);
	return 1;
}

static int smtp_reply_parse_textstring(struct smtp_reply_parser *parser)
{
	const unsigned char *first = parser->cur;

	/* textstring = 1*(%d09 / %d32-126) ; HT, SP, Printable US-ASCII
	 */
	while (parser->cur < parser->end && smtp_char_is_textstr(*parser->cur))
		parser->cur++;

	if (((parser->cur-first) + parser->state.reply_size +
		str_len(parser->strbuf)) > parser->max_reply_size) {
		smtp_reply_parser_error(parser,
			"Reply exceeds size limit");
		return -1;
	}

	str_append_data(parser->strbuf, first, parser->cur - first);
	if (parser->cur == parser->end)
		return 0;
	return 1;
}

static int smtp_reply_parse_ehlo_domain(struct smtp_reply_parser *parser)
{
	const unsigned char *first = parser->cur;

	/* Domain [ SP ...
	 */
	while (parser->cur < parser->end && *parser->cur != ' ' &&
		smtp_char_is_textstr(*parser->cur))
		parser->cur++;

	if (((parser->cur-first) + parser->state.reply_size +
		str_len(parser->strbuf)) > parser->max_reply_size) {
		smtp_reply_parser_error(parser,
			"Reply exceeds size limit");
		return -1;
	}
	str_append_data(parser->strbuf, first, parser->cur - first);
	if (parser->cur == parser->end)
		return 0;
	return 1;
}

static int smtp_reply_parse_ehlo_greet(struct smtp_reply_parser *parser)
{
	const unsigned char *first = parser->cur;

	/* ehlo-greet     = 1*(%d0-9 / %d11-12 / %d14-127)
	 *
	 * The greet is not supposed to be empty, but we don't really care
	 */

	if (parser->cur == parser->end)
		return 0;
	if (smtp_char_is_ehlo_greet(*parser->cur)) {
		for (;;) {
			while (parser->cur < parser->end &&
				smtp_char_is_textstr(*parser->cur))
				parser->cur++;

			if (((parser->cur-first) + parser->state.reply_size +
				str_len(parser->strbuf)) >
				parser->max_reply_size) {
				smtp_reply_parser_error(parser,
					"Reply exceeds size limit");
				return -1;
			}

			/* sanitize bad characters */
			str_append_data(parser->strbuf,
				first, parser->cur - first);

			if (parser->cur == parser->end)
				return 0;
			if (!smtp_char_is_ehlo_greet(*parser->cur))
				break;
			str_append_c(parser->strbuf, ' ');
			parser->cur++;
			first = parser->cur;
		}
	}
	return 1;
}

static inline const char *_chr_sanitize(unsigned char c)
{
	if (c >= 0x20 && c < 0x7F)
		return t_strdup_printf("'%c'", c);
	return t_strdup_printf("0x%02x", c);
}

static void
smtp_reply_parse_enhanced_code(struct smtp_reply_parser *parser,
	const char **pos)
{
	const char *p = *pos;
	unsigned int digits, x, y, z;
	unsigned int prevx = parser->state.reply->enhanced_code.x,
		prevy = parser->state.reply->enhanced_code.y,
		prevz = parser->state.reply->enhanced_code.z;

	if (prevx == 9)
		return; /* failed on earlier line */

	parser->state.reply->enhanced_code.x = 9;
	parser->state.reply->enhanced_code.y = 0;
	parser->state.reply->enhanced_code.z = 0;

	/* status-code ::= class "." subject "." detail
	   class       ::= "2" / "4" / "5"
	   subject     ::= 1*3digit
	   detail      ::= 1*3digit
	*/

	/* class */
	if (p[1] != '.' || (p[0] != '2' && p[0] != '4' && p[0] != '5'))
		return;
	x = p[0] - '0';
	p += 2;

	/* subject */
	digits = 0;
	y = 0;
	while (*p != '\0' && i_isdigit(*p) && digits++ < 3) {
		y = y*10 + (*p - '0');
		p++;
	}
	if (digits == 0 || *p != '.')
		return;
	p++;

	/* detail */
	digits = 0;
	z = 0;
	while (*p != '\0' && i_isdigit(*p) && digits++ < 3) {
		z = z*10 + (*p - '0');
		p++;
	}
	if (digits == 0 || (*p != ' ' && *p != '\r' && *p != '\n'))
		return;
	p++;

	/* code is syntactically valid; strip code from textstring */
	*pos = p;

	/* check for match with status */
	if (x != parser->state.reply->status / 100) {
		/* ignore code */
		return;
	}

	/* check for code consistency */
	if (parser->state.line > 0 &&
		(prevx != x || prevy != y || prevz != z)) {
		/* ignore code */
		return;
	}

	parser->state.reply->enhanced_code.x = x;
	parser->state.reply->enhanced_code.y = y;
	parser->state.reply->enhanced_code.z = z;
}

static void smtp_reply_parser_finish_line(struct smtp_reply_parser *parser)
{
	const char *text = str_c(parser->strbuf);

	if (parser->enhanced_codes && str_len(parser->strbuf) > 5) {
		smtp_reply_parse_enhanced_code(parser, &text);
	}

	parser->state.line++;
	parser->state.reply_size += str_len(parser->strbuf);
	text = p_strdup(parser->reply_pool, text);
	array_append(&parser->state.reply_lines, &text, 1);
	str_truncate(parser->strbuf, 0);
}

static int smtp_reply_parse_more(struct smtp_reply_parser *parser)
{
	unsigned int status;
	int ret;

	/*
	   Reply-line     = *( Reply-code "-" [ textstring ] CRLF )
	                     Reply-code [ SP textstring ] CRLF
	   Reply-code     = %x32-35 %x30-35 %x30-39

	   ehlo-ok-rsp    = ( "250" SP Domain [ SP ehlo-greet ] CRLF )
	                     / ( "250-" Domain [ SP ehlo-greet ] CRLF
	                      *( "250-" ehlo-line CRLF )
	                     "250" SP ehlo-line CRLF )
	 */

	for (;;) {
		switch (parser->state.state) {
		case SMTP_REPLY_PARSE_STATE_INIT:
			smtp_reply_parser_restart(parser);
			parser->state.state = SMTP_REPLY_PARSE_STATE_CODE;
			/* fall through */
		/* Reply-code */
		case SMTP_REPLY_PARSE_STATE_CODE:
			if ((ret=smtp_reply_parse_code(parser, &status)) <= 0) {
				if (ret < 0) {
					smtp_reply_parser_error(parser,
						"Invalid status code in reply");
				}
				return ret;
			}
			if (parser->state.line == 0) {
				parser->state.reply->status = status;
			} else if (status != parser->state.reply->status) {
				smtp_reply_parser_error(parser,
					"Inconsistent status codes in reply");
				return -1;
			}
			parser->state.state = SMTP_REPLY_PARSE_STATE_SEP;
			if (parser->cur == parser->end)
				return 0;
			/* fall through */
		/* "-" / SP / CRLF */
		case SMTP_REPLY_PARSE_STATE_SEP:
			switch (*parser->cur) {
			/* "-" [ textstring ] CRLF */
			case '-': 
				parser->cur++;
				parser->state.last_line = FALSE;
				parser->state.state =
					SMTP_REPLY_PARSE_STATE_TEXT;
				break;
			/* SP [ textstring ] CRLF ; allow missing text */
			case ' ': 
				parser->cur++;
				parser->state.state =
					SMTP_REPLY_PARSE_STATE_TEXT;
				parser->state.last_line = TRUE;
				break;
			/* CRLF */
			case '\r': 
			case '\n':
				parser->state.last_line = TRUE;
				parser->state.state = SMTP_REPLY_PARSE_STATE_CR;
				break;
			default:
				smtp_reply_parser_error(parser,
					"Encountered unexpected %s after reply status code",
					_chr_sanitize(*parser->cur));
				return -1;
			}
			if (parser->state.state != SMTP_REPLY_PARSE_STATE_TEXT)
				break;
			/* fall through */
		/* textstring / (Domain [ SP ehlo-greet ]) */
		case SMTP_REPLY_PARSE_STATE_TEXT:
			if (parser->ehlo &&
				parser->state.reply->status == 250 &&
				parser->state.line == 0) {
				/* handle first line of EHLO success response
				   differently because it can contain control
				   characters (WHY??!) */
				if ((ret=smtp_reply_parse_ehlo_domain(parser)) <= 0)
					return ret;
				parser->state.state =
					SMTP_REPLY_PARSE_STATE_EHLO_SPACE;
				if (parser->cur == parser->end)
					return 0;
				break;
			}
			if ((ret=smtp_reply_parse_textstring(parser)) <= 0)
				return ret;
			parser->state.state = SMTP_REPLY_PARSE_STATE_CR;
			if (parser->cur == parser->end)
				return 0;
			/* fall through */
		/* CR */
		case SMTP_REPLY_PARSE_STATE_CR:
			if (*parser->cur == '\r') {
				parser->cur++;
				parser->state.state =
					SMTP_REPLY_PARSE_STATE_CRLF;
			} else {
				parser->state.state =
					SMTP_REPLY_PARSE_STATE_LF;
			}
			if (parser->cur == parser->end)
				return 0;
			/* fall through */
		/* CRLF / LF */
		case SMTP_REPLY_PARSE_STATE_CRLF:
		case SMTP_REPLY_PARSE_STATE_LF:
			if (*parser->cur != '\n') {
				if (parser->state.state ==
					SMTP_REPLY_PARSE_STATE_CRLF) {
					smtp_reply_parser_error(parser,
						"Encountered stray CR in reply text");
				} else {
					smtp_reply_parser_error(parser,
						"Encountered stray %s in reply text",
						_chr_sanitize(*parser->cur));
				}
				return -1;
			}
			parser->cur++;
			smtp_reply_parser_finish_line(parser);
			if (parser->state.last_line) {
				parser->state.state =
					SMTP_REPLY_PARSE_STATE_INIT;
				return 1;
			}
			parser->state.state = SMTP_REPLY_PARSE_STATE_CODE;
			break;
		/* SP ehlo-greet */
		case SMTP_REPLY_PARSE_STATE_EHLO_SPACE:
			if (*parser->cur != ' ') {
				parser->state.state = SMTP_REPLY_PARSE_STATE_CR;
				break;
			}
			parser->cur++;
			str_append_c(parser->strbuf, ' ');
			parser->state.state = SMTP_REPLY_PARSE_STATE_EHLO_GREET;
			if (parser->cur == parser->end)
				return 0;
			/* fall through */
		/* ehlo-greet */
		case SMTP_REPLY_PARSE_STATE_EHLO_GREET:
			if ((ret=smtp_reply_parse_ehlo_greet(parser)) <= 0)
				return ret;
			parser->state.state = SMTP_REPLY_PARSE_STATE_CR;
			if (parser->cur == parser->end)
				return 0;
			break;
		default:
			i_unreached();
		}
	}

	i_unreached();
	return -1;
}

static int smtp_reply_parse(struct smtp_reply_parser *parser)
{
	size_t size;
	int ret;

	while ((ret = i_stream_read_more(parser->input,
					 &parser->begin, &size)) > 0) {
		parser->cur = parser->begin;
		parser->end = parser->cur + size;

		if ((ret = smtp_reply_parse_more(parser)) < 0)
			return -1;

		i_stream_skip(parser->input, parser->cur - parser->begin);
		if (ret > 0)
			return 1;
	}

	i_assert(ret != -2);
	if (ret < 0) {
		i_assert(parser->input->eof);
		if (parser->input->stream_errno == 0) {
			if (parser->state.state == SMTP_REPLY_PARSE_STATE_INIT)
				return 0;
			smtp_reply_parser_error(parser,
				"Premature end of input");
		} else {
			smtp_reply_parser_error(parser,
				"Stream error: %s",
				i_stream_get_error(parser->input));
		}
	}
	return ret;
}

int smtp_reply_parse_next(struct smtp_reply_parser *parser,
			  bool enhanced_codes, struct smtp_reply **reply_r,
			  const char **error_r)
{
	int ret;

	i_assert(parser->state.state == SMTP_REPLY_PARSE_STATE_INIT ||
		(parser->enhanced_codes == enhanced_codes && !parser->ehlo));

	parser->enhanced_codes = enhanced_codes;
	parser->ehlo = FALSE;

	i_free_and_null(parser->error);

	/*
	   Reply-line     = *( Reply-code "-" [ textstring ] CRLF )
	                    Reply-code [ SP textstring ] CRLF
	   Reply-code     = %x32-35 %x30-35 %x30-39
	   textstring     = 1*(%d09 / %d32-126) ; HT, SP, Printable US-ASCII

	   Greeting is not handled specially here.
	 */
	if ((ret=smtp_reply_parse(parser)) <= 0) {
		*error_r = parser->error;
		return ret;
	}

	i_assert(array_count(&parser->state.reply_lines) > 0);
	array_append_zero(&parser->state.reply_lines);

	parser->state.state = SMTP_REPLY_PARSE_STATE_INIT;
	parser->state.reply->text_lines =
		array_idx(&parser->state.reply_lines, 0);
	*reply_r = parser->state.reply;
	return 1;
}

int smtp_reply_parse_ehlo(struct smtp_reply_parser *parser,
			  struct smtp_reply **reply_r, const char **error_r)
{
	int ret;

	i_assert(parser->state.state == SMTP_REPLY_PARSE_STATE_INIT ||
		(!parser->enhanced_codes && parser->ehlo));

	parser->enhanced_codes = FALSE;
	parser->ehlo = TRUE;

	i_free_and_null(parser->error);

	/*
	   ehlo-ok-rsp    = ( "250" SP Domain [ SP ehlo-greet ] CRLF )
	                    / ( "250-" Domain [ SP ehlo-greet ] CRLF
	                      *( "250-" ehlo-line CRLF )
	                    "250" SP ehlo-line CRLF )
	   ehlo-greet     = 1*(%d0-9 / %d11-12 / %d14-127)
	                    ; string of any characters other than CR or LF
	   ehlo-line      = ehlo-keyword *( SP ehlo-param )
	   ehlo-keyword   = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
	                    ; additional syntax of ehlo-params depends on
	                    ; ehlo-keyword
	   ehlo-param     = 1*(%d33-126)
	                    ; any CHAR excluding <SP> and all
	                    ; control characters (US-ASCII 0-31 and 127
	                    ; inclusive)
	 */
	if ((ret=smtp_reply_parse(parser)) <= 0) {
		*error_r = parser->error;
		return ret;
	}

	i_assert(array_count(&parser->state.reply_lines) > 0);
	array_append_zero(&parser->state.reply_lines);

	parser->state.state = SMTP_REPLY_PARSE_STATE_INIT;
	parser->state.reply->text_lines =
		array_idx(&parser->state.reply_lines, 0);
	*reply_r = parser->state.reply;
	return 1;
}
