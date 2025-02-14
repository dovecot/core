/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "hex-dec.h"
#include "istream.h"
#include "ostream-private.h"

#include "json-syntax.h"
#include "json-generator.h"

#include <math.h>

#define JSON_STRING_OSTREAM_DEFAULT_BUFFER_SIZE 256

struct json_string_ostream;

enum json_generator_state {
	JSON_GENERATOR_STATE_VALUE = 0,
	JSON_GENERATOR_STATE_VALUE_END,
	JSON_GENERATOR_STATE_VALUE_NEXT,
	JSON_GENERATOR_STATE_OBJECT_MEMBER,
	JSON_GENERATOR_STATE_OBJECT_VALUE,
	JSON_GENERATOR_STATE_STRING,
	JSON_GENERATOR_STATE_TEXT,
	JSON_GENERATOR_STATE_SPACE,
	JSON_GENERATOR_STATE_END,
};

enum json_format_state {
	JSON_FORMAT_STATE_NONE = 0,
	JSON_FORMAT_STATE_INDENT,
	JSON_FORMAT_STATE_SPACE,
	JSON_FORMAT_STATE_CR,
	JSON_FORMAT_STATE_LF,
	JSON_FORMAT_STATE_DONE,
};

struct json_generator_level {
	bool object:1;
};

struct json_generator {
	struct ostream *output;
	enum json_generator_flags flags;

	/* Buffer for elements that the generator has assumed responsibility for
	   by returning > 0, but could not be written to the output stream right
	   away. */
	string_t *buf;
	/* Write position */
	size_t buf_pos;

	/* API state: based on called API functions */
	enum json_generator_state state;
	/* Write state: based on what is written to the output so far */
	enum json_generator_state write_state;

	/* Stack of syntax levels */
	ARRAY(struct json_generator_level) level_stack;
	/* API state: stack position of opened syntax levels */
	unsigned int level_stack_pos;
	/* Write state: stack position of written syntax levels */
	unsigned int level_stack_written;

	/* Formatting state */
	struct json_format format;
	char *format_indent;
	enum json_format_state format_state;
	unsigned int indent_pos, indent_count;

	/* Currently opened string output stream */
	struct json_string_ostream *str_stream;
	/* Currently pending string input stream */
	struct istream *value_input;

	/* We are in an object */
	bool object_level_written:1;  /* write state */
	bool object_level:1;          /* API state */
	/* We closed an empty string */
	bool string_empty:1;          /* API state */
	/* We opened an input stream string */
	bool string_stream:1;         /* API state */
	bool string_stream_written:1; /* write state */
	/* We opened an input stream JSON-text */
	bool text_stream:1;           /* API state */
	/* A json_string_ostream is running the generator */
	bool streaming:1;
	/* Finish writing formatting whitespace element */
	bool format_finish:1;
};

static int json_generator_flush_string_input(struct json_generator *generator);
static int json_generator_flush_text_input(struct json_generator *generator);

static struct json_generator *
json_generator_new(enum json_generator_flags flags)
{
	struct json_generator *generator;

	generator = i_new(struct json_generator, 1);
	generator->flags = flags;
	i_array_init(&generator->level_stack, 16);

	return generator;
}

struct json_generator *
json_generator_init(struct ostream *output, enum json_generator_flags flags)
{
	struct json_generator *generator;

	generator = json_generator_new(flags);
	generator->buf = str_new(default_pool, 128);
	generator->output = output;
	o_stream_ref(output);

	return generator;
}

struct json_generator *
json_generator_init_str(string_t *buf, enum json_generator_flags flags)
{
	struct json_generator *generator;

	generator = json_generator_new(flags);
	generator->buf = buf;

	return generator;
}

void json_generator_deinit(struct json_generator **_generator)
{
	struct json_generator *generator = *_generator;

	if (generator == NULL)
		return;
	*_generator = NULL;

	i_assert(generator->str_stream == NULL);

	i_stream_unref(&generator->value_input);
	if (generator->output != NULL) {
		o_stream_unref(&generator->output);
		str_free(&generator->buf);
	}
	array_free(&generator->level_stack);
	i_free(generator->format_indent);
	i_free(generator);
}

void json_generator_set_format(struct json_generator *generator,
				const struct json_format *format)
{
	i_assert(generator->state == JSON_GENERATOR_STATE_VALUE);
	i_assert(generator->write_state == JSON_GENERATOR_STATE_VALUE);
	generator->format = *format;

	i_free(generator->format_indent);
	if (format->indent_chars > 0) {
		generator->format_indent = i_malloc(format->indent_chars);
		memset(generator->format_indent,
		       (format->indent_tab ? '\t' : ' '),
		       format->indent_chars);
	}
}

static inline size_t
json_generator_bytes_available(struct json_generator *generator)
{
	if (generator->output == NULL || generator->output->blocking)
		return SIZE_MAX;
	return o_stream_get_buffer_avail_size(generator->output);
}

static int
json_generator_make_space(struct json_generator *generator, size_t space,
			  size_t *avail_r)
{
	*avail_r = json_generator_bytes_available(generator);
	if (*avail_r >= space)
		return 1;
	if (o_stream_flush(generator->output) < 0)
		return -1;
	*avail_r = json_generator_bytes_available(generator);
	return (*avail_r >= space ? 1 : 0);
}

static int
json_generator_write(struct json_generator *generator,
		     const void *data, size_t size)
{
	ssize_t ret;

	if (generator->output == NULL) {
		str_append_data(generator->buf, data, size);
		return 1;
	}
	ret = o_stream_send(generator->output, data, size);
	if (ret < 0)
		return -1;
	i_assert((size_t)ret == size);
	return 1;
}

static inline int
json_generator_write_all(struct json_generator *generator,
			 const void *data, size_t size)
{
	size_t avail;
	int ret;

	ret = json_generator_make_space(generator, size, &avail);
	if (ret <= 0)
		return ret;

	return json_generator_write(generator, data, size);
}

static int
json_generator_write_buffered(struct json_generator *generator,
			      const void *data, size_t size, bool continued)
{
	size_t avail, write;

	if (!continued || generator->output == NULL ||
	    str_len(generator->buf) == 0) {
		/* Try to write to output first */
		if (json_generator_make_space(generator, size, &avail) < 0)
			return -1;
		write = (avail < size ? avail : size);
		if (write > 0) {
			i_assert(generator->output == NULL ||
				 str_len(generator->buf) == 0);
			if (json_generator_write(generator, data, write) < 0)
				return -1;
			data = PTR_OFFSET(data, write);
			size -= write;
		}
	}

	if (size > 0) {
		i_assert(generator->output != NULL);
		/* Prevent buffer from growing needlessly */
		if (str_len(generator->buf) + size > 1024 &&
		    generator->buf_pos > 0)
			str_delete(generator->buf, 0, generator->buf_pos);
		/* Append data to buffer */
		str_append_data(generator->buf, data, size);
	}
	return 1;
}

static int json_generator_flush_buffer(struct json_generator *generator)
{
	const unsigned char *data;
	size_t size, avail;

	if (generator->output == NULL)
		return 1;
	if (str_len(generator->buf) == 0)
		return 1;

	data = str_data(generator->buf);
	size = str_len(generator->buf);
	i_assert(generator->buf_pos < size);

	data += generator->buf_pos;
	size -= generator->buf_pos;

	if (json_generator_make_space(generator, size, &avail) < 0)
		return -1;
	if (avail == 0)
		return 0;
	if (avail < size) {
		if (json_generator_write(generator, data, avail) < 0)
			return -1;
		generator->buf_pos += avail;
		return 0;
	}
	if (json_generator_write(generator, data, size) < 0)
		return -1;
	generator->buf_pos = 0;
	str_truncate(generator->buf, 0);
	return 1;
}

static int json_generator_flush_format(struct json_generator *generator)
{
	int ret;

	for (;;) switch (generator->format_state) {
	case JSON_FORMAT_STATE_NONE:
		return 1;
	case JSON_FORMAT_STATE_CR:
		ret = json_generator_write_all(generator, "\r", 1);
		if (ret <= 0)
			return ret;
		generator->format_state = JSON_FORMAT_STATE_LF;
		/* fall through */
	case JSON_FORMAT_STATE_LF:
		ret = json_generator_write_all(generator, "\n", 1);
		if (ret <= 0)
			return ret;
		if (generator->format.indent_chars == 0) {
			generator->format_state = JSON_FORMAT_STATE_DONE;
			break;
		}
		generator->format_state = JSON_FORMAT_STATE_INDENT;
		/* fall through */
	case JSON_FORMAT_STATE_INDENT:
		i_assert(generator->format.indent_chars != 0);
		while (generator->indent_pos < generator->indent_count) {
			ret = json_generator_write_buffered(
				generator, generator->format_indent,
				generator->format.indent_chars, FALSE);
			if (ret <= 0)
				return -1;
			generator->indent_pos++;
		}
		generator->format_state = JSON_FORMAT_STATE_DONE;
		break;
	case JSON_FORMAT_STATE_SPACE:
		ret = json_generator_write_all(generator, " ", 1);
		if (ret <= 0)
			return ret;
		generator->format_state = JSON_FORMAT_STATE_DONE;
		break;
	case JSON_FORMAT_STATE_DONE:
		if (!generator->format_finish)
			return 1;
		generator->format_state = JSON_FORMAT_STATE_NONE;
		break;
	}
	i_unreached();
}

static int
json_generator_write_newline(struct json_generator *generator,
			      unsigned int indent_count, bool finish)
{
	if (generator->format_state == JSON_FORMAT_STATE_DONE)
		return 1;
	i_assert(generator->format_state == JSON_FORMAT_STATE_NONE);
	if (!generator->format.new_line)
		return 1;
	if (generator->format.crlf)
		generator->format_state = JSON_FORMAT_STATE_CR;
	else
		generator->format_state = JSON_FORMAT_STATE_LF;
	generator->indent_pos = 0;
	generator->indent_count = indent_count;
	generator->format_finish = finish;
	return json_generator_flush_format(generator);
}

static int
json_generator_write_space(struct json_generator *generator,
			    bool finish)
{
	if (generator->format_state == JSON_FORMAT_STATE_DONE)
		return 1;
	i_assert(generator->format_state == JSON_FORMAT_STATE_NONE);
	if (!generator->format.whitespace)
		return 1;
	generator->format_state = JSON_FORMAT_STATE_SPACE;
	generator->format_finish = finish;
	return json_generator_flush_format(generator);
}

static void json_generator_finish_format(struct json_generator *generator)
{
	generator->format_state = JSON_FORMAT_STATE_NONE;
}

int json_generator_flush(struct json_generator *generator)
{
	bool hide_root = HAS_ALL_BITS(generator->flags,
				      JSON_GENERATOR_FLAG_HIDE_ROOT);
	int ret;

	/* Flush buffer */
	ret = json_generator_flush_buffer(generator);
	if (ret <= 0)
		return ret;
	/* Flush formatting whitespace */
	ret = json_generator_flush_format(generator);
	if (ret <= 0)
		return ret;
	/* Flush closing string */
	if (generator->write_state == JSON_GENERATOR_STATE_STRING &&
	    generator->state != JSON_GENERATOR_STATE_STRING) {
		ret = json_generator_write_all(generator, "\"", 1);
		if (ret <= 0)
			return ret;
		generator->write_state = JSON_GENERATOR_STATE_VALUE_END;
	}
	/* Flush object member */
	if (generator->write_state == JSON_GENERATOR_STATE_OBJECT_VALUE) {
		ret = json_generator_write_all(generator, ":", 1);
		if (ret <= 0)
			return ret;
		generator->write_state = JSON_GENERATOR_STATE_VALUE;
		ret = json_generator_write_space(generator, TRUE);
		if (ret <= 0)
			return ret;
	}
	/* Flush opening objects/arrays */
	for (;;) {
		struct json_generator_level *level;

		i_assert(generator->level_stack_written <=
			 generator->level_stack_pos);
		if (generator->level_stack_written == generator->level_stack_pos)
			break;

		i_assert(generator->write_state != JSON_GENERATOR_STATE_STRING &&
			 generator->write_state != JSON_GENERATOR_STATE_TEXT &&
			 generator->write_state != JSON_GENERATOR_STATE_SPACE);
		if (generator->write_state == JSON_GENERATOR_STATE_VALUE_END)
			generator->write_state = JSON_GENERATOR_STATE_VALUE_NEXT;
		if (generator->write_state == JSON_GENERATOR_STATE_VALUE_NEXT) {
			ret = json_generator_write_all(generator, ",", 1);
			if (ret <= 0)
				return ret;
			generator->write_state = JSON_GENERATOR_STATE_VALUE;
			ret = json_generator_write_newline(
				generator, generator->level_stack_written,
				TRUE);
			if (ret <= 0)
				return ret;
		}

		level = array_idx_get_space(&generator->level_stack,
					    generator->level_stack_written);
		if (level->object) {
			if (!hide_root || generator->level_stack_written > 0) {
				ret = json_generator_write_all(generator, "{", 1);
				if (ret <= 0)
					return ret;
			}
			generator->level_stack_written++;
			generator->write_state = JSON_GENERATOR_STATE_OBJECT_MEMBER;
			generator->object_level_written = TRUE;
		} else {
			if (!hide_root || generator->level_stack_written > 0) {
				ret = json_generator_write_all(generator, "[", 1);
				if (ret <= 0)
					return ret;
			}
			generator->level_stack_written++;
			generator->object_level_written = FALSE;
			generator->write_state = JSON_GENERATOR_STATE_VALUE;
		}
		ret = json_generator_write_newline(
			generator, generator->level_stack_written, TRUE);
		if (ret <= 0)
			return ret;
	}
	/* Flush separator */
	switch (generator->write_state) {
	/* Flush comma */
	case JSON_GENERATOR_STATE_VALUE_END:
		if (generator->level_stack_pos == 0) {
			generator->write_state = JSON_GENERATOR_STATE_END;
			ret = json_generator_write_newline(
				generator, generator->level_stack_written,
				TRUE);
			if (ret <= 0)
				return ret;
			break;
		}
		if (generator->state != JSON_GENERATOR_STATE_STRING &&
		    generator->state != JSON_GENERATOR_STATE_TEXT &&
		    generator->state != JSON_GENERATOR_STATE_SPACE)
			break;
		generator->write_state = JSON_GENERATOR_STATE_VALUE_NEXT;
		/* Fall through */
	case JSON_GENERATOR_STATE_VALUE_NEXT:
		ret = json_generator_write_all(generator, ",", 1);
		if (ret <= 0)
			return ret;
		if (generator->object_level_written) {
			generator->write_state = JSON_GENERATOR_STATE_OBJECT_MEMBER;
		} else {
			generator->write_state = JSON_GENERATOR_STATE_VALUE;
		}
		ret = json_generator_write_newline(
			generator, generator->level_stack_written, TRUE);
		if (ret <= 0)
			return ret;
		break;
	/* Flush colon */
	case JSON_GENERATOR_STATE_OBJECT_VALUE:
		ret = json_generator_write_all(generator, ":", 1);
		if (ret <= 0)
			return ret;
		generator->write_state = JSON_GENERATOR_STATE_VALUE;
		ret = json_generator_write_space(generator, TRUE);
		if (ret <= 0)
			return ret;
		break;
	default:
		break;
	}
	/* Flush opening empty string */
	if (generator->string_empty &&
	    generator->write_state != JSON_GENERATOR_STATE_STRING) {
		i_assert(generator->write_state == JSON_GENERATOR_STATE_VALUE ||
			 generator->write_state == JSON_GENERATOR_STATE_OBJECT_VALUE);
		ret = json_generator_write_all(generator, "\"", 1);
		if (ret <= 0)
			return ret;
		generator->string_empty = FALSE;
		ret = json_generator_write_all(generator, "\"", 1);
		if (ret < 0)
			return -1;
		if (ret == 0) {
			generator->write_state = JSON_GENERATOR_STATE_STRING;
			return 0;
		}
		generator->write_state = JSON_GENERATOR_STATE_VALUE_END;
	/* Flush opening string */
	} else if (generator->state == JSON_GENERATOR_STATE_STRING &&
		   generator->write_state != JSON_GENERATOR_STATE_STRING) {
		i_assert(generator->write_state == JSON_GENERATOR_STATE_VALUE ||
			 generator->write_state == JSON_GENERATOR_STATE_OBJECT_VALUE);
		ret = json_generator_write_all(generator, "\"", 1);
		if (ret <= 0)
			return ret;
		generator->write_state = JSON_GENERATOR_STATE_STRING;
	}
	/* Flush opening text */
	if (generator->state == JSON_GENERATOR_STATE_TEXT &&
	    generator->write_state != JSON_GENERATOR_STATE_TEXT)
		generator->write_state = JSON_GENERATOR_STATE_TEXT;
	/* Flush string stream */
	if (generator->string_stream) {
		i_assert(generator->value_input != NULL);
		if (!generator->string_stream_written) {
			ret = json_generator_write_all(generator, "\"", 1);
			if (ret <= 0)
				return ret;
			generator->string_stream_written = TRUE;
		}
		/* Flush the stream */
		ret = json_generator_flush_string_input(generator);
		if (ret <= 0)
			return ret;
		generator->string_stream = FALSE;
		generator->string_stream_written = FALSE;
		/* Close the string */
		ret = json_generator_write_all(generator, "\"", 1);
		if (ret < 0)
			return -1;
		if (ret == 0) {
			generator->write_state = JSON_GENERATOR_STATE_STRING;
			return 0;
		}
		generator->write_state = JSON_GENERATOR_STATE_VALUE_END;
	}
	/* flush opening <space> */
	if (generator->state == JSON_GENERATOR_STATE_SPACE &&
	    generator->write_state != JSON_GENERATOR_STATE_SPACE)
		generator->write_state = JSON_GENERATOR_STATE_SPACE;
	/* flush string stream */
	if (generator->text_stream) {
		i_assert(generator->value_input != NULL);
		/* flush the stream */
		ret = json_generator_flush_text_input(generator);
		if (ret <= 0)
			return ret;
		generator->text_stream = FALSE;
		generator->write_state = JSON_GENERATOR_STATE_VALUE_END;
	}
	return 1;
}

/*
 * value begin/end
 */

static inline void
json_generator_value_begin(struct json_generator *generator)
{
	i_assert(generator->state == JSON_GENERATOR_STATE_VALUE);
	i_assert(generator->streaming || generator->str_stream == NULL);
}

static inline int
json_generator_value_begin_flushed(struct json_generator *generator)
{
	int ret;

	json_generator_value_begin(generator);
	if (generator->write_state == JSON_GENERATOR_STATE_VALUE_END)
		generator->write_state = JSON_GENERATOR_STATE_VALUE_NEXT;
	ret = json_generator_flush(generator);
	if (ret <= 0)
		return ret;
	i_assert(generator->write_state == generator->state);
	return 1;
}

static inline void
json_generator_value_end(struct json_generator *generator)
{
	if (generator->level_stack_pos == 0)
		generator->state = JSON_GENERATOR_STATE_END;
	else if (generator->object_level)
		generator->state = JSON_GENERATOR_STATE_OBJECT_MEMBER;
	else
		generator->state = JSON_GENERATOR_STATE_VALUE;
	generator->write_state = JSON_GENERATOR_STATE_VALUE_END;
}

/*
 * number
 */

int json_generate_number(struct json_generator *generator, intmax_t number)
{
	int ret;

	ret = json_generator_value_begin_flushed(generator);
	if (ret <= 0)
		return ret;

	str_printfa(generator->buf, "%"PRIdMAX, number);

	json_generator_value_end(generator);
	return (json_generator_flush(generator) < 0 ? -1 : 1);
}

int json_generate_number_raw(struct json_generator *generator,
			      const char *number)
{
	int ret;

	ret = json_generator_value_begin_flushed(generator);
	if (ret <= 0)
		return ret;
	if (json_generator_write_buffered(generator, number,
					  strlen(number), FALSE) < 0)
		return -1;
	json_generator_value_end(generator);
	return 1;
}

/*
 * string
 */

void json_generate_string_open(struct json_generator *generator)
{
	json_generator_value_begin(generator);
	generator->state = JSON_GENERATOR_STATE_STRING;
}

static ssize_t
json_generate_string_write_data(struct json_generator *generator,
				const void *data, size_t size,
				bool buffered, bool last)
{
	const unsigned char *p, *pbegin, *pend;
	size_t avail;
	int ret;

	p = pbegin = data;
	pend = p + size;
	while (p < pend) {
		const unsigned char *poffset;
		unsigned char esc_hex[6];
		const char *esc = NULL;
		unsigned int esc_len = 2;
		int octets = 0;
		unichar_t ch;

		if (buffered)
			avail = SIZE_MAX;
		else {
			ret = json_generator_make_space(generator, pend - p,
							&avail);
			if (ret < 0)
				return -1;
		}
		if (avail == 0)
			break;

		poffset = p;
		while (avail > 0 && p < pend && esc == NULL) {
			octets = uni_utf8_get_char_n(p, (pend - p), &ch);
			if (octets < 0 || (octets == 0 && last) ||
			    (octets > 0  && !uni_is_valid_ucs4(ch))) {
				/* Replace invalid UTF-8/Unicode with the
				   replacement character. */
				esc = UNICODE_REPLACEMENT_CHAR_UTF8;
				esc_len = UTF8_REPLACEMENT_CHAR_LEN;
				octets = (octets <= 0 ? 1 : octets);
				break;
			}
			if (octets == 0 || (size_t)octets > avail)
				break;
			switch (ch) {
			/* %x22 /          ; "    quotation mark  U+0022 */
			case '"':
				esc = "\\\"";
				break;
			/* %x5C /          ; \    reverse solidus U+005C */
			case '\\':
				esc = "\\\\";
				break;
			/* %x62 /          ; b    backspace       U+0008 */
			case '\b':
				esc = "\\b";
				break;
			/* %x66 /          ; f    form feed       U+000C */
			case '\f':
				esc = "\\f";
				break;
			/* %x6E /          ; n    line feed       U+000A */
			case '\n':
				esc = "\\n";
				break;
			/* %x72 /          ; r    carriage return U+000D */
			case '\r':
				esc = "\\r";
				break;
			/* %x74 /          ; t    tab             U+0009 */
			case '\t':
				esc = "\\t";
				break;
			default:
				if (ch < 0x20 || ch == 0x2028 || ch == 0x2029) {
					esc_hex[0] = '\\';
					esc_hex[1] = 'u';
					dec2hex(&esc_hex[2], (uintmax_t)ch, 4);
					esc = (const char *)esc_hex;
					esc_len = sizeof(esc_hex);
				} else {
					p += octets;
					avail -= octets;
				}
			}
		}

		if ((p - poffset) > 0) {
			if (buffered) {
				if (json_generator_write_buffered(
					generator, poffset, p -poffset,
					TRUE) < 0)
					return -1;
			} else {
				if (json_generator_write(
					generator, poffset, p - poffset) < 0)
					return -1;
			}
		}
		if (esc != NULL) {
			if (esc_len > avail) {
				break;
			} else {
				if (buffered) {
					if (json_generator_write_buffered(
						generator, esc, esc_len,
						TRUE) < 0)
						return -1;
				} else {
					if (json_generator_write(
						generator, esc, esc_len) < 0)
						return -1;
				}
				p += octets;
			}
		}
		if (octets == 0 || (size_t)octets > avail)
			break;
	}

	return (ssize_t)(p - pbegin);
}

ssize_t json_generate_string_more(struct json_generator *generator,
				  const void *data, size_t size, bool last)
{
	int ret;

	i_assert(generator->value_input == NULL);
	i_assert(generator->state == JSON_GENERATOR_STATE_STRING);
	ret = json_generator_flush(generator);
	if (ret <= 0)
		return (ssize_t)ret;
	i_assert(generator->write_state == JSON_GENERATOR_STATE_STRING);

	return json_generate_string_write_data(generator, data, size,
					       FALSE, last);
}

void json_generate_string_close(struct json_generator *generator)
{
	i_assert(generator->streaming || generator->str_stream == NULL);
	i_assert(generator->value_input == NULL);
	i_assert(generator->state == JSON_GENERATOR_STATE_STRING);
	if (generator->write_state != JSON_GENERATOR_STATE_STRING) {
		/* Neither this nor the string_open() function flushes
		   first before changing state. So, we need to remember
		   closing the empty string, because otherwise nothing will
		   be emitted. */
		generator->string_empty = TRUE;
	}
	if (generator->level_stack_pos == 0)
		generator->state = JSON_GENERATOR_STATE_END;
	else if (generator->object_level)
		generator->state = JSON_GENERATOR_STATE_OBJECT_MEMBER;
	else
		generator->state = JSON_GENERATOR_STATE_VALUE;
}

int json_generate_string_write_close(struct json_generator *generator)
{
	i_assert(generator->streaming || generator->str_stream == NULL);
	if (generator->state == JSON_GENERATOR_STATE_STRING)
		json_generate_string_close(generator);
	return json_generator_flush(generator);
}

int json_generate_string_data(struct json_generator *generator,
			      const void *data, size_t size)
{
	int ret;

	ret = json_generator_value_begin_flushed(generator);
	if (ret <= 0)
		return ret;

	if (json_generator_write_buffered(generator, "\"", 1, FALSE) < 0)
		return -1;
	if (json_generate_string_write_data(generator, data, size,
					    TRUE, TRUE) < 0)
		return -1;
	if (json_generator_write_buffered(generator, "\"", 1, TRUE) < 0)
		return -1;

	json_generator_value_end(generator);
	return 1;
}

int json_generate_string(struct json_generator *generator, const char *str)
{
	return json_generate_string_data(generator,
					 (const unsigned char *)str,
					 strlen(str));
}

static int
json_generator_flush_string_input(struct json_generator *generator)
{
	const unsigned char *data;
	size_t size;
	ssize_t sret;
	int ret;

	while ((ret = i_stream_read_more(generator->value_input,
					 &data, &size)) > 0) {
		sret = json_generate_string_write_data(
			generator, data, size, FALSE,
			generator->value_input->eof);
		if (sret < 0)
			return -1;
		if (sret == 0)
			return 0;
		i_stream_skip(generator->value_input, (size_t)sret);
	}
	if (ret < 0) {
		if (generator->value_input->stream_errno != 0)
			return -1;

		i_assert(!i_stream_have_bytes_left(generator->value_input));
		i_stream_unref(&generator->value_input);
		return 1;
	}
	return 0;
}

int json_generate_string_stream(struct json_generator *generator,
				struct istream *input)
{
	i_assert(generator->value_input == NULL);
	json_generator_value_begin(generator);
	generator->value_input = input;
	i_stream_ref(input);
	generator->string_stream = TRUE;
	if (generator->write_state == JSON_GENERATOR_STATE_VALUE_END)
		generator->write_state = JSON_GENERATOR_STATE_VALUE_NEXT;
	if (generator->level_stack_pos == 0)
		generator->state = JSON_GENERATOR_STATE_END;
	else if (generator->object_level)
		generator->state = JSON_GENERATOR_STATE_OBJECT_MEMBER;
	else
		generator->state = JSON_GENERATOR_STATE_VALUE;
	if (json_generator_flush(generator) < 0)
		return -1;
	return 1;
}

/*
 * null, true, false
 */

static int
json_generate_literal(struct json_generator *generator, const char *literal)
{
	size_t lit_size = strlen(literal);
	int ret;

	ret = json_generator_value_begin_flushed(generator);
	if (ret <= 0)
		return ret;

	ret = json_generator_write_all(generator, literal, lit_size);
	if (ret <= 0)
		return ret;

	json_generator_value_end(generator);
	return ret;
}

int json_generate_null(struct json_generator *generator)
{
	return json_generate_literal(generator, "null");
}

int json_generate_false(struct json_generator *generator)
{
	return json_generate_literal(generator, "false");
}

int json_generate_true(struct json_generator *generator)
{
	return json_generate_literal(generator, "true");
}

/*
 * stack level
 */

static void
json_generator_level_open(struct json_generator *generator, bool object)
{
	struct json_generator_level *level;

	level = array_idx_get_space(&generator->level_stack,
				    generator->level_stack_pos++);
	i_zero(level);
	level->object = object;
	generator->object_level = object;
}

static void
json_generator_level_close(struct json_generator *generator, bool object)
{
	struct json_generator_level *level, *under_level;

	i_assert(generator->level_stack_pos > 0);

	i_assert(generator->level_stack_written == generator->level_stack_pos);
	generator->level_stack_written--;

	if (generator->level_stack_pos < 2) {
		generator->object_level_written = FALSE;
		generator->object_level = FALSE;
	} else {
		under_level = array_idx_modifiable(
			&generator->level_stack, generator->level_stack_pos-2);
		generator->object_level_written = under_level->object;
		generator->object_level = under_level->object;
	}
	level = array_idx_modifiable(&generator->level_stack,
				     --generator->level_stack_pos);
	i_assert(level->object == object);
}

/*
 * array
 */

void json_generate_array_open(struct json_generator *generator)
{
	json_generator_value_begin(generator);
	json_generator_level_open(generator, FALSE);
	generator->state = JSON_GENERATOR_STATE_VALUE;
}

int json_generate_array_close(struct json_generator *generator)
{
	bool hide_root = HAS_ALL_BITS(generator->flags,
				      JSON_GENERATOR_FLAG_HIDE_ROOT);
	int ret;

	i_assert(generator->str_stream == NULL);
	i_assert(generator->state == JSON_GENERATOR_STATE_VALUE);
	ret = json_generator_flush(generator);
	if (ret <= 0)
		return ret;
	i_assert(generator->write_state == JSON_GENERATOR_STATE_VALUE ||
		 generator->write_state == JSON_GENERATOR_STATE_VALUE_END);

	i_assert(generator->level_stack_written > 0);
	ret = json_generator_write_newline(
		generator, generator->level_stack_written - 1, FALSE);
	if (ret <= 0)
		return ret;
	if (!hide_root || generator->level_stack_written > 1) {
		ret = json_generator_write_all(generator, "]", 1);
		if (ret <= 0)
			return ret;
	}
	json_generator_level_close(generator, FALSE);
	json_generator_value_end(generator);
	json_generator_finish_format(generator);
	return 1;
}

/*
 * object
 */

void json_generate_object_open(struct json_generator *generator)
{
	json_generator_value_begin(generator);
	json_generator_level_open(generator, TRUE);
	generator->state = JSON_GENERATOR_STATE_OBJECT_MEMBER;
}

int json_generate_object_member(struct json_generator *generator,
				const char *name)
{
	int ret;

	i_assert(generator->str_stream == NULL);
	i_assert(generator->state == JSON_GENERATOR_STATE_OBJECT_MEMBER);
	if (generator->write_state == JSON_GENERATOR_STATE_VALUE_END) {
		generator->write_state = JSON_GENERATOR_STATE_VALUE_NEXT;
	}
	ret = json_generator_flush(generator);
	if (ret <= 0)
		return ret;
	i_assert(generator->write_state == generator->state);
	generator->state = JSON_GENERATOR_STATE_VALUE;

	if (json_generator_write_buffered(generator, "\"", 1, FALSE) < 0)
		return -1;
	if (json_generate_string_write_data(
		generator, name, strlen(name), TRUE, TRUE) < 0)
		return -1;
	if (json_generator_write_buffered(generator, "\"", 1, TRUE) < 0)
		return -1;
	generator->write_state = JSON_GENERATOR_STATE_OBJECT_VALUE;
	return 1;
}

int json_generate_object_close(struct json_generator *generator)
{
	bool hide_root = HAS_ALL_BITS(generator->flags,
				      JSON_GENERATOR_FLAG_HIDE_ROOT);
	int ret;

	i_assert(generator->str_stream == NULL);
	i_assert(generator->state == JSON_GENERATOR_STATE_OBJECT_MEMBER);
	ret = json_generator_flush(generator);
	if (ret <= 0)
		return ret;
	i_assert(generator->write_state == JSON_GENERATOR_STATE_OBJECT_MEMBER ||
		 generator->write_state == JSON_GENERATOR_STATE_VALUE_END);
	i_assert(generator->level_stack_written > 0);
	ret = json_generator_write_newline(
		generator, generator->level_stack_written - 1, FALSE);
	if (ret <= 0)
		return ret;
	if (!hide_root || generator->level_stack_written > 1) {
		ret = json_generator_write_all(generator, "}", 1);
		if (ret <= 0)
			return ret;
	}
	json_generator_level_close(generator, TRUE);
	json_generator_value_end(generator);
	json_generator_finish_format(generator);
	return 1;
}

/*
 * JSON-text
 */

void json_generate_text_open(struct json_generator *generator)
{
	json_generator_value_begin(generator);
	generator->state = JSON_GENERATOR_STATE_TEXT;
}

static ssize_t
json_generate_text_write_data(struct json_generator *generator,
			      const void *data, size_t size, bool buffered)
{
	int ret;

	if (!buffered) {
		size_t avail;

		ret = json_generator_make_space(generator, size, &avail);
		if (ret < 0)
			return -1;
		if (avail == 0)
			return 0;
		if (size > avail)
			size = avail;
	}

	if (buffered) {
		if (json_generator_write_buffered(generator, data, size,
						   FALSE) < 0)
			return -1;
	} else {
		if (json_generator_write(generator, data, size) < 0)
			return -1;
	}
	return (ssize_t)size;
}

ssize_t json_generate_text_more(struct json_generator *generator,
				const void *data, size_t size)
{
	int ret;

	i_assert(generator->state == JSON_GENERATOR_STATE_TEXT);
	ret = json_generator_flush(generator);
	if (ret <= 0)
		return (ssize_t)ret;
	i_assert(generator->write_state == JSON_GENERATOR_STATE_TEXT);

	return json_generate_text_write_data(generator, data, size, FALSE);
}

int json_generate_text_close(struct json_generator *generator)
{
	int ret;

	i_assert(generator->state == JSON_GENERATOR_STATE_TEXT);
	ret = json_generator_flush(generator);
	if (ret <= 0)
		return ret;
	i_assert(generator->write_state == JSON_GENERATOR_STATE_TEXT);

	json_generator_value_end(generator);
	return 1;
}

int json_generate_text_data(struct json_generator *generator,
			    const void *data, size_t size)
{
	int ret;

	ret = json_generator_value_begin_flushed(generator);
	if (ret <= 0)
		return ret;

	if (json_generate_text_write_data(generator, data, size, TRUE) < 0)
		return -1;
	json_generator_value_end(generator);
	return 1;
}

int json_generate_text(struct json_generator *generator, const char *str)
{
	return json_generate_text_data(generator, (const unsigned char *)str,
				       strlen(str));
}

static int
json_generator_flush_text_input(struct json_generator *generator)
{
	const unsigned char *data;
	size_t size;
	ssize_t sret;
	int ret;

	while ((ret = i_stream_read_more(generator->value_input,
					 &data, &size)) > 0) {
		sret = json_generate_text_write_data(generator, data,
						     size, FALSE);
		if (sret < 0)
			return -1;
		if (sret == 0)
			return 0;
		i_stream_skip(generator->value_input, (size_t)sret);
	}
	if (ret < 0) {
		if (generator->value_input->stream_errno != 0)
			return -1;

		i_assert(!i_stream_have_bytes_left(generator->value_input));
		i_stream_unref(&generator->value_input);
		return 1;
	}
	return 0;
}

int json_generate_text_stream(struct json_generator *generator,
			      struct istream *input)
{
	i_assert(generator->value_input == NULL);
	json_generator_value_begin(generator);
	generator->value_input = input;
	i_stream_ref(input);
	generator->text_stream = TRUE;
	if (generator->write_state == JSON_GENERATOR_STATE_VALUE_END)
		generator->write_state = JSON_GENERATOR_STATE_VALUE_NEXT;
	if (generator->level_stack_pos == 0)
		generator->state = JSON_GENERATOR_STATE_END;
	else if (generator->object_level)
		generator->state = JSON_GENERATOR_STATE_OBJECT_MEMBER;
	else
		generator->state = JSON_GENERATOR_STATE_VALUE;
	if (json_generator_flush(generator) < 0)
		return -1;
	return 1;
}

/*
 * <space>
 */

int json_generate_space_open(struct json_generator *generator)
{
	int ret;

	if (generator->state != JSON_GENERATOR_STATE_SPACE) {
		i_assert(generator->state == JSON_GENERATOR_STATE_VALUE ||
			 generator->state == JSON_GENERATOR_STATE_OBJECT_MEMBER);
		generator->state = JSON_GENERATOR_STATE_SPACE;
	}

	ret = json_generator_flush(generator);
	i_assert(ret <= 0 ||
		 generator->write_state == JSON_GENERATOR_STATE_SPACE);
	return ret;
}

void json_generate_space_close(struct json_generator *generator)
{
	i_assert(generator->state == JSON_GENERATOR_STATE_SPACE);
	i_assert(generator->write_state == JSON_GENERATOR_STATE_SPACE);

	json_generator_value_end(generator);
}

/*
 * value
 */

int json_generate_value(struct json_generator *generator,
			enum json_type type, const struct json_value *value)
{
	switch (type) {
	/* string */
	case JSON_TYPE_STRING:
		switch (value->content_type) {
		case JSON_CONTENT_TYPE_STRING:
			return json_generate_string(generator,
						    value->content.str);
		case JSON_CONTENT_TYPE_DATA:
			return json_generate_string_data(
				generator, value->content.data->data,
				value->content.data->size);
		case JSON_CONTENT_TYPE_STREAM:
			return json_generate_string_stream(
				generator, value->content.stream);
		default:
			break;
		}
		break;
	/* number */
	case JSON_TYPE_NUMBER:
		switch (value->content_type) {
		case JSON_CONTENT_TYPE_STRING:
			return json_generate_number_raw(generator,
							value->content.str);
		case JSON_CONTENT_TYPE_INTEGER:
			return json_generate_number(generator,
						    value->content.intnum);
		default:
			break;
		}
		break;
	/* true */
	case JSON_TYPE_TRUE:
		return json_generate_true(generator);
	/* false */
	case JSON_TYPE_FALSE:
		return json_generate_false(generator);
	/* null */
	case JSON_TYPE_NULL:
		return json_generate_null(generator);
	/* JSON-text */
	case JSON_TYPE_TEXT:
		switch (value->content_type) {
		case JSON_CONTENT_TYPE_STRING:
			return json_generate_text(generator,
						  value->content.str);
		case JSON_CONTENT_TYPE_DATA:
			return json_generate_text_data(
				generator, value->content.data->data,
				value->content.data->size);
		case JSON_CONTENT_TYPE_STREAM:
			return json_generate_text_stream(
				generator, value->content.stream);
		default:
			break;
		}
		break;
	/* ?? */
	default:
		break;
	}
	i_unreached();
}

/*
 * string stream
 */

struct json_string_ostream {
	struct ostream_private ostream;

	buffer_t *buf;

	struct json_generator *generator;
};

static void json_string_ostream_finish(struct json_string_ostream *jstream)
{
	struct json_generator *generator = jstream->generator;

	if (generator == NULL)
		return;

	generator->streaming = TRUE;
	json_generate_string_close(generator);
	generator->streaming = FALSE;

	generator->str_stream = NULL;
	jstream->generator = NULL;
}

static void json_string_ostream_cork(struct ostream_private *stream, bool set)
{
	struct json_string_ostream *jstream =
		container_of(stream, struct json_string_ostream, ostream);
	struct json_generator *generator = jstream->generator;

	if (generator == NULL || generator->output == NULL)
		return;
	if (set)
		o_stream_cork(generator->output);
	else
		o_stream_uncork(generator->output);
}

static void
json_string_ostream_close(struct iostream_private *stream,
			   bool close_parent)
{
	struct ostream_private *_stream =
		container_of(stream, struct ostream_private, iostream);
	struct json_string_ostream *jstream =
		container_of(_stream, struct json_string_ostream, ostream);

	if (jstream->ostream.ostream.stream_errno == 0)
		json_string_ostream_finish(jstream);
	if (close_parent)
		o_stream_close(jstream->ostream.parent);
}

static ssize_t
json_string_ostream_send(struct json_string_ostream *jstream,
			  const void *data, size_t size)
{
	struct ostream_private *stream = &jstream->ostream;
	struct json_generator *generator = jstream->generator;
	ssize_t sret;

	generator->streaming = TRUE;

	sret = json_generate_string_more(generator, data, size,
					 stream->finished);
	if (sret < 0) {
		io_stream_set_error(&stream->iostream, "%s",
				    o_stream_get_error(generator->output));
		stream->ostream.stream_errno =
			generator->output->stream_errno;
		generator->streaming = FALSE;
		return -1;
	}

	generator->streaming = FALSE;
	return sret;
}

static int json_string_ostream_send_buffer(struct json_string_ostream *jstream)
{
	ssize_t sret;

	if (jstream->buf == NULL)
		return 1;

	sret = json_string_ostream_send(jstream, jstream->buf->data,
					jstream->buf->used);
	if (sret < 0)
		return -1;

	if ((size_t)sret == jstream->buf->used) {
		buffer_set_used_size(jstream->buf, 0);
		return 1;
	}
	buffer_delete(jstream->buf, 0, (size_t)sret);
	return 0;
}

static ssize_t
json_string_ostream_sendv(struct ostream_private *stream,
			  const struct const_iovec *iov,
			  unsigned int iov_count)
{
	struct json_string_ostream *jstream =
		container_of(stream, struct json_string_ostream, ostream);
	ssize_t sret, sent;
	unsigned int i;
	int ret;

	ret = json_string_ostream_send_buffer(jstream);
	if (ret <= 0)
		return (ssize_t)ret;

	sent = 0;
	for (i = 0; i < iov_count; i++) {
		sret = json_string_ostream_send(jstream, iov[i].iov_base,
						iov[i].iov_len);
		if (sret < 0)
			return -1;
		sent += sret;
		if ((size_t)sret != iov[i].iov_len)
			break;
	}

	if (jstream->buf != NULL) {
		for (; i < iov_count; i++) {
			const void *base;
			size_t avail, append;

			i_assert(jstream->buf->used <=
				 jstream->ostream.max_buffer_size);
			avail = (jstream->ostream.max_buffer_size -
				 jstream->buf->used);
			if (avail == 0)
				break;

			if (sret > 0) {
				i_assert((size_t)sret < iov[i].iov_len);
				append = iov[i].iov_len - (size_t)sret;
				base = PTR_OFFSET(iov[i].iov_base, (size_t)sret);
				sret = 0;
			} else {
				append = iov[i].iov_len;
				base = iov[i].iov_base;
			}

			if (append < avail) {
				buffer_append(jstream->buf, base, append);
				sent += append;
			} else {
				buffer_append(jstream->buf, base, avail);
				sent += avail;
				break;
			}
		}
	}

	return sent;
}

static int json_string_ostream_flush(struct ostream_private *stream)
{
	struct json_string_ostream *jstream =
		container_of(stream, struct json_string_ostream, ostream);

	if (json_string_ostream_send_buffer(jstream) <= 0)
		return 0;

	if (stream->finished)
		json_string_ostream_finish(jstream);
	return 1;
}

static void json_string_ostream_destroy(struct iostream_private *stream)
{
	struct ostream_private *_stream =
		container_of(stream, struct ostream_private, iostream);
	struct json_string_ostream *jstream =
		container_of(_stream, struct json_string_ostream, ostream);

	buffer_free(&jstream->buf);
}

static size_t
json_string_ostream_get_buffer_used_size(const struct ostream_private *stream)
{
	const struct json_string_ostream *jstream =
		container_of(stream, const struct json_string_ostream,
			     ostream);
	struct json_generator *generator = jstream->generator;
	size_t size = 0;

	if (jstream->buf != NULL)
		size += jstream->buf->used;
	return (size + o_stream_get_buffer_used_size(generator->output));
}

static size_t
json_string_ostream_get_buffer_avail_size(const struct ostream_private *stream)
{
	const struct json_string_ostream *jstream =
		container_of(stream, const struct json_string_ostream,
			     ostream);
	struct json_generator *generator = jstream->generator;

	return o_stream_get_buffer_avail_size(generator->output);
}

static void
json_string_ostream_set_max_buffer_size(struct iostream_private *stream,
					size_t max_size)
{
	struct ostream_private *_stream =
		container_of(stream, struct ostream_private, iostream);
	struct json_string_ostream *jstream =
		container_of(_stream, struct json_string_ostream, ostream);
	struct json_generator *generator = jstream->generator;

	jstream->ostream.max_buffer_size =
		o_stream_get_max_buffer_size(generator->output) / 6;
	if (jstream->ostream.max_buffer_size < max_size) {
		jstream->ostream.max_buffer_size = max_size;
		if (jstream->buf == NULL)
			jstream->buf = buffer_create_dynamic(default_pool, 256);
	} else {
		buffer_free(&jstream->buf);
	}
}

struct ostream *
json_generate_string_open_stream(struct json_generator *generator)
{
	struct json_string_ostream *jstream;

	i_assert(generator->str_stream == NULL);

	jstream = i_new(struct json_string_ostream, 1);
	jstream->generator = generator;
	jstream->ostream.cork = json_string_ostream_cork;
	jstream->ostream.sendv = json_string_ostream_sendv;
	jstream->ostream.flush = json_string_ostream_flush;
	jstream->ostream.iostream.close = json_string_ostream_close;
	jstream->ostream.get_buffer_used_size =
		json_string_ostream_get_buffer_used_size;
	jstream->ostream.get_buffer_avail_size =
		json_string_ostream_get_buffer_avail_size;
	jstream->ostream.iostream.destroy = json_string_ostream_destroy;
	jstream->ostream.iostream.set_max_buffer_size =
		json_string_ostream_set_max_buffer_size;

	/* base default max_buffer_size on worst-case escape ratio */
	jstream->ostream.max_buffer_size =
		o_stream_get_max_buffer_size(generator->output) / 6;
	if (jstream->ostream.max_buffer_size <
		JSON_STRING_OSTREAM_DEFAULT_BUFFER_SIZE) {
		jstream->ostream.max_buffer_size =
			JSON_STRING_OSTREAM_DEFAULT_BUFFER_SIZE;
		jstream->buf = buffer_create_dynamic(default_pool, 256);
	}

	json_generate_string_open(jstream->generator);
	generator->str_stream = jstream;

	return o_stream_create(&jstream->ostream, NULL, -1);
}

/*
 * Simple string output
 */

static void json_append_escaped_char(string_t *dest, unsigned char src)
{
	switch (src) {
	case '\b':
		str_append(dest, "\\b");
		break;
	case '\f':
		str_append(dest, "\\f");
		break;
	case '\n':
		str_append(dest, "\\n");
		break;
	case '\r':
		str_append(dest, "\\r");
		break;
	case '\t':
		str_append(dest, "\\t");
		break;
	case '"':
		str_append(dest, "\\\"");
		break;
	case '\\':
		str_append(dest, "\\\\");
		break;
	default:
		if (src < 0x20 || src >= 0x80)
			str_printfa(dest, "\\u%04x", src);
		else
			str_append_c(dest, src);
		break;
	}
}

static void json_append_escaped_ucs4(string_t *dest, unichar_t chr)
{
	if (chr < 0x80)
		json_append_escaped_char(dest, (unsigned char)chr);
	else if (chr == 0x2028 || chr == 0x2029)
		str_printfa(dest, "\\u%04x", chr);
	else
		uni_ucs4_to_utf8_c(chr, dest);
}


void json_append_escaped(string_t *dest, const char *src)
{
	json_append_escaped_data(dest, (const unsigned char*)src, strlen(src));
}

void json_append_escaped_data(string_t *dest, const unsigned char *src,
			      size_t size)
{
	size_t i;
	int bytes = 0;
	unichar_t chr;

	for (i = 0; i < size;) {
		bytes = uni_utf8_get_char_n(src+i, size-i, &chr);
		if (bytes > 0 && uni_is_valid_ucs4(chr)) {
			json_append_escaped_ucs4(dest, chr);
			i += bytes;
		} else {
			str_append_data(dest, UNICODE_REPLACEMENT_CHAR_UTF8,
					UTF8_REPLACEMENT_CHAR_LEN);
			i++;
		}
	}
}
