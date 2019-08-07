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

enum json_generator_state {
	JSON_GENERATOR_STATE_VALUE = 0,
	JSON_GENERATOR_STATE_VALUE_END,
	JSON_GENERATOR_STATE_VALUE_NEXT,
	JSON_GENERATOR_STATE_OBJECT_MEMBER,
	JSON_GENERATOR_STATE_OBJECT_VALUE,
	JSON_GENERATOR_STATE_STRING,
	JSON_GENERATOR_STATE_TEXT,
	JSON_GENERATOR_STATE_END,
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

	i_stream_unref(&generator->value_input);
	if (generator->output != NULL) {
		o_stream_unref(&generator->output);
		str_free(&generator->buf);
	}
	array_free(&generator->level_stack);
	i_free(generator);
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

int json_generator_flush(struct json_generator *generator)
{
	bool hide_root = HAS_ALL_BITS(generator->flags,
				      JSON_GENERATOR_FLAG_HIDE_ROOT);
	int ret;

	/* Flush buffer */
	ret = json_generator_flush_buffer(generator);
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
	}
	/* Flush opening objects/arrays */
	for (;;) {
		struct json_generator_level *level;

		i_assert(generator->level_stack_written <=
			 generator->level_stack_pos);
		if (generator->level_stack_written == generator->level_stack_pos)
			break;

		i_assert(generator->write_state != JSON_GENERATOR_STATE_STRING &&
			 generator->write_state != JSON_GENERATOR_STATE_TEXT);
		if (generator->write_state == JSON_GENERATOR_STATE_VALUE_END)
			generator->write_state = JSON_GENERATOR_STATE_VALUE_NEXT;
		if (generator->write_state == JSON_GENERATOR_STATE_VALUE_NEXT) {
			ret = json_generator_write_all(generator, ",", 1);
			if (ret <= 0)
				return ret;
			generator->write_state = JSON_GENERATOR_STATE_VALUE;
		}

		// FIXME: add indent

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
	}
	/* Flush separator */
	switch (generator->write_state) {
	/* Flush comma */
	case JSON_GENERATOR_STATE_VALUE_END:
		if (generator->level_stack_pos == 0) {
			generator->write_state = JSON_GENERATOR_STATE_END;
			break;
		}
		if (generator->state != JSON_GENERATOR_STATE_STRING &&
			generator->state != JSON_GENERATOR_STATE_TEXT)
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
		break;
	/* Flush colon */
	case JSON_GENERATOR_STATE_OBJECT_VALUE:
		ret = json_generator_write_all(generator, ":", 1);
		if (ret <= 0)
			return ret;
		generator->write_state = JSON_GENERATOR_STATE_VALUE;
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
	const unsigned char *p, *pbegin, *poffset, *pend;
	size_t avail;
	int ret;

	p = pbegin = poffset = data;
	pend = p + size;
	while (p < pend) {
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
	i_assert(generator->value_input == NULL);
	i_assert(generator->state == JSON_GENERATOR_STATE_STRING);
	if (generator->write_state != JSON_GENERATOR_STATE_STRING) {
		/* This function does not flush first before changing state, nor
		   does the string_open() function. So, we need to remember
		   closing the an empty string, because otherwise nothing will
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

	i_assert(generator->state == JSON_GENERATOR_STATE_VALUE);
	ret = json_generator_flush(generator);
	if (ret <= 0)
		return ret;
	i_assert(generator->write_state == JSON_GENERATOR_STATE_VALUE ||
		 generator->write_state == JSON_GENERATOR_STATE_VALUE_END);

	i_assert(generator->level_stack_written > 0);
	if (!hide_root || generator->level_stack_written > 1) {
		ret = json_generator_write_all(generator, "]", 1);
		if (ret <= 0)
			return ret;
	}
	json_generator_level_close(generator, FALSE);
	json_generator_value_end(generator);
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

	i_assert(generator->state == JSON_GENERATOR_STATE_OBJECT_MEMBER);
	ret = json_generator_flush(generator);
	if (ret <= 0)
		return ret;
	i_assert(generator->write_state == JSON_GENERATOR_STATE_OBJECT_MEMBER ||
		 generator->write_state == JSON_GENERATOR_STATE_VALUE_END);
	i_assert(generator->level_stack_written > 0);
	if (!hide_root || generator->level_stack_written > 1) {
		ret = json_generator_write_all(generator, "}", 1);
		if (ret <= 0)
			return ret;
	}
	json_generator_level_close(generator, TRUE);
	json_generator_value_end(generator);
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
