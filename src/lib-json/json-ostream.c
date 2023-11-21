/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"

#include "json-ostream.h"

enum json_ostream_node_state {
	JSON_OSTREAM_NODE_STATE_NONE = 0,
	JSON_OSTREAM_NODE_STATE_VALUE,
	JSON_OSTREAM_NODE_STATE_ARRAY_CLOSE,
	JSON_OSTREAM_NODE_STATE_OBJECT_CLOSE,
};

struct json_ostream {
	int refcount;

	struct ostream *output;
	struct json_generator *generator;

	struct json_node node;
	enum json_ostream_node_state node_state;
	unsigned int write_node_level;

	struct json_tree_walker *tree_walker;
	struct json_tree *tree;
	struct json_node tree_node;

	struct json_data node_data;
	string_t *buffer;

	char *error;

	bool member_name_written:1;
	bool value_opened:1;
	bool value_persists:1;
	bool string_opened:1;
	bool space_opening:1;
	bool space_opened:1;
	bool last_errors_not_checked:1;
	bool error_handling_disabled:1;
	bool nfailed:1;
	bool closed:1;
};

static int json_ostream_write_tree_more(struct json_ostream *stream);
static int json_ostream_write_node_more(struct json_ostream *stream);
static int
json_ostream_do_write_node(struct json_ostream *stream,
			   const struct json_node *node, bool flush,
			   bool persist);

struct json_ostream *
json_ostream_create(struct ostream *output,
		    enum json_generator_flags gen_flags)
{
	struct json_ostream *stream;

	stream = i_new(struct json_ostream, 1);
	stream->refcount = 1;

	stream->output = output;
	o_stream_ref(output);

	stream->generator = json_generator_init(output, gen_flags);

	return stream;
}

struct json_ostream *
json_ostream_create_str(string_t *buf, enum json_generator_flags gen_flags)
{
	struct json_ostream *stream;

	stream = i_new(struct json_ostream, 1);
	stream->refcount = 1;

	stream->generator = json_generator_init_str(buf, gen_flags);

	return stream;
}

void json_ostream_ref(struct json_ostream *stream)
{
	i_assert(stream->refcount > 0);
	stream->refcount++;
}

void json_ostream_unref(struct json_ostream **_stream)
{
	struct json_ostream *stream = *_stream;

	if (stream == NULL)
		return;
	*_stream = NULL;

	i_assert(stream->refcount > 0);
	if (--stream->refcount != 0)
		return;

	if (stream->output != NULL && stream->last_errors_not_checked &&
	    !stream->error_handling_disabled) {
		i_panic("JSON output stream %s is missing error handling",
			o_stream_get_name(stream->output));
	}

	json_generator_deinit(&stream->generator);
	o_stream_unref(&stream->output);
	str_free(&stream->buffer);

	json_tree_walker_free(&stream->tree_walker);
	json_tree_unref(&stream->tree);

	i_free(stream->error);
	i_free(stream);
}

void json_ostream_destroy(struct json_ostream **_stream)
{
	struct json_ostream *stream = *_stream;

	if (stream == NULL)
		return;

	json_ostream_close(stream);
	json_ostream_unref(_stream);
}

unsigned int json_ostream_get_write_node_level(struct json_ostream *stream)
{
	return stream->write_node_level;
}

static void ATTR_FORMAT(2, 3)
json_ostream_set_error(struct json_ostream *stream, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	i_free(stream->error);
	stream->error = i_strdup_vprintf(fmt, args);
	va_end(args);
}

const char *json_ostream_get_error(struct json_ostream *stream)
{
	if (stream->error != NULL)
		return stream->error;
	if (stream->closed)
		return "<closed>";
	if (stream->output != NULL)
		return o_stream_get_error(stream->output);
	return "<no error>";
}

void json_ostream_close(struct json_ostream *stream)
{
	stream->closed = TRUE;
}

bool json_ostream_is_closed(struct json_ostream *stream)
{
	return stream->closed;
}

void json_ostream_set_format(struct json_ostream *stream,
			     const struct json_format *format)
{
	json_generator_set_format(stream->generator, format);
}

void json_ostream_cork(struct json_ostream *stream)
{
	if (stream->output != NULL)
		o_stream_cork(stream->output);
}

void json_ostream_uncork(struct json_ostream *stream)
{
	if (stream->output != NULL)
		o_stream_uncork(stream->output);
}

bool json_ostream_is_corked(struct json_ostream *stream)
{
	return (stream->output != NULL && o_stream_is_corked(stream->output));
}

int json_ostream_nfinish(struct json_ostream *stream)
{
	if (stream->closed)
		return -1;
	if (stream->error != NULL)
		return -1;
	json_ostream_nflush(stream);
	if (stream->output == NULL)
		return 0;
	json_ostream_ignore_last_errors(stream);
	if (stream->output->stream_errno == 0 && stream->nfailed) {
		json_ostream_set_error(stream,
			"Output stream buffer was full (%zu bytes)",
			o_stream_get_max_buffer_size(stream->output));
		return -1;
	}
	return (stream->output->stream_errno != 0 ? -1 : 0);
}

void json_ostream_nfinish_destroy(struct json_ostream **_stream)
{
	struct json_ostream *stream = *_stream;
	int ret;

	if (stream == NULL)
		return;

	ret = json_ostream_nfinish(stream);
	i_assert(ret >= 0);
	json_ostream_destroy(_stream);
}

void json_ostream_ignore_last_errors(struct json_ostream *stream)
{
	stream->last_errors_not_checked = FALSE;
}

void json_ostream_set_no_error_handling(struct json_ostream *stream, bool set)
{
	stream->error_handling_disabled = set;
}

/*
 * Partial data
 */

static void json_ostream_persist_value(struct json_ostream *stream)
{
	if (!json_node_is_singular(&stream->node))
		return;
	if (stream->value_persists)
		return;
	stream->value_persists = TRUE;

	switch (stream->node.value.content_type) {
	case JSON_CONTENT_TYPE_STRING:
		i_unreached();
	case JSON_CONTENT_TYPE_DATA:
		if (stream->buffer == NULL)
			stream->buffer = str_new(default_pool, 128);
		stream->node_data = *stream->node.value.content.data;
		str_truncate(stream->buffer, 0);
		str_append_data(stream->buffer,
				stream->node_data.data, stream->node_data.size);
		stream->node_data.data = str_data(stream->buffer);
		stream->node.value.content.data = &stream->node_data;
		break;
	default:
		break;
	}
}

static int json_ostream_do_write_more(struct json_ostream *stream)
{
	struct json_data *jdata;
	ssize_t sret;
	int ret;

	if (stream->closed)
		return -1;
	if (stream->space_opened) {
		if (stream->space_opening) {
			ret = json_generate_space_open(stream->generator);
			if (ret <= 0)
				return ret;
			stream->space_opening = FALSE;
		}
		return 1;
	}

	switch (stream->node.value.content_type) {
	case JSON_CONTENT_TYPE_STRING:
		i_zero(&stream->node_data);
		stream->node_data.data = (const unsigned char *)
			stream->node.value.content.str;
		stream->node_data.size = strlen(stream->node.value.content.str);
		stream->node.value.content.data = &stream->node_data;
		stream->node.value.content_type =
			JSON_CONTENT_TYPE_DATA;
		/* fall through */
	case JSON_CONTENT_TYPE_DATA:
		jdata = stream->node.value.content.data;
		switch (stream->node.type) {
		/* string */
		case JSON_TYPE_STRING:
			if (stream->string_opened)
				stream->value_opened = TRUE;
			if (!stream->value_opened) {
				json_generate_string_open(stream->generator);
				stream->value_opened = TRUE;
			}
			while (jdata->size > 0) {
				sret = json_generate_string_more(
					stream->generator, jdata->data,
					jdata->size, TRUE);
				if (sret <= 0)
					return (int)sret;
				i_assert((size_t)sret <= jdata->size);
				jdata->data += sret;
				jdata->size -= (size_t)sret;
			}
			if (!stream->string_opened) {
				ret = json_generate_string_write_close(
					stream->generator);
				if (ret <= 0)
					return ret;
			}
			stream->value_opened = FALSE;
			return 1;
		/* number, JSON-text */
		case JSON_TYPE_NUMBER:
		case JSON_TYPE_TEXT:
			i_assert(!stream->string_opened);
			if (!stream->value_opened) {
				json_generate_text_open(stream->generator);
				stream->value_opened = TRUE;
			}
			while (jdata->size > 0) {
				sret = json_generate_text_more(
					stream->generator, jdata->data,
					jdata->size);
				if (sret <= 0)
					return (int)sret;
				i_assert((size_t)sret <= jdata->size);
				jdata->data += sret;
				jdata->size -= (size_t)sret;
			}
			ret = json_generate_text_close(stream->generator);
			if (ret <= 0)
				return ret;
			stream->value_opened = FALSE;
			return 1;
		default:
			i_unreached();
		}
		break;
	default:
		break;
	}

	return json_generate_value(stream->generator, stream->node.type,
				   &stream->node.value);
}

static int json_ostream_write_more(struct json_ostream *stream)
{
	int ret;

	ret = json_ostream_do_write_more(stream);
	if (ret <= 0) {
		i_assert(stream->output != NULL);
		return ret;
	}
	i_zero(&stream->node);
	stream->value_persists = FALSE;
	stream->value_opened = FALSE;
	return 1;
}

int json_ostream_flush(struct json_ostream *stream)
{
	int ret;

	if (stream->closed)
		return -1;
	if (stream->node_state != JSON_OSTREAM_NODE_STATE_NONE) {
		ret = json_ostream_write_node_more(stream);
		if (ret <= 0)
			return ret;
	}
	if (stream->tree_walker != NULL) {
		ret = json_ostream_write_tree_more(stream);
		if (ret <= 0)
			return ret;
		if (stream->node_state != JSON_OSTREAM_NODE_STATE_NONE) {
			ret = json_ostream_write_node_more(stream);
			if (ret <= 0)
				return ret;
		}
	}
	if (json_node_is_none(&stream->node))
		return json_generator_flush(stream->generator);
	ret = json_ostream_write_more(stream);
	if (ret <= 0)
		return ret;
	return 1;
}

void json_ostream_nflush(struct json_ostream *stream)
{
	if (unlikely(stream->closed))
		return;
	if (unlikely(stream->nfailed)) {
		i_assert(stream->output != NULL);
		return;
	}
	if (stream->output != NULL) {
		if (unlikely(stream->output->closed ||
			     stream->output->stream_errno != 0))
			return;
	}
	if (json_ostream_flush(stream) <= 0) {
		i_assert(stream->output != NULL);
		stream->nfailed = TRUE;
	}
	stream->last_errors_not_checked = TRUE;
}

static int
json_ostream_write_init(struct json_ostream *stream, const char *name,
			enum json_type type)
{
	int ret;

	i_assert(!stream->space_opened);
	i_assert(name == NULL || !stream->string_opened);
	i_assert(!stream->string_opened || type == JSON_TYPE_STRING);

	ret = json_ostream_flush(stream);
	if (ret <= 0)
		return ret;

	if (stream->string_opened)
		return 1;

	if (name != NULL) {
		i_assert(!stream->member_name_written);
		ret = json_generate_object_member(stream->generator, name);
		if (ret <= 0)
			return ret;
	}
	stream->member_name_written = FALSE;
	return 1;
}

static int
json_ostream_write_space_init(struct json_ostream *stream, const char *name)
{
	int ret;

	i_assert(!stream->string_opened);

	ret = json_ostream_flush(stream);
	if (ret <= 0)
		return ret;

	if (stream->space_opened)
		return 1;

	if (name != NULL) {
		i_assert(!stream->member_name_written);
		ret = json_generate_object_member(stream->generator, name);
		if (ret <= 0)
			return ret;
	}
	stream->member_name_written = FALSE;
	return 1;
}

/*
 * Values
 */

static inline bool json_ostream_nwrite_pre(struct json_ostream *stream)
{
	if (unlikely(stream->closed))
		return FALSE;
	if (unlikely(stream->nfailed)) {
		i_assert(stream->output != NULL);
		return FALSE;
	}
	if (stream->output != NULL) {
		if (unlikely(stream->output->closed ||
			     stream->output->stream_errno != 0))
			return FALSE;
	}
	return TRUE;
}

static inline void
json_ostream_nwrite_post(struct json_ostream *stream, int ret)
{
	if (ret <= 0) {
		i_assert(stream->output != NULL);
		stream->nfailed = TRUE;
	}
	stream->last_errors_not_checked = TRUE;
}

/* object member */

int json_ostream_write_object_member(struct json_ostream *stream,
				     const char *name)
{
	int ret;

	ret = json_ostream_flush(stream);
	if (ret <= 0)
		return ret;

	i_assert(!stream->member_name_written);
	ret = json_generate_object_member(stream->generator, name);
	if (ret <= 0)
		return ret;
	stream->member_name_written = TRUE;
	return 1;
}

void json_ostream_nwrite_object_member(struct json_ostream *stream,
				       const char *name)
{
	int ret;

	if (!json_ostream_nwrite_pre(stream))
		return;
	ret = json_ostream_write_object_member(stream, name);
	json_ostream_nwrite_post(stream, ret);
}

/* value */

static int
json_ostream_do_write_value(struct json_ostream *stream,
			    const char *name, enum json_type type,
			    const struct json_value *value, bool persist)
{
	int ret;

	ret = json_ostream_write_init(stream, name, type);
	if (ret <= 0)
		return ret;

	i_zero(&stream->node);
	stream->node.type = type;
	stream->node.value = *value;

	ret = json_ostream_write_more(stream);
	if (ret < 0)
		return ret;
	if (ret == 0 && persist)
		json_ostream_persist_value(stream);
	return 1;
}

int json_ostream_write_value(struct json_ostream *stream,
			     const char *name, enum json_type type,
			     const struct json_value *value)
{
	return json_ostream_do_write_value(stream, name, type, value, TRUE);
}

void json_ostream_nwrite_value(struct json_ostream *stream,
			       const char *name, enum json_type type,
			       const struct json_value *value)
{
	int ret;

	if (!json_ostream_nwrite_pre(stream))
		return;
	ret = json_ostream_do_write_value(stream, name, type, value, FALSE);
	json_ostream_nwrite_post(stream, ret);
}

/* number */

int json_ostream_write_number(struct json_ostream *stream,
			      const char *name, intmax_t number)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_INTEGER;
	jvalue.content.intnum = number;

	return json_ostream_write_value(stream, name,
					JSON_TYPE_NUMBER, &jvalue);
}

void json_ostream_nwrite_number(struct json_ostream *stream,
				const char *name, intmax_t number)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_INTEGER;
	jvalue.content.intnum = number;

	json_ostream_nwrite_value(stream, name,
				  JSON_TYPE_NUMBER, &jvalue);
}

int json_ostream_write_number_raw(struct json_ostream *stream,
				  const char *name, const char *number)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STRING;
	jvalue.content.str = number;

	return json_ostream_write_value(stream, name,
					JSON_TYPE_NUMBER, &jvalue);
}

void json_ostream_nwrite_number_raw(struct json_ostream *stream,
				    const char *name, const char *number)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STRING;
	jvalue.content.str = number;

	json_ostream_nwrite_value(stream, name, JSON_TYPE_NUMBER, &jvalue);
}

/* string */

int json_ostream_write_string_data(struct json_ostream *stream,
				   const char *name,
				   const void *data, size_t size)
{
	struct json_value jvalue;
	struct json_data jdata;

	i_zero(&jdata);
	jdata.data = data;
	jdata.size = size;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_DATA;
	jvalue.content.data = &jdata;

	return json_ostream_write_value(stream, name, JSON_TYPE_STRING,
					&jvalue);
}

void json_ostream_nwrite_string_data(struct json_ostream *stream,
				     const char *name,
				     const void *data, size_t size)
{
	struct json_value jvalue;
	struct json_data jdata;

	i_zero(&jdata);
	jdata.data = data;
	jdata.size = size;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_DATA;
	jvalue.content.data = &jdata;

	json_ostream_nwrite_value(stream, name, JSON_TYPE_STRING, &jvalue);
}

int json_ostream_write_string(struct json_ostream *stream,
			      const char *name, const char *str)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STRING;
	jvalue.content.str = str;

	return json_ostream_write_value(stream, name, JSON_TYPE_STRING,
					 &jvalue);
}

void json_ostream_nwrite_string(struct json_ostream *stream,
				const char *name, const char *str)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STRING;
	jvalue.content.str = str;

	json_ostream_nwrite_value(stream, name, JSON_TYPE_STRING, &jvalue);
}

void json_ostream_nwritef_string(struct json_ostream *stream,
				 const char *name, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	json_ostream_nwrite_string(stream, name,
				   t_strdup_vprintf(format, args));
	va_end(args);
}

int json_ostream_write_string_stream(struct json_ostream *stream,
				     const char *name, struct istream *input)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STREAM;
	jvalue.content.stream = input;

	return json_ostream_write_value(stream, name, JSON_TYPE_STRING,
					&jvalue);
}

void json_ostream_nwrite_string_stream(struct json_ostream *stream,
				       const char *name, struct istream *input)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STREAM;
	jvalue.content.stream = input;

	json_ostream_nwrite_value(stream, name, JSON_TYPE_STRING, &jvalue);
	if (input->stream_errno != 0)
		stream->nfailed = TRUE;
}

int json_ostream_open_string(struct json_ostream *stream, const char *name)
{
	int ret;

	ret = json_ostream_write_init(stream, name, JSON_TYPE_STRING);
	if (ret <= 0)
		return ret;

	i_zero(&stream->node);
	json_generate_string_open(stream->generator);
	stream->string_opened = TRUE;
	return 1;
}

void json_ostream_nopen_string(struct json_ostream *stream, const char *name)
{
	int ret;

	if (!json_ostream_nwrite_pre(stream))
		return;
	ret = json_ostream_open_string(stream, name);
	json_ostream_nwrite_post(stream, ret);
}

int json_ostream_close_string(struct json_ostream *stream)
{
	int ret;

	i_assert(stream->string_opened);

	ret = json_ostream_flush(stream);
	if (ret <= 0)
		return ret;
	i_zero(&stream->node);
	ret = json_generate_string_write_close(stream->generator);
	if (ret <= 0)
		return ret;
	stream->string_opened = FALSE;
	return 1;
}

void json_ostream_nclose_string(struct json_ostream *stream)
{
	int ret;

	if (!json_ostream_nwrite_pre(stream))
		return;
	ret = json_ostream_close_string(stream);
	json_ostream_nwrite_post(stream, ret);
}

/* null */

int json_ostream_write_null(struct json_ostream *stream, const char *name)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	return json_ostream_write_value(stream, name, JSON_TYPE_NULL, &jvalue);
}

void json_ostream_nwrite_null(struct json_ostream *stream, const char *name)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	json_ostream_nwrite_value(stream, name, JSON_TYPE_NULL, &jvalue);
}


/* false, true */

int json_ostream_write_false(struct json_ostream *stream, const char *name)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	return json_ostream_write_value(stream, name, JSON_TYPE_FALSE,
					&jvalue);
}

void json_ostream_nwrite_false(struct json_ostream *stream, const char *name)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	json_ostream_nwrite_value(stream, name, JSON_TYPE_FALSE, &jvalue);
}

int json_ostream_write_true(struct json_ostream *stream, const char *name)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	return json_ostream_write_value(stream, name, JSON_TYPE_TRUE, &jvalue);
}

void json_ostream_nwrite_true(struct json_ostream *stream, const char *name)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	json_ostream_nwrite_value(stream, name, JSON_TYPE_TRUE, &jvalue);
}

int json_ostream_write_bool(struct json_ostream *stream, const char *name,
			    bool value)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	return json_ostream_write_value(
		stream, name, (value ? JSON_TYPE_TRUE : JSON_TYPE_FALSE),
		&jvalue);
}

void json_ostream_nwrite_bool(struct json_ostream *stream, const char *name,
			      bool value)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	json_ostream_nwrite_value(
		stream, name, (value ? JSON_TYPE_TRUE : JSON_TYPE_FALSE),
		&jvalue);
}

/* object */

int json_ostream_descend_object(struct json_ostream *stream, const char *name)
{
	int ret;

	ret = json_ostream_write_init(stream, name, JSON_TYPE_OBJECT);
	if (ret <= 0)
		return ret;

	i_zero(&stream->node);
	json_generate_object_open(stream->generator);
	stream->write_node_level++;
	return 1;
}

void json_ostream_ndescend_object(struct json_ostream *stream,
				  const char *name)
{
	int ret;

	if (!json_ostream_nwrite_pre(stream))
		return;
	ret = json_ostream_descend_object(stream, name);
	json_ostream_nwrite_post(stream, ret);
}

int json_ostream_ascend_object(struct json_ostream *stream)
{
	int ret;

	ret = json_ostream_flush(stream);
	if (ret <= 0)
		return ret;
	ret = json_generate_object_close(stream->generator);
	if (ret <= 0)
		return ret;
	i_assert(stream->write_node_level > 0);
	stream->write_node_level--;
	return 1;
}

void json_ostream_nascend_object(struct json_ostream *stream)
{
	int ret;

	if (!json_ostream_nwrite_pre(stream))
		return;
	ret = json_ostream_ascend_object(stream);
	json_ostream_nwrite_post(stream, ret);
}

/* array */

int json_ostream_descend_array(struct json_ostream *stream, const char *name)
{
	int ret;

	ret = json_ostream_write_init(stream, name, JSON_TYPE_ARRAY);
	if (ret <= 0)
		return ret;

	i_zero(&stream->node);
	json_generate_array_open(stream->generator);
	stream->write_node_level++;
	return 1;
}

void json_ostream_ndescend_array(struct json_ostream *stream,
				 const char *name)
{
	int ret;

	if (!json_ostream_nwrite_pre(stream))
		return;
	ret = json_ostream_descend_array(stream, name);
	json_ostream_nwrite_post(stream, ret);
}

int json_ostream_ascend_array(struct json_ostream *stream)
{
	int ret;

	ret = json_ostream_flush(stream);
	if (ret <= 0)
		return ret;
	ret = json_generate_array_close(stream->generator);
	if (ret <= 0)
		return ret;
	i_assert(stream->write_node_level > 0);
	stream->write_node_level--;
	return 1;
}

void json_ostream_nascend_array(struct json_ostream *stream)
{
	int ret;

	if (!json_ostream_nwrite_pre(stream))
		return;
	ret = json_ostream_ascend_array(stream);
	json_ostream_nwrite_post(stream, ret);
}

/* JSON-text */

/* string */

int json_ostream_write_text_data(struct json_ostream *stream,
				 const char *name,
				 const void *data, size_t size)
{
	struct json_value jvalue;
	struct json_data jdata;

	i_zero(&jdata);
	jdata.data = data;
	jdata.size = size;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_DATA;
	jvalue.content.data = &jdata;

	return json_ostream_write_value(stream, name, JSON_TYPE_TEXT, &jvalue);
}

void json_ostream_nwrite_text_data(struct json_ostream *stream,
				   const char *name,
				   const void *data, size_t size)
{
	struct json_value jvalue;
	struct json_data jdata;

	i_zero(&jdata);
	jdata.data = data;
	jdata.size = size;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_DATA;
	jvalue.content.data = &jdata;

	json_ostream_nwrite_value(stream, name, JSON_TYPE_TEXT, &jvalue);
}

int json_ostream_write_text(struct json_ostream *stream,
			    const char *name, const char *str)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STRING;
	jvalue.content.str = str;

	return json_ostream_write_value(stream, name, JSON_TYPE_TEXT, &jvalue);
}

void json_ostream_nwrite_text(struct json_ostream *stream,
			      const char *name, const char *str)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STRING;
	jvalue.content.str = str;

	json_ostream_nwrite_value(stream, name, JSON_TYPE_TEXT, &jvalue);
}

int json_ostream_write_text_stream(struct json_ostream *stream,
				   const char *name, struct istream *input)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STREAM;
	jvalue.content.stream = input;

	return json_ostream_write_value(stream, name, JSON_TYPE_TEXT,
					&jvalue);
}

void json_ostream_nwrite_text_stream(struct json_ostream *stream,
				     const char *name, struct istream *input)
{
	struct json_value jvalue;

	i_zero(&jvalue);
	jvalue.content_type = JSON_CONTENT_TYPE_STREAM;
	jvalue.content.stream = input;

	json_ostream_nwrite_value(stream, name, JSON_TYPE_TEXT, &jvalue);
	if (input->stream_errno != 0)
		stream->nfailed = TRUE;
}

static int json_ostream_write_tree_more(struct json_ostream *stream)
{
	int ret;

	i_assert(stream->tree_walker != NULL);

	for (;;) {
		/* Walk the tree to the next node */
		if (json_node_is_none(&stream->tree_node) &&
		    !json_tree_walk(stream->tree_walker,
				    &stream->tree_node)) {
			json_tree_walker_free(&stream->tree_walker);
			json_tree_unref(&stream->tree);
			i_zero(&stream->tree_node);
			return 1;
		}

		ret = json_ostream_do_write_node(stream, &stream->tree_node,
						 FALSE, FALSE);
		if (ret < 0) {
			json_tree_walker_free(&stream->tree_walker);
			json_tree_unref(&stream->tree);
			i_zero(&stream->tree_node);
			return -1;
		}
		if (ret == 0)
			return ret;
		i_zero(&stream->tree_node);
	}
	i_unreached();
}

static int
json_ostream_write_tree_init(struct json_ostream *stream, const char *name,
			     const struct json_tree *jtree)
{
	int ret;

	i_assert(jtree != NULL);

	ret = json_ostream_write_init(stream, name, JSON_TYPE_TEXT);
	if (ret <= 0)
		return ret;

	i_assert(stream->tree_walker == NULL);
	stream->tree_walker = json_tree_walker_create(jtree);
	i_zero(&stream->tree_node);

	return 1;
}

int json_ostream_write_tree(struct json_ostream *stream, const char *name,
			    struct json_tree *jtree)
{
	int ret;

	ret = json_ostream_write_tree_init(stream, name, jtree);
	if (ret <= 0)
		return ret;

	ret = json_ostream_write_tree_more(stream);
	if (stream->tree_walker != NULL) {
		stream->tree = jtree;
		json_tree_ref(jtree);
	}
	return (ret < 0 ? -1 : 1);
}

void json_ostream_nwrite_tree(struct json_ostream *stream, const char *name,
			      const struct json_tree *jtree)
{
	int ret;

	if (!json_ostream_nwrite_pre(stream))
		return;
	ret = json_ostream_write_tree_init(stream, name, jtree);
	if (ret > 0)
		ret = json_ostream_write_tree_more(stream);
	i_assert(ret <= 0 || stream->tree_walker == NULL);
	json_ostream_nwrite_post(stream, ret);
}

/*
 * Nodes
 */

static int json_ostream_write_node_more(struct json_ostream *stream)
{
	int ret;

	switch (stream->node_state) {
	case JSON_OSTREAM_NODE_STATE_NONE:
		break;
	case JSON_OSTREAM_NODE_STATE_VALUE:
		/* Continue value */
		ret = json_ostream_write_more(stream);
		if (ret <= 0)
			return ret;
		stream->node_state = JSON_OSTREAM_NODE_STATE_NONE;
		i_zero(&stream->node);
		break;
	case JSON_OSTREAM_NODE_STATE_ARRAY_CLOSE:
		/* Continue array close */
		ret = json_generate_array_close(stream->generator);
		if (ret <= 0)
			return ret;
		stream->node_state = JSON_OSTREAM_NODE_STATE_NONE;
		i_zero(&stream->node);
		break;
	case JSON_OSTREAM_NODE_STATE_OBJECT_CLOSE:
		/* Continue object close */
		ret = json_generate_object_close(stream->generator);
		if (ret <= 0)
			return ret;
		stream->node_state = JSON_OSTREAM_NODE_STATE_NONE;
		i_zero(&stream->node);
		break;
	default:
		i_unreached();
	}
	return 1;
}

static int
json_ostream_do_write_node(struct json_ostream *stream,
			   const struct json_node *node, bool flush,
			   bool persist)
{
	int ret;

	if (flush) {
		ret = json_ostream_flush(stream);
		if (ret <= 0)
			return ret;

		i_assert(stream->node_state == JSON_OSTREAM_NODE_STATE_NONE);
	} else if (stream->node_state != JSON_OSTREAM_NODE_STATE_NONE) {
		return 0;
	}

	i_assert(!json_node_is_none(node));

	if (!json_node_is_end(node) && node->name != NULL) {
		i_assert(!stream->member_name_written);
		ret = json_generate_object_member(stream->generator,
						  node->name);
		if (ret <= 0)
			return ret;
	}
	stream->member_name_written = FALSE;

	switch (node->type) {
	case JSON_TYPE_ARRAY:
		if (!json_node_is_array_end(node)) {
			/* Open array */
			json_generate_array_open(stream->generator);
			return 1;
		}
		/* Close array */
		stream->node = *node;
		stream->node_state = JSON_OSTREAM_NODE_STATE_ARRAY_CLOSE;
		break;
	case JSON_TYPE_OBJECT:
		if (!json_node_is_object_end(node)) {
			/* Open object */
			json_generate_object_open(stream->generator);
			return 1;
		}
		/* Close object */
		stream->node = *node;
		stream->node_state = JSON_OSTREAM_NODE_STATE_OBJECT_CLOSE;
		break;
	default:
		/* Write normal value */
		stream->node = *node;
		stream->node_state = JSON_OSTREAM_NODE_STATE_VALUE;
		break;
	}

	ret = json_ostream_write_node_more(stream);
	if (ret < 0)
		return -1;
	if (ret == 0 && persist)
		json_ostream_persist_value(stream);

	return 1;
}

int json_ostream_write_node(struct json_ostream *stream,
			    const struct json_node *node, bool copy)
{
	i_assert(!stream->space_opened);

	return json_ostream_do_write_node(stream, node, TRUE, copy);
}

void json_ostream_nwrite_node(struct json_ostream *stream,
			      const struct json_node *node)
{
	switch (node->type) {
	case JSON_TYPE_ARRAY:
		if (!json_node_is_array_end(node)) {
			/* Open array */
			json_ostream_ndescend_array(stream, node->name);
			return;
		}
		/* Close array */
		json_ostream_nascend_array(stream);
		return;
	case JSON_TYPE_OBJECT:
		if (!json_node_is_object_end(node)) {
			/* Open object */
			json_ostream_ndescend_object(stream, node->name);
			return;
		}
		/* Close object */
		json_ostream_nascend_object(stream);
		return;
	default:
		break;
	}

	json_ostream_nwrite_value(stream, node->name,
				  node->type, &node->value);
}

/*
 * String output stream
 */

int json_ostream_open_string_stream(struct json_ostream *stream,
				    const char *name,
				    struct ostream **ostream_r)
{
	int ret;

	*ostream_r = NULL;

	ret = json_ostream_write_init(stream, name, JSON_TYPE_NONE);
	if (ret <= 0)
		return ret;

	*ostream_r = json_generate_string_open_stream(stream->generator);
	return 1;
}

struct ostream *
json_ostream_nopen_string_stream(struct json_ostream *stream, const char *name)
{
	struct ostream *ostream;
	bool failed = FALSE;
	int ret;

	if (!json_ostream_nwrite_pre(stream)) {
		if (stream->output == NULL)
			i_assert(!stream->nfailed);
		else
			failed = TRUE;
	}
	if (failed) {
		int stream_errno = stream->output->stream_errno;
		if (stream_errno == 0)
			stream_errno = EIO;
		return o_stream_create_error(stream_errno);
	}
	ret = json_ostream_open_string_stream(stream, name, &ostream);
	json_ostream_nwrite_post(stream, ret);
	return ostream;
}

/*
 * <space>
 */

int json_ostream_open_space(struct json_ostream *stream, const char *name)
{
	int ret;

	ret = json_ostream_write_space_init(stream, name);
	if (ret <= 0)
		return ret;

	i_zero(&stream->node);
	stream->space_opened = TRUE;
	stream->space_opening = TRUE;

	return json_ostream_write_more(stream);
}

void json_ostream_nopen_space(struct json_ostream *stream, const char *name)
{
	int ret;

	if (!json_ostream_nwrite_pre(stream))
		return;
	ret = json_ostream_open_space(stream, name);
	json_ostream_nwrite_post(stream, ret);
}

void json_ostream_close_space(struct json_ostream *stream)
{
	i_assert(stream->space_opened);
	i_assert(!stream->space_opening);

	json_generate_space_close(stream->generator);
	stream->space_opened = FALSE;
}
