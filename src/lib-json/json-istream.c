/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "istream-seekable.h"

#include "json-istream.h"

struct json_istream {
	int refcount;

	struct istream *input;
	enum json_istream_type type;
	struct json_parser *parser;

	struct json_node node;
	unsigned int node_level;
	unsigned int read_node_level;
	unsigned int skip_nodes;

	struct istream *value_stream, *seekable_stream;

	struct json_tree *tree;
	struct json_tree_node *tree_node;
	unsigned int tree_node_level;

	char *error;

	bool opened:1;
	bool closed:1;
	bool node_parsed:1;    /* Parsed a node */
	bool member_parsed:1;  /* Parsed an object member name */
	bool read_member:1;    /* Read only the object member name */
	bool end_of_list:1;    /* Encountered the end of current array/object */
	bool end_of_input:1;   /* Encountered end of input */
	bool skip_to_end:1;    /* Skip to the end of the JSON text */
	bool deref_value:1;    /* Value (stream) needs to be dereferenced */
};

static void json_istream_dereference_value(struct json_istream *stream);
static int json_istream_consume_value_stream(struct json_istream *stream);

/*
 * Parser callbacks
 */

static void
json_istream_parse_list_open(void *context, void *list_context,
			     const char *name, bool object,
			     void **list_context_r);
static void
json_istream_parse_list_close(void *context, void *list_context, bool object);
static void
json_istream_parse_object_member(void *context,
				 void *parent_context ATTR_UNUSED,
				 const char *name);
static void
json_istream_parse_value(void *context, void *list_context, const char *name,
			 enum json_type type,
			 const struct json_value *value);

static const struct json_parser_callbacks parser_callbacks = {
	.parse_list_open = json_istream_parse_list_open,
	.parse_list_close = json_istream_parse_list_close,
	.parse_object_member = json_istream_parse_object_member,
	.parse_value = json_istream_parse_value
};

/*
 * Object
 */

struct json_istream *
json_istream_create(struct istream *input, enum json_istream_type type,
		    const struct json_limits *limits,
		    enum json_parser_flags parser_flags)
{
	struct json_istream *stream;

	stream = i_new(struct json_istream, 1);
	stream->refcount = 1;
	stream->type = type;

	stream->input = input; /* Parser holds reference */
	stream->parser = json_parser_init(input, limits, parser_flags,
					  &parser_callbacks, (void *)stream);

	return stream;
}

void json_istream_ref(struct json_istream *stream)
{
	i_assert(stream->refcount > 0);
	stream->refcount++;
}

void json_istream_unref(struct json_istream **_stream)
{
	struct json_istream *stream = *_stream;

	if (stream == NULL)
		return;
	*_stream = NULL;

	i_assert(stream->refcount > 0);
	if (--stream->refcount > 0)
		return;

	json_istream_dereference_value(stream);

	json_parser_deinit(&stream->parser);
	i_free(stream->error);
	i_free(stream);
}

void json_istream_destroy(struct json_istream **_stream)
{
	struct json_istream *stream = *_stream;

	if (stream == NULL)
		return;

	json_istream_dereference_value(stream);

	json_istream_close(stream);
	json_istream_unref(_stream);
}

void json_istream_close(struct json_istream *stream)
{
	stream->closed = TRUE;
	if (stream->value_stream != NULL)
		i_stream_close(stream->value_stream);
}

bool json_istream_is_closed(struct json_istream *stream)
{
	return stream->closed;
}

unsigned int json_istream_get_node_level(struct json_istream *stream)
{
	return stream->read_node_level;
}

bool json_istream_is_at_end(struct json_istream *stream)
{
	i_assert(!stream->end_of_input || stream->input->eof);
	return stream->end_of_input;
}

bool json_istream_failed(struct json_istream *stream)
{
	return (stream->error != NULL || stream->closed);
}

static void
json_istream_set_error(struct json_istream *stream, const char *error)
{
	if (stream->error != NULL)
		return;
	stream->error = i_strdup(error);
	json_istream_close(stream);
}

const char *json_istream_get_error(struct json_istream *stream)
{
	if (stream->error == NULL) {
		return (stream->closed ? "<closed>" :
			(stream->end_of_input ? "END-OF-INPUT" : "<no error>"));
	}
	return stream->error;
}

int json_istream_finish(struct json_istream **_stream, const char **error_r)
{
	struct json_istream *stream = *_stream;
	const char *error = NULL;
	int ret;

	i_assert(stream != NULL);
	stream->skip_to_end = TRUE;
	ret = json_istream_read(stream, NULL);
	if (ret == 0)
		return 0;

	ret = 1;
	if (stream->error != NULL) {
		error = t_strdup(stream->error);
		ret = -1;
	} else if (stream->closed) {
		error = "Stream is closed";
		ret = -1;
	} else if (!stream->end_of_input) {
		error = "Spurious data at end of JSON value";
		ret = -1;
	}
	if (ret < 0 && stream->error == NULL && stream->refcount > 1)
		stream->error = i_strdup(error);
	json_istream_unref(_stream);

	if (error_r != NULL)
		*error_r = error;
	return ret;
}

void json_istream_get_location(struct json_istream *stream,
			       struct json_parser_location *loc_r)
{
	json_parser_get_location(stream->parser, loc_r);
}

/*
 * Parser callbacks
 */

static inline bool json_istream_parse_skip(struct json_istream *stream)
{
	i_assert(!stream->skip_to_end);
	if (stream->skip_nodes > 0) {
		if (stream->skip_nodes < UINT_MAX)
			stream->skip_nodes--;
		return TRUE;
	}
	return FALSE;
}

static void
json_istream_parse_list_open(void *context, void *parent_context,
			     const char *name, bool object,
			     void **list_context_r)
{
	struct json_istream *stream = context;
	struct json_tree_node *parent = parent_context;
	unsigned int node_level = stream->node_level;

	if (stream->skip_to_end)
		return;

	i_assert(!stream->node_parsed);
	i_assert(stream->node_level >= stream->read_node_level);

	if (!stream->opened) {
		stream->opened = TRUE;
		switch (stream->type) {
		case JSON_ISTREAM_TYPE_NORMAL:
			break;
		case JSON_ISTREAM_TYPE_ARRAY:
			if (object) {
				i_assert(stream->error == NULL);
				json_istream_set_error(
					stream, "Root is not an array");
				json_parser_interrupt(stream->parser);
			}
			return;
		case JSON_ISTREAM_TYPE_OBJECT:
			if (!object) {
				i_assert(stream->error == NULL);
				json_istream_set_error(
					stream, "Root is not an object");
				json_parser_interrupt(stream->parser);
			}
			return;
		}
	}

	stream->node_level++;

	if (stream->tree != NULL) {
		if (parent == NULL)
			parent = stream->tree_node;
		if (object) {
			*list_context_r = (void *)
				json_tree_node_add_object(parent, name);
		} else {
			*list_context_r = (void *)
				json_tree_node_add_array(parent, name);
		}
		return;
	}

	if (node_level == stream->read_node_level) {
		i_zero(&stream->node);
		stream->node.name = name;
		stream->node.type = (object ?
			JSON_TYPE_OBJECT : JSON_TYPE_ARRAY);
		stream->node.value.content_type =
			JSON_CONTENT_TYPE_LIST;
		if (!json_istream_parse_skip(stream)) {
			stream->node_parsed = TRUE;
			json_parser_interrupt(stream->parser);
		}
	}
}

static void
json_istream_parse_list_close(void *context, void *list_context ATTR_UNUSED,
			      bool object)
{
	struct json_istream *stream = context;

	if (stream->skip_to_end)
		return;

	i_assert(!stream->node_parsed);

	if (stream->node_level == 0) {
		/* Already at lowest level; eat the root node */
		i_assert(stream->opened);
		stream->opened = FALSE;
		switch (stream->type) {
		case JSON_ISTREAM_TYPE_ARRAY:
		case JSON_ISTREAM_TYPE_OBJECT:
			return;
		default:
			i_unreached();
		}
	}

	stream->node_level--;
	if (stream->node_level == 0) {
		/* Moved to lowest level */
		switch (stream->type) {
		case JSON_ISTREAM_TYPE_NORMAL:
			stream->opened = FALSE;
			break;
		case JSON_ISTREAM_TYPE_ARRAY:
		case JSON_ISTREAM_TYPE_OBJECT:
			break;
		}
	}

	if (stream->tree != NULL) {
		if (stream->node_level < stream->tree_node_level) {
			stream->end_of_list = TRUE;
			stream->node_parsed = TRUE;
			json_parser_interrupt(stream->parser);
		} else if (stream->node_level == stream->tree_node_level) {
			if (!json_istream_parse_skip(stream)) {
				stream->node_parsed = TRUE;
				json_parser_interrupt(stream->parser);
			}
		}
		return;
	}

	if (stream->node_level < stream->read_node_level) {
		stream->end_of_list = TRUE;
		if (!json_istream_parse_skip(stream)) {
			i_zero(&stream->node);
			stream->node.type = (object ?
				JSON_TYPE_OBJECT : JSON_TYPE_ARRAY);
			stream->node_parsed = TRUE;
			stream->member_parsed = TRUE;
			json_parser_interrupt(stream->parser);
		}
	}
}

static void
json_istream_parse_object_member(void *context,
				 void *parent_context ATTR_UNUSED,
				 const char *name)
{
	struct json_istream *stream = context;

	if (stream->skip_to_end)
		return;

	i_assert(!stream->node_parsed && !stream->member_parsed);

	if (!stream->read_member)
		return;
	if (stream->skip_nodes > 0)
		return;

	i_assert(stream->tree == NULL);
	i_assert(stream->node_level >= stream->read_node_level);

	if (stream->node_level != stream->read_node_level)
		return;

	i_zero(&stream->node);
	stream->node.name = name;
	stream->member_parsed = TRUE;
	json_parser_interrupt(stream->parser);
}

static void
json_istream_parse_value(void *context, void *parent_context, const char *name,
			 enum json_type type, const struct json_value *value)
{
	struct json_istream *stream = context;
	struct json_tree_node *parent = parent_context;

	if (stream->skip_to_end)
		return;

	i_assert(!stream->node_parsed);
	i_assert(stream->node_level >= stream->read_node_level);

	if (!stream->opened) {
		switch (stream->type) {
		case JSON_ISTREAM_TYPE_NORMAL:
			break;
		case JSON_ISTREAM_TYPE_ARRAY:
			i_assert(stream->error == NULL);
			json_istream_set_error(
				stream, "Root is not an array");
			json_parser_interrupt(stream->parser);
			return;
		case JSON_ISTREAM_TYPE_OBJECT:
			i_assert(stream->error == NULL);
			json_istream_set_error(
				stream, "Root is not an object");
			json_parser_interrupt(stream->parser);
			return;
		}
	}

	if (stream->tree != NULL) {
		if (parent == NULL) {
			/* just starting; parent is not in the syntax tree */
			parent = stream->tree_node;
		}
		json_tree_node_add_value(parent, name, type, value);
		if (stream->node_level == stream->tree_node_level) {
			stream->node_parsed = TRUE;
			json_parser_interrupt(stream->parser);
		}
		return;
	}

	/* not parsing a full tree */
	if (stream->node_level != stream->read_node_level)
		return;
	if (json_istream_parse_skip(stream))
		return;
	i_zero(&stream->node);
	stream->node.name = name;
	stream->node.type = type;
	stream->node.value = *value;
	stream->node_parsed = TRUE;
	if (value->content_type == JSON_CONTENT_TYPE_STREAM) {
		stream->value_stream = value->content.stream;
		i_stream_ref(stream->value_stream);
	}
	json_parser_interrupt(stream->parser);
}

/*
 *
 */

static void json_istream_dereference_value(struct json_istream *stream)
{
	if (stream->deref_value) {
		stream->deref_value = FALSE;
		/* These streams have destroy callbacks that guarantee that no
		   stale pointer can remain in the JSON istream. */
		if (stream->seekable_stream != NULL) {
			struct istream *seekable_stream =
				stream->seekable_stream;
			i_stream_unref(&seekable_stream);
		} else if (stream->value_stream != NULL) {
			i_stream_unref(&stream->value_stream);
		}
		json_parser_disable_string_stream(stream->parser);
	}
	if (stream->tree != NULL)
		json_tree_unref(&stream->tree);
}

int json_istream_read(struct json_istream *stream, struct json_node *node_r)
{
	const char *error;
	int ret;

	if (stream->closed)
		return -1;

	if (!stream->node_parsed) {
		if (stream->end_of_input) {
			if (node_r != NULL)
				*node_r = stream->node;
			return -1;
		}
		if (stream->end_of_list) {
			if (node_r != NULL)
				*node_r = stream->node;
			return 1;
		}
		json_istream_dereference_value(stream);
		ret = json_istream_consume_value_stream(stream);
		if (ret <= 0)
			return ret;
		ret = json_parse_more(stream->parser, &error);
		if (ret < 0) {
			json_istream_set_error(stream, error);
			return ret;
		}
		if (stream->error != NULL)
			return -1;
		if (ret == 0 && !stream->node_parsed) {
			if (node_r != NULL)
				i_zero(node_r);
			return 0;
		}
		if (ret > 0) {
			stream->end_of_input = TRUE;
			if (!stream->node_parsed) {
				if (node_r != NULL)
					*node_r = stream->node;
				return -1;
			}
		}
	}

	if (node_r != NULL)
		*node_r = stream->node;
	return 1;
}

int json_istream_read_next(struct json_istream *stream,
			   struct json_node *node_r)
{
	int ret;

	ret = json_istream_read(stream, node_r);
	if (ret <= 0)
		return ret;
	json_istream_skip(stream);
	return 1;
}

static void json_istream_next_node(struct json_istream *stream)
{
	if (stream->skip_nodes == 0 &&
	    stream->member_parsed && !stream->node_parsed)
		stream->skip_nodes = 1;
	stream->node_parsed = FALSE;
	stream->member_parsed = FALSE;
}

void json_istream_skip(struct json_istream *stream)
{
	json_istream_dereference_value(stream);
	json_istream_next_node(stream);
}

void json_istream_ignore(struct json_istream *stream, unsigned int count)
{
	bool parsed = (stream->member_parsed || stream->node_parsed);

	if (count == 0)
		return;
	json_istream_skip(stream);
	if (count == UINT_MAX)
		stream->skip_nodes = UINT_MAX;
	else {
		if (parsed)
			count--;
		if (stream->skip_nodes >= (UINT_MAX - count))
			stream->skip_nodes = UINT_MAX;
		else
			stream->skip_nodes += count;
	}
}

int json_istream_read_object_member(struct json_istream *stream,
				    const char **name_r)
{
	const char *error;
	int ret;

	if (stream->closed)
		return -1;

	if (!stream->node_parsed && !stream->member_parsed) {
		if (stream->end_of_input) {
			*name_r = NULL;
			return -1;
		}
		if (stream->end_of_list) {
			*name_r = NULL;
			return 1;
		}
		json_istream_dereference_value(stream);
		ret = json_istream_consume_value_stream(stream);
		if (ret <= 0)
			return ret;
		stream->read_member = TRUE;
		ret = json_parse_more(stream->parser, &error);
		stream->read_member = FALSE;
		if (ret < 0) {
			json_istream_set_error(stream, error);
			return ret;
		}
		if (stream->error != NULL)
			return -1;
		if (stream->node_parsed)
			stream->node_parsed = FALSE;
		if (ret == 0 && !stream->member_parsed) {
			*name_r = NULL;
			return 0;
		}
		if (ret > 0) {
			stream->end_of_input = TRUE;
			i_assert(!stream->member_parsed);
			*name_r = NULL;
			return -1;
		}
	}

	if (stream->end_of_list) {
		*name_r = NULL;
		return 1;
	}

	*name_r = stream->node.name;
	return 1;
}

int json_istream_descend(struct json_istream *stream,
			 struct json_node *node_r)
{
	struct json_node node;
	int ret;

	ret = json_istream_read(stream, &node);
	if (ret <= 0)
		return ret;

	json_istream_skip(stream);
	if (json_node_is_object(&node) || json_node_is_array(&node))
		stream->read_node_level++;
	if (node_r != NULL)
		*node_r = node;
	return ret;
}

static void json_istream_ascend_common(struct json_istream *stream)
{
	if (stream->tree != NULL)
		json_tree_unref(&stream->tree);
	stream->skip_nodes = 0;
	stream->node_parsed = FALSE;
	stream->member_parsed = FALSE;
	stream->end_of_list = FALSE;
}

void json_istream_ascend(struct json_istream *stream)
{
	i_assert(stream->read_node_level > 0);
	json_istream_ascend_common(stream);
	stream->read_node_level--;
}

void json_istream_ascend_to(struct json_istream *stream,
			     unsigned int node_level)
{
	i_assert(stream->read_node_level >= node_level);
	if (node_level == stream->read_node_level) {
		json_istream_skip(stream);
		return;
	}
	json_istream_ascend_common(stream);
	stream->read_node_level = node_level;
}

int json_istream_walk(struct json_istream *stream, struct json_node *node_r)
{
	struct json_node node;
	int ret;

	ret = json_istream_descend(stream, &node);
	if (ret <= 0)
		return ret;
	if (json_node_is_end(&node)) {
		i_assert(stream->end_of_list);
		i_assert(stream->read_node_level > 0);
		json_istream_ascend_common(stream);
		stream->read_node_level--;
	}
	if (node_r != NULL)
		*node_r = node;
	return 1;
}

/*
 * Stream values
 */

static void json_istream_drop_seekable_stream(struct json_istream *stream)
{
	stream->deref_value = FALSE;
	stream->value_stream = NULL;
	stream->seekable_stream = NULL;
	json_parser_disable_string_stream(stream->parser);
}

static void json_istream_drop_value_stream(struct json_istream *stream)
{
	if (stream->deref_value) {
		stream->deref_value = FALSE;
		if (stream->seekable_stream != NULL) {
			i_stream_remove_destroy_callback(
				stream->seekable_stream,
				json_istream_drop_seekable_stream);
			i_stream_unref(&stream->seekable_stream);
		}
	}
	stream->value_stream = NULL;
	stream->seekable_stream = NULL;
}

static void json_istream_consumed_value_stream(struct json_istream *stream)
{
	json_istream_dereference_value(stream);
	if (stream->seekable_stream != NULL) {
		i_stream_remove_destroy_callback(
			stream->seekable_stream,
			json_istream_drop_seekable_stream);
	}
	if (stream->value_stream != NULL) {
		i_stream_remove_destroy_callback(
			stream->value_stream,
			json_istream_drop_value_stream);
	}
	stream->value_stream = NULL;
	stream->seekable_stream = NULL;
	json_parser_disable_string_stream(stream->parser);
}

static int json_istream_consume_value_stream(struct json_istream *stream)
{
	struct istream *input = stream->seekable_stream;
	const unsigned char *data;
	uoff_t v_offset;
	size_t size;
	int ret;

	if (input == NULL)
		return 1;
	if (!i_stream_have_bytes_left(stream->seekable_stream)) {
		json_istream_consumed_value_stream(stream);
		return 1;
	}

	v_offset = input->v_offset;
	i_stream_seek(input, stream->value_stream->v_offset);
	while ((ret = i_stream_read_more(input, &data, &size)) > 0)
		i_stream_skip(input, size);
	i_stream_seek(input, v_offset);
	if (ret == 0)
		return ret;

	if (input->stream_errno != 0) {
		json_istream_set_error(stream,
			t_strdup_printf("read(%s) failed: %s",
					i_stream_get_name(input),
					i_stream_get_error(input)));
		return -1;
	}
	i_assert(stream->value_stream == NULL ||
		 !i_stream_have_bytes_left(stream->value_stream));
	i_assert(stream->seekable_stream == NULL ||
		 !i_stream_have_bytes_left(stream->seekable_stream));
	json_istream_consumed_value_stream(stream);
	return 1;
}

static void
json_istream_handle_stream(struct json_istream *stream,
			    const char *temp_path_prefix,
			    size_t max_buffer_size,
			    struct json_node *node)
{
	if (node != NULL &&
	    node->value.content_type == JSON_CONTENT_TYPE_STREAM) {
		if (temp_path_prefix != NULL) {
			struct istream *input[2] = { NULL, NULL };

			i_assert(stream->value_stream != NULL);
			i_assert(stream->seekable_stream == NULL);
			i_assert(!stream->deref_value);

			input[0] = stream->value_stream;
			stream->seekable_stream = i_stream_create_seekable_path(
				input, max_buffer_size, temp_path_prefix);
			i_stream_unref(&input[0]);
			node->value.content.stream = stream->seekable_stream;
			i_stream_set_name(stream->seekable_stream,
					  "(seekable JSON string)");

			i_stream_add_destroy_callback(
				stream->value_stream,
				json_istream_drop_value_stream, stream);
			i_stream_add_destroy_callback(
				stream->seekable_stream,
				json_istream_drop_seekable_stream, stream);
		}
		stream->deref_value = TRUE;
	}
}

int json_istream_read_stream(struct json_istream *stream,
			     size_t threshold, size_t max_buffer_size,
			     const char *temp_path_prefix,
			     struct json_node *node_r)
{
	int ret;

	if (stream->closed)
		return -1;

	if (stream->node_parsed) {
		if (node_r != NULL)
			*node_r = stream->node;
		if (node_r != NULL &&
		    node_r->value.content_type == JSON_CONTENT_TYPE_STREAM &&
		    stream->seekable_stream != NULL)
			node_r->value.content.stream = stream->seekable_stream;
		return 1;
	}

	json_parser_enable_string_stream(stream->parser, threshold,
					 max_buffer_size);
	ret = json_istream_read(stream, node_r);
	if (ret <= 0 ) {
		json_parser_disable_string_stream(stream->parser);
		return ret;
	}

	json_istream_handle_stream(stream, temp_path_prefix, max_buffer_size,
				   node_r);
	return 1;
}

int json_istream_read_next_stream(struct json_istream *stream,
				  size_t threshold, size_t max_buffer_size,
				  const char *temp_path_prefix,
				  struct json_node *node_r)
{
	int ret;

	ret = json_istream_read_stream(stream, threshold, max_buffer_size,
				       temp_path_prefix, node_r);
	if (ret <= 0)
		return ret;
	json_istream_next_node(stream);
	return 1;
}

int json_istream_walk_stream(struct json_istream *stream,
			     size_t threshold, size_t max_buffer_size,
			     const char *temp_path_prefix,
			     struct json_node *node_r)
{
	int ret;

	if (stream->closed)
		return -1;

	if (stream->node_parsed) {
		if (node_r != NULL)
			*node_r = stream->node;
		if (node_r != NULL &&
		    node_r->value.content_type == JSON_CONTENT_TYPE_STREAM &&
		    stream->seekable_stream != NULL)
			node_r->value.content.stream = stream->seekable_stream;
		return 1;
	}

	json_parser_enable_string_stream(stream->parser, threshold,
					 max_buffer_size);
	ret = json_istream_walk(stream, node_r);
	if (ret <= 0 ) {
		json_parser_disable_string_stream(stream->parser);
		return ret;
	}

	json_istream_handle_stream(stream, temp_path_prefix, max_buffer_size,
				   node_r);
	return 1;
}

/*
 * Tree values
 */

static int json_istream_read_tree_common(struct json_istream *stream)
{
	const char *error;
	int ret;

	ret = json_istream_consume_value_stream(stream);
	if (ret <= 0)
		return ret;
	ret = json_parse_more(stream->parser, &error);
	if (ret < 0) {
		json_istream_set_error(stream, error);
		return ret;
	}
	if (stream->error != NULL)
		return -1;
	if (ret == 0 && !stream->node_parsed) {
		return 0;
	}
	if (ret > 0) {
		stream->end_of_input = TRUE;
		if (!stream->node_parsed)
			return -1;
	}
	return 1;
}

int json_istream_read_tree(struct json_istream *stream,
			   struct json_tree **tree_r)
{
	int ret;

	i_assert(tree_r != NULL);

	if (stream->closed) {
		*tree_r = NULL;
		return -1;
	}
	if (stream->end_of_input) {
		*tree_r = NULL;
		return -1;
	}
	if (stream->end_of_list) {
		*tree_r = NULL;
		return 1;
	}

	stream->member_parsed = FALSE;
	if (stream->node_parsed) {
		struct json_node root_node = stream->node;

		if (stream->tree != NULL) {
			*tree_r = stream->tree;
			return 1;
		}

		i_assert(stream->node.type != JSON_TYPE_NONE);
		i_assert(!json_node_is_end(&stream->node));

		/* start tree with parsed node */
		root_node.name = NULL;
		stream->tree = json_tree_create();
		stream->tree_node = json_tree_node_add(
			json_tree_get_root(stream->tree), &root_node);

		stream->node_parsed = FALSE;

		if (json_node_is_singular(&root_node)) {
			/* return tree with non-list item immediately */
			*tree_r = stream->tree;
			stream->tree = NULL;
			return 1;
		}

		stream->tree_node_level = stream->read_node_level;

	} else if (stream->tree == NULL) {
		/* start blank tree */
		stream->tree = json_tree_create();
		stream->tree_node = json_tree_get_root(stream->tree);
		stream->tree_node_level = stream->read_node_level;
	}

	ret = json_istream_read_tree_common(stream);
	if (ret < 0) {
		stream->tree_node = NULL;
		json_tree_unref(&stream->tree);
	}
	if (ret <= 0) {
		*tree_r = NULL;
		return ret;
	}

	if (stream->end_of_list) {
		*tree_r = NULL;
		return 1;
	}

	*tree_r = stream->tree;
	stream->tree_node = NULL;
	stream->tree = NULL;
	json_istream_skip(stream);
	return 1;
}

int json_istream_read_into_tree_node(struct json_istream *stream,
				     struct json_tree_node *tree_node)
{
	int ret;

	if (stream->tree != NULL) {
		if (stream->node_parsed)
			return 1;
	} else {
		if (!stream->node_parsed) {
			ret = json_istream_read(stream, NULL);
			if (ret <= 0 )
				return ret;
		}

		struct json_node new_node = stream->node;

		i_assert(new_node.type != JSON_TYPE_NONE);
		i_assert(!json_node_is_end(&new_node));

		/* start tree branch with parsed node */
		stream->tree_node = json_tree_node_add(tree_node, &new_node);

		stream->node_parsed = FALSE;

		if (json_node_is_singular(&new_node)) {
			stream->tree_node = NULL;
			json_istream_skip(stream);
			return 1;
		}

		stream->tree = json_tree_node_get_tree(tree_node);
		json_tree_ref(stream->tree);

		stream->tree_node_level = stream->read_node_level;
	}

	ret = json_istream_read_tree_common(stream);
	if (ret != 0) {
		stream->tree_node = NULL;
		json_tree_unref(&stream->tree);
	}
	if (ret <= 0)
		return ret;

	json_istream_skip(stream);
	return 1;
}

int json_istream_read_into_tree(struct json_istream *stream,
				struct json_tree *tree)
{
	return json_istream_read_into_tree_node(
		stream, json_tree_get_root(tree));
}
