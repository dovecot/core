/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "istream-concat.h"
#include "istream-sized.h"
#include "istream-base64.h"
#include "istream-attachment-connector.h"

struct istream_attachment_connector {
	pool_t pool;
	struct istream *base_input;
	uoff_t base_input_offset, msg_size;

	uoff_t encoded_offset;
	ARRAY(struct istream *) streams;
};

struct istream_attachment_connector *
istream_attachment_connector_begin(struct istream *base_input, uoff_t msg_size)
{
	struct istream_attachment_connector *conn;
	pool_t pool;

	pool = pool_alloconly_create("istream-attachment-connector", 1024);
	conn = p_new(pool, struct istream_attachment_connector, 1);
	conn->pool = pool;
	conn->base_input = base_input;
	conn->base_input_offset = base_input->v_offset;
	conn->msg_size = msg_size;
	p_array_init(&conn->streams, pool, 8);
	i_stream_ref(conn->base_input);
	return conn;
}

int istream_attachment_connector_add(struct istream_attachment_connector *conn,
				     struct istream *decoded_input,
				     uoff_t start_offset, uoff_t encoded_size,
				     unsigned int base64_blocks_per_line,
				     bool base64_have_crlf,
				     const char **error_r)
{
	struct istream *input, *input2;
	uoff_t base_prefix_size;

	if (start_offset < conn->encoded_offset) {
		*error_r = t_strdup_printf(
			"Attachment %s points before the previous attachment "
			"(%"PRIuUOFF_T" < %"PRIuUOFF_T")",
			i_stream_get_name(decoded_input),
			start_offset, conn->encoded_offset);
		return -1;
	}
	base_prefix_size = start_offset - conn->encoded_offset;
	if (start_offset + encoded_size > conn->msg_size) {
		*error_r = t_strdup_printf(
			"Attachment %s points outside message "
			"(%"PRIuUOFF_T" + %"PRIuUOFF_T" > %"PRIuUOFF_T")",
			i_stream_get_name(decoded_input),
			start_offset, encoded_size,
			conn->msg_size);
		return -1;
	}

	if (base_prefix_size > 0) {
		/* add a part of the base message before the attachment */
		input = i_stream_create_min_sized_range(conn->base_input,
			conn->base_input_offset, base_prefix_size);
		i_stream_set_name(input, t_strdup_printf("%s middle",
			i_stream_get_name(conn->base_input)));
		array_append(&conn->streams, &input, 1);
		conn->base_input_offset += base_prefix_size;
		conn->encoded_offset += base_prefix_size;
	}
	conn->encoded_offset += encoded_size;

	if (base64_blocks_per_line == 0) {
		input = decoded_input;
		i_stream_ref(input);
	} else {
		input = i_stream_create_base64_encoder(decoded_input,
						       base64_blocks_per_line*4,
						       base64_have_crlf);
		i_stream_set_name(input, t_strdup_printf("%s[base64:%u b/l%s]",
				  i_stream_get_name(decoded_input),
				  base64_blocks_per_line,
				  base64_have_crlf ? ",crlf" : ""));
	}
	input2 = i_stream_create_sized(input, encoded_size);
	array_append(&conn->streams, &input2, 1);
	i_stream_unref(&input);
	return 0;
}

static void
istream_attachment_connector_free(struct istream_attachment_connector *conn)
{
	struct istream *const *streamp, *stream;

	array_foreach(&conn->streams, streamp) {
		stream = *streamp;
		i_stream_unref(&stream);
	}
	i_stream_unref(&conn->base_input);
	pool_unref(&conn->pool);
}

struct istream *
istream_attachment_connector_finish(struct istream_attachment_connector **_conn)
{
	struct istream_attachment_connector *conn = *_conn;
	struct istream **inputs, *input;
	uoff_t trailer_size;

	*_conn = NULL;

	if (conn->base_input_offset != conn->msg_size) {
		i_assert(conn->base_input_offset < conn->msg_size);

		if (conn->msg_size != (uoff_t)-1) {
			trailer_size = conn->msg_size - conn->encoded_offset;
			input = i_stream_create_sized_range(conn->base_input,
							    conn->base_input_offset,
							    trailer_size);
			i_stream_set_name(input, t_strdup_printf(
				"%s trailer", i_stream_get_name(conn->base_input)));
		} else {
			input = i_stream_create_range(conn->base_input,
						      conn->base_input_offset,
						      (uoff_t)-1);
		}
		array_append(&conn->streams, &input, 1);
	}
	array_append_zero(&conn->streams);

	inputs = array_first_modifiable(&conn->streams);
	input = i_stream_create_concat(inputs);

	istream_attachment_connector_free(conn);
	return input;
}

void istream_attachment_connector_abort(struct istream_attachment_connector **_conn)
{
	struct istream_attachment_connector *conn = *_conn;

	*_conn = NULL;

	istream_attachment_connector_free(conn);
}
