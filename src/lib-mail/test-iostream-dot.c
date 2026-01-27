/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "randgen.h"
#include "istream.h"
#include "ostream.h"
#include "istream-dot.h"
#include "ostream-dot.h"
#include "test-common.h"

#include "hex-binary.h"

static void test_iostream_dot_random_io(void)
{
	unsigned char in_buf[1024];
	size_t in_buf_size;
	buffer_t *enc_buf, *dec_buf;
	unsigned int i, j;
	int ret;

	enc_buf = buffer_create_dynamic(default_pool, sizeof(in_buf));
	dec_buf = buffer_create_dynamic(default_pool, sizeof(in_buf));

	test_begin("dot istream/ostream random I/O");

	for (i = 0; !test_has_failed() && i < 2000; i++) {
		struct istream *input1, *input2;
		struct ostream *output1, *output2;
		struct istream *top_input;
		const unsigned char *data;
		size_t size, in_pos, out_pos;

		/* Initialize test data*/
		in_buf_size = i_rand_minmax(1, sizeof(in_buf));
		for (j = 0; j < in_buf_size; j++) {
			in_buf[j] = i_rand_limit(256);
			if (in_buf[j] == '\n' &&
			    (j == 0 || in_buf[j - 1] != '\r') ) {
				if (j + 1 == in_buf_size)
					in_buf[j] = ' ';
				else {
					in_buf[j] = '\r';
					in_buf[j + 1] = '\n';
				}
			}
		}

		/* Reset encode output buffer */
		buffer_set_used_size(enc_buf, 0);

		/* Create input stream for test data */
		input1 = test_istream_create_data(in_buf, in_buf_size);
		i_stream_set_name(input1, "[data]");

		/* Create output stream for test data */
		output1 = test_ostream_create_nonblocking(
			enc_buf, i_rand_minmax(3, 4096)); /* < 3 not supported */
		/* Create dot output stream */
		output2 = o_stream_create_dot(output1, FALSE);
		o_stream_set_name(output2, "[encoder]");

		/* Compress the data incrementally */
		in_pos = out_pos = 0;
		ret = 0;
		test_istream_set_size(input1, in_pos);
		while (ret == 0) {
			enum ostream_send_istream_result res;

			res = o_stream_send_istream(output2, input1);
			switch(res) {
			case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
			case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
				ret = -1;
				break;
			case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
				out_pos += i_rand_limit(512);
				test_ostream_set_max_output_size(
					output1, out_pos);
				ret = 0;
				break;
			case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
				in_pos += i_rand_limit(512);
				if (in_pos > in_buf_size)
					in_pos = in_buf_size;
				test_istream_set_size(input1, in_pos);
				ret = 0;
				break;
			case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
				/* finish it */
				ret = o_stream_finish(output2);
				break;
			}
		}

		/* Clean up */
		i_stream_unref(&input1);
		o_stream_unref(&output1);
		o_stream_unref(&output2);

		/* Reset decode output buffer */
		buffer_set_used_size(dec_buf, 0);

		/* Create input stream for compressed data */
		input1 = i_stream_create_from_buffer(enc_buf);
		i_stream_set_name(input1, "[dot-data]");

		/* Create decompressor stream */
		input2 =  i_stream_create_dot(input1, ISTREAM_DOT_TRIM_TRAIL |
						      ISTREAM_DOT_STRICT_EOT);
		i_stream_set_name(input2, "[decoder]");

		/* Assign random buffer sizes */
		i_stream_set_max_buffer_size(input2, i_rand_minmax(1, 4096));

		/* Read the outer stream in full with random increments. */
		top_input = input2;
		while ((ret = i_stream_read_more(
			top_input, &data, &size)) > 0) {
			size_t ch = i_rand_limit(512);

			size = I_MIN(size, ch);
			buffer_append(dec_buf, data, size);
			i_stream_skip(top_input, size);
		}
		if (ret < 0 && top_input->stream_errno == 0) {
			data = i_stream_get_data(top_input, &size);
			if (size > 0) {
				buffer_append(dec_buf, data, size);
				i_stream_skip(top_input, size);
			}
		}

		/* Assert stream status */
		test_assert_idx(ret < 0 && top_input->stream_errno == 0, i);

		if (in_buf_size > 2 && in_buf[in_buf_size-2] == '\r' &&
		    in_buf[in_buf_size-1] == '\n')
			in_buf_size -= 2;

		/* Assert input/output equality */
		test_assert_memcmp_idx(in_buf, in_buf_size, dec_buf->data, dec_buf->used, i);
		if (test_has_failed()) {
			i_info("EXPECTED INPUT: %s", binary_to_hex(in_buf, in_buf_size));
			i_info("ACTUAL   INPUT: %s", binary_to_hex(dec_buf->data, dec_buf->used));
		}

		if (top_input->stream_errno != 0) {
			i_error("%s: %s", i_stream_get_name(input1),
			       i_stream_get_error(input1));
			i_error("%s: %s", i_stream_get_name(input2),
			       i_stream_get_error(input2));
		}

		if (test_has_failed()) {
			i_info("Test parameters: size=%zu",
				in_buf_size);
		}

		/* Clean up */
		i_stream_unref(&input1);
		i_stream_unref(&input2);
	}
	test_end();
	buffer_free(&enc_buf);
	buffer_free(&dec_buf);
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_iostream_dot_random_io,
		NULL,
	};

	int ret;
	struct ioloop *ioloop;

	ioloop = io_loop_create();
	ret = test_run(test_functions);
	io_loop_destroy(&ioloop);

	return ret;
}
