/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "sha2.h"
#include "istream-private.h"
#include "istream-sized.h"
#include "istream-hash.h"
#include "istream-seekable.h"

#include <fcntl.h>
#include <unistd.h>

static int fd_callback(const char **path_r, void *context ATTR_UNUSED)
{
	int fd;

	*path_r = "test-lib.tmp";
	fd = open(*path_r, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		i_error("creat(%s) failed: %m", *path_r);
	else
		i_unlink(*path_r);
	return fd;
}

static void test_istream_seekable_one(unsigned int buffer_size)
{
	static const char *input_string = "xyz";
#define STREAM_COUNT 5
#define STREAM_BYTES 3
	struct istream *streams[STREAM_COUNT+1];
	struct istream *input;
	const unsigned char *data;
	size_t size;
	unsigned int i, j;

	for (i = 0; i < STREAM_COUNT; i++) {
		streams[i] = test_istream_create(input_string);
		streams[i]->seekable = FALSE;
		test_istream_set_allow_eof(streams[i], TRUE);
		test_istream_set_size(streams[i], 0);
	}
	streams[i] = NULL;

	input = i_stream_create_seekable(streams, buffer_size, fd_callback, NULL);
	test_assert(!input->blocking);
	for (i = 0; i/STREAM_BYTES < STREAM_COUNT; i++) {
		test_istream_set_size(streams[i/STREAM_BYTES], (i%STREAM_BYTES) + 1);
		if (i < buffer_size) {
			test_assert(i_stream_read(input) == 1);
			data = i_stream_get_data(input, &size);
			test_assert(size == i+1);
		} else {
			test_assert(i_stream_read(input) == -2);
			i_stream_skip(input, 1);
			test_assert(i_stream_read(input) == 1);
			data = i_stream_get_data(input, &size);
			test_assert(size == buffer_size);
		}
		for (j = 0; j < size; j++) {
			test_assert((char)data[j] == input_string[(input->v_offset + j) % STREAM_BYTES]);
		}
	}
	test_assert(!input->blocking);
	test_assert(i_stream_read(input) == -1);
	test_assert(input->blocking);
	for (i = 0; i < STREAM_COUNT; i++) {
		test_assert(streams[i]->eof && streams[i]->stream_errno == 0);
		i_stream_unref(&streams[i]);
	}
	i_stream_unref(&input);
}

static void test_istream_seekable_random(void)
{
	struct istream **streams, *input;
	const unsigned char *data;
	unsigned char *w_data;
	size_t size;
	unsigned int i, j, offset, stream_count, data_len, buffer_size;

	stream_count = i_rand_minmax(2, 10 + 2 - 1);
	streams = t_new(struct istream *, stream_count + 1);
	for (i = 0, offset = 0; i < stream_count; i++) {
		data_len = i_rand_minmax(1, 100);
		w_data = t_malloc_no0(data_len);
		for (j = 0; j < data_len; j++)
			w_data[j] = offset++;
		streams[i] = test_istream_create_data(w_data, data_len);
		streams[i]->seekable = FALSE;
		test_istream_set_allow_eof(streams[i], TRUE);
	}
	streams[i] = NULL;
	i_assert(offset > 0);

	buffer_size = i_rand_minmax(1, 100); size = 0;
	input = i_stream_create_seekable(streams, buffer_size, fd_callback, NULL);
	test_assert(!input->blocking);

	/* first read it through */
	while (i_stream_read(input) > 0) {
		size = i_stream_get_data_size(input);
		i_stream_skip(input, size);
	}
	test_assert(input->blocking);

	i_stream_seek(input, 0);
	for (i = 0; i < 100; i++) {
		if (i_rand_limit(3) == 0) {
			i_stream_seek(input, i_rand_limit(offset));
		} else {
			ssize_t ret = i_stream_read(input);
			if (input->v_offset + size == offset)
				test_assert(ret < 0);
			else if (ret == -2) {
				test_assert(size == buffer_size);
			} else {
				test_assert(ret > 0);
				test_assert(input->v_offset + ret <= offset);
				i_stream_skip(input, i_rand_limit(ret + 1));

				data = i_stream_get_data(input, &size);
				for (j = 0; j < size; j++) {
					test_assert(data[j] == (input->v_offset + j) % 256);
				}
			}
		}
		size = i_stream_get_data_size(input);
	}
	for (i = 0; i < stream_count; i++) {
		test_assert(streams[i]->eof && streams[i]->stream_errno == 0);
		i_stream_unref(&streams[i]);
	}
	i_stream_unref(&input);
}

static void test_istream_seekable_eof(void)
{
	static const char *in_str = "foo";
	unsigned int in_str_len = strlen(in_str);
	struct istream *streams[2], *input;
	const unsigned char *data;
	size_t size;

	test_begin("istream seekable eof");

	streams[0] = i_stream_create_from_data(in_str, in_str_len);
	streams[0]->seekable = FALSE;
	streams[1] = NULL;

	input = i_stream_create_seekable(streams, in_str_len, fd_callback, NULL);

	test_assert(i_stream_read(input) == (ssize_t)in_str_len);
	data = i_stream_get_data(input, &size);
	test_assert(size == in_str_len);
	test_assert(memcmp(data, in_str, in_str_len) == 0);

	test_assert(i_stream_read(input) == -1);
	data = i_stream_get_data(input, &size);
	test_assert(size == in_str_len);
	test_assert(memcmp(data, in_str, in_str_len) == 0);
	i_stream_seek(input, size);

	i_stream_unref(&input);

	test_assert(streams[0]->v_offset == in_str_len);
	test_assert(streams[0]->eof);
	i_stream_unref(&streams[0]);
	test_end();
}

static void test_istream_seekable_early_end(void)
{
	struct istream *input, *streams[2];

	test_begin("istream seekable early end");

	streams[0] = test_istream_create("stream");
	test_istream_set_size(streams[0], 3);
	test_istream_set_allow_eof(streams[0], FALSE);
	streams[0]->seekable = FALSE;
	streams[1] = NULL;

	input = i_stream_create_seekable(streams, 1000, fd_callback, NULL);
	test_assert(i_stream_read(input) == 3);
	test_istream_set_size(streams[0], 5);
	test_assert(i_stream_read(input) == 2);
	i_stream_skip(input, 5);
	i_stream_unref(&input);

	test_assert(streams[0]->v_offset == 5);
	i_stream_unref(&streams[0]);

	test_end();
}

static void test_istream_seekable_invalid_read(void)
{
	test_begin("istream seekable + other streams causing invalid read");
	struct sha256_ctx hash_ctx;
	sha256_init(&hash_ctx);
	struct istream *str_input = test_istream_create("123456");
	str_input->seekable = FALSE;
	struct istream *seek_inputs[] = { str_input, NULL };
	struct istream *seek_input = i_stream_create_seekable(seek_inputs, 3, fd_callback, NULL);
	struct istream *sized_input = i_stream_create_sized(seek_input, 3);
	struct istream *input = i_stream_create_hash(sized_input, &hash_method_sha256, &hash_ctx);
	test_assert(i_stream_read(input) == 3);
	test_assert(i_stream_read(input) == -2);
	i_stream_skip(input, 3);
	test_assert(i_stream_read(input) == -1);
	i_stream_unref(&input);
	i_stream_unref(&sized_input);
	i_stream_unref(&seek_input);
	i_stream_unref(&str_input);
	test_end();
}

void test_istream_seekable(void)
{
	unsigned int i;

	test_begin("istream seekable");
	for (i = 1; i <= STREAM_BYTES*STREAM_COUNT; i++)
		test_istream_seekable_one(i);
	test_end();

	test_begin("istream seekable random");
	for (i = 0; i < 100; i++) T_BEGIN {
		test_istream_seekable_random();
	} T_END;
	test_end();

	test_istream_seekable_eof();
	test_istream_seekable_early_end();
	test_istream_seekable_invalid_read();
}
