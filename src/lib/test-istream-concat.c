/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream-private.h"
#include "istream-concat.h"

#include <fcntl.h>
#include <unistd.h>

#define TEST_MAX_ISTREAM_COUNT 10
#define TEST_MAX_ISTREAM_SIZE 1024
#define TEST_MAX_BUFFER_SIZE 128

static void test_istream_concat_one(unsigned int buffer_size)
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
		test_istream_set_allow_eof(streams[i], TRUE);
		test_istream_set_size(streams[i], 0);
	}
	streams[i] = NULL;

	input = i_stream_create_concat(streams);
	for (i = 0; i/STREAM_BYTES < STREAM_COUNT; i++) {
		test_istream_set_size(streams[i/STREAM_BYTES], (i%STREAM_BYTES) + 1);
		test_assert(i_stream_read(input) == 1);
		if (i < buffer_size) {
			data = i_stream_get_data(input, &size);
			test_assert(size == i+1);
		} else {
			i_stream_skip(input, 1);
			data = i_stream_get_data(input, &size);
			test_assert(size == buffer_size);
		}
		for (j = 0; j < size; j++) {
			test_assert((char)data[j] == input_string[(input->v_offset + j) % STREAM_BYTES]);
		}
		test_assert(i_stream_read(input) <= 0);
	}
	test_assert(i_stream_read(input) == -1);
	i_stream_skip(input, i_stream_get_data_size(input));
	i_stream_unref(&input);

	for (i = 0; i < STREAM_COUNT; i++) {
		test_assert(streams[i]->eof && streams[i]->stream_errno == 0);
		i_stream_unref(&streams[i]);
	}
}

static bool test_istream_concat_random(void)
{
	struct istream **streams, *concat, **limits = NULL;
	const unsigned char *data;
	unsigned char *w_data;
	size_t size = 0;
	unsigned int i, j, offset, stream_count, data_len, simult;

	stream_count = i_rand_minmax(2, TEST_MAX_ISTREAM_COUNT + 2 - 1);
	streams = t_new(struct istream *, stream_count + 1);
	for (i = 0, offset = 0; i < stream_count; i++) {
		data_len = i_rand_minmax(1, TEST_MAX_ISTREAM_SIZE);
		w_data = t_malloc_no0(data_len);
		for (j = 0; j < data_len; j++)
			w_data[j] = (offset++) & 0xff;
		streams[i] = test_istream_create_data(w_data, data_len);
		test_istream_set_allow_eof(streams[i], TRUE);
	}
	streams[i] = NULL;
	i_assert(offset > 0);

	concat = i_stream_create_concat(streams);
	i_stream_set_max_buffer_size(concat, TEST_MAX_BUFFER_SIZE);

	simult = i_rand_limit(TEST_MAX_ISTREAM_COUNT);
	if (simult > 0) {
		limits = t_new(struct istream *, simult);
		for (i = 0; i < simult; i++)
			limits[i] = i_stream_create_limit(concat, UOFF_T_MAX);
	}

	for (i = 0; i < 1000; i++) {
		struct istream *input = (simult == 0) ? concat : limits[i_rand_limit(simult)];
		if (i_rand_limit(3) == 0) {
			i_stream_seek(input, i_rand_limit(offset));
		} else {
			ssize_t ret = i_stream_read(input);
			size = i_stream_get_data_size(input);
			if (ret == -2) {
				test_assert(size >= TEST_MAX_BUFFER_SIZE);
			} else if (input->v_offset + size != offset) {
				test_assert(ret > 0);
				test_assert(input->v_offset + ret <= offset);
				i_stream_skip(input, i_rand_limit(ret));

				data = i_stream_get_data(input, &size);
				for (j = 0; j < size; j++) {
					test_assert(data[j] == (input->v_offset + j) % 256);
				}
			}
		}
		if (test_has_failed())
			break;
	}
	for (i = 0; i < stream_count; i++)
		i_stream_unref(&streams[i]);
	for (i = 0; i < simult; i++)
		i_stream_unref(&limits[i]);
	i_stream_unref(&concat);
	return !test_has_failed();
}

static void test_istream_concat_seek_end(void)
{
	test_begin("istream concat seek end");

	struct istream *streams[] = {
		test_istream_create("s1"),
		test_istream_create("s2"),
		NULL
	};
	struct istream *input = i_stream_create_concat(streams);
	i_stream_unref(&streams[0]);
	i_stream_unref(&streams[1]);

	i_stream_seek(input, 4);
	test_assert(i_stream_read(input) == -1);
	i_stream_unref(&input);

	test_end();
}

static void test_istream_concat_early_end(void)
{
	struct istream *input, *streams[2];

	test_begin("istream concat early end");

	streams[0] = test_istream_create("stream");
	test_istream_set_size(streams[0], 3);
	test_istream_set_allow_eof(streams[0], FALSE);
	streams[1] = NULL;

	input = i_stream_create_concat(streams);
	test_assert(i_stream_read(input) == 3);
	test_istream_set_size(streams[0], 5);
	test_assert(i_stream_read(input) == 2);
	i_stream_skip(input, 5);
	i_stream_unref(&input);

	test_assert(streams[0]->v_offset == 5);
	i_stream_unref(&streams[0]);

	test_end();
}

static void test_istream_concat_snapshot(void)
{
	struct istream *input;
	const unsigned char *data;
	size_t size;

	test_begin("istream concat snapshot");

	struct istream *test_istreams[] = {
		test_istream_create("abcdefghijklmnopqrst"),
		test_istream_create("ABCDEFGHIJKLMNOPQRSTUVWXY"),
		test_istream_create("!\"#$%&'()*+,-./01234567890:;<="),
		NULL
	};

	input = i_stream_create_concat(test_istreams);
	for (unsigned int i = 0; test_istreams[i] != NULL; i++) {
		struct istream *tmp_istream = test_istreams[i];
		i_stream_unref(&tmp_istream);
	}

	test_istream_set_size(test_istreams[0], 20);
	test_istream_set_size(test_istreams[1], 0);
	test_istream_set_size(test_istreams[2], 0);

	/* first stream */
	test_istream_set_allow_eof(test_istreams[0], FALSE);
	test_assert(i_stream_read_data(input, &data, &size, 0) == 1);
	test_assert(size == 20);
	test_assert(memcmp(data, "abcdefghijklmnopqrst", 20) == 0);

	/* partially skip */
	i_stream_skip(input, 12);

	/* second stream */
	test_assert(i_stream_read_data(input, &data, &size, 10) == 0);
	test_assert(size == 8);
	test_istream_set_allow_eof(test_istreams[0], TRUE);
	test_istream_set_size(test_istreams[0], 0);
	test_assert(i_stream_read_data(input, &data, &size, 10) == 0);
	test_assert(size == 8);
	test_istream_set_size(test_istreams[1], 10);
	test_assert(i_stream_read_data(input, &data, &size, 10) == 1);
	test_assert(size == 18);
	test_istream_set_allow_eof(test_istreams[1], FALSE);
	test_assert(i_stream_read(input) == 0);
	test_istream_set_size(test_istreams[1], 25);
	test_istream_set_allow_eof(test_istreams[1], TRUE);
	test_assert(i_stream_read_data(input, &data, &size, 30) == 1);
	test_assert(size == 33);
	test_assert(memcmp(data, "mnopqrst"
		"ABCDEFGHIJKLMNOPQRSTUVWXY", 33) == 0);

	/* partially skip */
	i_stream_skip(input, 12);

	/* third stream */
	test_istream_set_size(test_istreams[2], 0);
	test_assert(i_stream_read(input) == 0);
	test_istream_set_size(test_istreams[2], 30);
	test_assert(i_stream_read_data(input, &data, &size, 25) == 1);
	test_assert(size == 51);
	test_assert(memcmp(data, "EFGHIJKLMNOPQRSTUVWXY"
		"!\"#$%&'()*+,-./01234567890:;<=", 51) == 0);

	i_stream_unref(&input);
	test_end();
}

void test_istream_concat(void)
{
	unsigned int i;

	test_begin("istream concat");
	for (i = 1; i < STREAM_BYTES*STREAM_COUNT; i++) {
		test_istream_concat_one(i);
	}
	test_end();

	test_begin("istream concat random");
	for (i = 0; i < 100; i++) T_BEGIN {
		if(!test_istream_concat_random())
			i = 101; /* don't break a T_BEGIN */
	} T_END;
	test_end();

	test_istream_concat_seek_end();
	test_istream_concat_early_end();
	test_istream_concat_snapshot();
}
