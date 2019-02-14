/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "ostream.h"
#include "sha1.h"
#include "randgen.h"
#include "test-common.h"
#include "compression.h"

#include <unistd.h>
#include <fcntl.h>

static void test_compression_handler(const struct compression_handler *handler)
{
	const char *path = "test-compression.tmp";
	struct istream *file_input, *input;
	struct ostream *file_output, *output;
	unsigned char buf[IO_BLOCK_SIZE];
	const unsigned char *data;
	size_t size;
	uoff_t stream_size;
	struct sha1_ctxt sha1;
	unsigned char output_sha1[SHA1_RESULTLEN], input_sha1[SHA1_RESULTLEN];
	unsigned int i;
	int fd;
	ssize_t ret;

	test_begin(t_strdup_printf("compression handler %s", handler->name));

	/* write compressed data */
	fd = open(path, O_TRUNC | O_CREAT | O_RDWR, 0600);
	if (fd == -1)
		i_fatal("creat(%s) failed: %m", path);
	file_output = o_stream_create_fd_file(fd, 0, FALSE);
	output = handler->create_ostream(file_output, 1);
	sha1_init(&sha1);

	/* 1) write lots of easily compressible data */
	memset(buf, 0, sizeof(buf));
	for (i = 0; i < 1024*1024*4 / sizeof(buf); i++) {
		sha1_loop(&sha1, buf, sizeof(buf));
		test_assert(o_stream_send(output, buf, sizeof(buf)) == sizeof(buf));
	}

	/* 2) write uncompressible data */
	for (i = 0; i < 1024*128 / sizeof(buf); i++) {
		random_fill(buf, sizeof(buf));
		sha1_loop(&sha1, buf, sizeof(buf));
		test_assert(o_stream_send(output, buf, sizeof(buf)) == sizeof(buf));
	}

	/* 3) write semi-compressible data */
	for (i = 0; i < sizeof(buf); i++) {
		if (i_rand_limit(3) == 0)
			buf[i] = i_rand_limit(4);
		else
			buf[i] = i;
	}
	for (i = 0; i < 1024*128 / sizeof(buf); i++) {
		sha1_loop(&sha1, buf, sizeof(buf));
		test_assert(o_stream_send(output, buf, sizeof(buf)) == sizeof(buf));
	}

	/* 4) write all two byte combinations */
	for (i = 0; i <= 512; i++) {
		for(int j = i; j <= 512; j++) {
			sha1_loop(&sha1,&i,1);
			test_assert(o_stream_send(output,&i,1) == 1);
			sha1_loop(&sha1,&j,1);
			test_assert(o_stream_send(output,&j,1) == 1);
		}
	}

	test_assert(o_stream_finish(output) > 0);
	uoff_t uncompressed_size = output->offset;
	o_stream_destroy(&output);
	uoff_t compressed_size = file_output->offset;
	o_stream_destroy(&file_output);
	sha1_result(&sha1, output_sha1);

	/* read and uncompress the data */
	file_input = i_stream_create_fd(fd, IO_BLOCK_SIZE);
	input = handler->create_istream(file_input, FALSE);

	test_assert(i_stream_get_size(input, FALSE, &stream_size) == 1);
	test_assert(stream_size == compressed_size);

	test_assert(i_stream_get_size(input, TRUE, &stream_size) == 1);
	test_assert(stream_size == uncompressed_size);
	//printf("\t%s compression ratio   :%f.2\n",handler->name,uncompressed_size*1.0/compressed_size);

	sha1_init(&sha1);
	for (bool seeked = FALSE;;) {
		sha1_init(&sha1);
		while ((ret = i_stream_read_more(input, &data, &size)) > 0) {
			sha1_loop(&sha1, data, size);
			i_stream_skip(input, size);
		}
		test_assert(ret == -1);
		test_assert(input->stream_errno == 0);
		sha1_result(&sha1, input_sha1);
		test_assert(memcmp(input_sha1, output_sha1, sizeof(input_sha1)) == 0);
		if (seeked)
			break;
		seeked = TRUE;
		i_stream_seek(input, 0);
	}

	i_stream_destroy(&input);
	i_stream_destroy(&file_input);

	i_unlink(path);
	i_close_fd(&fd);

	test_end();
}

static void test_compression(void)
{
	unsigned int i;

	for (i = 0; compression_handlers[i].name != NULL; i++) {
		if (compression_handlers[i].create_istream != NULL)
			test_compression_handler(&compression_handlers[i]);
	}
}

static void concat(const char *str1, const char *str2
		,const struct compression_handler *handler)
{
	struct ostream *buf_output, *output;
	struct istream *test_input, *input;
	buffer_t *buf = t_buffer_create(512);

//	if (gz == NULL || gz->create_ostream == NULL)
//		return; /* not compiled in */

	/* write concated output */
	buf_output = o_stream_create_buffer(buf);
	o_stream_set_finish_via_child(buf_output, FALSE);

	output = handler->create_ostream(buf_output, 6);
	o_stream_nsend_str(output, str1);
	test_assert(o_stream_finish(output) > 0);
	o_stream_destroy(&output);

	if (str2[0] != '\0') {
		output = handler->create_ostream(buf_output, 6);
		o_stream_nsend_str(output, "world");
		test_assert(o_stream_finish(output) > 0);
		o_stream_destroy(&output);
	}

	o_stream_destroy(&buf_output);

	/* read concated input */
	const unsigned char *data;
	size_t size;
	test_input = test_istream_create_data(buf->data, buf->used);
	test_istream_set_allow_eof(test_input, FALSE);
	input = handler->create_istream(test_input, TRUE);
	for (size_t i = 0; i <= buf->used; i++) {
		test_istream_set_size(test_input, i);
		test_assert(i_stream_read(input) >= 0);
	}
	test_istream_set_allow_eof(test_input, TRUE);
	test_assert(i_stream_read(input) == -1);
	test_assert(input->stream_errno == 0);

	data = i_stream_get_data(input, &size);
	test_assert(size == strlen(str1)+strlen(str2) &&
		    memcmp(data, str1, strlen(str1)) == 0 &&
		    memcmp(data+strlen(str1), str2, strlen(str2)) == 0);
	i_stream_unref(&input);
	i_stream_unref(&test_input);
}



static void test_concat(void)
{
	unsigned int i;

	for (i = 0; compression_handlers[i].name != NULL; i++) {
		if(!(compression_handlers[i].name[0] == 'g' ||
				compression_handlers[i].name[0] == 'x')) {
			continue;
		}
		if (compression_handlers[i].create_istream != NULL) {
			test_begin(t_strdup_printf("concat %s",compression_handlers[i].name));
			concat("hello","world",&compression_handlers[i]);
			test_end();
		}
	}
}

static void test_no_concat(void)
{
	unsigned int i;

	for (i = 0; compression_handlers[i].name != NULL; i++) {
		if(!(compression_handlers[i].name[0] == 'g' ||
				compression_handlers[i].name[0] == 'x')) {
			continue;
		}
		if (compression_handlers[i].create_istream != NULL) {
			test_begin(t_strdup_printf("no concat %s",compression_handlers[i].name));
			concat("hello","",&compression_handlers[i]);
			test_end();
		}
	}

}

static void test_gz_large_header(void)
{
	const struct compression_handler *gz = compression_lookup_handler("gz");
	static const unsigned char gz_input[] = {
		0x1f, 0x8b, 0x08, 0x08,
		'a','a','a','a','a','a','a','a','a','a','a',
		0
	};
	struct istream *file_input, *input;
	size_t i;

	if (gz == NULL || gz->create_istream == NULL)
		return; /* not compiled in */

	test_begin("gz large header");

	/* max buffer size smaller than gz header */
	for (i = 1; i < sizeof(gz_input); i++) {
		file_input = test_istream_create_data(gz_input, sizeof(gz_input));
		test_istream_set_size(file_input, i);
		test_istream_set_max_buffer_size(file_input, i);

		input = gz->create_istream(file_input, FALSE);
		test_assert_idx(i_stream_read(input) == 0, i);
		test_assert_idx(i_stream_read(input) == -1 &&
				input->stream_errno == EINVAL, i);
		i_stream_unref(&input);
		i_stream_unref(&file_input);
	}

	/* max buffer size is exactly the gz header */
	file_input = test_istream_create_data(gz_input, sizeof(gz_input));
	input = gz->create_istream(file_input, FALSE);
	test_istream_set_size(input, i);
	test_istream_set_allow_eof(input, FALSE);
	test_istream_set_max_buffer_size(input, i);
	test_assert(i_stream_read(input) == 0);
	i_stream_unref(&input);
	i_stream_unref(&file_input);

	test_end();
}

static void test_uncompress_file(const char *path)
{
	const struct compression_handler *handler;
	struct istream *input, *file_input;
	const unsigned char *data;
	size_t size;

	handler = compression_lookup_handler_from_ext(path);
	if (handler == NULL)
		i_fatal("Can't detect compression algorithm from path %s", path);
	if (handler->create_istream == NULL)
		i_fatal("Support not compiled in for %s", handler->name);

	file_input = i_stream_create_file(path, IO_BLOCK_SIZE);
	input = handler->create_istream(file_input, TRUE);
	while (i_stream_read_more(input, &data, &size) > 0) {
		if (write(STDOUT_FILENO, data, size) < 0)
			break;
		i_stream_skip(input, size);
	}
	i_stream_destroy(&input);
}

static void test_compress_file(const char *in_path, const char *out_path)
{
	const struct compression_handler *handler;
	struct istream *input, *file_input;
	struct ostream *output, *file_output;
	int fd_in, fd_out;
	struct sha1_ctxt sha1;
	unsigned char output_sha1[SHA1_RESULTLEN], input_sha1[SHA1_RESULTLEN];
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	handler = compression_lookup_handler_from_ext(out_path);
	if (handler == NULL)
		i_fatal("Can't detect compression algorithm from path %s", out_path);
	if (handler->create_ostream == NULL)
		i_fatal("Support not compiled in for %s", handler->name);

	/* write the compressed output file */
	fd_in = open(in_path, O_RDONLY);
	if (fd_in == -1)
		i_fatal("open(%s) failed: %m", in_path);
	fd_out = open(out_path, O_TRUNC | O_CREAT | O_RDWR, 0600);
	if (fd_out == -1)
		i_fatal("creat(%s) failed: %m", out_path);

	sha1_init(&sha1);
	file_output = o_stream_create_fd_file(fd_out, 0, FALSE);
	output = handler->create_ostream(file_output, 1);
	input = i_stream_create_fd_autoclose(&fd_in, IO_BLOCK_SIZE);
	while (i_stream_read_more(input, &data, &size) > 0) {
		sha1_loop(&sha1, data, size);
		o_stream_nsend(output, data, size);
		i_stream_skip(input, size);
	}
	if (o_stream_finish(output) < 0) {
		i_fatal("write(%s) failed: %s",
			out_path, o_stream_get_error(output));
	}
	i_stream_destroy(&input);
	o_stream_destroy(&output);
	o_stream_destroy(&file_output);
	sha1_result(&sha1, output_sha1);

	/* verify that we can read the compressed file */
	sha1_init(&sha1);
	file_input = i_stream_create_fd(fd_out, IO_BLOCK_SIZE);
	input = handler->create_istream(file_input, FALSE);
	while ((ret = i_stream_read_more(input, &data, &size)) > 0) {
		sha1_loop(&sha1, data, size);
		i_stream_skip(input, size);
	}
	i_stream_destroy(&input);
	i_stream_destroy(&file_input);
	sha1_result(&sha1, input_sha1);

	if (memcmp(input_sha1, output_sha1, sizeof(input_sha1)) != 0)
		i_fatal("Decompression couldn't get the original input");
	i_close_fd(&fd_out);
}

int main(int argc, char *argv[])
{
	static void (*const test_functions[])(void) = {
		test_compression,
		test_concat,
		test_no_concat,
		test_gz_large_header,
		NULL
	};
	if (argc == 2) {
		test_uncompress_file(argv[1]);
		return 0;
	}
	if (argc == 3) {
		test_compress_file(argv[1], argv[2]);
		return 0;
	}
	return test_run(test_functions);
}
