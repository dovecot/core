/* Copyright (c) 2014-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
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
		random_fill_weak(buf, sizeof(buf));
		sha1_loop(&sha1, buf, sizeof(buf));
		test_assert(o_stream_send(output, buf, sizeof(buf)) == sizeof(buf));
	}

	/* 3) write semi-compressible data */
	for (i = 0; i < sizeof(buf); i++) {
		if (rand () % 3 == 0)
			buf[i] = rand() % 4;
		else
			buf[i] = i;
	}
	for (i = 0; i < 1024*128 / sizeof(buf); i++) {
		sha1_loop(&sha1, buf, sizeof(buf));
		test_assert(o_stream_send(output, buf, sizeof(buf)) == sizeof(buf));
	}

	o_stream_destroy(&output);
	o_stream_destroy(&file_output);
	sha1_result(&sha1, output_sha1);

	/* read and uncompress the data */
	sha1_init(&sha1);
	file_input = i_stream_create_fd(fd, IO_BLOCK_SIZE, FALSE);
	input = handler->create_istream(file_input, FALSE);
	while ((ret = i_stream_read_more(input, &data, &size)) > 0) {
		sha1_loop(&sha1, data, size);
		i_stream_skip(input, size);
	}
	test_assert(ret == -1);
	i_stream_destroy(&input);
	i_stream_destroy(&file_input);
	sha1_result(&sha1, input_sha1);

	test_assert(memcmp(input_sha1, output_sha1, sizeof(input_sha1)) == 0);
	i_unlink(path);

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
	if (o_stream_nfinish(output) < 0) {
		i_fatal("write(%s) failed: %s",
			out_path, o_stream_get_error(output));
	}
	i_stream_destroy(&input);
	o_stream_destroy(&output);
	o_stream_destroy(&file_output);
	sha1_result(&sha1, output_sha1);

	/* verify that we can read the compressed file */
	sha1_init(&sha1);
	file_input = i_stream_create_fd(fd_out, IO_BLOCK_SIZE, FALSE);
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
	static void (*test_functions[])(void) = {
		test_compression,
		NULL
	};
	if (argc == 3) {
		test_compress_file(argv[1], argv[2]);
		return 0;
	}
	return test_run(test_functions);
}
