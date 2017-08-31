/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "ostream.h"
#include "sha1.h"
#include "randgen.h"
#include "test-common.h"
#include "compression.h"

#include "hex-binary.h"

#include <unistd.h>
#include <fcntl.h>

static void test_compression_handler_detect(const struct compression_handler *handler)
{
	const unsigned char test_data[] = {'h','e','l','l','o',' ',
					   'w','o','r','l','d','\n'};
	const unsigned char *data;
	size_t size;
	buffer_t *buffer;
	struct ostream *test_output;
	struct ostream *output;

	struct istream *test_input;
	struct istream *input;

	/* write some amount of data */
	test_begin(t_strdup_printf("compression handler %s (detect)", handler->name));

	buffer = buffer_create_dynamic(default_pool, 1024);

	test_output = test_ostream_create(buffer);
	output = handler->create_ostream(test_output, 1);
	o_stream_unref(&test_output);

	/* write data at once */
	test_assert(o_stream_send(output, test_data, sizeof(test_data)) == sizeof(test_data));
	test_assert(o_stream_finish(output) == 1);
	o_stream_unref(&output);

	test_input = test_istream_create_data(buffer->data, buffer->used);
	handler = compression_detect_handler(test_input);
	i_stream_seek(test_input, 0);
	test_assert(handler != NULL);
	if (handler != NULL) {
		input = handler->create_istream(test_input, TRUE);
		i_stream_unref(&test_input);

		test_assert(i_stream_read_more(input, &data, &size) > 0);
		test_assert(size == sizeof(test_data) &&
			    memcmp(data, test_data, size) == 0);

		i_stream_unref(&input);
	} else {
		i_stream_unref(&test_input);
	}

	buffer_free(&buffer);
	test_end();
}

static void test_compression_handler_short(const struct compression_handler *handler)
{
	const unsigned char *data;
	size_t len, size;
	buffer_t *test_data;
	buffer_t *buffer;
	struct ostream *test_output;
	struct ostream *output;

	struct istream *test_input;
	struct istream *input;

	/* write some amount of data */
	test_begin(t_strdup_printf("compression handler %s (small)", handler->name));
	len = i_rand_minmax(1, 1024);
	test_data = buffer_create_dynamic(default_pool, len);
	random_fill(buffer_append_space_unsafe(test_data, len), len);
	buffer_set_used_size(test_data, len);
	buffer_append(test_data, "hello. world.\n", 14);

	buffer = buffer_create_dynamic(default_pool, 1024);
	test_output = test_ostream_create(buffer);
	output = handler->create_ostream(test_output, 1);
	o_stream_unref(&test_output);

	/* write data at once */
	test_assert(o_stream_send(output, test_data->data, test_data->used) == (ssize_t)test_data->used);
	test_assert(o_stream_finish(output) == 1);
	o_stream_unref(&output);

	/* read data at once */
	test_input = test_istream_create_data(buffer->data, buffer->used);
	input = handler->create_istream(test_input, TRUE);
	i_stream_unref(&test_input);

	test_assert(i_stream_read_more(input, &data, &size) > 0);
	test_assert(size == test_data->used &&
		    memcmp(data, test_data->data, size) ==0);

	i_stream_unref(&input);

	buffer_free(&buffer);
	buffer_free(&test_data);

	test_end();
}

static void test_compression_handler_seek(const struct compression_handler *handler)
{
	const unsigned char *data,*ptr;
	size_t len, size, pos;
	buffer_t *test_data;
	buffer_t *buffer;
	struct ostream *test_output;
	struct ostream *output;

	struct istream *test_input;
	struct istream *input;

	/* write some amount of data */
	test_begin(t_strdup_printf("compression handler %s (seek)", handler->name));
	len = i_rand_minmax(1024, 2048);
	test_data = buffer_create_dynamic(default_pool, len);
	random_fill(buffer_append_space_unsafe(test_data, len), len);
	buffer_set_used_size(test_data, len);
	buffer_append(test_data, "hello. world.\n", 14);

	buffer = buffer_create_dynamic(default_pool, 1024);
	test_output = test_ostream_create(buffer);
	output = handler->create_ostream(test_output, 1);
	o_stream_unref(&test_output);

	/* write data at once */
	test_assert(o_stream_send(output, test_data->data, test_data->used) == (ssize_t)test_data->used);
	test_assert(o_stream_finish(output) == 1);
	o_stream_unref(&output);

	test_input = test_istream_create_data(buffer->data, buffer->used);
	input = handler->create_istream(test_input, TRUE);
	i_stream_unref(&test_input);

	/* seek forward */
	i_stream_seek(input, test_data->used - 14); /* should read 'hello. world.\n' */

	test_assert(i_stream_read_more(input, &data, &size) > 0);
	test_assert(size >= 14 && memcmp(data, "hello. world.\n", 14) == 0);
	i_stream_skip(input, size);

	ptr = test_data->data;

	/* seek to random positions and see that we get correct data */
	for (unsigned int i = 0; i < 1000; i++) {
		pos = i_rand_limit(test_data->used);
		i_stream_seek(input, pos);
		size = 0;
		test_assert_idx(i_stream_read_more(input, &data, &size) > 0, i);
		test_assert_idx(size > 0 && memcmp(data,ptr+pos,size) == 0, i);
	}

	i_stream_unref(&input);

	buffer_free(&buffer);
	buffer_free(&test_data);

	test_end();
}

static void test_compression_handler_reset(const struct compression_handler *handler)
{
	const unsigned char *data;
	size_t len, size;
	buffer_t *test_data;
	buffer_t *buffer;
	struct ostream *test_output;
	struct ostream *output;

	struct istream *test_input;
	struct istream *input;

	/* write some amount of data */
	test_begin(t_strdup_printf("compression handler %s (reset)", handler->name));
	len = i_rand_minmax(1024, 2048);
	test_data = buffer_create_dynamic(default_pool, len);
	random_fill(buffer_append_space_unsafe(test_data, len), len);
	buffer_set_used_size(test_data, len);
	buffer_append(test_data, "hello. world.\n", 14);

	buffer = buffer_create_dynamic(default_pool, 1024);
	test_output = test_ostream_create(buffer);
	output = handler->create_ostream(test_output, 1);
	o_stream_unref(&test_output);

	/* write data at once */
	test_assert(o_stream_send(output, test_data->data, test_data->used) == (ssize_t)test_data->used);
	test_assert(o_stream_finish(output) == 1);
	o_stream_unref(&output);

	test_input = test_istream_create_data(buffer->data, buffer->used);
	input = handler->create_istream(test_input, TRUE);
	i_stream_unref(&test_input);

	/* seek forward */
	i_stream_seek(input, test_data->used - 14); /* should read 'hello. world.\n' */

	test_assert(i_stream_read_more(input, &data, &size) > 0);
	test_assert(size >= 14 && memcmp(data, "hello. world.\n", 14) == 0);
	i_stream_skip(input, size);

	/* reset */
	i_stream_sync(input);

	/* see that we still get data, at start */
	size = 0;
	test_assert(i_stream_read_more(input, &data, &size) > 0);
	test_assert(size > 0 && memcmp(data, test_data->data, size) == 0);

	i_stream_unref(&input);

	buffer_free(&buffer);
	buffer_free(&test_data);

	test_end();
}

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
	/* make sure the input size isn't multiple of something simple */
	random_fill(buf, sizeof(buf));
	sha1_loop(&sha1, buf, sizeof(buf) - 5);
	test_assert(o_stream_send(output, buf, sizeof(buf) - 5) == sizeof(buf) - 5);

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

	test_assert(o_stream_finish(output) > 0);
	uoff_t uncompressed_size = output->offset;
	o_stream_destroy(&output);
	uoff_t compressed_size = file_output->offset;
	o_stream_destroy(&file_output);
	sha1_result(&sha1, output_sha1);

	/* read and uncompress the data */
	file_input = i_stream_create_fd(fd, IO_BLOCK_SIZE);
	input = handler->create_istream(file_input, TRUE);

	test_assert(i_stream_get_size(input, FALSE, &stream_size) == 1);
	test_assert(stream_size == compressed_size);

	test_assert(i_stream_get_size(input, TRUE, &stream_size) == 1);
	test_assert(stream_size == uncompressed_size);

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
		i_stream_seek(input, 1);
		(void)i_stream_read(input);
		i_stream_seek(input, 0);
	}
	i_stream_destroy(&input);
	i_stream_destroy(&file_input);

	i_unlink(path);
	i_close_fd(&fd);

	test_end();
}

static void test_compression_handler_partial_parent_write(const struct compression_handler *handler)
{
	test_begin(t_strdup_printf("compression handler %s (partial parent writes)", handler->name));

	int ret;
	buffer_t *buffer = t_buffer_create(64);
	buffer_t *compressed_data = t_buffer_create(256);
	struct ostream *os = test_ostream_create_nonblocking(buffer, 64);
	struct ostream *os_compressed = handler->create_ostream(os, 9);
	o_stream_unref(&os);

	unsigned char input_buffer[256];
	/* create unlikely compressible data */
	random_fill(input_buffer, 64);

	for (unsigned int i = 0; i < 10; i++) {
		/* write it to stream */
		test_assert_idx(o_stream_send(os_compressed, input_buffer, sizeof(input_buffer)) == sizeof(input_buffer), i);

		while ((ret = o_stream_flush(os_compressed)) == 0) {
			/* flush buffer */
			if (buffer->used > 0)
				buffer_append(compressed_data, buffer->data, buffer->used);
			buffer_set_used_size(buffer, 0);
		}
		if (buffer->used > 0)
			buffer_append(compressed_data, buffer->data, buffer->used);
		buffer_set_used_size(buffer, 0);
		test_assert_idx(ret == 1, i);
	}
	test_assert(o_stream_finish(os_compressed) == 1);
	o_stream_unref(&os_compressed);
        if (buffer->used > 0)
                buffer_append(compressed_data, buffer->data, buffer->used);

	struct istream *is = test_istream_create_data(compressed_data->data, compressed_data->used);
	struct istream *is_decompressed = handler->create_istream(is, TRUE);
	i_stream_unref(&is);

	const unsigned char *data;
	size_t siz;
	buffer_t *decompressed_data = t_buffer_create(sizeof(input_buffer)*10);

	while(i_stream_read_more(is_decompressed, &data, &siz) > 0) {
		buffer_append(decompressed_data, data, siz);
		i_stream_skip(is_decompressed, siz);
	}
	test_assert(decompressed_data->used == sizeof(input_buffer)*10);
	for(siz = 0; siz < decompressed_data->used; siz+=sizeof(input_buffer)) {
		test_assert(decompressed_data->used - siz >= sizeof(input_buffer) &&
			   memcmp(CONST_PTR_OFFSET(decompressed_data->data, siz),
				  input_buffer, sizeof(input_buffer)) == 0);
	}

	i_stream_unref(&is_decompressed);

	test_end();
}

static void test_compression_handler_errors(const struct compression_handler *handler)
{
	test_begin(t_strdup_printf("compression handler %s (errors)", handler->name));

	/* test that zero stream reading errors out */
	struct istream *is = test_istream_create("");
	struct istream *input = handler->create_istream(is, FALSE);
	i_stream_unref(&is);
	test_assert(i_stream_read(input) == -1 && input->eof);
	i_stream_unref(&input);

	/* test that garbage isn't considered valid */
	is = test_istream_create("dedededededededededededededede"
				 "dedededeededdedededededededede"
				 "dedededededededededededededede");
	input = handler->create_istream(is, FALSE);
	i_stream_unref(&is);
	test_assert(i_stream_read(input) == -1 && input->eof);
	i_stream_unref(&input);

	/* test that truncated data is not considered valid */
	buffer_t *odata = buffer_create_dynamic(pool_datastack_create(), 65535);
	unsigned char buf[IO_BLOCK_SIZE];
	struct ostream *os = test_ostream_create(odata);
	struct ostream *output = handler->create_ostream(os, 1);
	o_stream_unref(&os);

	for (unsigned int i = 0; i < 10; i++) {
		random_fill(buf, sizeof(buf));
		test_assert(o_stream_send(output, buf, sizeof(buf)) == sizeof(buf));
	}

	test_assert(o_stream_finish(output) == 1);
	o_stream_unref(&output);

	/* truncate buffer */
	is = test_istream_create_data(odata->data, odata->used - sizeof(buf)*2 - 1);
	input = handler->create_istream(is, FALSE);
	i_stream_unref(&is);

	const unsigned char *data ATTR_UNUSED;
	size_t size;
	while (i_stream_read_more(input, &data, &size) > 0)
		i_stream_skip(input, size);

	test_assert(input->stream_errno == EPIPE);
	i_stream_unref(&input);

	test_end();
}

static void test_compression(void)
{
	unsigned int i;

	for (i = 0; compression_handlers[i].name != NULL; i++) {
		if (compression_handlers[i].create_istream != NULL) T_BEGIN {
			test_compression_handler_short(&compression_handlers[i]);
			test_compression_handler(&compression_handlers[i]);
			if (compression_handlers[i].is_compressed != NULL)
				test_compression_handler_detect(&compression_handlers[i]);
			test_compression_handler_seek(&compression_handlers[i]);
			test_compression_handler_reset(&compression_handlers[i]);
			test_compression_handler_partial_parent_write(&compression_handlers[i]);
			test_compression_handler_errors(&compression_handlers[i]);
		} T_END;
	}
}

static void test_gz(const char *str1, const char *str2)
{
	const struct compression_handler *gz = compression_lookup_handler("gz");
	struct ostream *buf_output, *output;
	struct istream *test_input, *input;
	buffer_t *buf = t_buffer_create(512);

	if (gz == NULL || gz->create_ostream == NULL)
		return; /* not compiled in */

	/* write concated output */
	buf_output = o_stream_create_buffer(buf);
	o_stream_set_finish_via_child(buf_output, FALSE);

	output = gz->create_ostream(buf_output, 6);
	o_stream_nsend_str(output, str1);
	test_assert(o_stream_finish(output) > 0);
	o_stream_destroy(&output);

	if (str2[0] != '\0') {
		output = gz->create_ostream(buf_output, 6);
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
	input = gz->create_istream(test_input, TRUE);
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

static void test_gz_concat(void)
{
	test_begin("gz concat");
	test_gz("hello", "world");
	test_end();
}

static void test_gz_no_concat(void)
{
	test_begin("gz no concat");
	test_gz("hello", "");
	test_end();
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
	input = gz->create_istream(file_input, TRUE);
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
	input = handler->create_istream(file_input, TRUE);
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
		test_gz_concat,
		test_gz_no_concat,
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
