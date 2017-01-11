/* Copyright (c) 2007-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "base64.h"
#include "buffer.h"
#include "str.h"
#include "sha1.h"
#include "istream.h"
#include "istream-crlf.h"
#include "istream-binary-converter.h"
#include "test-common.h"

#include <stdio.h>

#define BINARY_TEXT_LONG "we have\ra lot \nof \0binary stuff in here\n" \
"b adjig sadjg jasidgjiaehga3wht8a3w8ghxjc dsgad hasdghsd gasd ds" \
"jdsoga sjdga0w3tjhawjgsertniq3n5oqerjqw2r89q23h awhrqh835r8a"
#define BINARY_TEXT_LONG_BASE64 \
"d2UgaGF2ZQ1hIGxvdCAKb2YgAGJpbmFyeSBzdHVmZiBpbiBoZXJlCmIgYWRqaWcgc2FkamcgamFz\r\n" \
"aWRnamlhZWhnYTN3aHQ4YTN3OGdoeGpjIGRzZ2FkIGhhc2RnaHNkIGdhc2QgZHNqZHNvZ2Egc2pk\r\n" \
"Z2EwdzN0amhhd2pnc2VydG5pcTNuNW9xZXJqcXcycjg5cTIzaCBhd2hycWg4MzVyOGE="

#define BINARY_TEXT_SHORT "eh"
#define BINARY_TEXT_SHORT_BASE64 "ZWg="

static const char mail_input_mime[] =
"MIME-Version: 1.0\r\n"
"Content-Type: multipart/alternative;\r\n boundary=\"bound\"\r\n"
"\r\n"
"mime header\r\n"
"\r\n--bound\r\n"
"Content-Transfer-Encoding: binary\r\n"
"Content-Type: text/plain\r\n"
"\r\n"
BINARY_TEXT_LONG
"\r\n--bound\r\n"
"Content-Type: text/plain\r\n"
"Content-Transfer-Encoding: binary\r\n"
"\r\n"
BINARY_TEXT_SHORT
"\n--bound\r\n"
"Content-Type: text/plain\r\n"
"\r\n"
"hello world\r\n"
"\r\n--bound--\r\n";

static const char mail_output_mime[] =
"MIME-Version: 1.0\r\n"
"Content-Type: multipart/alternative;\r\n boundary=\"bound\"\r\n"
"\r\n"
"mime header\r\n"
"\r\n--bound\r\n"
"Content-Transfer-Encoding: base64\r\n"
"Content-Type: text/plain\r\n"
"\r\n"
BINARY_TEXT_LONG_BASE64
"\r\n--bound\r\n"
"Content-Type: text/plain\r\n"
"Content-Transfer-Encoding: base64\r\n"
"\r\n"
BINARY_TEXT_SHORT_BASE64
"\n--bound\r\n"
"Content-Type: text/plain\r\n"
"\r\n"
"hello world\r\n"
"\r\n--bound--\r\n";

static const char mail_input_root_hdr[] =
"MIME-Version: 1.0\r\n"
"Content-Transfer-Encoding: binary\r\n"
"Content-Type: text/plain\r\n"
"\r\n";

static const char mail_output_root_hdr[] =
"MIME-Version: 1.0\r\n"
"Content-Transfer-Encoding: base64\r\n"
"Content-Type: text/plain\r\n"
"\r\n";

static const char mail_root_nonbinary[] =
"MIME-Version: 1.0\r\n"
"Content-Type: text/plain\r\n"
"\r\n"
"hello\n\n";

static void
test_istream_binary_converter_test(const char *mail_input, unsigned int mail_input_len,
				   const char *mail_output, unsigned int mail_output_len,
				   unsigned int idx)
{
	struct istream *datainput, *input;
	const unsigned char *data;
	size_t i, size;
	int ret;

	datainput = test_istream_create_data(mail_input, mail_input_len);
	test_istream_set_allow_eof(datainput, FALSE);
	input = i_stream_create_binary_converter(datainput);

	for (i = 1; i <= mail_input_len; i++) {
		test_istream_set_size(datainput, i);
		while ((ret = i_stream_read(input)) > 0) ;
		test_assert_idx(ret == 0, idx);
	}
	test_istream_set_allow_eof(datainput, TRUE);
	while ((ret = i_stream_read(input)) > 0) ;
	test_assert_idx(ret == -1, idx);

	data = i_stream_get_data(input, &size);
	test_assert_idx(size == mail_output_len &&
			memcmp(data, mail_output, size) == 0, idx);
	i_stream_unref(&input);
	i_stream_unref(&datainput);
}

static void test_istream_binary_converter_mime(void)
{
	test_begin("istream binary converter in mime parts");
	test_istream_binary_converter_test(mail_input_mime, sizeof(mail_input_mime)-1,
					   mail_output_mime, sizeof(mail_output_mime)-1, 0);
	test_end();
}

static void test_istream_binary_converter_root(void)
{
	buffer_t *inbuf = buffer_create_dynamic(pool_datastack_create(), 512);
	buffer_t *outbuf = buffer_create_dynamic(pool_datastack_create(), 512);
	const char *const suffixes[] = { "\n", "\r\n", "\n\r\n\n\n" };
	unsigned int i;
	unsigned int input_hdr_len = sizeof(mail_input_root_hdr)-1;

	test_begin("istream binary converter in root");
	buffer_append(inbuf, mail_input_root_hdr, input_hdr_len);
	buffer_append(outbuf, mail_output_root_hdr, sizeof(mail_output_root_hdr)-1);
	for (i = 0; i < N_ELEMENTS(suffixes); i++) {
		buffer_set_used_size(inbuf, input_hdr_len);
		buffer_set_used_size(outbuf, sizeof(mail_output_root_hdr)-1);
		buffer_append(inbuf, BINARY_TEXT_SHORT, sizeof(BINARY_TEXT_SHORT)-1);
		buffer_append(inbuf, suffixes[i], strlen(suffixes[i]));
		base64_encode(CONST_PTR_OFFSET(inbuf->data, input_hdr_len),
			      inbuf->used - input_hdr_len, outbuf);
		test_istream_binary_converter_test(inbuf->data, inbuf->used,
						   outbuf->data, outbuf->used, i);
	}
	test_end();
}

static void test_istream_binary_converter_root_nonbinary(void)
{
	test_begin("istream binary converter in root having non-binary");
	test_istream_binary_converter_test(mail_root_nonbinary, sizeof(mail_root_nonbinary)-1,
					   mail_root_nonbinary, sizeof(mail_root_nonbinary)-1, 0);
	test_end();
}

static int test_input_file(const char *path)
{
	struct istream *file_input, *input, *input2;
	const unsigned char *data;
	size_t size;
	struct sha1_ctxt hash;
	unsigned char hash_file[SHA1_RESULTLEN], hash_converter[SHA1_RESULTLEN];
	int ret = 0;

	lib_init();

	file_input = i_stream_create_file(path, 64);
	
	/* get hash when directly reading input */
	input = i_stream_create_crlf(file_input);
	sha1_init(&hash);
	while (i_stream_read_data(input, &data, &size, 0) > 0) {
		sha1_loop(&hash, data, size);
		i_stream_skip(input, size);
	}
	sha1_result(&hash, hash_file);
	i_stream_unref(&input);

	/* get hash when going through converter */
	i_stream_seek(file_input, 0);
	input = i_stream_create_crlf(file_input);
	input2 = i_stream_create_binary_converter(input);
	sha1_init(&hash);
	while (i_stream_read_data(input2, &data, &size, 0) > 0) {
		sha1_loop(&hash, data, size);
		i_stream_skip(input2, size);
	}
	sha1_result(&hash, hash_converter);
	i_stream_unref(&input2);
	i_stream_unref(&input);

	if (memcmp(hash_file, hash_converter, SHA1_RESULTLEN) != 0) {
		fprintf(stderr, "istream-binary-converter: mismatch on file %s\n",
			path);
		ret = 1;
	}

	i_stream_unref(&file_input);
	lib_deinit();
	return ret;
}

int main(int argc, char *argv[])
{
	static void (*test_functions[])(void) = {
		test_istream_binary_converter_mime,
		test_istream_binary_converter_root,
		test_istream_binary_converter_root_nonbinary,
		NULL
	};
	if (argc > 1)
		return test_input_file(argv[1]);
	else
		return test_run(test_functions);
}
