/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
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

static const char mail_input[] =
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
"\r\n--bound\r\n"
"Content-Type: text/plain\r\n"
"\r\n"
"hello world\r\n"
"\r\n--bound--\r\n";

static const char mail_output[] =
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
"\r\n--bound\r\n"
"Content-Type: text/plain\r\n"
"\r\n"
"hello world\r\n"
"\r\n--bound--\r\n";

static void test_istream_binary_converter(void)
{
	struct istream *datainput, *input;
	const unsigned char *data;
	size_t i, size;
	int ret;

	test_begin("istream binary converter");
	datainput = test_istream_create_data(mail_input, sizeof(mail_input));
	test_istream_set_allow_eof(datainput, FALSE);
	input = i_stream_create_binary_converter(datainput);

	for (i = 1; i <= sizeof(mail_input); i++) {
		test_istream_set_size(datainput, i);
		while ((ret = i_stream_read(input)) > 0) ;
		test_assert(ret == 0);
	}
	test_istream_set_allow_eof(datainput, TRUE);
	while ((ret = i_stream_read(input)) > 0) ;
	test_assert(ret == -1);

	data = i_stream_get_data(input, &size);
	test_assert(size == sizeof(mail_output) &&
		    memcmp(data, mail_output, size) == 0);
	i_stream_unref(&input);
	i_stream_unref(&datainput);
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
		test_istream_binary_converter,
		NULL
	};
	if (argc > 1)
		return test_input_file(argv[1]);
	else
		return test_run(test_functions);
}
