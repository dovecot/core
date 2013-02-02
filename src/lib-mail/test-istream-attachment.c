/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "sha1.h"
#include "hash-format.h"
#include "safe-mkstemp.h"
#include "istream.h"
#include "istream-crlf.h"
#include "istream-attachment-extractor.h"
#include "istream-attachment-connector.h"
#include "ostream.h"
#include "test-common.h"

#include <stdio.h>
#include <unistd.h>

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
"Content-Transfer-Encoding: base64\r\n"
"Content-Type: text/plain\r\n"
"\r\n"
BINARY_TEXT_LONG_BASE64
"\r\n--bound\r\n"
"Content-Type: text/plain\r\n"
"Content-Transfer-Encoding: base64\r\n"
"\r\n"
BINARY_TEXT_SHORT_BASE64
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
"\r\n--bound\r\n"
"Content-Type: text/plain\r\n"
"Content-Transfer-Encoding: base64\r\n"
"\r\n"
"\r\n--bound--\r\n";

struct attachment {
	size_t buffer_offset;
	uoff_t start_offset;
	uoff_t encoded_size, decoded_size;
	unsigned int base64_blocks_per_line;
};

static buffer_t *attachment_data;
static ARRAY(struct attachment) attachments;

static int test_open_temp_fd(void *context ATTR_UNUSED)
{
	string_t *str = t_str_new(128);
	int fd;

	str_append(str, "/tmp/dovecot-test.");
	fd = safe_mkstemp(str, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1)
		i_fatal("safe_mkstemp(%s) failed: %m", str_c(str));
	(void)unlink(str_c(str));
	return fd;
}

static int test_open_attachment_ostream(struct istream_attachment_info *info,
					struct ostream **output_r,
					void *context ATTR_UNUSED)
{
	struct attachment *a;

	if (attachment_data == NULL)
		attachment_data = buffer_create_dynamic(default_pool, 1024);
	if (!array_is_created(&attachments))
		i_array_init(&attachments, 8);
	a = array_append_space(&attachments);
	a->buffer_offset = attachment_data->used;
	a->start_offset = info->start_offset;
	a->encoded_size = info->encoded_size;
	a->base64_blocks_per_line = info->base64_blocks_per_line;
	test_assert(strlen(info->hash) == 160/8*2); /* sha1 size */

	*output_r = o_stream_create_buffer(attachment_data);
	if (o_stream_seek(*output_r, a->buffer_offset) < 0)
		i_unreached();
	return 0;
}

static int test_close_attachment_ostream(struct ostream *output, bool success,
					 void *context ATTR_UNUSED)
{
	struct attachment *a;

	i_assert(success);

	a = array_idx_modifiable(&attachments, array_count(&attachments)-1);
	a->decoded_size = output->offset - a->buffer_offset;

	if (o_stream_nfinish(output) < 0)
		i_unreached();
	o_stream_destroy(&output);
	return 0;
}

static struct istream *
test_build_original_istream(struct istream *base_input, uoff_t msg_size)
{
	struct istream_attachment_connector *conn;
	const unsigned char *data = attachment_data->data;
	const struct attachment *a;
	struct istream *input;
	uoff_t data_size = attachment_data->used;
	const char *error;

	conn = istream_attachment_connector_begin(base_input, msg_size);
	array_foreach(&attachments, a) {
		input = i_stream_create_from_data(data, a->decoded_size);
		if (istream_attachment_connector_add(conn, input,
				a->start_offset, a->encoded_size,
				a->base64_blocks_per_line, TRUE, &error) < 0)
			i_unreached();
		i_stream_unref(&input);

		i_assert(a->decoded_size <= data_size);
		data += a->decoded_size;
		data_size -= a->decoded_size;
	}
	i_assert(data_size == 0);
	return istream_attachment_connector_finish(&conn);
}

static void
get_istream_attachment_settings(struct istream_attachment_settings *set_r)
{
	const char *error;

	memset(set_r, 0, sizeof(*set_r));
	set_r->min_size = 1;
	set_r->drain_parent_input = TRUE;
	set_r->open_temp_fd = test_open_temp_fd;
	set_r->open_attachment_ostream = test_open_attachment_ostream;
	set_r->close_attachment_ostream= test_close_attachment_ostream;
	if (hash_format_init("%{sha1}", &set_r->hash_format, &error) < 0)
		i_unreached();
}

static int test_input_stream(struct istream *file_input)
{
	struct istream_attachment_settings set;
	struct istream *input, *input2;
	const unsigned char *data;
	size_t size;
	struct sha1_ctxt hash;
	uoff_t msg_size;
	buffer_t *base_buf;
	unsigned char hash_file[SHA1_RESULTLEN], hash_attached[SHA1_RESULTLEN];
	int ret = 0;

	/* get hash when directly reading input */
	input = i_stream_create_crlf(file_input);
	sha1_init(&hash);
	while (i_stream_read_data(input, &data, &size, 0) > 0) {
		sha1_loop(&hash, data, size);
		i_stream_skip(input, size);
	}
	sha1_result(&hash, hash_file);
	msg_size = input->v_offset;
	i_stream_unref(&input);

	/* read through attachment extractor */
	get_istream_attachment_settings(&set);

	i_stream_seek(file_input, 0);
	input = i_stream_create_crlf(file_input);
	input2 = i_stream_create_attachment_extractor(input, &set, NULL);
	i_stream_unref(&input);
	base_buf = buffer_create_dynamic(default_pool, 1024);
	while (i_stream_read_data(input2, &data, &size, 0) > 0) {
		buffer_append(base_buf, data, size);
		i_stream_skip(input2, size);
	}
	i_stream_unref(&input2);

	/* rebuild the original stream and see if the hash matches */
	input2 = i_stream_create_from_data(base_buf->data, base_buf->used);
	input = test_build_original_istream(input2, msg_size);
	i_stream_unref(&input2);

	sha1_init(&hash);
	while (i_stream_read_data(input, &data, &size, 0) > 0) {
		sha1_loop(&hash, data, size);
		i_stream_skip(input, size);
	}
	sha1_result(&hash, hash_attached);
	i_stream_unref(&input);

	ret = memcmp(hash_file, hash_attached, SHA1_RESULTLEN) == 0 ? 0 : -1;

	i_stream_unref(&file_input);
	buffer_free(&base_buf);
	if (attachment_data != NULL)
		buffer_free(&attachment_data);
	if (array_is_created(&attachments))
		array_free(&attachments);
	return ret;
}

static void test_istream_attachment(void)
{
	struct istream_attachment_settings set;
	struct istream *datainput, *input;
	const unsigned char *data;
	size_t i, size;
	int ret;

	test_begin("istream attachment");
	datainput = test_istream_create_data(mail_input, sizeof(mail_input));
	test_istream_set_allow_eof(datainput, FALSE);

	get_istream_attachment_settings(&set);
	input = i_stream_create_attachment_extractor(datainput, &set, NULL);

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

	data = attachment_data->data;
	test_assert(attachment_data->used ==
		    sizeof(BINARY_TEXT_LONG)-1 + strlen(BINARY_TEXT_SHORT));
	test_assert(memcmp(data, BINARY_TEXT_LONG, sizeof(BINARY_TEXT_LONG)-1) == 0);
	test_assert(memcmp(data + sizeof(BINARY_TEXT_LONG)-1,
			   BINARY_TEXT_SHORT, strlen(BINARY_TEXT_SHORT)) == 0);
	i_stream_unref(&input);
	i_stream_unref(&datainput);
	test_end();
}

static int test_input_file(const char *path)
{
	struct istream *file_input;
	int ret = 0;

	lib_init();

	file_input = i_stream_create_file(path, 64);
	if (test_input_stream(file_input) < 0) {
		fprintf(stderr, "istream-attachment-extractor: mismatch on file %s\n",
			path);
		ret = -1;
	}
	i_stream_unref(&file_input);

	lib_deinit();
	return ret;
}

int main(int argc, char *argv[])
{
	static void (*test_functions[])(void) = {
		test_istream_attachment,
		NULL
	};
	if (argc > 1)
		return test_input_file(argv[1]) < 0 ? 1 : 0;
	else
		return test_run(test_functions);
}
