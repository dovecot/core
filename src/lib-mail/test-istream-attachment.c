/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

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

static const char *mail_broken_input_body_prefix =
"MIME-Version: 1.0\r\n"
"Content-Type: multipart/alternative;\r\n boundary=\"bound\"\r\n"
"\r\n"
"--bound\r\n"
"Content-Transfer-Encoding: base64\r\n"
"Content-Type: text/plain\r\n"
"\r\n";

static const char *mail_broken_input_bodies[] = {
	/* broken base64 input */
	"Zm9vCg=\n",
	"Zm9vCg\n",
	"Zm9vC\n",
	/* extra whitespace */
	"Zm9v\n Zm9v\n",
	"Zm9v \nZm9v\n",
	/* mixed LF vs CRLFs */
	"Zm9vYmFy\r\nZm9vYmFy\n",
	"Zm9vYmFy\nZm9vYmFy\r\n",
	/* line length increases */
	"Zm9v\nZm9vYmFy\n",
	"Zm9v\nZm9vCg==",
	"Zm9v\nZm9vYgo="
};

static const char *mail_nonbroken_input_bodies[] = {
	/* suffixes with explicit '=' end */
	"Zm9vCg==",
	"Zm9vCg==\n",
	"Zm9vCg==\r\n",
	"Zm9vCg==\nfoo\n",
	"Zm9vCg==\r\nfoo\n",
	"Zm9vCg==  \t\t\n\n",
	/* suffixes with shorter line length */
	"Zm9vYmFy\nZm9v\n",
	"Zm9vYmFy\r\nZm9v\r\n",
	"Zm9vYmFy\nZm9v\nfoo\n",
	"Zm9vYmFy\r\nZm9v\r\nfoo\n",
	"Zm9vYmFy\nZm9v\n  \t\t\n\n",
	/* suffixes with empty line */
	"Zm9v\n\n",
	"Zm9v\r\n\r\n",
	"Zm9v\n\nfoo\n"
	"Zm9v\r\n\nfoo\n"
	"Zm9v\r\n\r\nfoo\n"
#if 0
	/* the whitespace here could be handled as suffixes, but for now
	   they're not: */
	"Zm9v ",
	"Zm9v \n"
#endif
};

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
	i_unlink(str_c(str));
	return fd;
}

static int test_open_attachment_ostream(struct istream_attachment_info *info,
					struct ostream **output_r,
					const char **error_r ATTR_UNUSED,
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

static int
test_open_attachment_ostream_error(struct istream_attachment_info *info ATTR_UNUSED,
				   struct ostream **output_r ATTR_UNUSED,
				   const char **error_r,
				   void *context ATTR_UNUSED)
{
	*error_r = "test open error";
	return -1;
}

static int test_close_attachment_ostream(struct ostream *output, bool success,
					 const char **error_r ATTR_UNUSED,
					 void *context ATTR_UNUSED)
{
	struct attachment *a;

	i_assert(success);

	a = array_back_modifiable(&attachments);
	a->decoded_size = output->offset - a->buffer_offset;

	if (o_stream_finish(output) < 0)
		i_unreached();
	o_stream_destroy(&output);
	return 0;
}

static int
test_close_attachment_ostream_error(struct ostream *output,
				    bool success, const char **error,
				    void *context ATTR_UNUSED)
{
	if (success)
		*error = "test output error";
	o_stream_abort(output);
	o_stream_destroy(&output);
	return -1;
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

	i_zero(set_r);
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
	uoff_t msg_size, orig_msg_size;
	buffer_t *base_buf;
	unsigned char hash_file[SHA1_RESULTLEN], hash_attached[SHA1_RESULTLEN];
	int ret = 0;

	/* get hash when directly reading input */
	input = i_stream_create_crlf(file_input);
	sha1_init(&hash);
	while (i_stream_read_more(input, &data, &size) > 0) {
		sha1_loop(&hash, data, size);
		i_stream_skip(input, size);
	}
	sha1_result(&hash, hash_file);
	msg_size = orig_msg_size = input->v_offset;
	i_stream_unref(&input);

	/* read through attachment extractor */
	get_istream_attachment_settings(&set);

	i_stream_seek(file_input, 0);
	input = i_stream_create_crlf(file_input);
	input2 = i_stream_create_attachment_extractor(input, &set, NULL);
	i_stream_unref(&input);
	base_buf = buffer_create_dynamic(default_pool, 1024);
	while (i_stream_read_more(input2, &data, &size) > 0) {
		buffer_append(base_buf, data, size);
		i_stream_skip(input2, size);
	}
	i_stream_unref(&input2);

	/* rebuild the original stream and see if the hash matches */
	for (unsigned int i = 0; i < 2; i++) {
		input2 = i_stream_create_from_data(base_buf->data, base_buf->used);
		input = test_build_original_istream(input2, msg_size);
		i_stream_unref(&input2);

		sha1_init(&hash);
		while (i_stream_read_more(input, &data, &size) > 0) {
			sha1_loop(&hash, data, size);
			i_stream_skip(input, size);
		}
		test_assert_idx(input->eof && input->stream_errno == 0, i);
		sha1_result(&hash, hash_attached);
		i_stream_unref(&input);

		if (memcmp(hash_file, hash_attached, SHA1_RESULTLEN) != 0)
			ret = -1;

		/* try again without knowing the message's size */
		msg_size = (uoff_t)-1;
	}

	/* try with a wrong message size */
	for (int i = 0; i < 2; i++) {
		input2 = i_stream_create_from_data(base_buf->data, base_buf->used);
		input = test_build_original_istream(input2, orig_msg_size +
						    (i == 0 ? 1 : -1));
		i_stream_unref(&input2);
		while (i_stream_read_more(input, &data, &size) > 0)
			i_stream_skip(input, size);
		test_assert(input->stream_errno == (i == 0 ? EPIPE : EINVAL));
		i_stream_unref(&input);
	}

	buffer_free(&base_buf);
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

	buffer_free(&attachment_data);
	if (array_is_created(&attachments))
		array_free(&attachments);
	test_end();
}

static bool test_istream_attachment_extractor_one(const char *body, int err_type)
{
	const size_t prefix_len = strlen(mail_broken_input_body_prefix);
	struct istream_attachment_settings set;
	struct istream *datainput, *input;
	char *mail_text;
	const unsigned char *data;
	size_t size;
	int ret;
	bool unchanged;

	mail_text = i_strconcat(mail_broken_input_body_prefix, body, NULL);
	datainput = test_istream_create_data(mail_text, strlen(mail_text));

	get_istream_attachment_settings(&set);
	if (err_type == 1)
		set.open_attachment_ostream = test_open_attachment_ostream_error;
	else if (err_type == 2)
		set.close_attachment_ostream = test_close_attachment_ostream_error;
	input = i_stream_create_attachment_extractor(datainput, &set, NULL);

	while ((ret = i_stream_read(input)) > 0) ;
	if (err_type != 0) {
		test_assert(ret == -1 && input->stream_errno == EIO);
		unchanged = FALSE;
		goto cleanup;
	}
	test_assert(ret == -1 && input->stream_errno == 0);

	data = i_stream_get_data(input, &size);
	i_assert(size >= prefix_len &&
		 memcmp(data, mail_broken_input_body_prefix, prefix_len) == 0);
	data += prefix_len;
	size -= prefix_len;

	i_assert(attachment_data != NULL);
	unchanged = attachment_data->used <= strlen(body) &&
		memcmp(attachment_data->data, body, attachment_data->used) == 0 &&
		strlen(body) - attachment_data->used == size &&
		memcmp(data, body + attachment_data->used, size) == 0;

cleanup:
	buffer_free(&attachment_data);
	if (array_is_created(&attachments))
		array_free(&attachments);

	i_stream_unref(&input);
	i_stream_unref(&datainput);
	i_free(mail_text);
	return unchanged;
}

static void test_istream_attachment_extractor(void)
{
	unsigned int i;

	test_begin("istream attachment extractor");
	for (i = 0; i < N_ELEMENTS(mail_broken_input_bodies); i++)
		test_assert(test_istream_attachment_extractor_one(mail_broken_input_bodies[i], 0));
	for (i = 0; i < N_ELEMENTS(mail_nonbroken_input_bodies); i++)
		test_assert(!test_istream_attachment_extractor_one(mail_nonbroken_input_bodies[i], 0));
	test_end();
}

static void test_istream_attachment_extractor_error(void)
{
	unsigned int i;

	test_begin("istream attachment extractor error");
	for (int err_type = 1; err_type <= 2; err_type++) {
		for (i = 0; i < N_ELEMENTS(mail_broken_input_bodies); i++)
			test_istream_attachment_extractor_one(mail_broken_input_bodies[i], err_type);
		for (i = 0; i < N_ELEMENTS(mail_nonbroken_input_bodies); i++)
			test_istream_attachment_extractor_one(mail_nonbroken_input_bodies[i], err_type);
	}
	test_end();
}

static void test_istream_attachment_connector(void)
{
	struct istream *input;

	test_begin("istream attachment connector");
	input = i_stream_create_from_data(mail_input, sizeof(mail_input));
	test_assert(test_input_stream(input) == 0);
	i_stream_unref(&input);
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
	static void (*const test_functions[])(void) = {
		test_istream_attachment,
		test_istream_attachment_extractor,
		test_istream_attachment_extractor_error,
		test_istream_attachment_connector,
		NULL
	};
	if (argc > 1)
		return test_input_file(argv[1]) < 0 ? 1 : 0;
	else
		return test_run(test_functions);
}
