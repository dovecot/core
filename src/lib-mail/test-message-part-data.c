/* Copyright (c) 2023-2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "message-parser.h"
#include "message-part-data.h"
#include "test-common.h"

static int message_parse_stream(pool_t pool, struct istream *input,
				const struct message_parser_settings *set,
				bool parse_data, struct message_part **parts_r)
{
	int ret;
	struct message_parser_ctx *parser;
	struct message_block block;

	i_zero(&block);
	parser = message_parser_init(pool, input, set);
	while ((ret = message_parser_parse_next_block(parser, &block)) > 0)
		if (parse_data)
			message_part_data_parse_from_header(pool, block.part,
							    block.hdr);
	message_parser_deinit(&parser, parts_r);
	test_assert(input->stream_errno == 0);
	return ret;
}

static void test_message_part_attachment(const char test_name[],
					 const char input_msg_part[],
					 bool expected_is_attach,
					 const char *expected_filename)
{
	const struct message_parser_settings parser_set = {
		.max_total_mime_parts = 2,
	};
	const struct message_part_attachment_settings attach_settings = {
		.content_type_filter = NULL,
		.exclude_inlined = FALSE,
	};
	struct istream *input;
	struct message_part *parts, *part;
	pool_t pool;

	test_begin(test_name);

	pool = pool_alloconly_create("message parser", 10240);
	input = test_istream_create(input_msg_part);

	message_parse_stream(pool, input, &parser_set, TRUE, &parts);
	part = parts;

	bool actual_is_attach = message_part_is_attachment(part, &attach_settings);
	test_assert(actual_is_attach == expected_is_attach);

	if (actual_is_attach != expected_is_attach)
		i_debug("Expected %s, got %s\n",
			expected_is_attach ? "TRUE" : "FALSE",
			actual_is_attach ? "TRUE" : "FALSE");

	if (actual_is_attach) {
		const char *actual_filename = NULL;
		bool actual_filename_is_attach = message_part_data_get_filename(
			part, &actual_filename);
		test_assert(actual_filename_is_attach == expected_is_attach);
		test_assert_strcmp(actual_filename, expected_filename);
	}

	i_stream_unref(&input);
	pool_unref(&pool);

	test_end();
}

static void test_message_inline_with_cd_filename_star(void)
{
	const char test_name[] =
		"attachment detection disposition inline with filename*";
	const char input[] =
		"Content-Disposition: inline;filename*=\"foo.bar\"\n"
		"Content-Type: foo/bar;\n"
		"\n"
		"xxxdata\n";

	test_message_part_attachment(test_name, input, TRUE, "foo.bar");
}

static void test_message_inline_with_cd_filename(void)
{
	const char test_name[] =
		"attachment detection disposition inline with filename";
	const char input[] =
		"Content-Disposition: inline;filename=\"foo.bar\"\n"
		"Content-Type: foo/bar;\n"
		"\n"
		"xxxdata\n";

	test_message_part_attachment(test_name, input, TRUE, "foo.bar");
}

static void test_message_inline_with_ct_name_star(void)
{
	const char test_name[] =
		"attachment detection disposition inline with filename*";
	const char input[] =
		"Content-Disposition: inline;\n"
		"Content-Type: foo/bar;name*=\"foo.bar\"\n"
		"\n"
		"xxxdata\n";

	test_message_part_attachment(test_name, input, TRUE, "foo.bar");
}

static void test_message_inline_with_ct_name(void)
{
	const char test_name[] =
		"attachment detection disposition inline with filename";
	const char input[] =
		"Content-Disposition: inline;\n"
		"Content-Type: foo/bar;name=\"foo.bar\"\n"
		"\n"
		"xxxdata\n";

	test_message_part_attachment(test_name, input, TRUE, "foo.bar");
}

static void test_message_inline_without_filename(void)
{
	const char test_name[] =
		"attachment detection disposition inline without filename";
	const char input[] =
		"Content-Disposition: inline;\n"
		"Content-Type: foo/bar;\n"
		"\n"
		"xxxdata\n";

	test_message_part_attachment(test_name, input, FALSE, NULL);
}

static void test_message_attachment_without_filename(void)
{
	const char test_name[] =
		"attachment detection disposition attachment without filename";
	const char input[] =
		"Content-Disposition: attachment;\n"
		"Content-Type: foo/bar;\n"
		"\n"
		"xxxdata\n";

	test_message_part_attachment(test_name, input, TRUE, NULL);
}

static void test_message_attachment_with_cd_filename_star(void)
{
	const char test_name[] =
		"attachment detection disposition attachment with filename*";
	const char input[] =
		"Content-Disposition: attachment;filename*=\"foo.bar\"\n"
		"Content-Type: foo/bar;\n"
		"\n"
		"xxxdata\n";

	test_message_part_attachment(test_name, input, TRUE, "foo.bar");
}


static void test_message_attachment_with_cd_filename(void)
{
	const char test_name[] =
		"attachment detection disposition attachment with filename";
	const char input[] =
		"Content-Disposition: attachment;filename=\"foo.bar\"\n"
		"Content-Type: foo/bar;\n"
		"\n"
		"xxxdata\n";

	test_message_part_attachment(test_name, input, TRUE, "foo.bar");
}

static void test_message_without_attachment(void)
{
	const char test_name[] = "attachment detection not attachment";
	const char input[] =
		"Content-Type: foo/bar;\n"
		"\n"
		"xxxdata\n";

	test_message_part_attachment(test_name, input, FALSE, NULL);
}

static void test_message_attachment_with_ct_name(void)
{
	const char test_name[] =
		"attachment detection disposition attachment with file";
	const char input[] =
		"Content-Type: application/octet-stream; name=\"foo.pdf\"\n"
		"Content-Disposition: attachment\n"
		"Content-Transfer-Encoding: base64\n"
		"\n"
		"xxxdata\n";

	test_message_part_attachment(test_name, input, TRUE, "foo.pdf");
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_without_attachment,
		test_message_inline_with_ct_name,
		test_message_attachment_with_ct_name,
		test_message_inline_with_cd_filename,
		test_message_inline_without_filename,
		test_message_inline_with_ct_name_star,
		test_message_attachment_with_cd_filename,
		test_message_attachment_without_filename,
		test_message_inline_with_cd_filename_star,
		test_message_attachment_with_cd_filename_star,
		NULL
	};
	return test_run(test_functions);
}
