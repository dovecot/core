/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

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

static void test_message_part_attachment_detection(const char test_name[],
    const char input_msg_part[], bool is_expected_attachment)
{
	const struct message_parser_settings parser_set = {
		.max_total_mime_parts = 2,
	};
    const struct message_part_attachment_settings set_attachment_settings = {
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

	test_assert(message_part_is_attachment(part, &set_attachment_settings) == is_expected_attachment);

	i_stream_unref(&input);
	pool_unref(&pool);

	test_end();
}

static void test_message_inline_with_filename(void)
{
    const char test_name_filename_star[] = "attachment detection disposition inline with filename*";
    const char input_msg_part_inline_att_with_filename_star[] =
        "Content-Disposition: inline;filename*=\"foo.bar\"\n"
        "Content-Type: foo/bar;\n"
        "\n"
        "xxxdata\n";

    const char test_name_filename[] = "attachment detection disposition inline with filename";
    const char input_msg_part_inline_att_with_filename[] =
        "Content-Disposition: inline;filename=\"foo.bar\"\n"
        "Content-Type: foo/bar;\n"
        "\n"
        "xxxdata\n";

    test_message_part_attachment_detection(test_name_filename_star,
        input_msg_part_inline_att_with_filename_star, TRUE);
    test_message_part_attachment_detection(test_name_filename,
        input_msg_part_inline_att_with_filename, TRUE);
}

static void test_message_inline_without_filename(void)
{
    const char test_name[] = "attachment detection disposition inline without filename";
    const char input_msg_part[] =
        "Content-Disposition: inline;\n"
        "Content-Type: foo/bar;\n"
        "\n"
        "xxxdata\n";

    test_message_part_attachment_detection(test_name, input_msg_part, FALSE);
}

static void test_message_attachment_without_filename(void)
{
    const char test_name[] = "attachment detection disposition attachment without filename";
    const char input_msg_part[] =
        "Content-Disposition: attachment;\n"
        "Content-Type: foo/bar;\n"
        "\n"
        "xxxdata\n";

    test_message_part_attachment_detection(test_name, input_msg_part, TRUE);
}

static void test_message_attachment_with_filename(void)
{
    const char test_name[] = "attachment detection disposition attachment with filename";
    const char input_msg_part[] =
        "Content-Disposition: attachment;filename=\"foo.bar\"\n"
        "Content-Type: foo/bar;\n"
        "\n"
        "xxxdata\n";

    test_message_part_attachment_detection(test_name, input_msg_part, TRUE);
}

static void test_message_without_attachment(void)
{
    const char test_name[] = "attachment detection not attachment";
    const char input_msg_part[] =
        "Content-Type: foo/bar;\n"
        "\n"
        "xxxdata\n";

    test_message_part_attachment_detection(test_name, input_msg_part, FALSE);
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_inline_with_filename,
		test_message_inline_without_filename,
		test_message_attachment_without_filename,
		test_message_attachment_with_filename,
		test_message_without_attachment,
		NULL
	};
	return test_run(test_functions);
}
