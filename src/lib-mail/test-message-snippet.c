/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "unichar.h"
#include "message-parser.h"
#include "message-snippet.h"
#include "test-common.h"

static const struct {
	const char *input;
	unsigned int max_snippet_chars;
	const char *output;
} tests[] = {
	{ "Content-Type: text/plain\n"
	  "\n"
	  "1234567890 234567890",
	  12,
	  "1234567890 2" },
	{ "Content-Type: text/plain\n"
	  "\n"
	  "line1\n>quote2\nline2\n",
	  100,
	  "line1 line2" },
	{ "Content-Type: text/plain\n"
	  "\n"
	  "line1\n>quote2\n> quote3\n > line4\n\n  \t\t  \nline5\n  \t ",
	  100,
	  "line1 > line4 line5" },
	{ "Content-Type: text/plain; charset=utf-8\n"
	  "\n"
	  "hyv\xC3\xA4\xC3\xA4 p\xC3\xA4iv\xC3\xA4\xC3\xA4",
	  11,
	  "hyv\xC3\xA4\xC3\xA4 p\xC3\xA4iv\xC3\xA4" },
	{ "Content-Type: text/plain; charset=utf-8\n"
	  "Content-Transfer-Encoding: quoted-printable\n"
	  "\n"
	  "hyv=C3=A4=C3=A4 p=C3=A4iv=C3=A4=C3=A4",
	  11,
	  "hyv\xC3\xA4\xC3\xA4 p\xC3\xA4iv\xC3\xA4" },

	{ "Content-Transfer-Encoding: quoted-printable\n"
	  "Content-Type: text/html;\n"
	  "      charset=utf-8\n"
	  "\n"
	  "<html><head><meta http-equiv=3D\"Content-Type\" content=3D\"text/html =\n"
	  "charset=3Dutf-8\"></head><body style=3D\"word-wrap: break-word; =\n"
	  "-webkit-nbsp-mode: space; -webkit-line-break: after-white-space;\" =\n"
	  "class=3D\"\">Hi,<div class=3D\"\"><br class=3D\"\"></div><div class=3D\"\">How =\n"
	  "is it going? <blockquote>quoted text is ignored</blockquote>\n"
	  "&gt; -foo\n"
	  "</div><br =class=3D\"\"></body></html>=\n",
	  100,
	  "Hi, How is it going?" },

	{ "Content-Transfer-Encoding: quoted-printable\n"
	  "Content-Type: application/xhtml+xml;\n"
	  "      charset=utf-8\n"
	  "\n"
	  "<html><head><meta http-equiv=3D\"Content-Type\" content=3D\"text/html =\n"
	  "charset=3Dutf-8\"></head><body style=3D\"word-wrap: break-word; =\n"
	  "-webkit-nbsp-mode: space; -webkit-line-break: after-white-space;\" =\n"
	  "class=3D\"\">Hi,<div class=3D\"\"><br class=3D\"\"></div><div class=3D\"\">How =\n"
	  "is it going? <blockquote>quoted text is ignored</blockquote>\n"
	  "&gt; -foo\n"
	  "</div><br =class=3D\"\"></body></html>=\n",
	  100,
	  "Hi, How is it going?" },
	{ "Content-Type: text/plain\n"
	  "\n"
	  ">quote1\n>quote2\n",
	  100,
	  ">quote1 quote2" },
	{ "Content-Type: text/plain\n"
	  "\n"
	  ">quote1\n>quote2\nbottom\nposter\n",
	  100,
	  "bottom poster" },
	{ "Content-Type: text/plain\n"
	  "\n"
	  "top\nposter\n>quote1\n>quote2\n",
	  100,
	  "top poster" },
	{ "Content-Type: text/plain\n"
	  "\n"
	  ">quoted long text",
	  7,
	  ">quoted" },
	{ "Content-Type: text/plain\n"
	  "\n"
	  ">quoted long text",
	  8,
	  ">quoted" },
	{ "Content-Type: text/plain\n"
	  "\n"
	  "whitespace and more",
	  10,
	  "whitespace" },
	{ "Content-Type: text/plain\n"
	  "\n"
	  "whitespace and more",
	  11,
	  "whitespace" },
	{ "Content-Type: text/plain; charset=utf-8\n"
	  "\n"
	  "Invalid utf8 \x80\xff\n",
	  100,
	  "Invalid utf8 "UNICODE_REPLACEMENT_CHAR_UTF8 },
	{ "Content-Type: text/plain; charset=utf-8\n"
	  "\n"
	  "Incomplete utf8 \xC3",
	  100,
	  "Incomplete utf8" },
	{ "Content-Transfer-Encoding: quoted-printable\n"
	  "Content-Type: text/html;\n"
	  "      charset=utf-8\n"
	  "\n"
	  "<html><head><meta http-equiv=3D\"Content-Type\" content=3D\"text/html =\n"
	  "charset=3Dutf-8\"></head><body style=3D\"word-wrap: break-word; =\n"
	  "-webkit-nbsp-mode: space; -webkit-line-break: after-white-space;\" =\n"
	  "class=3D\"\"><div><blockquote>quoted text is included</blockquote>\n"
	  "</div><br =class=3D\"\"></body></html>=\n",
	  100,
	  ">quoted text is included" },
	{ "Content-Type: text/plain; charset=utf-8\n"
	 "\n"
	 "I think\n",
	 100,
	 "I think"
	},
	{ "Content-Type: text/plain; charset=utf-8\n"
	 "\n"
	 "  Lorem Ipsum\n",
	 100,
	 "Lorem Ipsum"
	},
	{ "Content-Type: text/plain; charset=utf-8\n"
	 "\n"
	 " I think\n",
	 100,
	 "I think"
	},
	{ "Content-Type: text/plain; charset=utf-8\n"
	 "\n"
	 "   A cat\n",
	 100,
	 "A cat"
	},
	{ "Content-Type: text/plain; charset=utf-8\n"
	 "\n"
	 " \n",
	 100,
	 ""
	},
	{ "MIME-Version: 1.0\n"
	 "Content-Type: multipart/mixed; boundary=a\n"
	 "\n--a\n"
	 "Content-Transfer-Encoding: 7bit\n"
	 "Content-Type: text/html; charset=utf-8\n\n"
	 "<html><head></head><body><p>part one</p></body></head>\n"
	 "\n--a\n"
	 "Content-Transfer-Encoding: 7bit\n"
	 "Content-Type: text/html; charset=utf-8\n\n"
	 "<html><head></head><body><p>part two</p></body></head>\n"
	 "\n--a--\n",
	 100,
	 "part one"
	},
	{ "MIME-Version: 1.0\n"
	 "Content-Type: multipart/alternative; boundary=a\n"
	 "\n--a\n"
	 "Content-Transfer-Encoding: 7bit\n"
	 "Content-Type: text/html; charset=utf-8\n\n"
	 "<html><head></head><body><p>part one</p></body></head>\n"
	 "\n--a\n"
	 "Content-Transfer-Encoding: 7bit\n"
	 "Content-Type: text/plain; charset=utf-8\n\n"
	 "part two\n"
	 "\n--a--\n",
	 100,
	 "part one"
	},
	{ "MIME-Version: 1.0\n"
	  "Content-Type: multipart/mixed; boundary=a\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: 7bit\n"
	  "Content-Type: text/html; charset=utf-8\n\n"
	  "<html><head></head><body><div><p></p><!-- comment --></body></head>\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: 7bit\n"
	  "Content-Type: text/html; charset=utf-8\n\n"
	  "<html><head></head><body><p>part two</p></body></head>\n"
	  "\n--a--\n",
	  100,
	  "part two"
	},
	{ "MIME-Version: 1.0\n"
	  "Content-Type: multipart/alternative; boundary=a\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: 7bit\n"
	 "Content-Type: text/plain; charset=utf-8\n\n"
	  "> original text\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: 7bit\n"
	  "Content-Type: text/plain; charset=utf-8\n\n"
	  "part two\n"
	  "\n--a--\n",
	  100,
	  ">original text"
	},
	{ "MIME-Version: 1.0\n"
	  "Content-Type: multipart/alternative; boundary=a\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: 7bit\n"
	  "Content-Type: text/plain; charset=utf-8\n\n"
	  "top poster\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: 7bit\n"
	  "Content-Type: text/plain; charset=utf-8\n\n"
	  "> original text\n"
	  "\n--a--\n",
	  100,
	  "top poster"
	},
	{ "MIME-Version: 1.0\n"
	  "Content-Type: multipart/mixed; boundary=a\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: 7bit\n"
	  "Content-Type: text/html; charset=utf-8\n\n"
	  "<html><head></head><body><div><p></p><!-- comment --></body></head>\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: 7bit\n"
	  "Content-Type: text/html; charset=utf-8\n\n"
	  "<html><head></head><body><blockquote><!-- another --></blockquote>\n"
	 "</body></head>\n"
	  "\n--a--\n",
	  100,
	  ""
	},
	{ "MIME-Version: 1.0\n"
	  "Content-Type: multipart/mixed; boundary=a\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: 7bit\n"
	  "Content-Type: text/html; charset=utf-8\n\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: 7bit\n"
	  "Content-Type: text/html; charset=utf-8\n\n"
	  "</body></head>\n"
	  "\n--a--\n",
	  100,
	  ""
	},
	{ "MIME-Version: 1.0\n"
	  "Content-Type: multipart/mixed; boundary=a\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: base64\n"
	  "Content-Type: application/octet-stream\n\n"
	  "U2hvdWxkIG5vdCBiZSBpbiBzbmlwcGV0\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: 7bit\n"
	  "Content-Type: text/html; charset=utf-8\n\n"
	  "<html><head></head><body><p>Should be in snippet</p></body></html>\n"
	  "\n--a--\n",
	  100,
	  "Should be in snippet"
	},
	{ "MIME-Version: 1.0\n"
	  "Content-Type: multipart/mixed; boundary=a\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: base64\n"
	  "Content-Type: application/octet-stream\n\n"
	  "U2hvdWxkIG5vdCBiZSBpbiBzbmlwcGV0\n"
	  "\n--a\n"
	  "Content-Transfer-Encoding: base64\n"
	  "Content-Type: TeXT/html; charset=utf-8\n\n"
	  "PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5PjxwPlNob3VsZCBiZSBpbiBzbmlwcGV0PC9wPjwvYm9k\n"
	  "eT48L2h0bWw+\n"
	  "\n--a--\n",
	  100,
	  "Should be in snippet"
	},
};

static void test_message_snippet(void)
{
	string_t *str = t_str_new(128);
	struct istream *input;
	unsigned int i;

	test_begin("message snippet");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		input = test_istream_create(tests[i].input);
		/* Limit the input max buffer size so the parsing uses multiple
		   blocks. 45 = large enough to be able to read the Content-*
		   headers. */
		test_istream_set_max_buffer_size(input,
			I_MIN(45, strlen(tests[i].input)));
		test_assert_idx(message_snippet_generate(input, tests[i].max_snippet_chars, str) == 0, i);
		test_assert_strcmp_idx(tests[i].output, str_c(str), i);
		i_stream_destroy(&input);
	}
	test_end();
}

static void test_message_snippet_nuls(void)
{
	const char input_text[] = "\nfoo\0bar";
	string_t *str = t_str_new(128);
	struct istream *input;

	test_begin("message snippet with NULs");

	input = i_stream_create_from_data(input_text, sizeof(input_text)-1);
	test_assert(message_snippet_generate(input, 5, str) == 0);
	test_assert_strcmp(str_c(str), "fooba");
	i_stream_destroy(&input);
	test_end();
}

static void
test_message_snippet_incremental_part(struct message_snippet_context *ctx,
				      struct istream *input,
				      const struct message_part *part,
				      unsigned int max_snippet_chars,
				      unsigned int idx)
{
	string_t *incremental = t_str_new(128), *expected = t_str_new(128);
	struct istream *part_input;
	bool have_snippet;

	for (; part != NULL; part = part->next) {
		if ((part->flags & (MESSAGE_PART_FLAG_MULTIPART |
				    MESSAGE_PART_FLAG_MESSAGE_RFC822)) != 0) {
			/* no snippet for parts that have child parts */
			str_truncate(incremental, 0);
			test_assert_idx(!message_snippet_get(ctx, part,
							     incremental), idx);
			test_message_snippet_incremental_part(ctx, input,
				part->children, max_snippet_chars, idx);
			continue;
		}
		str_truncate(incremental, 0);
		have_snippet = message_snippet_get(ctx, part, incremental);
		/* all text parts must have a snippet */
		test_assert_idx(have_snippet ||
			(part->flags & MESSAGE_PART_FLAG_TEXT) == 0, idx);
		if (!have_snippet)
			continue;

		/* The snippet must be the same as when generating it only
		   from this part. */
		i_stream_seek(input, part->physical_pos);
		part_input = i_stream_create_limit(input,
			part->header_size.physical_size +
			part->body_size.physical_size);
		str_truncate(expected, 0);
		test_assert_idx(message_snippet_generate(part_input,
			max_snippet_chars, expected) == 0, idx);
		test_assert_strcmp_idx(str_c(expected), str_c(incremental),
				       idx);
		i_stream_unref(&part_input);
	}
}

static void
test_message_snippet_incremental_one(const char *input_text,
				     unsigned int max_snippet_chars,
				     bool byte_at_a_time, unsigned int idx)
{
	/* Parse the message the same way as index-mail does when saving */
	const struct message_parser_settings parser_set = {
		.hdr_flags = MESSAGE_HEADER_PARSER_FLAG_SKIP_INITIAL_LWSP |
			MESSAGE_HEADER_PARSER_FLAG_DROP_CR,
	};
	struct message_snippet_context *ctx;
	struct message_parser_ctx *parser;
	struct message_part *parts;
	struct message_block block;
	struct istream *input;
	size_t len = strlen(input_text), size = 0;
	pool_t pool;
	int ret;

	input = test_istream_create(input_text);
	if (byte_at_a_time) {
		/* Feed the input a byte at a time, so the parser returns
		   the blocks as small as they can be (like when the mail
		   arrives slowly from the network). */
		test_istream_set_allow_eof(input, FALSE);
		test_istream_set_size(input, size);
	} else {
		/* Limit the input max buffer size so the parsing uses
		   multiple blocks. */
		test_istream_set_max_buffer_size(input, I_MIN(45, len));
	}

	pool = pool_alloconly_create("test message parts", 1024);
	parser = message_parser_init(pool, input, &parser_set);
	ctx = message_snippet_init(max_snippet_chars);
	for (;;) {
		while ((ret = message_parser_parse_next_block(parser,
							      &block)) > 0)
			(void)message_snippet_more(ctx, &block);
		if (ret < 0)
			break;
		/* the parser wants more input */
		test_assert_idx(byte_at_a_time && size < len, idx);
		if (!byte_at_a_time || size >= len)
			break;
		size++;
		test_istream_set_size(input, size);
		if (size == len)
			test_istream_set_allow_eof(input, TRUE);
	}
	test_assert_idx(ret < 0, idx);
	message_parser_deinit(&parser, &parts);

	test_istream_set_max_buffer_size(input, SIZE_MAX);
	test_message_snippet_incremental_part(ctx, input, parts,
					      max_snippet_chars, idx);

	message_snippet_deinit(&ctx);
	pool_unref(&pool);
	i_stream_destroy(&input);
}

static void test_message_snippet_incremental(void)
{
	/* Inputs that are additionally fed a byte at a time */
	static const char *const byte_inputs[] = {
		/* multipart/digest child without Content-Type is
		   message/rfc822, whose child has the snippet */
		"Content-Type: multipart/digest; boundary=a\n"
		"\n--a\n"
		"\n"
		"Subject: inner\n"
		"\n"
		"inner body\n"
		"\n--a--\n",
		/* base64 body with two lines. Fed a byte at a time, the body
		   blocks that have only a line feed or a single base64
		   character decode to nothing. */
		"Content-Type: text/plain\n"
		"Content-Transfer-Encoding: base64\n"
		"\n"
		"aGVsbG8gd29ybGQsIHRoaXMgaXMgYSBtZXNzYWdlIHRoYXQgaXMgbG9uZyBlbm91Z2ggdG8gbmVl\nZCB0d28gYmFzZTY0IGxpbmVz\n",
		"Content-Type: multipart/alternative; boundary=a\n"
		"\n--a\n"
		"Content-Type: text/plain; charset=iso-8859-1\n"
		"Content-Transfer-Encoding: quoted-printable\n"
		"\n"
		"> quoted p=E4iv=E4=E4\n"
		"hyv=E4=E4 p=E4iv=E4=E4\n"
		"\n--a\n"
		"Content-Type: text/plain\n"
		"\n"
		"second part\n"
		"\n--a--\n",
	};
	unsigned int i, mode;

	test_begin("message snippet incremental");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		for (mode = 0; mode < 2; mode++) T_BEGIN {
			/* The charset conversion's replacement of invalid
			   UTF-8 depends on how the input is split, so feed
			   only valid UTF-8 a byte at a time. */
			if (mode == 0 || uni_utf8_str_is_valid(tests[i].input)) {
				test_message_snippet_incremental_one(
					tests[i].input,
					tests[i].max_snippet_chars,
					mode == 1, mode * 1000 + i);
			}
		} T_END;
	}
	for (i = 0; i < N_ELEMENTS(byte_inputs); i++) {
		for (mode = 0; mode < 2; mode++) T_BEGIN {
			test_message_snippet_incremental_one(byte_inputs[i],
				100, mode == 1, 2000 + i * 10 + mode);
		} T_END;
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_message_snippet,
		test_message_snippet_nuls,
		test_message_snippet_incremental,
		NULL
	};
	return test_run(test_functions);
}
