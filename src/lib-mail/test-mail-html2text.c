/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "mail-html2text.h"
#include "test-common.h"

static const struct {
	const char *input;
	const char *output;
} tests[] = {
	{ "&&aaaaaaaaaa", "" },

	{ "a&amp;&lt;&clubs;&gt;b",
	  "a&<\xE2\x99\xA3>b" },
	{ "&", "" },
	{ "&amp", "" },

	{ "a<style>stylesheet is ignored</style>b",
	  "a b" },
	{ "a<stylea>b</stylea>c",
	  "a b c" },
	{ "a<!--x <p foo=\"bar\">commented tags ignored also</p> y-->b",
	  "ab" },
	{ "a<script>javascript <p>foo</p> ignored</script>b",
	  "a b" },
	{ "a<scripta>b</scripta>c",
	  "a b c" },
	{ "a<blockquote><blockquote>second level</blockquote>ignored</blockquote>b",
	  "a b" },
	{ "a<![CDATA[<style>]] >b</style>]]>c",
	  "a<style>]] >b</style>c" },

	{ "a<foo", "a" },
	{ "a<blockquote", "a" },
	{ "a<blockquote>foo</blockquote", "a " },
	{ "a<", "a" },
	{ "a<![CDATA[b", "ab" },
	{ "a<![CDATA[b]]", "ab" },
	{ "a&#228;", "a\xC3\xA4" },
	{ "a&#xe4;", "a\xC3\xA4" },
	{ "&#8364;", "\xE2\x82\xAC" },
	{ "&#deee;", "" }, // invalid codepoint
};

static const char *test_blockquote_input[] = {
	"a<blockquote>b<blockquote><blockquote>c</blockquote>d</blockquote>e</blockquote>f",
	"a&amp;<blockquote>b&amp;<blockquote>&amp;<blockquote>&amp;c</blockquote>d&amp;</blockquote>&amp;e</blockquote>f&amp;",
	NULL
};

static const char *test_blockquote_output[] = {
	"a\n> b\n> \n> c\n> d\n> e\nf",
	"a&\n> b&\n> &\n> &c\n> d&\n> &e\nf&",
	NULL
};

static void test_mail_html2text(void)
{
	string_t *str = t_str_new(128);
	struct mail_html2text *ht;
	unsigned int i, j;

	test_begin("mail_html2text()");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		ht = mail_html2text_init(MAIL_HTML2TEXT_FLAG_SKIP_QUOTED);
		for (j = 0; tests[i].input[j] != '\0'; j++) {
			unsigned char c = tests[i].input[j];
			mail_html2text_more(ht, &c, 1, str);
		}
		test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);
		mail_html2text_deinit(&ht);
		str_truncate(str, 0);
	}

	/* test without skipping quoted */
	for (unsigned int i = 0; test_blockquote_input[i] != NULL; i++) {
		str_truncate(str, 0);
		ht = mail_html2text_init(0);
		mail_html2text_more(ht, (const void *)test_blockquote_input[i],
				    strlen(test_blockquote_input[i]), str);
		test_assert_idx(strcmp(str_c(str), test_blockquote_output[i]) == 0, i);
		mail_html2text_deinit(&ht);
	}

	test_end();
}

static void test_mail_html2text_random(void)
{
	string_t *str = t_str_new(128);
	struct mail_html2text *ht;

	test_begin("mail_html2text() random");
	for (unsigned int i = 0; i < 1000; i++) {
		char valid_chars[] = { '0', 'a', '<', '>', '&', ';', '\\', '\'', '"', '/' };
		unsigned char s[2];

		ht = mail_html2text_init(0);
		for (unsigned int i = 0; i < 100; i++) {
			s[0] = valid_chars[i_rand_limit(N_ELEMENTS(valid_chars))];
			s[1] = valid_chars[i_rand_limit(N_ELEMENTS(valid_chars))];
			mail_html2text_more(ht, s, i_rand_minmax(1, 2), str);
		}
		mail_html2text_deinit(&ht);
		str_truncate(str, 0);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_html2text,
		test_mail_html2text_random,
		NULL
	};
	return test_run(test_functions);
}
