/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "str.h"
#include "failures-private.h"

#include <unistd.h>
#include <fcntl.h>

enum test_log_event_type {
	TYPE_END,
	TYPE_PREFIX_APPEND,
	TYPE_PREFIX_REPLACE,
	TYPE_PREFIX_APPEND_CB,
	TYPE_PREFIX_REPLACE_CB,
	TYPE_MESSAGE_AMEND,
	TYPE_SKIP,
};

enum test_log_event_flag {
	FLAG_BASE_EVENT = BIT(0),
	FLAG_DROP_PREFIXES_1 = BIT(1),
	FLAG_DROP_PREFIXES_2 = BIT(2),
	FLAG_DROP_PREFIXES_4 = BIT(3),
};

enum test_log_flag {
	FLAG_NO_SEND = BIT(0),
};

struct test_log_event {
	enum test_log_event_type type;
	const char *str;
	enum test_log_event_flag flags;
};

struct test_log {
	const struct test_log_event *prefixes;
	const char *global_log_prefix;
	const char *base_send_prefix;
	const char *base_str_prefix;
	const char *result;
	const char *result_str_out;
	enum test_log_flag flags;
};

static const char *temp_log_file = ".temp.log_file";

static const char *
test_event_log_prefix_cb(char *prefix)
{
	return t_strdup_printf("callback(%s)", prefix);
}

static const char *
test_event_log_message_cb(char *prefix,
			  enum log_type log_type ATTR_UNUSED,
			  const char *message)
{
	return t_strdup_printf("[%s%s]", prefix, message);
}

static int temp_log_file_init(void)
{
	int log_fd = open(temp_log_file, O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (log_fd == -1)
		i_fatal("open(%s) failed: %m", temp_log_file);
	i_set_failure_file(temp_log_file, "");
	return log_fd;
}

static const char *read_log_line(int log_fd)
{
	static char line[1024];

	ssize_t ret = read(log_fd, line, sizeof(line)-1);
	if (ret < 0)
		i_fatal("read(%s) failed: %m", temp_log_file);
	if (ret == 0)
		return NULL;

	if (ret > 0 && line[ret-1] == '\n')
		ret--;
	line[ret] = '\0';
	return line;
}

static void test_event_log_message(int log_fd)
{
	struct test_log tests[] = {
		{
			.prefixes = (const struct test_log_event []) {
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global1.",
			.result = "global1.Info: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2.Info: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: appended2.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global2.",
			.result = "global2.Info: appended1,TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: appended1,appended2.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: "
				  "appended1,appended2.appended3.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2.Info: appended3#TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ TYPE_PREFIX_APPEND, "appended5-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: appended5-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND_CB, "appended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: callback(appended1-)TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced1.", 0 },
				{ TYPE_PREFIX_REPLACE_CB, "replaced2-", 0 },
				{ .type = TYPE_END }
			},
			.result = "callback(replaced2-)Info: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.", 0 },
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ .type = TYPE_END }
			},
			.result = "callback(replaced1.)Info: appended1,TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2-Info: TEXT",
		},
		/* Tests involving event_set_log_message_callback() */
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-" , 0},
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-[amended2-TEXT]]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-appended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: appended1-[amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: "
				"appended1-[amended1-appended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-appended1-"
				"[amended2-appended2-TEXT]]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: [amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2,Info: [amended2-TEXT]",
		},
		/* Tests with params->base_str_out != NULL */
		{
			.prefixes = (const struct test_log_event []) {
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global1.",
			.result = "global1.Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2.Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2.Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.result = "replaced2.Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: appended2.TEXT",
			.result_str_out = "appended2.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: appended2.TEXT",
			.result_str_out = "appended2.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: appended2.TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced1,",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global2.",
			.result = "global2.Info: appended1,TEXT",
			.result_str_out = "appended1,TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global2.",
			.result = "global2.Info: appended1,TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: appended1,appended2.TEXT",
			.result_str_out = "appended1,appended2.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: appended1,appended2.TEXT",
			.result_str_out = "appended2.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: appended1,appended2.TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: "
				  "appended1,appended2.appended3.TEXT",
			.result_str_out = "appended1,appended2.appended3.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: "
				  "appended1,appended2.appended3.TEXT",
			.result_str_out = "appended2.appended3.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: "
				  "appended1,appended2.appended3.TEXT",
			.result_str_out = "appended3.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: "
				  "appended1,appended2.appended3.TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2.Info: appended3#TEXT",
			.result_str_out = "appended3#TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2.Info: appended3#TEXT",
			.result_str_out = "appended3#TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2.Info: appended3#TEXT",
			.result_str_out = "appended3#TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.result = "replaced2.Info: appended3#TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ TYPE_PREFIX_APPEND, "appended5-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: appended5-TEXT",
			.result_str_out = "appended5-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ TYPE_PREFIX_APPEND, "appended5-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: appended5-TEXT",
			.result_str_out = "appended5-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ TYPE_PREFIX_APPEND, "appended5-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: appended5-TEXT",
			.result_str_out = "appended5-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ TYPE_PREFIX_APPEND, "appended5-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: appended5-TEXT",
			.result_str_out = "appended5-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended5-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: appended5-TEXT",
			.result_str_out = "appended5-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ TYPE_PREFIX_APPEND, "appended5-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: appended5-TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND_CB, "appended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: callback(appended1-)TEXT",
			.result_str_out = "callback(appended1-)TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND_CB, "appended1-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: callback(appended1-)TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced1.", 0 },
				{ TYPE_PREFIX_REPLACE_CB, "replaced2-", 0 },
				{ .type = TYPE_END }
			},
			.result = "callback(replaced2-)Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced1.", 0 },
				{ TYPE_PREFIX_REPLACE_CB, "replaced2-", 0 },
				{ .type = TYPE_END }
			},
			.result = "callback(replaced2-)Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced1.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE_CB, "replaced2-", 0 },
				{ .type = TYPE_END }
			},
			.result = "callback(replaced2-)Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced1.", 0 },
				{ TYPE_PREFIX_REPLACE_CB, "replaced2-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.result = "callback(replaced2-)Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.", 0 },
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ .type = TYPE_END }
			},
			.result = "callback(replaced1.)Info: appended1,TEXT",
			.result_str_out = "appended1,TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ .type = TYPE_END }
			},
			.result = "callback(replaced1.)Info: appended1,TEXT",
			.result_str_out = "appended1,TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.", 0 },
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.result = "callback(replaced1.)Info: appended1,TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2-Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced2-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2-Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.result = "replaced2-Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-" , 0},
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-TEXT]",
			.result_str_out = "[amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-" ,
				  FLAG_BASE_EVENT},
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-TEXT]",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-[amended2-TEXT]]",
			.result_str_out = "[amended1-[amended2-TEXT]]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-[amended2-TEXT]]",
			.result_str_out = "[amended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-[amended2-TEXT]]",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-appended1-TEXT]",
			.result_str_out = "[amended1-appended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-appended1-TEXT]",
			.result_str_out = "appended1-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-appended1-TEXT]",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: appended1-[amended1-TEXT]",
			.result_str_out = "appended1-[amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: appended1-[amended1-TEXT]",
			.result_str_out = "[amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: appended1-[amended1-TEXT]",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: "
				"appended1-[amended1-appended2-TEXT]",
			.result_str_out = "appended1-[amended1-appended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: "
				"appended1-[amended1-appended2-TEXT]",
			.result_str_out = "[amended1-appended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: "
				"appended1-[amended1-appended2-TEXT]",
			.result_str_out = "appended2-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: "
				"appended1-[amended1-appended2-TEXT]",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-appended1-"
				"[amended2-appended2-TEXT]]",
			.result_str_out = "[amended1-appended1-"
				"[amended2-appended2-TEXT]]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-appended1-"
				"[amended2-appended2-TEXT]]",
			.result_str_out = "appended1-[amended2-appended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-appended1-"
				"[amended2-appended2-TEXT]]",
			.result_str_out = "[amended2-appended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-appended1-"
				"[amended2-appended2-TEXT]]",
			.result_str_out = "appended2-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = "global4.Info: [amended1-appended1-"
				"[amended2-appended2-TEXT]]",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: [amended1-TEXT]",
			.result_str_out = "[amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: [amended1-TEXT]",
			.result_str_out = "[amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: [amended1-TEXT]",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2,Info: [amended2-TEXT]",
			.result_str_out = "[amended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2,Info: [amended2-TEXT]",
			.result_str_out = "[amended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced2,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2,Info: [amended2-TEXT]",
			.result_str_out = "[amended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2,",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.result = "replaced2,Info: [amended2-TEXT]",
			.result_str_out = "[amended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.result = "replaced2,Info: [amended2-TEXT]",
			.result_str_out = "TEXT",
		},
		/* Tests involving params->no_send */
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = NULL,
			.result_str_out = "appended3.TEXT",
			.flags = FLAG_NO_SEND,
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.result = NULL,
			.result_str_out = "[amended2-appended2-TEXT]",
			.flags = FLAG_NO_SEND,
		},
		/* Tests with params->base_*_prefix assigned */
		{
			.prefixes = (const struct test_log_event []) {
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global1.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global1.Info: PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",

			.result = "replaced1,Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced1,Info: PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2.Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2.Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2.Info: PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced1,Info: appended2.TEXT",
			.result_str_out = "appended2.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced1,Info: PREFIX: appended2.TEXT",
			.result_str_out = "STR_PREFIX: appended2.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced1,Info: appended2.PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced1,Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced1,Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced1,",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced1,Info: PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global2.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global2.Info: PREFIX: appended1,TEXT",
			.result_str_out = "STR_PREFIX: appended1,TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global2.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global2.Info: appended1,PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global3.Info: PREFIX: "
				"appended1,appended2.TEXT",
			.result_str_out = "STR_PREFIX: "
				"appended1,appended2.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global3.Info: appended1,PREFIX: "
				"appended2.TEXT",
			.result_str_out = "STR_PREFIX: appended2.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global3.Info: appended1,appended2."
				"PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global3.Info: PREFIX: "
				"appended1,appended2.appended3.TEXT",
			.result_str_out = "STR_PREFIX: "
				"appended1,appended2.appended3.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global3.Info: appended1,PREFIX: "
				"appended2.appended3.TEXT",
			.result_str_out = "STR_PREFIX: "
				"appended2.appended3.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global3.Info: appended1,appended2.PREFIX: "
				"appended3.TEXT",
			.result_str_out = "STR_PREFIX: appended3.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global3.Info: "
				"appended1,appended2.appended3.PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2.Info: appended3#TEXT",
			.result_str_out = "appended3#TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2.Info: appended3#TEXT",
			.result_str_out = "appended3#TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2.Info: PREFIX: appended3#TEXT",
			.result_str_out = "STR_PREFIX: appended3#TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2.Info: appended3#PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced4;Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced4;Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced4;Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced4;Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced4;Info: PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ TYPE_PREFIX_APPEND, "appended5-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced4;Info: appended5-TEXT",
			.result_str_out = "appended5-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ TYPE_PREFIX_APPEND, "appended5-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced4;Info: appended5-TEXT",
			.result_str_out = "appended5-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ TYPE_PREFIX_APPEND, "appended5-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced4;Info: appended5-TEXT",
			.result_str_out = "appended5-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ TYPE_PREFIX_APPEND, "appended5-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced4;Info: appended5-TEXT",
			.result_str_out = "appended5-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended5-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced4;Info: PREFIX: appended5-TEXT",
			.result_str_out = "STR_PREFIX: appended5-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3#", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced4;", 0 },
				{ TYPE_PREFIX_APPEND, "appended5-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced4;Info: appended5-PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND_CB, "appended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global3.Info: PREFIX: "
				"callback(appended1-)TEXT",
			.result_str_out = "STR_PREFIX: "
				"callback(appended1-)TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND_CB, "appended1-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global3.Info: callback(appended1-)PREFIX: "
				"TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced1.", 0 },
				{ TYPE_PREFIX_REPLACE_CB, "replaced2-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "callback(replaced2-)Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced1.", 0 },
				{ TYPE_PREFIX_REPLACE_CB, "replaced2-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "callback(replaced2-)Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced1.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE_CB, "replaced2-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "callback(replaced2-)Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced1.", 0 },
				{ TYPE_PREFIX_REPLACE_CB, "replaced2-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "callback(replaced2-)Info: PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.", 0 },
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "callback(replaced1.)Info: appended1,TEXT",
			.result_str_out = "appended1,TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "callback(replaced1.)Info: PREFIX: "
				"appended1,TEXT",
			.result_str_out = "STR_PREFIX: appended1,TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.", 0 },
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "callback(replaced1.)Info: appended1,PREFIX: "
				"TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2-Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced2-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2-Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE_CB, "replaced1.", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2-Info: PREFIX: TEXT",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-" , 0},
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: PREFIX: [amended1-TEXT]",
			.result_str_out = "STR_PREFIX: [amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-" ,
				  FLAG_BASE_EVENT},
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: [amended1-PREFIX: TEXT]",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: PREFIX: "
				"[amended1-[amended2-TEXT]]",
			.result_str_out = "STR_PREFIX: "
				"[amended1-[amended2-TEXT]]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: [amended1-PREFIX: "
				"[amended2-TEXT]]",
			.result_str_out = "STR_PREFIX: [amended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: [amended1-[amended2-PREFIX: "
				"TEXT]]",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: PREFIX: "
				"[amended1-appended1-TEXT]",
			.result_str_out = "STR_PREFIX: "
				"[amended1-appended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: [amended1-PREFIX: "
				"appended1-TEXT]",
			.result_str_out = "STR_PREFIX: appended1-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: [amended1-appended1-PREFIX: "
				"TEXT]",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: PREFIX: "
				"appended1-[amended1-TEXT]",
			.result_str_out = "STR_PREFIX: "
				"appended1-[amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: appended1-PREFIX: "
				"[amended1-TEXT]",
			.result_str_out = "STR_PREFIX: [amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: appended1-[amended1-PREFIX: "
				"TEXT]",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: PREFIX: "
				"appended1-[amended1-appended2-TEXT]",
			.result_str_out = "STR_PREFIX: "
				"appended1-[amended1-appended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: appended1-PREFIX: "
				"[amended1-appended2-TEXT]",
			.result_str_out = "STR_PREFIX: "
				"[amended1-appended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: appended1-[amended1-PREFIX: "
				"appended2-TEXT]",
			.result_str_out = "STR_PREFIX: appended2-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: "
				"appended1-[amended1-appended2-PREFIX: TEXT]",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: PREFIX: [amended1-appended1-"
				"[amended2-appended2-TEXT]]",
			.result_str_out = "STR_PREFIX: [amended1-appended1-"
				"[amended2-appended2-TEXT]]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: [amended1-PREFIX: appended1-"
				"[amended2-appended2-TEXT]]",
			.result_str_out = "STR_PREFIX: "
				"appended1-[amended2-appended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: [amended1-appended1-PREFIX: "
				"[amended2-appended2-TEXT]]",
			.result_str_out = "STR_PREFIX: "
				"[amended2-appended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_APPEND, "appended2-", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: [amended1-appended1-"
				"[amended2-PREFIX: appended2-TEXT]]",
			.result_str_out = "STR_PREFIX: appended2-TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_APPEND, "appended1-", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ TYPE_PREFIX_APPEND, "appended2-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global4.",
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "global4.Info: [amended1-appended1-"
				"[amended2-appended2-PREFIX: TEXT]]",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced1,Info: [amended1-TEXT]",
			.result_str_out = "[amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced1,Info: PREFIX: [amended1-TEXT]",
			.result_str_out = "STR_PREFIX: [amended1-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced1,Info: [amended1-PREFIX: TEXT]",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2,Info: [amended2-TEXT]",
			.result_str_out = "[amended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2,Info: [amended2-TEXT]",
			.result_str_out = "[amended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-",
				  FLAG_BASE_EVENT },
				{ TYPE_PREFIX_REPLACE, "replaced2,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2,Info: [amended2-TEXT]",
			.result_str_out = "[amended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2,",
				  FLAG_BASE_EVENT },
				{ TYPE_MESSAGE_AMEND, "amended2-", 0 },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2,Info: PREFIX: [amended2-TEXT]",
			.result_str_out = "STR_PREFIX: [amended2-TEXT]",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_REPLACE, "replaced1,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended1-", 0 },
				{ TYPE_PREFIX_REPLACE, "replaced2,", 0 },
				{ TYPE_MESSAGE_AMEND, "amended2-",
				  FLAG_BASE_EVENT },
				{ .type = TYPE_END }
			},
			.base_send_prefix = "PREFIX: ",
			.base_str_prefix = "STR_PREFIX: ",
			.result = "replaced2,Info: [amended2-PREFIX: TEXT]",
			.result_str_out = "STR_PREFIX: TEXT",
		},
		/* Tests in which parent log prefixes are dropped by an event
		   lower in the hierarchy. */
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ TYPE_PREFIX_APPEND, "appended4.", 0 },
				{ TYPE_PREFIX_APPEND, "appended5.", 0 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: "
				"appended1,appended2.appended3."
				"appended4.appended5.TEXT",
			.result_str_out = "appended1,appended2.appended3."
				"appended4.appended5.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ TYPE_PREFIX_APPEND, "appended4.", 0 },
				{ TYPE_PREFIX_APPEND, "appended5.",
				  FLAG_DROP_PREFIXES_1 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: "
				"appended1,appended2.appended3."
				"appended5.TEXT",
			.result_str_out = "appended1,appended2.appended3."
				"appended5.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ TYPE_PREFIX_APPEND, "appended4.", 0 },
				{ TYPE_PREFIX_APPEND, "appended5.", 0 },
				{ TYPE_SKIP, NULL, FLAG_DROP_PREFIXES_1 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: "
				"appended1,appended2.appended3."
				"appended4.TEXT",
			.result_str_out = "appended1,appended2.appended3."
				"appended4.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ TYPE_PREFIX_APPEND, "appended4.", 0 },
				{ TYPE_PREFIX_APPEND, "appended5.",
				  FLAG_DROP_PREFIXES_2 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: "
				"appended1,appended2.appended5.TEXT",
			.result_str_out = "appended1,appended2.appended5.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ TYPE_PREFIX_APPEND, "appended4.", 0 },
				{ TYPE_PREFIX_APPEND, "appended5.",
				  (FLAG_DROP_PREFIXES_1 |
				   FLAG_DROP_PREFIXES_2) },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: appended1,appended5.TEXT",
			.result_str_out = "appended1,appended5.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ TYPE_PREFIX_APPEND, "appended4.", 0 },
				{ TYPE_PREFIX_APPEND, "appended5.",
				  FLAG_DROP_PREFIXES_4 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: appended5.TEXT",
			.result_str_out = "appended5.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ TYPE_PREFIX_APPEND, "appended4.", 0 },
				{ TYPE_PREFIX_APPEND, "appended5.",
				  (FLAG_DROP_PREFIXES_1 |
				   FLAG_DROP_PREFIXES_2 |
				   FLAG_DROP_PREFIXES_4) },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: appended5.TEXT",
			.result_str_out = "appended5.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ TYPE_PREFIX_APPEND, "appended4.", 0 },
				{ TYPE_PREFIX_APPEND, "appended5.", 0 },
				{ TYPE_SKIP, NULL, (FLAG_DROP_PREFIXES_1 |
						    FLAG_DROP_PREFIXES_2 |
						    FLAG_DROP_PREFIXES_4) },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: TEXT",
			.result_str_out = "TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.",
				  FLAG_DROP_PREFIXES_1 },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ TYPE_PREFIX_APPEND, "appended4.", 0 },
				{ TYPE_PREFIX_APPEND, "appended5.",
				  FLAG_DROP_PREFIXES_1 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: "
				"appended2.appended3.appended5.TEXT",
			.result_str_out = "appended2.appended3.appended5.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,",
				  FLAG_DROP_PREFIXES_1 },
				{ TYPE_PREFIX_APPEND, "appended2.",
				  FLAG_DROP_PREFIXES_1 },
				{ TYPE_PREFIX_APPEND, "appended3.",
				  FLAG_DROP_PREFIXES_1 },
				{ TYPE_PREFIX_APPEND, "appended4.",
				  FLAG_DROP_PREFIXES_1 },
				{ TYPE_PREFIX_APPEND, "appended5.",
				  FLAG_DROP_PREFIXES_1 },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: appended5.TEXT",
			.result_str_out = "appended5.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ .type = TYPE_SKIP },
				{ TYPE_PREFIX_APPEND, "appended2.",
				  FLAG_DROP_PREFIXES_1 },
				{ .type = TYPE_SKIP },
				{ TYPE_PREFIX_APPEND, "appended3.", 0 },
				{ .type = TYPE_SKIP },
				{ TYPE_PREFIX_APPEND, "appended4.", 0 },
				{ .type = TYPE_SKIP },
				{ TYPE_PREFIX_APPEND, "appended5.",
				  FLAG_DROP_PREFIXES_1 },
				{ .type = TYPE_SKIP },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: "
				"appended2.appended3.appended5.TEXT",
			.result_str_out = "appended2.appended3.appended5.TEXT",
		},
		{
			.prefixes = (const struct test_log_event []) {
				{ TYPE_PREFIX_APPEND, "appended1,", 0 },
				{ TYPE_PREFIX_APPEND, "appended2.", 0 },
				{ TYPE_PREFIX_APPEND, "appended3.",
				  FLAG_DROP_PREFIXES_1 },
				{ TYPE_PREFIX_APPEND, "appended4.", 0 },
				{ TYPE_PREFIX_APPEND, "appended5.",
				  (FLAG_DROP_PREFIXES_1 |
				   FLAG_DROP_PREFIXES_2) },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: appended5.TEXT",
			.result_str_out = "appended5.TEXT",
		},
	};

	test_begin("event log message");

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		const struct test_log *test = &tests[i];
		struct event_log_params params = {
			.log_type = LOG_TYPE_INFO,
			.base_send_prefix = test->base_send_prefix,
			.base_str_prefix = test->base_str_prefix,
			.no_send = ((test->flags & FLAG_NO_SEND) != 0),
		};

		if (test->global_log_prefix != NULL)
			i_set_failure_prefix("%s", test->global_log_prefix);
		else
			i_set_failure_prefix("UNEXPECTED GLOBAL PREFIX");

		struct event *event, *parent;
		event = parent = event_create(NULL);
		for (unsigned int j = 0; test->prefixes[j].type != TYPE_END; j++) {
			unsigned int drop_prefixes = 0;

			if (event == NULL) {
				struct event *child = event_create(parent);
				event_unref(&parent);
				event = parent = child;
			}
			if ((test->prefixes[j].flags & FLAG_BASE_EVENT) != 0) {
				i_assert(params.base_event == NULL);
				params.base_event = event;
			}
			if ((test->prefixes[j].flags &
			     FLAG_DROP_PREFIXES_1) != 0)
				drop_prefixes += 1;
			if ((test->prefixes[j].flags &
			     FLAG_DROP_PREFIXES_2) != 0)
				drop_prefixes += 2;
			if ((test->prefixes[j].flags &
			     FLAG_DROP_PREFIXES_4) != 0)
				drop_prefixes += 4;
			event_drop_parent_log_prefixes(event, drop_prefixes);

			switch (test->prefixes[j].type) {
			case TYPE_END:
				i_unreached();
			case TYPE_PREFIX_APPEND:
				event_set_append_log_prefix(event, test->prefixes[j].str);
				break;
			case TYPE_PREFIX_REPLACE:
				event_replace_log_prefix(event, test->prefixes[j].str);
				break;
			case TYPE_PREFIX_APPEND_CB:
				event_set_log_prefix_callback(event, FALSE,
							      test_event_log_prefix_cb,
							      (char*)test->prefixes[j].str);
				break;
			case TYPE_PREFIX_REPLACE_CB:
				event_set_log_prefix_callback(event, TRUE,
							      test_event_log_prefix_cb,
							      (char*)test->prefixes[j].str);
				break;
			case TYPE_MESSAGE_AMEND:
				event_set_log_message_callback(event,
							       test_event_log_message_cb,
							       (char*)test->prefixes[j].str);
				break;
			case TYPE_SKIP:
				break;
			}
			event = NULL;
		}
		event = parent;

		if (test->result_str_out != NULL) {
			/* Use small value so buffer size grows. This way the
			   unit test fails if anyone attempts to add data-stack
			   frame to event_log(). */
			params.base_str_out = t_str_new(1);
		}
		event_log(event, &params, "TEXT");

		test_assert_strcmp(test->result, read_log_line(log_fd));
		if (test->result_str_out != NULL) {
			test_assert_strcmp(test->result_str_out,
					   str_c(params.base_str_out));
		}
		event_unref(&event);
	} T_END;
	i_unset_failure_prefix();
	test_end();
}

static void test_event_duration()
{
	uintmax_t duration;
	test_begin("event duration");
	struct event *e = event_create(NULL);
	usleep(10);
	e_info(e, "Submit event");
	event_get_last_duration(e, &duration);
	test_assert(duration > 0);
	event_unref(&e);
	test_end();
}

static void test_event_log_level(int log_fd)
{
	test_begin("event log level");

	struct event *event = event_create(NULL);
	event_set_min_log_level(event, LOG_TYPE_WARNING);
	errno = EACCES;
	e_info(event, "Info event");
	const char *test_output = read_log_line(log_fd);
	test_assert(test_output == NULL);
	e_warning(event, "Warning event");
	test_output = read_log_line(log_fd);
	test_assert_strcmp(test_output, "Warning: Warning event");
	event_unref(&event);
	test_assert(errno == EACCES);
	test_end();
}

void test_event_log(void)
{
	test_event_duration();

	failure_callback_t *orig_fatal;
	failure_callback_t *orig_error, *orig_info, *orig_debug;
	i_get_failure_handlers(&orig_fatal, &orig_error,
			       &orig_info, &orig_debug);
	int log_fd = temp_log_file_init();
	test_event_log_message(log_fd);
	test_event_log_level(log_fd);

	i_set_failure_file("/dev/stderr", "");
	i_set_error_handler(orig_error);
	i_close_fd(&log_fd);
	i_unlink(temp_log_file);
}
