/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ioloop.h"
#include "str.h"
#include "failures-private.h"

#include <unistd.h>

enum test_log_prefix_type {
	TYPE_END,
	TYPE_APPEND,
	TYPE_REPLACE,
	TYPE_CALLBACK_APPEND,
	TYPE_CALLBACK_REPLACE,
	TYPE_SKIP,
};

struct test_log_prefix {
	enum test_log_prefix_type type;
	const char *str;
};

struct test_log {
	const struct test_log_prefix *prefixes;
	const char *global_log_prefix;
	const char *result;
};

static char *test_output;

static void ATTR_FORMAT(2, 0)
info_handler(const struct failure_context *ctx,
	     const char *format, va_list args)
{
	size_t prefix_len;

	i_assert(ctx->type == LOG_TYPE_INFO);

	i_free(test_output);
	T_BEGIN {
		string_t *str = failure_handler.v->format(ctx, &prefix_len,
							  format, args);
		test_output = i_strdup(str_c(str));
	} T_END;
}

static void ATTR_FORMAT(2, 0)
error_handler(const struct failure_context *ctx,
	     const char *format, va_list args)
{
	size_t prefix_len;

	i_assert(ctx->type == LOG_TYPE_WARNING ||
		 ctx->type == LOG_TYPE_ERROR);

	i_free(test_output);
	T_BEGIN {
		string_t *str = failure_handler.v->format(ctx, &prefix_len,
							  format, args);
		test_output = i_strdup(str_c(str));
	} T_END;
}

static const char *
test_event_log_prefix_cb(char *prefix)
{
	return t_strdup_printf("callback(%s)", prefix);
}

static void test_event_log_prefix(void)
{
	struct test_log tests[] = {
		{
			.prefixes = (const struct test_log_prefix []) {
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global1.",
			.result = "global1.Info: TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_REPLACE, "replaced1," },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_REPLACE, "replaced1," },
				{ TYPE_REPLACE, "replaced2." },
				{ .type = TYPE_END }
			},
			.result = "replaced2.Info: TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_REPLACE, "replaced1," },
				{ TYPE_APPEND, "appended2." },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: appended2.TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_APPEND, "appended1," },
				{ TYPE_REPLACE, "replaced1," },
				{ .type = TYPE_END }
			},
			.result = "replaced1,Info: TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_APPEND, "appended1," },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global2.",
			.result = "global2.Info: appended1,TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_APPEND, "appended1," },
				{ TYPE_APPEND, "appended2." },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: appended1,appended2.TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_APPEND, "appended1," },
				{ TYPE_REPLACE, "replaced2." },
				{ TYPE_APPEND, "appended3#" },
				{ .type = TYPE_END }
			},
			.result = "replaced2.Info: appended3#TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_APPEND, "appended1," },
				{ TYPE_REPLACE, "replaced2." },
				{ TYPE_APPEND, "appended3#" },
				{ TYPE_REPLACE, "replaced4;" },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_APPEND, "appended1," },
				{ TYPE_REPLACE, "replaced2." },
				{ TYPE_APPEND, "appended3#" },
				{ TYPE_REPLACE, "replaced4;" },
				{ TYPE_APPEND, "appended5-" },
				{ .type = TYPE_END }
			},
			.result = "replaced4;Info: appended5-TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_CALLBACK_APPEND, "appended1-" },
				{ .type = TYPE_END }
			},
			.global_log_prefix = "global3.",
			.result = "global3.Info: callback(appended1-)TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_APPEND, "appended1," },
				{ TYPE_REPLACE, "replaced1." },
				{ TYPE_CALLBACK_REPLACE, "replaced2-" },
				{ .type = TYPE_END }
			},
			.result = "callback(replaced2-)Info: TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_CALLBACK_REPLACE, "replaced1." },
				{ TYPE_APPEND, "appended1," },
				{ .type = TYPE_END }
			},
			.result = "callback(replaced1.)Info: appended1,TEXT",
		},
		{
			.prefixes = (const struct test_log_prefix []) {
				{ TYPE_CALLBACK_REPLACE, "replaced1." },
				{ TYPE_REPLACE, "replaced2-" },
				{ .type = TYPE_END }
			},
			.result = "replaced2-Info: TEXT",
		},
	};
	const struct event_log_params params = {
		.log_type = LOG_TYPE_INFO,
	};

	test_begin("event log prefixes");

	failure_callback_t *orig_fatal, *orig_error, *orig_info, *orig_debug;
	i_get_failure_handlers(&orig_fatal, &orig_error, &orig_info, &orig_debug);
	i_set_info_handler(info_handler);
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		const struct test_log *test = &tests[i];

		if (test->global_log_prefix != NULL)
			i_set_failure_prefix("%s", test->global_log_prefix);
		else
			i_set_failure_prefix("UNEXPECTED GLOBAL PREFIX");

		struct event *event, *parent;
		event = parent = event_create(NULL);
		for (unsigned int j = 0; test->prefixes[j].type != TYPE_END; j++) {
			if (event == NULL) {
				struct event *child = event_create(parent);
				event_unref(&parent);
				event = parent = child;
			}
			switch (test->prefixes[j].type) {
			case TYPE_END:
				i_unreached();
			case TYPE_APPEND:
				event_set_append_log_prefix(event, test->prefixes[j].str);
				break;
			case TYPE_REPLACE:
				event_replace_log_prefix(event, test->prefixes[j].str);
				break;
			case TYPE_CALLBACK_APPEND:
				event_set_log_prefix_callback(event, FALSE,
							      test_event_log_prefix_cb,
							      (char*)test->prefixes[j].str);
				break;
			case TYPE_CALLBACK_REPLACE:
				event_set_log_prefix_callback(event, TRUE,
							      test_event_log_prefix_cb,
							      (char*)test->prefixes[j].str);
				break;
			case TYPE_SKIP:
				break;
			}
			event = NULL;
		}
		event = parent;
		event_log(event, &params, "TEXT");

		test_assert_strcmp(test->result, test_output);
		event_unref(&event);
	}
	i_set_info_handler(orig_info);
	i_unset_failure_prefix();
	i_free(test_output);
	test_end();
}

static void test_event_duration()
{
	intmax_t duration;
	test_begin("event duration");
	struct event *e = event_create(NULL);
	usleep(10);
	e_info(e, "Submit event");
	event_get_last_duration(e, &duration);
	test_assert(duration > 0);
	event_unref(&e);
	test_end();
}

static void test_event_log_level(void)
{
	test_begin("event log level");
	failure_callback_t *orig_fatal, *orig_error, *orig_info, *orig_debug;
	i_get_failure_handlers(&orig_fatal, &orig_error, &orig_info, &orig_debug);
	i_set_info_handler(info_handler);
	i_set_error_handler(error_handler);

	struct event *event = event_create(NULL);
	event_set_min_log_level(event, LOG_TYPE_WARNING);
	e_info(event, "Info event");
	test_assert(test_output == NULL);
	e_warning(event, "Warning event");
	test_assert_strcmp(test_output, "Warning: Warning event");
	event_unref(&event);
	i_set_info_handler(orig_info);
	i_set_error_handler(orig_error);
	i_free(test_output);
	test_end();
}

void test_event_log(void)
{
	test_event_log_prefix();
	test_event_duration();
	test_event_log_level();
}
