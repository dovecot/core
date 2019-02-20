/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "array.h"
#include "test-common.h"
#include "smtp-common.h"
#include "smtp-address.h"
#include "smtp-params.h"

static const char *test_extensions[] = { "FROP", "FRUP", NULL };

static struct smtp_address test_address1 =
	{ .localpart = NULL, .domain = NULL };
static struct smtp_address test_address2 =
	{ .localpart = "user+detail", .domain = NULL };
static struct smtp_address test_address3 =
	{ .localpart = "e=mc2", .domain = "example.com" };

static struct smtp_param test_params1[] = {
	{ .keyword = "FROP", .value = "friep" }
};
static struct smtp_param test_params2[] = {
	{ .keyword = "FROP", .value = "friep" },
	{ .keyword = "FRUP", .value = "frml" }
};

static struct buffer test_params_buffer1 = {
	.data = (void*)&test_params1,
	.used = sizeof(test_params1)
};
static struct buffer test_params_buffer2 = {
	.data = (void*)&test_params2,
	.used = sizeof(test_params2)
};

/* Valid mail params tests */

struct valid_mail_params_parse_test {
	const char *input, *output;

	enum smtp_capability caps;
	const char *const *extensions;
	const char *const *body_extensions;

	struct smtp_params_mail params;
};

static const struct valid_mail_params_parse_test
valid_mail_params_parse_tests[] = {
	/* AUTH */
	{
		.input = "AUTH=<>",
		.caps = SMTP_CAPABILITY_AUTH,
		.params = {
			.auth = &test_address1
		}
	},{
		.input = "AUTH=user+2Bdetail",
		.caps = SMTP_CAPABILITY_AUTH,
		.params = {
			.auth = &test_address2
		}
	},{
		.input = "AUTH=e+3Dmc2@example.com",
		.caps = SMTP_CAPABILITY_AUTH,
		.params = {
			.auth = &test_address3
		}
	/* BODY */
	},{
		.input = "",
		.caps = SMTP_CAPABILITY_8BITMIME,
		.params = {
			.body = {
				.type = SMTP_PARAM_MAIL_BODY_TYPE_UNSPECIFIED,
			}
		}
	},{
		.input = "BODY=7BIT",
		.caps = SMTP_CAPABILITY_8BITMIME,
		.params = {
			.body = {
				.type = SMTP_PARAM_MAIL_BODY_TYPE_7BIT,
			}
		}
	},{
		.input = "BODY=8BITMIME",
		.caps = SMTP_CAPABILITY_8BITMIME,
		.params = {
			.body = {
				.type = SMTP_PARAM_MAIL_BODY_TYPE_8BITMIME,
			}
		}
	},{
		.input = "BODY=BINARYMIME",
		.caps = SMTP_CAPABILITY_8BITMIME |
			SMTP_CAPABILITY_BINARYMIME |
			SMTP_CAPABILITY_CHUNKING,
		.params = {
			.body = {
				.type = SMTP_PARAM_MAIL_BODY_TYPE_BINARYMIME,
			}
		}
	},{
		.input = "BODY=FROP",
		.caps = SMTP_CAPABILITY_8BITMIME |
			SMTP_CAPABILITY_BINARYMIME |
			SMTP_CAPABILITY_CHUNKING,
		.body_extensions = test_extensions,
		.params = {
			.body = {
				.type = SMTP_PARAM_MAIL_BODY_TYPE_EXTENSION,
				.ext = "FROP"
			}
		}
	/* ENVID */
	},{
		.input = "",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.envid = NULL,
		}
	},{
		.input = "ENVID=",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.envid = "",
		}
	},{
		.input = "ENVID=AABBCCDD",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.envid = "AABBCCDD",
		}
	},{
		.input = "ENVID=AA+2BBB+3DCC+2BDD",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.envid = "AA+BB=CC+DD",
		}
	/* RET */
	},{
		.input = "",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.ret = SMTP_PARAM_MAIL_RET_UNSPECIFIED,
		}
	},{
		.input = "RET=HDRS",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.ret = SMTP_PARAM_MAIL_RET_HDRS,
		}
	},{
		.input = "RET=FULL",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.ret = SMTP_PARAM_MAIL_RET_FULL,
		}
	/* SIZE */
	},{
		.input = "",
		.caps = SMTP_CAPABILITY_SIZE,
		.params = {
			.size = 0
		}
	},{
		.input = "SIZE=267914296",
		.caps = SMTP_CAPABILITY_SIZE,
		.params = {
			.size = 267914296
		}
	/* <extensions> */
	},{
		.input = "FROP=friep",
		.caps = SMTP_CAPABILITY_SIZE,
		.extensions = test_extensions,
		.params = {
			.extra_params = {
				.arr = {
					.buffer = &test_params_buffer1,
					.element_size = sizeof(struct smtp_param)
				}
			}
		}
	},{
		.input = "FROP=friep FRUP=frml",
		.extensions = test_extensions,
		.params = {
			.extra_params = {
				.arr = {
					.buffer = &test_params_buffer2,
					.element_size = sizeof(struct smtp_param)
				}
			}
		}
	}
};

unsigned int valid_mail_params_parse_test_count =
	N_ELEMENTS(valid_mail_params_parse_tests);

static void
test_smtp_mail_params_auth(const struct smtp_params_mail *test,
	const struct smtp_params_mail *parsed)
{
	if (parsed->auth->localpart == NULL ||
		test->auth->localpart == NULL) {
		test_out(t_strdup_printf("params.auth->localpart = %s",
					 parsed->auth->localpart),
			 (parsed->auth->localpart == test->auth->localpart));
	} else {
		test_out(t_strdup_printf("params.auth->localpart = \"%s\"",
					 parsed->auth->localpart),
			 strcmp(parsed->auth->localpart,
				test->auth->localpart) == 0);
	}
	if (parsed->auth->domain == NULL ||
		test->auth->domain == NULL) {
		test_out(t_strdup_printf("params.auth->domain = %s",
					 parsed->auth->domain),
			 (parsed->auth->domain == test->auth->domain));
	} else {
		test_out(t_strdup_printf("params.auth->domain = \"%s\"",
					 parsed->auth->domain),
			 strcmp(parsed->auth->domain,
				test->auth->domain) == 0);
	}
}

static void
test_smtp_mail_params_body(const struct smtp_params_mail *test,
	const struct smtp_params_mail *parsed)
{
	const char *type_name = NULL;

	switch (parsed->body.type) {
	case SMTP_PARAM_MAIL_BODY_TYPE_UNSPECIFIED:
		type_name = "<UNSPECIFIED>";
		break;
	case SMTP_PARAM_MAIL_BODY_TYPE_7BIT:
		type_name = "7BIT";
		break;
	case SMTP_PARAM_MAIL_BODY_TYPE_8BITMIME:
		type_name = "8BITMIME";
		break;
	case SMTP_PARAM_MAIL_BODY_TYPE_BINARYMIME:
		type_name = "BINARYMIME";
		break;
	case SMTP_PARAM_MAIL_BODY_TYPE_EXTENSION:
		type_name = parsed->body.ext;
		break;
	default:
		i_unreached();
	}

	test_out(t_strdup_printf("params.body.type = %s", type_name),
		(parsed->body.type == test->body.type &&
			(parsed->body.type != SMTP_PARAM_MAIL_BODY_TYPE_EXTENSION ||
				(parsed->body.ext != NULL &&
					strcmp(parsed->body.ext, test->body.ext) == 0))));
}

static void
test_smtp_mail_params_envid(const struct smtp_params_mail *test,
	const struct smtp_params_mail *parsed)
{
	if (parsed->envid == NULL ||
		test->envid == NULL) {
		test_out(t_strdup_printf("params.auth->localpart = %s",
					 parsed->envid),
			 (parsed->envid == test->envid));
	} else {
		test_out(t_strdup_printf("params.auth->localpart = \"%s\"",
					 parsed->envid),
			 strcmp(parsed->envid, test->envid) == 0);
	}
}

static void
test_smtp_mail_params_ret(const struct smtp_params_mail *test,
	const struct smtp_params_mail *parsed)
{
	const char *ret_name = NULL;

	switch (parsed->ret) {
	case SMTP_PARAM_MAIL_RET_UNSPECIFIED:
		ret_name = "<UNSPECIFIED>";
		break;
	case SMTP_PARAM_MAIL_RET_HDRS:
		ret_name = "HDRS";
		break;
	case SMTP_PARAM_MAIL_RET_FULL:
		ret_name = "FULL";
		break;
	default:
		i_unreached();
	}

	test_out(t_strdup_printf("params.ret = %s", ret_name),
		 parsed->ret == test->ret);
}

static void
test_smtp_mail_params_size(const struct smtp_params_mail *test,
	const struct smtp_params_mail *parsed)
{
	test_out(t_strdup_printf("params.size = %"PRIuUOFF_T, parsed->size),
		 parsed->size == test->size);
}

static void
test_smtp_mail_params_extensions(const struct smtp_params_mail *test,
	const struct smtp_params_mail *parsed)
{
	const struct smtp_param *tparam, *pparam;
	unsigned int i;

	if (!array_is_created(&test->extra_params) ||
		array_count(&test->extra_params) == 0) {
		test_out(t_strdup_printf("params.extra_params.count = %u",
			 (!array_is_created(&parsed->extra_params) ? 0 :
				array_count(&parsed->extra_params))),
			 (!array_is_created(&parsed->extra_params) ||
				array_count(&parsed->extra_params) == 0));
		return;
	}

	if (!array_is_created(&parsed->extra_params) ||
		array_count(&parsed->extra_params) == 0) {
		test_out("params.extra_params.count = 0", FALSE);
		return;
	}

	if (array_count(&test->extra_params) !=
		array_count(&parsed->extra_params)) {
		test_out(t_strdup_printf("params.extra_params.count = %u",
			 (!array_is_created(&parsed->extra_params) ? 0 :
				array_count(&parsed->extra_params))), FALSE);
		return;
	}

	for (i = 0; i < array_count(&test->extra_params); i++) {
		tparam = array_idx(&test->extra_params, i);
		pparam = array_idx(&parsed->extra_params, i);		
	
		test_out(t_strdup_printf(
			"params.extra_params[%u] = [\"%s\"=\"%s\"]", i,
				pparam->keyword, pparam->value),
			strcmp(pparam->keyword, tparam->keyword) == 0 &&
				((pparam->value == NULL && tparam->value == NULL) ||
				 (pparam->value != NULL && tparam->value != NULL &&
					strcmp(pparam->value, tparam->value) == 0)));
	}
}

static void test_smtp_mail_params_parse_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_mail_params_parse_test_count; i++) T_BEGIN {
		const struct valid_mail_params_parse_test *test;
		struct smtp_params_mail params;
		enum smtp_param_parse_error error_code;
		const char *error = NULL, *output;
		int ret;

		test = &valid_mail_params_parse_tests[i];
		ret = smtp_params_mail_parse(pool_datastack_create(),
			test->input, test->caps, test->extensions,
			test->body_extensions, &params, &error_code, &error);

		test_begin(t_strdup_printf("smtp mail params valid [%d]", i));
		test_out_reason(t_strdup_printf("parse(\"%s\")",
			test->input), ret >= 0, error);

		if (ret >= 0) {
			string_t *encoded;

			/* AUTH */
			if ((test->caps & SMTP_CAPABILITY_AUTH) != 0)
				test_smtp_mail_params_auth(&test->params, &params);
			/* BODY */
			if ((test->caps & SMTP_CAPABILITY_8BITMIME) != 0 ||
				(test->caps & SMTP_CAPABILITY_BINARYMIME) != 0)
				test_smtp_mail_params_body(&test->params, &params);
			/* ENVID */
			if ((test->caps & SMTP_CAPABILITY_DSN) != 0)
				test_smtp_mail_params_envid(&test->params, &params);
			/* RET */
			if ((test->caps & SMTP_CAPABILITY_DSN) != 0)
				test_smtp_mail_params_ret(&test->params, &params);
			/* SIZE */
			if ((test->caps & SMTP_CAPABILITY_SIZE) != 0)
				test_smtp_mail_params_size(&test->params, &params);
			/* <extensions> */
			if (test->extensions != NULL)
				test_smtp_mail_params_extensions(&test->params, &params);

			encoded = t_str_new(256);
			smtp_params_mail_write(encoded, test->caps, &params);

			output = (test->output == NULL ? test->input : test->output);
			test_out(t_strdup_printf
				("encode() = \"%s\"", str_c(encoded)),
				strcmp(str_c(encoded), output) == 0);
		}
		test_end();
	} T_END;
}

/* Invalid mail params tests */

struct invalid_mail_params_parse_test {
	const char *input;

	enum smtp_capability caps;
	const char *const *extensions;
};

static const struct invalid_mail_params_parse_test
invalid_mail_params_parse_tests[] = {
	/* AUTH */
	{
		.input = "AUTH=<>",
	},{
		.input = "AUTH=++",
		.caps = SMTP_CAPABILITY_AUTH
	/* BODY */
	},{
		.input = "BODY=8BITMIME",
	},{
		.input = "BODY=BINARYMIME",
	},{
		.input = "BODY=BINARYMIME",
		.caps = SMTP_CAPABILITY_BINARYMIME
	},{
		.input = "BODY=FROP",
		.caps = SMTP_CAPABILITY_8BITMIME
	/* ENVID */
	},{
		.input = "ENVID=AABBCC",
	},{
		.input = "ENVID=++",
		.caps = SMTP_CAPABILITY_DSN
	/* RET */
	},{
		.input = "RET=FULL",
	},{
		.input = "RET=HDR",
	},{
		.input = "RET=FROP",
		.caps = SMTP_CAPABILITY_DSN
	/* SIZE */
	},{
		.input = "SIZE=13",
	},{
		.input = "SIZE=ABC",
		.caps = SMTP_CAPABILITY_SIZE
	}
};

unsigned int invalid_mail_params_parse_test_count =
	N_ELEMENTS(invalid_mail_params_parse_tests);

static void test_smtp_mail_params_parse_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_mail_params_parse_test_count; i++) T_BEGIN {
		const struct invalid_mail_params_parse_test *test;
		struct smtp_params_mail params;
		enum smtp_param_parse_error error_code;
		const char *error = NULL;
		int ret;

		test = &invalid_mail_params_parse_tests[i];
		ret = smtp_params_mail_parse(pool_datastack_create(),
			test->input, test->caps, test->extensions, NULL,
			&params, &error_code, &error);

		test_begin(t_strdup_printf("smtp mail params invalid [%d]", i));
		test_out_reason(t_strdup_printf("parse(\"%s\")",
			test->input), ret < 0, error);
		test_end();
	} T_END;
}

/* Valid rcpt params tests */

struct valid_rcpt_params_parse_test {
	const char *input, *output;

	enum smtp_capability caps;
	const char *const *extensions;

	struct smtp_params_rcpt params;
};

static const struct valid_rcpt_params_parse_test
valid_rcpt_params_parse_tests[] = {
	/* AUTH */
	{
#if 0 // FIXME: message_address_parser() does not allow bare localpart
      //         addresses.
		.input = "ORCPT=rfc822;user+2Bdetail",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.orcpt = {
				.addr = &test_address2
			}
		}
	},{
#endif
		.input = "ORCPT=rfc822;e+3Dmc2@example.com",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.orcpt = {
				.addr = &test_address3
			}
		}
	/* NOTIFY */
	},{
		.input = "",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.notify = SMTP_PARAM_RCPT_NOTIFY_UNSPECIFIED,
		}
	},{
		.input = "NOTIFY=SUCCESS",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.notify = SMTP_PARAM_RCPT_NOTIFY_SUCCESS,
		}
	},{
		.input = "NOTIFY=FAILURE",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.notify = SMTP_PARAM_RCPT_NOTIFY_FAILURE,
		}
	},{
		.input = "NOTIFY=DELAY",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.notify = SMTP_PARAM_RCPT_NOTIFY_DELAY,
		}
	},{
		.input = "NOTIFY=NEVER",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.notify = SMTP_PARAM_RCPT_NOTIFY_NEVER,
		}
	},{
		.input = "NOTIFY=SUCCESS,FAILURE,DELAY",
		.caps = SMTP_CAPABILITY_DSN,
		.params = {
			.notify = SMTP_PARAM_RCPT_NOTIFY_SUCCESS |
				SMTP_PARAM_RCPT_NOTIFY_FAILURE |
				SMTP_PARAM_RCPT_NOTIFY_DELAY,
		}
	/* <extensions> */
	},{
		.input = "FROP=friep",
		.caps = SMTP_CAPABILITY_SIZE,
		.extensions = test_extensions,
		.params = {
			.extra_params = {
				.arr = {
					.buffer = &test_params_buffer1,
					.element_size = sizeof(struct smtp_param)
				}
			}
		}
	},{
		.input = "FROP=friep FRUP=frml",
		.extensions = test_extensions,
		.params = {
			.extra_params = {
				.arr = {
					.buffer = &test_params_buffer2,
					.element_size = sizeof(struct smtp_param)
				}
			}
		}
	}
};

unsigned int valid_rcpt_params_parse_test_count =
	N_ELEMENTS(valid_rcpt_params_parse_tests);

static void
test_smtp_rcpt_params_orcpt(const struct smtp_params_rcpt *test,
	const struct smtp_params_rcpt *parsed)
{
	if (parsed->orcpt.addr == NULL) {
		test_out("params.orcpt.addr = NULL",
			test->orcpt.addr == NULL);
		return;
	}
		
	if (parsed->orcpt.addr->localpart == NULL ||
		test->orcpt.addr->localpart == NULL) {
		test_out(t_strdup_printf("params.orcpt.addr->localpart = %s",
					 parsed->orcpt.addr->localpart),
			 (parsed->orcpt.addr->localpart ==
				test->orcpt.addr->localpart));
	} else {
		test_out(t_strdup_printf("params.orcpt.addr->localpart = \"%s\"",
					 parsed->orcpt.addr->localpart),
			 strcmp(parsed->orcpt.addr->localpart,
				test->orcpt.addr->localpart) == 0);
	}
	if (parsed->orcpt.addr->domain == NULL ||
		test->orcpt.addr->domain == NULL) {
		test_out(t_strdup_printf("params.orcpt.addr->domain = %s",
					 parsed->orcpt.addr->domain),
			 (parsed->orcpt.addr->domain ==
				test->orcpt.addr->domain));
	} else {
		test_out(t_strdup_printf("params.orcpt.addr->domain = \"%s\"",
					 parsed->orcpt.addr->domain),
			 strcmp(parsed->orcpt.addr->domain,
				test->orcpt.addr->domain) == 0);
	}
}


static void
test_smtp_rcpt_params_notify(const struct smtp_params_rcpt *test,
	const struct smtp_params_rcpt *parsed)
{
	string_t *notify_name;

	notify_name = t_str_new(64);
	if (parsed->notify == 0) {
		str_append(notify_name, "<UNSPECIFIED>");
	} else if ((parsed->notify & SMTP_PARAM_RCPT_NOTIFY_NEVER) != 0) {
		i_assert((parsed->notify & SMTP_PARAM_RCPT_NOTIFY_SUCCESS) == 0);
		i_assert((parsed->notify & SMTP_PARAM_RCPT_NOTIFY_FAILURE) == 0);
		i_assert((parsed->notify & SMTP_PARAM_RCPT_NOTIFY_DELAY) == 0);
		str_append(notify_name, "NEVER");
	} else {
		if ((parsed->notify & SMTP_PARAM_RCPT_NOTIFY_SUCCESS) != 0)
			str_append(notify_name, "SUCCESS");
		if ((parsed->notify & SMTP_PARAM_RCPT_NOTIFY_FAILURE) != 0) {
			if (str_len(notify_name) > 0)
				str_append_c(notify_name, ',');
			str_append(notify_name, "FAILURE");
		}
		if ((parsed->notify & SMTP_PARAM_RCPT_NOTIFY_DELAY) != 0) {
			if (str_len(notify_name) > 0)
				str_append_c(notify_name, ',');
			str_append(notify_name, "DELAY");
		}
	}

	test_out(t_strdup_printf("params.notify = %s", str_c(notify_name)),
		 parsed->notify == test->notify);
}

static void
test_smtp_rcpt_params_extensions(const struct smtp_params_rcpt *test,
	const struct smtp_params_rcpt *parsed)
{
	const struct smtp_param *tparam, *pparam;
	unsigned int i;

	if (!array_is_created(&test->extra_params) ||
		array_count(&test->extra_params) == 0) {
		test_out(t_strdup_printf("params.extra_params.count = %u",
			 (!array_is_created(&parsed->extra_params) ? 0 :
				array_count(&parsed->extra_params))),
			 (!array_is_created(&parsed->extra_params) ||
				array_count(&parsed->extra_params) == 0));
		return;
	}

	if (!array_is_created(&parsed->extra_params) ||
		array_count(&parsed->extra_params) == 0) {
		test_out("params.extra_params.count = 0", FALSE);
		return;
	}

	if (array_count(&test->extra_params) !=
		array_count(&parsed->extra_params)) {
		test_out(t_strdup_printf("params.extra_params.count = %u",
			 (!array_is_created(&parsed->extra_params) ? 0 :
				array_count(&parsed->extra_params))), FALSE);
		return;
	}

	for (i = 0; i < array_count(&test->extra_params); i++) {
		tparam = array_idx(&test->extra_params, i);
		pparam = array_idx(&parsed->extra_params, i);		
	
		test_out(t_strdup_printf(
				"params.extra_params[%u] = [\"%s\"=\"%s\"]", i,
				pparam->keyword, pparam->value),
			 strcmp(pparam->keyword, tparam->keyword) == 0 &&
				((pparam->value == NULL && tparam->value == NULL) ||
				 (pparam->value != NULL && tparam->value != NULL &&
					strcmp(pparam->value, tparam->value) == 0)));
	}
}

static void test_smtp_rcpt_params_parse_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_rcpt_params_parse_test_count; i++) T_BEGIN {
		const struct valid_rcpt_params_parse_test *test;
		struct smtp_params_rcpt params;
		enum smtp_param_parse_error error_code;
		const char *error = NULL, *output;
		int ret;

		test = &valid_rcpt_params_parse_tests[i];
		ret = smtp_params_rcpt_parse(pool_datastack_create(),
			test->input, test->caps, test->extensions,
			&params, &error_code, &error);

		test_begin(t_strdup_printf("smtp rcpt params valid [%d]", i));
		test_out_reason(t_strdup_printf("parse(\"%s\")",
			test->input), ret >= 0, error);

		if (ret >= 0) {
			string_t *encoded;

			/* ORCPT */
			if ((test->caps & SMTP_CAPABILITY_DSN) != 0)
				test_smtp_rcpt_params_orcpt(&test->params, &params);
			/* NOTIFY */
			if ((test->caps & SMTP_CAPABILITY_DSN) != 0)
				test_smtp_rcpt_params_notify(&test->params, &params);
			/* <extensions> */
			if (test->extensions != NULL)
				test_smtp_rcpt_params_extensions(&test->params, &params);

			encoded = t_str_new(256);
			smtp_params_rcpt_write(encoded, test->caps, &params);

			output = (test->output == NULL ? test->input : test->output);
			test_out(t_strdup_printf("encode() = \"%s\"",
						 str_c(encoded)),
				 strcmp(str_c(encoded), output) == 0);
		}
		test_end();
	} T_END;
}

/* Invalid rcpt params tests */

struct invalid_rcpt_params_parse_test {
	const char *input;

	enum smtp_capability caps;
	const char *const *extensions;
};

static const struct invalid_rcpt_params_parse_test
invalid_rcpt_params_parse_tests[] = {
	/* DSN */
	{
		.input = "ORCPT=rfc822;frop@example.com",
	},{
		.input = "ORCPT=++",
		.caps = SMTP_CAPABILITY_DSN
	},{
		.input = "ORCPT=rfc822;++",
		.caps = SMTP_CAPABILITY_DSN
	},{
		.input = "NOTIFY=SUCCESS",
	},{
		.input = "NOTIFY=FROP",
		.caps = SMTP_CAPABILITY_DSN
	},{
		.input = "NOTIFY=NEVER,SUCCESS",
		.caps = SMTP_CAPABILITY_DSN
	}
};

unsigned int invalid_rcpt_params_parse_test_count =
	N_ELEMENTS(invalid_rcpt_params_parse_tests);

static void test_smtp_rcpt_params_parse_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_rcpt_params_parse_test_count; i++) T_BEGIN {
		const struct invalid_rcpt_params_parse_test *test;
		struct smtp_params_rcpt params;
		enum smtp_param_parse_error error_code;
		const char *error = NULL;
		int ret;

		test = &invalid_rcpt_params_parse_tests[i];
		ret = smtp_params_rcpt_parse(pool_datastack_create(),
			test->input, test->caps, test->extensions,
			&params, &error_code, &error);

		test_begin(t_strdup_printf("smtp rcpt params invalid [%d]", i));
		test_out_reason(t_strdup_printf("parse(\"%s\")",
			test->input), ret < 0, error);
		test_end();
	} T_END;
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_smtp_mail_params_parse_valid,
		test_smtp_mail_params_parse_invalid,
		test_smtp_rcpt_params_parse_valid,
		test_smtp_rcpt_params_parse_invalid,
		NULL
	};
	return test_run(test_functions);
}
