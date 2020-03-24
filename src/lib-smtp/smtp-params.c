/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "message-address.h"
#include "smtp-common.h"
#include "smtp-parser.h"
#include "smtp-syntax.h"
#include "smtp-address.h"

#include "smtp-params.h"

#include <ctype.h>

/*
 * SMTP parameter parsing
 */

static int
smtp_param_do_parse(struct smtp_parser *parser, struct smtp_param *param_r)
{
	const unsigned char *pbegin = parser->cur;

	/* esmtp-param    = esmtp-keyword ["=" esmtp-value]
	   esmtp-keyword  = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
	   esmtp-value    = 1*(%d33-60 / %d62-126)
	                  ; any CHAR excluding "=", SP, and control
	                  ; characters.  If this string is an email address,
	                  ; i.e., a Mailbox, then the "xtext" syntax [32]
	                  ; SHOULD be used.
	 */

	if (parser->cur >= parser->end || !i_isalnum(*parser->cur)) {
		parser->error = "Unexpected character in parameter keyword";
		return -1;
	}
	parser->cur++;

	while (parser->cur < parser->end &&
	       (i_isalnum(*parser->cur) || *parser->cur == '-'))
		parser->cur++;
	param_r->keyword = t_strndup(pbegin, parser->cur - pbegin);

	if (parser->cur >= parser->end) {
		param_r->value = NULL;
		return 1;
	}
	if (*parser->cur != '=') {
		parser->error = "Unexpected character in parameter keyword";
		return -1;
	}
	parser->cur++;

	pbegin = parser->cur;
	while (parser->cur < parser->end &&
	       smtp_char_is_esmtp_value(*parser->cur))
		parser->cur++;

	if (parser->cur < parser->end) {
		parser->error = "Unexpected character in parameter value";
		return -1;
	}
	param_r->value = t_strndup(pbegin, parser->cur - pbegin);
	return 1;
}

int smtp_param_parse(pool_t pool, const char *text,
		     struct smtp_param *param_r, const char **error_r)
{
	struct smtp_parser parser;

	i_zero(param_r);

	if (text == NULL || *text == '\0') {
		if (error_r != NULL)
			*error_r = "Parameter is empty";
		return -1;
	}

	smtp_parser_init(&parser, pool, text);

	if (smtp_param_do_parse(&parser, param_r) <= 0) {
		if (error_r != NULL)
			*error_r = parser.error;
		return -1;
	}
	return 1;
}

static bool smtp_param_value_valid(const char *value)
{
	const char *p = value;

	while (*p != '\0' && smtp_char_is_esmtp_value(*p))
		p++;
	return (*p == '\0');
}

void smtp_param_write(string_t *out, const struct smtp_param *param)
{
	str_append(out, t_str_ucase(param->keyword));
	if (param->value != NULL) {
		i_assert(smtp_param_value_valid(param->value));
		str_append_c(out, '=');
		str_append(out, param->value);
	}
}

/*
 * MAIL parameters
 */

/* parse */

struct smtp_params_mail_parser {
	pool_t pool;
	struct smtp_params_mail *params;
	enum smtp_capability caps;

	enum smtp_param_parse_error error_code;
	const char *error;
};

static int
smtp_params_mail_parse_auth(struct smtp_params_mail_parser *pmparser,
			    const char *xtext)
{
	struct smtp_params_mail *params = pmparser->params;
	struct smtp_address *auth_addr;
	const char *value, *error;

	/* AUTH=: RFC 4954, Section 5

	   We ignore this parameter, but we do check it for validity
	 */

	/* cannot specify this multiple times */
	if (params->auth != NULL) {
		pmparser->error = "Duplicate AUTH= parameter";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	/* value required */
	if (xtext == NULL) {
		pmparser->error = "Missing AUTH= parameter value";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	if (smtp_xtext_parse(xtext, &value, &error) < 0) {
		pmparser->error = t_strdup_printf(
			"Invalid AUTH= parameter value: %s", error);
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	if (strcmp(value, "<>") == 0) {
		params->auth = p_new(pmparser->pool, struct smtp_address, 1);
	} else if (smtp_address_parse_mailbox(
			pmparser->pool,	value,
			SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART,
			&auth_addr, &error) < 0)	{
		pmparser->error = t_strdup_printf(
			"Invalid AUTH= address value: %s", error);
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	} else {
		params->auth = auth_addr;
	}
	/* ignore, our own AUTH data is added below */
	return 0;
}

static int
smtp_params_mail_parse_body(struct smtp_params_mail_parser *pmparser,
			    const char *value, const char *const *extensions)
{
	struct smtp_params_mail *params = pmparser->params;
	enum smtp_capability caps = pmparser->caps;

	/* BODY=<type>: RFC 6152 */

	/* cannot specify this multiple times */
	if (params->body.type != SMTP_PARAM_MAIL_BODY_TYPE_UNSPECIFIED) {
		pmparser->error = "Duplicate BODY= parameter";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	/* value required */
	if (value == NULL) {
		pmparser->error = "Missing BODY= parameter value";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}

	value = t_str_ucase(value);
	params->body.ext = NULL;
	/* =7BIT: RFC 6152 */
	if (strcmp(value, "7BIT") == 0) {
		params->body.type = SMTP_PARAM_MAIL_BODY_TYPE_7BIT;
	/* =8BITMIME: RFC 6152 */
	} else if ((caps & SMTP_CAPABILITY_8BITMIME) != 0 &&
		   strcmp(value, "8BITMIME") == 0) {
		params->body.type = SMTP_PARAM_MAIL_BODY_TYPE_8BITMIME;
	/* =BINARYMIME: RFC 3030 */
	} else if ((caps & SMTP_CAPABILITY_BINARYMIME) != 0 &&
		   (caps & SMTP_CAPABILITY_CHUNKING) != 0 &&
		   strcmp(value, "BINARYMIME") == 0) {
		params->body.type = SMTP_PARAM_MAIL_BODY_TYPE_BINARYMIME;
	/* =?? */
	} else if (extensions != NULL &&
		   str_array_icase_find(extensions, value)) {
		params->body.type = SMTP_PARAM_MAIL_BODY_TYPE_EXTENSION;
		params->body.ext = p_strdup(pmparser->pool, value);
	} else {
		pmparser->error = "Unsupported mail BODY type";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_NOT_SUPPORTED;
		return -1;
	}
	return 0;
}

static int
smtp_params_mail_parse_envid(struct smtp_params_mail_parser *pmparser,
			     const char *xtext)
{
	struct smtp_params_mail *params = pmparser->params;
	const unsigned char *p, *pend;
	const char *envid, *error;

	/* ENVID=<envid>: RFC 3461 */

	/* cannot specify this multiple times */
	if (params->envid != NULL) {
		pmparser->error = "Duplicate ENVID= parameter";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	/* value required */
	if (xtext == NULL) {
		pmparser->error = "Missing ENVID= parameter value";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	/* check xtext */
	if (smtp_xtext_parse(xtext, &envid, &error) < 0) {
		pmparser->error = t_strdup_printf(
			"Invalid ENVID= parameter value: %s", error);
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	/* RFC 3461, Section 4.4:

	   Due to limitations in the Delivery Status Notification format, the
	   value of the ENVID parameter prior to encoding as "xtext" MUST
	   consist entirely of printable (graphic and white space) characters
	   from the US-ASCII repertoire.
	 */
	p = (const unsigned char *)envid;
	pend = p + strlen(envid);
	while (p < pend && smtp_char_is_textstr(*p))
		p++;
	if (p < pend) {
		pmparser->error =
			"Invalid ENVID= parameter value: "
			"Contains non-printable characters";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	params->envid = p_strdup(pmparser->pool, envid);
	return 0;
}

static int
smtp_params_mail_parse_ret(struct smtp_params_mail_parser *pmparser,
			   const char *value)
{
	struct smtp_params_mail *params = pmparser->params;

	/* RET=<keyword>: RFC 3461 */

	/* cannot specify this multiple times */
	if (params->ret != SMTP_PARAM_MAIL_RET_UNSPECIFIED) {
		pmparser->error = "Duplicate RET= parameter";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	/* value required */
	if (value == NULL) {
		pmparser->error = "Missing RET= parameter value";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}

	value = t_str_ucase(value);
	/* =FULL */
	if (strcmp(value, "FULL") == 0) {
		params->ret = SMTP_PARAM_MAIL_RET_FULL;
	/* =HDRS */
	} else if (strcmp(value, "HDRS") == 0) {
		params->ret = SMTP_PARAM_MAIL_RET_HDRS;
	} else {
		pmparser->error = "Unsupported RET= parameter keyword";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_NOT_SUPPORTED;
		return -1;
	}
	return 0;
}

static int
smtp_params_mail_parse_size(struct smtp_params_mail_parser *pmparser,
			    const char *value)
{
	struct smtp_params_mail *params = pmparser->params;

	/* SIZE=<size-value>: RFC 1870 */

	/* cannot specify this multiple times */
	if (params->size != 0) {
		pmparser->error = "Duplicate SIZE= parameter";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	/* value required */
	if (value == NULL) {
		pmparser->error = "Missing SIZE= parameter value";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}

	/* size-value ::= 1*20DIGIT */
	if (str_to_uoff(value, &params->size) < 0) {
		pmparser->error = "Unsupported SIZE parameter value";
		pmparser->error_code = SMTP_PARAM_PARSE_ERROR_NOT_SUPPORTED;
		return -1;
	}
	return 0;
}

int smtp_params_mail_parse(pool_t pool, const char *args,
			   enum smtp_capability caps,
			   const char *const *extensions,
			   const char *const *body_extensions,
			   struct smtp_params_mail *params_r,
			   enum smtp_param_parse_error *error_code_r,
			   const char **error_r)
{
	struct smtp_params_mail_parser pmparser;
	struct smtp_param param;
	const char *const *argv;
	const char *error;
	int ret = 0;

	i_zero(params_r);

	i_zero(&pmparser);
	pmparser.pool = pool;
	pmparser.params = params_r;
	pmparser.caps = caps;

	argv = t_strsplit(args, " ");
	for (; *argv != NULL; argv++) {
		if (smtp_param_parse(pool_datastack_create(), *argv,
				     &param, &error) < 0) {
			*error_r = t_strdup_printf(
				"Invalid MAIL parameter: %s", error);
			*error_code_r = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
			return -1;
		}

		/* parse known parameters */
		param.keyword = t_str_ucase(param.keyword);
		if ((caps & SMTP_CAPABILITY_AUTH) != 0 &&
		    strcmp(param.keyword, "AUTH") == 0) {
			if (smtp_params_mail_parse_auth(
				&pmparser, param.value) < 0) {
				ret = -1;
				break;
			}
		} else if (strcmp(param.keyword, "BODY") == 0) {
			if (smtp_params_mail_parse_body(&pmparser, param.value,
							body_extensions) < 0) {
				ret = -1;
				break;
			}
		} else if ((caps & SMTP_CAPABILITY_DSN) != 0 &&
			   strcmp(param.keyword, "ENVID") == 0) {
			if (smtp_params_mail_parse_envid(&pmparser,
							 param.value) < 0) {
				ret = -1;
				break;
			}
		} else if ((caps & SMTP_CAPABILITY_DSN) != 0 &&
			   strcmp(param.keyword, "RET") == 0) {
			if (smtp_params_mail_parse_ret(&pmparser,
						       param.value) < 0) {
				ret = -1;
				break;
			}
		} else if ((caps & SMTP_CAPABILITY_SIZE) != 0 &&
			   strcmp(param.keyword, "SIZE") == 0) {
			if (smtp_params_mail_parse_size(&pmparser,
							param.value) < 0) {
				ret = -1;
				break;
			}
		} else if (extensions != NULL &&
			   str_array_icase_find(extensions, param.keyword)) {
			/* add the rest to ext_param for specific
			   applications */
			smtp_params_mail_add_extra(params_r, pool,
						   param.keyword, param.value);
		} else {
			/* RFC 5321, Section 4.1.1.11:
			   If the server SMTP does not recognize or cannot
			   implement one or more of the parameters associated
			   with a particular MAIL FROM or RCPT TO command, it
			   will return code 555. */
			*error_r = "Unsupported parameters";
			*error_code_r = SMTP_PARAM_PARSE_ERROR_NOT_SUPPORTED;
			return -1;
		}
	}

	if (ret < 0) {
		*error_r = pmparser.error;
		*error_code_r = pmparser.error_code;
	}
	return ret;
}

/* manipulate */

void smtp_params_mail_copy(pool_t pool, struct smtp_params_mail *dst,
			   const struct smtp_params_mail *src)
{
	i_zero(dst);

	if (src == NULL)
		return;

	dst->auth = smtp_address_clone(pool, src->auth);
	dst->body.type = src->body.type;
	dst->body.ext = p_strdup(pool, src->body.ext);
	dst->envid = p_strdup(pool, src->envid);
	dst->ret = src->ret;
	dst->size = src->size;

	if (array_is_created(&src->extra_params)) {
		const struct smtp_param *param;
		struct smtp_param param_new;

		p_array_init(&dst->extra_params, pool,
			     array_count(&src->extra_params));
		array_foreach(&src->extra_params, param) {
			param_new.keyword = p_strdup(pool, param->keyword);
			param_new.value = p_strdup(pool, param->value);
			array_push_back(&dst->extra_params, &param_new);
		}
	}
}

void smtp_params_mail_add_extra(struct smtp_params_mail *params, pool_t pool,
				const char *keyword, const char *value)
{
	struct smtp_param param;

	if (!array_is_created(&params->extra_params))
		p_array_init(&params->extra_params, pool, 4);

	i_zero(&param);
	param.keyword = p_strdup(pool, keyword);
	param.value = p_strdup(pool, value);
	array_push_back(&params->extra_params, &param);
}

bool smtp_params_mail_drop_extra(struct smtp_params_mail *params,
				 const char *keyword, const char **value_r)
{
	const struct smtp_param *param;

	if (!array_is_created(&params->extra_params))
		return FALSE;

	array_foreach(&params->extra_params, param) {
		if (strcasecmp(param->keyword, keyword) == 0) {
			if (value_r != NULL)
				*value_r = param->value;
			array_delete(&params->extra_params,
				     array_foreach_idx(&params->extra_params,
						       param), 1);
			return TRUE;
		}
	}
	return FALSE;
}

/* write */

static void
smtp_params_mail_write_auth(string_t *buffer, enum smtp_capability caps,
			    const struct smtp_params_mail *params)
{
	/* add AUTH= parameter */
	string_t *auth_addr;

	if (params->auth == NULL)
		return;
	if ((caps & SMTP_CAPABILITY_AUTH) == 0)
		return;

	auth_addr = t_str_new(256);

	if (params->auth->localpart == NULL)
		str_append(auth_addr, "<>");
	else
		smtp_address_write(auth_addr, params->auth);
	str_append(buffer, "AUTH=");
	smtp_xtext_encode(buffer, str_data(auth_addr), str_len(auth_addr));
	str_append_c(buffer, ' ');
}

static void
smtp_params_mail_write_body(string_t *buffer, enum smtp_capability caps,
			    const struct smtp_params_mail *params)
{
	/* BODY=<type>: RFC 6152 */
	/* =7BIT: RFC 6152 */
	switch (params->body.type) {
	case SMTP_PARAM_MAIL_BODY_TYPE_UNSPECIFIED:
		break;
	case SMTP_PARAM_MAIL_BODY_TYPE_7BIT:
		str_append(buffer, "BODY=7BIT ");
		break;
	/* =8BITMIME: RFC 6152 */
	case SMTP_PARAM_MAIL_BODY_TYPE_8BITMIME:
		i_assert((caps & SMTP_CAPABILITY_8BITMIME) != 0);
		str_append(buffer, "BODY=8BITMIME ");
		break;
	/* =BINARYMIME: RFC 3030 */
	case SMTP_PARAM_MAIL_BODY_TYPE_BINARYMIME:
		i_assert((caps & SMTP_CAPABILITY_BINARYMIME) != 0 &&
			 (caps & SMTP_CAPABILITY_CHUNKING) != 0);
		str_append(buffer, "BODY=BINARYMIME ");
		break;
	case SMTP_PARAM_MAIL_BODY_TYPE_EXTENSION:
		str_append(buffer, "BODY=");
		str_append(buffer, params->body.ext);
		str_append_c(buffer, ' ');
		break;
	default:
		i_unreached();
	}
}

static void
smtp_params_mail_write_envid(string_t *buffer, enum smtp_capability caps,
			     const struct smtp_params_mail *params)
{
	const char *envid = params->envid;

	/* ENVID=<envid>: RFC 3461 */

	if (envid == NULL)
		return;
	if ((caps & SMTP_CAPABILITY_DSN) == 0)
		return;

	str_append(buffer, "ENVID=");
	smtp_xtext_encode(buffer, (const unsigned char *)envid, strlen(envid));
	str_append_c(buffer, ' ');
}

static void
smtp_params_mail_write_ret(string_t *buffer, enum smtp_capability caps,
			   const struct smtp_params_mail *params)
{
	if ((caps & SMTP_CAPABILITY_DSN) == 0)
		return;
	/* RET=<keyword>: RFC 3461 */
	switch (params->ret) {
	case SMTP_PARAM_MAIL_RET_UNSPECIFIED:
		break;
	case SMTP_PARAM_MAIL_RET_HDRS:
		str_append(buffer, "RET=HDRS ");
		break;
	case SMTP_PARAM_MAIL_RET_FULL:
		str_append(buffer, "RET=FULL ");
		break;
	default:
		i_unreached();
	}
}

static void
smtp_params_mail_write_size(string_t *buffer, enum smtp_capability caps,
			    const struct smtp_params_mail *params)
{
	/* SIZE=<size-value>: RFC 1870 */

	if (params->size == 0)
		return;
	if ((caps & SMTP_CAPABILITY_SIZE) == 0)
		return;

	/* proxy the SIZE parameter (account for additional size) */
	str_printfa(buffer, "SIZE=%"PRIuUOFF_T" ", params->size);
}

void smtp_params_mail_write(string_t *buffer, enum smtp_capability caps,
			    const struct smtp_params_mail *params)
{
	size_t init_len = str_len(buffer);

	smtp_params_mail_write_auth(buffer, caps, params);
	smtp_params_mail_write_body(buffer, caps, params);
	smtp_params_mail_write_envid(buffer, caps, params);
	smtp_params_mail_write_ret(buffer, caps, params);
	smtp_params_mail_write_size(buffer, caps, params);

	if (array_is_created(&params->extra_params)) {
		const struct smtp_param *param;

		array_foreach(&params->extra_params, param) {
			smtp_param_write(buffer, param);
			str_append_c(buffer, ' ');
		}
	}

	if (str_len(buffer) > init_len)
		str_truncate(buffer, str_len(buffer)-1);
}

/* evaluate */

const struct smtp_param *
smtp_params_mail_get_extra(const struct smtp_params_mail *params,
			   const char *keyword)
{
	const struct smtp_param *param;

	if (!array_is_created(&params->extra_params))
		return NULL;

	array_foreach(&params->extra_params, param) {
		if (strcasecmp(param->keyword, keyword) == 0)
			return param;
	}
	return NULL;
}

/* events */

static void
smtp_params_mail_add_auth_to_event(const struct smtp_params_mail *params,
				   struct event *event)
{
	/* AUTH: RFC 4954 */
	if (params->auth == NULL)
		return;

	event_add_str(event, "mail_param_auth",
		      smtp_address_encode(params->auth));
}

static void
smtp_params_mail_add_body_to_event(const struct smtp_params_mail *params,
				   struct event *event)
{
	/* BODY: RFC 6152 */
	switch (params->body.type) {
	case SMTP_PARAM_MAIL_BODY_TYPE_UNSPECIFIED:
		break;
	case SMTP_PARAM_MAIL_BODY_TYPE_7BIT:
		event_add_str(event, "mail_param_body", "7BIT");
		break;
	case SMTP_PARAM_MAIL_BODY_TYPE_8BITMIME:
		event_add_str(event, "mail_param_body", "8BITMIME");
		break;
	case SMTP_PARAM_MAIL_BODY_TYPE_BINARYMIME:
		event_add_str(event, "mail_param_body", "BINARYMIME");
		break;
	case SMTP_PARAM_MAIL_BODY_TYPE_EXTENSION:
		event_add_str(event, "mail_param_body", params->body.ext);
		break;
	default:
		i_unreached();
	}
}

static void
smtp_params_mail_add_envid_to_event(const struct smtp_params_mail *params,
				    struct event *event)
{
	/* ENVID: RFC 3461, Section 4.4 */
	if (params->envid == NULL)
		return;

	event_add_str(event, "mail_param_envid", params->envid);
}

static void
smtp_params_mail_add_ret_to_event(const struct smtp_params_mail *params,
				  struct event *event)
{
	/* RET: RFC 3461, Section 4.3 */
	switch (params->ret) {
	case SMTP_PARAM_MAIL_RET_UNSPECIFIED:
		break;
	case SMTP_PARAM_MAIL_RET_HDRS:
		event_add_str(event, "mail_param_ret", "HDRS");
		break;
	case SMTP_PARAM_MAIL_RET_FULL:
		event_add_str(event, "mail_param_ret", "FULL");
		break;
	default:
		i_unreached();
	}
}

static void
smtp_params_mail_add_size_to_event(const struct smtp_params_mail *params,
				   struct event *event)
{
	/* SIZE: RFC 1870 */
	if (params->size == 0)
		return;

	event_add_int(event, "mail_param_size", params->size);
}

void smtp_params_mail_add_to_event(const struct smtp_params_mail *params,
				   struct event *event)
{
	smtp_params_mail_add_auth_to_event(params, event);
	smtp_params_mail_add_body_to_event(params, event);
	smtp_params_mail_add_envid_to_event(params, event);
	smtp_params_mail_add_ret_to_event(params, event);
	smtp_params_mail_add_size_to_event(params, event);
}

/*
 * RCPT parameters
 */

/* parse */

struct smtp_params_rcpt_parser {
	pool_t pool;
	struct smtp_params_rcpt *params;
	enum smtp_param_rcpt_parse_flags flags;
	enum smtp_capability caps;

	enum smtp_param_parse_error error_code;
	const char *error;
};

static int
smtp_params_rcpt_parse_notify(struct smtp_params_rcpt_parser *prparser,
			      const char *value)
{
	struct smtp_params_rcpt *params = prparser->params;
	const char *const *list;
	bool valid, unsupported;

	/* NOTIFY=<type>: RFC 3461

	   notify-esmtp-value = "NEVER" / 1#notify-list-element
	   notify-list-element = "SUCCESS" / "FAILURE" / "DELAY"

	   We check and normalize this parameter.
	*/

	/* cannot specify this multiple times */
	if (params->notify != SMTP_PARAM_RCPT_NOTIFY_UNSPECIFIED) {
		prparser->error = "Duplicate NOTIFY= parameter";
		prparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	/* value required */
	if (value == NULL) {
		prparser->error = "Missing NOTIFY= parameter value";
		prparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}

	valid = TRUE;
	unsupported = FALSE;
	list = t_strsplit(value, ","); /* RFC 822, Section 2.7 */
	while (*list != NULL) {
		if (**list != '\0') {
			/* NEVER */
			if (strcasecmp(*list, "NEVER") == 0) {
				if (params->notify != SMTP_PARAM_RCPT_NOTIFY_UNSPECIFIED)
					valid = FALSE;
				params->notify = SMTP_PARAM_RCPT_NOTIFY_NEVER;
			/* SUCCESS */
			} else if (strcasecmp(*list, "SUCCESS") == 0) {
				if ((params->notify & SMTP_PARAM_RCPT_NOTIFY_NEVER) != 0)
					valid = FALSE;
				params->notify |= SMTP_PARAM_RCPT_NOTIFY_SUCCESS;
			/* FAILURE */
			} else if (strcasecmp(*list, "FAILURE") == 0) {
				if ((params->notify & SMTP_PARAM_RCPT_NOTIFY_NEVER) != 0)
					valid = FALSE;
				params->notify |= SMTP_PARAM_RCPT_NOTIFY_FAILURE;
			/* DELAY */
			} else if (strcasecmp(*list, "DELAY") == 0) {
				if ((params->notify & SMTP_PARAM_RCPT_NOTIFY_NEVER) != 0)
					valid = FALSE;
				params->notify |= SMTP_PARAM_RCPT_NOTIFY_DELAY;
			} else {
				unsupported = TRUE;
			}
		}
		list++;
	}

	if (!valid || unsupported ||
	    params->notify == SMTP_PARAM_RCPT_NOTIFY_UNSPECIFIED) {
		prparser->error = "Invalid NOTIFY= parameter value";
		prparser->error_code = ((valid && unsupported) ?
					SMTP_PARAM_PARSE_ERROR_NOT_SUPPORTED :
					SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX);
		return -1;
	}
	return 0;
}

static int
smtp_params_rcpt_parse_orcpt_rfc822(struct smtp_params_rcpt_parser *prparser,
				    const char *addr_str, pool_t pool,
				    const struct smtp_address **addr_r)
{
	struct message_address *rfc822_addr;
	struct smtp_address *addr;

	rfc822_addr = message_address_parse(pool_datastack_create(),
					    (const unsigned char *)addr_str,
					    strlen(addr_str), 2, 0);
	if (rfc822_addr == NULL || rfc822_addr->next != NULL)
		return -1;
	if (rfc822_addr->invalid_syntax) {
		if (HAS_NO_BITS(prparser->flags,
				SMTP_PARAM_RCPT_FLAG_ORCPT_ALLOW_LOCALPART) ||
		    rfc822_addr->mailbox == NULL ||
		    *rfc822_addr->mailbox == '\0')
			return -1;
		rfc822_addr->invalid_syntax = FALSE;
	}
	if (smtp_address_create_from_msg(pool, rfc822_addr, &addr) < 0)
		return -1;
	*addr_r = addr;
	return 0;
}

static int
smtp_params_rcpt_parse_orcpt(struct smtp_params_rcpt_parser *prparser,
			     const char *value)
{
	struct smtp_params_rcpt *params = prparser->params;
	struct smtp_parser parser;
	const unsigned char *p, *pend;
	string_t *address;
	const char *addr_type;
	int ret;

	/* ORCPT=<address>: RFC 3461

	   orcpt-parameter = "ORCPT=" original-recipient-address
	   original-recipient-address = addr-type ";" xtext
	   addr-type = atom

	   We check and normalize this parameter.
	*/

	/* cannot specify this multiple times */
	if (params->orcpt.addr_type != NULL) {
		prparser->error = "Duplicate ORCPT= parameter";
		prparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	/* value required */
	if (value == NULL) {
		prparser->error = "Missing ORCPT= parameter value";
		prparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}

	/* check addr-type */
	smtp_parser_init(&parser, pool_datastack_create(), value);
	if (smtp_parser_parse_atom(&parser, &addr_type) <= 0 ||
	    parser.cur >= parser.end || *parser.cur != ';') {
		prparser->error = "Invalid addr-type for ORCPT= parameter";
		prparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}
	params->orcpt.addr_type = p_strdup(prparser->pool, addr_type);
	parser.cur++;

	/* check xtext */
	address = t_str_new(256);
	if ((ret=smtp_parser_parse_xtext(&parser, address)) <= 0 ||
		parser.cur < parser.end) {
		if (ret < 0) {
			prparser->error = t_strdup_printf(
				"Invalid ORCPT= parameter: %s",
				parser.error);
			prparser->error_code =
				SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		} else if (parser.cur < parser.end) {
			prparser->error = "Invalid ORCPT= parameter: "
				"Invalid character in xtext";
			prparser->error_code =
				SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		} else {
			prparser->error = "Invalid ORCPT= parameter: "
				"Empty address value";
			prparser->error_code =
				SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		}
		return -1;
	}

	/* RFC 3461, Section 4.2:

	   Due to limitations in the Delivery Status Notification format, the
	   value of the original recipient address prior to encoding as "xtext"
	   MUST consist entirely of printable (graphic and white space)
	   characters from the US-ASCII repertoire.
	 */
	p = str_data(address);
	pend = p + str_len(address);
	while (p < pend && smtp_char_is_textstr(*p))
		p++;
	if (p < pend) {
		prparser->error =
			"Invalid ORCPT= address value: "
			"Contains non-printable characters";
		prparser->error_code = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
		return -1;
	}

	params->orcpt.addr_raw = p_strdup(prparser->pool, str_c(address));

	if (strcasecmp(params->orcpt.addr_type, "rfc822") == 0) {
		if (smtp_params_rcpt_parse_orcpt_rfc822(
			prparser, params->orcpt.addr_raw, prparser->pool,
			&params->orcpt.addr) < 0) {
			prparser->error = "Invalid ORCPT= address value: "
				"Invalid RFC822 address";
			prparser->error_code =
				SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
			return -1;
		}
	}
	return 0;
}

int smtp_params_rcpt_parse(pool_t pool, const char *args,
			   enum smtp_param_rcpt_parse_flags flags,
			   enum smtp_capability caps,
			   const char *const *extensions,
			   struct smtp_params_rcpt *params_r,
			   enum smtp_param_parse_error *error_code_r,
			   const char **error_r)
{
	struct smtp_params_rcpt_parser prparser;
	struct smtp_param param;
	const char *const *argv;
	const char *error;
	int ret = 0;

	i_zero(params_r);

	i_zero(&prparser);
	prparser.pool = pool;
	prparser.params = params_r;
	prparser.flags = flags;
	prparser.caps = caps;

	argv = t_strsplit(args, " ");
	for (; *argv != NULL; argv++) {
		if (smtp_param_parse(pool_datastack_create(), *argv,
				     &param, &error) < 0) {
			*error_r = t_strdup_printf(
				"Invalid RCPT parameter: %s", error);
			*error_code_r = SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX;
			return -1;
		}

		/* parse known parameters */
		param.keyword = t_str_ucase(param.keyword);
		if ((caps & SMTP_CAPABILITY_DSN) != 0 &&
		     strcmp(param.keyword, "NOTIFY") == 0) {
			if (smtp_params_rcpt_parse_notify
				(&prparser, param.value) < 0) {
				ret = -1;
				break;
			}
		} else if (((caps & SMTP_CAPABILITY_DSN) != 0 ||
			    (caps & SMTP_CAPABILITY__ORCPT) != 0) &&
			   strcmp(param.keyword, "ORCPT") == 0) {
			if (smtp_params_rcpt_parse_orcpt
				(&prparser, param.value) < 0) {
				ret = -1;
				break;
			}
		} else if (extensions != NULL &&
			   str_array_icase_find(extensions, param.keyword)) {
			/* add the rest to ext_param for specific applications
			 */
			smtp_params_rcpt_add_extra(params_r, pool,
						   param.keyword, param.value);
		} else {
			/* RFC 5321, Section 4.1.1.11:
			   If the server SMTP does not recognize or cannot
			   implement one or more of the parameters associated
			   with a particular MAIL FROM or RCPT TO command, it
			   will return code 555. */
			*error_r = "Unsupported parameters";
			*error_code_r = SMTP_PARAM_PARSE_ERROR_NOT_SUPPORTED;
			return -1;
		}
	}

	if (ret < 0) {
		*error_r = prparser.error;
		*error_code_r = prparser.error_code;
	}
	return ret;
}

/* manipulate */

void smtp_params_rcpt_copy(pool_t pool, struct smtp_params_rcpt *dst,
			   const struct smtp_params_rcpt *src)
{
	i_zero(dst);

	if (src == NULL)
		return;

	dst->notify = src->notify;
	dst->orcpt.addr_type = p_strdup(pool, src->orcpt.addr_type);
	dst->orcpt.addr_raw = p_strdup(pool, src->orcpt.addr_raw);
	dst->orcpt.addr = smtp_address_clone(pool, src->orcpt.addr);

	if (array_is_created(&src->extra_params)) {
		const struct smtp_param *param;
		struct smtp_param param_new;

		p_array_init(&dst->extra_params, pool,
			array_count(&src->extra_params));
		array_foreach(&src->extra_params, param) {
			param_new.keyword = p_strdup(pool, param->keyword);
			param_new.value = p_strdup(pool, param->value);
			array_push_back(&dst->extra_params, &param_new);
		}
	}
}

void smtp_params_rcpt_add_extra(struct smtp_params_rcpt *params, pool_t pool,
				const char *keyword, const char *value)
{
	struct smtp_param param;

	if (!array_is_created(&params->extra_params))
		p_array_init(&params->extra_params, pool, 4);

	i_zero(&param);
	param.keyword = p_strdup(pool, keyword);
	param.value = p_strdup(pool, value);
	array_push_back(&params->extra_params, &param);
}

bool smtp_params_rcpt_drop_extra(struct smtp_params_rcpt *params,
				 const char *keyword, const char **value_r)
{
	const struct smtp_param *param;

	if (!array_is_created(&params->extra_params))
		return FALSE;

	array_foreach(&params->extra_params, param) {
		if (strcasecmp(param->keyword, keyword) == 0) {
			if (value_r != NULL)
				*value_r = param->value;
			array_delete(&params->extra_params,
				     array_foreach_idx(&params->extra_params,
						       param), 1);
			return TRUE;
		}
	}
	return FALSE;
}

void smtp_params_rcpt_set_orcpt(struct smtp_params_rcpt *params, pool_t pool,
				struct smtp_address *rcpt)
{
	params->orcpt.addr_type = "rfc822";
	params->orcpt.addr = smtp_address_clone(pool, rcpt);
	params->orcpt.addr_raw = p_strdup(pool, smtp_address_encode(rcpt));
}

/* write */

static void
smtp_params_rcpt_write_notify(string_t *buffer, enum smtp_capability caps,
			      const struct smtp_params_rcpt *params)
{
	if (params->notify == SMTP_PARAM_RCPT_NOTIFY_UNSPECIFIED)
		return;
	if ((caps & SMTP_CAPABILITY_DSN) == 0)
		return;

	/* NOTIFY=<type>: RFC 3461

	   notify-esmtp-value = "NEVER" / 1#notify-list-element
	   notify-list-element = "SUCCESS" / "FAILURE" / "DELAY"
	*/

	str_append(buffer, "NOTIFY=");
	if ((params->notify & SMTP_PARAM_RCPT_NOTIFY_NEVER) != 0) {
		i_assert(params->notify == SMTP_PARAM_RCPT_NOTIFY_NEVER);
		str_append(buffer, "NEVER");
	} else {
		bool comma = FALSE;
		if ((params->notify & SMTP_PARAM_RCPT_NOTIFY_SUCCESS) != 0) {
			str_append(buffer, "SUCCESS");
			comma = TRUE;
		}
		if ((params->notify & SMTP_PARAM_RCPT_NOTIFY_FAILURE) != 0) {
			if (comma)
				str_append_c(buffer, ',');
			str_append(buffer, "FAILURE");
			comma = TRUE;
		}
		if ((params->notify & SMTP_PARAM_RCPT_NOTIFY_DELAY) != 0) {
			if (comma)
				str_append_c(buffer, ',');
			str_append(buffer, "DELAY");
		}
	}
	str_append_c(buffer, ' ');
}

static void
smtp_params_rcpt_write_orcpt(string_t *buffer, enum smtp_capability caps,
			     const struct smtp_params_rcpt *params)
{
	if (!smtp_params_rcpt_has_orcpt(params))
		return;
	if ((caps & SMTP_CAPABILITY_DSN) == 0 &&
	    (caps & SMTP_CAPABILITY__ORCPT) == 0)
		return;

	/* ORCPT=<address>: RFC 3461 */

	str_printfa(buffer, "ORCPT=%s;", params->orcpt.addr_type);
	if (strcasecmp(params->orcpt.addr_type, "rfc822") == 0) {
		smtp_xtext_encode_cstr(
			buffer, smtp_address_encode(params->orcpt.addr));
	} else {
		i_assert(params->orcpt.addr_raw != NULL);
		smtp_xtext_encode_cstr(buffer, params->orcpt.addr_raw);
	}
	str_append_c(buffer, ' ');
}

void smtp_params_rcpt_write(string_t *buffer, enum smtp_capability caps,
			    const struct smtp_params_rcpt *params)
{
	size_t init_len = str_len(buffer);

	smtp_params_rcpt_write_notify(buffer, caps, params);
	smtp_params_rcpt_write_orcpt(buffer, caps, params);

	if (array_is_created(&params->extra_params)) {
		const struct smtp_param *param;

		array_foreach(&params->extra_params, param) {
			smtp_param_write(buffer, param);
			str_append_c(buffer, ' ');
		}
	}

	if (str_len(buffer) > init_len)
		str_truncate(buffer, str_len(buffer)-1);
}

/* evaluate */

const struct smtp_param *
smtp_params_rcpt_get_extra(const struct smtp_params_rcpt *params,
			   const char *keyword)
{
	const struct smtp_param *param;

	if (!array_is_created(&params->extra_params))
		return NULL;

	array_foreach(&params->extra_params, param) {
		if (strcasecmp(param->keyword, keyword) == 0)
			return param;
	}
	return NULL;
}

bool smtp_params_rcpt_equals(const struct smtp_params_rcpt *params1,
			     const struct smtp_params_rcpt *params2)
{
	if (params1 == NULL || params2 == NULL)
		return (params1 == params2);

	/* NOTIFY: RFC 3461, Section 4.1 */
	if (params1->notify != params2->notify)
		return FALSE;

	/* ORCPT: RFC 3461, Section 4.2 */
	if (null_strcasecmp(params1->orcpt.addr_type,
			    params2->orcpt.addr_type) != 0)
		return FALSE;
	if (null_strcasecmp(params1->orcpt.addr_type, "rfc822") == 0) {
		if (!smtp_address_equals(params1->orcpt.addr,
					 params2->orcpt.addr))
			return FALSE;
	} else {
		if (null_strcmp(params1->orcpt.addr_raw,
				params2->orcpt.addr_raw) != 0)
			return FALSE;
	}

	/* extra parameters */
	if (array_is_created(&params1->extra_params) !=
	    array_is_created(&params2->extra_params))
		return FALSE;
	if (array_is_created(&params1->extra_params)) {
		const struct smtp_param *param1, *param2;
	
		if (array_count(&params1->extra_params) !=
		    array_count(&params2->extra_params))
			return FALSE;
		array_foreach(&params1->extra_params, param1) {
			param2 = smtp_params_rcpt_get_extra(
				params2, param1->keyword);
			if (param2 == NULL)
				return FALSE;
			if (null_strcmp(param1->value, param2->value) != 0)
				return FALSE;
		}
	}
	return TRUE;
}

/* events */

static void
smtp_params_rcpt_add_notify_to_event(const struct smtp_params_rcpt *params,
				     struct event *event)
{
	/* NOTIFY: RFC 3461, Section 4.1 */
	if (params->notify == SMTP_PARAM_RCPT_NOTIFY_UNSPECIFIED)
		return;
	if ((params->notify & SMTP_PARAM_RCPT_NOTIFY_NEVER) != 0) {
		i_assert(params->notify ==
			 SMTP_PARAM_RCPT_NOTIFY_NEVER);
		event_add_str(event, "rcpt_param_notify", "NEVER");
	} else {
		string_t *str = t_str_new(32);
		if ((params->notify & SMTP_PARAM_RCPT_NOTIFY_SUCCESS) != 0)
			str_append(str, "SUCCESS");
		if ((params->notify & SMTP_PARAM_RCPT_NOTIFY_FAILURE) != 0) {
			if (str_len(str) > 0)
				str_append_c(str, ',');
			str_append(str, "FAILURE");
		}
		if ((params->notify & SMTP_PARAM_RCPT_NOTIFY_DELAY) != 0) {
			if (str_len(str) > 0)
				str_append_c(str, ',');
			str_append(str, "DELAY");
		}
		event_add_str(event, "rcpt_param_notify", str_c(str));
	}
}

static void
smtp_params_rcpt_add_orcpt_to_event(const struct smtp_params_rcpt *params,
				    struct event *event)
{
	/* ORCPT: RFC 3461, Section 4.2 */
	if (params->orcpt.addr_type == NULL)
		return;

	event_add_str(event, "rcpt_param_orcpt_type",
		      params->orcpt.addr_type);
	if (strcasecmp(params->orcpt.addr_type, "rfc822") == 0) {
		event_add_str(event, "rcpt_param_orcpt",
			      smtp_address_encode(params->orcpt.addr));
	} else {
		i_assert(params->orcpt.addr_raw != NULL);
		event_add_str(event, "rcpt_param_orcpt",
			      params->orcpt.addr_raw);
	}
}

void smtp_params_rcpt_add_to_event(const struct smtp_params_rcpt *params,
				   struct event *event)
{
	smtp_params_rcpt_add_notify_to_event(params, event);
	smtp_params_rcpt_add_orcpt_to_event(params, event);
}
