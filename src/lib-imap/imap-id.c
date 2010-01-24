/* Copyright (c) 2008-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "str-sanitize.h"
#include "istream.h"
#include "imap-parser.h"
#include "imap-quote.h"
#include "imap-id.h"

#ifdef HAVE_SYS_UTSNAME_H
#  include <sys/utsname.h>
#endif

#ifdef HAVE_UNAME
static struct utsname utsname_result;
static bool utsname_set = FALSE;

static const char *imap_id_get_uname(const char *key)
{
	if (!utsname_set) {
		utsname_set = TRUE;
		if (uname(&utsname_result) < 0) {
			i_error("uname() failed: %m");
			memset(&utsname_result, 0, sizeof(utsname_result));
		}
	}

	if (strcmp(key, "os") == 0)
		return utsname_result.sysname;
	if (strcmp(key, "os-version") == 0)
		return utsname_result.release;
	return NULL;
}
#endif

static const char *imap_id_get_default(const char *key)
{
	if (strcasecmp(key, "name") == 0)
		return PACKAGE_NAME;
	if (strcasecmp(key, "version") == 0)
		return PACKAGE_VERSION;
	if (strcasecmp(key, "support-url") == 0)
		return PACKAGE_WEBPAGE;
	if (strcasecmp(key, "support-email") == 0)
		return PACKAGE_BUGREPORT;
#ifdef HAVE_UNAME
	return imap_id_get_uname(key);
#endif
}

static const char *
imap_id_reply_generate_from_imap_args(const struct imap_arg *args)
{
	string_t *str;
	const char *key, *value;

	if (args->type == IMAP_ARG_EOL)
		return "NIL";

	str = t_str_new(256);
	str_append_c(str, '(');
	for (; args->type != IMAP_ARG_EOL; args++) {
		if (!IMAP_ARG_TYPE_IS_STRING(args->type)) {
			/* broken input */
			if (args[1].type == IMAP_ARG_EOL)
				break;
			args++;
		} else {
			/* key */
			if (str_len(str) > 1)
				str_append_c(str, ' ');
			key = IMAP_ARG_STR_NONULL(args);
			imap_dquote_append(str, key);
			str_append_c(str, ' ');
			/* value */
			if (args[1].type == IMAP_ARG_EOL) {
				str_append(str, "NIL");
				break;
			}
			args++;
			if (!IMAP_ARG_TYPE_IS_STRING(args->type))
				value = NULL;
			else {
				value = IMAP_ARG_STR_NONULL(args);
				if (strcmp(value, "*") == 0)
					value = imap_id_get_default(key);
			}

			if (value == NULL)
				str_append(str, "NIL");
			else
				imap_quote_append_string(str, value, FALSE);
		}
	}
	if (str_len(str) == 1) {
		/* broken */
		return "NIL";
	}
	str_append_c(str, ')');
	return str_c(str);
}

const char *imap_id_reply_generate(const char *settings)
{
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args;
	const char *ret;

	if (settings == NULL)
		return "NIL";

	input = i_stream_create_from_data(settings, strlen(settings));
	(void)i_stream_read(input);

	parser = imap_parser_create(input, NULL, (size_t)-1);
	if (imap_parser_finish_line(parser, 0, 0, &args) <= 0)
		ret = "NIL";
	else
		ret = imap_id_reply_generate_from_imap_args(args);

	imap_parser_destroy(&parser);
	i_stream_destroy(&input);
	return ret;
}

const char *imap_id_args_get_log_reply(const struct imap_arg *args,
				       const char *settings)
{
	const char *const *keys, *key, *value;
	string_t *reply;
	bool log_all;

	if (settings == NULL || *settings == '\0' ||
	    args->type != IMAP_ARG_LIST)
		return NULL;

	args = IMAP_ARG_LIST_ARGS(args);

	log_all = strcmp(settings, "*") == 0;
	reply = t_str_new(256);
	keys = t_strsplit_spaces(settings, " ");
	while (args->type != IMAP_ARG_EOL && args[1].type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_STRING) {
			/* broken input */
			args += 2;
			continue;
		}
		key = IMAP_ARG_STR_NONULL(args);
		args++;
		if (strlen(key) > 30) {
			/* broken: ID spec requires fields to be max. 30
			   octets */
			args++;
			continue;
		}

		if (log_all || str_array_icase_find(keys, key)) {
			if (IMAP_ARG_TYPE_IS_STRING(args->type))
				value = IMAP_ARG_STR_NONULL(args);
			else if (args->type == IMAP_ARG_NIL)
				value = "NIL";
			else
				value = "";
			if (str_len(reply) > 0)
				str_append(reply, ", ");
			str_append(reply, str_sanitize(key, 30));
			str_append_c(reply, '=');
			str_append(reply, str_sanitize(value, 80));
		}
	}
	return str_len(reply) == 0 ? NULL : str_c(reply);
}
