/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "str-sanitize.h"
#include "istream.h"
#include "imap-parser.h"
#include "imap-quote.h"
#include "imap-id.h"
#include "dovecot-version.h"

#ifdef HAVE_SYS_UTSNAME_H
#  include <sys/utsname.h>
#endif

/* Limit the allowed characters that an IMAP ID parameter might have. */
#define IMAP_ID_KEY_ACCEPT_CHARS "abcdefghijklmnopqrstuvwxyz0123456789_-"

static struct utsname utsname_result;
static bool utsname_set = FALSE;

static const char *imap_id_get_uname(const char *key)
{
	if (!utsname_set) {
		utsname_set = TRUE;
		if (uname(&utsname_result) < 0) {
			i_error("uname() failed: %m");
			i_zero(&utsname_result);
		}
	}

	if (strcasecmp(key, "os") == 0)
		return utsname_result.sysname;
	if (strcasecmp(key, "os-version") == 0)
		return utsname_result.release;
	return NULL;
}

static const char *imap_id_get_default(const char *key)
{
	if (strcasecmp(key, "name") == 0)
		return PACKAGE_NAME;
	if (strcasecmp(key, "version") == 0)
		return PACKAGE_VERSION;
	if (strcasecmp(key, "revision") == 0)
		return DOVECOT_REVISION;
	if (strcasecmp(key, "support-url") == 0)
		return PACKAGE_WEBPAGE;
	if (strcasecmp(key, "support-email") == 0)
		return PACKAGE_BUGREPORT;
	return imap_id_get_uname(key);
}

static const char *
imap_id_reply_generate_from_imap_args(const struct imap_arg *args)
{
	string_t *str;
	const char *key, *value;

	if (IMAP_ARG_IS_EOL(args))
		return "NIL";

	str = t_str_new(256);
	str_append_c(str, '(');
	for (; !IMAP_ARG_IS_EOL(args); args++) {
		if (!imap_arg_get_astring(args, &key)) {
			/* broken input */
			if (IMAP_ARG_IS_EOL(&args[1]))
				break;
			args++;
		} else {
			/* key */
			if (str_len(str) > 1)
				str_append_c(str, ' ');
			imap_append_quoted(str, key);
			str_append_c(str, ' ');
			/* value */
			if (IMAP_ARG_IS_EOL(&args[1])) {
				str_append(str, "NIL");
				break;
			}
			args++;
			if (!imap_arg_get_astring(args, &value))
				value = NULL;
			else {
				if (strcmp(value, "*") == 0)
					value = imap_id_get_default(key);
			}
			imap_append_nstring(str, value);
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

	parser = imap_parser_create(input, NULL, SIZE_MAX);
	if (imap_parser_finish_line(parser, 0, 0, &args) <= 0)
		ret = "NIL";
	else
		ret = imap_id_reply_generate_from_imap_args(args);

	imap_parser_unref(&parser);
	i_stream_destroy(&input);
	return ret;
}

void
imap_id_add_log_entry(struct imap_id_log_entry *log_entry, const char *key,
		      const char *value)
{
	if (str_len(log_entry->reply) > 0)
		str_append(log_entry->reply, ", ");
	str_append(log_entry->reply, key);
	str_append_c(log_entry->reply, '=');
	str_append(log_entry->reply, value == NULL ? "NIL" : value);

	const char *l_key = t_str_lcase(key);
	const char *prefixed_key;
	const char *val_str = value == NULL ? "NIL" : value;
	if (strspn(l_key, IMAP_ID_KEY_ACCEPT_CHARS) == strlen(l_key)) {
		prefixed_key = t_strconcat("id_param_", l_key, NULL);
		event_add_str(log_entry->event, prefixed_key, val_str);
	} else {
		prefixed_key = t_strdup_printf("id_invalid%u",
					       ++log_entry->invalid_key_id_counter);
		const char *key_val = t_strconcat(key, " ", val_str, NULL);
		event_add_str(log_entry->event, prefixed_key, key_val);
	}
}
