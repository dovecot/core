/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "str-sanitize.h"
#include "istream.h"
#include "imap-parser.h"
#include "imap-quote.h"
#include "imap-id.h"
#include "dovecot-version.h"

/* Limit the allowed characters that an IMAP ID parameter might have. */
#define IMAP_ID_KEY_ACCEPT_CHARS "abcdefghijklmnopqrstuvwxyz0123456789_-"

const char *imap_id_reply_generate(const ARRAY_TYPE(const_string) *args)
{
	if (array_is_empty(args))
		return "NIL";

	string_t *str = t_str_new(256);
	str_append_c(str, '(');
	unsigned int count;
	const char *const *kv = array_get(args, &count);
	for (unsigned int i = 0; i < count; i += 2) {
		if (i > 0)
			str_append_c(str, ' ');
		imap_append_quoted(str, kv[i]);
		str_append_c(str, ' ');
		const char *value = kv[i + 1];
#if defined(DOVECOT_EDITION)
		if (strcasecmp(kv[i], "name") == 0 &&
		    strcmp(DOVECOT_EDITION, "Pro") == 0)
			value = DOVECOT_NAME;
#endif
		imap_append_nstring(str, value);
	}
	str_append_c(str, ')');
	return str_c(str);
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
