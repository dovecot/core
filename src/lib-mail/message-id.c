/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "rfc822-parser.h"
#include "message-id.h"

static bool get_untokenized_msgid(const char **msgid_p, string_t *msgid)
{
	struct rfc822_parser_context parser;

	rfc822_parser_init(&parser, (const unsigned char *)*msgid_p,
			   strlen(*msgid_p), NULL);

	/*
	   msg-id          = [CFWS] "<" id-left "@" id-right ">" [CFWS]
	   id-left         = dot-atom-text / no-fold-quote / obs-id-left
	   id-right        = dot-atom-text / no-fold-literal / obs-id-right
	   no-fold-quote   = DQUOTE *(qtext / quoted-pair) DQUOTE
	   no-fold-literal = "[" *(dtext / quoted-pair) "]"
	*/

	(void)rfc822_skip_lwsp(&parser);

	if (rfc822_parse_dot_atom(&parser, msgid) <= 0)
		return FALSE;

	if (*parser.data != '@')
		return FALSE;
	str_append_c(msgid, '@');
	parser.data++;
	(void)rfc822_skip_lwsp(&parser);

	if (rfc822_parse_dot_atom(&parser, msgid) <= 0)
		return FALSE;

	if (*parser.data != '>')
		return FALSE;

	*msgid_p = (const char *)parser.data + 1;
	return TRUE;
}

static void strip_lwsp(char *str)
{
	/* @UNSAFE */
	char *dest;

	/* find the first lwsp */
	while (*str != ' ' && *str != '\t' && *str != '\r' && *str != '\n') {
		if (*str == '\0')
			return;
		str++;
	}

	for (dest = str; *str != '\0'; str++) {
		if (*str != ' ' && *str != '\t' && *str != '\r' && *str != '\n')
			*dest++ = *str;
	}
	*dest = '\0';
}

const char *message_id_get_next(const char **msgid_p)
{
	const char *msgid = *msgid_p;
	const char *p;
	string_t *str = NULL;
	bool found_at;

	if (*msgid_p == NULL)
		return NULL;

	for (;;) {
		/* skip until '<' */
		while (*msgid != '<') {
			if (*msgid == '\0') {
				*msgid_p = msgid;
				return NULL;
			}
			msgid++;
		}
		msgid++;

		/* check it through quickly to see if it's already normalized */
		p = msgid; found_at = FALSE;
		for (;; p++) {
			if ((unsigned char)*p >= 'A') /* matches most */
				continue;

			if (*p == '@')
				found_at = TRUE;
			if (*p == '>' || *p == '"' || *p == '(' || *p == '[')
				break;

			if (*p == '\0') {
				*msgid_p = p;
				return NULL;
			}
		}

		if (*p == '>') {
			*msgid_p = p+1;
			if (found_at) {
				char *s;

				s = p_strdup_until(unsafe_data_stack_pool,
						   msgid, p);
				strip_lwsp(s);
				return s;
			}
		} else {
			/* ok, do it the slow way */
			*msgid_p = msgid;

			if (str == NULL) {
				/* allocate only once, so we don't leak
				   with multiple invalid message IDs */
				str = t_str_new(256);
			}
			if (get_untokenized_msgid(msgid_p, str))
				return str_c(str);
		}

		/* invalid message id, see if there's another valid one */
		msgid = *msgid_p;
	}
}
