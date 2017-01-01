/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-thread.h"

struct {
	const char *name;
	enum mail_thread_type type;
} mail_thread_type_strings[] = {
	{ "REFERENCES", MAIL_THREAD_REFERENCES },
	{ "REFS", MAIL_THREAD_REFS },
	{ "ORDEREDSUBJECT", MAIL_THREAD_ORDEREDSUBJECT }
};

bool mail_thread_type_parse(const char *str, enum mail_thread_type *type_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(mail_thread_type_strings); i++) {
		if (strcasecmp(str, mail_thread_type_strings[i].name) == 0) {
			*type_r = mail_thread_type_strings[i].type;
			return TRUE;
		}
	}
	return FALSE;
}

const char *mail_thread_type_to_str(enum mail_thread_type type)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(mail_thread_type_strings); i++) {
		if (mail_thread_type_strings[i].type == type)
			return mail_thread_type_strings[i].name;
	}
	i_panic("Unknown mail_thread_type %d", type);
}
