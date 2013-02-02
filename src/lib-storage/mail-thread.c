/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-thread.h"

bool mail_thread_type_parse(const char *str, enum mail_thread_type *type_r)
{
	if (strcasecmp(str, "REFERENCES") == 0)
		*type_r = MAIL_THREAD_REFERENCES;
	else if (strcasecmp(str, "REFS") == 0)
		*type_r = MAIL_THREAD_REFS;
	else if (strcasecmp(str, "ORDEREDSUBJECT") == 0)
		*type_r = MAIL_THREAD_ORDEREDSUBJECT;
	else
		return FALSE;
	return TRUE;
}
