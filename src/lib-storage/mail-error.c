/* Copyright (c) 2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-error.h"

bool mail_error_from_errno(enum mail_error *error_r,
			   const char **error_string_r)
{
	if (ENOACCESS(errno)) {
		*error_r = MAIL_ERROR_PERM;
		*error_string_r = MAIL_ERRSTR_NO_PERMISSION;
	} else if (ENOSPACE(errno)) {
		*error_r = MAIL_ERROR_NOSPACE;
		*error_string_r = MAIL_ERRSTR_NO_SPACE;
	} else if (ENOTFOUND(errno)) {
		*error_r = MAIL_ERROR_NOTFOUND;
		*error_string_r = errno != ELOOP ? "Not found" :
			"Directory structure is broken";
	} else {
		return FALSE;
	}
	return TRUE;
}
