/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "eacces-error.h"
#include "mail-error.h"

bool mail_error_from_errno(enum mail_error *error_r,
			   const char **error_string_r)
{
	if (errno == EACCES || errno == EPERM) {
		*error_r = MAIL_ERROR_PERM;
		*error_string_r = MAIL_ERRSTR_NO_PERMISSION;
	} else if (errno == EROFS) {
		*error_r = MAIL_ERROR_PERM;
		*error_string_r = "Read only file system";
	} else if (ENOQUOTA(errno)) {
		*error_r = MAIL_ERROR_NOQUOTA;
		*error_string_r = MAIL_ERRSTR_NO_QUOTA;
	} else if (ENOTFOUND(errno)) {
		*error_r = MAIL_ERROR_NOTFOUND;
		*error_string_r = errno != ELOOP ? "Not found" :
			"Directory structure is broken";
	} else {
		return FALSE;
	}
	return TRUE;
}

const char *mail_error_eacces_msg(const char *func, const char *path)
{
	return eacces_error_get(func, path);
}

const char *mail_error_create_eacces_msg(const char *func, const char *path)
{
	return eacces_error_get_creating(func, path);
}
