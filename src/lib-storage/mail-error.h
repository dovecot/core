#ifndef __MAIL_ERROR_H
#define __MAIL_ERROR_H

/* Some error strings that should be used everywhere to avoid
   permissions checks from revealing mailbox's existence */
#define MAIL_ERRSTR_MAILBOX_NOT_FOUND "Mailbox doesn't exist: %s"
#define MAIL_ERRSTR_NO_PERMISSION "Permission denied"

/* And just for making error strings consistent: */
#define MAIL_ERRSTR_NO_SPACE "Not enough disk space"
#define MAIL_ERRSTR_LOCK_TIMEOUT "Timeout while waiting for lock"

#define T_MAIL_ERR_MAILBOX_NOT_FOUND(name) \
	t_strdup_printf(MAIL_ERRSTR_MAILBOX_NOT_FOUND, name)

enum mail_error {
	MAIL_ERROR_NONE = 0,

	/* Temporary internal error */
	MAIL_ERROR_TEMP,
	/* It's not possible to do the wanted operation */
	MAIL_ERROR_NOTPOSSIBLE,
	/* Invalid parameters (eg. mailbox name not valid) */
	MAIL_ERROR_PARAMS,
	/* No permission to do the request */
	MAIL_ERROR_PERM,
	/* Out of disk space or quota */
	MAIL_ERROR_NOSPACE,
	/* Item (eg. mailbox) doesn't exist or it's not visible to us */
	MAIL_ERROR_NOTFOUND,
	/* Tried to access an expunged message */
	MAIL_ERROR_EXPUNGED
};

/* Convert errno to mail_error and an error string. Returns TRUE if successful,
   FALSE if we couldn't handle the errno. */
bool mail_error_from_errno(enum mail_error *error_r,
			   const char **error_string_r);

#endif
