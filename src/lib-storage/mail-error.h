#ifndef MAIL_ERROR_H
#define MAIL_ERROR_H

/* Some error strings that should be used everywhere to avoid
   permissions checks from revealing mailbox's existence */
#define MAIL_ERRSTR_MAILBOX_NOT_FOUND "Mailbox doesn't exist: %s"
#define MAIL_ERRSTR_NO_PERMISSION "Permission denied"
#define MAIL_ERRSTR_INTERRUPTED "Operation interrupted"

/* And just for making error strings consistent: */
#define MAIL_ERRSTR_NO_QUOTA "Not enough disk quota"
#define MAIL_ERRSTR_LOCK_TIMEOUT "Timeout while waiting for lock"

/* Message to show to users when critical error occurs */
#define MAIL_ERRSTR_CRITICAL_MSG \
	"Internal error occurred. Refer to server log for more information."
#define MAIL_ERRSTR_CRITICAL_MSG_STAMP \
	MAIL_ERRSTR_CRITICAL_MSG " [%Y-%m-%d %H:%M:%S]"

#define T_MAIL_ERR_MAILBOX_NOT_FOUND(name) \
	t_strdup_printf(MAIL_ERRSTR_MAILBOX_NOT_FOUND, name)

enum mail_error {
	MAIL_ERROR_NONE = 0,

	/* Temporary internal error */
	MAIL_ERROR_TEMP,
	/* Temporary failure because a subsystem is down */
	MAIL_ERROR_UNAVAILABLE,
	/* It's not possible to do the wanted operation */
	MAIL_ERROR_NOTPOSSIBLE,
	/* Invalid parameters (eg. mailbox name not valid) */
	MAIL_ERROR_PARAMS,
	/* No permission to do the request */
	MAIL_ERROR_PERM,
	/* Out of disk quota for user */
	MAIL_ERROR_NOQUOTA,
	/* Item (e.g. mailbox) doesn't exist or it's not visible to us */
	MAIL_ERROR_NOTFOUND,
	/* Item (e.g. mailbox) already exists */
	MAIL_ERROR_EXISTS,
	/* Tried to access an expunged message */
	MAIL_ERROR_EXPUNGED,
	/* Operation cannot be done because another session prevents it
	   (e.g. lock timeout) */
	MAIL_ERROR_INUSE,
	/* Can't do the requested data conversion (e.g. IMAP BINARY's
	   UNKNOWN-CTE code) */
	MAIL_ERROR_CONVERSION,
	/* Can't do the requested data conversion because the original data
	   isn't valid. */
	MAIL_ERROR_INVALIDDATA,
	/* Operation ran against some kind of a limit. */
	MAIL_ERROR_LIMIT,
	/* Operation couldn't be finished as efficiently as required by
	   mail.lookup_abort. */
	MAIL_ERROR_LOOKUP_ABORTED,
	/* Interrupted (due to a signal). */
	MAIL_ERROR_INTERRUPTED,
};

/* Convert errno to mail_error and an error string. Returns TRUE if successful,
   FALSE if we couldn't handle the errno. */
bool mail_error_from_errno(enum mail_error *error_r,
			   const char **error_string_r);

/* Build a helpful error message for a failed EACCES syscall. */
const char *mail_error_eacces_msg(const char *func, const char *path);
/* Build a helpful error message for a failed EACCES syscall that tried to
   write to directory (create, rename, etc). */
const char *mail_error_create_eacces_msg(const char *func, const char *path);

#endif
