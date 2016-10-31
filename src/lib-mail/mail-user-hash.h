#ifndef MAIL_USER_HASH
#define MAIL_USER_HASH

/* Get a hash for username, based on given format. The format can use
   %n, %d and %u variables. Returns TRUE if ok, FALSE if format is invalid. */
bool mail_user_hash(const char *username, const char *format,
		    unsigned int *hash_r, const char **error_r);

#endif
