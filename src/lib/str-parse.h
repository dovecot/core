/* Copyright (c) Dovecot authors, see top-level COPYING file */
#ifndef STR_PARSE_H
#define STR_PARSE_H

/* Parse time interval string, return as seconds. */
int str_parse_get_interval(const char *str, unsigned int *secs_r,
			   const char **error_r);
/* Parse time interval string, return as milliseconds. */
int str_parse_get_interval_msecs(const char *str, unsigned int *msecs_r,
				 const char **error_r);
/* Parse size string, return as bytes. */
int str_parse_get_size(const char *str, uoff_t *bytes_r,
		       const char **error_r);
/* Parse boolean string, return as boolean. Only "yes" and "no" are valid. */
int str_parse_get_bool_strict(const char *value, bool *result_r,
			      const char **error_r);
/* Same as str_parse_get_bool_strict(), but also accept the legacy "y" and "1"
   as TRUE. Use this only for values that come from outside the configuration,
   e.g. from a userdb lookup. */
int str_parse_get_bool(const char *value, bool *result_r,
		       const char **error_r);

#endif // STR_PARSE_H
