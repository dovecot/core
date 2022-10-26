/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */
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
/* Parse boolean string, return as boolean */
int str_parse_get_bool(const char *value, bool *result_r,
		       const char **error_r);

#endif // STR_PARSE_H
