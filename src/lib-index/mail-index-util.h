#ifndef __MAIL_INDEX_UTIL_H
#define __MAIL_INDEX_UTIL_H

/* Set the current error message */
void index_set_error(MailIndex *index, const char *fmt, ...)
	__attr_format__(2, 3);

/* Reset the current error */
void index_reset_error(MailIndex *index);

/* Create temporary file into index's directory. Returns opened file handle
   and sets *path to the full path of the created file.  */
int mail_index_create_temp_file(MailIndex *index, const char **path);

#endif
