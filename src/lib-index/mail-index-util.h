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

/* Calculates virtual size for specified message. If the fastscan is FALSE
   and the size can't be figured out from headers, the message is opened and
   fully scanned to calculate the size. Returns TRUE if size was successfully
   got. */
int mail_index_get_virtual_size(MailIndex *index, MailIndexRecord *rec,
				int fastscan, uoff_t *virtual_size);

#endif
