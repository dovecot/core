#ifndef __MAIL_INDEX_UTIL_H
#define __MAIL_INDEX_UTIL_H

/* Set the current error message */
int index_set_error(MailIndex *index, const char *fmt, ...)
	__attr_format__(2, 3);

/* "Error in index file %s: ...". Also marks the index file as corrupted. */
int index_set_corrupted(MailIndex *index, const char *fmt, ...);

/* "%s failed with index file %s: %m" */
int index_set_syscall_error(MailIndex *index, const char *function);

/* "%s failed with file %s: %m" */
int index_file_set_syscall_error(MailIndex *index, const char *filepath,
				 const char *function);

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
