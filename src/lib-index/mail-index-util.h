#ifndef __MAIL_INDEX_UTIL_H
#define __MAIL_INDEX_UTIL_H

/* Get index's lock state as mprotect() argument */
#define MAIL_INDEX_PROT(index) \
	((index)->lock_type == MAIL_LOCK_EXCLUSIVE ? (PROT_READ|PROT_WRITE) : \
	 (index)->lock_type == MAIL_LOCK_SHARED || !(index)->opened ? \
	 PROT_READ : PROT_NONE)

/* DEBUG: Force mmap() locks with mprotect() */
#ifdef DEBUG
#  define debug_mprotect(mmap_base, mmap_length, index) \
	mprotect(mmap_base, mmap_length, MAIL_INDEX_PROT(index))
#else
#  define debug_mprotect(mmap_base, mmap_length, index)
#endif

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

#endif
