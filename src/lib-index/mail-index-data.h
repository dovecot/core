#ifndef __MAIL_INDEX_DATA_H
#define __MAIL_INDEX_DATA_H

#define DATA_FILE_PREFIX ".data"

int mail_index_data_open(MailIndex *index);
int mail_index_data_create(MailIndex *index);
void mail_index_data_free(MailIndexData *data);

/* Truncate the data file and update it's indexid */
int mail_index_data_reset(MailIndexData *data);

/* Set indexid to 0 to notify other processes using this file that they should
   re-open it. */
int mail_index_data_mark_deleted(MailIndexData *data);

/* Mark the file as being modified */
void mail_index_data_mark_modified(MailIndexData *data);

/* Append new data at the end of the file. Returns the position in file
   where the data begins, or 0 if error occured. */
uoff_t mail_index_data_append(MailIndexData *data, const void *buffer,
			      size_t size);

/* Increase header->deleted_space field */
int mail_index_data_add_deleted_space(MailIndexData *data, size_t data_size);

/* Synchronize the data into disk */
int mail_index_data_sync_file(MailIndexData *data, int *fsync_fd);

/* Looks up a field from data file. If field is 0, returns the first field
   found. Returns NULL if not found or if error occured. */
MailIndexDataRecord *
mail_index_data_lookup(MailIndexData *data, MailIndexRecord *index_rec,
		       MailField field);

/* Returns the next record in data file, or NULL if there's no more. */
MailIndexDataRecord *
mail_index_data_next(MailIndexData *data, MailIndexRecord *index_rec,
		     MailIndexDataRecord *rec);

/* Returns TRUE if rec->data is a valid \0-terminated string */
int mail_index_data_record_verify(MailIndexData *data,
				  MailIndexDataRecord *rec);

/* Return the whole data file mmap()ed. */
void *mail_index_data_get_mmaped(MailIndexData *data, size_t *size);

/* "Error in index data file %s: ...". Also marks the index file as
   corrupted. */
int index_data_set_corrupted(MailIndexData *data, const char *fmt, ...);

#endif
