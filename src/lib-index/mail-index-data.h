#ifndef __MAIL_INDEX_DATA_H
#define __MAIL_INDEX_DATA_H

#define DATA_FILE_PREFIX ".data"

int mail_index_data_open(struct mail_index *index);
int mail_index_data_create(struct mail_index *index);
void mail_index_data_free(struct mail_index_data *data);

/* Truncate the data file and update it's indexid */
int mail_index_data_reset(struct mail_index_data *data);

/* Set indexid to 0 to notify other processes using this file that they should
   re-open it. */
int mail_index_data_mark_file_deleted(struct mail_index_data *data);

/* Mark the file as being modified */
void mail_index_data_mark_modified(struct mail_index_data *data);

/* Append new data at the end of the file. Returns the position in file
   where the data begins, or 0 if error occured. */
uoff_t mail_index_data_append(struct mail_index_data *data, const void *buffer,
			      size_t size);

/* Mark the given record deleted. */
int mail_index_data_delete(struct mail_index_data *data,
			   struct mail_index_record *index_rec);

/* Synchronize the data into disk */
int mail_index_data_sync_file(struct mail_index_data *data, int *fsync_fd);

/* Looks up a record header from data file. Returns NULL if not found or
   if error occured. */
struct mail_index_data_record_header *
mail_index_data_lookup_header(struct mail_index_data *data,
			      struct mail_index_record *index_rec);

/* Looks up a field from data file. If field is 0, returns the first field
   found. Returns NULL if not found or if error occured. */
struct mail_index_data_record *
mail_index_data_lookup(struct mail_index_data *data,
		       struct mail_index_record *index_rec,
		       enum mail_data_field field);

/* Returns the next record in data file, or NULL if there's no more. */
struct mail_index_data_record *
mail_index_data_next(struct mail_index_data *data,
		     struct mail_index_record *index_rec,
		     struct mail_index_data_record *rec);

/* Returns TRUE if rec->data is a valid \0-terminated string */
int mail_index_data_record_verify(struct mail_index_data *data,
				  struct mail_index_data_record *rec);

/* Return the whole data file mmap()ed. */
void *mail_index_data_get_mmaped(struct mail_index_data *data, size_t *size);

/* "Error in index data file %s: ...". Also marks the index file as
   corrupted. */
int index_data_set_corrupted(struct mail_index_data *data, const char *fmt, ...)
	__attr_format__(2, 3);

#endif
