#ifndef __MAIL_INDEX_DATA_H
#define __MAIL_INDEX_DATA_H

#define DATA_FILE_PREFIX ".data"

int mail_index_data_open(MailIndex *index);
int mail_index_data_create(MailIndex *index);
void mail_index_data_free(MailIndexData *data);

/* Truncate the data file and update it's indexid */
int mail_index_data_reset(MailIndexData *data);

/* Needs to be called whenever new messages are added. File must never
   be shrinked while it's open. */
void mail_index_data_new_data_notify(MailIndexData *data);

/* Append new data at the end of the file. Returns the position in file
   where the data begins, or (off_t)-1 if error occured. */
off_t mail_index_data_append(MailIndexData *data, void *buffer, size_t size);

/* Increase header->deleted_space field */
int mail_index_data_add_deleted_space(MailIndexData *data,
				      unsigned int data_size);

/* Synchronize the data into disk */
int mail_index_data_sync_file(MailIndexData *data);

/* Looks up a field from data file. Returns NULL if not found or
   if error occured. */
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

#endif
