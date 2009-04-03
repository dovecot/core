#ifndef DBOX_FILE_MAILDIR_H
#define DBOX_FILE_MAILDIR_H

const char *dbox_file_maildir_metadata_get(struct dbox_file *file,
					   enum dbox_metadata_key key);
bool dbox_maildir_uid_get_fname(struct dbox_mailbox *mbox, uint32_t uid,
				const char **fname_r);

#endif
