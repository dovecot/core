#ifndef MBOX_FILE_H
#define MBOX_FILE_H

int mbox_file_open(struct mbox_mailbox *mbox);
void mbox_file_close(struct mbox_mailbox *mbox);

int mbox_file_open_stream(struct mbox_mailbox *mbox);
void mbox_file_close_stream(struct mbox_mailbox *mbox);

int mbox_file_lookup_offset(struct mbox_mailbox *mbox,
			    struct mail_index_view *view,
			    uint32_t seq, uoff_t *offset_r);
int mbox_file_seek(struct mbox_mailbox *mbox, struct mail_index_view *view,
		   uint32_t seq, bool *deleted_r);

#endif
