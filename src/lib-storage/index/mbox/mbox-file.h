#ifndef __MBOX_FILE_H
#define __MBOX_FILE_H

int mbox_file_open(struct mbox_mailbox *mbox);
void mbox_file_close(struct mbox_mailbox *mbox);

int mbox_file_open_stream(struct mbox_mailbox *mbox);
void mbox_file_close_stream(struct mbox_mailbox *mbox);

int mbox_file_seek(struct mbox_mailbox *mbox, struct mail_index_view *view,
		   uint32_t seq, int *deleted_r);

#endif
