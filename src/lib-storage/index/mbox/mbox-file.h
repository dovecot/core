#ifndef __MBOX_FILE_H
#define __MBOX_FILE_H

int mbox_file_open(struct index_mailbox *ibox);
void mbox_file_close(struct index_mailbox *ibox);

int mbox_file_open_stream(struct index_mailbox *ibox);
void mbox_file_close_stream(struct index_mailbox *ibox);

int mbox_file_seek(struct index_mailbox *ibox, struct mail_index_view *view,
		   uint32_t seq, int *deleted_r);

#endif
