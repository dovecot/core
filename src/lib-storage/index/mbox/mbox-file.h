#ifndef __MBOX_FILE_H
#define __MBOX_FILE_H

int mbox_file_open(struct index_mailbox *ibox);
void mbox_file_close(struct index_mailbox *ibox);

int mbox_file_open_stream(struct index_mailbox *ibox);
void mbox_file_close_stream(struct index_mailbox *ibox);

#endif
