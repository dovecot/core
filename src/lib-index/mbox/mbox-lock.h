#ifndef __MBOX_LOCK_H
#define __MBOX_LOCK_H

int mbox_lock_read(MailIndex *index);
int mbox_lock_write(MailIndex *index);
int mbox_unlock(MailIndex *index);

#endif
