#ifndef __MBOX_LOCK_H
#define __MBOX_LOCK_H

/* NOTE: if mbox file is not open, it's opened. if it is open but file has
   been overwritten (ie. inode has changed), it's reopened. */
int mbox_lock(MailIndex *index, MailLockType lock_type);
int mbox_unlock(MailIndex *index);

#endif
