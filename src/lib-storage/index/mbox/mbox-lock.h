#ifndef MBOX_LOCK_H
#define MBOX_LOCK_H

/* NOTE: if mbox file is not open, it's opened. if it is open but file has
   been overwritten (ie. inode has changed), it's reopened. */
int mbox_lock(struct mbox_mailbox *mbox, int lock_type,
	      unsigned int *lock_id_r);
int ATTR_NOWARN_UNUSED_RESULT
mbox_unlock(struct mbox_mailbox *mbox, unsigned int lock_id);

unsigned int mbox_get_cur_lock_id(struct mbox_mailbox *mbox);

void mbox_dotlock_touch(struct mbox_mailbox *mbox);

#endif
