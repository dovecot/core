#ifndef __MBOX_LOCK_H
#define __MBOX_LOCK_H

/* NOTE: if mbox file is not open, it's opened. if it is open but file has
   been overwritten (ie. inode has changed), it's reopened. */
int mbox_lock(struct index_mailbox *ibox, int lock_type,
	      unsigned int *lock_id_r);
int mbox_unlock(struct index_mailbox *ibox, unsigned int lock_id);

#endif
