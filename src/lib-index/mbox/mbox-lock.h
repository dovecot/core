#ifndef __MBOX_LOCK_H
#define __MBOX_LOCK_H

int mbox_lock(MailIndex *index, const char *path, int fd, int exclusive);
int mbox_unlock(MailIndex *index, const char *path, int fd);

#endif
