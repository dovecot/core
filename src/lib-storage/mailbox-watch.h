#ifndef MAILBOX_WATCH_H
#define MAILBOX_WATCH_H

void mailbox_watch_add(struct mailbox *box, const char *path);
void mailbox_watch_remove_all(struct mailbox *box);

/* Create a new temporary ioloop, add all the watches back and call
   io_loop_extract_notify_fd() on it. Returns fd on success, -1 on error. */
int mailbox_watch_extract_notify_fd(struct mailbox *box, const char **reason_r);

#endif
