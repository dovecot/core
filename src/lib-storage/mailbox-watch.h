#ifndef MAILBOX_WATCH_H
#define MAILBOX_WATCH_H

void mailbox_watch_add(struct mailbox *box, const char *path);
void mailbox_watch_remove_all(struct mailbox *box);

#endif
