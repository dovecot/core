#ifndef MAILBOX_UIDVALIDITY_H
#define MAILBOX_UIDVALIDITY_H

struct mailbox_list;

uint32_t mailbox_uidvalidity_next(struct mailbox_list *list, const char *path);

#endif
