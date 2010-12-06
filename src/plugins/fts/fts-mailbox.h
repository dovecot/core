#ifndef FTS_MAILBOX_H
#define FTS_MAILBOX_H

/* If box is a virtual mailbox, look up UID for the given backend message.
   Returns TRUE if found, FALSE if not. */
bool fts_mailbox_get_virtual_uid(struct mailbox *box,
				 const char *backend_mailbox,
				 uint32_t backend_uidvalidity,
				 uint32_t backend_uid, uint32_t *uid_r);
/* If box is a virtual mailbox, return all backend mailboxes. If
   only_with_msgs=TRUE, return only those mailboxes that have at least one
   message existing in the virtual mailbox. */
void fts_mailbox_get_virtual_backend_boxes(struct mailbox *box,
					   ARRAY_TYPE(mailboxes) *mailboxes,
					   bool only_with_msgs);
/* If mailbox is a virtual mailbox, return all mailbox list patterns that
   are used to figure out which mailboxes belong to the virtual mailbox. */
void fts_mailbox_get_virtual_box_patterns(struct mailbox *box,
				ARRAY_TYPE(mailbox_virtual_patterns) *includes,
				ARRAY_TYPE(mailbox_virtual_patterns) *excludes);

#endif
