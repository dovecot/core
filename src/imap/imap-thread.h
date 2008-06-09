#ifndef IMAP_THREAD_H
#define IMAP_THREAD_H

enum mail_thread_type {
	MAIL_THREAD_NONE,
	MAIL_THREAD_ORDEREDSUBJECT,
	MAIL_THREAD_REFERENCES,
	MAIL_THREAD_REFERENCES2
};

int imap_thread(struct mailbox *box, bool id_is_uid, struct ostream *output,
 		struct mail_search_args *args, enum mail_thread_type type);

void imap_thread_init(void);
void imap_thread_deinit(void);

#endif
