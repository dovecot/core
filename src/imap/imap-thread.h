#ifndef IMAP_THREAD_H
#define IMAP_THREAD_H

enum mail_thread_type {
	MAIL_THREAD_NONE,
	MAIL_THREAD_ORDEREDSUBJECT,
	MAIL_THREAD_REFERENCES,
	MAIL_THREAD_REFERENCES2
};

int imap_thread(struct client_command_context *cmd, const char *charset,
		struct mail_search_arg *args, enum mail_thread_type type);

void imap_thread_init(void);
void imap_thread_deinit(void);

#endif
