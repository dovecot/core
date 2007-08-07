#ifndef __IMAP_THREAD_H
#define __IMAP_THREAD_H

enum mail_thread_type {
	MAIL_THREAD_NONE,
	MAIL_THREAD_ORDEREDSUBJECT,
	MAIL_THREAD_REFERENCES
};

int imap_thread(struct client_command_context *cmd, const char *charset,
		struct mail_search_arg *args, enum mail_thread_type type);

#endif
