#ifndef __IMAP_THREAD_H
#define __IMAP_THREAD_H

int imap_thread(struct client *client, const char *charset,
		struct mail_search_arg *args, enum mail_thread_type type);

#endif
