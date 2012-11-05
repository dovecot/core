#ifndef POP3C_STORAGE_H
#define POP3C_STORAGE_H

#include "index-storage.h"

#define POP3C_STORAGE_NAME "pop3c"

struct pop3c_storage {
	struct mail_storage storage;
	const struct pop3c_settings *set;
};

struct pop3c_mailbox {
	struct mailbox box;
	struct pop3c_storage *storage;

	struct pop3c_client *client;

	pool_t uidl_pool;
	unsigned int msg_count;
	/* LIST sizes */
	uoff_t *msg_sizes;
	/* UIDL strings */
	const char *const *msg_uidls;
	/* index UIDs for each message in this session.
	   the UID may not exist for the entire session */
	uint32_t *msg_uids;

	unsigned int logged_in:1;
};

extern struct mail_vfuncs pop3c_mail_vfuncs;

#endif
