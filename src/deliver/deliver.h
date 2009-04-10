#ifndef DELIVER_H
#define DELIVER_H

#include <sysexits.h>

#ifndef EX_CONFIG
#  define EX_CONFIG 78 /* HP-UX */
#endif

#include "lib.h"
#include "mail-storage.h"
#include "deliver-settings.h"

extern const struct deliver_settings *deliver_set;
extern bool mailbox_autosubscribe;
extern bool mailbox_autocreate;
extern bool tried_default_save;

typedef int deliver_mail_func_t(struct mail_namespace *namespaces,
				struct mail_storage **storage_r,
				struct mail *mail,
				const char *destaddr, const char *mailbox);

extern deliver_mail_func_t *deliver_mail;

/* Save a mail into given mailbox with given flags and keywords. */
int deliver_save(struct mail_namespace *namespaces,
		 struct mail_storage **storage_r, const char *mailbox,
		 struct mail *mail, enum mail_flags flags,
		 const char *const *keywords);

/* Extracts user@domain from Return-Path header. Returns NULL if not found. */
const char *deliver_get_return_address(struct mail *mail);

/* Returns a new unique Message-ID */
const char *deliver_get_new_message_id(void);

#endif
