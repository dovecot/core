#ifndef DELIVER_H
#define DELIVER_H

#include <sysexits.h>

#ifndef EX_CONFIG
#  define EX_CONFIG 78 /* HP-UX */
#endif

#include "lib.h"
#include "mail-storage.h"

#define DEFAULT_MAIL_REJECTION_SUBJECT \
	"Automatically rejected mail"
#define DEFAULT_MAIL_REJECTION_HUMAN_REASON \
	"Your message to <%t> was automatically rejected:%n%r"
#define DEFAULT_LOG_FORMAT "msgid=%m: %$"

struct deliver_settings {
	const char *hostname;
	const char *postmaster_address;
	const char *sendmail_path;
	const char *rejection_subject;
	const char *rejection_reason;
	const char *log_format;
	bool mailbox_autosubscribe;
	bool mailbox_autocreate;
};

extern struct deliver_settings *deliver_set;
extern bool tried_default_save;

typedef int deliver_mail_func_t(struct mail_namespace *namespaces,
				struct mail_storage **storage_r,
				struct mail *mail,
				const char *destaddr, const char *mailbox);

extern deliver_mail_func_t *deliver_mail;

void deliver_env_clean(bool preserve_home);

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
