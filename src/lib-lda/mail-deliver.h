#ifndef MAIL_DELIVER_H
#define MAIL_DELIVER_H

#include "guid.h"

enum mail_flags;
enum mail_error;
struct mail_storage;
struct mail_save_context;
struct mailbox;

struct mail_deliver_session {
	pool_t pool;

	/* List of INBOX GUIDs where this mail has already been saved to */
	ARRAY_DEFINE(inbox_guids, guid_128_t);
};

struct mail_deliver_context {
	pool_t pool;
	const struct lda_settings *set;
	struct mail_deliver_session *session;

	struct duplicate_context *dup_ctx;

	/* Session ID, used as log line prefix if non-NULL. */
	const char *session_id;
	/* Mail to save */
	struct mail *src_mail;
	/* Envelope sender, if known. */
	const char *src_envelope_sender;

	/* Destination user */
	struct mail_user *dest_user;
	/* Original recipient address */
	const char *dest_addr;
	/* Final recipient address (typically same as dest_addr) */
	const char *final_dest_addr;
	/* Mailbox where mail should be saved, unless e.g. Sieve does
	   something to it. */
	const char *dest_mailbox_name;

	/* Filled with destination mail, if save_dest_mail=TRUE.
	   The caller must free the mail, its transaction and close
	   the mailbox. */
	struct mail *dest_mail;

	/* mail_deliver_log() caches the var expand table here */
	struct var_expand_table *var_expand_table;

	bool tried_default_save;
	bool saved_mail;
	bool save_dest_mail;
};

struct mail_deliver_save_open_context {
	struct mail_user *user;
	bool lda_mailbox_autocreate;
	bool lda_mailbox_autosubscribe;
};

typedef int deliver_mail_func_t(struct mail_deliver_context *ctx,
				struct mail_storage **storage_r);

extern deliver_mail_func_t *deliver_mail;

const struct var_expand_table *
mail_deliver_get_log_var_expand_table(struct mail *mail, const char *message);
void mail_deliver_log(struct mail_deliver_context *ctx, const char *fmt, ...)
	ATTR_FORMAT(2, 3);

const char *mail_deliver_get_address(struct mail *mail, const char *header);
const char *mail_deliver_get_return_address(struct mail_deliver_context *ctx);
const char *mail_deliver_get_new_message_id(struct mail_deliver_context *ctx);

struct mail_deliver_session *mail_deliver_session_init(void);
void mail_deliver_session_deinit(struct mail_deliver_session **session);

/* Try to open mailbox for saving. Returns 0 if ok, -1 if error. The box may
   be returned even with -1, and the caller must free it then. */
int mail_deliver_save_open(struct mail_deliver_save_open_context *ctx,
			   const char *name, struct mailbox **box_r,
			   enum mail_error *error_r, const char **error_str_r);
int mail_deliver_save(struct mail_deliver_context *ctx, const char *mailbox,
		      enum mail_flags flags, const char *const *keywords,
		      struct mail_storage **storage_r);
void mail_deliver_deduplicate_guid_if_needed(struct mail_deliver_session *session,
					     struct mail_save_context *save_ctx);

int mail_deliver(struct mail_deliver_context *ctx,
		 struct mail_storage **storage_r);

/* Sets the deliver_mail hook and returns the previous hook,
   which the new_hook should call if it's non-NULL. */
deliver_mail_func_t *mail_deliver_hook_set(deliver_mail_func_t *new_hook);

#endif
