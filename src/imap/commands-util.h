#ifndef __COMMANDS_UTIL_H
#define __COMMANDS_UTIL_H

struct msgset_generator_context {
	string_t *str;
	uint32_t first_uid, last_uid;
};

struct mail_full_flags;

/* Finds mail storage for given mailbox from namespaces. If not found,
   sends "Unknown namespace" error message to client. */
struct mail_storage *
client_find_storage(struct client *client, const char *mailbox);

/* If should_exist is TRUE, this function returns TRUE if the mailbox
   exists. If it doesn't exist but would be a valid mailbox name, the
   error message is prefixed with [TRYCREATE].

   If should_exist is FALSE, the should_not_exist specifies if we should
   return TRUE or FALSE if mailbox doesn't exist. */
int client_verify_mailbox_name(struct client *client, const char *mailbox,
			       int should_exist, int should_not_exist);

/* Returns TRUE if mailbox is selected. If not, sends "No mailbox selected"
   error message to client. */
int client_verify_open_mailbox(struct client *client);

/* Synchronize selected mailbox with client by sending EXPUNGE,
   FETCH FLAGS, EXISTS and RECENT responses. */
void client_sync_full(struct client *client);

/* Synchronize fast. */
void client_sync_full_fast(struct client *client);

/* Synchronize all but expunges with client. */
void client_sync_without_expunges(struct client *client);

/* Send last mail storage error message to client. */
void client_send_storage_error(struct client *client,
			       struct mail_storage *storage);

/* Send untagged error message to client. */
void client_send_untagged_storage_error(struct client *client,
					struct mail_storage *storage);

/* Parse flags. Returns TRUE if successful, if not sends an error message to
   client. */
int client_parse_mail_flags(struct client *client, struct imap_arg *args,
                            const struct mailbox_keywords *old_keywords,
			    struct mail_full_flags *flags);

/* Send FLAGS + PERMANENTFLAGS to client. */
void client_send_mailbox_flags(struct client *client, struct mailbox *box,
			       const char *keywords[],
			       unsigned int keywords_count);

/* Copy keywords into dest. dest must have been initialized. */
void client_save_keywords(struct mailbox_keywords *dest,
			  const char *keywords[], unsigned int keywords_count);

int mailbox_name_equals(const char *box1, const char *box2);

void msgset_generator_init(struct msgset_generator_context *ctx, string_t *str);
void msgset_generator_next(struct msgset_generator_context *ctx, uint32_t uid);
void msgset_generator_finish(struct msgset_generator_context *ctx);

#endif
