#ifndef __COMMANDS_UTIL_H
#define __COMMANDS_UTIL_H

struct msgset_generator_context {
	string_t *str;
	uint32_t first_uid, last_uid;
};

struct mail_full_flags;
struct mailbox_keywords;

/* Finds namespace for given mailbox from namespaces. If not found,
   sends "Unknown namespace" error message to client. */
struct mail_namespace *
client_find_namespace(struct client_command_context *cmd, const char **mailbox);
/* Finds mail storage for given mailbox from namespaces. If not found,
   sends "Unknown namespace" error message to client. */
struct mail_storage *
client_find_storage(struct client_command_context *cmd, const char **mailbox);

/* If should_exist is TRUE, this function returns TRUE if the mailbox
   exists. If it doesn't exist but would be a valid mailbox name, the
   error message is prefixed with [TRYCREATE].

   If should_exist is FALSE, the should_not_exist specifies if we should
   return TRUE or FALSE if mailbox doesn't exist. */
bool client_verify_mailbox_name(struct client_command_context *cmd,
				const char *mailbox,
				bool should_exist, bool should_not_exist);

/* Returns TRUE if mailbox is selected. If not, sends "No mailbox selected"
   error message to client. */
bool client_verify_open_mailbox(struct client_command_context *cmd);

/* Send last mail storage error message to client. */
void client_send_storage_error(struct client_command_context *cmd,
			       struct mail_storage *storage);

/* Send untagged error message to client. */
void client_send_untagged_storage_error(struct client *client,
					struct mail_storage *storage);

/* Parse flags. Returns TRUE if successful, if not sends an error message to
   client. */
bool client_parse_mail_flags(struct client_command_context *cmd,
			     struct imap_arg *args, enum mail_flags *flags_r,
			     const char *const **keywords_r);

/* Send FLAGS + PERMANENTFLAGS to client. */
void client_send_mailbox_flags(struct client *client, struct mailbox *box,
			       const ARRAY_TYPE(keywords) *keywords);

/* Copy keywords into dest. dest must have been initialized. Returns TRUE if
   keywords changed. */
bool client_save_keywords(struct mailbox_keywords *dest,
			  const ARRAY_TYPE(keywords) *keywords);

bool mailbox_equals(struct mailbox *box1, struct mail_storage *storage2,
		    const char *name2);

void msgset_generator_init(struct msgset_generator_context *ctx, string_t *str);
void msgset_generator_next(struct msgset_generator_context *ctx, uint32_t uid);
void msgset_generator_finish(struct msgset_generator_context *ctx);

#endif
