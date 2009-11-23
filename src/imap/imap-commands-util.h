#ifndef IMAP_COMMANDS_UTIL_H
#define IMAP_COMMANDS_UTIL_H

enum client_verify_mailbox_mode {
	/* Don't verify mailbox name validity */
	CLIENT_VERIFY_MAILBOX_NONE,
	/* Verify only that the mailbox name is valid */
	CLIENT_VERIFY_MAILBOX_NAME,
	/* If mailbox doesn't exist, fail with [NONEXISTENT] resp code */
	CLIENT_VERIFY_MAILBOX_SHOULD_EXIST,
	/* If mailbox doesn't exist, fail with [TRYCREATE] resp code */
	CLIENT_VERIFY_MAILBOX_SHOULD_EXIST_TRYCREATE,
	/* If mailbox exists, fail with [ALREADYEXISTS] resp code */
	CLIENT_VERIFY_MAILBOX_SHOULD_NOT_EXIST
};

struct msgset_generator_context {
	string_t *str;
	uint32_t first_uid, last_uid;
};

struct mail_full_flags;
struct mailbox_keywords;

/* Finds namespace for given mailbox from namespaces. If namespace isn't found
   or mailbox name is invalid, sends a tagged NO reply to client. */
struct mail_namespace *
client_find_namespace(struct client_command_context *cmd, const char **mailbox,
		      enum client_verify_mailbox_mode mode);

/* Returns TRUE if mailbox is selected. If not, sends "No mailbox selected"
   error message to client. */
bool client_verify_open_mailbox(struct client_command_context *cmd);

const char *
imap_get_error_string(struct client_command_context *cmd,
		      const char *error_string, enum mail_error error);

/* Send last mailbox list error message to client. */
void client_send_list_error(struct client_command_context *cmd,
			    struct mailbox_list *list);
/* Send last mail storage error message to client. */
void client_send_storage_error(struct client_command_context *cmd,
			       struct mail_storage *storage);

/* Send untagged error message to client. */
void client_send_untagged_storage_error(struct client *client,
					struct mail_storage *storage);

/* Parse flags. Returns TRUE if successful, if not sends an error message to
   client. */
bool client_parse_mail_flags(struct client_command_context *cmd,
			     const struct imap_arg *args,
			     enum mail_flags *flags_r,
			     const char *const **keywords_r);

/* Send FLAGS + PERMANENTFLAGS to client if they have changed,
   or if selecting=TRUE. */
void client_send_mailbox_flags(struct client *client, bool selecting);
/* Update client->keywords array. Use keywords=NULL when unselecting. */
void client_update_mailbox_flags(struct client *client,
				 const ARRAY_TYPE(keywords) *keywords);
/* Convert keyword indexes to keyword names in selected mailbox. */
const char *const *
client_get_keyword_names(struct client *client, ARRAY_TYPE(keywords) *dest,
			 const ARRAY_TYPE(keyword_indexes) *src);

bool mailbox_equals(const struct mailbox *box1,
		    const struct mail_namespace *ns2,
		    const char *name2) ATTR_PURE;

void msgset_generator_init(struct msgset_generator_context *ctx, string_t *str);
void msgset_generator_next(struct msgset_generator_context *ctx, uint32_t uid);
void msgset_generator_finish(struct msgset_generator_context *ctx);

#endif
