/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "buffer.h"
#include "str.h"
#include "commands-util.h"
#include "imap-util.h"
#include "mail-storage.h"
#include "imap-parser.h"
#include "imap-sync.h"
#include "namespace.h"

/* Maximum length for mailbox name, including it's path. This isn't fully
   exact since the user can create folder hierarchy with small names, then
   rename them to larger names. Mail storages should set more strict limits
   to them, mbox/maildir currently allow paths only up to PATH_MAX. */
#define MAILBOX_MAX_NAME_LEN 512

struct mail_storage *
client_find_storage(struct client *client, const char **mailbox)
{
	struct namespace *ns;

	ns = namespace_find(client->namespaces, mailbox);
	if (ns != NULL)
		return ns->storage;

	client_send_tagline(client, "NO Unknown namespace.");
	return NULL;
}

int client_verify_mailbox_name(struct client *client, const char *mailbox,
			       int should_exist, int should_not_exist)
{
	struct mail_storage *storage;
	enum mailbox_name_status mailbox_status;
	const char *p;
	char sep;

	storage = client_find_storage(client, &mailbox);
	if (storage == NULL)
		return FALSE;

	/* make sure it even looks valid */
	sep = mail_storage_get_hierarchy_sep(storage);
	if (*mailbox == '\0' || strspn(mailbox, "\r\n*%?") != 0) {
		client_send_tagline(client, "NO Invalid mailbox name.");
		return FALSE;
	}

	/* make sure two hierarchy separators aren't next to each others */
	for (p = mailbox+1; *p != '\0'; p++) {
		if (p[0] == sep && p[1] == sep) {
			client_send_tagline(client, "NO Invalid mailbox name.");
			return FALSE;
		}
	}

	if (strlen(mailbox) > MAILBOX_MAX_NAME_LEN) {
		client_send_tagline(client, "NO Mailbox name too long.");
		return FALSE;
	}

	/* check what our storage thinks of it */
	if (mail_storage_get_mailbox_name_status(storage, mailbox,
						 &mailbox_status) < 0) {
		client_send_storage_error(client, storage);
		return FALSE;
	}

	switch (mailbox_status) {
	case MAILBOX_NAME_EXISTS:
		if (should_exist || !should_not_exist)
			return TRUE;

		client_send_tagline(client, "NO Mailbox exists.");
		break;

	case MAILBOX_NAME_VALID:
		if (!should_exist)
			return TRUE;

		client_send_tagline(client, t_strconcat(
			"NO [TRYCREATE] Mailbox doesn't exist: ",
			mailbox, NULL));
		break;

	case MAILBOX_NAME_INVALID:
		client_send_tagline(client, t_strconcat(
			"NO Invalid mailbox name: ", mailbox, NULL));
		break;

	case MAILBOX_NAME_NOINFERIORS:
		client_send_tagline(client,
			"NO Mailbox parent doesn't allow inferior mailboxes.");
		break;

	default:
                i_unreached();
	}

	return FALSE;
}

int client_verify_open_mailbox(struct client *client)
{
	if (client->mailbox != NULL)
		return TRUE;
	else {
		client_send_tagline(client, "BAD No mailbox selected.");
		return FALSE;
	}
}

void client_send_storage_error(struct client *client,
			       struct mail_storage *storage)
{
	const char *error;
	int syntax;

	if (client->mailbox != NULL &&
	    mailbox_is_inconsistent(client->mailbox)) {
		/* we can't do forced CLOSE, so have to disconnect */
		client_disconnect_with_error(client,
			"Mailbox is in inconsistent state, please relogin.");
		return;
	}

	error = mail_storage_get_last_error(storage, &syntax);
	client_send_tagline(client, t_strconcat(syntax ? "BAD " : "NO ",
						error, NULL));
}

void client_send_untagged_storage_error(struct client *client,
					struct mail_storage *storage)
{
	const char *error;
	int syntax;

	if (client->mailbox != NULL &&
	    mailbox_is_inconsistent(client->mailbox)) {
		/* we can't do forced CLOSE, so have to disconnect */
		client_disconnect_with_error(client,
			"Mailbox is in inconsistent state, please relogin.");
		return;
	}

	error = mail_storage_get_last_error(storage, &syntax);
	client_send_line(client,
			 t_strconcat(syntax ? "* BAD " : "* NO ", error, NULL));
}

static int is_valid_keyword(struct client *client,
			    const struct mailbox_keywords *old_keywords,
			    const char *keyword)
{
	size_t i;

	/* if it already exists, skip validity checks */
	for (i = 0; i < old_keywords->keywords_count; i++) {
		if (old_keywords->keywords[i] != NULL &&
		    strcasecmp(old_keywords->keywords[i], keyword) == 0)
			return TRUE;
	}

	if (strlen(keyword) > max_keyword_length) {
		client_send_tagline(client,
			t_strdup_printf("BAD Invalid keyword name '%s': "
					"Maximum length is %u characters",
					keyword, max_keyword_length));
		return FALSE;
	}

	return TRUE;
}

int client_parse_mail_flags(struct client *client, struct imap_arg *args,
                            const struct mailbox_keywords *old_keywords,
			    struct mail_full_flags *flags)
{
	const char *const *keywords;
	char *atom;
	buffer_t *buffer;
	size_t size, i;

	memset(flags, 0, sizeof(*flags));
	buffer = buffer_create_dynamic(client->cmd_pool, 256, (size_t)-1);

	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_send_command_error(client,
				"Flags list contains non-atoms.");
			return FALSE;
		}

		atom = IMAP_ARG_STR(args);
		if (*atom == '\\') {
			/* system flag */
			str_ucase(atom);
			if (strcmp(atom, "\\ANSWERED") == 0)
				flags->flags |= MAIL_ANSWERED;
			else if (strcmp(atom, "\\FLAGGED") == 0)
				flags->flags |= MAIL_FLAGGED;
			else if (strcmp(atom, "\\DELETED") == 0)
				flags->flags |= MAIL_DELETED;
			else if (strcmp(atom, "\\SEEN") == 0)
				flags->flags |= MAIL_SEEN;
			else if (strcmp(atom, "\\DRAFT") == 0)
				flags->flags |= MAIL_DRAFT;
			else {
				client_send_tagline(client, t_strconcat(
					"BAD Invalid system flag ",
					atom, NULL));
				return FALSE;
			}
		} else {
			/* keyword - first make sure it's not a duplicate */
			keywords = buffer_get_data(buffer, &size);
			size /= sizeof(const char *);
			for (i = 0; i < size; i++) {
				if (strcasecmp(keywords[i], atom) == 0)
					break;
			}

			if (i == size) {
				if (!is_valid_keyword(client, old_keywords,
						      atom))
					return FALSE;
				buffer_append(buffer, &atom, sizeof(atom));
			}
		}

		args++;
	}

	flags->keywords = buffer_get_modifyable_data(buffer, &size);
	flags->keywords_count = size / sizeof(const char *);
	return TRUE;
}

static const char *
get_keywords_string(const char *keywords[], unsigned int keywords_count)
{
	string_t *str;
	unsigned int i;

	/* first see if there even is keywords */
	for (i = 0; i < keywords_count; i++) {
		if (keywords[i] != NULL)
			break;
	}

	if (i == keywords_count)
		return "";

	str = t_str_new(256);
	for (; i < keywords_count; i++) {
		if (keywords[i] != NULL) {
			str_append_c(str, ' ');
			str_append(str, keywords[i]);
		}
	}
	return str_c(str);
}

#define SYSTEM_FLAGS "\\Answered \\Flagged \\Deleted \\Seen \\Draft"

void client_send_mailbox_flags(struct client *client, struct mailbox *box,
			       const char *keywords[],
			       unsigned int keywords_count)
{
	const char *str;

	str = get_keywords_string(keywords, keywords_count);
	client_send_line(client,
		t_strconcat("* FLAGS ("SYSTEM_FLAGS, str, ")", NULL));

	if (mailbox_is_readonly(box)) {
		client_send_line(client, "* OK [PERMANENTFLAGS ()] "
				 "Read-only mailbox.");
	} else {
		client_send_line(client,
			t_strconcat("* OK [PERMANENTFLAGS ("SYSTEM_FLAGS, str,
				    mailbox_allow_new_keywords(box) ?
				    " \\*" : "", ")] Flags permitted.", NULL));
	}
}

void client_save_keywords(struct mailbox_keywords *dest,
			  const char *keywords[], unsigned int keywords_count)
{
	unsigned int i;

	p_clear(dest->pool);

	if (keywords_count == 0) {
		dest->keywords = NULL;
		dest->keywords_count = 0;
		return;
	}

	dest->keywords = p_new(dest->pool, char *, keywords_count);
	dest->keywords_count = keywords_count;

	for (i = 0; i < keywords_count; i++)
		dest->keywords[i] = p_strdup(dest->pool, keywords[i]);
}

int mailbox_name_equals(const char *box1, const char *box2)
{
	if (strcmp(box1, box2) == 0)
		return TRUE;

	return strcasecmp(box1, "INBOX") == 0 && strcasecmp(box2, "INBOX") == 0;
}

void msgset_generator_init(struct msgset_generator_context *ctx, string_t *str)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->str = str;
	ctx->last_uid = (uint32_t)-1;
}

void msgset_generator_next(struct msgset_generator_context *ctx, uint32_t uid)
{
	if (uid != ctx->last_uid+1) {
		if (ctx->first_uid == 0)
			;
		else if (ctx->first_uid == ctx->last_uid)
			str_printfa(ctx->str, "%u,", ctx->first_uid);
		else {
			str_printfa(ctx->str, "%u:%u,",
				    ctx->first_uid, ctx->last_uid);
		}
		ctx->first_uid = uid;
	}
	ctx->last_uid = uid;
}

void msgset_generator_finish(struct msgset_generator_context *ctx)
{
	if (ctx->first_uid == ctx->last_uid)
		str_printfa(ctx->str, "%u", ctx->first_uid);
	else
		str_printfa(ctx->str, "%u:%u", ctx->first_uid, ctx->last_uid);
}
