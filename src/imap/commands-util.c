/* Copyright (C) 2002-2003 Timo Sirainen */

#include "common.h"
#include "array.h"
#include "buffer.h"
#include "str.h"
#include "str-sanitize.h"
#include "mail-storage.h"
#include "commands-util.h"
#include "imap-parser.h"
#include "imap-sync.h"
#include "imap-util.h"
#include "mail-namespace.h"

/* Maximum length for mailbox name, including it's path. This isn't fully
   exact since the user can create folder hierarchy with small names, then
   rename them to larger names. Mail storages should set more strict limits
   to them, mbox/maildir currently allow paths only up to PATH_MAX. */
#define MAILBOX_MAX_NAME_LEN 512

struct mail_namespace *
client_find_namespace(struct client_command_context *cmd, const char **mailbox)
{
	struct mail_namespace *ns;

	ns = mail_namespace_find(cmd->client->namespaces, mailbox);
	if (ns != NULL)
		return ns;

	client_send_tagline(cmd, "NO Unknown namespace.");
	return NULL;
}

struct mail_storage *
client_find_storage(struct client_command_context *cmd, const char **mailbox)
{
	struct mail_namespace *ns;

	ns = client_find_namespace(cmd, mailbox);
	return ns == NULL ? NULL : ns->storage;
}

bool client_verify_mailbox_name(struct client_command_context *cmd,
				const char *mailbox,
				bool should_exist, bool should_not_exist)
{
	struct mail_namespace *ns;
	struct mailbox_list *list;
	enum mailbox_name_status mailbox_status;
	const char *orig_mailbox, *p;

	orig_mailbox = mailbox;
	ns = client_find_namespace(cmd, &mailbox);
	if (ns == NULL)
		return FALSE;

	/* make sure it even looks valid */
	if (*mailbox == '\0') {
		client_send_tagline(cmd, "NO Empty mailbox name.");
		return FALSE;
	}

	if (ns->real_sep != ns->sep && ns->prefix_len < strlen(orig_mailbox)) {
		/* make sure there are no real separators used in the mailbox
		   name. */
		orig_mailbox += ns->prefix_len;
		for (p = orig_mailbox; *p != '\0'; p++) {
			if (*p == ns->real_sep) {
				client_send_tagline(cmd, t_strdup_printf(
					"NO Character not allowed "
					"in mailbox name: '%c'",
					ns->real_sep));
				return FALSE;
			}
		}
	}

	/* make sure two hierarchy separators aren't next to each others */
	for (p = mailbox+1; *p != '\0'; p++) {
		if (p[0] == ns->real_sep && p[-1] == ns->real_sep) {
			client_send_tagline(cmd, "NO Invalid mailbox name.");
			return FALSE;
		}
	}

	if (strlen(mailbox) > MAILBOX_MAX_NAME_LEN) {
		client_send_tagline(cmd, "NO Mailbox name too long.");
		return FALSE;
	}

	/* check what our storage thinks of it */
	list = mail_storage_get_list(ns->storage);
	if (mailbox_list_get_mailbox_name_status(list, mailbox,
						 &mailbox_status) < 0) {
		client_send_storage_error(cmd, ns->storage);
		return FALSE;
	}

	switch (mailbox_status) {
	case MAILBOX_NAME_EXISTS:
		if (should_exist || !should_not_exist)
			return TRUE;

		client_send_tagline(cmd, "NO Mailbox exists.");
		break;

	case MAILBOX_NAME_VALID:
		if (!should_exist)
			return TRUE;

		client_send_tagline(cmd, t_strconcat(
			"NO [TRYCREATE] Mailbox doesn't exist: ",
			str_sanitize(orig_mailbox, MAILBOX_MAX_NAME_LEN),
			NULL));
		break;

	case MAILBOX_NAME_INVALID:
		client_send_tagline(cmd, t_strconcat(
			"NO Invalid mailbox name: ",
			str_sanitize(orig_mailbox, MAILBOX_MAX_NAME_LEN),
			NULL));
		break;

	case MAILBOX_NAME_NOINFERIORS:
		client_send_tagline(cmd,
			"NO Mailbox parent doesn't allow inferior mailboxes.");
		break;

	default:
                i_unreached();
	}

	return FALSE;
}

bool client_verify_open_mailbox(struct client_command_context *cmd)
{
	if (cmd->client->mailbox != NULL)
		return TRUE;
	else {
		client_send_tagline(cmd, "BAD No mailbox selected.");
		return FALSE;
	}
}

void client_send_storage_error(struct client_command_context *cmd,
			       struct mail_storage *storage)
{
	const char *error;
	bool temporary_error;

	if (cmd->client->mailbox != NULL &&
	    mailbox_is_inconsistent(cmd->client->mailbox)) {
		/* we can't do forced CLOSE, so have to disconnect */
		client_disconnect_with_error(cmd->client,
			"Mailbox is in inconsistent state, please relogin.");
		return;
	}

	error = mail_storage_get_last_error(storage, &temporary_error);
	client_send_tagline(cmd, t_strconcat("NO ", error, NULL));
}

void client_send_untagged_storage_error(struct client *client,
					struct mail_storage *storage)
{
	const char *error;
	bool temporary_error;

	if (client->mailbox != NULL &&
	    mailbox_is_inconsistent(client->mailbox)) {
		/* we can't do forced CLOSE, so have to disconnect */
		client_disconnect_with_error(client,
			"Mailbox is in inconsistent state, please relogin.");
		return;
	}

	error = mail_storage_get_last_error(storage, &temporary_error);
	client_send_line(client, t_strconcat("* NO ", error, NULL));
}

static bool is_valid_keyword(struct client_command_context *cmd,
			     const char *keyword)
{
	const char *const *names;
	unsigned int i, count;

	/* if it already exists, skip validity checks */
	if (array_is_created(&cmd->client->keywords.keywords)) {
		names = array_get(&cmd->client->keywords.keywords, &count);
		for (i = 0; i < count; i++) {
			if (strcasecmp(names[i], keyword) == 0)
				return TRUE;
		}
	}

	if (strlen(keyword) > max_keyword_length) {
		client_send_tagline(cmd,
			t_strdup_printf("BAD Invalid keyword name '%s': "
					"Maximum length is %u characters",
					keyword, max_keyword_length));
		return FALSE;
	}

	return TRUE;
}

bool client_parse_mail_flags(struct client_command_context *cmd,
			     struct imap_arg *args, enum mail_flags *flags_r,
			     const char *const **keywords_r)
{
	const char *const *keywords;
	char *atom;
	buffer_t *buffer;
	size_t size, i;

	*flags_r = 0;
	*keywords_r = NULL;
	buffer = buffer_create_dynamic(cmd->pool, 256);

	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_send_command_error(cmd,
				"Flags list contains non-atoms.");
			return FALSE;
		}

		atom = IMAP_ARG_STR(args);
		if (*atom == '\\') {
			/* system flag */
			str_ucase(atom);
			if (strcmp(atom, "\\ANSWERED") == 0)
				*flags_r |= MAIL_ANSWERED;
			else if (strcmp(atom, "\\FLAGGED") == 0)
				*flags_r |= MAIL_FLAGGED;
			else if (strcmp(atom, "\\DELETED") == 0)
				*flags_r |= MAIL_DELETED;
			else if (strcmp(atom, "\\SEEN") == 0)
				*flags_r |= MAIL_SEEN;
			else if (strcmp(atom, "\\DRAFT") == 0)
				*flags_r |= MAIL_DRAFT;
			else {
				client_send_tagline(cmd, t_strconcat(
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
				if (!is_valid_keyword(cmd, atom))
					return FALSE;
				buffer_append(buffer, &atom, sizeof(atom));
			}
		}

		args++;
	}

	atom = NULL;
	buffer_append(buffer, &atom, sizeof(atom));
	*keywords_r = buffer->used == sizeof(atom) ? NULL :
		buffer_get_data(buffer, NULL);
	return TRUE;
}

static const char *get_keywords_string(const ARRAY_TYPE(keywords) *keywords)
{
	string_t *str;
	const char *const *names;
	unsigned int i, count;

	if (array_count(keywords) == 0)
		return "";

	str = t_str_new(256);
	names = array_get(keywords, &count);
	for (i = 0; i < count; i++) {
		str_append_c(str, ' ');
		str_append(str, names[i]);
	}
	return str_c(str);
}

#define SYSTEM_FLAGS "\\Answered \\Flagged \\Deleted \\Seen \\Draft"

void client_send_mailbox_flags(struct client *client, struct mailbox *box,
			       const ARRAY_TYPE(keywords) *keywords)
{
	const char *str;

	str = get_keywords_string(keywords);
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

bool client_save_keywords(struct mailbox_keywords *dest,
			  const ARRAY_TYPE(keywords) *keywords)
{
	const char *const *names, *const *old_names;
	unsigned int i, count, old_count;
	bool changed;

	names = array_get(keywords, &count);

	/* first check if anything changes */
	if (!array_is_created(&dest->keywords))
		changed = count != 0;
	else {
		old_names = array_get(&dest->keywords, &old_count);
		if (count != old_count)
			changed = TRUE;
		else {
			changed = FALSE;
			for (i = 0; i < count; i++) {
				if (strcmp(names[i], old_names[i]) != 0) {
					changed = TRUE;
					break;
				}
			}
		}
	}

	if (!changed)
		return FALSE;

	p_clear(dest->pool);
	p_array_init(&dest->keywords, dest->pool, array_count(keywords));

	for (i = 0; i < count; i++) {
		const char *name = p_strdup(dest->pool, names[i]);

		array_append(&dest->keywords, &name, 1);
	}
	return TRUE;
}

bool mailbox_equals(struct mailbox *box1, struct mail_storage *storage2,
		    const char *name2)
{
	struct mail_storage *storage1 = mailbox_get_storage(box1);
	const char *name1;

	if (storage1 != storage2)
		return FALSE;

        name1 = mailbox_get_name(box1);
	if (strcmp(name1, name2) == 0)
		return TRUE;

	return strcasecmp(name1, "INBOX") == 0 &&
		strcasecmp(name2, "INBOX") == 0;
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
