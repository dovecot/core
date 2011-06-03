/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "array.h"
#include "buffer.h"
#include "str.h"
#include "str-sanitize.h"
#include "imap-resp-code.h"
#include "imap-parser.h"
#include "imap-sync.h"
#include "imap-util.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "imap-commands-util.h"

/* Maximum length for mailbox name, including it's path. This isn't fully
   exact since the user can create folder hierarchy with small names, then
   rename them to larger names. Mail storages should set more strict limits
   to them, mbox/maildir currently allow paths only up to PATH_MAX. */
#define MAILBOX_MAX_NAME_LEN 512

struct mail_namespace *
client_find_namespace(struct client_command_context *cmd, const char *mailbox,
		      const char **storage_name_r,
		      enum mailbox_name_status *mailbox_status_r)
{
	struct mail_namespace *namespaces = cmd->client->user->namespaces;
	struct mail_namespace *ns;
	const char *storage_name, *p;
	unsigned int storage_name_len;

	storage_name = mailbox;
	ns = mail_namespace_find(namespaces, &storage_name);
	if (ns == NULL) {
		client_send_tagline(cmd, t_strdup_printf(
			"NO Client tried to access nonexistent namespace. "
			"(Mailbox name should probably be prefixed with: %s)",
			mail_namespace_find_inbox(namespaces)->prefix));
		return NULL;
	}

	if (mailbox_status_r == NULL) {
		*storage_name_r = storage_name;
		return ns;
	}

	/* make sure it even looks valid */
	if (*storage_name == '\0' && !(*mailbox != '\0' && ns->list)) {
		client_send_tagline(cmd, "NO Empty mailbox name.");
		return NULL;
	}

	storage_name_len = strlen(storage_name);
	if ((cmd->client->set->parsed_workarounds &
	     		WORKAROUND_TB_EXTRA_MAILBOX_SEP) != 0 &&
	    storage_name_len > 0 &&
	    storage_name[storage_name_len-1] == ns->real_sep) {
		/* drop the extra trailing hierarchy separator */
		storage_name = t_strndup(storage_name, storage_name_len-1);
	}

	if (strlen(mailbox) == ns->prefix_len) {
		/* trying to open "ns prefix/" */
		client_send_tagline(cmd, "NO Invalid mailbox name.");
		return NULL;
	}

	if (ns->real_sep != ns->sep && ns->prefix_len < strlen(mailbox)) {
		/* make sure there are no real separators used in the mailbox
		   name. */
		mailbox += ns->prefix_len;
		for (p = mailbox; *p != '\0'; p++) {
			if (*p == ns->real_sep) {
				client_send_tagline(cmd, t_strdup_printf(
					"NO Character not allowed "
					"in mailbox name: '%c'",
					ns->real_sep));
				return NULL;
			}
		}
	}

	/* make sure two hierarchy separators aren't next to each others */
	for (p = storage_name+1; *p != '\0'; p++) {
		if (p[0] == ns->real_sep && p[-1] == ns->real_sep) {
			client_send_tagline(cmd, "NO Invalid mailbox name.");
			return NULL;
		}
	}

	if (storage_name_len > MAILBOX_MAX_NAME_LEN) {
		client_send_tagline(cmd, "NO Mailbox name too long.");
		return NULL;
	}

	/* check what our storage thinks of it */
	if (mailbox_list_get_mailbox_name_status(ns->list, storage_name,
						 mailbox_status_r) < 0) {
		client_send_list_error(cmd, ns->list);
		return NULL;
	}
	*storage_name_r = storage_name;
	return ns;
}

void client_fail_mailbox_name_status(struct client_command_context *cmd,
				     const char *mailbox_name,
				     const char *resp_code,
				     enum mailbox_name_status status)
{
	switch (status) {
	case MAILBOX_NAME_EXISTS_MAILBOX:
	case MAILBOX_NAME_EXISTS_DIR:
		client_send_tagline(cmd, t_strconcat(
			"NO [", IMAP_RESP_CODE_ALREADYEXISTS,
			"] Mailbox already exists: ",
			str_sanitize(mailbox_name, MAILBOX_MAX_NAME_LEN),
			NULL));
		break;
	case MAILBOX_NAME_VALID:
		if (resp_code == NULL)
			resp_code = "";
		else
			resp_code = t_strconcat("[", resp_code, "] ", NULL);
		client_send_tagline(cmd, t_strconcat(
			"NO ", resp_code, "Mailbox doesn't exist: ",
			str_sanitize(mailbox_name, MAILBOX_MAX_NAME_LEN),
			NULL));
		break;
	case MAILBOX_NAME_INVALID:
		client_send_tagline(cmd, t_strconcat(
			"NO Invalid mailbox name: ",
			str_sanitize(mailbox_name, MAILBOX_MAX_NAME_LEN),
			NULL));
		break;
	case MAILBOX_NAME_NOINFERIORS:
		client_send_tagline(cmd,
			"NO Parent mailbox doesn't allow child mailboxes.");
		break;
	}
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

const char *
imap_get_error_string(struct client_command_context *cmd,
		      const char *error_string, enum mail_error error)
{
	const char *resp_code = NULL;

	switch (error) {
	case MAIL_ERROR_NONE:
		break;
	case MAIL_ERROR_TEMP:
		resp_code = IMAP_RESP_CODE_SERVERBUG;
		break;
	case MAIL_ERROR_NOTPOSSIBLE:
	case MAIL_ERROR_PARAMS:
		resp_code = IMAP_RESP_CODE_CANNOT;
		break;
	case MAIL_ERROR_PERM:
		resp_code = IMAP_RESP_CODE_NOPERM;
		break;
	case MAIL_ERROR_NOSPACE:
		resp_code = IMAP_RESP_CODE_OVERQUOTA;
		break;
	case MAIL_ERROR_NOTFOUND:
		if ((cmd->cmd_flags & COMMAND_FLAG_USE_NONEXISTENT) != 0)
			resp_code = IMAP_RESP_CODE_NONEXISTENT;
		break;
	case MAIL_ERROR_EXISTS:
		resp_code = IMAP_RESP_CODE_ALREADYEXISTS;
		break;
	case MAIL_ERROR_EXPUNGED:
		resp_code = IMAP_RESP_CODE_EXPUNGEISSUED;
		break;
	case MAIL_ERROR_INUSE:
		resp_code = IMAP_RESP_CODE_INUSE;
		break;
	}
	if (resp_code == NULL || *error_string == '[')
		return t_strconcat("NO ", error_string, NULL);
	else
		return t_strdup_printf("NO [%s] %s", resp_code, error_string);
}

void client_send_list_error(struct client_command_context *cmd,
			    struct mailbox_list *list)
{
	const char *error_string;
	enum mail_error error;

	error_string = mailbox_list_get_last_error(list, &error);
	client_send_tagline(cmd, imap_get_error_string(cmd, error_string,
						       error));
}

void client_send_storage_error(struct client_command_context *cmd,
			       struct mail_storage *storage)
{
	const char *error_string;
	enum mail_error error;

	if (cmd->client->mailbox != NULL &&
	    mailbox_is_inconsistent(cmd->client->mailbox)) {
		/* we can't do forced CLOSE, so have to disconnect */
		client_disconnect_with_error(cmd->client,
			"IMAP session state is inconsistent, please relogin.");
		return;
	}

	error_string = mail_storage_get_last_error(storage, &error);
	client_send_tagline(cmd, imap_get_error_string(cmd, error_string,
						       error));
}

void client_send_untagged_storage_error(struct client *client,
					struct mail_storage *storage)
{
	const char *error_string;
	enum mail_error error;

	if (client->mailbox != NULL &&
	    mailbox_is_inconsistent(client->mailbox)) {
		/* we can't do forced CLOSE, so have to disconnect */
		client_disconnect_with_error(client,
			"IMAP session state is inconsistent, please relogin.");
		return;
	}

	error_string = mail_storage_get_last_error(storage, &error);
	client_send_line(client, t_strconcat("* NO ", error_string, NULL));
}

bool client_parse_mail_flags(struct client_command_context *cmd,
			     const struct imap_arg *args,
			     enum mail_flags *flags_r,
			     const char *const **keywords_r)
{
	const char *atom;
	enum mail_flags flag;
	ARRAY_DEFINE(keywords, const char *);

	*flags_r = 0;
	*keywords_r = NULL;
	p_array_init(&keywords, cmd->pool, 16);

	while (!IMAP_ARG_IS_EOL(args)) {
		if (!imap_arg_get_atom(args, &atom)) {
			client_send_command_error(cmd,
				"Flags list contains non-atoms.");
			return FALSE;
		}

		if (*atom == '\\') {
			/* system flag */
			atom = t_str_ucase(atom);
			flag = imap_parse_system_flag(atom);
			if (flag != 0 && flag != MAIL_RECENT)
				*flags_r |= flag;
			else {
				client_send_tagline(cmd, t_strconcat(
					"BAD Invalid system flag ",
					atom, NULL));
				return FALSE;
			}
		} else {
			/* keyword validity checks are done by lib-storage */
			array_append(&keywords, &atom, 1);
		}

		args++;
	}

	if (array_count(&keywords) == 0)
		*keywords_r = NULL;
	else {
		(void)array_append_space(&keywords); /* NULL-terminate */
		*keywords_r = array_idx(&keywords, 0);
	}
	return TRUE;
}

static const char *get_keywords_string(const ARRAY_TYPE(keywords) *keywords)
{
	string_t *str;
	const char *const *names;

	str = t_str_new(256);
	array_foreach(keywords, names) {
		const char *name = *names;

		str_append_c(str, ' ');
		str_append(str, name);
	}
	return str_c(str);
}

#define SYSTEM_FLAGS "\\Answered \\Flagged \\Deleted \\Seen \\Draft"

void client_send_mailbox_flags(struct client *client, bool selecting)
{
	unsigned int count = array_count(client->keywords.names);
	const char *str;

	if (!selecting && count == client->keywords.announce_count) {
		/* no changes to keywords and we're not selecting a mailbox */
		return;
	}

	client->keywords.announce_count = count;
	str = count == 0 ? "" : get_keywords_string(client->keywords.names);
	client_send_line(client,
		t_strconcat("* FLAGS ("SYSTEM_FLAGS, str, ")", NULL));

	if (mailbox_is_readonly(client->mailbox)) {
		client_send_line(client, "* OK [PERMANENTFLAGS ()] "
				 "Read-only mailbox.");
	} else {
		bool star = mailbox_allow_new_keywords(client->mailbox);

		client_send_line(client,
			t_strconcat("* OK [PERMANENTFLAGS ("SYSTEM_FLAGS, str,
				    star ? " \\*" : "",
				    ")] Flags permitted.", NULL));
	}
}

void client_update_mailbox_flags(struct client *client,
				 const ARRAY_TYPE(keywords) *keywords)
{
	client->keywords.names = keywords;
	client->keywords.announce_count = 0;
}

const char *const *
client_get_keyword_names(struct client *client, ARRAY_TYPE(keywords) *dest,
			 const ARRAY_TYPE(keyword_indexes) *src)
{
	const unsigned int *kw_indexes;
	const char *const *all_names;
	unsigned int all_count;

	client_send_mailbox_flags(client, FALSE);

	/* convert indexes to names */
	all_names = array_get(client->keywords.names, &all_count);
	array_clear(dest);
	array_foreach(src, kw_indexes) {
		unsigned int kw_index = *kw_indexes;

		i_assert(kw_index < all_count);
		array_append(dest, &all_names[kw_index], 1);
	}

	(void)array_append_space(dest);
	return array_idx(dest, 0);
}

bool mailbox_equals(const struct mailbox *box1,
		    const struct mail_namespace *ns2, const char *name2)
{
	struct mail_namespace *ns1 = mailbox_get_namespace(box1);
	const char *name1;

	if (ns1 != ns2)
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
