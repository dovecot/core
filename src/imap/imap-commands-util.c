/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "array.h"
#include "buffer.h"
#include "str.h"
#include "str-sanitize.h"
#include "imap-resp-code.h"
#include "imap-parser.h"
#include "imap-sync.h"
#include "imap-utf7.h"
#include "imap-util.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "imap-commands-util.h"

struct mail_namespace *
client_find_namespace_full(struct client *client,
			   const char **mailbox, const char **error_r)
{
	struct mail_namespace *namespaces = client->user->namespaces;
	struct mail_namespace *ns;
	string_t *utf8_name;

	utf8_name = t_str_new(64);
	if (imap_utf7_to_utf8(*mailbox, utf8_name) < 0) {
		*error_r = "NO Mailbox name is not valid mUTF-7";
		return NULL;
	}

	ns = mail_namespace_find(namespaces, str_c(utf8_name));
	if ((ns->flags & NAMESPACE_FLAG_AUTOCREATED) != 0 &&
	    ns->prefix_len == 0) {
		/* this matched only the autocreated prefix="" namespace.
		   give a nice human-readable error message */
		*error_r = t_strdup_printf(
			"NO Client tried to access nonexistent namespace. "
			"(Mailbox name should probably be prefixed with: %s)",
			mail_namespace_find_inbox(namespaces)->prefix);
		return NULL;
	}

	if ((client->set->parsed_workarounds &
	     		WORKAROUND_TB_EXTRA_MAILBOX_SEP) != 0 &&
	    str_len(utf8_name) > 0 &&
	    str_c(utf8_name)[str_len(utf8_name)-1] == mail_namespace_get_sep(ns)) {
		/* drop the extra trailing hierarchy separator */
		str_truncate(utf8_name, str_len(utf8_name)-1);
	}

	*mailbox = str_c(utf8_name);
	return ns;
}

struct mail_namespace *
client_find_namespace(struct client_command_context *cmd, const char **mailbox)
{
	struct mail_namespace *ns;
	const char *error;

	ns = client_find_namespace_full(cmd->client, mailbox, &error);
	if (ns == NULL)
		client_send_tagline(cmd, error);
	return ns;
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

void imap_client_close_mailbox(struct client *client)
{
	struct mailbox *box;

	i_assert(client->mailbox != NULL);

	if (array_is_created(&client->fetch_failed_uids))
		array_clear(&client->fetch_failed_uids);
	client_search_updates_free(client);

	box = client->mailbox;
	client->mailbox = NULL;

	mailbox_free(&box);
	client_update_mailbox_flags(client, NULL);
}

int client_open_save_dest_box(struct client_command_context *cmd,
			      const char *name, struct mailbox **destbox_r)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *error_string;
	enum mail_error error;

	ns = client_find_namespace(cmd, &name);
	if (ns == NULL)
		return -1;

	if (cmd->client->mailbox != NULL &&
	    mailbox_equals(cmd->client->mailbox, ns, name)) {
		*destbox_r = cmd->client->mailbox;
		return 0;
	}
	box = mailbox_alloc(ns->list, name, MAILBOX_FLAG_SAVEONLY);
	mailbox_set_reason(box, cmd->name);
	if (mailbox_open(box) < 0) {
		error_string = mailbox_get_last_error(box, &error);
		if (error == MAIL_ERROR_NOTFOUND) {
			client_send_tagline(cmd,  t_strdup_printf(
				"NO [TRYCREATE] %s", error_string));
		} else {
			client_send_box_error(cmd, box);
		}
		mailbox_free(&box);
		return -1;
	}
	if (mailbox_enable(box, client_enabled_mailbox_features(cmd->client)) < 0) {
		client_send_box_error(cmd, box);
		mailbox_free(&box);
		return -1;
	}
	*destbox_r = box;
	return 0;
}

const char *imap_client_command_get_reason(struct client_command_context *cmd)
{
	return cmd->args[0] == '\0' ? cmd->name :
		t_strdup_printf("%s %s", cmd->name, cmd->human_args);
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
	case MAIL_ERROR_LOOKUP_ABORTED: /* BUG: shouldn't be visible here */
		resp_code = IMAP_RESP_CODE_SERVERBUG;
		break;
	case MAIL_ERROR_UNAVAILABLE:
		resp_code = IMAP_RESP_CODE_UNAVAILABLE;
		break;
	case MAIL_ERROR_NOTPOSSIBLE:
	case MAIL_ERROR_PARAMS:
		resp_code = IMAP_RESP_CODE_CANNOT;
		break;
	case MAIL_ERROR_PERM:
		resp_code = IMAP_RESP_CODE_NOPERM;
		break;
	case MAIL_ERROR_NOQUOTA:
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
	case MAIL_ERROR_CONVERSION:
	case MAIL_ERROR_INVALIDDATA:
		break;
	case MAIL_ERROR_LIMIT:
		resp_code = IMAP_RESP_CODE_LIMIT;
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

void client_disconnect_if_inconsistent(struct client *client)
{
	if (client->mailbox != NULL &&
	    mailbox_is_inconsistent(client->mailbox)) {
		/* we can't do forced CLOSE, so have to disconnect */
		client_disconnect_with_error(client,
			"IMAP session state is inconsistent, please relogin.");
	}
}

void client_send_box_error(struct client_command_context *cmd,
			   struct mailbox *box)
{
	client_send_storage_error(cmd, mailbox_get_storage(box));
}

void client_send_storage_error(struct client_command_context *cmd,
			       struct mail_storage *storage)
{
	const char *error_string;
	enum mail_error error;

	error_string = mail_storage_get_last_error(storage, &error);
	client_send_tagline(cmd, imap_get_error_string(cmd, error_string,
						       error));

	client_disconnect_if_inconsistent(cmd->client);
}

void client_send_untagged_storage_error(struct client *client,
					struct mail_storage *storage)
{
	const char *error_string;
	enum mail_error error;

	error_string = mail_storage_get_last_error(storage, &error);
	client_send_line(client, t_strconcat("* NO ", error_string, NULL));

	client_disconnect_if_inconsistent(client);
}

bool client_parse_mail_flags(struct client_command_context *cmd,
			     const struct imap_arg *args,
			     enum mail_flags *flags_r,
			     const char *const **keywords_r)
{
	const char *atom;
	enum mail_flags flag;
	ARRAY(const char *) keywords;

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
				client_send_command_error(cmd, t_strconcat(
					"Invalid system flag ", atom, NULL));
				return FALSE;
			}
		} else {
			/* keyword validity checks are done by lib-storage */
			array_push_back(&keywords, &atom);
		}

		args++;
	}

	if (array_count(&keywords) == 0)
		*keywords_r = NULL;
	else {
		array_append_zero(&keywords); /* NULL-terminate */
		*keywords_r = array_front(&keywords);
	}
	return TRUE;
}

void client_send_mailbox_flags(struct client *client, bool selecting)
{
	struct mailbox_status status;
	unsigned int count = array_count(client->keywords.names);
	const char *const *keywords;
	string_t *str;

	if (!selecting && count == client->keywords.announce_count) {
		/* no changes to keywords and we're not selecting a mailbox */
		return;
	}

	client->keywords.announce_count = count;
	mailbox_get_open_status(client->mailbox, STATUS_PERMANENT_FLAGS,
				&status);

	keywords = count == 0 ? NULL :
		array_front(client->keywords.names);
	str = t_str_new(128);
	str_append(str, "* FLAGS (");
	imap_write_flags(str, status.flags, keywords);
	str_append_c(str, ')');
	client_send_line(client, str_c(str));

	if (!status.permanent_keywords)
		keywords = NULL;

	str_truncate(str, 0);
	str_append(str, "* OK [PERMANENTFLAGS (");
	imap_write_flags(str, status.permanent_flags, keywords);
	if (status.allow_new_keywords) {
		if (status.permanent_flags != 0 || keywords != NULL)
			str_append_c(str, ' ');
		str_append(str, "\\*");
	}
	str_append(str, ")] ");

	if (mailbox_is_readonly(client->mailbox))
		str_append(str, "Read-only mailbox.");
	else
		str_append(str, "Flags permitted.");
	client_send_line(client, str_c(str));
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
		array_push_back(dest, &all_names[kw_index]);
	}

	array_append_zero(dest);
	return array_front(dest);
}

void msgset_generator_init(struct msgset_generator_context *ctx, string_t *str)
{
	i_zero(ctx);
	ctx->str = str;
	ctx->last_uid = (uint32_t)-1;
}

void msgset_generator_next(struct msgset_generator_context *ctx, uint32_t uid)
{
	i_assert(uid > 0);

	if (uid-1 != ctx->last_uid) {
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
