/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "istream.h"
#include "istream-sized.h"
#include "ostream.h"
#include "mailbox-list-iter.h"
#include "imap-utf7.h"
#include "imap-quote.h"
#include "imap-metadata.h"

struct imap_getmetadata_context {
	struct client_command_context *cmd;

	struct mailbox *box;
	struct imap_metadata_transaction *trans;
	struct mailbox_list_iterate_context *list_iter;

	ARRAY_TYPE(const_string) entries;
	uint32_t maxsize;
	uoff_t largest_seen_size;
	unsigned int depth;

	struct istream *cur_stream;

	struct imap_metadata_iter *iter;
	string_t *iter_entry_prefix;

	string_t *delayed_errors;
	enum mail_error last_error;

	unsigned int entry_idx;
	bool first_entry_sent;
};

static bool
cmd_getmetadata_mailbox_iter_next(struct imap_getmetadata_context *ctx);

static bool
cmd_getmetadata_parse_options(struct imap_getmetadata_context *ctx,
			      const struct imap_arg *options)
{
	const char *value;

	while (!IMAP_ARG_IS_EOL(options)) {
		if (imap_arg_atom_equals(options, "MAXSIZE")) {
			options++;
			if (!imap_arg_get_atom(options, &value) ||
			    str_to_uint32(value, &ctx->maxsize) < 0) {
				client_send_command_error(ctx->cmd,
					"Invalid value for MAXSIZE option");
				return FALSE;
			}
		} else if (imap_arg_atom_equals(options, "DEPTH")) {
			options++;
			if (!imap_arg_get_atom(options, &value)) {
				client_send_command_error(ctx->cmd,
					"Invalid value for DEPTH option");
				return FALSE;
			}
			if (strcmp(value, "0") == 0)
				ctx->depth = 0;
			else if (strcmp(value, "1") == 0)
				ctx->depth = 1;
			else if (strcmp(value, "infinity") == 0)
				ctx->depth = UINT_MAX;
			else {
				client_send_command_error(ctx->cmd,
					"Invalid value for DEPTH option");
				return FALSE;
			}
		} else {
			client_send_command_error(ctx->cmd, "Unknown option");
			return FALSE;
		}
		options++;
	}
	return TRUE;
}

static bool
imap_metadata_parse_entry_names(struct imap_getmetadata_context *ctx,
				const struct imap_arg *entries)
{
	const char *value, *client_error;

	p_array_init(&ctx->entries, ctx->cmd->pool, 4);
	for (; !IMAP_ARG_IS_EOL(entries); entries++) {
		if (!imap_arg_get_astring(entries, &value)) {
			client_send_command_error(ctx->cmd, "Entry isn't astring");
			return FALSE;
		}
		if (!imap_metadata_verify_entry_name(value, &client_error)) {
			client_send_command_error(ctx->cmd, client_error);
			return FALSE;
		}

		/* names are case-insensitive so we'll always lowercase them */
		value = p_strdup(ctx->cmd->pool, t_str_lcase(value));
		array_push_back(&ctx->entries, &value);
	}
	return TRUE;
}

static string_t *
metadata_add_entry(struct imap_getmetadata_context *ctx, const char *entry)
{
	string_t *str;

	str = t_str_new(64);
	if (!ctx->first_entry_sent) {
		string_t *mailbox_mutf7 = t_str_new(64);

		ctx->first_entry_sent = TRUE;
		str_append(str, "* METADATA ");
		if (ctx->box == NULL) {
			/* server metadata reply */
			str_append(str, "\"\"");
		} else {
			if (imap_utf8_to_utf7(mailbox_get_vname(ctx->box), mailbox_mutf7) < 0)
				i_unreached();
			imap_append_astring(str, str_c(mailbox_mutf7));
		}
		str_append(str, " (");

		/* nothing can be sent until untagged METADATA is finished */
		ctx->cmd->client->output_cmd_lock = ctx->cmd;
	} else {
		str_append_c(str, ' ');
	}
	imap_append_astring(str, entry);
	return str;
}

static void
cmd_getmetadata_send_nil_reply(struct imap_getmetadata_context *ctx,
			       const char *entry)
{
	string_t *str;

	/* client requested a specific entry that didn't exist.
	   we must return it as NIL. */
	str = metadata_add_entry(ctx, entry);
	str_append(str, " NIL");
	o_stream_nsend(ctx->cmd->client->output, str_data(str), str_len(str));
}

static void cmd_getmetadata_send_entry(struct imap_getmetadata_context *ctx,
				       const char *entry, bool require_reply)
{
	struct client *client = ctx->cmd->client;
	struct mail_attribute_value value;
	const char *error_string;
	enum mail_error error;
	uoff_t value_len;
	string_t *str;

	if (imap_metadata_get_stream(ctx->trans, entry, &value) < 0) {
		error_string = imap_metadata_transaction_get_last_error(
			ctx->trans, &error);
		if (error != MAIL_ERROR_NOTFOUND && error != MAIL_ERROR_PERM) {
			str_printfa(ctx->delayed_errors, "* NO %s\r\n",
				    error_string);
			ctx->last_error = error;
			return;
		}
	}

	if (value.value != NULL)
		value_len = strlen(value.value);
	else if (value.value_stream != NULL) {
		if (i_stream_get_size(value.value_stream, TRUE, &value_len) < 0) {
			i_error("GETMETADATA %s: i_stream_get_size(%s) failed: %s", entry,
				i_stream_get_name(value.value_stream),
				i_stream_get_error(value.value_stream));
			i_stream_unref(&value.value_stream);
			ctx->last_error = MAIL_ERROR_TEMP;
			return;
		}
	} else {
		/* skip nonexistent entries */
		if (require_reply)
			cmd_getmetadata_send_nil_reply(ctx, entry);
		return;
	}

	if (value_len > ctx->maxsize) {
		/* value length is larger than specified MAXSIZE,
		   skip this entry */
		if (ctx->largest_seen_size < value_len)
			ctx->largest_seen_size = value_len;
		i_stream_unref(&value.value_stream);
		return;
	}

	str = metadata_add_entry(ctx, entry);
	if (value.value != NULL) {
		str_printfa(str, " {%"PRIuUOFF_T"}\r\n%s", value_len, value.value);
		o_stream_nsend(client->output, str_data(str), str_len(str));
	} else {
		str_printfa(str, " ~{%"PRIuUOFF_T"}\r\n", value_len);
		o_stream_nsend(client->output, str_data(str), str_len(str));

		ctx->cur_stream = i_stream_create_sized(value.value_stream, value_len);
		i_stream_unref(&value.value_stream);
	}
}

static bool
cmd_getmetadata_stream_continue(struct imap_getmetadata_context *ctx)
{
	enum ostream_send_istream_result res;

	o_stream_set_max_buffer_size(ctx->cmd->client->output, 0);
	res = o_stream_send_istream(ctx->cmd->client->output, ctx->cur_stream);
	o_stream_set_max_buffer_size(ctx->cmd->client->output, (size_t)-1);

	switch (res) {
	case OSTREAM_SEND_ISTREAM_RESULT_FINISHED:
		return TRUE;
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_INPUT:
		i_unreached();
	case OSTREAM_SEND_ISTREAM_RESULT_WAIT_OUTPUT:
		return FALSE;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_INPUT:
		i_error("read(%s) failed: %s",
			i_stream_get_name(ctx->cur_stream),
			i_stream_get_error(ctx->cur_stream));
		client_disconnect(ctx->cmd->client,
				  "Internal GETMETADATA failure");
		return TRUE;
	case OSTREAM_SEND_ISTREAM_RESULT_ERROR_OUTPUT:
		/* client disconnected */
		return TRUE;
	}
	i_unreached();
}

static int
cmd_getmetadata_send_entry_tree(struct imap_getmetadata_context *ctx,
					   const char *entry)
{
	struct client *client = ctx->cmd->client;

	if (o_stream_get_buffer_used_size(client->output) >=
	    CLIENT_OUTPUT_OPTIMAL_SIZE) {
		if (o_stream_flush(client->output) <= 0) {
			o_stream_set_flush_pending(client->output, TRUE);
			return 0;
		}
	}

	if (ctx->iter != NULL) {
		const char *subentry;

		/* DEPTH iteration */
		do {
			subentry = imap_metadata_iter_next(ctx->iter);
			if (subentry == NULL) {
				/* iteration finished, get to the next entry */
				if (imap_metadata_iter_deinit(&ctx->iter) < 0) {
					str_printfa(ctx->delayed_errors, "* NO %s\r\n",
						imap_metadata_transaction_get_last_error(ctx->trans, &ctx->last_error));
				}
				return -1;
			}
		} while (ctx->depth == 1 && strchr(subentry, '/') != NULL);
		entry = t_strconcat(str_c(ctx->iter_entry_prefix), subentry, NULL);
	}
	cmd_getmetadata_send_entry(ctx, entry, ctx->iter == NULL);

	if (ctx->cur_stream != NULL) {
		if (!cmd_getmetadata_stream_continue(ctx))
			return 0;
		i_stream_unref(&ctx->cur_stream);
	}

	if (ctx->iter != NULL) {
		/* already iterating the entry */
		return 1;
	} else if (ctx->depth == 0) {
		/* no iteration for the entry */
		return -1;
	} else {
		/* we just sent the entry root. iterate its children. */
		str_truncate(ctx->iter_entry_prefix, 0);
		str_append(ctx->iter_entry_prefix, entry);
		str_append_c(ctx->iter_entry_prefix, '/');

		ctx->iter = imap_metadata_iter_init(ctx->trans, entry);
		return 1;
	}
}

static void cmd_getmetadata_iter_deinit(struct imap_getmetadata_context *ctx)
{
	if (ctx->iter != NULL)
		(void)imap_metadata_iter_deinit(&ctx->iter);
	if (ctx->trans != NULL)
		(void)imap_metadata_transaction_commit(&ctx->trans, NULL, NULL);
	if (ctx->box != NULL)
		mailbox_free(&ctx->box);
	ctx->first_entry_sent = FALSE;
	ctx->entry_idx = 0;
}

static void cmd_getmetadata_deinit(struct imap_getmetadata_context *ctx)
{
	struct client_command_context *cmd = ctx->cmd;

	cmd_getmetadata_iter_deinit(ctx);
	cmd->client->output_cmd_lock = NULL;

	if (ctx->list_iter != NULL &&
	    mailbox_list_iter_deinit(&ctx->list_iter) < 0)
		client_send_list_error(cmd, cmd->client->user->namespaces->list);
	else if (ctx->last_error != 0) {
		client_send_tagline(cmd, "NO Getmetadata failed to send some entries");
	} else if (ctx->largest_seen_size != 0) {
		client_send_tagline(cmd, t_strdup_printf(
			"OK [METADATA LONGENTRIES %"PRIuUOFF_T"] "
			"Getmetadata completed.", ctx->largest_seen_size));
	} else {
		client_send_tagline(cmd, "OK Getmetadata completed.");
	}
}

static bool cmd_getmetadata_continue(struct client_command_context *cmd)
{
	struct imap_getmetadata_context *ctx = cmd->context;
	const char *const *entries;
	unsigned int count;
	int ret;

	if (cmd->cancel) {
		cmd_getmetadata_deinit(ctx);
		return TRUE;
	}

	if (ctx->cur_stream != NULL) {
		if (!cmd_getmetadata_stream_continue(ctx))
			return FALSE;
		i_stream_unref(&ctx->cur_stream);
	}

	entries = array_get(&ctx->entries, &count);
	for (; ctx->entry_idx < count; ctx->entry_idx++) {
		do {
			T_BEGIN {
				ret = cmd_getmetadata_send_entry_tree(ctx, entries[ctx->entry_idx]);
			} T_END;
			if (ret == 0)
				return FALSE;
		} while (ret > 0);
	}
	if (ctx->first_entry_sent)
		o_stream_nsend_str(cmd->client->output, ")\r\n");

	if (str_len(ctx->delayed_errors) > 0) {
		o_stream_nsend(cmd->client->output,
			       str_data(ctx->delayed_errors),
			       str_len(ctx->delayed_errors));
		str_truncate(ctx->delayed_errors, 0);
	}

	cmd_getmetadata_iter_deinit(ctx);
	if (ctx->list_iter != NULL)
		return cmd_getmetadata_mailbox_iter_next(ctx);
	cmd_getmetadata_deinit(ctx);
	return TRUE;
}

static bool
cmd_getmetadata_start(struct imap_getmetadata_context *ctx)
{
	struct client_command_context *cmd = ctx->cmd;

	if (ctx->depth > 0)
		ctx->iter_entry_prefix = str_new(cmd->pool, 128);
	imap_metadata_transaction_validated_only(ctx->trans,
		!cmd->client->set->imap_metadata);

	if (!cmd_getmetadata_continue(cmd)) {
		cmd->state = CLIENT_COMMAND_STATE_WAIT_OUTPUT;
		cmd->func = cmd_getmetadata_continue;
		return FALSE;
	}
	return TRUE;
}

static bool
cmd_getmetadata_server(struct imap_getmetadata_context *ctx)
{
	ctx->trans = imap_metadata_transaction_begin_server(ctx->cmd->client->user);
	return cmd_getmetadata_start(ctx);
}

static int
cmd_getmetadata_try_mailbox(struct imap_getmetadata_context *ctx,
			    struct mail_namespace *ns, const char *mailbox)
{
	ctx->box = mailbox_alloc(ns->list, mailbox, MAILBOX_FLAG_READONLY);
	mailbox_set_reason(ctx->box, "GETMETADATA");
	if (mailbox_open(ctx->box) < 0)
		return -1;

	ctx->trans = imap_metadata_transaction_begin(ctx->box);
	return cmd_getmetadata_start(ctx) ? 1 : 0;
}

static bool
cmd_getmetadata_mailbox(struct imap_getmetadata_context *ctx,
			struct mail_namespace *ns, const char *mailbox)
{
	int ret;

	ret = cmd_getmetadata_try_mailbox(ctx, ns, mailbox);
	if (ret < 0) {
		client_send_box_error(ctx->cmd, ctx->box);
		mailbox_free(&ctx->box);
	}
	return ret != 0;
}

static bool
cmd_getmetadata_mailbox_iter_next(struct imap_getmetadata_context *ctx)
{
	const struct mailbox_info *info;
	int ret;

	while ((info = mailbox_list_iter_next(ctx->list_iter)) != NULL) {
		if ((info->flags & (MAILBOX_NOSELECT | MAILBOX_NONEXISTENT)) != 0)
			continue;
		ret = cmd_getmetadata_try_mailbox(ctx, info->ns, info->vname);
		if (ret > 0) {
			/* we'll already recursively went through
			   all the mailboxes (FIXME: ugly and potentially
			   stack consuming) */
			return TRUE;
		} else if (ret == 0) {
			/* need to send more data later */
			return FALSE;
		}
		T_BEGIN {
			client_send_line(ctx->cmd->client, t_strdup_printf(
				"* NO Failed to open mailbox %s: %s",
				info->vname, mailbox_get_last_error(ctx->box, NULL)));
		} T_END;
		mailbox_free(&ctx->box);
	}
	cmd_getmetadata_deinit(ctx);
	return TRUE;
}

bool cmd_getmetadata(struct client_command_context *cmd)
{
	struct imap_getmetadata_context *ctx;
	struct mail_namespace *ns;
	const struct imap_arg *args, *options, *entries;
	const char *mailbox, *entry_name;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	ctx = p_new(cmd->pool, struct imap_getmetadata_context, 1);
	ctx->cmd = cmd;
	ctx->maxsize = (uint32_t)-1;
	ctx->cmd->context = ctx;
	ctx->delayed_errors = str_new(cmd->pool, 128);

	if (imap_arg_get_list(&args[0], &options)) {
		if (!cmd_getmetadata_parse_options(ctx, options))
			return TRUE;
		args++;
	}
	if (!imap_arg_get_astring(&args[0], &mailbox)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}
	if (!imap_arg_get_list(&args[1], &entries)) {
		if (!imap_arg_get_astring(&args[1], &entry_name) ||
		    !IMAP_ARG_IS_EOL(&args[2])) {
			client_send_command_error(cmd, "Invalid arguments.");
			return TRUE;
		}
		entries = args+1;
	}
	if (!imap_metadata_parse_entry_names(ctx, entries))
		return TRUE;

	if (mailbox[0] == '\0') {
		/* server attribute */
		return cmd_getmetadata_server(ctx);
	} else if (strchr(mailbox, '*') == NULL &&
		   strchr(mailbox, '%') == NULL) {
		/* mailbox attribute */
		ns = client_find_namespace(cmd, &mailbox);
		if (ns == NULL)
			return TRUE;
		return cmd_getmetadata_mailbox(ctx, ns, mailbox);
	} else {
		/* wildcards in mailbox name. this isn't supported by RFC 5464,
		   but it was in the earlier drafts and is already used by
		   some software (Horde). */
		const char *patterns[2];
		patterns[0] = mailbox; patterns[1] = NULL;

		ctx->list_iter =
			mailbox_list_iter_init_namespaces(
				cmd->client->user->namespaces,
				patterns, MAIL_NAMESPACE_TYPE_MASK_ALL, 0);
		return cmd_getmetadata_mailbox_iter_next(ctx);
	}
}
