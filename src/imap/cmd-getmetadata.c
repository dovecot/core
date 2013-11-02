/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "imap-quote.h"
#include "imap-metadata.h"

struct imap_getmetadata_context {
	struct client_command_context *cmd;

	struct mailbox *box;
	struct mailbox_transaction_context *trans;

	ARRAY_TYPE(const_string) entries;
	uint32_t maxsize;
	uoff_t largest_seen_size;
	unsigned int depth;

	struct istream *cur_stream;
	uoff_t cur_stream_offset, cur_stream_size;

	struct mailbox_attribute_iter *iter;
	string_t *iter_entry_prefix;

	const char *key_prefix;
	unsigned int entry_idx;
	bool first_entry_sent;
	bool failed;
};

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
	const char *value;

	p_array_init(&ctx->entries, ctx->cmd->pool, 4);
	for (; !IMAP_ARG_IS_EOL(entries); entries++) {
		if (!imap_arg_get_astring(entries, &value)) {
			client_send_command_error(ctx->cmd, "Entry isn't astring");
			return FALSE;
		}
		if (!imap_metadata_verify_entry_name(ctx->cmd, value))
			return FALSE;

		/* names are case-insensitive so we'll always lowercase them */
		value = p_strdup(ctx->cmd->pool, t_str_lcase(value));
		array_append(&ctx->entries, &value, 1);
	}
	return TRUE;
}

static void cmd_getmetadata_send_entry(struct imap_getmetadata_context *ctx,
				       const char *entry)
{
	enum mail_attribute_type type;
	struct mail_attribute_value value;
	enum mail_error error;
	uoff_t value_len;
	const char *key;
	string_t *str;

	imap_metadata_entry2key(entry, ctx->key_prefix, &type, &key);
	if (ctx->key_prefix == NULL &&
	    strncmp(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT,
		    strlen(MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT)) == 0) {
		/* skip over dovecot's internal attributes. (if key_prefix
		   isn't NULL, we're getting server metadata, which is handled
		   inside the private metadata.) */
		return;
	}

	if (mailbox_attribute_get_stream(ctx->trans, type, key, &value) < 0) {
		(void)mailbox_get_last_error(ctx->box, &error);
		if (error != MAIL_ERROR_NOTFOUND && error != MAIL_ERROR_PERM) {
			client_send_untagged_storage_error(ctx->cmd->client,
				mailbox_get_storage(ctx->box));
			ctx->failed = TRUE;
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
			ctx->failed = TRUE;
			return;
		}
	} else {
		/* skip nonexistent entries */
		return;
	}

	if (value_len > ctx->maxsize) {
		/* value length is larger than specified MAXSIZE,
		   skip this entry */
		if (ctx->largest_seen_size < value_len)
			ctx->largest_seen_size = value_len;
		if (value.value_stream != NULL)
			i_stream_unref(&value.value_stream);
		return;
	}

	str = t_str_new(64);
	if (!ctx->first_entry_sent) {
		ctx->first_entry_sent = TRUE;
		str_append(str, "* METADATA ");
		imap_append_astring(str, mailbox_get_vname(ctx->box));
		str_append(str, " (");

		/* nothing can be sent until untagged METADATA is finished */
		ctx->cmd->client->output_cmd_lock = ctx->cmd;
	} else {
		str_append_c(str, ' ');
	}
	imap_append_astring(str, entry);
	if (value.value != NULL) {
		str_printfa(str, " {%"PRIuUOFF_T"}\r\n%s", value_len, value.value);
		o_stream_send(ctx->cmd->client->output, str_data(str), str_len(str));
	} else {
		str_printfa(str, " ~{%"PRIuUOFF_T"}\r\n", value_len);
		o_stream_send(ctx->cmd->client->output, str_data(str), str_len(str));

		ctx->cur_stream_offset = 0;
		ctx->cur_stream_size = value_len;
		ctx->cur_stream = value.value_stream;
	}
}

static bool
cmd_getmetadata_stream_continue(struct imap_getmetadata_context *ctx)
{
	off_t ret;

	o_stream_set_max_buffer_size(ctx->cmd->client->output, 0);
	ret = o_stream_send_istream(ctx->cmd->client->output, ctx->cur_stream);
	o_stream_set_max_buffer_size(ctx->cmd->client->output, (size_t)-1);

	if (ret > 0)
		ctx->cur_stream_offset += ret;

	if (ctx->cur_stream_offset == ctx->cur_stream_size) {
		/* finished */
		return TRUE;
	}
	if (ctx->cur_stream->stream_errno != 0) {
		i_error("read(%s) failed: %s",
			i_stream_get_name(ctx->cur_stream),
			i_stream_get_error(ctx->cur_stream));
		client_disconnect(ctx->cmd->client,
				  "Internal GETMETADATA failure");
		return -1;
	}
	if (!i_stream_have_bytes_left(ctx->cur_stream)) {
		/* Input stream gave less data than expected */
		i_error("read(%s): GETMETADATA stream had less data than expected",
			i_stream_get_name(ctx->cur_stream));
		client_disconnect(ctx->cmd->client,
				  "Internal GETMETADATA failure");
		return -1;
	}
	o_stream_set_flush_pending(ctx->cmd->client->output, TRUE);
	return FALSE;
}

static int cmd_getmetadata_send_entry_tree(struct imap_getmetadata_context *ctx,
					   const char *entry)
{
	const char *key;
	enum mail_attribute_type type;

	if (o_stream_get_buffer_used_size(ctx->cmd->client->output) >=
	    CLIENT_OUTPUT_OPTIMAL_SIZE) {
		if (o_stream_flush(ctx->cmd->client->output) <= 0) {
			o_stream_set_flush_pending(ctx->cmd->client->output, TRUE);
			return 0;
		}
	}

	if (ctx->iter != NULL) {
		/* DEPTH iteration */
		do {
			key = mailbox_attribute_iter_next(ctx->iter);
			if (key == NULL) {
				/* iteration finished, get to the next entry */
				if (mailbox_attribute_iter_deinit(&ctx->iter) < 0) {
					client_send_untagged_storage_error(ctx->cmd->client,
						mailbox_get_storage(ctx->box));
					ctx->failed = TRUE;
				}
				return -1;
			}
		} while (ctx->depth == 1 && strchr(key, '/') != NULL);
		entry = t_strconcat(str_c(ctx->iter_entry_prefix), key, NULL);
	}
	cmd_getmetadata_send_entry(ctx, entry);

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

		imap_metadata_entry2key(entry, ctx->key_prefix, &type, &key);
		type = type;
		ctx->iter = mailbox_attribute_iter_init(ctx->box, type,
			key[0] == '\0' ? "" : t_strconcat(key, "/", NULL));
		return 1;
	}
}

static void cmd_getmetadata_deinit(struct imap_getmetadata_context *ctx)
{
	ctx->cmd->client->output_cmd_lock = NULL;

	if (ctx->iter != NULL)
		(void)mailbox_attribute_iter_deinit(&ctx->iter);
	(void)mailbox_transaction_commit(&ctx->trans);
	mailbox_free(&ctx->box);
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

	if (ctx->failed) {
		client_send_tagline(cmd, "NO Getmetadata failed to send some entries");
	} else if (ctx->largest_seen_size != 0) {
		client_send_tagline(cmd, t_strdup_printf(
			"OK [METADATA LONGENTRIES %"PRIuUOFF_T"] "
			"Getmetadata completed.", ctx->largest_seen_size));
	} else {
		client_send_tagline(cmd, "OK Getmetadata completed.");
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

	if (!cmd->client->imap_metadata_enabled) {
		client_send_command_error(cmd, "METADATA disabled.");
		return TRUE;
	}

	ctx = p_new(cmd->pool, struct imap_getmetadata_context, 1);
	ctx->cmd = cmd;
	ctx->maxsize = (uint32_t)-1;
	ctx->cmd->context = ctx;

	if (imap_arg_get_list(&args[0], &options)) {
		if (!cmd_getmetadata_parse_options(ctx, options))
			return TRUE;
	}
	if (!imap_arg_get_astring(&args[1], &mailbox)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}
	if (!imap_arg_get_list(&args[2], &entries)) {
		if (!imap_arg_get_astring(&args[2], &entry_name) ||
		    !IMAP_ARG_IS_EOL(&args[3])) {
			client_send_command_error(cmd, "Invalid arguments.");
			return TRUE;
		}
		entries = args+2;
	}
	if (!imap_metadata_parse_entry_names(ctx, entries))
		return TRUE;

	if (mailbox[0] == '\0') {
		/* server attribute */
		ctx->key_prefix = MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER;
		ns = mail_namespace_find_inbox(cmd->client->user->namespaces);
		mailbox = "INBOX";
	} else {
		ns = client_find_namespace(cmd, &mailbox);
		if (ns == NULL)
			return TRUE;
	}

	ctx->box = mailbox_alloc(ns->list, mailbox, MAILBOX_FLAG_READONLY);
	if (mailbox_open(ctx->box) < 0) {
		client_send_storage_error(cmd, mailbox_get_storage(ctx->box));
		mailbox_free(&ctx->box);
		return TRUE;
	}
	ctx->trans = mailbox_transaction_begin(ctx->box, 0);

	if (ctx->depth > 0)
		ctx->iter_entry_prefix = str_new(cmd->pool, 128);

	if (!cmd_getmetadata_continue(cmd)) {
		cmd->state = CLIENT_COMMAND_STATE_WAIT_OUTPUT;
		cmd->func = cmd_getmetadata_continue;
		return FALSE;
	}
	return TRUE;
}
