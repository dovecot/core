/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "pop3-common.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "hash.h"
#include "str.h"
#include "strfuncs.h"
#include "var-expand.h"
#include "message-size.h"
#include "mail-storage.h"
#include "mail-storage-settings.h"
#include "mail-search-build.h"
#include "pop3-capability.h"
#include "pop3-commands.h"

static enum mail_sort_type pop3_sort_program[] = {
	MAIL_SORT_POP3_ORDER,
	MAIL_SORT_END
};

static uint32_t msgnum_to_seq(struct client *client, uint32_t msgnum)
{
	return msgnum < client->msgnum_to_seq_map_count ?
		client->msgnum_to_seq_map[msgnum] : msgnum+1;
}

static const char *get_msgnum(struct pop3_command_context *cctx,
			      unsigned int *msgnum, bool thenspace)
{
	unsigned int num;

	if (*cctx->args < '0' || *cctx->args > '9') {
		client_send_line(cctx->client,
				 "-ERR Invalid message number: %s", cctx->args);
		return NULL;
	}
	if (str_parse_uint(cctx->args, &num, &cctx->args) < 0) {
		client_send_line(cctx->client,
				 "-ERR Message number too large: %s", cctx->args);
		return NULL;
	}
	if (*cctx->args != (thenspace ? ' ' : '\0')) {
		client_send_line(cctx->client,
				 "-ERR Noise after message number: %s", cctx->args);
		return NULL;
	}
	if (num == 0 || num > cctx->client->messages_count) {
		client_send_line(cctx->client,
				 "-ERR There's no message %u.", num);
		return NULL;
	}
	num--;

	if (cctx->client->deleted) {
		if ((cctx->client->deleted_bitmask[num / CHAR_BIT] &
		     (1 << (num % CHAR_BIT))) != 0) {
			client_send_line(cctx->client, "-ERR Message is deleted.");
			return NULL;
		}
	}

	while (*cctx->args == ' ') cctx->args++;

	*msgnum = num;
	return cctx->args;
}

static const char *get_size(struct pop3_command_context *cctx,
			    uoff_t *size, bool thenspace)
{
	uoff_t num;

	if (*cctx->args < '0' || *cctx->args > '9') {
		client_send_line(cctx->client, "-ERR Invalid size: %s",
				 cctx->args);
		return NULL;
	}
	if (str_parse_uoff(cctx->args, &num, &cctx->args) < 0) {
		client_send_line(cctx->client, "-ERR Size too large: %s",
				 cctx->args);
		return NULL;
	}
	if (*cctx->args != (thenspace ? ' ' : '\0')) {
		client_send_line(cctx->client, "-ERR Noise after size: %s", cctx->args);
		return NULL;
	}

	while (*cctx->args == ' ') cctx->args++;

	*size = num;
	return cctx->args;
}

static int cmd_capa(struct pop3_command_context *cctx)
{
	client_send_line(cctx->client, "+OK\r\n"POP3_CAPABILITY_REPLY".");
	return 1;
}

static int cmd_dele(struct pop3_command_context *cctx)
{
	unsigned int msgnum;

	if (get_msgnum(cctx, &msgnum, FALSE) == NULL)
		return -1;

	if (!cctx->client->deleted) {
		cctx->client->deleted_bitmask = i_malloc(MSGS_BITMASK_SIZE(cctx->client));
		cctx->client->deleted = TRUE;
	}

	cctx->client->deleted_bitmask[msgnum / CHAR_BIT] |= 1 << (msgnum % CHAR_BIT);
	cctx->client->deleted_count++;
	cctx->client->deleted_size += cctx->client->message_sizes[msgnum];
	client_send_line(cctx->client, "+OK Marked to be deleted.");
	return 1;
}

struct cmd_list_context {
	unsigned int msgnum;
};

static void cmd_list_callback(struct client *client)
{
	struct cmd_list_context *ctx = client->cmd_context;

	for (; ctx->msgnum != client->messages_count; ctx->msgnum++) {
		if (client->output->closed)
			break;
		if (POP3_CLIENT_OUTPUT_FULL(client)) {
			/* buffer full */
			return;
		}

		if (client->deleted) {
			if ((client->deleted_bitmask[ctx->msgnum / CHAR_BIT] &
			     (1 << (ctx->msgnum % CHAR_BIT))) != 0)
				continue;
		}

		client_send_line(client, "%u %"PRIuUOFF_T, ctx->msgnum+1,
				 client->message_sizes[ctx->msgnum]);
	}

	client_send_line(client, ".");

	i_free(ctx);
	client->cmd = NULL;
}

static int cmd_list(struct pop3_command_context *cctx)
{
        struct cmd_list_context *ctx;

	if (*cctx->args == '\0') {
		ctx = i_new(struct cmd_list_context, 1);
		client_send_line(cctx->client, "+OK %u messages:",
				 cctx->client->messages_count - cctx->client->deleted_count);

		cctx->client->cmd = cmd_list_callback;
		cctx->client->cmd_context = ctx;
		cmd_list_callback(cctx->client);
	} else {
		unsigned int msgnum;

		if (get_msgnum(cctx, &msgnum, FALSE) == NULL)
			return -1;

		client_send_line(cctx->client, "+OK %u %"PRIuUOFF_T, msgnum+1,
				 cctx->client->message_sizes[msgnum]);
	}

	return 1;
}

static int cmd_last(struct pop3_command_context *cctx)
{
	if (cctx->client->set->pop3_enable_last)
		client_send_line(cctx->client, "+OK %u", cctx->client->last_seen_pop3_msn);
	else
		client_send_line(cctx->client, "-ERR LAST command not enabled");
	return 1;
}

static int cmd_noop(struct pop3_command_context *cctx)
{
	client_send_line(cctx->client, "+OK");
	return 1;
}

static struct mail_search_args *
pop3_search_build_seqset(ARRAY_TYPE(seq_range) *seqset)
{
	struct mail_search_args *search_args;
	struct mail_search_arg *sarg;

	search_args = mail_search_build_init();
	sarg = mail_search_build_add(search_args, SEARCH_SEQSET);
	sarg->value.seqset = *seqset;
	return search_args;
}

static struct mail_search_args *
pop3_search_build(struct client *client, uint32_t seq)
{
	struct mail_search_args *search_args;

	if (seq == 0)
		return pop3_search_build_seqset(&client->all_seqs);

	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, seq, seq);
	return search_args;
}

static int client_verify_ordering(struct client *client,
				  struct mail *mail, uint32_t msgnum)
{
	uint32_t seq;

	seq = msgnum_to_seq(client, msgnum);
	if (seq != mail->seq) {
		e_error(client->event,
			"Message ordering changed unexpectedly "
			"(msg #%u: storage seq %u -> %u)",
			msgnum+1, seq, mail->seq);
		return -1;
	}
	return 0;
}

static void client_expunge(struct client *client, struct mail *mail)
{
	switch (client->set->parsed_delete_type) {
	case POP3_DELETE_TYPE_EXPUNGE:
		mail_expunge(mail);
		break;
	case POP3_DELETE_TYPE_FLAG:
		i_assert(client->deleted_kw != NULL);
		mail_update_keywords(mail, MODIFY_ADD, client->deleted_kw);
		break;
	}
}

bool client_update_mails(struct client *client)
{
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	ARRAY_TYPE(seq_range) deleted_msgs, seen_msgs;
	uint32_t msgnum, bit;
	bool ret = TRUE;

	if (mailbox_is_readonly(client->mailbox)) {
		/* silently ignore */
		return TRUE;
	}

	/* translate msgnums to sequences (in case POP3 ordering is
	   different) */
	t_array_init(&deleted_msgs, 8);
	if (client->deleted_bitmask != NULL && client->quit_seen) {
		for (msgnum = 0; msgnum < client->messages_count; msgnum++) {
			bit = 1 << (msgnum % CHAR_BIT);
			if ((client->deleted_bitmask[msgnum / CHAR_BIT] & bit) != 0)
				seq_range_array_add(&deleted_msgs, msgnum_to_seq(client, msgnum));
		}
	}
	t_array_init(&seen_msgs, 8);
	if (client->seen_bitmask != NULL) {
		for (msgnum = 0; msgnum < client->messages_count; msgnum++) {
			bit = 1 << (msgnum % CHAR_BIT);
			if ((client->seen_bitmask[msgnum / CHAR_BIT] & bit) != 0)
				seq_range_array_add(&seen_msgs, msgnum_to_seq(client, msgnum));
		}
	}

	if (array_count(&deleted_msgs) > 0) {
		/* expunge DELEted mails */
		search_args = pop3_search_build_seqset(&deleted_msgs);
		ctx = mailbox_search_init(client->trans, search_args, NULL, 0, NULL);
		mail_search_args_unref(&search_args);

		while (mailbox_search_next(ctx, &mail))
			client_expunge(client, mail);
		if (mailbox_search_deinit(&ctx) < 0)
			ret = FALSE;
		/* don't bother setting \Seen flags for deleted messages */
		seq_range_array_invert(&deleted_msgs, 1, client->highest_seq);
		seq_range_array_intersect(&seen_msgs, &deleted_msgs);
	}

	if (array_count(&seen_msgs) > 0) {
		/* add \Seen flags for RETRed mails */
		search_args = pop3_search_build_seqset(&seen_msgs);
		ctx = mailbox_search_init(client->trans, search_args, NULL, 0, NULL);
		mail_search_args_unref(&search_args);

		while (mailbox_search_next(ctx, &mail))
			mail_update_flags(mail, MODIFY_ADD, MAIL_SEEN);
		if (mailbox_search_deinit(&ctx) < 0)
			ret = FALSE;
	}

	client->seen_change_count = 0;
	return ret;
}

static int cmd_quit(struct pop3_command_context *cctx)
{
	cctx->client->quit_seen = TRUE;
	if (cctx->client->deleted || cctx->client->seen_bitmask != NULL) {
		if (!client_update_mails(cctx->client)) {
			client_send_storage_error(cctx->client);
			client_disconnect(cctx->client,
				"Storage error during logout.");
			return 1;
		}
	}

	if (mailbox_transaction_commit(&cctx->client->trans) < 0 ||
	    mailbox_sync(cctx->client->mailbox, MAILBOX_SYNC_FLAG_FULL_WRITE) < 0) {
		client_send_storage_error(cctx->client);
		client_disconnect(cctx->client, "Storage error during logout.");
		return 1;
	} else {
		cctx->client->delete_success = TRUE;
	}

	if (!cctx->client->deleted)
		client_send_line(cctx->client, "+OK Logging out.");
	else
		client_send_line(cctx->client, "+OK Logging out, messages deleted.");

	client_disconnect(cctx->client, "Logged out");
	return 1;
}

struct fetch_context {
	struct mail *mail;
	struct istream *stream;
	uoff_t body_lines;

	uoff_t *byte_counter;
	uoff_t byte_counter_offset;

	unsigned char last;
	bool cr_skipped, in_body;
};

static void fetch_deinit(struct fetch_context *ctx)
{
	mail_free(&ctx->mail);
	i_free(ctx);
}

static void fetch_callback(struct client *client)
{
	struct fetch_context *ctx = client->cmd_context;
	const unsigned char *data;
	unsigned char add;
	size_t i, size;
	int ret;

	while ((ctx->body_lines > 0 || !ctx->in_body) &&
	       i_stream_read_more(ctx->stream, &data, &size) > 0) {
		if (size > 4096)
			size = 4096;

		add = '\0';
		for (i = 0; i < size; i++) {
			if ((data[i] == '\r' || data[i] == '\n') &&
			    !ctx->in_body) {
				if (i == 0 && (ctx->last == '\0' ||
					       ctx->last == '\n'))
					ctx->in_body = TRUE;
				else if (i > 0 && data[i-1] == '\n')
					ctx->in_body = TRUE;
			}

			if (data[i] == '\n') {
				if ((i == 0 && ctx->last != '\r') ||
				    (i > 0 && data[i-1] != '\r')) {
					/* missing CR */
					add = '\r';
					break;
				}

				if (ctx->in_body) {
					if (--ctx->body_lines == 0) {
						i++;
						break;
					}
				}
			} else if (data[i] == '.' &&
				   ((i == 0 && ctx->last == '\n') ||
				    (i > 0 && data[i-1] == '\n'))) {
				/* escape the dot */
				add = '.';
				break;
			} else if (data[i] == '\0' &&
				   (client->set->parsed_workarounds &
				    WORKAROUND_OUTLOOK_NO_NULS) != 0) {
				add = 0x80;
				break;
			}
		}

		if (i > 0) {
			if (o_stream_send(client->output, data, i) < 0)
				break;
			ctx->last = data[i-1];
			i_stream_skip(ctx->stream, i);
		}

		if (o_stream_get_buffer_used_size(client->output) >= 4096) {
			if ((ret = o_stream_flush(client->output)) < 0)
				break;
			if (ret == 0) {
				/* continue later */
				return;
			}
		}

		if (add != '\0') {
			if (o_stream_send(client->output, &add, 1) < 0)
				break;

			ctx->last = add;
			if (add == 0x80)
				i_stream_skip(ctx->stream, 1);
		}
	}

	if (ctx->last != '\n') {
		/* didn't end with CRLF */
		o_stream_nsend(client->output, "\r\n", 2);
	}

	if (!ctx->in_body &&
	    (client->set->parsed_workarounds & WORKAROUND_OE_NS_EOH) != 0) {
		/* Add the missing end of headers line. */
		o_stream_nsend(client->output, "\r\n", 2);
	}

	*ctx->byte_counter +=
		client->output->offset - ctx->byte_counter_offset;

	client_send_line(client, ".");
	fetch_deinit(ctx);
	client->cmd = NULL;
}

static int client_reply_msg_expunged(struct client *client, unsigned int msgnum)
{
	client_send_line(client, "-ERR Message %u expunged.", msgnum + 1);
	if (msgnum <= client->highest_expunged_fetch_msgnum) {
		/* client tried to fetch an expunged message again.
		   treat this as error so we'll eventually disconnect the
		   client instead of letting it loop forever. */
		return -1;
	}
	client->highest_expunged_fetch_msgnum = msgnum;
	return 1;
}

static int fetch(struct client *client, unsigned int msgnum, uoff_t body_lines,
		 const char *reason, uoff_t *byte_counter)
{
        struct fetch_context *ctx;
	int ret;

	ctx = i_new(struct fetch_context, 1);
	ctx->byte_counter = byte_counter;
	ctx->byte_counter_offset = client->output->offset;
	ctx->mail = mail_alloc(client->trans,
			       MAIL_FETCH_STREAM_HEADER |
			       MAIL_FETCH_STREAM_BODY, NULL);
	mail_set_seq(ctx->mail, msgnum_to_seq(client, msgnum));

	if (mail_get_stream_because(ctx->mail, NULL, NULL, reason, &ctx->stream) < 0) {
		ret = client_reply_msg_expunged(client, msgnum);
		fetch_deinit(ctx);
		return ret;
	}

	if (body_lines == UOFF_T_MAX && client->seen_bitmask != NULL) {
		if ((mail_get_flags(ctx->mail) & MAIL_SEEN) == 0) {
			/* mark the message seen with RETR command */
			client->seen_bitmask[msgnum / CHAR_BIT] |=
				1 << (msgnum % CHAR_BIT);
			client->seen_change_count++;
		}
	}

	ctx->body_lines = body_lines;
	if (body_lines == UOFF_T_MAX) {
		client_send_line(client, "+OK %"PRIuUOFF_T" octets",
				 client->message_sizes[msgnum]);
	} else {
		client_send_line(client, "+OK");
		ctx->body_lines++; /* internally we count the empty line too */
	}

	client->cmd = fetch_callback;
	client->cmd_context = ctx;
	fetch_callback(client);
	return 1;
}

static int cmd_retr(struct pop3_command_context *cctx)
{
	unsigned int msgnum;

	if (get_msgnum(cctx, &msgnum, FALSE) == NULL)
		return -1;

	if (cctx->client->lowest_retr_pop3_msn > msgnum+1 ||
	    cctx->client->lowest_retr_pop3_msn == 0)
		cctx->client->lowest_retr_pop3_msn = msgnum+1;
	if (cctx->client->last_seen_pop3_msn < msgnum+1)
		cctx->client->last_seen_pop3_msn = msgnum+1;

	cctx->client->retr_count++;
	return fetch(cctx->client, msgnum, UOFF_T_MAX, "RETR",
		     &cctx->client->retr_bytes);
}

static int cmd_rset(struct pop3_command_context *cctx)
{
	struct mail_search_context *search_ctx;
	struct mail *mail;
	struct mail_search_args *search_args;

	cctx->client->last_seen_pop3_msn = 0;

	if (cctx->client->deleted) {
		cctx->client->deleted = FALSE;
		memset(cctx->client->deleted_bitmask, 0, MSGS_BITMASK_SIZE(cctx->client));
		cctx->client->deleted_count = 0;
		cctx->client->deleted_size = 0;
	}
	if (cctx->client->seen_change_count > 0) {
		memset(cctx->client->seen_bitmask, 0, MSGS_BITMASK_SIZE(cctx->client));
		cctx->client->seen_change_count = 0;
	}

	if (cctx->client->set->pop3_enable_last) {
		/* remove all \Seen flags (as specified by RFC 1460) */
		search_args = pop3_search_build(cctx->client, 0);
		search_ctx = mailbox_search_init(cctx->client->trans,
						 search_args, NULL, 0, NULL);
		mail_search_args_unref(&search_args);

		while (mailbox_search_next(search_ctx, &mail))
			mail_update_flags(mail, MODIFY_REMOVE, MAIL_SEEN);
		(void)mailbox_search_deinit(&search_ctx);

		(void)mailbox_transaction_commit(&cctx->client->trans);
		cctx->client->trans = mailbox_transaction_begin(cctx->client->mailbox, 0,
							  __func__);
	}

	client_send_line(cctx->client, "+OK");
	return 1;
}

static int cmd_stat(struct pop3_command_context *cctx)
{
	client_send_line(cctx->client, "+OK %u %"PRIuUOFF_T,
			 cctx->client->messages_count - cctx->client->deleted_count,
			 cctx->client->total_size - cctx->client->deleted_size);
	return 1;
}

static int cmd_top(struct pop3_command_context *cctx)
{
	unsigned int msgnum;
	uoff_t max_lines;

	cctx->args = get_msgnum(cctx, &msgnum, TRUE);
	if (cctx->args == NULL)
		return -1;
	if (get_size(cctx, &max_lines, FALSE) == NULL)
		return -1;

	cctx->client->top_count++;
	return fetch(cctx->client, msgnum, max_lines, "TOP", &cctx->client->top_bytes);
}

struct cmd_uidl_context {
	struct mail_search_context *search_ctx;
	struct mail *mail;
	uint32_t msgnum;
	bool list_all;
};

static int
pop3_get_uid(struct client *client, struct mail *mail, string_t *str,
	     bool *permanent_uidl_r)
{
	char uid_str[MAX_INT_STRLEN] = { 0 };
	const char *uidl;
	const char *hdr_md5 = NULL, *filename = NULL, *guid = NULL;

	if (mail_get_special(mail, MAIL_FETCH_UIDL_BACKEND, &uidl) == 0 &&
	    *uidl != '\0') {
		str_append(str, uidl);
		/* UIDL is already permanent */
		*permanent_uidl_r = TRUE;
		return 0;
	}

	*permanent_uidl_r = FALSE;

	if (client->set->pop3_reuse_xuidl &&
	    mail_get_first_header(mail, "X-UIDL", &uidl) > 0) {
		str_append(str, uidl);
		return 0;
	}

	if ((client->uidl_keymask & UIDL_UID) != 0) {
		if (i_snprintf(uid_str, sizeof(uid_str), "%u", mail->uid) < 0)
			i_unreached();
	}
	if ((client->uidl_keymask & UIDL_MD5) != 0) {
		if (mail_get_special(mail, MAIL_FETCH_HEADER_MD5,
				     &hdr_md5) < 0) {
			e_error(client->event,
				"UIDL: Header MD5 lookup failed: %s",
				mailbox_get_last_internal_error(mail->box, NULL));
			return -1;
		} else if (hdr_md5[0] == '\0') {
			e_error(client->event,
				"UIDL: Header MD5 not found "
				"(pop3_uidl_format=%%m not supported by storage?)");
			return -1;
		}
	}
	if ((client->uidl_keymask & UIDL_FILE_NAME) != 0) {
		if (mail_get_special(mail, MAIL_FETCH_STORAGE_ID,
				     &filename) < 0) {
			e_error(client->event,
				"UIDL: File name lookup failed: %s",
				mailbox_get_last_internal_error(mail->box, NULL));
			return -1;
		} else if (filename[0] == '\0') {
			e_error(client->event,
				"UIDL: File name not found "
				"(pop3_uidl_format=%%f not supported by storage?)");
			return -1;
		}
	}
	if ((client->uidl_keymask & UIDL_GUID) != 0) {
		if (mail_get_special(mail, MAIL_FETCH_GUID,
				     &guid) < 0) {
			e_error(client->event,
				"UIDL: Message GUID lookup failed: %s",
				mailbox_get_last_internal_error(mail->box, NULL));
			return -1;
		} else if (guid[0] == '\0') {
			e_error(client->event,
				"UIDL: Message GUID not found "
				"(pop3_uidl_format=%%g not supported by storage?)");
			return -1;
		}
	}

	const struct var_expand_table tab[] = {
		{ 'v', dec2str(client->uid_validity), "uidvalidity" },
		{ 'u', uid_str, "uid" },
		{ 'm', hdr_md5, "md5" },
		{ 'f', filename, "filename" },
		{ 'g', guid, "guid" },
		{ '\0', NULL, NULL }
	};
	const char *error;

	if (var_expand(str, client->mail_set->pop3_uidl_format,
		       tab, &error) <= 0) {
		e_error(client->event,
			"UIDL: Failed to expand pop3_uidl_format=%s: %s",
			client->mail_set->pop3_uidl_format, error);
		return -1;
	}
	return 0;
}

static bool
list_uidls_saved_iter(struct client *client, struct cmd_uidl_context *ctx)
{
	bool found = FALSE;

	while (ctx->msgnum < client->messages_count) {
		uint32_t msgnum = ctx->msgnum++;

		if (client->deleted) {
			if ((client->deleted_bitmask[msgnum / CHAR_BIT] &
			     (1 << (msgnum % CHAR_BIT))) != 0)
				continue;
		}
		found = TRUE;

		client_send_line(client,
				 ctx->list_all ? "%u %s" : "+OK %u %s",
				 msgnum+1, client->message_uidls[msgnum]);
		if (client->output->closed || !ctx->list_all)
			break;
		if (POP3_CLIENT_OUTPUT_FULL(client)) {
			/* output is being buffered, continue when there's
			   more space */
			return FALSE;
		}
	}
	/* finished */
	client->cmd = NULL;

	if (ctx->list_all)
		client_send_line(client, ".");
	i_free(ctx);
	return found;
}

static bool list_uids_iter(struct client *client, struct cmd_uidl_context *ctx)
{
	string_t *str;
	bool permanent_uidl, found = FALSE;
	bool failed = FALSE;

	if (client->message_uidls != NULL)
		return list_uidls_saved_iter(client, ctx);

	str = t_str_new(128);
	while (mailbox_search_next(ctx->search_ctx, &ctx->mail)) {
		uint32_t msgnum = ctx->msgnum++;

		if (client_verify_ordering(client, ctx->mail, msgnum) < 0) {
			failed = TRUE;
			break;
		}
		if (client->deleted) {
			if ((client->deleted_bitmask[msgnum / CHAR_BIT] &
			     (1 << (msgnum % CHAR_BIT))) != 0)
				continue;
		}
		found = TRUE;

		str_truncate(str, 0);
		if (pop3_get_uid(client, ctx->mail, str, &permanent_uidl) < 0) {
			failed = TRUE;
			break;
		}
		if (client->set->pop3_save_uidl && !permanent_uidl)
			mail_update_pop3_uidl(ctx->mail, str_c(str));

		client_send_line(client, ctx->list_all ? "%u %s" : "+OK %u %s",
				 msgnum+1, str_c(str));
		if (client->output->closed)
			break;
		if (POP3_CLIENT_OUTPUT_FULL(client) && ctx->list_all) {
			/* output is being buffered, continue when there's
			   more space */
			return FALSE;
		}
	}

	/* finished */
	(void)mailbox_search_deinit(&ctx->search_ctx);

	client->cmd = NULL;

	if (ctx->list_all && !failed)
		client_send_line(client, ".");
	i_free(ctx);
	if (failed)
		client_disconnect(client, "POP3 UIDLs couldn't be listed");
	return found || failed;
}

static void cmd_uidl_callback(struct client *client)
{
	struct cmd_uidl_context *ctx = client->cmd_context;

        (void)list_uids_iter(client, ctx);
}

HASH_TABLE_DEFINE_TYPE(uidl_counter, char *, void *);

static void
uidl_rename_duplicate(string_t *uidl, HASH_TABLE_TYPE(uidl_counter) prev_uidls)
{
	char *key;
	void *value;
	unsigned int counter;

	while (hash_table_lookup_full(prev_uidls, str_c(uidl), &key, &value)) {
		/* duplicate. the value contains the number of duplicates. */
		counter = POINTER_CAST_TO(value, unsigned int) + 1;
		hash_table_update(prev_uidls, key, POINTER_CAST(counter));
		str_printfa(uidl, "-%u", counter);
		/* the second lookup really should return NULL, but just in
		   case of some weird UIDLs do this as many times as needed */
	}
}

static void client_uidls_save(struct client *client)
{
	struct mail_search_context *search_ctx;
	struct mail_search_args *search_args;
	struct mail *mail;
	HASH_TABLE_TYPE(uidl_counter) prev_uidls;
	const char **seq_uidls;
	string_t *str;
	char *uidl;
	enum mail_fetch_field wanted_fields;
	uint32_t msgnum;
	bool permanent_uidl, uidl_duplicates_rename, failed = FALSE;

	i_assert(client->message_uidls == NULL);

	search_args = pop3_search_build(client, 0);
	wanted_fields = 0;
	if ((client->uidl_keymask & UIDL_MD5) != 0)
		wanted_fields |= MAIL_FETCH_HEADER_MD5;

	search_ctx = mailbox_search_init(client->trans, search_args,
					 NULL, wanted_fields, NULL);
	mail_search_args_unref(&search_args);

	uidl_duplicates_rename =
		strcmp(client->set->pop3_uidl_duplicates, "rename") == 0;
	if (uidl_duplicates_rename)
		hash_table_create(&prev_uidls, default_pool, 0, str_hash,
				  strcmp);
	client->uidl_pool = pool_alloconly_create("message uidls", 1024);

	/* first read all the UIDLs into a temporary [seq] array */
	seq_uidls = i_new(const char *, client->highest_seq);
	str = t_str_new(128);
	while (mailbox_search_next(search_ctx, &mail)) {
		str_truncate(str, 0);
		if (pop3_get_uid(client, mail, str, &permanent_uidl) < 0) {
			failed = TRUE;
			break;
		}
		if (uidl_duplicates_rename)
			uidl_rename_duplicate(str, prev_uidls);

		uidl = p_strdup(client->uidl_pool, str_c(str));
		if (client->set->pop3_save_uidl && !permanent_uidl)
			mail_update_pop3_uidl(mail, uidl);

		i_assert(mail->seq <= client->highest_seq);
		seq_uidls[mail->seq-1] = uidl;
		if (uidl_duplicates_rename)
			hash_table_update(prev_uidls, uidl, POINTER_CAST(1));
	}
	(void)mailbox_search_deinit(&search_ctx);
	if (uidl_duplicates_rename)
		hash_table_destroy(&prev_uidls);

	if (failed) {
		pool_unref(&client->uidl_pool);
		i_free(seq_uidls);
		return;
	}
	/* map UIDLs to msgnums (in case POP3 sort ordering is different) */
	client->message_uidls = p_new(client->uidl_pool, const char *,
				      MALLOC_ADD(client->messages_count, 1));
	for (msgnum = 0; msgnum < client->messages_count; msgnum++) {
		client->message_uidls[msgnum] =
			seq_uidls[msgnum_to_seq(client, msgnum) - 1];
	}
	i_free(seq_uidls);
}

static struct cmd_uidl_context *
cmd_uidl_init(struct client *client, uint32_t seq)
{
        struct cmd_uidl_context *ctx;
	struct mail_search_args *search_args;
	enum mail_fetch_field wanted_fields;

	if (client->message_uidls_save && client->message_uidls == NULL &&
	    client->messages_count > 0)
		client_uidls_save(client);

	ctx = i_new(struct cmd_uidl_context, 1);
	ctx->list_all = seq == 0;

	if (client->message_uidls == NULL) {
		wanted_fields = 0;
		if ((client->uidl_keymask & UIDL_MD5) != 0)
			wanted_fields |= MAIL_FETCH_HEADER_MD5;

		search_args = pop3_search_build(client, seq);
		ctx->search_ctx = mailbox_search_init(client->trans, search_args,
						      pop3_sort_program,
						      wanted_fields, NULL);
		mail_search_args_unref(&search_args);
	}

	if (seq == 0) {
		client->cmd = cmd_uidl_callback;
		client->cmd_context = ctx;
	}
	return ctx;
}

static int cmd_uidl(struct pop3_command_context *cctx)
{
        struct cmd_uidl_context *ctx;
	uint32_t seq;

	if (*cctx->args == '\0') {
		client_send_line(cctx->client, "+OK");
		ctx = cmd_uidl_init(cctx->client, 0);
		(void)list_uids_iter(cctx->client, ctx);
	} else {
		unsigned int msgnum;

		if (get_msgnum(cctx, &msgnum, FALSE) == NULL)
			return -1;

		seq = msgnum_to_seq(cctx->client, msgnum);
		ctx = cmd_uidl_init(cctx->client, seq);
		ctx->msgnum = msgnum;
		if (!list_uids_iter(cctx->client, ctx))
			return client_reply_msg_expunged(cctx->client, msgnum);
	}

	return 1;
}

static const struct pop3_command pop3_commands[] = {
	{ "capa", cmd_capa },
	{ "dele", cmd_dele },
	{ "list", cmd_list },
	{ "last", cmd_last },
	{ "noop", cmd_noop },
	{ "quit", cmd_quit },
	{ "retr", cmd_retr },
	{ "rset", cmd_rset },
	{ "stat", cmd_stat },
	{ "top", cmd_top },
	{ "uidl", cmd_uidl },
};

const struct pop3_command *pop3_command_find(const char *name)
{
	for (unsigned int i = 0; i < N_ELEMENTS(pop3_commands); i++) {
		if (strcasecmp(pop3_commands[i].name, name) == 0)
			return &pop3_commands[i];
	}
	return NULL;
}

int client_command_execute(struct pop3_command_context *cctx)
{
	while (*cctx->args == ' ') cctx->args++;
	cctx->orig_args = cctx->args;

	return cctx->command->func(cctx);
}
