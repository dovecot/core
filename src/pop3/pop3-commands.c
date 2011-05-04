/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "pop3-common.h"
#include "array.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "crc32.h"
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

static const char *get_msgnum(struct client *client, const char *args,
			      unsigned int *msgnum)
{
	unsigned int num, last_num;

	num = 0;
	while (*args != '\0' && *args != ' ') {
		if (*args < '0' || *args > '9') {
			client_send_line(client,
				"-ERR Invalid message number: %s", args);
			return NULL;
		}

		last_num = num;
		num = num*10 + (*args - '0');
		if (num < last_num) {
			client_send_line(client,
				"-ERR Message number too large: %s", args);
			return NULL;
		}
		args++;
	}

	if (num == 0 || num > client->messages_count) {
		client_send_line(client,
				 "-ERR There's no message %u.", num);
		return NULL;
	}
	num--;

	if (client->deleted) {
		if (client->deleted_bitmask[num / CHAR_BIT] &
		    (1 << (num % CHAR_BIT))) {
			client_send_line(client, "-ERR Message is deleted.");
			return NULL;
		}
	}

	while (*args == ' ') args++;

	*msgnum = num;
	return args;
}

static const char *get_size(struct client *client, const char *args,
			    uoff_t *size)
{
	uoff_t num, last_num;

	num = 0;
	while (*args != '\0' && *args != ' ') {
		if (*args < '0' || *args > '9') {
			client_send_line(client, "-ERR Invalid size: %s",
					 args);
			return NULL;
		}

		last_num = num;
		num = num*10 + (*args - '0');
		if (num < last_num) {
			client_send_line(client, "-ERR Size too large: %s",
					 args);
			return NULL;
		}
		args++;
	}

	while (*args == ' ') args++;

	*size = num;
	return args;
}

static int cmd_capa(struct client *client, const char *args ATTR_UNUSED)
{
	client_send_line(client, "+OK\r\n"POP3_CAPABILITY_REPLY".");
	return 1;
}

static int cmd_dele(struct client *client, const char *args)
{
	unsigned int msgnum;

	if (get_msgnum(client, args, &msgnum) == NULL)
		return -1;

	if (!client->deleted) {
		client->deleted_bitmask = i_malloc(MSGS_BITMASK_SIZE(client));
		client->deleted = TRUE;
	}

	client->deleted_bitmask[msgnum / CHAR_BIT] |= 1 << (msgnum % CHAR_BIT);
	client->deleted_count++;
	client->deleted_size += client->message_sizes[msgnum];
	client_send_line(client, "+OK Marked to be deleted.");
	return 1;
}

struct cmd_list_context {
	unsigned int msgnum;
};

static void cmd_list_callback(struct client *client)
{
	struct cmd_list_context *ctx = client->cmd_context;
	int ret = 1;

	for (; ctx->msgnum != client->messages_count; ctx->msgnum++) {
		if (ret == 0) {
			/* buffer full */
			return;
		}

		if (client->deleted) {
			if (client->deleted_bitmask[ctx->msgnum / CHAR_BIT] &
			    (1 << (ctx->msgnum % CHAR_BIT)))
				continue;
		}

		ret = client_send_line(client, "%u %"PRIuUOFF_T, ctx->msgnum+1,
				       client->message_sizes[ctx->msgnum]);
		if (ret < 0)
			break;
	}

	client_send_line(client, ".");

	i_free(ctx);
	client->cmd = NULL;
}

static int cmd_list(struct client *client, const char *args)
{
        struct cmd_list_context *ctx;

	if (*args == '\0') {
		ctx = i_new(struct cmd_list_context, 1);
		client_send_line(client, "+OK %u messages:",
				 client->messages_count - client->deleted_count);

		client->cmd = cmd_list_callback;
		client->cmd_context = ctx;
		cmd_list_callback(client);
	} else {
		unsigned int msgnum;

		if (get_msgnum(client, args, &msgnum) == NULL)
			return -1;

		client_send_line(client, "+OK %u %"PRIuUOFF_T, msgnum+1,
				 client->message_sizes[msgnum]);
	}

	return 1;
}

static int cmd_last(struct client *client, const char *args ATTR_UNUSED)
{
	client_send_line(client, "+OK %u", client->last_seen_pop3_msn);
	return 1;
}

static int cmd_noop(struct client *client, const char *args ATTR_UNUSED)
{
	client_send_line(client, "+OK");
	return 1;
}

static struct mail_search_args *
pop3_search_build(struct client *client, uint32_t seq)
{
	struct mail_search_args *search_args;

	search_args = mail_search_build_init();
	if (seq == 0) {
		mail_search_build_add_seqset(search_args,
					     1, client->messages_count);
	} else {
		mail_search_build_add_seqset(search_args, seq, seq);
	}
	return search_args;
}

static int client_verify_ordering(struct client *client,
				  struct mail *mail, uint32_t msgnum)
{
	uint32_t seq;

	seq = msgnum_to_seq(client, msgnum);
	if (seq != mail->seq) {
		i_error("Message ordering changed unexpectedly "
			"(msg #%u: storage seq %u -> %u)",
			msgnum+1, seq, mail->seq);
		return -1;
	}
	return 0;
}

bool client_update_mails(struct client *client)
{
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	uint32_t msgnum, bit;
	bool ret = TRUE;

	if (mailbox_is_readonly(client->mailbox)) {
		/* silently ignore */
		return TRUE;
	}

	search_args = pop3_search_build(client, 0);
	ctx = mailbox_search_init(client->trans, search_args,
				  pop3_sort_program);
	mail_search_args_unref(&search_args);

	msgnum = 0;
	mail = mail_alloc(client->trans, 0, NULL);
	while (mailbox_search_next(ctx, mail)) {
		if (client_verify_ordering(client, mail, msgnum) < 0) {
			ret = FALSE;
			break;
		}

		bit = 1 << (msgnum % CHAR_BIT);
		if (client->deleted_bitmask != NULL &&
		    (client->deleted_bitmask[msgnum / CHAR_BIT] & bit) != 0) {
			mail_expunge(mail);
			client->expunged_count++;
		} else if (client->seen_bitmask != NULL &&
			   (client->seen_bitmask[msgnum / CHAR_BIT] & bit) != 0) {
			mail_update_flags(mail, MODIFY_ADD, MAIL_SEEN);
		}
		msgnum++;
	}
	mail_free(&mail);

	client->seen_change_count = 0;
	if (mailbox_search_deinit(&ctx) < 0)
		ret = FALSE;
	return ret;
}

static int cmd_quit(struct client *client, const char *args ATTR_UNUSED)
{
	if (client->deleted || client->seen_bitmask != NULL) {
		if (!client_update_mails(client)) {
			client_send_storage_error(client);
			client_disconnect(client,
				"Storage error during logout.");
			return 1;
		}
	}

	if (mailbox_transaction_commit(&client->trans) < 0 ||
	    mailbox_sync(client->mailbox, MAILBOX_SYNC_FLAG_FULL_WRITE) < 0) {
		client_send_storage_error(client);
		client_disconnect(client, "Storage error during logout.");
		return 1;
	}

	if (!client->deleted)
		client_send_line(client, "+OK Logging out.");
	else
		client_send_line(client, "+OK Logging out, messages deleted.");

	client_disconnect(client, "Logged out");
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
	       i_stream_read_data(ctx->stream, &data, &size, 0) > 0) {
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
		(void)o_stream_send(client->output, "\r\n", 2);
	}

	if (!ctx->in_body &&
	    (client->set->parsed_workarounds & WORKAROUND_OE_NS_EOH) != 0) {
		/* Add the missing end of headers line. */
		(void)o_stream_send(client->output, "\r\n", 2);
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
		 uoff_t *byte_counter)
{
        struct fetch_context *ctx;
	int ret;

	ctx = i_new(struct fetch_context, 1);
	ctx->byte_counter = byte_counter;
	ctx->byte_counter_offset = client->output->offset;

	ctx->mail = mail_alloc(client->trans, MAIL_FETCH_STREAM_HEADER |
			       MAIL_FETCH_STREAM_BODY, NULL);
	mail_set_seq(ctx->mail, msgnum_to_seq(client, msgnum));

	if (mail_get_stream(ctx->mail, NULL, NULL, &ctx->stream) < 0) {
		ret = client_reply_msg_expunged(client, msgnum);
		fetch_deinit(ctx);
		return ret;
	}

	if (body_lines == (uoff_t)-1 && client->seen_bitmask != NULL) {
		if ((mail_get_flags(ctx->mail) & MAIL_SEEN) == 0) {
			/* mark the message seen with RETR command */
			client->seen_bitmask[msgnum / CHAR_BIT] |=
				1 << (msgnum % CHAR_BIT);
			client->seen_change_count++;
		}
	}

	ctx->body_lines = body_lines;
	if (body_lines == (uoff_t)-1) {
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

static int cmd_retr(struct client *client, const char *args)
{
	unsigned int msgnum;

	if (get_msgnum(client, args, &msgnum) == NULL)
		return -1;

	if (client->lowest_retr_pop3_msn > msgnum+1 ||
	    client->lowest_retr_pop3_msn == 0)
		client->lowest_retr_pop3_msn = msgnum+1;
	if (client->last_seen_pop3_msn < msgnum+1)
		client->last_seen_pop3_msn = msgnum+1;

	client->retr_count++;
	return fetch(client, msgnum, (uoff_t)-1, &client->retr_bytes);
}

static int cmd_rset(struct client *client, const char *args ATTR_UNUSED)
{
	struct mail_search_context *search_ctx;
	struct mail *mail;
	struct mail_search_args *search_args;

	client->last_seen_pop3_msn = 0;

	if (client->deleted) {
		client->deleted = FALSE;
		memset(client->deleted_bitmask, 0, MSGS_BITMASK_SIZE(client));
		client->deleted_count = 0;
		client->deleted_size = 0;
	}
	if (client->seen_change_count > 0) {
		memset(client->seen_bitmask, 0, MSGS_BITMASK_SIZE(client));
		client->seen_change_count = 0;
	}

	if (client->set->pop3_enable_last) {
		/* remove all \Seen flags (as specified by RFC 1460) */
		search_args = pop3_search_build(client, 0);
		search_ctx = mailbox_search_init(client->trans,
						 search_args, NULL);
		mail_search_args_unref(&search_args);

		mail = mail_alloc(client->trans, 0, NULL);
		while (mailbox_search_next(search_ctx, mail))
			mail_update_flags(mail, MODIFY_REMOVE, MAIL_SEEN);
		mail_free(&mail);
		(void)mailbox_search_deinit(&search_ctx);

		mailbox_transaction_commit(&client->trans);
		client->trans = mailbox_transaction_begin(client->mailbox, 0);
	}

	client_send_line(client, "+OK");
	return 1;
}

static int cmd_stat(struct client *client, const char *args ATTR_UNUSED)
{
	client_send_line(client, "+OK %u %"PRIuUOFF_T,
			 client->messages_count - client->deleted_count,
			 client->total_size - client->deleted_size);
	return 1;
}

static int cmd_top(struct client *client, const char *args)
{
	unsigned int msgnum;
	uoff_t max_lines;

	args = get_msgnum(client, args, &msgnum);
	if (args == NULL)
		return -1;
	if (get_size(client, args, &max_lines) == NULL)
		return -1;

	client->top_count++;
	return fetch(client, msgnum, max_lines, &client->top_bytes);
}

struct cmd_uidl_context {
	struct mail_search_context *search_ctx;
	struct mail *mail;
	uint32_t msgnum;
	bool list_all;
};

static bool pop3_get_uid(struct client *client, struct cmd_uidl_context *ctx,
			 struct var_expand_table *tab, string_t *str)
{
	char uid_str[MAX_INT_STRLEN];
	const char *uidl;

	if (mail_get_special(ctx->mail, MAIL_FETCH_UIDL_BACKEND, &uidl) == 0 &&
	    *uidl != '\0') {
		str_append(str, uidl);
		return TRUE;
	}

	if (client->set->pop3_reuse_xuidl &&
	    mail_get_first_header(ctx->mail, "X-UIDL", &uidl) > 0) {
		str_append(str, uidl);
		return FALSE;
	}

	if ((client->uidl_keymask & UIDL_UID) != 0) {
		i_snprintf(uid_str, sizeof(uid_str), "%u",
			   ctx->mail->uid);
		tab[1].value = uid_str;
	}
	if ((client->uidl_keymask & UIDL_MD5) != 0) {
		if (mail_get_special(ctx->mail, MAIL_FETCH_HEADER_MD5,
				     &tab[2].value) < 0 ||
		    *tab[2].value == '\0') {
			/* broken */
			i_fatal("UIDL: Header MD5 not found");
		}
	}
	if ((client->uidl_keymask & UIDL_FILE_NAME) != 0) {
		if (mail_get_special(ctx->mail,
				     MAIL_FETCH_UIDL_FILE_NAME,
				     &tab[3].value) < 0 ||
		    *tab[3].value == '\0') {
			/* broken */
			i_fatal("UIDL: File name not found");
		}
	}
	if ((client->uidl_keymask & UIDL_GUID) != 0) {
		if (mail_get_special(ctx->mail, MAIL_FETCH_GUID,
				     &tab[4].value) < 0 ||
		    *tab[4].value == '\0') {
			/* broken */
			i_fatal("UIDL: Message GUID not found");
		}
	}
	var_expand(str, client->mail_set->pop3_uidl_format, tab);
	return FALSE;
}

static bool list_uids_iter(struct client *client, struct cmd_uidl_context *ctx)
{
	static struct var_expand_table static_tab[] = {
		{ 'v', NULL, "uidvalidity" },
		{ 'u', NULL, "uid" },
		{ 'm', NULL, "md5" },
		{ 'f', NULL, "filename" },
		{ 'g', NULL, "guid" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;
	string_t *str;
	int ret;
	unsigned int uidl_pos;
	bool save_hashes, found = FALSE;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));
	tab[0].value = t_strdup_printf("%u", client->uid_validity);

	save_hashes = client->message_uidl_hashes_save && ctx->list_all;
	if (save_hashes && client->message_uidl_hashes == NULL) {
		client->message_uidl_hashes =
			i_new(uint32_t, client->messages_count);
	}

	str = t_str_new(128);
	while (mailbox_search_next(ctx->search_ctx, ctx->mail)) {
		uint32_t msgnum = ctx->msgnum++;

		if (client_verify_ordering(client, ctx->mail, msgnum) < 0)
			i_fatal("Can't finish POP3 UIDL command");
		if (client->deleted) {
			if (client->deleted_bitmask[msgnum / CHAR_BIT] &
			    (1 << (msgnum % CHAR_BIT)))
				continue;
		}
		found = TRUE;

		str_truncate(str, 0);
		str_printfa(str, ctx->list_all ? "%u " : "+OK %u ", msgnum+1);
		uidl_pos = str_len(str);
		if (!pop3_get_uid(client, ctx, tab, str) &&
		    client->set->pop3_save_uidl)
			mail_update_pop3_uidl(ctx->mail, str_c(str) + uidl_pos);

		if (save_hashes) {
			client->message_uidl_hashes[msgnum] =
				crc32_str(str_c(str) + uidl_pos);
		}

		ret = client_send_line(client, "%s", str_c(str));
		if (ret < 0)
			break;
		if (ret == 0 && ctx->list_all) {
			/* output is being buffered, continue when there's
			   more space */
			return FALSE;
		}
	}

	/* finished */
	mail_free(&ctx->mail);
	(void)mailbox_search_deinit(&ctx->search_ctx);

	client->cmd = NULL;

	if (save_hashes)
		client->message_uidl_hashes_save = FALSE;
	if (ctx->list_all)
		client_send_line(client, ".");
	i_free(ctx);
	return found;
}

static void cmd_uidl_callback(struct client *client)
{
	struct cmd_uidl_context *ctx = client->cmd_context;

        (void)list_uids_iter(client, ctx);
}

static struct cmd_uidl_context *
cmd_uidl_init(struct client *client, uint32_t seq)
{
        struct cmd_uidl_context *ctx;
	struct mail_search_args *search_args;
	enum mail_fetch_field wanted_fields;

	search_args = pop3_search_build(client, seq);

	ctx = i_new(struct cmd_uidl_context, 1);
	ctx->list_all = seq == 0;

	wanted_fields = 0;
	if ((client->uidl_keymask & UIDL_MD5) != 0)
		wanted_fields |= MAIL_FETCH_HEADER_MD5;

	ctx->search_ctx = mailbox_search_init(client->trans, search_args,
					      pop3_sort_program);
	mail_search_args_unref(&search_args);

	ctx->mail = mail_alloc(client->trans, wanted_fields, NULL);
	if (seq == 0) {
		client->cmd = cmd_uidl_callback;
		client->cmd_context = ctx;
	}
	return ctx;
}

static int cmd_uidl(struct client *client, const char *args)
{
        struct cmd_uidl_context *ctx;
	uint32_t seq;

	if (*args == '\0') {
		client_send_line(client, "+OK");
		ctx = cmd_uidl_init(client, 0);
		(void)list_uids_iter(client, ctx);
	} else {
		unsigned int msgnum;

		if (get_msgnum(client, args, &msgnum) == NULL)
			return -1;

		seq = msgnum_to_seq(client, msgnum);
		ctx = cmd_uidl_init(client, seq);
		ctx->msgnum = msgnum;
		if (!list_uids_iter(client, ctx))
			return client_reply_msg_expunged(client, msgnum);
	}

	return 1;
}

int client_command_execute(struct client *client,
			   const char *name, const char *args)
{
	/* keep the command uppercased */
	name = t_str_ucase(name);

	while (*args == ' ') args++;

	switch (*name) {
	case 'C':
		if (strcmp(name, "CAPA") == 0)
			return cmd_capa(client, args);
		break;
	case 'D':
		if (strcmp(name, "DELE") == 0)
			return cmd_dele(client, args);
		break;
	case 'L':
		if (strcmp(name, "LIST") == 0)
			return cmd_list(client, args);
		if (strcmp(name, "LAST") == 0 && client->set->pop3_enable_last)
			return cmd_last(client, args);
		break;
	case 'N':
		if (strcmp(name, "NOOP") == 0)
			return cmd_noop(client, args);
		break;
	case 'Q':
		if (strcmp(name, "QUIT") == 0)
			return cmd_quit(client, args);
		break;
	case 'R':
		if (strcmp(name, "RETR") == 0)
			return cmd_retr(client, args);
		if (strcmp(name, "RSET") == 0)
			return cmd_rset(client, args);
		break;
	case 'S':
		if (strcmp(name, "STAT") == 0)
			return cmd_stat(client, args);
		break;
	case 'T':
		if (strcmp(name, "TOP") == 0)
			return cmd_top(client, args);
		break;
	case 'U':
		if (strcmp(name, "UIDL") == 0)
			return cmd_uidl(client, args);
		break;
	}

	client_send_line(client, "-ERR Unknown command: %s", name);
	return -1;
}
