/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "safe-mkstemp.h"
#include "mail-storage-service.h"
#include "index/raw/raw-storage.h"
#include "lda-settings.h"
#include "mail-deliver.h"
#include "main.h"
#include "client.h"
#include "commands.h"

#define ERRSTR_MAILBOX_TEMP_FAIL "451 4.2.0 <%s> Temporary internal error"

int cmd_lhlo(struct client *client, const char *args ATTR_UNUSED)
{
	client_state_reset(client);
	client_send_line(client, "250-%s", client->my_domain);
	client_send_line(client, "250-8BITMIME");
	client_send_line(client, "250-ENHANCEDSTATUSCODES");
	client_send_line(client, "250 PIPELINING");
	return 0;
}

int cmd_mail(struct client *client, const char *args)
{
	const char *addr;
	unsigned int len;

	if (client->state.mail_from != NULL) {
		client_send_line(client, "503 5.5.1 MAIL already given");
		return 0;
	}

	addr = args;
	args = strchr(args, ' ');
	if (args == NULL)
		args = "";
	else {
		addr = t_strdup_until(addr, args);
		args++;
	}
	len = strlen(addr);
	if (strncasecmp(addr, "FROM:<", 6) != 0 || addr[len-1] != '>') {
		client_send_line(client, "501 5.5.4 Invalid parameters");
		return 0;
	}

	if (*args != '\0') {
		client_send_line(client, "501 5.5.4 Unsupported options");
		return 0;
	}

	client->state.mail_from =
		p_strndup(client->state_pool, addr + 6, len - 7);
	p_array_init(&client->state.rcpt_to, client->state_pool, 64);
	client_send_line(client, "250 2.1.0 OK");
	return 0;
}

static bool rcpt_is_duplicate(struct client *client, const char *name)
{
	const struct mail_recipient *rcpts;
	unsigned int i, count;

	rcpts = array_get(&client->state.rcpt_to, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(rcpts[i].name, name) == 0)
			return TRUE;
	}
	return FALSE;
}

int cmd_rcpt(struct client *client, const char *args)
{
	struct mail_recipient rcpt;
	const char *name, *error;
	unsigned int len;
	int ret;

	if (client->state.mail_from == NULL) {
		client_send_line(client, "503 5.5.1 MAIL needed first");
		return 0;
	}

	len = strlen(args);
	if (strncasecmp(args, "TO:<", 4) != 0 || args[len-1] != '>') {
		client_send_line(client, "501 5.5.4 Invalid parameters");
		return 0;
	}

	memset(&rcpt, 0, sizeof(rcpt));
	name = t_strndup(args + 4, len - 5);

	if (rcpt_is_duplicate(client, name)) {
		client_send_line(client, "250 2.1.5 OK, ignoring duplicate");
		return 0;
	}

	ret = mail_storage_service_multi_lookup(multi_service, name,
						client->state_pool,
						&rcpt.multi_user, &error);
	if (ret < 0) {
		i_error("User lookup failed: %s", error);
		client_send_line(client,
				 "451 4.3.0 Temporary user lookup failure");
		return 0;
	}
	if (ret == 0) {
		client_send_line(client,
				 "550 5.1.1 <%s> User doesn't exist", name);
		return 0;
	}

	rcpt.name = p_strdup(client->state_pool, name);
	array_append(&client->state.rcpt_to, &rcpt, 1);

	client_send_line(client, "250 2.1.5 OK");
	return 0;
}

int cmd_quit(struct client *client, const char *args ATTR_UNUSED)
{
	client_destroy(client, "221 2.0.0", "Logged out");
	return -1;
}

int cmd_vrfy(struct client *client, const char *args ATTR_UNUSED)
{
	client_send_line(client, "252 2.3.3 Try RCPT instead");
	return 0;
}

int cmd_rset(struct client *client, const char *args ATTR_UNUSED)
{
	client_state_reset(client);
	client_send_line(client, "250 2.0.0 OK");
	return 0;
}

int cmd_noop(struct client *client, const char *args ATTR_UNUSED)
{
	client_send_line(client, "250 2.0.0 OK");
	return 0;
}

static int
client_deliver(struct client *client, const struct mail_recipient *rcpt,
	       struct mail *src_mail)
{
	struct mail_deliver_context dctx;
	struct mail_storage *storage;
	void **sets;
	const char *error;
	enum mail_error mail_error;
	int ret;

	i_set_failure_prefix(t_strdup_printf("lmtp(%s): ", rcpt->name));
	if (mail_storage_service_multi_next(multi_service, rcpt->multi_user,
					    &client->state.dest_user,
					    &error) < 0) {
		i_error("%s", error);
		client_send_line(client, ERRSTR_MAILBOX_TEMP_FAIL, rcpt->name);
		return -1;
	}
	sets = mail_storage_service_multi_user_get_set(rcpt->multi_user);

	memset(&dctx, 0, sizeof(dctx));
	dctx.pool = pool_alloconly_create("mail delivery", 1024);
	dctx.set = sets[1];
	dctx.src_mail = src_mail;
	dctx.src_envelope_sender = client->state.mail_from;
	dctx.dest_user = client->state.dest_user;
	dctx.dest_addr = rcpt->name;
	dctx.dest_mailbox_name = "INBOX";
	dctx.save_dest_mail = array_count(&client->state.rcpt_to) > 1 &&
		client->state.first_saved_mail == NULL;

	if (mail_deliver(&dctx, &storage) == 0) {
		if (dctx.dest_mail != NULL) {
			i_assert(client->state.first_saved_mail == NULL);
			client->state.first_saved_mail = dctx.dest_mail;
		}
		client_send_line(client, "250 2.0.0 <%s> Saved", rcpt->name);
		ret = 0;
	} else if (storage == NULL) {
		/* This shouldn't happen */
		i_error("BUG: Saving failed to unknown storage");
		client_send_line(client, ERRSTR_MAILBOX_TEMP_FAIL,
				 rcpt->name);
		ret = -1;
	} else {
		error = mail_storage_get_last_error(storage, &mail_error);
		if (mail_error == MAIL_ERROR_NOSPACE) {
			client_send_line(client, "%s <%s> %s",
					 dctx.set->quota_full_tempfail ?
					 "452 4.2.2" : "552 5.2.2",
					 rcpt->name, error);
		} else {
			client_send_line(client, "451 4.2.0 <%s> %s",
					 rcpt->name, error);
		}
		ret = -1;
	}
	pool_unref(&dctx.pool);
	return ret;
}

static bool client_deliver_next(struct client *client, struct mail *src_mail)
{
	const struct mail_recipient *rcpts;
	unsigned int count;
	int ret;

	rcpts = array_get(&client->state.rcpt_to, &count);
	while (client->state.rcpt_idx < count) {
		ret = client_deliver(client, &rcpts[client->state.rcpt_idx],
				     src_mail);
		i_set_failure_prefix("lmtp: ");

		client->state.rcpt_idx++;
		if (ret == 0)
			return TRUE;
		/* failed. try the next one. */
		if (client->state.dest_user != NULL)
			mail_user_unref(&client->state.dest_user);
	}
	return FALSE;
}

static void client_rcpt_fail_all(struct client *client)
{
	const struct mail_recipient *rcpts;
	unsigned int i, count;

	rcpts = array_get(&client->state.rcpt_to, &count);
	for (i = 0; i < count; i++) {
		client_send_line(client, ERRSTR_MAILBOX_TEMP_FAIL,
				 rcpts[i].name);
	}
}

static int client_open_raw_mail(struct client *client)
{
	static const char *wanted_headers[] = {
		"From", "To", "Message-ID", "Subject", "Return-Path",
		NULL
	};
	struct mail_storage *raw_storage =
		client->raw_mail_user->namespaces->storage;
	struct mailbox *box;
	struct raw_mailbox *raw_box;
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct istream *input;
	enum mail_error error;

	if (client->state.mail_data_output != NULL) {
		o_stream_unref(&client->state.mail_data_output);
		input = i_stream_create_fd(client->state.mail_data_fd,
					   MAIL_READ_BLOCK_SIZE, FALSE);
	} else {
		input = i_stream_create_from_data(client->state.mail_data->data,
						  client->state.mail_data->used);
	}
	client->state.raw_box = box =
		mailbox_open(&raw_storage, "Dovecot Delivery Mail", input,
			     MAILBOX_OPEN_NO_INDEX_FILES);
	i_stream_unref(&input);
	if (box == NULL) {
		i_error("Can't open delivery mail as raw: %s",
			mail_storage_get_last_error(raw_storage, &error));
		client_rcpt_fail_all(client);
		return -1;
	}
	if (mailbox_sync(box, 0, 0, NULL) < 0) {
		i_error("Can't sync delivery mail: %s",
			mail_storage_get_last_error(raw_storage, &error));
		client_rcpt_fail_all(client);
		return -1;
	}
	raw_box = (struct raw_mailbox *)box;
	raw_box->envelope_sender = client->state.mail_from;

	client->state.raw_trans = mailbox_transaction_begin(box, 0);

	headers_ctx = mailbox_header_lookup_init(box, wanted_headers);
	client->state.raw_mail = mail_alloc(client->state.raw_trans,
					    0, headers_ctx);
	mailbox_header_lookup_unref(&headers_ctx);
	mail_set_seq(client->state.raw_mail, 1);
	return 0;
}

static void client_input_data_finish(struct client *client)
{
	struct mail *src_mail;

	io_remove(&client->io);
	client->io = io_add(client->fd_in, IO_READ, client_input, client);

	if (client_open_raw_mail(client) < 0)
		return;

	/* save the message to the first recipient's mailbox */
	src_mail = client->state.raw_mail;
	if (!client_deliver_next(client, src_mail))
		return;

	if (client->state.first_saved_mail == NULL)
		mail_user_unref(&client->state.dest_user);
	else
		src_mail = client->state.first_saved_mail;

	/* use the first saved message to save it elsewhere too.
	   this might allow hard linking the files. */
	while (client_deliver_next(client, src_mail))
		mail_user_unref(&client->state.dest_user);

	if (client->state.first_saved_mail != NULL) {
		struct mail *mail = client->state.first_saved_mail;
		struct mailbox_transaction_context *trans = mail->transaction;
		struct mailbox *box = trans->box;
		struct mail_user *user = box->storage->ns->user;

		mail_free(&mail);
		mailbox_transaction_rollback(&trans);
		mailbox_close(&box);
		mail_user_unref(&user);
	}
}

static int client_input_add_file(struct client *client,
				 const unsigned char *data, size_t size)
{
	string_t *path;
	int fd;

	if (client->state.mail_data_output != NULL) {
		/* continue writing to file */
		if (o_stream_send(client->state.mail_data_output,
				  data, size) != (ssize_t)size)
			return -1;
		return 0;
	}

	/* move everything to a temporary file. FIXME: it really shouldn't
	   be in /tmp.. */
	path = t_str_new(256);
	str_append(path, "/tmp/dovecot.lmtp.");
	fd = safe_mkstemp_hostpid(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1)
		return -1;

	/* we just want the fd, unlink it */
	if (unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_error("unlink(%s) failed: %m", str_c(path));
		(void)close(fd);
		return -1;
	}

	client->state.mail_data_fd = fd;
	client->state.mail_data_output = o_stream_create_fd_file(fd, 0, FALSE);
	o_stream_cork(client->state.mail_data_output);
	if (o_stream_send(client->state.mail_data_output,
			  data, size) != (ssize_t)size)
		return -1;
	return 0;
}

static int
client_input_add(struct client *client, const unsigned char *data, size_t size)
{
	if (client->state.mail_data->used + size <=
	    CLIENT_MAIL_DATA_MAX_INMEMORY_SIZE) {
		buffer_append(client->state.mail_data, data, size);
		return 0;
	} else {
		return client_input_add_file(client, data, size);
	}
}

static void client_input_data_handle(struct client *client)
{
#define DATA_DOT_NEXT_POS 3
#define DATA_END_SIZE 5
	static const char *data_end = "\r\n.\r\n";
	const unsigned char *data;
	size_t i, size, start, skip;
	unsigned int rewind;

	data = i_stream_get_data(client->input, &size);
	skip = 0;
	for (i = start = 0; i < size; i++) {
		if (data[i] == data_end[client->state.data_end_idx]) {
			if (++client->state.data_end_idx == DATA_END_SIZE) {
				/* found the ending. drop the "." line out. */
				skip = i + 1;
				i -= DATA_END_SIZE - DATA_DOT_NEXT_POS;
				client->state.data_end_idx = 0;
				break;
			}
		} else if (client->state.data_end_idx == DATA_DOT_NEXT_POS) {
			/* saw a dot at the beginning of line. drop it. */
			if (client_input_add(client, data, i-1) < 0) {
				client_destroy(client, "451 4.3.0",
					       "Temporary internal failure");
				return;
			}
			start = i;
			client->state.data_end_idx = 0;
		} else {
			client->state.data_end_idx = 0;
		}
	}
	if (client->state.data_end_idx >= DATA_DOT_NEXT_POS) {
		/* we might not want to write the dot, so keep it in buffer
		   until we're sure what to do about it. */
		rewind = client->state.data_end_idx - DATA_DOT_NEXT_POS + 1;
		i -= rewind; size -= rewind;
	}
	if (client_input_add(client, data + start, i-start) < 0) {
		client_destroy(client, "451 4.3.0",
			       "Temporary internal failure");
		return;
	}
	i_stream_skip(client->input, skip == 0 ? i : skip);

	if (i < size) {
		client_input_data_finish(client);
		client_state_reset(client);
		if (i_stream_have_bytes_left(client->input))
			client_input_handle(client);
	}
}

static void client_input_data(struct client *client)
{
	if (client_input_read(client) < 0)
		return;

	client_input_data_handle(client);
}

int cmd_data(struct client *client, const char *args ATTR_UNUSED)
{
	if (client->state.mail_from == NULL) {
		client_send_line(client, "503 5.5.1 MAIL needed first");
		return 0;
	}
	if (array_count(&client->state.rcpt_to) == 0) {
		client_send_line(client, "554 5.5.1 No valid recipients");
		return 0;
	}

	i_assert(client->state.mail_data == NULL);
	client->state.mail_data = buffer_create_dynamic(default_pool, 1024*64);

	io_remove(&client->io);
	client->io = io_add(client->fd_in, IO_READ, client_input_data, client);
	client_send_line(client, "354 OK");

	client_input_data_handle(client);
	return -1;
}
