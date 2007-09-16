/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "buffer.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "var-expand.h"
#include "mail-storage.h"
#include "commands.h"
#include "mail-search.h"
#include "mail-namespace.h"

#include <stdlib.h>
#include <unistd.h>

/* max. length of input command line (spec says 512) */
#define MAX_INBUF_SIZE 2048

/* Stop reading input when output buffer has this many bytes. Once the buffer
   size has dropped to half of it, start reading input again. */
#define OUTBUF_THROTTLE_SIZE 4096

/* If we can't send anything for 10 minutes, disconnect the client */
#define CLIENT_OUTPUT_TIMEOUT (10*60)

/* Disconnect client when it sends too many bad commands in a row */
#define CLIENT_MAX_BAD_COMMANDS 20

/* Disconnect client after idling this many seconds */
#define CLIENT_IDLE_TIMEOUT (10*60)

static struct client *my_client; /* we don't need more than one currently */
static struct timeout *to_idle;

static void client_input(struct client *client);
static int client_output(struct client *client);

static int sync_mailbox(struct mailbox *box, struct mailbox_status *status)
{
	struct mailbox_sync_context *ctx;
        struct mailbox_sync_rec sync_rec;

	ctx = mailbox_sync_init(box, MAILBOX_SYNC_FLAG_FULL_READ);
	while (mailbox_sync_next(ctx, &sync_rec))
		;
	return mailbox_sync_deinit(&ctx, STATUS_UIDVALIDITY, status);
}

static bool init_mailbox(struct client *client, const char **error_r)
{
	struct mail_search_arg search_arg;
        struct mailbox_transaction_context *t;
	struct mail_search_context *ctx;
        struct mailbox_status status;
	struct mail *mail;
	buffer_t *message_sizes_buf;
	uint32_t failed_uid = 0;
	uoff_t size;
	int i;
	bool failed, expunged;

	message_sizes_buf = buffer_create_dynamic(default_pool, 512);

	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_ALL;

	for (i = 0; i < 2; i++) {
		if (sync_mailbox(client->mailbox, &status) < 0) {
			client_send_storage_error(client);
			break;
		}
		client->uid_validity = status.uidvalidity;

		t = mailbox_transaction_begin(client->mailbox, 0);
		ctx = mailbox_search_init(t, NULL, &search_arg, NULL);

		client->last_seen = 0;
		client->total_size = 0;
		buffer_set_used_size(message_sizes_buf, 0);

		expunged = FALSE;
		failed = FALSE;
		mail = mail_alloc(t, MAIL_FETCH_VIRTUAL_SIZE, NULL);
		while (mailbox_search_next(ctx, mail) > 0) {
			if (mail_get_virtual_size(mail, &size) < 0) {
				expunged = mail->expunged;
				failed = TRUE;
				if (failed_uid == mail->uid) {
					i_error("Getting size of message "
						"UID=%u failed", mail->uid);
					break;
				}
				failed_uid = mail->uid;
				break;
			}

			if ((mail_get_flags(mail) & MAIL_SEEN) != 0)
				client->last_seen = mail->seq;
                        client->total_size += size;

			buffer_append(message_sizes_buf, &size, sizeof(size));
		}
		client->messages_count =
			message_sizes_buf->used / sizeof(uoff_t);

		mail_free(&mail);
		if (mailbox_search_deinit(&ctx) < 0 || (failed && !expunged)) {
			client_send_storage_error(client);
			(void)mailbox_transaction_commit(&t, 0);
			break;
		}

		if (!failed) {
			client->trans = t;
			client->message_sizes =
				buffer_free_without_data(&message_sizes_buf);
			return TRUE;
		}

		/* well, sync and try again. we might have cached virtual
		   sizes, make sure they get committed. */
		(void)mailbox_transaction_commit(&t, 0);
	}

	if (expunged) {
		client_send_line(client,
				 "-ERR [IN-USE] Couldn't sync mailbox.");
		*error_r = "Can't sync mailbox: Messages keep getting expunged";
	} else {
		struct mail_storage *storage = client->inbox_ns->storage;
		enum mail_error error;

		*error_r = mail_storage_get_last_error(storage, &error);
	}
	buffer_free(&message_sizes_buf);
	return FALSE;
}

struct client *client_create(int fd_in, int fd_out,
			     struct mail_namespace *namespaces)
{
	struct mail_storage *storage;
	const char *inbox;
	struct client *client;
        enum mailbox_open_flags flags;
	const char *errmsg;
	enum mail_error error;

	/* always use nonblocking I/O */
	net_set_nonblock(fd_in, TRUE);
	net_set_nonblock(fd_out, TRUE);

	client = i_new(struct client, 1);
	client->fd_in = fd_in;
	client->fd_out = fd_out;
	client->input = i_stream_create_fd(fd_in, MAX_INBUF_SIZE, FALSE);
	client->output = o_stream_create_fd(fd_out, (size_t)-1, FALSE);
	o_stream_set_flush_callback(client->output, client_output, client);

	client->io = io_add(fd_in, IO_READ, client_input, client);
        client->last_input = ioloop_time;

	client->namespaces = namespaces;

	inbox = "INBOX";
	client->inbox_ns = mail_namespace_find(namespaces, &inbox);
	if (client->inbox_ns == NULL) {
		client_send_line(client, "-ERR No INBOX namespace for user.");
		client_destroy(client, "No INBOX namespace for user.");
		return NULL;
	}

	storage = client->inbox_ns->storage;

	flags = 0;
	if (no_flag_updates)
		flags |= MAILBOX_OPEN_KEEP_RECENT;
	if (lock_session)
		flags |= MAILBOX_OPEN_KEEP_LOCKED;
	client->mailbox = mailbox_open(storage, "INBOX", NULL, flags);
	if (client->mailbox == NULL) {
		errmsg = t_strdup_printf("Couldn't open INBOX: %s",
				mail_storage_get_last_error(storage,
							    &error));
		i_error("%s", errmsg);
		client_send_line(client, "-ERR [IN-USE] %s", errmsg);
		client_destroy(client, "Couldn't open INBOX");
		return NULL;
	}

	if (!init_mailbox(client, &errmsg)) {
		i_error("Couldn't init INBOX: %s", errmsg);
		client_destroy(client, "Mailbox init failed");
		return NULL;
	}

	i_assert(my_client == NULL);
	my_client = client;

	if (hook_client_created != NULL)
		hook_client_created(&client);
	return client;
}

static const char *client_stats(struct client *client)
{
	static struct var_expand_table static_tab[] = {
		{ 'p', NULL },
		{ 't', NULL },
		{ 'b', NULL },
		{ 'r', NULL },
		{ 'd', NULL },
		{ 'm', NULL },
		{ 's', NULL },
		{ 'i', NULL },
		{ 'o', NULL },
		{ '\0', NULL }
	};
	struct var_expand_table *tab;
	string_t *str;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = dec2str(client->top_bytes);
	tab[1].value = dec2str(client->top_count);
	tab[2].value = dec2str(client->retr_bytes);
	tab[3].value = dec2str(client->retr_count);
	tab[4].value = dec2str(client->expunged_count);
	tab[5].value = dec2str(client->messages_count);
	tab[6].value = dec2str(client->total_size);
	tab[7].value = dec2str(client->input->v_offset);
	tab[8].value = dec2str(client->output->offset);

	str = t_str_new(128);
	var_expand(str, logout_format, tab);
	return str_c(str);
}

void client_destroy(struct client *client, const char *reason)
{
	if (!client->disconnected) {
		if (reason == NULL)
			reason = "Disconnected";
		i_info("%s %s", reason, client_stats(client));
	}

	if (client->cmd != NULL) {
		/* deinitialize command */
		i_stream_close(client->input);
		o_stream_close(client->output);
		client->cmd(client);
		i_assert(client->cmd == NULL);
	}
	if (client->trans != NULL) {
		/* client didn't QUIT, but we still want to save any changes
		   done in this transaction. especially the cached virtual
		   message sizes. */
		(void)mailbox_transaction_commit(&client->trans, 0);
	}
	if (client->mailbox != NULL)
		mailbox_close(&client->mailbox);
	mail_namespaces_deinit(&client->namespaces);

	i_free(client->message_sizes);
	i_free(client->deleted_bitmask);

	if (client->io != NULL)
		io_remove(&client->io);

	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);

	if (close(client->fd_in) < 0)
		i_error("close(client in) failed: %m");
	if (client->fd_in != client->fd_out) {
		if (close(client->fd_out) < 0)
			i_error("close(client out) failed: %m");
	}

	i_free(client);

	/* quit the program */
	my_client = NULL;
	io_loop_stop(ioloop);
}

void client_disconnect(struct client *client, const char *reason)
{
	if (client->disconnected)
		return;

	client->disconnected = TRUE;
	i_info("Disconnected: %s %s", reason, client_stats(client));

	(void)o_stream_flush(client->output);

	i_stream_close(client->input);
	o_stream_close(client->output);
}

int client_send_line(struct client *client, const char *fmt, ...)
{
	va_list va;
	string_t *str;
	ssize_t ret;

	if (client->output->closed)
		return -1;

	t_push();
	va_start(va, fmt);

	str = t_str_new(256);
	str_vprintfa(str, fmt, va);
	str_append(str, "\r\n");

	ret = o_stream_send(client->output, str_data(str), str_len(str));
	if (ret >= 0) {
		i_assert((size_t)ret == str_len(str));

		if (o_stream_get_buffer_used_size(client->output) <
		    OUTBUF_THROTTLE_SIZE) {
			ret = 1;
			client->last_output = ioloop_time;
		} else {
			ret = 0;
			if (client->io != NULL) {
				/* no more input until client has read
				   our output */
				io_remove(&client->io);

				/* If someone happens to flush output,
				   we want to get our IO handler back in
				   flush callback */
				o_stream_set_flush_pending(client->output,
							   TRUE);
			}
		}
	}

	va_end(va);
	t_pop();
	return (int)ret;
}

void client_send_storage_error(struct client *client)
{
	enum mail_error error;

	if (mailbox_is_inconsistent(client->mailbox)) {
		client_send_line(client, "-ERR Mailbox is in inconsistent "
				 "state, please relogin.");
		client_disconnect(client, "Mailbox is in inconsistent state.");
		return;
	}

	client_send_line(client, "-ERR %s",
			 mail_storage_get_last_error(client->inbox_ns->storage,
						     &error));
}

static void client_input(struct client *client)
{
	char *line, *args;
	int ret;

	if (client->cmd != NULL) {
		/* we're still processing a command. wait until it's
		   finished. */
		io_remove(&client->io);
		client->waiting_input = TRUE;
		return;
	}

	client->waiting_input = FALSE;
	client->last_input = ioloop_time;

	switch (i_stream_read(client->input)) {
	case -1:
		/* disconnected */
		client_destroy(client, NULL);
		return;
	case -2:
		/* line too long, kill it */
		client_send_line(client, "-ERR Input line too long.");
		client_destroy(client, "Input line too long");
		return;
	}

	o_stream_cork(client->output);
	while (!client->output->closed &&
	       (line = i_stream_next_line(client->input)) != NULL) {
		args = strchr(line, ' ');
		if (args != NULL)
			*args++ = '\0';

		t_push();
		ret = client_command_execute(client, line,
					     args != NULL ? args : "");
		t_pop();
		if (ret >= 0) {
			client->bad_counter = 0;
			if (client->cmd != NULL) {
				o_stream_set_flush_pending(client->output,
							   TRUE);
				client->waiting_input = TRUE;
				break;
			}
		} else if (++client->bad_counter > CLIENT_MAX_BAD_COMMANDS) {
			client_send_line(client, "-ERR Too many bad commands.");
			client_disconnect(client, "Too many bad commands.");
		}
	}
	o_stream_uncork(client->output);

	if (client->output->closed)
		client_destroy(client, NULL);
}

static int client_output(struct client *client)
{
	int ret;

	if ((ret = o_stream_flush(client->output)) < 0) {
		client_destroy(client, NULL);
		return 1;
	}

	client->last_output = ioloop_time;

	if (client->cmd != NULL) {
		o_stream_cork(client->output);
		client->cmd(client);
		o_stream_uncork(client->output);
	}

	if (client->cmd == NULL) {
		if (o_stream_get_buffer_used_size(client->output) <
		    OUTBUF_THROTTLE_SIZE/2 && client->io == NULL) {
			/* enable input again */
			client->io = io_add(i_stream_get_fd(client->input),
					    IO_READ, client_input, client);
		}
		if (client->io != NULL && client->waiting_input)
			client_input(client);
	}

	return client->cmd == NULL;
}

static void idle_timeout(void *context ATTR_UNUSED)
{
	if (my_client == NULL)
		return;

	if (my_client->cmd != NULL) {
		if (ioloop_time - my_client->last_output >=
		    CLIENT_OUTPUT_TIMEOUT) {
			client_destroy(my_client, "Disconnected for inactivity "
				       "in reading our output");
		}
	} else {
		if (ioloop_time - my_client->last_input >=
		    CLIENT_IDLE_TIMEOUT) {
			client_send_line(my_client,
					 "-ERR Disconnected for inactivity.");
			client_destroy(my_client, "Disconnected for inactivity");
		}
	}
}

void clients_init(void)
{
	my_client = NULL;
	to_idle = timeout_add(10000, idle_timeout, NULL);
}

void clients_deinit(void)
{
	if (my_client != NULL) {
		client_send_line(my_client, "-ERR Server shutting down.");
		client_destroy(my_client, "Server shutting down");
	}

	timeout_remove(&to_idle);
}
