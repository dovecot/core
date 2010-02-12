/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "pop3-common.h"
#include "buffer.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "llist.h"
#include "hostpid.h"
#include "var-expand.h"
#include "master-service.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "pop3-commands.h"
#include "mail-search-build.h"
#include "mail-namespace.h"

#include <stdlib.h>
#include <unistd.h>

/* max. length of input command line (spec says 512) */
#define MAX_INBUF_SIZE 2048

/* Stop reading input when output buffer has this many bytes. Once the buffer
   size has dropped to half of it, start reading input again. */
#define OUTBUF_THROTTLE_SIZE 4096

/* Disconnect client when it sends too many bad commands in a row */
#define CLIENT_MAX_BAD_COMMANDS 20

/* Disconnect client after idling this many milliseconds */
#define CLIENT_IDLE_TIMEOUT_MSECS (10*60*1000)
/* If client starts idling for this many milliseconds, commit the current
   transaction. This allows the mailbox to become unlocked. */
#define CLIENT_COMMIT_TIMEOUT_MSECS (10*1000)

struct client *pop3_clients;
unsigned int pop3_client_count;

static void client_input(struct client *client);
static int client_output(struct client *client);

static void client_commit_timeout(struct client *client)
{
	if (client->cmd != NULL) {
		/* Can't commit while commands are running */
		return;
	}

	(void)mailbox_transaction_commit(&client->trans);
	client->trans = mailbox_transaction_begin(client->mailbox, 0);
}

static void client_idle_timeout(struct client *client)
{
	if (client->cmd != NULL) {
		client_destroy(client,
			"Disconnected for inactivity in reading our output");
	} else {
		client_send_line(client, "-ERR Disconnected for inactivity.");
		client_destroy(client, "Disconnected for inactivity");
	}
}

static bool init_mailbox(struct client *client, const char **error_r)
{
	struct mail_search_args *search_args;
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

	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);

	for (i = 0; i < 2; i++) {
		expunged = FALSE;
		if (mailbox_sync(client->mailbox,
				 MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
			client_send_storage_error(client);
			break;
		}
		mailbox_get_status(client->mailbox, STATUS_UIDVALIDITY, &status);
		client->uid_validity = status.uidvalidity;

		t = mailbox_transaction_begin(client->mailbox, 0);
		ctx = mailbox_search_init(t, search_args, NULL);

		client->last_seen = 0;
		client->total_size = 0;
		buffer_set_used_size(message_sizes_buf, 0);

		failed = FALSE;
		mail = mail_alloc(t, MAIL_FETCH_VIRTUAL_SIZE, NULL);
		while (mailbox_search_next(ctx, mail)) {
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
			(void)mailbox_transaction_commit(&t);
			break;
		}

		if (!failed) {
			client->trans = t;
			client->message_sizes =
				buffer_free_without_data(&message_sizes_buf);
			mail_search_args_unref(&search_args);
			return TRUE;
		}

		/* well, sync and try again. we might have cached virtual
		   sizes, make sure they get committed. */
		(void)mailbox_transaction_commit(&t);
	}
	mail_search_args_unref(&search_args);

	if (expunged) {
		client_send_line(client,
				 "-ERR [IN-USE] Couldn't sync mailbox.");
		*error_r = "Can't sync mailbox: Messages keep getting expunged";
	} else {
		struct mail_storage *storage;
		enum mail_error error;

		storage = mailbox_get_storage(client->mailbox);
		*error_r = mail_storage_get_last_error(storage, &error);
	}
	buffer_free(&message_sizes_buf);
	return FALSE;
}

static enum uidl_keys parse_uidl_keymask(const char *format)
{
	enum uidl_keys mask = 0;

	for (; *format != '\0'; format++) {
		if (format[0] == '%' && format[1] != '\0') {
			switch (var_get_key(++format)) {
			case 'v':
				mask |= UIDL_UIDVALIDITY;
				break;
			case 'u':
				mask |= UIDL_UID;
				break;
			case 'm':
				mask |= UIDL_MD5;
				break;
			case 'f':
				mask |= UIDL_FILE_NAME;
				break;
			case 'g':
				mask |= UIDL_GUID;
				break;
			}
		}
	}
	return mask;
}

struct client *client_create(int fd_in, int fd_out, struct mail_user *user,
			     struct mail_storage_service_user *service_user,
			     const struct pop3_settings *set)
{
	struct mail_namespace *ns;
	struct mail_storage *storage;
	const char *inbox, *ident;
	struct client *client;
        enum mailbox_flags flags;
	const char *errmsg;
	enum mail_error error;

	/* always use nonblocking I/O */
	net_set_nonblock(fd_in, TRUE);
	net_set_nonblock(fd_out, TRUE);

	client = i_new(struct client, 1);
	client->service_user = service_user;
	client->set = set;
	client->fd_in = fd_in;
	client->fd_out = fd_out;
	client->input = i_stream_create_fd(fd_in, MAX_INBUF_SIZE, FALSE);
	client->output = o_stream_create_fd(fd_out, (size_t)-1, FALSE);
	o_stream_set_flush_callback(client->output, client_output, client);

	client->io = io_add(fd_in, IO_READ, client_input, client);
        client->last_input = ioloop_time;
	client->to_idle = timeout_add(CLIENT_IDLE_TIMEOUT_MSECS,
				      client_idle_timeout, client);
	if (!set->pop3_lock_session) {
		client->to_commit = timeout_add(CLIENT_COMMIT_TIMEOUT_MSECS,
						client_commit_timeout, client);
	}

	client->user = user;

	inbox = "INBOX";
	ns = mail_namespace_find(user->namespaces, &inbox);
	if (ns == NULL) {
		client_send_line(client, "-ERR No INBOX namespace for user.");
		client_destroy(client, "No INBOX namespace for user.");
		return NULL;
	}
	client->inbox_ns = ns;

	flags = MAILBOX_FLAG_POP3_SESSION;
	if (set->pop3_no_flag_updates)
		flags |= MAILBOX_FLAG_KEEP_RECENT;
	if (set->pop3_lock_session)
		flags |= MAILBOX_FLAG_KEEP_LOCKED;
	client->mailbox = mailbox_alloc(ns->list, "INBOX", flags);
	storage = mailbox_get_storage(client->mailbox);
	if (mailbox_open(client->mailbox) < 0) {
		errmsg = t_strdup_printf("Couldn't open INBOX: %s",
					 mail_storage_get_last_error(storage,
								     &error));
		i_error("%s", errmsg);
		client_send_line(client, "-ERR [IN-USE] %s", errmsg);
		client_destroy(client, "Couldn't open INBOX");
		return NULL;
	}
	client->mail_set = mail_storage_get_settings(storage);

	if (!init_mailbox(client, &errmsg)) {
		i_error("Couldn't init INBOX: %s", errmsg);
		client_destroy(client, "Mailbox init failed");
		return NULL;
	}

	client->uidl_keymask =
		parse_uidl_keymask(client->mail_set->pop3_uidl_format);
	if (client->uidl_keymask == 0)
		i_fatal("Invalid pop3_uidl_format");

	if (!set->pop3_no_flag_updates && client->messages_count > 0)
		client->seen_bitmask = i_malloc(MSGS_BITMASK_SIZE(client));

	ident = mail_user_get_anvil_userip_ident(client->user);
	if (ident != NULL) {
		master_service_anvil_send(master_service, t_strconcat(
			"CONNECT\t", my_pid, "\tpop3/", ident, "\n", NULL));
		client->anvil_sent = TRUE;
	}

	pop3_client_count++;
	DLLIST_PREPEND(&pop3_clients, client);
	if (hook_client_created != NULL)
		hook_client_created(&client);

	pop3_refresh_proctitle();
	return client;
}

static const char *client_stats(struct client *client)
{
	static struct var_expand_table static_tab[] = {
		{ 'p', NULL, "top_bytes" },
		{ 't', NULL, "top_count" },
		{ 'b', NULL, "retr_bytes" },
		{ 'r', NULL, "retr_count" },
		{ 'd', NULL, "deleted_count" },
		{ 'm', NULL, "message_count" },
		{ 's', NULL, "message_bytes" },
		{ 'i', NULL, "input" },
		{ 'o', NULL, "output" },
		{ '\0', NULL, NULL }
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
	var_expand(str, client->set->pop3_logout_format, tab);
	return str_c(str);
}

static const char *client_get_disconnect_reason(struct client *client)
{
	errno = client->input->stream_errno != 0 ?
		client->input->stream_errno :
		client->output->stream_errno;
	return errno == 0 || errno == EPIPE ? "Connection closed" :
		t_strdup_printf("Connection closed: %m");
}

void client_destroy(struct client *client, const char *reason)
{
	if (client->seen_change_count > 0)
		client_update_mails(client);

	if (!client->disconnected) {
		if (reason == NULL)
			reason = client_get_disconnect_reason(client);
		i_info("%s %s", reason, client_stats(client));
	}

	if (client->cmd != NULL) {
		/* deinitialize command */
		i_stream_close(client->input);
		o_stream_close(client->output);
		client->cmd(client);
		i_assert(client->cmd == NULL);
	}
	pop3_client_count--;
	DLLIST_REMOVE(&pop3_clients, client);

	if (client->trans != NULL) {
		/* client didn't QUIT, but we still want to save any changes
		   done in this transaction. especially the cached virtual
		   message sizes. */
		(void)mailbox_transaction_commit(&client->trans);
	}
	if (client->mailbox != NULL)
		mailbox_free(&client->mailbox);
	if (client->anvil_sent) {
		master_service_anvil_send(master_service, t_strconcat(
			"DISCONNECT\t", my_pid, "\tpop3/",
			mail_user_get_anvil_userip_ident(client->user),
			"\n", NULL));
	}
	mail_user_unref(&client->user);

	i_free(client->message_sizes);
	i_free(client->deleted_bitmask);
	i_free(client->seen_bitmask);

	if (client->io != NULL)
		io_remove(&client->io);
	timeout_remove(&client->to_idle);
	if (client->to_commit != NULL)
		timeout_remove(&client->to_commit);

	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);

	if (close(client->fd_in) < 0)
		i_error("close(client in) failed: %m");
	if (client->fd_in != client->fd_out) {
		if (close(client->fd_out) < 0)
			i_error("close(client out) failed: %m");
	}
	mail_storage_service_user_free(&client->service_user);
	i_free(client);

	master_service_client_connection_destroyed(master_service);
	pop3_refresh_proctitle();
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
	ssize_t ret;

	if (client->output->closed)
		return -1;

	va_start(va, fmt);

	T_BEGIN {
		string_t *str;

		str = t_str_new(256);
		str_vprintfa(str, fmt, va);
		str_append(str, "\r\n");

		ret = o_stream_send(client->output,
				    str_data(str), str_len(str));
		i_assert(ret < 0 || (size_t)ret == str_len(str));
	} T_END;
	if (ret >= 0) {
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
	return (int)ret;
}

void client_send_storage_error(struct client *client)
{
	struct mail_storage *storage;
	enum mail_error error;

	if (mailbox_is_inconsistent(client->mailbox)) {
		client_send_line(client, "-ERR Mailbox is in inconsistent "
				 "state, please relogin.");
		client_disconnect(client, "Mailbox is in inconsistent state.");
		return;
	}

	storage = mailbox_get_storage(client->mailbox);
	client_send_line(client, "-ERR %s",
			 mail_storage_get_last_error(storage, &error));
}

bool client_handle_input(struct client *client)
{
	char *line, *args;
	int ret;

	o_stream_cork(client->output);
	while (!client->output->closed &&
	       (line = i_stream_next_line(client->input)) != NULL) {
		args = strchr(line, ' ');
		if (args != NULL)
			*args++ = '\0';

		T_BEGIN {
			ret = client_command_execute(client, line,
						     args != NULL ? args : "");
		} T_END;
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

	if (client->output->closed) {
		client_destroy(client, NULL);
		return FALSE;
	}
	return TRUE;
}

static void client_input(struct client *client)
{
	if (client->cmd != NULL) {
		/* we're still processing a command. wait until it's
		   finished. */
		io_remove(&client->io);
		client->waiting_input = TRUE;
		return;
	}

	client->waiting_input = FALSE;
	client->last_input = ioloop_time;
	timeout_reset(client->to_idle);
	if (client->to_commit != NULL)
		timeout_reset(client->to_commit);

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

	(void)client_handle_input(client);
}

static int client_output(struct client *client)
{
	int ret;

	if ((ret = o_stream_flush(client->output)) < 0) {
		client_destroy(client, NULL);
		return 1;
	}

	client->last_output = ioloop_time;
	timeout_reset(client->to_idle);
	if (client->to_commit != NULL)
		timeout_reset(client->to_commit);

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

void clients_destroy_all(void)
{
	while (pop3_clients != NULL) {
		if (pop3_clients->cmd == NULL) {
			client_send_line(pop3_clients,
				"-ERR Server shutting down.");
		}
		client_destroy(pop3_clients, "Server shutting down.");
	}
}
