/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "write-full.h"
#include "strescape.h"
#include "process-title.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "master-connection.h"

#include <unistd.h>

#define INDEXER_PROTOCOL_MAJOR_VERSION 1
#define INDEXER_PROTOCOL_MINOR_VERSION 0

#define INDEXER_WORKER_HANDSHAKE "VERSION\tindexer-worker-master\t1\t0\n%u\n"
#define INDEXER_MASTER_NAME "indexer-master-worker"

struct master_connection {
	struct mail_storage_service_ctx *storage_service;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	unsigned int version_received:1;
};

static void
indexer_worker_refresh_proctitle(const char *username, const char *mailbox)
{
	if (!master_service_settings_get(master_service)->verbose_proctitle)
		return;

	if (username != NULL)
		process_title_set(t_strdup_printf("[%s %s]", username, mailbox));
	else
		process_title_set("[idling]");
}

static int index_mailbox(struct mail_user *user, const char *mailbox,
			 unsigned int max_recent_msgs)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mailbox_status status;
	const char *errstr;
	enum mail_error error;
	int ret = 0;

	ns = mail_namespace_find(user->namespaces, mailbox);
	if (ns == NULL) {
		i_error("Namespace not found for mailbox %s: ", mailbox);
		return -1;
	}

	/* FIXME: the current lib-storage API doesn't allow sending
	   "n% competed" notifications */
	box = mailbox_alloc(ns->list, mailbox, MAILBOX_FLAG_KEEP_RECENT);
	if (max_recent_msgs != 0) {
		/* index only if there aren't too many recent messages.
		   don't bother syncing the mailbox, that alone can take a
		   while with large maildirs. */
		if (mailbox_open(box) < 0) {
			i_error("Opening mailbox %s failed: %s", mailbox,
				mail_storage_get_last_error(mailbox_get_storage(box), NULL));
			ret = -1;
		} else {
			mailbox_get_open_status(box, STATUS_RECENT, &status);
		}
		if (ret < 0 || status.recent > max_recent_msgs) {
			mailbox_free(&box);
			return ret;
		}
	}
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ |
			 MAILBOX_SYNC_FLAG_PRECACHE) < 0) {
		errstr = mail_storage_get_last_error(mailbox_get_storage(box),
						     &error);
		if (error != MAIL_ERROR_NOTFOUND) {
			i_error("Syncing mailbox %s failed: %s",
				mailbox, errstr);
		} else if (user->mail_debug) {
			i_debug("Syncing mailbox %s failed: %s",
				mailbox, errstr);
		}
		ret = -1;
	}
	mailbox_free(&box);
	return ret;
}

static int
master_connection_input_line(struct master_connection *conn, const char *line)
{
	const char *const *args = t_strsplit_tabescaped(line);
	struct mail_storage_service_input input;
	struct mail_storage_service_user *service_user;
	struct mail_user *user;
	const char *str, *error;
	unsigned int max_recent_msgs;
	int ret;

	/* <username> <mailbox> <max_recent_msgs> */
	if (str_array_length(args) != 3 ||
	    str_to_uint(args[2], &max_recent_msgs) < 0) {
		i_error("Invalid input from master: %s", line);
		return -1;
	}

	memset(&input, 0, sizeof(input));
	input.module = "mail";
	input.service = "indexer-worker";
	input.username = args[0];

	if (mail_storage_service_lookup_next(conn->storage_service, &input,
					     &service_user, &user, &error) <= 0) {
		i_error("User %s lookup failed: %s", args[0], error);
		ret = -1;
	} else {
		indexer_worker_refresh_proctitle(user->username, args[1]);
		ret = index_mailbox(user, args[1], max_recent_msgs);
		indexer_worker_refresh_proctitle(NULL, NULL);
		mail_user_unref(&user);
		mail_storage_service_user_free(&service_user);
	}

	str = ret < 0 ? "-1\n" : "100\n";
	return write_full(conn->fd, str, strlen(str));
}

static void master_connection_input(struct master_connection *conn)
{
	const char *line;
	int ret;

	if (i_stream_read(conn->input) < 0) {
		master_service_stop(master_service);
		return;
	}

	if (!conn->version_received) {
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;

		if (!version_string_verify(line, INDEXER_MASTER_NAME,
				INDEXER_PROTOCOL_MAJOR_VERSION)) {
			i_error("Indexer master not compatible with this master "
				"(mixed old and new binaries?)");
			master_service_stop(master_service);
			return;
		}
		conn->version_received = TRUE;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = master_connection_input_line(conn, line);
		} T_END;
		if (ret < 0) {
			master_service_stop(master_service);
			break;
		}
	}
}

struct master_connection *
master_connection_create(int fd, struct mail_storage_service_ctx *storage_service)
{
	struct master_connection *conn;
	const char *handshake;

	conn = i_new(struct master_connection, 1);
	conn->storage_service = storage_service;
	conn->fd = fd;
	conn->io = io_add(conn->fd, IO_READ, master_connection_input, conn);
	conn->input = i_stream_create_fd(conn->fd, (size_t)-1, FALSE);

	handshake = t_strdup_printf(INDEXER_WORKER_HANDSHAKE,
		master_service_get_process_limit(master_service));
	(void)write_full(conn->fd, handshake, strlen(handshake));
	return conn;
}

void master_connection_destroy(struct master_connection **_conn)
{
	struct master_connection *conn = *_conn;

	*_conn = NULL;

	io_remove(&conn->io);
	i_stream_destroy(&conn->input);

	if (close(conn->fd) < 0)
		i_error("close(master conn) failed: %m");
	i_free(conn);

	master_service_client_connection_destroyed(master_service);
}
