/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "connection.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "strescape.h"
#include "hostpid.h"
#include "process-title.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mail-storage-service.h"
#include "mail-search-build.h"
#include "master-connection.h"

#include <unistd.h>

#define INDEXER_PROTOCOL_MAJOR_VERSION 1
#define INDEXER_PROTOCOL_MINOR_VERSION 0

#define INDEXER_MASTER_NAME "indexer-master-worker"
#define INDEXER_WORKER_NAME "indexer-worker-master"

static struct event_category event_category_indexer_worker = {
	.name = "indexer-worker",
};

struct master_connection {
	struct connection conn;
	struct mail_storage_service_ctx *storage_service;

	bool version_received:1;
};

static void ATTR_NULL(1, 2)
indexer_worker_refresh_proctitle(const char *username, const char *mailbox,
				 uint32_t seq1, uint32_t seq2)
{
	if (!master_service_settings_get(master_service)->verbose_proctitle)
		return;

	if (username == NULL)
		process_title_set("[idling]");
	else if (seq1 == 0)
		process_title_set(t_strdup_printf("[%s %s]", username, mailbox));
	else {
		process_title_set(t_strdup_printf("[%s %s - %u/%u]",
						  username, mailbox, seq1, seq2));
	}
}

static const char *
get_attempt_error(unsigned int counter, uint32_t first_uid, uint32_t last_uid)
{
	if (counter == 0)
		return " (no mails indexed)";
	return t_strdup_printf(
		" (attempted to index %u messages between UIDs %u..%u)",
		counter, first_uid, last_uid);
}

static int
index_mailbox_precache(struct master_connection *conn, struct mailbox *box)
{
	struct mail_storage *storage = mailbox_get_storage(box);
	const char *username = mail_storage_get_user(storage)->username;
	const char *box_vname = mailbox_get_vname(box);
	const char *errstr;
	enum mail_error error;
	struct mailbox_status status;
	struct mailbox_transaction_context *trans;
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct mailbox_metadata metadata;
	uint32_t seq, first_uid = 0, last_uid = 0;
	char percentage_str[2+1+1];
	unsigned int counter = 0, max, percentage, percentage_sent = 0;
	int ret = 0;
	struct event *index_event = event_create(box->event);
	event_add_category(index_event, &event_category_indexer_worker);

	if (mailbox_get_metadata(box, MAILBOX_METADATA_PRECACHE_FIELDS,
				 &metadata) < 0) {
		e_error(index_event, "Precache-fields lookup failed: %s",
			mailbox_get_last_internal_error(box, NULL));
		event_unref(&index_event);
		return -1;
	}
	if (mailbox_get_status(box, STATUS_MESSAGES | STATUS_LAST_CACHED_SEQ,
			       &status) < 0) {
		e_error(index_event, "Status lookup failed: %s",
			mailbox_get_last_internal_error(box, NULL));
		event_unref(&index_event);
		return -1;
	}
	seq = status.last_cached_seq + 1;

	trans = mailbox_transaction_begin(box, MAILBOX_TRANSACTION_FLAG_NO_CACHE_DEC,
					  "indexing");
	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, seq, status.messages);

	event_enable_user_cpu_usecs(index_event);

	ctx = mailbox_search_init(trans, search_args, NULL,
				  metadata.precache_fields, NULL);
	mail_search_args_unref(&search_args);

	max = status.messages + 1 - seq;
	while (mailbox_search_next(ctx, &mail)) {
		if (first_uid == 0)
			first_uid = mail->uid;
		last_uid = mail->uid;
		e_debug(index_event, "Indexing UID=%u", mail->uid);

		if (mail_precache(mail) < 0) {
			e_error(index_event, "Precache for UID=%u failed: %s%s",
				mail->uid,
				mail_get_last_internal_error(mail, NULL),
				get_attempt_error(counter, first_uid, last_uid));
			ret = -1;
			break;
		}
		if (++counter % 100 == 0) {
			percentage = counter*100 / max;
			if (percentage != percentage_sent && percentage < 100) {
				percentage_sent = percentage;
				if (i_snprintf(percentage_str,
					       sizeof(percentage_str), "%u\n",
					       percentage) < 0)
					i_unreached();
				o_stream_nsend_str(conn->conn.output,
						   percentage_str);
			}
			indexer_worker_refresh_proctitle(username, box_vname,
							 counter, max);
		}
	}
	if (mailbox_search_deinit(&ctx) < 0) {
		enum mail_error error;
		const char *errstr = mailbox_get_last_internal_error(box, &error);

		if (error == MAIL_ERROR_INTERRUPTED) {
			e_info(index_event, "Mail search interrupted: %s%s", errstr,
			       get_attempt_error(counter, first_uid, last_uid));
		} else {
			e_error(index_event, "Mail search failed: %s%s", errstr,
				get_attempt_error(counter, first_uid, last_uid));
		}
		ret = -1;
	}
	const char *uids = first_uid == 0 ? "" :
		t_strdup_printf(" (UIDs %u..%u)", first_uid, last_uid);
	event_add_int(index_event, "message_count", counter);
	event_add_int(index_event, "first_uid", first_uid);
	event_add_int(index_event, "last_uid", last_uid);

#define FINISHED_EVENT_NAME "indexer_worker_indexing_finished"
	if (mailbox_transaction_commit(&trans) < 0) {
		struct event_passthrough *e = event_create_passthrough(index_event)->
			set_name(FINISHED_EVENT_NAME);
		errstr = t_strdup_printf("Transaction commit failed: %s",
					 mailbox_get_last_internal_error(box, &error));
		e->add_str("error", errstr);
		const char *log_error = t_strdup_printf("%s (attempted to index %u messages%s)",
							errstr, counter, uids);
		if (error != MAIL_ERROR_NOTFOUND)
			e_error(e->event(), "%s", log_error);
		else
			e_debug(e->event(), "%s", log_error);
		ret = -1;
	} else {
		struct event_passthrough *e = event_create_passthrough(index_event)->
			set_name(FINISHED_EVENT_NAME);
		e_debug(e->event(), "Indexed %u messages%s", counter, uids);
	}
	event_unref(&index_event);
	return ret;
}

static int
index_mailbox(struct master_connection *conn, struct mail_user *user,
	      const char *mailbox, unsigned int max_recent_msgs,
	      const char *what)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mailbox_status status;
	const char *path, *errstr;
	enum mail_error error;
	enum mailbox_sync_flags sync_flags = MAILBOX_SYNC_FLAG_FULL_READ;
	int ret;

	ns = mail_namespace_find(user->namespaces, mailbox);
	box = mailbox_alloc(ns->list, mailbox, 0);
	ret = mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX, &path);
	if (ret < 0) {
		errstr = mailbox_get_last_internal_error(box, &error);
		if (error != MAIL_ERROR_NOTFOUND)
			e_error(box->event, "Getting path failed: %s", errstr);
		mailbox_free(&box);
		return -1;
	}
	if (ret == 0) {
		e_info(box->event, "Indexes disabled, skipping");
		mailbox_free(&box);
		return 0;
	}
	ret = 0;

	if (max_recent_msgs != 0) {
		/* index only if there aren't too many recent messages.
		   don't bother syncing the mailbox, that alone can take a
		   while with large maildirs. */
		if (mailbox_open(box) < 0) {
			errstr = mailbox_get_last_internal_error(box, &error);
			if (error != MAIL_ERROR_NOTFOUND)
				e_error(box->event, "Opening failed: %s",
					errstr);
			ret = -1;
		} else {
			mailbox_get_open_status(box, STATUS_RECENT, &status);
		}
		if (ret < 0 || status.recent > max_recent_msgs) {
			mailbox_free(&box);
			return ret;
		}
	}

	if (strchr(what, 'o') != NULL)
		sync_flags |= MAILBOX_SYNC_FLAG_OPTIMIZE;

	if (mailbox_sync(box, sync_flags) < 0) {
		errstr = mailbox_get_last_internal_error(box, &error);
		if (error != MAIL_ERROR_NOTFOUND) {
			e_error(box->event, "Syncing failed: %s", errstr);
		} else {
			e_debug(box->event, "Syncing failed: %s", errstr);
		}
		ret = -1;
	} else if (strchr(what, 'i') != NULL) {
		if (index_mailbox_precache(conn, box) < 0)
			ret = -1;
	}
	mailbox_free(&box);
	return ret;
}

static int
master_connection_cmd_index(struct master_connection *conn,
			    const char *username, const char *mailbox,
			    const char *session_id,
			    unsigned int max_recent_msgs, const char *what)
{
	struct mail_storage_service_input input;
	struct mail_user *user;
	const char *error;
	int ret;

	i_zero(&input);
	input.service = "indexer-worker";
	input.username = username;
	/* if session-id is given, use it as a prefix to a unique session ID.
	   we can't use the session-id directly or stats process will complain
	   about duplicates. (especially LMTP would use the same session-id for
	   multiple users' indexing at the same time.) */
	if (session_id[0] != '\0')
		input.session_id_prefix = session_id;

	if (mail_storage_service_lookup_next(conn->storage_service, &input,
					     &user, &error) <= 0) {
		e_error(conn->conn.event, "User %s lookup failed: %s",
			username, error);
		return -1;
	}

	struct master_service_anvil_session anvil_session;
	guid_128_t anvil_conn_guid;
	bool anvil_sent = FALSE;
	mail_user_get_anvil_session(user, &anvil_session);
	if (master_service_anvil_connect(master_service, &anvil_session,
					 TRUE, anvil_conn_guid))
		anvil_sent = TRUE;

	indexer_worker_refresh_proctitle(user->username, mailbox, 0, 0);
	struct event_reason *reason =
		event_reason_begin("indexer:index_mailbox");
	ret = index_mailbox(conn, user, mailbox, max_recent_msgs, what);
	event_reason_end(&reason);
	/* refresh proctitle before a potentially long-running
	   user unref */
	indexer_worker_refresh_proctitle(user->username, "(deinit)", 0, 0);

	if (anvil_sent) {
		master_service_anvil_disconnect(master_service, &anvil_session,
						anvil_conn_guid);
	}

	mail_user_deinit(&user);
	indexer_worker_refresh_proctitle(NULL, NULL, 0, 0);
	return ret;
}

static int
master_connection_input_args(struct connection *_conn, const char *const *args)
{
	struct master_connection *conn =
		container_of(_conn, struct master_connection, conn);
	const char *str;
	unsigned int max_recent_msgs;
	int ret;

	/* <username> <mailbox> <session ID> <max_recent_msgs> [i][o] */
	if (str_array_length(args) != 5 ||
	    str_to_uint(args[3], &max_recent_msgs) < 0 || args[4][0] == '\0') {
		e_error(conn->conn.event, "Invalid input from master: %s",
			t_strarray_join(args, "\t"));
		return -1;
	}
	const char *username = args[0];
	const char *mailbox = args[1];
	const char *session_id = args[2];
	const char *what = args[4];

	ret = master_connection_cmd_index(conn, username, mailbox, session_id,
					  max_recent_msgs, what);

	str = ret < 0 ? "-1\n" : "100\n";
	o_stream_nsend_str(conn->conn.output, str);
	return ret;
}

static void master_connection_destroy(struct connection *connection)
{
	connection_deinit(connection);
	i_free(connection);
	master_service_client_connection_destroyed(master_service);
}

static int master_connection_handshake_args(struct connection *connection,
					    const char *const *args)
{
	int ret;
	if ((ret = connection_handshake_args_default(connection, args)) < 1)
		return ret;
	const char *limit = t_strdup_printf("%u\t%s\n",
		master_service_get_process_limit(master_service), my_pid);
	o_stream_nsend_str(connection->output, limit);
	return 1;
}

static struct connection_list *master_connection_list = NULL;

static const struct connection_vfuncs master_connection_vfuncs = {
	.destroy = master_connection_destroy,
	.input_args = master_connection_input_args,
	.handshake_args = master_connection_handshake_args,
};

static const struct connection_settings master_connection_set = {
	.service_name_in = INDEXER_MASTER_NAME,
	.service_name_out = INDEXER_WORKER_NAME,
	.major_version = INDEXER_PROTOCOL_MAJOR_VERSION,
	.minor_version = INDEXER_PROTOCOL_MINOR_VERSION,
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
};

bool
master_connection_create(struct master_service_connection *master,
			 struct mail_storage_service_ctx *storage_service)
{
	struct master_connection *conn;

	if (master_connection_list == NULL) {
		master_connection_list =
			connection_list_init(&master_connection_set,
					     &master_connection_vfuncs);
	} else if (master_connection_list->connections_count > 0) {
		return FALSE;
	}

	conn = i_new(struct master_connection, 1);
	conn->storage_service = storage_service;
	conn->conn.event_parent = event_create(NULL);
	event_add_category(conn->conn.event_parent, &event_category_indexer_worker);
	connection_init_server(master_connection_list, &conn->conn,
			       master->name, master->fd, master->fd);

	event_unref(&conn->conn.event_parent);
	return TRUE;
}

void master_connections_destroy(void)
{
	if (master_connection_list != NULL)
		connection_list_deinit(&master_connection_list);
}
