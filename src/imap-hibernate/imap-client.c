/* Copyright (c) 2014-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "fd-set-nonblock.h"
#include "fdpass.h"
#include "hostpid.h"
#include "connection.h"
#include "iostream.h"
#include "istream.h"
#include "ostream.h"
#include "llist.h"
#include "priorityq.h"
#include "base64.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "imap-keepalive.h"
#include "imap-master-connection.h"
#include "imap-client.h"

#include <unistd.h>

#define IMAP_MASTER_SOCKET_NAME "imap-master"

/* we only need enough for "DONE\r\nIDLE\r\n" */
#define IMAP_MAX_INBUF 12

/* If client has sent input and we can't recreate imap process in this
   many seconds, disconnect the client. */
#define IMAP_CLIENT_MOVE_BACK_WITH_INPUT_TIMEOUT_SECS 10
/* If there's a change notification and we can't recreate imap process in this
   many seconds, disconnect the client. */
#define IMAP_CLIENT_MOVE_BACK_WITHOUT_INPUT_TIMEOUT_SECS (60*5)

/* How often to try to unhibernate clients. */
#define IMAP_UNHIBERNATE_RETRY_MSECS 10

enum imap_client_input_state {
	IMAP_CLIENT_INPUT_STATE_UNKNOWN,
	IMAP_CLIENT_INPUT_STATE_BAD,
	IMAP_CLIENT_INPUT_STATE_DONE_LF,
	IMAP_CLIENT_INPUT_STATE_DONE_CRLF,
	IMAP_CLIENT_INPUT_STATE_DONEIDLE
};

struct imap_client_notify {
	int fd;
	struct io *io;
};

struct imap_client {
	struct priorityq_item item;

	struct imap_client *prev, *next;
	pool_t pool;
	struct imap_client_state state;
	ARRAY(struct imap_client_notify) notifys;

	time_t move_back_start;
	struct timeout *to_move_back;

	int fd;
	struct io *io;
	struct istream *input;
	struct timeout *to_keepalive;
	struct imap_master_connection *master_conn;
	struct ioloop_context *ioloop_ctx;
	const char *log_prefix;
	unsigned int imap_still_here_text_pos;
	unsigned int next_read_threshold;
	bool bad_done, idle_done;
	bool unhibernate_queued;
	bool input_pending;
};

static struct imap_client *imap_clients;
static struct priorityq *unhibernate_queue;
static struct timeout *to_unhibernate;
static const char imap_still_here_text[] = "* OK Still here\r\n";

static void imap_client_stop(struct imap_client *client);
void imap_client_destroy(struct imap_client **_client, const char *reason);
static void imap_client_add_idle_keepalive_timeout(struct imap_client *client);
static void imap_clients_unhibernate(void *context);

static void imap_client_disconnected(struct imap_client **_client)
{
	struct imap_client *client = *_client;
	const char *reason;

	reason = io_stream_get_disconnect_reason(client->input, NULL);
	imap_client_destroy(_client, reason);
}

static void
imap_client_parse_userdb_fields(struct imap_client *client,
				const char **auth_user_r)
{
	const char *const *field;
	unsigned int i;

	*auth_user_r = NULL;

	if (client->state.userdb_fields == NULL)
		return;

	field = t_strsplit_tabescaped(client->state.userdb_fields);
	for (i = 0; field[i] != NULL; i++) {
		if (strncmp(field[i], "auth_user=", 10) == 0)
			*auth_user_r = field[i] + 10;
	}
}

static void
imap_client_move_back_send_callback(void *context, struct ostream *output)
{
	struct imap_client *client = context;
	const struct imap_client_state *state = &client->state;
	string_t *str = t_str_new(256);
	const unsigned char *input_data;
	size_t input_size;
	ssize_t ret;

	str_append_tabescaped(str, state->username);
	if (state->session_id != NULL) {
		str_append(str, "\tsession=");
		str_append_tabescaped(str, state->session_id);
	}
	if (state->local_ip.family != 0)
		str_printfa(str, "\tlip=%s", net_ip2addr(&state->local_ip));
	if (state->remote_ip.family != 0)
		str_printfa(str, "\trip=%s", net_ip2addr(&state->remote_ip));
	if (state->userdb_fields != NULL) {
		str_append(str, "\tuserdb_fields=");
		str_append_tabescaped(str, state->userdb_fields);
	}
	if (major(state->peer_dev) != 0 || minor(state->peer_dev) != 0) {
		str_printfa(str, "\tpeer_dev_major=%lu\tpeer_dev_minor=%lu",
			    (unsigned long)major(state->peer_dev),
			    (unsigned long)minor(state->peer_dev));
	}
	if (state->peer_ino != 0)
		str_printfa(str, "\tpeer_ino=%llu", (unsigned long long)state->peer_ino);
	if (state->state_size > 0) {
		str_append(str, "\tstate=");
		base64_encode(state->state, state->state_size, str);
	}
	input_data = i_stream_get_data(client->input, &input_size);
	if (input_size > 0) {
		str_append(str, "\tclient_input=");
		base64_encode(input_data, input_size, str);
	}
	if (client->imap_still_here_text_pos != 0) {
		str_append(str, "\tclient_output=");
		base64_encode(imap_still_here_text + client->imap_still_here_text_pos,
			      sizeof(imap_still_here_text)-1 - client->imap_still_here_text_pos,
			      str);
	}
	if (client->idle_done) {
		if (client->bad_done)
			str_append(str, "\tbad-done");
	} else if (client->state.idle_cmd) {
		/* IDLE continues after sending changes */
		str_append(str, "\tidle-continue");
	}
	str_append_c(str, '\n');

	/* send the fd first */
	ret = fd_send(o_stream_get_fd(output), client->fd, str_data(str), 1);
	if (ret < 0) {
		i_error("fd_send(%s) failed: %m",
			o_stream_get_name(output));
		imap_client_destroy(&client, "Failed to recreate imap process");
		return;
	}
	i_assert(ret > 0);
	o_stream_nsend(output, str_data(str) + 1, str_len(str) - 1);
}

static void
imap_client_move_back_read_callback(void *context, const char *line)
{
	struct imap_client *client = context;

	if (line[0] != '+') {
		/* failed - FIXME: retry later? */
		imap_client_destroy(&client, t_strdup_printf(
			"Failed to recreate imap process: %s", line+1));
	} else {
		imap_client_destroy(&client, NULL);
	}
}

static bool imap_client_try_move_back(struct imap_client *client)
{
	const struct master_service_settings *master_set;
	const char *path, *error;
	int ret;

	master_set = master_service_settings_get(master_service);
	path = t_strconcat(master_set->base_dir,
			   "/"IMAP_MASTER_SOCKET_NAME, NULL);
	ret = imap_master_connection_init(path,
					  imap_client_move_back_send_callback,
					  imap_client_move_back_read_callback,
					  client, &client->master_conn, &error);
	if (ret > 0) {
		/* success */
		imap_client_stop(client);
		return TRUE;
	} else if (ret < 0) {
		/* failed to connect to the imap-master socket */
		imap_client_destroy(&client, error);
		return TRUE;
	}

	int max_secs = client->input_pending ?
		IMAP_CLIENT_MOVE_BACK_WITH_INPUT_TIMEOUT_SECS :
		IMAP_CLIENT_MOVE_BACK_WITHOUT_INPUT_TIMEOUT_SECS;
	if (ioloop_time - client->move_back_start > max_secs) {
		/* we've waited long enough */
		imap_client_destroy(&client, error);
		return TRUE;
	}
	return FALSE;
}

static void imap_client_move_back(struct imap_client *client)
{
	if (imap_client_try_move_back(client))
		return;

	/* imap-master socket is busy. retry in a while. */
	if (client->move_back_start == 0)
		client->move_back_start = ioloop_time;
	client->unhibernate_queued = TRUE;
	priorityq_add(unhibernate_queue, &client->item);
	if (to_unhibernate == NULL) {
		to_unhibernate = timeout_add_short(IMAP_UNHIBERNATE_RETRY_MSECS,
						   imap_clients_unhibernate, NULL);
	}
}

static enum imap_client_input_state
imap_client_input_parse(const unsigned char *data, size_t size)
{
	enum imap_client_input_state state = IMAP_CLIENT_INPUT_STATE_DONE_LF;

	/* skip over DONE[\r]\n */
	if (i_memcasecmp(data, "DONE", I_MIN(size, 4)) != 0)
		return IMAP_CLIENT_INPUT_STATE_BAD;
	if (size <= 4)
		return IMAP_CLIENT_INPUT_STATE_UNKNOWN;
	data += 4; size -= 4;

	if (data[0] == '\r') {
		state = IMAP_CLIENT_INPUT_STATE_DONE_CRLF;
		data++; size--;
	}
	if (size == 0)
		return IMAP_CLIENT_INPUT_STATE_UNKNOWN;
	if (data[0] != '\n')
		return IMAP_CLIENT_INPUT_STATE_BAD;
	data++; size--;

	/* skip over IDLE[\r]\n - checking this assumes that the DONE and IDLE
	   are sent in the same IP packet, otherwise we'll unnecessarily
	   recreate the imap process and immediately resume IDLE there. if this
	   becomes an issue we could add a small delay to the imap process
	   creation and wait for the IDLE command during it. */
	if (size <= 4 || i_memcasecmp(data, "IDLE", 4) != 0)
		return state;
	data += 4; size -= 4;

	if (data[0] == '\r') {
		data++; size--;
	}
	return size == 1 && data[0] == '\n' ?
		IMAP_CLIENT_INPUT_STATE_DONEIDLE : state;
}

static void imap_client_input_idle_cmd(struct imap_client *client)
{
	const unsigned char *data;
	size_t size;
	int ret;

	/* we should read either DONE or disconnection. also handle if client
	   sends DONE\nIDLE simply to recreate the IDLE. */
	ret = i_stream_read_data(client->input, &data, &size,
				 client->next_read_threshold);
	if (size == 0) {
		if (ret < 0)
			imap_client_disconnected(&client);
		return;
	}
	client->next_read_threshold = 0;
	switch (imap_client_input_parse(data, size)) {
	case IMAP_CLIENT_INPUT_STATE_UNKNOWN:
		/* we haven't received a full DONE[\r]\n yet - wait */
		client->next_read_threshold = size;
		return;
	case IMAP_CLIENT_INPUT_STATE_BAD:
		/* invalid input - return this to the imap process */
		client->bad_done = TRUE;
		break;
	case IMAP_CLIENT_INPUT_STATE_DONE_LF:
		i_stream_skip(client->input, 4+1);
		break;
	case IMAP_CLIENT_INPUT_STATE_DONE_CRLF:
		i_stream_skip(client->input, 4+2);
		break;
	case IMAP_CLIENT_INPUT_STATE_DONEIDLE:
		/* we received DONE+IDLE, so the client simply wanted to notify
		   us that it's still there. continue hibernation. */
		i_stream_skip(client->input, size);
		return;
	}
	client->idle_done = TRUE;
	client->input_pending = TRUE;
	imap_client_move_back(client);
}

static void imap_client_input_nonidle(struct imap_client *client)
{
	if (i_stream_read(client->input) < 0)
		imap_client_disconnected(&client);
	else {
		client->input_pending = TRUE;
		imap_client_move_back(client);
	}
}

static void imap_client_input_notify(struct imap_client *client)
{
	imap_client_move_back(client);
}

static void keepalive_timeout(struct imap_client *client)
{
	unsigned int text_left = sizeof(imap_still_here_text)-1 -
		client->imap_still_here_text_pos;
	ssize_t ret;

	ret = write(client->fd,
		    imap_still_here_text + client->imap_still_here_text_pos,
		    text_left);
	if (ret < 0) {
		/* disconnect */
		const char *reason = errno == EPIPE ? "Connection closed" :
			t_strdup_printf("Connection closed: %m");
		imap_client_destroy(&client, reason);
		return;
	}
	client->imap_still_here_text_pos += ret;
	if (client->imap_still_here_text_pos >= sizeof(imap_still_here_text)-1)
		client->imap_still_here_text_pos = 0;
	else {
		/* we didn't write the entire line, but that's ok. we could
		   io_add(IO_WRITE) here, but that's probably not necessary.
		   just continue writing the "still here" line after the next
		   timeout. its main purpose is to see if the connection is
		   still alive, and we're successfully doing that already.
		   besides, it's highly unlikely we'll ever even get here.. */
	}
	imap_client_add_idle_keepalive_timeout(client);
}

static void imap_client_add_idle_keepalive_timeout(struct imap_client *client)
{
	unsigned int interval = client->state.imap_idle_notify_interval;

	if (interval == 0)
		return;

	interval = imap_keepalive_interval_msecs(client->state.username,
						 &client->state.remote_ip,
						 interval);

	if (client->to_keepalive!= NULL)
		timeout_remove(&client->to_keepalive);
	client->to_keepalive = timeout_add(interval, keepalive_timeout, client);
}

static const struct var_expand_table *
imap_client_get_var_expand_table(struct imap_client *client)
{
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL, "user" },
		{ 'n', NULL, "username" },
		{ 'd', NULL, "domain" },
		{ 's', NULL, "service" },
		{ 'h', NULL, "home" },
		{ 'l', NULL, "lip" },
		{ 'r', NULL, "rip" },
		{ 'p', NULL, "pid" },
		{ 'i', NULL, "uid" },
		{ '\0', NULL, "gid" },
		{ '\0', NULL, "session" },
		{ '\0', NULL, "auth_user" },
		{ '\0', NULL, "auth_username" },
		{ '\0', NULL, "auth_domain" },
		/* NOTE: keep this synced with lib-storage's
		   mail_user_var_expand_table() */
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;
	const char *auth_user;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = client->state.username;
	tab[1].value = t_strcut(client->state.username, '@');
	tab[2].value = strchr(client->state.username, '@');
	if (tab[2].value != NULL) tab[2].value++;
	tab[3].value = "imap-hibernate";
	tab[4].value = NULL; /* we shouldn't need this */
	tab[5].value = client->state.local_ip.family == 0 ? NULL :
		net_ip2addr(&client->state.local_ip);
	tab[6].value = client->state.remote_ip.family == 0 ? NULL :
		net_ip2addr(&client->state.remote_ip);
	tab[7].value = my_pid;
	tab[8].value = dec2str(client->state.uid);
	tab[9].value = dec2str(client->state.gid);
	tab[10].value = client->state.session_id;

	imap_client_parse_userdb_fields(client, &auth_user);
	if (auth_user == NULL) {
		tab[11].value = tab[0].value;
		tab[12].value = tab[1].value;
		tab[13].value = tab[2].value;
	} else {
		tab[11].value = auth_user;
		tab[12].value = t_strcut(auth_user, '@');
		tab[13].value = strchr(auth_user, '@');
	}
	return tab;
}

static void imap_client_io_activate_user(struct imap_client *client)
{
	i_set_failure_prefix("%s", client->log_prefix);
}

static void imap_client_io_deactivate_user(struct imap_client *client ATTR_UNUSED)
{
	i_set_failure_prefix("imap-hibernate: ");
}

static const char *imap_client_get_anvil_userip_ident(struct imap_client_state *state)
{
	if (state->remote_ip.family == 0)
		return NULL;
	return t_strconcat(net_ip2addr(&state->remote_ip), "/",
			   str_tabescape(state->username), NULL);
}

struct imap_client *
imap_client_create(int fd, const struct imap_client_state *state)
{
	struct imap_client *client;
	pool_t pool = pool_alloconly_create("imap client", 256);
	void *statebuf;
	const char *ident;

	i_assert(state->username != NULL);
	i_assert(state->mail_log_prefix != NULL);

	fd_set_nonblock(fd, TRUE); /* it should already be, but be sure */

	client = p_new(pool, struct imap_client, 1);
	client->pool = pool;
	client->fd = fd;
	client->input = i_stream_create_fd(fd, IMAP_MAX_INBUF, FALSE);

	client->state = *state;
	client->state.username = p_strdup(pool, state->username);
	client->state.session_id = p_strdup(pool, state->session_id);
	client->state.userdb_fields = p_strdup(pool, state->userdb_fields);
	client->state.stats = p_strdup(pool, state->stats);

	if (state->state_size > 0) {
		client->state.state = statebuf = p_malloc(pool, state->state_size);
		memcpy(statebuf, state->state, state->state_size);
		client->state.state_size = state->state_size;
	}
	T_BEGIN {
		string_t *str;

		str = t_str_new(256);
		var_expand(str, state->mail_log_prefix,
			   imap_client_get_var_expand_table(client));
		client->log_prefix = p_strdup(pool, str_c(str));
	} T_END;

	ident = imap_client_get_anvil_userip_ident(&client->state);
	if (ident != NULL) {
		master_service_anvil_send(master_service, t_strconcat(
			"CONNECT\t", my_pid, "\timap/", ident, "\n", NULL));
		client->state.anvil_sent = TRUE;
	}

	p_array_init(&client->notifys, pool, 2);
	DLLIST_PREPEND(&imap_clients, client);
	return client;
}

static void imap_client_stop(struct imap_client *client)
{
	struct imap_client_notify *notify;

	if (client->unhibernate_queued)
		priorityq_remove(unhibernate_queue, &client->item);
	if (client->io != NULL)
		io_remove(&client->io);
	if (client->to_keepalive != NULL)
		timeout_remove(&client->to_keepalive);

	array_foreach_modifiable(&client->notifys, notify) {
		if (notify->io != NULL)
			io_remove(&notify->io);
		if (notify->fd != -1)
			i_close_fd(&notify->fd);
	}
}

void imap_client_destroy(struct imap_client **_client, const char *reason)
{
	struct imap_client *client = *_client;

	*_client = NULL;

	if (reason != NULL) {
		/* the client input/output bytes don't count the DONE+IDLE by
		   imap-hibernate, but that shouldn't matter much. */
		i_info("%s %s", reason, client->state.stats);
	}

	if (client->state.anvil_sent) {
		master_service_anvil_send(master_service, t_strconcat(
			"DISCONNECT\t", my_pid, "\timap/",
			imap_client_get_anvil_userip_ident(&client->state),
			"\n", NULL));
	}

	if (client->ioloop_ctx != NULL) {
		io_loop_context_remove_callbacks(client->ioloop_ctx,
						 imap_client_io_activate_user,
						 imap_client_io_deactivate_user, client);
		imap_client_io_deactivate_user(client);
		io_loop_context_unref(&client->ioloop_ctx);
	}

	DLLIST_REMOVE(&imap_clients, client);
	imap_client_stop(client);
	i_stream_destroy(&client->input);
	i_close_fd(&client->fd);
	pool_unref(&client->pool);

	master_service_client_connection_destroyed(master_service);
}

void imap_client_add_notify_fd(struct imap_client *client, int fd)
{
	struct imap_client_notify *notify;

	notify = array_append_space(&client->notifys);
	notify->fd = fd;
}

void imap_client_create_finish(struct imap_client *client)
{
	struct imap_client_notify *notify;

	client->ioloop_ctx = io_loop_context_new(current_ioloop);
	io_loop_context_add_callbacks(client->ioloop_ctx,
				      imap_client_io_activate_user,
				      imap_client_io_deactivate_user, client);
	imap_client_io_activate_user(client);

	if (client->state.idle_cmd) {
		client->io = io_add(client->fd, IO_READ,
				    imap_client_input_idle_cmd, client);
	} else {
		client->io = io_add(client->fd, IO_READ,
				    imap_client_input_nonidle, client);
	}
	imap_client_add_idle_keepalive_timeout(client);

	array_foreach_modifiable(&client->notifys, notify) {
		notify->io = io_add(notify->fd, IO_READ,
				    imap_client_input_notify, client);
	}
}

static int client_unhibernate_cmp(const void *p1, const void *p2)
{
	const struct imap_client *c1 = p1, *c2 = p2;
	time_t t1, t2;

	t1 = c1->move_back_start +
		(c1->input_pending ?
		 IMAP_CLIENT_MOVE_BACK_WITH_INPUT_TIMEOUT_SECS :
		 IMAP_CLIENT_MOVE_BACK_WITHOUT_INPUT_TIMEOUT_SECS);
	t2 = c2->move_back_start +
		(c1->input_pending ?
		 IMAP_CLIENT_MOVE_BACK_WITH_INPUT_TIMEOUT_SECS :
		 IMAP_CLIENT_MOVE_BACK_WITHOUT_INPUT_TIMEOUT_SECS);
	if (t1 < t2)
		return -1;
	if (t1 > t2)
		return 1;
	return 0;
}

static void imap_clients_unhibernate(void *context ATTR_UNUSED)
{
	struct priorityq_item *item;

	while ((item = priorityq_pop(unhibernate_queue)) != NULL) {
		struct imap_client *client = (struct imap_client *)item;

		if (!imap_client_try_move_back(client))
			return;
	}
	timeout_remove(&to_unhibernate);
}

void imap_clients_init(void)
{
	unhibernate_queue = priorityq_init(client_unhibernate_cmp, 64);
}

void imap_clients_deinit(void)
{
	while (imap_clients != NULL) {
		struct imap_client *client = imap_clients;

		imap_client_io_activate_user(client);
		imap_client_destroy(&client, "Shutting down");
	}
	if (to_unhibernate != NULL)
		timeout_remove(&to_unhibernate);
	priorityq_deinit(&unhibernate_queue);
}
