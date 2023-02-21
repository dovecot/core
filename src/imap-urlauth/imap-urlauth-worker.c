/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "net.h"
#include "fdpass.h"
#include "istream.h"
#include "istream-unix.h"
#include "ostream.h"
#include "str.h"
#include "str-sanitize.h"
#include "strescape.h"
#include "llist.h"
#include "hostpid.h"
#include "var-expand.h"
#include "process-title.h"
#include "randgen.h"
#include "restrict-access.h"
#include "settings-parser.h"
#include "connection.h"
#include "master-service.h"
#include "master-interface.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "mail-namespace.h"
#include "imap-url.h"
#include "imap-msgpart-url.h"
#include "imap-urlauth.h"
#include "imap-urlauth-fetch.h"
#include "imap-urlauth-worker-common.h"
#include "imap-urlauth-worker-settings.h"

#include <unistd.h>
#include <sysexits.h>

/* max. length of input lines (URLs) */
#define MAX_INBUF_SIZE 2048

/* Disconnect client after idling this many milliseconds */
#define CLIENT_IDLE_TIMEOUT_MSECS (10*60*1000)

#define IS_STANDALONE() \
        (getenv(MASTER_IS_PARENT_ENV) == NULL)

struct client {
	struct connection conn;
	struct connection conn_ctrl;

	struct client *prev, *next;
	struct event *event;

	struct timeout *to_idle;

	char *access_user, *access_service;
	ARRAY_TYPE(string) access_apps;

	struct mail_user *mail_user;

	struct imap_urlauth_context *urlauth_ctx;

	struct imap_msgpart_url *url;
	struct istream *msg_part_input;
	uoff_t msg_part_size;

	/* settings: */
	const struct imap_urlauth_worker_settings *set;
	const struct mail_storage_settings *mail_set;

	bool finished:1;
	bool waiting_input:1;
	bool access_received:1;
	bool access_anonymous:1;
};

static bool verbose_proctitle = FALSE;
static struct mail_storage_service_ctx *storage_service;

static struct connection_list *clist;
static struct connection_list *clist_ctrl;

static void client_destroy(struct client *client);
static void client_abort(struct client *client, const char *reason);
static int client_run_url(struct client *client);
static bool client_handle_input(struct client *client);
static int client_output(struct client *client);

static void imap_urlauth_worker_refresh_proctitle(void)
{
	struct client *client;
	string_t *title;

	if (!verbose_proctitle)
		return;

	title = t_str_new(128);
	str_append_c(title, '[');
	switch (clist_ctrl->connections_count) {
	case 0:
		str_append(title, "idling");
		break;
	case 1:
		client = container_of(clist->connections, struct client, conn);
		if (client->mail_user == NULL)
			str_append(title, client->access_user);
		else {
			str_append(title, client->access_user);
			str_append(title, "->");
			str_append(title, client->mail_user->username);
		}
		break;
	default:
		str_printfa(title, "%u connections",
			    clist_ctrl->connections_count);
		break;
	}
	str_append_c(title, ']');
	process_title_set(str_c(title));
}

static void client_idle_timeout(struct client *client)
{
	if (client->url != NULL) {
		client_abort(client,
			"Session closed for inactivity in reading our output");
	} else {
		client_destroy(client);
	}
}

static struct client *client_create(int fd)
{
	struct client *client;

	/* always use nonblocking I/O */
	net_set_nonblock(fd, TRUE);

	client = i_new(struct client, 1);
	i_array_init(&client->access_apps, 16);
	client->access_anonymous = TRUE; /* default until overridden */

	client->event = event_create(NULL);

	client->conn_ctrl.event_parent = client->event;
	client->conn_ctrl.unix_socket = TRUE;
	connection_init_server(clist_ctrl, &client->conn_ctrl, NULL, fd, fd);
	i_stream_unix_set_read_fd(client->conn_ctrl.input);

	client->conn.event_parent = client->event;
	connection_init(clist, &client->conn, NULL);

	client->to_idle = timeout_add(CLIENT_IDLE_TIMEOUT_MSECS,
				      client_idle_timeout, client);

	imap_urlauth_worker_refresh_proctitle();
	return client;
}

static struct client *
client_create_standalone(const char *access_user,
			 const char *const *access_applications,
			 int fd_in, int fd_out, bool debug)
{
	struct client *client;

	/* always use nonblocking I/O */
	net_set_nonblock(fd_in, TRUE);
	net_set_nonblock(fd_out, TRUE);

	client = i_new(struct client, 1);
	i_array_init(&client->access_apps, 16);

	if (access_user != NULL && *access_user != '\0')
		client->access_user = i_strdup(access_user);
	else {
		client->access_user = i_strdup("anonymous");
		client->access_anonymous = TRUE;
	}
	if (access_applications != NULL) {
		const char *const *apps = access_applications;
		for (; *apps != NULL; apps++) {
			char *app = i_strdup(*apps);
			array_push_back(&client->access_apps, &app);
		}
	}
	client->event = event_create(NULL);
	event_set_forced_debug(client->event, debug);

	client->conn_ctrl.event_parent = client->event;
	connection_init(clist_ctrl, &client->conn_ctrl, NULL);

	client->conn.event_parent = client->event;
	connection_init_server(clist, &client->conn, NULL, fd_in, fd_out);

	client->to_idle = timeout_add(CLIENT_IDLE_TIMEOUT_MSECS,
				      client_idle_timeout, client);

	i_set_failure_prefix("imap-urlauth[%s](%s): ",
			     my_pid, client->access_user);
	return client;
}

static void client_abort(struct client *client, const char *reason)
{
	e_error(client->event, "%s", reason);
	client_destroy(client);
}

static void client_destroy(struct client *client)
{
	char *app;

	i_set_failure_prefix("imap-urlauth[%s](%s): ",
			     my_pid, client->access_user);

	connection_disconnect(&client->conn);
	if (client->url != NULL) {
		/* deinitialize url */
		(void)client_run_url(client);
		i_assert(client->url == NULL);
	}

	if (client->urlauth_ctx != NULL)
		imap_urlauth_deinit(&client->urlauth_ctx);

	if (client->mail_user != NULL)
		mail_user_deinit(&client->mail_user);

	timeout_remove(&client->to_idle);

	connection_disconnect(&client->conn_ctrl);

	i_free(client->access_user);
	i_free(client->access_service);
	array_foreach_elem(&client->access_apps, app)
		i_free(app);
	array_free(&client->access_apps);
	connection_deinit(&client->conn_ctrl);
	connection_deinit(&client->conn);
	event_unref(&client->event);
	i_free(client);

	imap_urlauth_worker_refresh_proctitle();
	master_service_client_connection_destroyed(master_service);
}

static int client_run_url(struct client *client)
{
	const unsigned char *data;
	size_t size;
	ssize_t ret = 0;

	while (i_stream_read_more(client->msg_part_input, &data, &size) > 0) {
		if (client->conn.output == NULL ||
		    (ret = o_stream_send(client->conn.output, data, size)) < 0)
			break;
		i_stream_skip(client->msg_part_input, ret);

		if (o_stream_get_buffer_used_size(client->conn.output) >= 4096) {
			if ((ret = o_stream_flush(client->conn.output)) < 0)
				break;
			if (ret == 0)
				return 0;
		}
	}

	if (client->conn.output == NULL || client->conn. output->closed ||
	    ret < 0) {
		imap_msgpart_url_free(&client->url);
		return -1;
	}

	if (client->msg_part_input->eof) {
		o_stream_nsend(client->conn.output, "\n", 1);
		imap_msgpart_url_free(&client->url);
		return 1;
	}
	return 0;
}

static void ATTR_FORMAT(2, 3)
client_send_line(struct client *client, const char *fmt, ...)
{
	va_list va;

	if (client->conn.output == NULL || client->conn.output->closed)
		return;

	va_start(va, fmt);

	T_BEGIN {
		string_t *str;

		str = t_str_new(256);
		str_vprintfa(str, fmt, va);
		str_append(str, "\n");

		o_stream_nsend(client->conn.output,
			       str_data(str), str_len(str));
	} T_END;

	va_end(va);
}

static int
client_fetch_urlpart(struct client *client, const char *url,
		     enum imap_urlauth_fetch_flags url_flags,
		     const char **bpstruct_r, bool *binary_with_nuls_r,
		     const char **errormsg_r)
{
	const char *error;
	struct imap_msgpart_open_result mpresult;
	enum mail_error error_code;
	int ret;

	*bpstruct_r = NULL;
	*errormsg_r = NULL;
	*binary_with_nuls_r = FALSE;

	ret = imap_urlauth_fetch(client->urlauth_ctx, url,
				 &client->url, &error_code, &error);
	if (ret <= 0) {
		if (ret < 0)
			return -1;
		error = t_strdup_printf(
			"Failed to fetch URLAUTH \"%s\": %s", url, error);
		e_debug(client->event, "%s", error);
		/* don't leak info about existence/accessibility
		   of mailboxes */
		if (error_code == MAIL_ERROR_PARAMS)
			*errormsg_r = error;
		return 0;
	}

	if ((url_flags & IMAP_URLAUTH_FETCH_FLAG_BINARY) != 0)
		imap_msgpart_url_set_decode_to_binary(client->url);
	if ((url_flags & IMAP_URLAUTH_FETCH_FLAG_BODYPARTSTRUCTURE) != 0) {
		ret = imap_msgpart_url_get_bodypartstructure(client->url,
							     bpstruct_r, &error);
		if (ret <= 0) {
			*errormsg_r = t_strdup_printf(
				"Failed to read URLAUTH \"%s\": %s", url, error);
			e_debug(client->event, "%s", *errormsg_r);
			return ret;
		}
	}

	/* if requested, read the message part the URL points to */
	if ((url_flags & IMAP_URLAUTH_FETCH_FLAG_BODY) != 0 ||
	    (url_flags & IMAP_URLAUTH_FETCH_FLAG_BINARY) != 0) {
		ret = imap_msgpart_url_read_part(client->url, &mpresult, &error);
		if (ret <= 0) {
			*errormsg_r = t_strdup_printf(
				"Failed to read URLAUTH \"%s\": %s", url, error);
			e_debug(client->event, "%s", *errormsg_r);
			return ret;
		}
		client->msg_part_size = mpresult.size;
		client->msg_part_input = mpresult.input;
		*binary_with_nuls_r = mpresult.binary_decoded_input_has_nuls;
	}
	return 1;
}

static int client_fetch_url(struct client *client, const char *url,
			    enum imap_urlauth_fetch_flags url_flags)
{
	string_t *response;
	const char *bpstruct, *errormsg;
	bool binary_with_nuls;
	int ret;

	i_assert(client->url == NULL);

	client->msg_part_size = 0;
	client->msg_part_input = NULL;

	e_debug(client->event, "Fetching URLAUTH %s", url);

	/* fetch URL */
	ret = client_fetch_urlpart(client, url, url_flags, &bpstruct,
				   &binary_with_nuls, &errormsg);
	if (ret <= 0) {
		/* fetch failed */
		if (client->url != NULL)
			imap_msgpart_url_free(&client->url);
		/* don't send error details to anonymous users: just to be sure
		   that no information about the target user account is unduly
		   leaked. */
		if (client->access_anonymous || errormsg == NULL)
			client_send_line(client, "NO");
		else {
			client_send_line(client, "NO\terror=%s",
					 str_tabescape(errormsg));
		}
		if (ret < 0) {
			/* fetch failed badly */
			client_abort(client, "Session aborted: Fatal failure while fetching URL");
		}
		return 0;
	}

	response = t_str_new(256);
	str_append(response, "OK");
	if (binary_with_nuls)
		str_append(response, "\thasnuls");
	if (bpstruct != NULL) {
		str_append(response, "\tbpstruct=");
		str_append(response, str_tabescape(bpstruct));
		e_debug(client->event,
			"Fetched URLAUTH yielded BODYPARTSTRUCTURE (%s)", bpstruct);
	}

	/* return content */
	o_stream_cork(client->conn.output);
	if (client->msg_part_size == 0 || client->msg_part_input == NULL) {
		/* empty */
		str_append(response, "\t0");
		client_send_line(client, "%s", str_c(response));

		imap_msgpart_url_free(&client->url);
		client->url = NULL;
		e_debug(client->event, "Fetched URLAUTH yielded empty result");
	} else {

		/* actual content */
		str_printfa(response, "\t%"PRIuUOFF_T, client->msg_part_size);
		client_send_line(client, "%s", str_c(response));

		e_debug(client->event,
			"Fetched URLAUTH yielded %"PRIuUOFF_T" bytes "
			"of %smessage data", client->msg_part_size,
			binary_with_nuls ? "binary " : "");
		if (client_run_url(client) < 0) {
			client_abort(client,
				"Session aborted: Fatal failure while transferring URL");
			return 0;
		}
	}

	if (client->url != NULL) {
		/* URL not finished */
		o_stream_set_flush_pending(client->conn.output, TRUE);
		client->waiting_input = TRUE;
	}
	o_stream_uncork(client->conn.output);
	return client->url != NULL ? 0 : 1;
}

static int
client_handle_command(struct client *client, const char *cmd,
		      const char *const *args, const char **error_r)
{
	int ret;

	*error_r = NULL;

	/* "URL"["\tbody"]["\tbinary"]["\tbpstruct"]"\t"<url>:
	   fetch URL (meta)data */
	if (strcmp(cmd, "URL") == 0) {
		enum imap_urlauth_fetch_flags url_flags = 0;
		const char *url;

		if (*args == NULL) {
			*error_r = "URL: Missing URL parameter";
			return -1;
		}

		url = *args;

		args++;
		while (*args != NULL) {
			if (strcasecmp(*args, "body") == 0)
				url_flags |= IMAP_URLAUTH_FETCH_FLAG_BODY;
			else if (strcasecmp(*args, "binary") == 0)
				url_flags |= IMAP_URLAUTH_FETCH_FLAG_BINARY;
			else if (strcasecmp(*args, "bpstruct") == 0)
				url_flags |= IMAP_URLAUTH_FETCH_FLAG_BODYPARTSTRUCTURE;

			args++;
		}

		if (url_flags == 0)
			url_flags = IMAP_URLAUTH_FETCH_FLAG_BODY;

		T_BEGIN {
			ret = client_fetch_url(client, url, url_flags);
		} T_END;
		return ret;
	}

	/* "END": unselect current user (closes worker) */
	if (strcmp(cmd, "END") == 0) {
		if (args[0] != NULL) {
			*error_r = "END: Invalid number of parameters";
			return -1;
		}

		client->finished = TRUE;
		if (client->conn_ctrl.output != NULL) {
			o_stream_nsend_str(client->conn_ctrl.output,
					   "FINISHED\n");
		}
		client_destroy(client);
		return 0;
	}

	*error_r = t_strconcat("Unknown or inappropriate command: ", cmd, NULL);
	return -1;
}

static int
client_handle_user_command(struct client *client, const char *cmd,
			   const char *const *args, const char **error_r)
{
	struct mail_storage_service_input input;
	struct imap_urlauth_worker_settings *set;
	struct imap_urlauth_config config;
	struct mail_user *mail_user;
	const char *error;
	unsigned int count;
	int ret;

	/* "USER\t"<username> */
	*error_r = NULL;

	/* check command syntax */
	if (strcmp(cmd, "USER") != 0) {
		*error_r = t_strconcat("Unknown or inappropriate command: ",
				       cmd, NULL);
		return -1;
	}

	if (args[0] == NULL || args[1] != NULL) {
		*error_r = "USER: Invalid number of parameters";
		return -1;
	}

	/* lookup user */
	i_zero(&input);
	input.service = "imap-urlauth-worker";
	input.username = args[0];
	input.event_parent = client->event;

	e_debug(client->event, "Looking up user %s", input.username);

	ret = mail_storage_service_lookup_next(storage_service, &input,
					       &mail_user, &error);
	if (ret < 0) {
		e_error(client->event,
			"Failed to lookup user %s: %s", input.username, error);
		client_abort(client, "Session aborted: Failed to lookup user");
		return 0;
	} else if (ret == 0) {
		e_debug(client->event, "User %s doesn't exist", input.username);
		client_send_line(client, "NO");
		return 1;
	}

	event_set_forced_debug(client->event, mail_user->mail_debug);

	/* drop privileges */
	restrict_access_allow_coredumps(TRUE);

	set = settings_parser_get_root_set(mail_user->set_parser,
			&imap_urlauth_worker_setting_parser_info);

	if (set->verbose_proctitle) {
		verbose_proctitle = TRUE;
		imap_urlauth_worker_refresh_proctitle();
	}

	client->mail_user = mail_user;
	client->set = set;

	e_debug(client->event, "Found user account `%s' on behalf of user `%s'",
		mail_user->username, client->access_user);

	/* initialize urlauth context */
	if (*set->imap_urlauth_host == '\0') {
		e_error(client->event,
			"imap_urlauth_host setting is not configured for user %s",
			mail_user->username);
		client_send_line(client, "NO");
		client_abort(client, "Session aborted: URLAUTH not configured");
		return 0;
	}

	i_zero(&config);
	config.url_host = set->imap_urlauth_host;
	config.url_port = set->imap_urlauth_port;
	config.access_user = client->access_user;
	config.access_service = client->access_service;
	config.access_anonymous = client->access_anonymous;
	config.access_applications =
		(const void *)array_get(&client->access_apps, &count);

	client->urlauth_ctx = imap_urlauth_init(client->mail_user, &config);
	e_debug(client->event,
		"Providing access to user account `%s' on behalf of user `%s' using service `%s'",
		mail_user->username, client->access_user, client->access_service);

	i_set_failure_prefix("imap-urlauth[%s](%s->%s): ",
			     my_pid, client->access_user, mail_user->username);

	client_send_line(client, "OK");
	return 1;
}

static bool client_handle_input(struct client *client)
{
	const char *line, *cmd, *error;
	int ret;

	if (client->url != NULL) {
		/* we're still processing a URL. wait until it's
		   finished. */
		connection_input_halt(&client->conn);
		client->waiting_input = TRUE;
		return TRUE;
	}

	connection_input_resume(&client->conn);
	client->waiting_input = FALSE;
	timeout_reset(client->to_idle);

	if (connection_input_read(&client->conn) < 0)
		return FALSE;

	while ((line = i_stream_next_line(client->conn.input)) != NULL) {
		const char *const *args = t_strsplit_tabescaped(line);

		if (args[0] == NULL)
			continue;
		cmd = args[0]; args++;

		if (client->mail_user == NULL)
			ret = client_handle_user_command(client, cmd, args, &error);
		else
			ret = client_handle_command(client, cmd, args, &error);

		if (ret <= 0) {
			if (ret == 0)
				break;
			e_error(client->event,
				"Client input error: %s", error);
			client_abort(client, "Session aborted: Unexpected input");
			return FALSE;
		}
	}
	return TRUE;
}

static void client_input(struct connection *_conn)
{
	struct client *client = container_of(_conn, struct client, conn);

	(void)client_handle_input(client);
}

static int client_output(struct client *client)
{
	if (o_stream_flush(client->conn.output) < 0) {
		if (client->conn_ctrl.output != NULL) {
			o_stream_nsend_str(client->conn_ctrl.output,
					   "DISCONNECTED\n");
		}
		client_destroy(client);
		return 1;
	}
	timeout_reset(client->to_idle);

	if (client->url != NULL) {
		if (client_run_url(client) < 0) {
			client_destroy(client);
			return 1;
		}

		if (client->url == NULL && client->waiting_input) {
			if (!client_handle_input(client)) {
				/* client got destroyed */
				return 1;
			}
		}
	}

	if (client->url != NULL) {
		/* url not finished yet */
		return 0;
	} else if (client->conn.io == NULL) {
		/* data still in output buffer, get back here to add IO */
		return 0;
	} else {
		return 1;
	}
}

static int
client_ctrl_read_fd(struct client *client, unsigned char *data_r, int *fd_r)
{
	const unsigned char *data;
	size_t size;
	int ret;

	ret = i_stream_read_more(client->conn_ctrl.input, &data, &size);
	if (ret <= 0)
		return ret;
	i_stream_skip(client->conn_ctrl.input, 1);

	*data_r = data[0];
	*fd_r = i_stream_unix_get_read_fd(client->conn_ctrl.input);
	return 1;
}

static int client_ctrl_read_fds(struct client *client)
{
	unsigned char data = 0;
	int ret = 1;

	if (client->conn.fd_in == -1) {
		ret = client_ctrl_read_fd(client, &data, &client->conn.fd_in);
		if (ret > 0 && data == '0')
			client->conn.fd_out = client->conn.fd_in;
		else
			i_stream_unix_set_read_fd(client->conn_ctrl.input);
	}
	if (ret > 0 && client->conn.fd_out == -1) {
		ret = client_ctrl_read_fd(client, &data, &client->conn.fd_out);
	}

	if (ret == 0) {
		return 0;
	} else if (ret < 0) {
		if (errno == EAGAIN)
			return 0;
		e_error(client->event,
			"fd_read() failed: %m");
		return -1;
	} else if (data != '0') {
		e_error(client->event,
			"fd_read() returned invalid byte 0x%2x", data);
		return -1;
	}

	if (client->conn.fd_in == -1 || client->conn.fd_out == -1) {
		e_error(client->event,
			"Handshake is missing a file descriptor");
		return -1;
	}

	connection_init_server(clist, &client->conn, NULL,
			       client->conn.fd_in, client->conn.fd_out);
	connection_input_halt(&client->conn);

	return 1;
}

static int client_ctrl_handshake(struct client *client)
{
	if (client->conn_ctrl.version_received)
		return 1;

	const char *line;

	line = i_stream_next_line(client->conn_ctrl.input);
	if (line == NULL)
		return 0;

	if (connection_handshake_args_default(
		&client->conn_ctrl, t_strsplit_tabescaped(line)) < 0) {
		client_abort(client, "Control session aborted: "
			     "Received bad VERSION line");
		return -1;
	}
	return 1;
}

static void client_ctrl_input(struct connection *_conn)
{
	struct client *client = container_of(_conn, struct client, conn_ctrl);
	const char *const *args;
	const char *line, *value;
	int ret;

	timeout_reset(client->to_idle);

	if (connection_input_read(&client->conn_ctrl) < 0)
		return;
	if (client_ctrl_handshake(client) <= 0)
		return;

	if (client->conn.fd_in == -1 || client->conn.fd_out == -1) {
		if ((ret = client_ctrl_read_fds(client)) <= 0) {
			if (ret < 0)
				client_abort(client, "FD Transfer failed");
			return;
		}
		if (o_stream_send_str(client->conn_ctrl.output, "OK\n") < 0) {
			client_destroy(client);
			return;
		}
	}

	if (client->access_received) {
		client_abort(client, "Control session aborted: Unexpected input");
		return;
	}

	if ((line = i_stream_next_line(client->conn_ctrl.input)) == NULL)
		return;

	args = t_strsplit_tabescaped(line);
	if (*args == NULL || strcmp(*args, "ACCESS") != 0) {
		e_error(client->event,
			"Invalid control command: %s", str_sanitize(line, 80));
		client_abort(client, "Control session aborted: Invalid command");
		return;
	}
	args++;
	if (args[0] == NULL || args[1] == NULL) {
		e_error(client->event,
			"Invalid ACCESS command: %s", str_sanitize(line, 80));
		client_abort(client, "Control session aborted: Invalid command");
		return;
	}

	i_assert(client->access_user == NULL);
	i_assert(client->access_service == NULL);
	if (**args != '\0') {
		client->access_user = i_strdup(*args);
		client->access_anonymous = FALSE;
	} else {
		client->access_user = i_strdup("anonymous");
		client->access_anonymous = TRUE;
	}
	args++;
	client->access_service = i_strdup(*args);

	i_set_failure_prefix("imap-urlauth[%s](%s): ",
			     my_pid, client->access_user);

	args++;
	while (*args != NULL) {
		/* debug */
		if (strcasecmp(*args, "debug") == 0) {
			event_set_forced_debug(client->event, TRUE);

		/* apps=<access-application>[,<access-application,...] */
		} else if (str_begins_icase(*args, "apps=", &value) &&
			   value[0] != '\0') {
			const char *const *apps = t_strsplit(value, ",");

			while (*apps != NULL) {
				char *app = i_strdup(*apps);

				array_push_back(&client->access_apps, &app);
				e_debug(client->event,
					"User %s has URLAUTH %s access",
					client->access_user, app);
				apps++;
			}
		} else {
			e_error(client->event,
				"Invalid ACCESS parameter: %s", str_sanitize(*args, 80));
			client_abort(client, "Control session aborted: Invalid command");
			return;
		}
		args++;
	}

	client->access_received = TRUE;

	if (o_stream_send_str(client->conn_ctrl.output, "OK\n") < 0) {
		client_destroy(client);
		return;
	}

	connection_input_resume(&client->conn);
	o_stream_set_flush_callback(client->conn.output, client_output, client);

	e_debug(client->event,
		"Worker activated for access by user `%s' using service `%s'",
		client->access_user, client->access_service);
}

static void client_ctrl_connection_destroy(struct connection *conn)
{
	struct client *client = container_of(conn, struct client, conn_ctrl);

	switch (conn->disconnect_reason) {
	case CONNECTION_DISCONNECT_NOT:
	case CONNECTION_DISCONNECT_HANDSHAKE_FAILED:
	case CONNECTION_DISCONNECT_BUFFER_FULL:
		i_unreached();
	default:
		break;
	}

	client_destroy(client);
}

static void client_connection_destroy(struct connection *conn)
{
	struct client *client = container_of(conn, struct client, conn);

	switch (conn->disconnect_reason) {
	case CONNECTION_DISCONNECT_NOT:
	case CONNECTION_DISCONNECT_HANDSHAKE_FAILED:
	case CONNECTION_DISCONNECT_BUFFER_FULL:
		i_unreached();
	default:
		break;
	}

	client_destroy(client);
}

static const struct connection_vfuncs client_ctrl_connection_vfuncs = {
	.input = client_ctrl_input,
	.destroy = client_ctrl_connection_destroy,
};

static const struct connection_settings client_ctrl_connection_set = {
	.service_name_in = IMAP_URLAUTH_WORKER_SOCKET,
	.service_name_out = IMAP_URLAUTH_WORKER_SOCKET,
	.major_version = IMAP_URLAUTH_WORKER_PROTOCOL_MAJOR_VERSION,
	.minor_version = IMAP_URLAUTH_WORKER_PROTOCOL_MINOR_VERSION,
	.unix_client_connect_msecs = 1000,
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
};

static const struct connection_vfuncs client_connection_vfuncs = {
	.input = client_input,
	.destroy = client_connection_destroy,
};

static const struct connection_settings client_connection_set = {
	.unix_client_connect_msecs = 1000,
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
};

static void imap_urlauth_worker_die(void)
{
	/* do nothing */
}

static void main_stdio_run(const char *access_user,
			   const char *const *access_applications)
{
	bool debug;

	debug = getenv("DEBUG") != NULL;
	access_user = access_user != NULL ? access_user : getenv("USER");
	if (access_user == NULL && IS_STANDALONE())
		access_user = getlogin();
	if (access_user == NULL)
		i_fatal("USER environment missing");

	(void)client_create_standalone(access_user, access_applications,
				       STDIN_FILENO, STDOUT_FILENO, debug);
}

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);
	(void)client_create(conn->fd);
}

int main(int argc, char *argv[])
{
	static const struct setting_parser_info *set_roots[] = {
		&imap_urlauth_worker_setting_parser_info,
		NULL
	};
	enum master_service_flags service_flags = 0;
	enum mail_storage_service_flags storage_service_flags =
		MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP |
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT;
	ARRAY_TYPE (const_string) access_apps;
	const char *access_user = NULL;
	int c;

	if (IS_STANDALONE()) {
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE |
			MASTER_SERVICE_FLAG_STD_CLIENT;
	}

	master_service = master_service_init("imap-urlauth-worker", service_flags,
					     &argc, &argv, "a:");

	t_array_init(&access_apps, 4);
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'a': {
			const char *app = t_strdup(optarg);

			array_push_back(&access_apps, &app);
			break;
		}
		default:
			return FATAL_DEFAULT;
		}
	}

	if ( optind < argc ) {
		access_user = argv[optind++];
	}

	if (optind != argc) {
		i_fatal_status(EX_USAGE, "Unknown argument: %s", argv[optind]);
	}

	master_service_init_log_with_pid(master_service);
	master_service_set_die_callback(master_service, imap_urlauth_worker_die);

	storage_service =
		mail_storage_service_init(master_service,
					  set_roots, storage_service_flags);
	master_service_init_finish(master_service);

	/* fake that we're running, so we know if client was destroyed
	   while handling its initial input */
	io_loop_set_running(current_ioloop);

	clist = connection_list_init(&client_connection_set,
				     &client_connection_vfuncs);
	clist_ctrl = connection_list_init(&client_ctrl_connection_set,
					  &client_ctrl_connection_vfuncs);

	if (IS_STANDALONE()) {
		T_BEGIN {
			if (array_count(&access_apps) > 0) {
				(void)array_append_space(&access_apps);
				main_stdio_run(access_user,
					       array_front(&access_apps));
			} else {
				main_stdio_run(access_user, NULL);
			}
		} T_END;
	} else {
		io_loop_set_running(current_ioloop);
	}

	if (io_loop_is_running(current_ioloop))
		master_service_run(master_service, client_connected);

	connection_list_deinit(&clist);
	connection_list_deinit(&clist_ctrl);

	mail_storage_service_deinit(&storage_service);
	master_service_deinit(&master_service);
	return 0;
}
