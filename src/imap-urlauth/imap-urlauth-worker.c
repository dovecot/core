/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "net.h"
#include "fdpass.h"
#include "istream.h"
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
#include "master-service.h"
#include "master-interface.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "mail-namespace.h"
#include "imap-url.h"
#include "imap-msgpart-url.h"
#include "imap-urlauth.h"
#include "imap-urlauth-fetch.h"
#include "imap-urlauth-worker-settings.h"

#include <unistd.h>
#include <sysexits.h>

#define MAX_CTRL_HANDSHAKE 255

/* max. length of input lines (URLs) */
#define MAX_INBUF_SIZE 2048

/* Disconnect client after idling this many milliseconds */
#define CLIENT_IDLE_TIMEOUT_MSECS (10*60*1000)

#define IS_STANDALONE() \
        (getenv(MASTER_IS_PARENT_ENV) == NULL)

#define IMAP_URLAUTH_WORKER_PROTOCOL_MAJOR_VERSION 2
#define IMAP_URLAUTH_WORKER_PROTOCOL_MINOR_VERSION 0

struct client {
	struct client *prev, *next;

	int fd_in, fd_out, fd_ctrl;

	struct io *io, *ctrl_io;
	struct istream *input, *ctrl_input;
	struct ostream *output, *ctrl_output;
	struct timeout *to_idle;

	char *access_user, *access_service;
	ARRAY_TYPE(string) access_apps;

	struct mail_storage_service_user *service_user;
	struct mail_user *mail_user;

	struct imap_urlauth_context *urlauth_ctx;

	struct imap_msgpart_url *url;
	struct istream *msg_part_input;
	uoff_t msg_part_size;

	/* settings: */
	const struct imap_urlauth_worker_settings *set;
	const struct mail_storage_settings *mail_set;

	bool debug:1;
	bool finished:1;
	bool waiting_input:1;
	bool version_received:1;
	bool access_received:1;
	bool access_anonymous:1;
};

static bool verbose_proctitle = FALSE;
static struct mail_storage_service_ctx *storage_service;

struct client *imap_urlauth_worker_clients;
unsigned int imap_urlauth_worker_client_count;

static void client_destroy(struct client *client);
static void client_abort(struct client *client, const char *reason);
static int client_run_url(struct client *client);
static void client_input(struct client *client);
static bool client_handle_input(struct client *client);
static int client_output(struct client *client);

static void client_ctrl_input(struct client *client);

static void imap_urlauth_worker_refresh_proctitle(void)
{
	struct client *client = imap_urlauth_worker_clients;
	string_t *title;

	if (!verbose_proctitle)
		return;

	title = t_str_new(128);
	str_append_c(title, '[');
	switch (imap_urlauth_worker_client_count) {
	case 0:
		str_append(title, "idling");
		break;
	case 1:
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
			    imap_urlauth_worker_client_count);
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
	client->fd_in = -1;
	client->fd_out = -1;
	client->fd_ctrl = fd;
	client->access_anonymous = TRUE; /* default until overridden */

	client->ctrl_io = io_add(fd, IO_READ, client_ctrl_input, client);
	client->to_idle = timeout_add(CLIENT_IDLE_TIMEOUT_MSECS,
				      client_idle_timeout, client);

	imap_urlauth_worker_client_count++;
	DLLIST_PREPEND(&imap_urlauth_worker_clients, client);

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
	client->fd_in = fd_in;
	client->fd_out = fd_out;
	client->fd_ctrl = -1;

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
	client->debug = debug;

	client->input = i_stream_create_fd(fd_in, MAX_INBUF_SIZE);
	client->output = o_stream_create_fd(fd_out, (size_t)-1);
	client->io = io_add(fd_in, IO_READ, client_input, client);
	client->to_idle = timeout_add(CLIENT_IDLE_TIMEOUT_MSECS,
				      client_idle_timeout, client);
	o_stream_set_no_error_handling(client->output, TRUE);
	o_stream_set_flush_callback(client->output, client_output, client);

	imap_urlauth_worker_client_count++;
	DLLIST_PREPEND(&imap_urlauth_worker_clients, client);

	i_set_failure_prefix("imap-urlauth[%s](%s): ",
			     my_pid, client->access_user);
	return client;
}

static void client_abort(struct client *client, const char *reason)
{
	i_error("%s", reason);
	client_destroy(client);
}

static void client_destroy(struct client *client)
{
	char **app;

	i_set_failure_prefix("imap-urlauth[%s](%s): ",
			     my_pid, client->access_user);

	if (client->url != NULL) {
		/* deinitialize url */
		i_stream_close(client->input);
		o_stream_close(client->output);
		(void)client_run_url(client);
		i_assert(client->url == NULL);
	}

	imap_urlauth_worker_client_count--;
	DLLIST_REMOVE(&imap_urlauth_worker_clients, client);

	if (client->urlauth_ctx != NULL)
		imap_urlauth_deinit(&client->urlauth_ctx);

	if (client->mail_user != NULL)
		mail_user_unref(&client->mail_user);

	io_remove(&client->io);
	io_remove(&client->ctrl_io);
	timeout_remove(&client->to_idle);

	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);

	i_stream_destroy(&client->ctrl_input);
	o_stream_destroy(&client->ctrl_output);

	fd_close_maybe_stdio(&client->fd_in, &client->fd_out);
	if (client->fd_ctrl >= 0)
		net_disconnect(client->fd_ctrl);

	if (client->service_user != NULL)
		mail_storage_service_user_unref(&client->service_user);
	i_free(client->access_user);
	i_free(client->access_service);
	array_foreach_modifiable(&client->access_apps, app)
		i_free(*app);
	array_free(&client->access_apps);
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
		if ((ret = o_stream_send(client->output, data, size)) < 0)
			break;
		i_stream_skip(client->msg_part_input, ret);

		if (o_stream_get_buffer_used_size(client->output) >= 4096) {
			if ((ret = o_stream_flush(client->output)) < 0)
				break;
			if (ret == 0)
				return 0;
		}
	}

	if (client->output->closed || ret < 0) {
		imap_msgpart_url_free(&client->url);
		return -1;
	}

	if (client->msg_part_input->eof) {
		o_stream_nsend(client->output, "\n", 1);
		imap_msgpart_url_free(&client->url);
		return 1;
	}
	return 0;
}

static void clients_destroy_all(void)
{
	while (imap_urlauth_worker_clients != NULL)
		client_destroy(imap_urlauth_worker_clients);
}

static void ATTR_FORMAT(2, 3)
client_send_line(struct client *client, const char *fmt, ...)
{
	va_list va;

	if (client->output->closed)
		return;

	va_start(va, fmt);

	T_BEGIN {
		string_t *str;

		str = t_str_new(256);
		str_vprintfa(str, fmt, va);
		str_append(str, "\n");

		o_stream_nsend(client->output, str_data(str), str_len(str));
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
		error = t_strdup_printf("Failed to fetch URLAUTH \"%s\": %s",
					url, error);
		if (client->debug)
			i_debug("%s", error);
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
			if (client->debug)
				i_debug("%s", *errormsg_r);
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
			if (client->debug)
				i_debug("%s", *errormsg_r);
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

	if (client->debug)
		i_debug("Fetching URLAUTH %s", url);

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
		if (client->debug) {
			i_debug("Fetched URLAUTH yielded BODYPARTSTRUCTURE (%s)",
				bpstruct);
		}
	}

	/* return content */
	o_stream_cork(client->output);
	if (client->msg_part_size == 0 || client->msg_part_input == NULL) {
		/* empty */
		str_append(response, "\t0");
		client_send_line(client, "%s", str_c(response));

		imap_msgpart_url_free(&client->url);
		client->url = NULL;
		if (client->debug)
			i_debug("Fetched URLAUTH yielded empty result");
	} else {

		/* actual content */
		str_printfa(response, "\t%"PRIuUOFF_T, client->msg_part_size);
		client_send_line(client, "%s", str_c(response));

		if (client->debug) {
			i_debug("Fetched URLAUTH yielded %"PRIuUOFF_T" bytes "
				"of %smessage data", client->msg_part_size,
				(binary_with_nuls ? "binary " : ""));
		}
		if (client_run_url(client) < 0) {
			client_abort(client,
				"Session aborted: Fatal failure while transferring URL");
			return 0;
		}		
	}

	if (client->url != NULL) {
		/* URL not finished */
		o_stream_set_flush_pending(client->output, TRUE);
		client->waiting_input = TRUE;
	}
	o_stream_uncork(client->output);
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
		if (client->ctrl_output != NULL)
			o_stream_nsend_str(client->ctrl_output, "FINISHED\n");
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
	struct mail_storage_service_user *user;
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
	input.module = "imap-urlauth-worker";
	input.service = "imap-urlauth-worker";
	input.username = args[0];

	if (client->debug)
		i_debug("Looking up user %s", input.username);

	ret = mail_storage_service_lookup_next(storage_service, &input,
					       &user, &mail_user, &error);
	if (ret < 0) {
		i_error("Failed to lookup user %s: %s", input.username, error);
		client_abort(client, "Session aborted: Failed to lookup user");
		return 0;
	} else if (ret == 0) {
		if (client->debug)
			i_debug("User %s doesn't exist", input.username);

		client_send_line(client, "NO");
		return 1;
	}

	client->debug = mail_user->mail_debug =
		client->debug || mail_user->mail_debug;

	/* drop privileges */
	restrict_access_allow_coredumps(TRUE);

	set = mail_storage_service_user_get_set(user)[1];
	if (settings_var_expand(&imap_urlauth_worker_setting_parser_info, set,
				mail_user->pool,
				mail_user_var_expand_table(mail_user),
				&error) <= 0) {
		client_send_line(client, "NO");
		client_abort(client, t_strdup_printf(
			"Session aborted: Failed to expand settings: %s", error));
		return 0;
	}

	if (set->verbose_proctitle) {
		verbose_proctitle = TRUE;
		imap_urlauth_worker_refresh_proctitle();
	}

	client->service_user = user;
	client->mail_user = mail_user;
	client->set = set;

	if (client->debug) {
		i_debug("Found user account `%s' on behalf of user `%s'",
			mail_user->username, client->access_user);
	}

	/* initialize urlauth context */
	if (*set->imap_urlauth_host == '\0') {
		i_error("imap_urlauth_host setting is not configured for user %s",
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
	if (client->debug) {
		i_debug("Providing access to user account `%s' on behalf of user `%s' "
			"using service `%s'", mail_user->username, client->access_user,
			client->access_service);
	}

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
		io_remove(&client->io);
		client->io = NULL;
		client->waiting_input = TRUE;
		return TRUE;
	}

	if (client->io == NULL) {
		client->io = io_add(client->fd_in, IO_READ,
				    client_input, client);
	}
	client->waiting_input = FALSE;
	timeout_reset(client->to_idle);

	switch (i_stream_read(client->input)) {
	case -1:
		/* disconnected */
		if (client->ctrl_output != NULL)
			o_stream_nsend_str(client->ctrl_output, "DISCONNECTED\n");
		client_destroy(client);
		return FALSE;
	case -2:
		/* line too long, kill it */
		client_abort(client, "Session aborted: Input line too long");
		return FALSE;
	}

	while ((line = i_stream_next_line(client->input)) != NULL) {
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
			i_error("Client input error: %s", error);
			client_abort(client, "Session aborted: Unexpected input");
			return FALSE;
		}
	}
	return TRUE;
}

static void client_input(struct client *client)
{
	(void)client_handle_input(client);
}

static int client_output(struct client *client)
{
	if (o_stream_flush(client->output) < 0) {
		if (client->ctrl_output != NULL)
			o_stream_nsend_str(client->ctrl_output, "DISCONNECTED\n");
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
	} else if (client->io == NULL) {
		/* data still in output buffer, get back here to add IO */
		return 0;
	} else {
		return 1;
	}
}

static int
client_ctrl_read_fds(struct client *client)
{
	unsigned char data = 0;
	ssize_t ret = 1;

	if (client->fd_in == -1) {
		ret = fd_read(client->fd_ctrl, &data,
			      sizeof(data), &client->fd_in);
		if (ret > 0 && data == '0')
			client->fd_out = client->fd_in;
	}
	if (ret > 0 && client->fd_out == -1) {
		ret = fd_read(client->fd_ctrl, &data,
			      sizeof(data), &client->fd_out);
	}

	if (ret == 0) {
		/* unexpectedly disconnected */
		client_destroy(client);
		return 0;
	} else if (ret < 0) {
		if (errno == EAGAIN)
			return 0;
		i_error("fd_read() failed: %m");
		return -1;
	} else if (data != '0') {
		i_error("fd_read() returned invalid byte 0x%2x", data);
		return -1;
	}

	if (client->fd_in == -1 || client->fd_out == -1) {
		i_error("Handshake is missing a file descriptor");
		return -1;
	}

	client->ctrl_input =
		i_stream_create_fd(client->fd_ctrl, MAX_INBUF_SIZE);
	client->ctrl_output = o_stream_create_fd(client->fd_ctrl, (size_t)-1);
	o_stream_set_no_error_handling(client->ctrl_output, TRUE);
	return 1;
}

static void client_ctrl_input(struct client *client)
{
	const char *const *args;
	const char *line;
	int ret;

	timeout_reset(client->to_idle);

	if (client->fd_in == -1 || client->fd_out == -1) {
		if ((ret = client_ctrl_read_fds(client)) <= 0) {
			if (ret < 0)
				client_abort(client, "FD Transfer failed");
			return;
		}
	}

	switch (i_stream_read(client->ctrl_input)) {
	case -1:
		/* disconnected */
		client_destroy(client);
		return;
	case -2:
		/* line too long, kill it */
		client_abort(client,
			     "Control session aborted: Input line too long");
		return;
	}

	if (!client->version_received) {
		if ((line = i_stream_next_line(client->ctrl_input)) == NULL)
			return;

		if (!version_string_verify(line, "imap-urlauth-worker",
				IMAP_URLAUTH_WORKER_PROTOCOL_MAJOR_VERSION)) {
			i_error("imap-urlauth-worker client not compatible with this server "
				"(mixed old and new binaries?) %s", line);
			client_abort(client, "Control session aborted: Version mismatch");
			return;
		}

		client->version_received = TRUE;
		if (o_stream_send_str(client->ctrl_output, "OK\n") < 0) {
			client_destroy(client);
			return;
		}
	}

	if (client->access_received) {
		client_abort(client, "Control session aborted: Unexpected input");
		return;
	}

	if ((line = i_stream_next_line(client->ctrl_input)) == NULL)
		return;

	args = t_strsplit_tabescaped(line);
	if (*args == NULL || strcmp(*args, "ACCESS") != 0) {
		i_error("Invalid control command: %s", str_sanitize(line, 80));
		client_abort(client, "Control session aborted: Invalid command");
		return;
	}
	args++;
	if (args[0] == NULL || args[1] == NULL) {
		i_error("Invalid ACCESS command: %s", str_sanitize(line, 80));
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
			client->debug = TRUE;
		/* apps=<access-application>[,<access-application,...] */
		} else if (strncasecmp(*args, "apps=", 5) == 0 &&
			   (*args)[5] != '\0') {
			const char *const *apps = t_strsplit(*args+5, ",");

			while (*apps != NULL) {
				char *app = i_strdup(*apps);

				array_push_back(&client->access_apps, &app);
				if (client->debug) {
					i_debug("User %s has URLAUTH %s access",
						client->access_user, app);
				}
				apps++;
			}
		} else {
			i_error("Invalid ACCESS parameter: %s", str_sanitize(*args, 80));
			client_abort(client, "Control session aborted: Invalid command");
			return;
		} 
		args++;
	}

	client->access_received = TRUE;

	if (o_stream_send_str(client->ctrl_output, "OK\n") < 0) {
		client_destroy(client);
		return;
	}

	client->input = i_stream_create_fd(client->fd_in, MAX_INBUF_SIZE);
	client->output = o_stream_create_fd(client->fd_out, (size_t)-1);
	client->io = io_add(client->fd_in, IO_READ, client_input, client);
	o_stream_set_no_error_handling(client->output, TRUE);
	o_stream_set_flush_callback(client->output, client_output, client);

	if (client->debug) {
		i_debug("Worker activated for access by user `%s' using service `%s'",
			client->access_user, client->access_service);
	}
}

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
	} else {
		service_flags |= MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN;
	}

	master_service = master_service_init("imap-urlauth-worker", service_flags,
					     &argc, &argv, "a:");

	t_array_init(&access_apps, 4);
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'a': {
			const char *app = t_strdup(optarg);

			array_append(&access_apps, &app, 1);
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

	master_service_init_log(master_service,
				t_strdup_printf("imap-urlauth[%s]: ", my_pid));
	master_service_set_die_callback(master_service, imap_urlauth_worker_die);

	storage_service =
		mail_storage_service_init(master_service,
					  set_roots, storage_service_flags);
	master_service_init_finish(master_service);

	/* fake that we're running, so we know if client was destroyed
	   while handling its initial input */
	io_loop_set_running(current_ioloop);

	if (IS_STANDALONE()) {
		T_BEGIN {
			if (array_count(&access_apps) > 0) {
				(void)array_append_space(&access_apps);
				main_stdio_run(access_user,
					       array_first(&access_apps));
			} else {
				main_stdio_run(access_user, NULL);
			}
		} T_END;
	} else {
		io_loop_set_running(current_ioloop);
	}

	if (io_loop_is_running(current_ioloop))
		master_service_run(master_service, client_connected);
	clients_destroy_all();

	mail_storage_service_deinit(&storage_service);
	master_service_deinit(&master_service);
	return 0;
}
