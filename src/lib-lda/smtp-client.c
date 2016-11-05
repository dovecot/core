/* Copyright (c) 2006-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "safe-mkstemp.h"
#include "istream.h"
#include "ostream.h"
#include "master-service.h"
#include "lmtp-client.h"
#include "lda-settings.h"
#include "mail-deliver.h"
#include "program-client.h"
#include "smtp-client.h"

#include <unistd.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <signal.h>

#define DEFAULT_SUBMISSION_PORT 25

struct smtp_client {
	pool_t pool;
	struct ostream *output;
	int temp_fd;

	const struct lda_settings *set;
	const char *temp_path;
	ARRAY_TYPE(const_string) destinations;
	const char *return_path;
	const char *error;

	bool success:1;
	bool finished:1;
	bool tempfail:1;
};

static int create_temp_file(const char **path_r)
{
	string_t *path;
	int fd;

	path = t_str_new(128);
	str_append(path, "/tmp/dovecot.");
	str_append(path, master_service_get_name(master_service));
	str_append_c(path, '.');

	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		i_error("safe_mkstemp(%s) failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (i_unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_close_fd(&fd);
		return -1;
	}

	*path_r = str_c(path);
	return fd;
}

struct smtp_client *
smtp_client_init(const struct lda_settings *set, const char *return_path)
{
	struct smtp_client *client;
	pool_t pool;

	pool = pool_alloconly_create("smtp client", 256);
	client = p_new(pool, struct smtp_client, 1);
	client->pool = pool;
	client->set = set;
	client->return_path = p_strdup(pool, return_path);
	p_array_init(&client->destinations, pool, 2);
	return client;
}

void smtp_client_add_rcpt(struct smtp_client *client, const char *address)
{
	i_assert(client->output == NULL);

	address = p_strdup(client->pool, address);
	array_append(&client->destinations, &address, 1);
}

struct ostream *smtp_client_send(struct smtp_client *client)
{
	const char *path;
	int fd;

	i_assert(array_count(&client->destinations) > 0);

	if ((fd = create_temp_file(&path)) == -1)
		return o_stream_create_error(errno);
	client->temp_path = i_strdup(path);
	client->temp_fd = fd;
	client->output = o_stream_create_fd_autoclose(&fd, IO_BLOCK_SIZE);
	o_stream_set_no_error_handling(client->output, TRUE);
	return client->output;
}

static void smtp_client_send_finished(void *context)
{
	struct smtp_client *smtp_client = context;

	smtp_client->finished = TRUE;
	io_loop_stop(current_ioloop);
}

static void
smtp_client_error(struct smtp_client *client, const char *error)
{
	if (client->error == NULL) {
		client->error = i_strdup_printf("smtp(%s): %s",
			client->set->submission_host, error);
	}
}

static void
rcpt_to_callback(enum lmtp_client_result result, const char *reply, void *context)
{
	struct smtp_client *client = context;

	if (result != LMTP_CLIENT_RESULT_OK) {
		if (reply[0] != '5')
			client->tempfail = TRUE;
		smtp_client_error(client, t_strdup_printf(
			"RCPT TO failed: %s", reply));
		smtp_client_send_finished(client);
	}
}

static void
data_callback(enum lmtp_client_result result, const char *reply, void *context)
{
	struct smtp_client *client = context;

	if (result != LMTP_CLIENT_RESULT_OK) {
		if (reply[0] != '5')
			client->tempfail = TRUE;
		smtp_client_error(client, t_strdup_printf(
			"DATA failed: %s", reply));
		smtp_client_send_finished(client);
	} else {
		client->success = TRUE;
	}
}

static int
smtp_client_send_host(struct smtp_client *client,
		       unsigned int timeout_secs, const char **error_r)
{
	struct lmtp_client_settings client_set;
	struct lmtp_client *lmtp_client;
	struct ioloop *ioloop;
	struct istream *input;
	const char *host, *const *destp;
	in_port_t port;

	if (net_str2hostport(client->set->submission_host,
			     DEFAULT_SUBMISSION_PORT, &host, &port) < 0) {
		*error_r = t_strdup_printf(
			"Invalid submission_host: %s", host);
		return -1;
	}

	memset(&client_set, 0, sizeof(client_set));
	client_set.mail_from = client->return_path == NULL ? "<>" :
		t_strconcat("<", client->return_path, ">", NULL);
	client_set.my_hostname = client->set->hostname;
	client_set.timeout_secs = timeout_secs;

	ioloop = io_loop_create();
	lmtp_client = lmtp_client_init(&client_set, smtp_client_send_finished,
				  client);

	if (lmtp_client_connect_tcp(lmtp_client, LMTP_CLIENT_PROTOCOL_SMTP,
				    host, port) < 0) {
		lmtp_client_deinit(&lmtp_client);
		io_loop_destroy(&ioloop);
		*error_r = t_strdup_printf("Couldn't connect to %s:%u",
					   host, port);
		return -1;
	}

	array_foreach(&client->destinations, destp) {
		lmtp_client_add_rcpt(lmtp_client, *destp, rcpt_to_callback,
				     data_callback, client);
	}

	input = i_stream_create_fd(client->temp_fd, (size_t)-1);
	lmtp_client_send(lmtp_client, input);
	i_stream_unref(&input);

	if (!client->finished)
		io_loop_run(ioloop);
	io_loop_destroy(&ioloop);

	if (client->success)
		return 1;
	else if (client->tempfail) {
		i_assert(client->error != NULL);
		*error_r = t_strdup(client->error);
		return -1;
	} else {
		i_assert(client->error != NULL);
		*error_r = t_strdup(client->error);
		return 0;
	}
}

static int
smtp_client_send_sendmail(struct smtp_client *client,
		       unsigned int timeout_secs, const char **error_r)
{
	const char *const *sendmail_args, *sendmail_bin, *str;
	ARRAY_TYPE(const_string) args;
	unsigned int i;
	struct program_client_settings pc_set;
	struct program_client *pc;
	struct istream *input;
	int ret;

	sendmail_args = t_strsplit(client->set->sendmail_path, " ");
	t_array_init(&args, 16);
	i_assert(sendmail_args[0] != NULL);
	sendmail_bin = sendmail_args[0];
	for (i = 1; sendmail_args[i] != NULL; i++)
		array_append(&args, &sendmail_args[i], 1);

	str = "-i"; array_append(&args, &str, 1); /* ignore dots */
	str = "-f"; array_append(&args, &str, 1);
	str = (client->return_path != NULL &&
		*client->return_path != '\0' ?
			client->return_path : "<>");
	array_append(&args, &str, 1);

	str = "--"; array_append(&args, &str, 1);
	array_append_array(&args, &client->destinations);
	array_append_zero(&args);

	memset(&pc_set, 0, sizeof(pc_set));
	pc_set.client_connect_timeout_msecs = timeout_secs * 1000;
	pc_set.input_idle_timeout_msecs = timeout_secs * 1000;
	restrict_access_init(&pc_set.restrict_set);

	pc = program_client_local_create
		(sendmail_bin, array_idx(&args, 0), &pc_set);

	input = i_stream_create_fd(client->temp_fd, (size_t)-1);
	program_client_set_input(pc, input);
	i_stream_unref(&input);

	ret = program_client_run(pc);

	program_client_destroy(&pc);

	if (ret < 0) {
		*error_r = "Failed to execute sendmail";
		return -1;
	} else if (ret == 0) {
		*error_r = "Sendmail program returned error";
		return -1;
	}
	return 1;
}

void smtp_client_abort(struct smtp_client **_client)
{
	struct smtp_client *client = *_client;

	*_client = NULL;

	o_stream_ignore_last_errors(client->output);
	o_stream_destroy(&client->output);
	pool_unref(&client->pool);
}

int smtp_client_deinit(struct smtp_client *client, const char **error_r)
{
	return smtp_client_deinit_timeout(client, 0, error_r);
}

int smtp_client_deinit_timeout(struct smtp_client *client,
			       unsigned int timeout_secs, const char **error_r)
{
	int ret;

	/* the mail has been written to a file. now actually send it. */

	if (o_stream_nfinish(client->output) < 0) {
		*error_r = t_strdup_printf("write(%s) failed: %s",
			client->temp_path, o_stream_get_error(client->output));
		return -1;
	}
	if (o_stream_seek(client->output, 0) < 0) {
		*error_r = t_strdup_printf("lseek(%s) failed: %s",
			client->temp_path, o_stream_get_error(client->output));
		return -1;
	}

	if (*client->set->submission_host != '\0') {
		ret = smtp_client_send_host
			(client, timeout_secs, error_r);
	} else {
		ret = smtp_client_send_sendmail
			(client, timeout_secs, error_r);
	}

	smtp_client_abort(&client);
	return ret;
}
