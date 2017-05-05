/* Copyright (c) 2006-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-temp.h"
#include "master-service.h"
#include "program-client.h"
#include "lmtp-client.h"
#include "smtp-submit.h"

#include <unistd.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <signal.h>

#define DEFAULT_SUBMISSION_PORT 25

struct smtp_submit {
	pool_t pool;
	struct ostream *output;
	struct istream *input;

	struct smtp_submit_settings set;
	ARRAY_TYPE(const_string) destinations;
	const char *return_path;
	const char *error;

	bool success:1;
	bool finished:1;
	bool tempfail:1;
};

struct smtp_submit *
smtp_submit_init(const struct smtp_submit_settings *set, const char *return_path)
{
	struct smtp_submit *subm;
	pool_t pool;

	pool = pool_alloconly_create("smtp submit", 256);
	subm = p_new(pool, struct smtp_submit, 1);
	subm->pool = pool;

	subm->set.hostname = p_strdup_empty(pool, set->hostname);
	subm->set.submission_host = p_strdup_empty(pool, set->submission_host);
	subm->set.sendmail_path = p_strdup_empty(pool, set->sendmail_path);

	subm->return_path = p_strdup(pool, return_path);
	p_array_init(&subm->destinations, pool, 2);
	return subm;
}

void smtp_submit_add_rcpt(struct smtp_submit *subm, const char *address)
{
	i_assert(subm->output == NULL);

	address = p_strdup(subm->pool, address);
	array_append(&subm->destinations, &address, 1);
}

struct ostream *smtp_submit_send(struct smtp_submit *subm)
{
	i_assert(subm->output == NULL);
	i_assert(array_count(&subm->destinations) > 0);

	subm->output = iostream_temp_create
		(t_strconcat("/tmp/dovecot.",
			master_service_get_name(master_service), NULL), 0);
	o_stream_set_no_error_handling(subm->output, TRUE);
	return subm->output;
}

static void smtp_submit_send_finished(void *context)
{
	struct smtp_submit *smtp_submit = context;

	smtp_submit->finished = TRUE;
	io_loop_stop(current_ioloop);
}

static void
smtp_submit_error(struct smtp_submit *subm,
		 bool tempfail, const char *error)
{
	if (subm->error == NULL) {
		subm->tempfail = tempfail;
		subm->error = p_strdup_printf(subm->pool,
			"smtp(%s): %s",
			subm->set.submission_host, error);
	}
}

static void
rcpt_to_callback(enum lmtp_client_result result, const char *reply, void *context)
{
	struct smtp_submit *subm = context;

	if (result != LMTP_CLIENT_RESULT_OK) {
		smtp_submit_error(subm, (reply[0] != '5'),
			t_strdup_printf("RCPT TO failed: %s", reply));
		smtp_submit_send_finished(subm);
	}
}

static void
data_callback(enum lmtp_client_result result, const char *reply, void *context)
{
	struct smtp_submit *subm = context;

	if (result != LMTP_CLIENT_RESULT_OK) {
		smtp_submit_error(subm, (reply[0] != '5'),
			t_strdup_printf("DATA failed: %s", reply));
		smtp_submit_send_finished(subm);
	} else {
		subm->success = TRUE;
	}
}

static int
smtp_submit_send_host(struct smtp_submit *subm,
		       unsigned int timeout_secs, const char **error_r)
{
	struct lmtp_client_settings client_set;
	struct lmtp_client *lmtp_client;
	struct ioloop *ioloop;
	const char *host, *const *destp;
	in_port_t port;

	if (net_str2hostport(subm->set.submission_host,
			     DEFAULT_SUBMISSION_PORT, &host, &port) < 0) {
		*error_r = t_strdup_printf(
			"Invalid submission_host: %s", host);
		return -1;
	}

	i_zero(&client_set);
	client_set.mail_from = subm->return_path == NULL ? "<>" :
		t_strconcat("<", subm->return_path, ">", NULL);
	client_set.my_hostname = subm->set.hostname;
	client_set.timeout_secs = timeout_secs;

	ioloop = io_loop_create();
	lmtp_client = lmtp_client_init(&client_set, smtp_submit_send_finished,
				  subm);

	if (lmtp_client_connect_tcp(lmtp_client, LMTP_CLIENT_PROTOCOL_SMTP,
				    host, port) < 0) {
		lmtp_client_deinit(&lmtp_client);
		io_loop_destroy(&ioloop);
		*error_r = t_strdup_printf("Couldn't connect to %s:%u",
					   host, port);
		return -1;
	}

	array_foreach(&subm->destinations, destp) {
		lmtp_client_add_rcpt(lmtp_client, *destp, rcpt_to_callback,
				     data_callback, subm);
	}

	lmtp_client_send(lmtp_client, subm->input);
	i_stream_unref(&subm->input);

	if (!subm->finished)
		io_loop_run(ioloop);
	lmtp_client_deinit(&lmtp_client);
	io_loop_destroy(&ioloop);

	if (subm->success)
		return 1;
	else if (subm->tempfail) {
		i_assert(subm->error != NULL);
		*error_r = t_strdup(subm->error);
		return -1;
	} else {
		i_assert(subm->error != NULL);
		*error_r = t_strdup(subm->error);
		return 0;
	}
}

static int
smtp_submit_send_sendmail(struct smtp_submit *subm,
		       unsigned int timeout_secs, const char **error_r)
{
	const char *const *sendmail_args, *sendmail_bin, *str;
	ARRAY_TYPE(const_string) args;
	unsigned int i;
	struct program_client_settings pc_set;
	struct program_client *pc;
	int ret;

	sendmail_args = t_strsplit(subm->set.sendmail_path, " ");
	t_array_init(&args, 16);
	i_assert(sendmail_args[0] != NULL);
	sendmail_bin = sendmail_args[0];
	for (i = 1; sendmail_args[i] != NULL; i++)
		array_append(&args, &sendmail_args[i], 1);

	str = "-i"; array_append(&args, &str, 1); /* ignore dots */
	str = "-f"; array_append(&args, &str, 1);
	str = (subm->return_path != NULL &&
		*subm->return_path != '\0' ?
			subm->return_path : "<>");
	array_append(&args, &str, 1);

	str = "--"; array_append(&args, &str, 1);
	array_append_array(&args, &subm->destinations);
	array_append_zero(&args);

	i_zero(&pc_set);
	pc_set.client_connect_timeout_msecs = timeout_secs * 1000;
	pc_set.input_idle_timeout_msecs = timeout_secs * 1000;
	restrict_access_init(&pc_set.restrict_set);

	pc = program_client_local_create
		(sendmail_bin, array_idx(&args, 0), &pc_set);

	program_client_set_input(pc, subm->input);
	i_stream_unref(&subm->input);

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

void smtp_submit_abort(struct smtp_submit **_subm)
{
	struct smtp_submit *subm = *_subm;

	*_subm = NULL;

	if (subm->output != NULL) {
		o_stream_ignore_last_errors(subm->output);
		o_stream_destroy(&subm->output);
	}
	if (subm->input != NULL)
		i_stream_destroy(&subm->input);
	pool_unref(&subm->pool);
}

int smtp_submit_deinit(struct smtp_submit *subm, const char **error_r)
{
	return smtp_submit_deinit_timeout(subm, 0, error_r);
}

int smtp_submit_deinit_timeout(struct smtp_submit *subm,
			       unsigned int timeout_secs, const char **error_r)
{
	int ret;

	/* the mail has been written to a file. now actually send it. */
	subm->input = iostream_temp_finish
		(&subm->output, IO_BLOCK_SIZE);

	if (subm->set.submission_host != NULL) {
		ret = smtp_submit_send_host
			(subm, timeout_secs, error_r);
	} else {
		ret = smtp_submit_send_sendmail
			(subm, timeout_secs, error_r);
	}

	smtp_submit_abort(&subm);
	return ret;
}
