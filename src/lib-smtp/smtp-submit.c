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

struct smtp_submit_session {
	pool_t pool;
	struct smtp_submit_settings set;
};

struct smtp_submit {
	pool_t pool;

	struct smtp_submit_session *session;

	struct ostream *output;
	struct istream *input;

	ARRAY_TYPE(const_string) destinations;
	const char *return_path;

	struct timeout *to_error;
	int status;
	const char *error;

	struct program_client *prg_client;
	struct lmtp_client *lmtp_client;

	smtp_submit_callback_t *callback;
	void *context;

	bool simple:1;
};

struct smtp_submit_session *
smtp_submit_session_init(const struct smtp_submit_settings *set)
{
	struct smtp_submit_session *session;
	pool_t pool;

	pool = pool_alloconly_create("smtp submit session", 128);
	session = p_new(pool, struct smtp_submit_session, 1);
	session->pool = pool;

	session->set = *set;
	session->set.hostname = p_strdup_empty(pool, set->hostname);
	session->set.submission_host = p_strdup_empty(pool, set->submission_host);
	session->set.sendmail_path = p_strdup_empty(pool, set->sendmail_path);
	return session;
}

void smtp_submit_session_deinit(struct smtp_submit_session **_session)
{
	struct smtp_submit_session *session = *_session;

	*_session = NULL;

	pool_unref(&session->pool);
}

struct smtp_submit *
smtp_submit_init(struct smtp_submit_session *session, const char *return_path)
{
	struct smtp_submit *subm;
	pool_t pool;

	pool = pool_alloconly_create("smtp submit", 256);
	subm = p_new(pool, struct smtp_submit, 1);
	subm->session = session;
	subm->pool = pool;

	subm->return_path = p_strdup(pool, return_path);
	p_array_init(&subm->destinations, pool, 2);
	return subm;
}

struct smtp_submit *
smtp_submit_init_simple(const struct smtp_submit_settings *set,
	const char *return_path)
{
	struct smtp_submit_session *session;
	struct smtp_submit *subm;

	session = smtp_submit_session_init(set);
	subm = smtp_submit_init(session, return_path);
	subm->simple = TRUE;
	return subm;
}

void smtp_submit_deinit(struct smtp_submit **_subm)
{
	struct smtp_submit *subm = *_subm;

	*_subm = NULL;

	if (subm->output != NULL) {
		o_stream_ignore_last_errors(subm->output);
		o_stream_destroy(&subm->output);
	}
	if (subm->input != NULL)
		i_stream_destroy(&subm->input);

	if (subm->prg_client != NULL)
		program_client_destroy(&subm->prg_client);
	if (subm->lmtp_client != NULL)
		lmtp_client_deinit(&subm->lmtp_client);

	if (subm->to_error != NULL)
		timeout_remove(&subm->to_error);

	if (subm->simple)
		 smtp_submit_session_deinit(&subm->session);
	pool_unref(&subm->pool);
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

static void
smtp_submit_callback(struct smtp_submit *subm, int status,
	const char *error)
{
	struct smtp_submit_result result;
	smtp_submit_callback_t *callback;

	if (subm->to_error != NULL)
		timeout_remove(&subm->to_error);

	i_zero(&result);
	result.status = status;
	result.error = error;

	callback = subm->callback;
	subm->callback = NULL;
	callback(&result, subm->context);
}

static void
smtp_submit_delayed_error_callback(struct smtp_submit *subm)
{
	smtp_submit_callback(subm, -1, subm->error);
}

static void
smtp_submit_delayed_error(struct smtp_submit *subm,
	const char *error)
{
	subm->status = -1;
	subm->error = p_strdup(subm->pool, error);
	subm->to_error = timeout_add_short(0,
		smtp_submit_delayed_error_callback, subm);
}

static void
smtp_submit_error(struct smtp_submit *subm,
	int status, const char *error)
{
	const struct smtp_submit_settings *set = &subm->session->set;
	i_assert(status <= 0);
	if (subm->error != NULL)
		return;

	subm->status = status;
	subm->error = p_strdup_printf(subm->pool,
		"smtp(%s): %s",
		set->submission_host, error);
}

static void
smtp_submit_success(struct smtp_submit *subm)
{
	if (subm->error != NULL)
		return;
	subm->status = 1;
}

static void
smtp_submit_send_host_finished(void *context)
{
	struct smtp_submit *subm = (struct smtp_submit *)context;

	i_assert(subm->status > 0 || subm->error != NULL);
	smtp_submit_callback(subm, subm->status, subm->error);
}

static void
rcpt_to_callback(enum lmtp_client_result result, const char *reply, void *context)
{
	struct smtp_submit *subm = (struct smtp_submit *)context;

	if (result != LMTP_CLIENT_RESULT_OK) {
		smtp_submit_error(subm,
			(reply[0] != '5' ? -1 : 0),
			t_strdup_printf("RCPT TO failed: %s", reply));
	}
}

static void
data_callback(enum lmtp_client_result result, const char *reply, void *context)
{
	struct smtp_submit *subm = (struct smtp_submit *)context;

	if (result != LMTP_CLIENT_RESULT_OK) {
		smtp_submit_error(subm,
			(reply[0] != '5' ? -1 : 0),
			t_strdup_printf("DATA failed: %s", reply));
		return;
	}

	smtp_submit_success(subm);
}

static void
smtp_submit_send_host(struct smtp_submit *subm)
{
	const struct smtp_submit_settings *set = &subm->session->set;
	struct lmtp_client_settings client_set;
	struct lmtp_client *lmtp_client;
	const char *host, *const *destp;
	in_port_t port;

	if (net_str2hostport(set->submission_host,
			DEFAULT_SUBMISSION_PORT, &host, &port) < 0) {
		smtp_submit_delayed_error(subm, t_strdup_printf(
			"Invalid submission_host: %s", host));
		return;
	}

	i_zero(&client_set);
	client_set.mail_from = subm->return_path == NULL ? "<>" :
		t_strconcat("<", subm->return_path, ">", NULL);
	client_set.my_hostname = set->hostname;
	client_set.timeout_secs = set->submission_timeout;

	lmtp_client = lmtp_client_init(&client_set,
		smtp_submit_send_host_finished, subm);

	if (lmtp_client_connect_tcp(lmtp_client, LMTP_CLIENT_PROTOCOL_SMTP,
				    host, port) < 0) {
		smtp_submit_delayed_error(subm, t_strdup_printf(
			"Couldn't connect to %s:%u", host, port));
		lmtp_client_deinit(&lmtp_client);
		return;
	}

	array_foreach(&subm->destinations, destp) {
		lmtp_client_add_rcpt(lmtp_client, *destp, rcpt_to_callback,
				     data_callback, subm);
	}

	subm->lmtp_client = lmtp_client;

	lmtp_client_send(lmtp_client, subm->input);
	i_stream_unref(&subm->input);
}

static void
smtp_submit_sendmail_callback(int status, struct smtp_submit *subm)
{
	if (status < 0) {
		smtp_submit_callback(subm, -1,
			"Failed to execute sendmail");
		return;
	}
	if (status == 0) {
		smtp_submit_callback(subm, -1,
			"Sendmail program returned error");
		return;
	}

	smtp_submit_callback(subm, 1, NULL);
}

static void
smtp_submit_send_sendmail(struct smtp_submit *subm)
{
	const struct smtp_submit_settings *set = &subm->session->set;
	const char *const *sendmail_args, *sendmail_bin, *str;
	ARRAY_TYPE(const_string) args;
	unsigned int i;
	struct program_client_settings pc_set;
	struct program_client *pc;

	sendmail_args = t_strsplit(set->sendmail_path, " ");
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
	pc_set.client_connect_timeout_msecs = set->submission_timeout * 1000;
	pc_set.input_idle_timeout_msecs = set->submission_timeout * 1000;
	restrict_access_init(&pc_set.restrict_set);

	pc = program_client_local_create
		(sendmail_bin, array_idx(&args, 0), &pc_set);

	program_client_set_input(pc, subm->input);
	i_stream_unref(&subm->input);

	subm->prg_client = pc;

	program_client_run_async(pc, smtp_submit_sendmail_callback, subm);
}

struct smtp_submit_run_context {
	int status;
	char *error;
};

static void
smtp_submit_run_callback(const struct smtp_submit_result *result,
	struct smtp_submit_run_context *rctx)
{
	rctx->error = i_strdup(result->error);
	rctx->status = result->status;
	io_loop_stop(current_ioloop);
}

int smtp_submit_run(struct smtp_submit *subm,
			       const char **error_r)
{
	struct smtp_submit_run_context rctx;
	struct ioloop *ioloop;

	ioloop = io_loop_create();
	io_loop_set_running(ioloop);

	i_zero(&rctx);
	smtp_submit_run_async(subm,
		smtp_submit_run_callback, &rctx);

	if (io_loop_is_running(ioloop))
		io_loop_run(ioloop);

	io_loop_destroy(&ioloop);

	if (rctx.error == NULL)
		*error_r = NULL;
	else {
		*error_r = t_strdup(rctx.error);
		i_free(rctx.error);
	}

	return rctx.status;
}

#undef smtp_submit_run_async
void smtp_submit_run_async(struct smtp_submit *subm,
			       smtp_submit_callback_t *callback, void *context)
{
	const struct smtp_submit_settings *set = &subm->session->set;

	subm->callback = callback;
	subm->context = context;

	/* the mail has been written to a file. now actually send it. */
	subm->input = iostream_temp_finish
		(&subm->output, IO_BLOCK_SIZE);

	if (set->submission_host != NULL) {
		smtp_submit_send_host(subm);
	} else {
		smtp_submit_send_sendmail(subm);
	}
}
