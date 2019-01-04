/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "llist.h"
#include "istream.h"
#include "istream-sized.h"

#include "submission-recipient.h"
#include "submission-client.h"
#include "submission-commands.h"
#include "submission-backend.h"

struct submission_backend_module_register
submission_backend_module_register = { 0 };

void submission_backend_init(struct submission_backend *backend,
			     pool_t pool, struct client *client,
			     const struct submission_backend_vfuncs *vfunc)
{
	backend->pool = pool;
	backend->client = client;
	backend->v = *vfunc;

	p_array_init(&backend->module_contexts, pool, 5);

	client->backends_count++;
	DLLIST_PREPEND(&client->backends, backend);
}

static void submission_backend_destroy(struct submission_backend *backend)
{
	struct client *client = backend->client;

	i_stream_unref(&backend->data_input);

	i_free(backend->fail_enh_code);
	i_free(backend->fail_reason);

	DLLIST_REMOVE(&client->backends, backend);
	backend->v.destroy(backend);
	pool_unref(&backend->pool);
}

void submission_backends_destroy_all(struct client *client)
{
	while (client->backends != NULL)
		submission_backend_destroy(client->backends);
	array_clear(&client->rcpt_backends);
	client->state.backend = NULL;
}

void submission_backend_start(struct submission_backend *backend)
{
	if (backend->started)
		return;
	if (backend->fail_reason != NULL) {
		/* Don't restart until failure is reset at transaction end */
		return;
	}
	backend->started = TRUE;
	backend->v.start(backend);
}

void submission_backend_started(struct submission_backend *backend,
				enum smtp_capability caps)
{
	struct client *client = backend->client;

	if (backend == client->backend_default)
		client_default_backend_started(client, caps);
	backend->ready = TRUE;
	if (backend->v.ready != NULL)
		backend->v.ready(backend, caps);
}

static void
submission_backend_fail_rcpts(struct submission_backend *backend)
{
	struct client *client = backend->client;
	struct submission_recipient *const *rcptp;
	const char *enh_code = backend->fail_enh_code;
	const char *reason = backend->fail_reason;

	i_assert(array_count(&client->rcpt_to) > 0);

	i_assert(reason != NULL);
	if (enh_code == NULL)
		enh_code = "4.0.0";

	array_foreach_modifiable(&client->rcpt_to, rcptp) {
		struct submission_recipient *rcpt = *rcptp;
		struct smtp_server_cmd_ctx *cmd = rcpt->rcpt->cmd;
		unsigned int index = 0;

		if (rcpt->backend != backend)
			continue;
		if (cmd == NULL)
			continue;

		if (smtp_server_command_get_reply_count(cmd->cmd) > 1)
			index = rcpt->rcpt->index;

		smtp_server_reply_index(cmd, index, 451,
					enh_code, "%s", reason);
	}
}

static inline void
submission_backend_reply_failure(struct submission_backend *backend,
				 struct smtp_server_cmd_ctx *cmd)
{
	const char *enh_code = backend->fail_enh_code;
	const char *reason = backend->fail_reason;

	if (enh_code == NULL)
		enh_code = "4.0.0";

	i_assert(smtp_server_command_get_reply_count(cmd->cmd) == 1);
	smtp_server_reply(cmd, 451, enh_code, "%s", reason);
}

static inline bool
submission_backend_handle_failure(struct submission_backend *backend,
				  struct smtp_server_cmd_ctx *cmd)
{
	if (backend->fail_reason == NULL)
		return TRUE;

	/* already failed */
	submission_backend_reply_failure(backend, cmd);
	return TRUE;
}

void submission_backend_fail(struct submission_backend *backend,
			     struct smtp_server_cmd_ctx *cmd,
			     const char *enh_code, const char *reason)
{
	struct client *client = backend->client;
	bool failed_before = (backend->fail_reason != NULL);

	/* Can be called several times */

	if (backend == client->backend_default) {
		/* default backend: fail the whole client */
		client_destroy(client, enh_code, reason);
		return;
	}

	/* Non-default backend for this transaction (maybe even for only
	   some of the approved recipients): fail only the affected
	   transaction and/or specific recipients. */

	/* Remember the failure only once */
	if (!failed_before) {
		backend->fail_enh_code = i_strdup(enh_code);
		backend->fail_reason = i_strdup(reason);
	}
	if (cmd == NULL) {
		/* Called outside command context: just remember the failure */
	} else if (smtp_server_command_get_reply_count(cmd->cmd) > 1) {
		/* Fail DATA/BDAT/BURL command expecting several replies */
		submission_backend_fail_rcpts(backend);
	} else {
		/* Single command */
		submission_backend_reply_failure(backend, cmd);
	}

	/* Call the fail vfunc only once */
	if (!failed_before && backend->v.fail != NULL)
		backend->v.fail(backend, enh_code, reason);
	backend->started = FALSE;
	backend->ready = FALSE;
}

void submission_backends_client_input_pre(struct client *client)
{
	struct submission_backend *backend;

	for (backend = client->backends; backend != NULL;
	     backend = backend->next) {
		if (!backend->started)
			continue;
		if (backend->v.client_input_pre != NULL)
			backend->v.client_input_pre(backend);

	}
}

void submission_backends_client_input_post(struct client *client)
{
	struct submission_backend *backend;

	for (backend = client->backends; backend != NULL;
	     backend = backend->next) {
		if (!backend->started)
			continue;
		if (backend->v.client_input_post != NULL)
			backend->v.client_input_post(backend);
	}
}

uoff_t submission_backend_get_max_mail_size(struct submission_backend *backend)
{
	if (backend->v.get_max_mail_size != NULL)
		return backend->v.get_max_mail_size(backend);
	return UOFF_T_MAX;
}

void submission_backend_trans_start(struct submission_backend *backend,
				    struct smtp_server_transaction *trans)
{
	submission_backend_start(backend);

	if (backend->trans_started)
		return;
	backend->trans_started = TRUE;

	if (backend->v.trans_start != NULL) {
		backend->v.trans_start(backend, trans,
				       trans->mail_from, &trans->params);
	}
}

static void
submission_backend_trans_free(struct submission_backend *backend,
			      struct smtp_server_transaction *trans)
{
	i_stream_unref(&backend->data_input);
	if (backend->v.trans_free != NULL)
		backend->v.trans_free(backend, trans);
	backend->trans_started = FALSE;

	i_free(backend->fail_enh_code);
	i_free(backend->fail_reason);
}

void submission_backends_trans_start(struct client *client,
				     struct smtp_server_transaction *trans)
{
	struct submission_backend *const *bkp;

	i_assert(client->state.backend != NULL);
	submission_backend_trans_start(client->state.backend, trans);

	array_foreach(&client->pending_backends, bkp) {
		struct submission_backend *backend = *bkp;

		submission_backend_trans_start(backend, trans);
	}
	array_clear(&client->pending_backends);
}

void submission_backends_trans_free(struct client *client,
				     struct smtp_server_transaction *trans)
{
	struct submission_backend *const *bkp;

	i_assert(client->state.backend != NULL ||
		 array_count(&client->rcpt_backends) == 0);

	array_foreach(&client->rcpt_backends, bkp) {
		struct submission_backend *backend = *bkp;
		submission_backend_trans_free(backend, trans);
	}
	array_clear(&client->pending_backends);
	array_clear(&client->rcpt_backends);
	client->state.backend = NULL;
}

int submission_backend_cmd_helo(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd,
				struct smtp_server_cmd_helo *data)
{
	/* failure on default backend closes the client connection */
	i_assert(backend->fail_reason == NULL);

	if (!backend->started || backend->v.cmd_helo == NULL) {
		/* default backend is not interested, respond right away */
		submission_helo_reply_submit(cmd, data);
		return 1;
	}

	return backend->v.cmd_helo(backend, cmd, data);
}

void submission_backend_helo_reply_submit(
	struct submission_backend *backend ATTR_UNUSED,
	struct smtp_server_cmd_ctx *cmd, struct smtp_server_cmd_helo *data)
{
	submission_helo_reply_submit(cmd, data);
}

int submission_backend_cmd_mail(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd,
				struct smtp_server_cmd_mail *data)
{
	if (!submission_backend_handle_failure(backend, cmd))
		return -1;

	submission_backend_start(backend);

	if (backend->v.cmd_mail == NULL) {
		/* mail backend is not interested, respond right away */
		return 1;
	}

	return backend->v.cmd_mail(backend, cmd, data);
}

static void
submission_backend_add_pending(struct submission_backend *backend)
{
	struct client *client = backend->client;

	struct submission_backend *const *bkp;

	array_foreach(&client->pending_backends, bkp) {
		if (backend == *bkp)
			return;
	}

	array_push_back(&client->pending_backends, &backend);
}

int submission_backend_cmd_rcpt(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd,
				struct submission_recipient *srcpt)
{
	struct smtp_server_transaction *trans;

	if (!submission_backend_handle_failure(backend, cmd))
		return -1;

	i_assert(backend->started);

	if (backend->v.cmd_rcpt == NULL) {
		/* backend is not interested, respond right away */
		return 1;
	}

	trans = smtp_server_connection_get_transaction(cmd->conn);
	if (trans != NULL)
		submission_backend_trans_start(srcpt->backend, trans);
	else
		submission_backend_add_pending(srcpt->backend);

	return backend->v.cmd_rcpt(backend, cmd, srcpt);
}

int submission_backend_cmd_rset(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd)
{
	if (!submission_backend_handle_failure(backend, cmd))
		return -1;

	submission_backend_start(backend);

	if (backend->v.cmd_rset == NULL) {
		/* backend is not interested, respond right away */
		return 1;
	}
	return backend->v.cmd_rset(backend, cmd);
}

static int
submission_backend_cmd_data(struct submission_backend *backend,
			    struct smtp_server_cmd_ctx *cmd,
			    struct smtp_server_transaction *trans)
{
	if (backend->fail_reason != NULL) {
		submission_backend_fail_rcpts(backend);
		return 0;
	}

	i_assert(backend->started);

	return backend->v.cmd_data(backend, cmd, trans,
				   backend->data_input, backend->data_size);
}

int submission_backends_cmd_data(struct client *client,
				 struct smtp_server_cmd_ctx *cmd,
				 struct smtp_server_transaction *trans,
				 struct istream *data_input, uoff_t data_size)
{
	struct submission_backend *const *bkp;
	int ret = 0;

	i_assert(array_count(&client->rcpt_backends) > 0);

	/* create the data_input streams first */
	array_foreach_modifiable(&client->rcpt_backends, bkp) {
		struct submission_backend *backend = *bkp;

		backend->data_input =
			i_stream_create_sized(data_input, data_size);
		backend->data_size = data_size;
	}

	/* now that all the streams are created, start reading them
	   (reading them earlier could have caused the data_input parent's
	   offset to change) */
	array_foreach_modifiable(&client->rcpt_backends, bkp) {
		struct submission_backend *backend = *bkp;

		ret = submission_backend_cmd_data(backend, cmd, trans);
		if (ret < 0)
			break;
	}

	return ret;
}

int submission_backend_cmd_vrfy(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd,
				const char *param)
{
	/* failure on default backend closes the client connection */
	i_assert(backend->fail_reason == NULL);

	submission_backend_start(backend);

	if (backend->v.cmd_vrfy == NULL) {
		/* backend is not interested, respond right away */
		return 1;
	}
	return backend->v.cmd_vrfy(backend, cmd, param);
}

int submission_backend_cmd_noop(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd)
{
	/* failure on default backend closes the client connection */
	i_assert(backend->fail_reason == NULL);

	submission_backend_start(backend);

	if (backend->v.cmd_noop == NULL) {
		/* backend is not interested, respond right away */
		return 1;
	}
	return backend->v.cmd_noop(backend, cmd);
}

int submission_backend_cmd_quit(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd)
{
	/* failure on default backend closes the client connection */
	i_assert(backend->fail_reason == NULL);

	if (!backend->started) {
		/* quit before backend even started */
		return 1;
	}
	if (backend->v.cmd_quit == NULL) {
		/* backend is not interested, respond right away */
		return 1;
	}
	return backend->v.cmd_quit(backend, cmd);
}
