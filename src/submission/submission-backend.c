/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "llist.h"
#include "istream.h"
#include "istream-sized.h"

#include "submission-client.h"
#include "submission-commands.h"
#include "submission-backend.h"

void submission_backend_init(struct submission_backend *backend,
			     struct client *client,
			     const struct submission_backend_vfuncs *vfunc)
{
	backend->client = client;
	backend->v = *vfunc;

	client->backends_count++;
	DLLIST_PREPEND(&client->backends, backend);
}

static void submission_backend_destroy(struct submission_backend *backend)
{
	struct client *client = backend->client;

	i_stream_unref(&backend->data_input);

	DLLIST_REMOVE(&client->backends, backend);
	backend->v.destroy(backend);
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
	backend->v.start(backend);
	backend->started = TRUE;
}

void submission_backend_started(struct submission_backend *backend,
				enum smtp_capability caps)
{
	struct client *client = backend->client;

	if (backend == client->backend_default)
		client_default_backend_started(client, caps);
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

	if (backend->v.trans_start != NULL)
		backend->v.trans_start(backend, trans);
}

static void
submission_backend_trans_free(struct submission_backend *backend,
			      struct smtp_server_transaction *trans)
{
	i_stream_unref(&backend->data_input);
	if (backend->v.trans_free != NULL)
		backend->v.trans_free(backend, trans);
}

void submission_backends_trans_start(struct client *client,
				     struct smtp_server_transaction *trans)
{
	struct submission_backend *const *bkp;

	i_assert(client->state.backend != NULL);
	submission_backend_trans_start(client->state.backend, trans);

	array_foreach(&client->rcpt_backends, bkp) {
		struct submission_backend *backend = *bkp;
		submission_backend_trans_start(backend, trans);
	}
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
	array_clear(&client->rcpt_backends);
	client->state.backend = NULL;
}

int submission_backend_cmd_helo(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd,
				struct smtp_server_cmd_helo *data)
{
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
	submission_backend_start(backend);

	if (backend->v.cmd_mail == NULL) {
		/* mail backend is not interested, respond right away */
		return 1;
	}

	return backend->v.cmd_mail(backend, cmd, data);
}

int submission_backend_cmd_rcpt(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd,
				struct smtp_server_cmd_rcpt *data)
{
	if (backend->v.cmd_rcpt == NULL) {
		/* backend is not interested, respond right away */
		return 1;
	}

	return backend->v.cmd_rcpt(backend, cmd, data);
}

int submission_backend_cmd_rset(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd)
{
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
	if (backend->v.cmd_vrfy == NULL) {
		/* backend is not interested, respond right away */
		return 1;
	}
	return backend->v.cmd_vrfy(backend, cmd, param);
}

int submission_backend_cmd_noop(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd)
{
	if (backend->v.cmd_noop == NULL) {
		/* backend is not interested, respond right away */
		return 1;
	}
	return backend->v.cmd_noop(backend, cmd);
}

int submission_backend_cmd_quit(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd)
{
	if (backend->v.cmd_quit == NULL) {
		/* backend is not interested, respond right away */
		return 1;
	}
	return backend->v.cmd_quit(backend, cmd);
}
