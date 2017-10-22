/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "array.h"
#include "time-util.h"
#include "hostpid.h"
#include "var-expand.h"
#include "ioloop.h"
#include "restrict-access.h"
#include "anvil-client.h"
#include "settings-parser.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "mail-namespace.h"
#include "mail-deliver.h"
#include "mail-autoexpunge.h"
#include "index/raw/raw-storage.h"
#include "master-service.h"
#include "smtp-address.h"
#include "smtp-submit-settings.h"
#include "lda-settings.h"
#include "lmtp-settings.h"
#include "client.h"
#include "main.h"
#include "lmtp-local.h"

#define ERRSTR_TEMP_MAILBOX_FAIL "451 4.3.0 <%s> Temporary internal error"
#define ERRSTR_TEMP_USERDB_FAIL_PREFIX "451 4.3.0 <%s> "

struct lmtp_local_recipient {
	struct lmtp_recipient rcpt;
	char *session_id;

	char *detail;

	struct mail_storage_service_user *service_user;
	struct anvil_query *anvil_query;

	bool anvil_connect_sent:1;
};

struct lmtp_local {
	struct client *client;

	ARRAY(struct lmtp_local_recipient *) rcpt_to;

	struct mail *raw_mail, *first_saved_mail;
	struct mail_user *rcpt_user;
};

static void
lmtp_local_rcpt_deinit(struct lmtp_local_recipient *rcpt);

/*
 * LMTP local
 */

static struct lmtp_local *
lmtp_local_init(struct client *client)
{
	struct lmtp_local *local;

	local = i_new(struct lmtp_local, 1);
	local->client = client;
	i_array_init(&local->rcpt_to, 8);

	return local;
}

void lmtp_local_deinit(struct lmtp_local **_local)
{
	struct lmtp_local *local = *_local;
	struct lmtp_local_recipient *const *rcptp;

	*_local = NULL;

	if (array_is_created(&local->rcpt_to)) {
		array_foreach_modifiable(&local->rcpt_to, rcptp)
			lmtp_local_rcpt_deinit(*rcptp);
		array_free(&local->rcpt_to);
	}

	if (local->raw_mail != NULL) {
		struct mailbox_transaction_context *raw_trans =
			local->raw_mail->transaction;
		struct mailbox *raw_box = local->raw_mail->box;

		mail_free(&local->raw_mail);
		mailbox_transaction_rollback(&raw_trans);
		mailbox_free(&raw_box);
	}

	i_free(local);
}

/*
 * Recipient
 */

unsigned int lmtp_local_rcpt_count(struct client *client)
{
	if (client->local == NULL)
		return 0;
	return array_count(&client->local->rcpt_to);
}

static void
lmtp_local_rcpt_anvil_disconnect(struct lmtp_local_recipient *rcpt)
{
	const struct mail_storage_service_input *input;

	if (!rcpt->anvil_connect_sent)
		return;

	input = mail_storage_service_user_get_input(rcpt->service_user);
	master_service_anvil_send(master_service, t_strconcat(
		"DISCONNECT\t", my_pid, "\t", master_service_get_name(master_service),
		"/", input->username, "\n", NULL));
}

void lmtp_local_rcpt_deinit(struct lmtp_local_recipient *rcpt)
{
	if (rcpt->anvil_query != NULL)
		anvil_client_query_abort(anvil, &rcpt->anvil_query);
	lmtp_local_rcpt_anvil_disconnect(rcpt);
	mail_storage_service_user_unref(&rcpt->service_user);

	i_free(rcpt->session_id);
	i_free(rcpt->detail);
	i_free(rcpt);
}

static void
lmtp_local_rcpt_reply_overquota(struct lmtp_local_recipient *rcpt,
				const char *error)
{
	struct client *client = rcpt->rcpt.client;
	struct lda_settings *lda_set =
		mail_storage_service_user_get_set(rcpt->service_user)[2];

	client_send_line(client, "%s <%s> %s",
		lda_set->quota_full_tempfail ? "452 4.2.2" : "552 5.2.2",
		smtp_address_encode(rcpt->rcpt.address), error);
}

static void
lmtp_local_rcpt_fail_all(struct lmtp_local *local)
{
	struct lmtp_local_recipient *const *rcptp;

	array_foreach(&local->rcpt_to, rcptp) {
		client_send_line(local->client, ERRSTR_TEMP_MAILBOX_FAIL,
				 smtp_address_encode((*rcptp)->rcpt.address));
	}
}

/*
 * RCPT command
 */

static int
lmtp_local_rcpt_check_quota(struct lmtp_local_recipient *rcpt)
{
	struct client *client = rcpt->rcpt.client;
	struct smtp_address *address = rcpt->rcpt.address;
	struct mail_user *user;
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mailbox_status status;
	enum mail_error mail_error;
	const char *error;
	int ret;

	if (!client->lmtp_set->lmtp_rcpt_check_quota)
		return 0;

	/* mail user will be created second time when mail is saved,
	   so it's session_id needs to be different,
	   but second time session_id needs to be the same as rcpt session_id and
	   mail user session id for the first rcpt should not overlap with session id
	   of the second recipient, so add custom ":quota" suffix to the session_id without
	   session_id counter increment, so next time mail user will get
	   the same session id as rcpt */
	ret = mail_storage_service_next_with_session_suffix(storage_service,
							    rcpt->service_user,
							    "quota",
							    &user, &error);

	if (ret < 0) {
		i_error("Failed to initialize user %s: %s",
			smtp_address_encode(address), error);
		ret = -1;
	} else {
		ns = mail_namespace_find_inbox(user->namespaces);
		box = mailbox_alloc(ns->list, "INBOX", 0);
		mailbox_set_reason(box, "over-quota check");
		ret = mailbox_get_status(box, STATUS_CHECK_OVER_QUOTA, &status);
		if (ret < 0) {
			error = mailbox_get_last_error(box, &mail_error);
			if (mail_error == MAIL_ERROR_NOQUOTA) {
				lmtp_local_rcpt_reply_overquota(rcpt, error);
				ret = 0;
			} else {
				i_error("mailbox_get_status(%s, STATUS_CHECK_OVER_QUOTA) "
					"failed: %s",
					mailbox_get_vname(box),
					mailbox_get_last_internal_error(box, NULL));
			}
		}
		mailbox_free(&box);
		mail_user_unref(&user);
	}

	if (ret < 0) {
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
				 smtp_address_encode(address));
	}
	return ret;
}

static bool
lmtp_local_rcpt_anvil_finish(struct lmtp_local_recipient *rcpt)
{
	struct client *client = rcpt->rcpt.client;
	int ret;

	if ((ret = lmtp_local_rcpt_check_quota(rcpt)) < 0) {
		mail_storage_service_user_unref(&rcpt->service_user);
		return FALSE;
	}
	array_append(&client->local->rcpt_to, &rcpt, 1);
	client_send_line(client, "250 2.1.5 OK");
	return TRUE;
}

static void
lmtp_local_rcpt_anvil_cb(const char *reply, void *context)
{
	struct lmtp_local_recipient *rcpt = context;
	struct client *client = rcpt->rcpt.client;
	const struct mail_storage_service_input *input;
	unsigned int parallel_count = 0;

	rcpt->anvil_query = NULL;
	if (reply == NULL) {
		/* lookup failed */
	} else if (str_to_uint(reply, &parallel_count) < 0) {
		i_error("Invalid reply from anvil: %s", reply);
	}

	if (parallel_count >= client->lmtp_set->lmtp_user_concurrency_limit) {
		client_send_line(client, ERRSTR_TEMP_USERDB_FAIL_PREFIX
				 "Too many concurrent deliveries for user",
				 smtp_address_encode(rcpt->rcpt.address));
		mail_storage_service_user_unref(&rcpt->service_user);
	} else if (lmtp_local_rcpt_anvil_finish(rcpt)) {
		rcpt->anvil_connect_sent = TRUE;
		input = mail_storage_service_user_get_input(rcpt->service_user);
		master_service_anvil_send(master_service, t_strconcat(
			"CONNECT\t", my_pid, "\t", master_service_get_name(master_service),
			"/", input->username, "\n", NULL));
	}

	client_io_reset(client);
	client_input_handle(client);
}

int lmtp_local_rcpt(struct client *client,
	struct smtp_address *address,
	const char *username, const char *detail,
	const struct smtp_params_rcpt *params)
{
	struct lmtp_local_recipient *rcpt;
	struct mail_storage_service_input input;
	struct mail_storage_service_user *service_user;
	const char *session_id, *error = NULL;
	int ret;

	/* Use a unique session_id for each mail delivery. This is especially
	   important for stats process to not see duplicate sessions. */
	if (client_get_rcpt_count(client) == 0)
		session_id = client->state.session_id;
	else {
		session_id =
			t_strdup_printf("%s:%u", client->state.session_id,
					client_get_rcpt_count(client)+1);
	}

	i_zero(&input);
	input.module = input.service = "lmtp";
	input.username = username;
	input.local_ip = client->local_ip;
	input.remote_ip = client->remote_ip;
	input.local_port = client->local_port;
	input.remote_port = client->remote_port;
	input.session_id = session_id;

	ret = mail_storage_service_lookup(storage_service, &input,
					  &service_user, &error);

	if (ret < 0) {
		i_error("Failed to lookup user %s: %s", username, error);
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
			smtp_address_encode(address));
		return 0;
	}
	if (ret == 0) {
		client_send_line(client,
				 "550 5.1.1 <%s> User doesn't exist: %s",
				 smtp_address_encode(address), username);
		return 0;
	}
	if (client->proxy != NULL) {
		/* NOTE: if this restriction is ever removed, we'll also need
		   to send different message bodies to local and proxy
		   (with and without Return-Path: header) */
		client_send_line(client, "451 4.3.0 <%s> "
			"Can't handle mixed proxy/non-proxy destinations",
			smtp_address_encode(address));
		mail_storage_service_user_unref(&service_user);
		return 0;
	}

	if (client->local == NULL)
		client->local = lmtp_local_init(client);

	rcpt = i_new(struct lmtp_local_recipient, 1);
	rcpt->rcpt.client = client;
	rcpt->rcpt.address = smtp_address_clone(client->state_pool, address); 
	smtp_params_rcpt_copy(client->state_pool, &rcpt->rcpt.params, params);
	rcpt->detail = i_strdup(detail);
	rcpt->service_user = service_user;
	rcpt->session_id = i_strdup(session_id);

	if (client->lmtp_set->lmtp_user_concurrency_limit == 0) {
		(void)lmtp_local_rcpt_anvil_finish(rcpt);
		return 0;
	} else {
		/* NOTE: username may change as the result of the userdb
		   lookup. Look up the new one via service_user. */
		const struct mail_storage_service_input *input =
			mail_storage_service_user_get_input(rcpt->service_user);
		const char *query = t_strconcat("LOOKUP\t",
			master_service_get_name(master_service),
			"/", str_tabescape(input->username), NULL);
		io_remove(&client->io);
		rcpt->anvil_query = anvil_client_query(anvil, query,
			lmtp_local_rcpt_anvil_cb, rcpt);
		/* stop processing further commands while anvil query is
		   pending */
		return rcpt->anvil_query == NULL ? 0 : -1;
	}
}

/*
 * DATA command
 */

void lmtp_local_add_headers(struct lmtp_local *local,
			    string_t *headers)
{
	struct client *client = local->client;
	struct lmtp_local_recipient *const *rcpts;
	const struct lmtp_settings *lmtp_set;
	const struct smtp_address *rcpt_to = NULL;
	unsigned int count;
	void **sets;

	str_printfa(headers, "Return-Path: <%s>\r\n",
		    smtp_address_encode(client->state.mail_from));

	rcpts = array_get(&local->rcpt_to, &count);
	if (count == 1) {
		sets = mail_storage_service_user_get_set(rcpts[0]->service_user);
		lmtp_set = sets[3];

		switch (lmtp_set->parsed_lmtp_hdr_delivery_address) {
		case LMTP_HDR_DELIVERY_ADDRESS_NONE:
			break;
		case LMTP_HDR_DELIVERY_ADDRESS_FINAL:
			rcpt_to = rcpts[0]->rcpt.address;
			break;
		case LMTP_HDR_DELIVERY_ADDRESS_ORIGINAL:
			rcpt_to = rcpts[0]->rcpt.params.orcpt.addr;
			break;
		}
	}
	if (rcpt_to != NULL) {
		str_printfa(headers, "Delivered-To: %s\r\n",
			smtp_address_encode(rcpt_to));
	}
}

static int
lmtp_local_deliver(struct lmtp_local *local,
		   struct lmtp_local_recipient *rcpt,
		   struct mail *src_mail,
		   struct mail_deliver_session *session)
{
	struct client *client = local->client;
	struct mail_storage_service_user *service_user = rcpt->service_user;
	struct mail_deliver_context dctx;
	struct mail_user *rcpt_user;
	struct mail_storage *storage;
	const struct mail_storage_service_input *input;
	const struct mail_storage_settings *mail_set;
	struct smtp_submit_settings *smtp_set;
	struct lda_settings *lda_set;
	struct mail_namespace *ns;
	struct setting_parser_context *set_parser;
	const struct var_expand_table *var_table;
	struct timeval delivery_time_started;
	void **sets;
	const char *line, *error, *username;
	string_t *str;
	enum mail_error mail_error;
	int ret;

	input = mail_storage_service_user_get_input(service_user);
	username = t_strdup(input->username);

	mail_set = mail_storage_service_user_get_mail_set(service_user);
	set_parser = mail_storage_service_user_get_settings_parser(service_user);
	if (client->proxy_timeout_secs > 0 &&
	    (mail_set->mail_max_lock_timeout == 0 ||
	     mail_set->mail_max_lock_timeout > client->proxy_timeout_secs)) {
		/* set lock timeout waits to be less than when proxy has
		   advertised that it's going to timeout the connection.
		   this avoids duplicate deliveries in case the delivery
		   succeeds after the proxy has already disconnected from us. */
		line = t_strdup_printf("mail_max_lock_timeout=%us",
				       client->proxy_timeout_secs <= 1 ? 1 :
				       client->proxy_timeout_secs-1);
		if (settings_parse_line(set_parser, line) < 0)
			i_unreached();
	}

	/* get the timestamp before user is created, since it starts the I/O */
	io_loop_time_refresh();
	delivery_time_started = ioloop_timeval;

	client_state_set(client, "DATA", username);
	i_set_failure_prefix("lmtp(%s, %s): ", my_pid, username);
	if (mail_storage_service_next(storage_service, service_user,
				      &rcpt_user, &error) < 0) {
		i_error("Failed to initialize user: %s", error);
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
				 smtp_address_encode(rcpt->rcpt.address));
		return -1;
	}
	local->rcpt_user = rcpt_user;

	sets = mail_storage_service_user_get_set(service_user);
	var_table = mail_user_var_expand_table(rcpt_user);
	smtp_set = sets[1];
	lda_set = sets[2];
	ret = settings_var_expand(
		&smtp_submit_setting_parser_info,
		smtp_set, client->pool, var_table,
		&error);
	if (ret > 0) {
		ret = settings_var_expand(
			&lda_setting_parser_info,
			lda_set, client->pool, var_table,
			&error);
	}
	if (ret <= 0) {
		i_error("Failed to expand settings: %s", error);
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
				 smtp_address_encode(rcpt->rcpt.address));
		return -1;
	}

	str = t_str_new(256);
	if (var_expand_with_funcs(str, rcpt_user->set->mail_log_prefix,
				  var_table, mail_user_var_expand_func_table,
				  rcpt_user, &error) <= 0) {
		i_error("Failed to expand mail_log_prefix=%s: %s",
			rcpt_user->set->mail_log_prefix, error);
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
				 smtp_address_encode(rcpt->rcpt.address));
		return -1;
	}
	i_set_failure_prefix("%s", str_c(str));

	i_zero(&dctx);
	dctx.session = session;
	dctx.pool = session->pool;
	dctx.set = lda_set;
	dctx.smtp_set = smtp_set;
	dctx.session_id = rcpt->session_id;
	dctx.src_mail = src_mail;

	/* MAIL FROM */
	dctx.mail_from = client->state.mail_from;
	dctx.mail_params = client->state.mail_params;

	/* RCPT TO */
	dctx.rcpt_user = rcpt_user;
	dctx.rcpt_params = rcpt->rcpt.params;
	if (dctx.rcpt_params.orcpt.addr != NULL) {
		/* used ORCPT */
	} else if (*dctx.set->lda_original_recipient_header != '\0') {
		dctx.rcpt_params.orcpt.addr = mail_deliver_get_address(src_mail,
				dctx.set->lda_original_recipient_header);
	}
	if (dctx.rcpt_params.orcpt.addr == NULL)
		dctx.rcpt_params.orcpt.addr = rcpt->rcpt.address;
	dctx.rcpt_to = rcpt->rcpt.address;
	if (*rcpt->detail == '\0' ||
	    !client->lmtp_set->lmtp_save_to_detail_mailbox)
		dctx.rcpt_default_mailbox = "INBOX";
	else {
		ns = mail_namespace_find_inbox(rcpt_user->namespaces);
		dctx.rcpt_default_mailbox =
			t_strconcat(ns->prefix, rcpt->detail, NULL);
	}

	dctx.save_dest_mail = array_count(&local->rcpt_to) > 1 &&
		local->first_saved_mail == NULL;

	dctx.session_time_msecs =
		timeval_diff_msecs(&client->state.data_end_timeval,
				   &client->state.mail_from_timeval);
	dctx.delivery_time_started = delivery_time_started;

	if (mail_deliver(&dctx, &storage) == 0) {
		if (dctx.dest_mail != NULL) {
			i_assert(local->first_saved_mail == NULL);
			local->first_saved_mail = dctx.dest_mail;
		}
		client_send_line(client, "250 2.0.0 <%s> %s Saved",
				 smtp_address_encode(rcpt->rcpt.address),
				 rcpt->session_id);
		ret = 0;
	} else if (dctx.tempfail_error != NULL) {
		client_send_line(client, "451 4.2.0 <%s> %s",
				 smtp_address_encode(rcpt->rcpt.address),
				 dctx.tempfail_error);
		ret = -1;
	} else if (storage != NULL) {
		error = mail_storage_get_last_error(storage, &mail_error);
		if (mail_error == MAIL_ERROR_NOQUOTA) {
			lmtp_local_rcpt_reply_overquota(rcpt, error);
		} else {
			client_send_line(client, "451 4.2.0 <%s> %s",
					 smtp_address_encode(rcpt->rcpt.address), error);
		}
		ret = -1;
	} else {
		/* This shouldn't happen */
		i_error("BUG: Saving failed to unknown storage");
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
				 smtp_address_encode(rcpt->rcpt.address));
		ret = -1;
	}
	return ret;
}

static uid_t
lmtp_local_deliver_to_rcpts(struct lmtp_local *local,
			    struct mail_deliver_session *session)
{
	struct client *client = local->client;
	uid_t first_uid = (uid_t)-1;
	struct mail *src_mail;
	struct lmtp_local_recipient *const *rcpts;
	unsigned int count, i;
	int ret;

	src_mail = local->raw_mail;

	rcpts = array_get(&local->rcpt_to, &count);
	for (i = 0; i < count; i++) {
		struct lmtp_local_recipient *rcpt = rcpts[i];

		ret = lmtp_local_deliver(local, rcpt,
				     src_mail, session);
		client_state_set(client, "DATA", "");
		i_set_failure_prefix("lmtp(%s): ", my_pid);

		/* succeeded and mail_user is not saved in first_saved_mail */
		if ((ret == 0 &&
		     (local->first_saved_mail == NULL ||
		      local->first_saved_mail == src_mail)) ||
		    /* failed. try the next one. */
		    (ret != 0 && local->rcpt_user != NULL)) {
			if (i == (count - 1))
				mail_user_autoexpunge(local->rcpt_user);
			mail_user_unref(&local->rcpt_user);
		} else if (ret == 0) {
			/* use the first saved message to save it elsewhere too.
			   this might allow hard linking the files.
			   mail_user is saved in first_saved_mail,
			   will be unreferenced later on */
			local->rcpt_user = NULL;
			src_mail = local->first_saved_mail;
			first_uid = geteuid();
			i_assert(first_uid != 0);
		}
	}
	return first_uid;
}

static int
lmtp_local_open_raw_mail(struct lmtp_local *local,
			 struct istream *input)
{
	static const char *wanted_headers[] = {
		"From", "To", "Message-ID", "Subject", "Return-Path",
		NULL
	};
	struct client *client = local->client;
	struct mailbox *box;
	struct mailbox_transaction_context *mtrans;
	struct mailbox_header_lookup_ctx *headers_ctx;
	enum mail_error error;

	if (raw_mailbox_alloc_stream(client->raw_mail_user, input,
				     (time_t)-1, smtp_address_encode(client->state.mail_from),
				     &box) < 0) {
		i_error("Can't open delivery mail as raw: %s",
			mailbox_get_last_internal_error(box, &error));
		mailbox_free(&box);
		lmtp_local_rcpt_fail_all(local);
		return -1;
	}

	mtrans = mailbox_transaction_begin(box, 0, __func__);

	headers_ctx = mailbox_header_lookup_init(box, wanted_headers);
	local->raw_mail = mail_alloc(mtrans, 0, headers_ctx);
	mailbox_header_lookup_unref(&headers_ctx);
	mail_set_seq(local->raw_mail, 1);
	return 0;
}

void lmtp_local_data(struct client *client, struct istream *input)
{
	struct lmtp_local *local = client->local;
	struct mail_deliver_session *session;
	uid_t old_uid, first_uid;

	if (lmtp_local_open_raw_mail(local, input) < 0)
		return;

	session = mail_deliver_session_init();
	old_uid = geteuid();
	first_uid = lmtp_local_deliver_to_rcpts(local, session);
	mail_deliver_session_deinit(&session);

	if (local->first_saved_mail != NULL) {
		struct mail *mail = local->first_saved_mail;
		struct mailbox_transaction_context *trans = mail->transaction;
		struct mailbox *box = trans->box;
		struct mail_user *user = box->storage->user;

		/* just in case these functions are going to write anything,
		   change uid back to user's own one */
		if (first_uid != old_uid) {
			if (seteuid(0) < 0)
				i_fatal("seteuid(0) failed: %m");
			if (seteuid(first_uid) < 0)
				i_fatal("seteuid() failed: %m");
		}

		mail_free(&mail);
		mailbox_transaction_rollback(&trans);
		mailbox_free(&box);
		mail_user_autoexpunge(user);
		mail_user_unref(&user);
	}

	if (old_uid == 0) {
		/* switch back to running as root, since that's what we're
		   practically doing anyway. it's also important in case we
		   lose e.g. config connection and need to reconnect to it. */
		if (seteuid(0) < 0)
			i_fatal("seteuid(0) failed: %m");
		/* enable core dumping again. we need to chdir also to
		   root-owned directory to get core dumps. */
		restrict_access_allow_coredumps(TRUE);
		if (chdir(base_dir) < 0)
			i_error("chdir(%s) failed: %m", base_dir);
	}
}
