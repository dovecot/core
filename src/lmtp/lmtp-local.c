/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "time-util.h"
#include "hostpid.h"
#include "var-expand.h"
#include "ioloop.h"
#include "restrict-access.h"
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

void client_rcpt_anvil_disconnect(const struct mail_recipient *rcpt)
{
	const struct mail_storage_service_input *input;

	if (!rcpt->anvil_connect_sent)
		return;

	input = mail_storage_service_user_get_input(rcpt->service_user);
	master_service_anvil_send(master_service, t_strconcat(
		"DISCONNECT\t", my_pid, "\t", master_service_get_name(master_service),
		"/", input->username, "\n", NULL));
}

static void
client_send_line_overquota(struct client *client,
			   const struct mail_recipient *rcpt, const char *error)
{
	struct lda_settings *lda_set =
		mail_storage_service_user_get_set(rcpt->service_user)[2];

	client_send_line(client, "%s <%s> %s",
		lda_set->quota_full_tempfail ? "452 4.2.2" : "552 5.2.2",
		smtp_address_encode(rcpt->address), error);
}

static void
client_rcpt_fail_all(struct client *client)
{
	struct mail_recipient *const *rcptp;

	array_foreach(&client->state.rcpt_to, rcptp) {
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
				 smtp_address_encode((*rcptp)->address));
	}
}

static int
lmtp_rcpt_to_is_over_quota(struct client *client,
			   const struct mail_recipient *rcpt)
{
	struct mail_user *user;
	struct mail_namespace *ns;
	struct mailbox *box;
	struct mailbox_status status;
	const char *errstr;
	enum mail_error error;
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
							    &user, &errstr);

	if (ret < 0) {
		i_error("Failed to initialize user %s: %s",
			smtp_address_encode(rcpt->address), errstr);
		return -1;
	}

	ns = mail_namespace_find_inbox(user->namespaces);
	box = mailbox_alloc(ns->list, "INBOX", 0);
	mailbox_set_reason(box, "over-quota check");
	ret = mailbox_get_status(box, STATUS_CHECK_OVER_QUOTA, &status);
	if (ret < 0) {
		errstr = mailbox_get_last_error(box, &error);
		if (error == MAIL_ERROR_NOQUOTA) {
			client_send_line_overquota(client, rcpt, errstr);
			ret = 1;
		} else {
			i_error("mailbox_get_status(%s, STATUS_CHECK_OVER_QUOTA) "
				"failed: %s",
				mailbox_get_vname(box),
				mailbox_get_last_internal_error(box, NULL));
		}
	}
	mailbox_free(&box);
	mail_user_unref(&user);
	return ret;
}

bool cmd_rcpt_finish(struct client *client, struct mail_recipient *rcpt)
{
	int ret;

	if ((ret = lmtp_rcpt_to_is_over_quota(client, rcpt)) != 0) {
		if (ret < 0) {
			client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
					 smtp_address_encode(rcpt->address));
		}
		mail_storage_service_user_unref(&rcpt->service_user);
		return FALSE;
	}
	array_append(&client->state.rcpt_to, &rcpt, 1);
	client_send_line(client, "250 2.1.5 OK");
	return TRUE;
}

void rcpt_anvil_lookup_callback(const char *reply, void *context)
{
	struct mail_recipient *rcpt = context;
	struct client *client = rcpt->client;
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
				 smtp_address_encode(rcpt->address));
		mail_storage_service_user_unref(&rcpt->service_user);
	} else if (cmd_rcpt_finish(client, rcpt)) {
		rcpt->anvil_connect_sent = TRUE;
		input = mail_storage_service_user_get_input(rcpt->service_user);
		master_service_anvil_send(master_service, t_strconcat(
			"CONNECT\t", my_pid, "\t", master_service_get_name(master_service),
			"/", input->username, "\n", NULL));
	}

	client_io_reset(client);
	client_input_handle(client);
}

static int
client_deliver(struct client *client, const struct mail_recipient *rcpt,
	       struct mail *src_mail, struct mail_deliver_session *session)
{
	struct mail_deliver_context dctx;
	struct mail_user *dest_user;
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

	input = mail_storage_service_user_get_input(rcpt->service_user);
	username = t_strdup(input->username);

	mail_set = mail_storage_service_user_get_mail_set(rcpt->service_user);
	set_parser = mail_storage_service_user_get_settings_parser(rcpt->service_user);
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
	if (mail_storage_service_next(storage_service, rcpt->service_user,
				      &dest_user, &error) < 0) {
		i_error("Failed to initialize user: %s", error);
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
				 smtp_address_encode(rcpt->address));
		return -1;
	}
	client->state.dest_user = dest_user;

	sets = mail_storage_service_user_get_set(rcpt->service_user);
	var_table = mail_user_var_expand_table(dest_user);
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
				 smtp_address_encode(rcpt->address));
		return -1;
	}

	str = t_str_new(256);
	if (var_expand_with_funcs(str, dest_user->set->mail_log_prefix,
				  var_table, mail_user_var_expand_func_table,
				  dest_user, &error) <= 0) {
		i_error("Failed to expand mail_log_prefix=%s: %s",
			dest_user->set->mail_log_prefix, error);
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
				 smtp_address_encode(rcpt->address));
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
	dctx.rcpt_user = dest_user;
	dctx.rcpt_params = rcpt->params;
	if (dctx.rcpt_params.orcpt.addr != NULL) {
		/* used ORCPT */
	} else if (*dctx.set->lda_original_recipient_header != '\0') {
		dctx.rcpt_params.orcpt.addr = mail_deliver_get_address(src_mail,
				dctx.set->lda_original_recipient_header);
	}
	if (dctx.rcpt_params.orcpt.addr == NULL)
		dctx.rcpt_params.orcpt.addr = rcpt->address;
	dctx.rcpt_to = rcpt->address;
	if (*rcpt->detail == '\0' ||
	    !client->lmtp_set->lmtp_save_to_detail_mailbox)
		dctx.rcpt_default_mailbox = "INBOX";
	else {
		ns = mail_namespace_find_inbox(dest_user->namespaces);
		dctx.rcpt_default_mailbox =
			t_strconcat(ns->prefix, rcpt->detail, NULL);
	}

	dctx.save_dest_mail = array_count(&client->state.rcpt_to) > 1 &&
		client->state.first_saved_mail == NULL;

	dctx.session_time_msecs =
		timeval_diff_msecs(&client->state.data_end_timeval,
				   &client->state.mail_from_timeval);
	dctx.delivery_time_started = delivery_time_started;

	if (mail_deliver(&dctx, &storage) == 0) {
		if (dctx.dest_mail != NULL) {
			i_assert(client->state.first_saved_mail == NULL);
			client->state.first_saved_mail = dctx.dest_mail;
		}
		client_send_line(client, "250 2.0.0 <%s> %s Saved",
				 smtp_address_encode(rcpt->address),
				 rcpt->session_id);
		ret = 0;
	} else if (dctx.tempfail_error != NULL) {
		client_send_line(client, "451 4.2.0 <%s> %s",
				 smtp_address_encode(rcpt->address),
				 dctx.tempfail_error);
		ret = -1;
	} else if (storage != NULL) {
		error = mail_storage_get_last_error(storage, &mail_error);
		if (mail_error == MAIL_ERROR_NOQUOTA) {
			client_send_line_overquota(client, rcpt, error);
		} else {
			client_send_line(client, "451 4.2.0 <%s> %s",
					 smtp_address_encode(rcpt->address), error);
		}
		ret = -1;
	} else {
		/* This shouldn't happen */
		i_error("BUG: Saving failed to unknown storage");
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
				 smtp_address_encode(rcpt->address));
		ret = -1;
	}
	return ret;
}

static bool client_rcpt_to_is_last(struct client *client)
{
	return client->state.rcpt_idx >= array_count(&client->state.rcpt_to);
}

static uid_t client_deliver_to_rcpts(struct client *client,
				     struct mail_deliver_session *session)
{
	uid_t first_uid = (uid_t)-1;
	struct mail *src_mail;

	struct mail_recipient *const *rcpts;
	unsigned int count;
	int ret;
	src_mail = client->state.raw_mail;

	rcpts = array_get(&client->state.rcpt_to, &count);
	while (client->state.rcpt_idx < count) {
		ret = client_deliver(client, rcpts[client->state.rcpt_idx],
				     src_mail, session);
		client_state_set(client, "DATA", "");
		i_set_failure_prefix("lmtp(%s): ", my_pid);

		client->state.rcpt_idx++;

		/* succeeded and mail_user is not saved in first_saved_mail */
		if ((ret == 0 &&
		     (client->state.first_saved_mail == NULL ||
		      client->state.first_saved_mail == src_mail)) ||
		    /* failed. try the next one. */
		    (ret != 0 && client->state.dest_user != NULL)) {
			if (client_rcpt_to_is_last(client))
				mail_user_autoexpunge(client->state.dest_user);
			mail_user_unref(&client->state.dest_user);
		} else if (ret == 0) {
			/* use the first saved message to save it elsewhere too.
			   this might allow hard linking the files.
			   mail_user is saved in first_saved_mail,
			   will be unreferenced later on */
			client->state.dest_user = NULL;
			src_mail = client->state.first_saved_mail;
			first_uid = geteuid();
			i_assert(first_uid != 0);
		}
	}
	return first_uid;
}

static int client_open_raw_mail(struct client *client, struct istream *input)
{
	static const char *wanted_headers[] = {
		"From", "To", "Message-ID", "Subject", "Return-Path",
		NULL
	};
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	struct mailbox_header_lookup_ctx *headers_ctx;
	enum mail_error error;

	if (raw_mailbox_alloc_stream(client->raw_mail_user, input,
				     (time_t)-1, smtp_address_encode(client->state.mail_from),
				     &box) < 0) {
		i_error("Can't open delivery mail as raw: %s",
			mailbox_get_last_internal_error(box, &error));
		mailbox_free(&box);
		client_rcpt_fail_all(client);
		return -1;
	}

	trans = mailbox_transaction_begin(box, 0, __func__);

	headers_ctx = mailbox_header_lookup_init(box, wanted_headers);
	client->state.raw_mail = mail_alloc(trans, 0, headers_ctx);
	mailbox_header_lookup_unref(&headers_ctx);
	mail_set_seq(client->state.raw_mail, 1);
	return 0;
}

void client_input_data_write_local(struct client *client, struct istream *input)
{
	struct mail_deliver_session *session;
	uid_t old_uid, first_uid;

	if (client_open_raw_mail(client, input) < 0)
		return;

	session = mail_deliver_session_init();
	old_uid = geteuid();
	first_uid = client_deliver_to_rcpts(client, session);
	mail_deliver_session_deinit(&session);

	if (client->state.first_saved_mail != NULL) {
		struct mail *mail = client->state.first_saved_mail;
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
