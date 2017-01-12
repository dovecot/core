/* Copyright (c) 2005-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "fd-set-nonblock.h"
#include "istream.h"
#include "istream-seekable.h"
#include "istream-header-filter.h"
#include "abspath.h"
#include "safe-mkstemp.h"
#include "str.h"
#include "str-sanitize.h"
#include "strescape.h"
#include "var-expand.h"
#include "rfc822-parser.h"
#include "message-address.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "mail-storage-service.h"
#include "raw-storage.h"
#include "mail-deliver.h"
#include "mail-send.h"
#include "mbox-from.h"
#include "lda-settings.h"
#include "lmtp-client.h"

#include <stdio.h>
#include <sysexits.h>

#define DEFAULT_ENVELOPE_SENDER "MAILER-DAEMON"
#define DEFAULT_LMTP_PORT 24

/* After buffer grows larger than this, create a temporary file to /tmp
   where to read the mail. */
#define MAIL_MAX_MEMORY_BUFFER (1024*128)

struct client {
	struct mail_storage_service_input service_input;

	bool finished;
	bool success;
	bool tempfail;
	const char *error;
	const char *state;
};

static const char *escape_local_part(const char *local_part)
{
	const char *p;

	/* if local_part isn't dot-atom-text, we need to return quoted-string
	   dot-atom-text = 1*atext *("." 1*atext) */
	for (p = local_part; *p != '\0'; p++) {
		if (!IS_ATEXT(*p) && *p != '.')
			break;
	}
	if (*p != '\0' || *local_part == '.' ||
	    (p != local_part && p[-1] == '.'))
		local_part = t_strdup_printf("\"%s\"", str_escape(local_part));
	return local_part;
}

static const char *address_sanitize(const char *address)
{
	struct message_address *addr;
	const char *ret, *mailbox;
	pool_t pool;

	pool = pool_alloconly_create("address sanitizer", 256);
	addr = message_address_parse(pool, (const unsigned char *)address,
				     strlen(address), 1, FALSE);

	if (addr == NULL || addr->mailbox == NULL || addr->domain == NULL ||
	    *addr->mailbox == '\0')
		ret = DEFAULT_ENVELOPE_SENDER;
	else {
		mailbox = escape_local_part(addr->mailbox);
		if (*addr->domain == '\0')
			ret = t_strdup(mailbox);
		else
			ret = t_strdup_printf("%s@%s", mailbox, addr->domain);
	}
	pool_unref(&pool);
	return ret;
}

static int seekable_fd_callback(const char **path_r, void *context)
{
	struct mail_deliver_context *ctx = context;
	string_t *path;
	int fd;

	path = t_str_new(128);
	mail_user_set_get_temp_prefix(path, ctx->dest_user->set);
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

static struct istream *create_raw_stream(struct mail_deliver_context *ctx,
	int fd, time_t *mtime_r)
{
	struct istream *input, *input2, *input_list[2];
	const unsigned char *data;
	char *sender = NULL;
	size_t i, size;
	int ret, tz;

	*mtime_r = (time_t)-1;
	fd_set_nonblock(fd, FALSE);

	input = i_stream_create_fd(fd, 4096, FALSE);
	input->blocking = TRUE;
	/* If input begins with a From-line, drop it */
	ret = i_stream_read_data(input, &data, &size, 5);
	if (ret > 0 && size >= 5 && memcmp(data, "From ", 5) == 0) {
		/* skip until the first LF */
		i_stream_skip(input, 5);
		while (i_stream_read_data(input, &data, &size, 0) > 0) {
			for (i = 0; i < size; i++) {
				if (data[i] == '\n')
					break;
			}
			if (i != size) {
				(void)mbox_from_parse(data, i, mtime_r, &tz,
						      &sender);
				i_stream_skip(input, i + 1);
				break;
			}
			i_stream_skip(input, size);
		}
	}

	if (sender != NULL && ctx->src_envelope_sender == NULL) {
		/* use the envelope sender from From_-line, but only if it
		   hasn't been specified with -f already. */
		ctx->src_envelope_sender = p_strdup(ctx->pool, sender);
	}
	i_free(sender);

	if (input->v_offset == 0) {
		input2 = input;
		i_stream_ref(input2);
	} else {
		input2 = i_stream_create_limit(input, (uoff_t)-1);
	}
	i_stream_unref(&input);

	input_list[0] = input2; input_list[1] = NULL;
	input = i_stream_create_seekable(input_list, MAIL_MAX_MEMORY_BUFFER,
					 seekable_fd_callback, ctx);
	i_stream_unref(&input2);
	return input;
}

static void set_dest_addr(struct mail_deliver_context *ctx,
	const char *destaddr_source)
{
	if (ctx->dest_addr == NULL &&
	    *ctx->set->lda_original_recipient_header != '\0') {
		ctx->dest_addr = mail_deliver_get_address(ctx->src_mail,
					ctx->set->lda_original_recipient_header);
		destaddr_source = t_strconcat(
			ctx->set->lda_original_recipient_header, " header", NULL);
	}
	if (ctx->final_dest_addr == NULL)
		ctx->final_dest_addr = ctx->dest_addr;

	if (ctx->dest_user->mail_debug && ctx->dest_addr != NULL) {
		i_debug("Destination address: %s (source: %s)",
			ctx->dest_addr, destaddr_source);
	}
}

static void lmtp_client_send_finished(void *context)
{
	struct client *client = context;

	client->finished = TRUE;
	io_loop_stop(current_ioloop);
}

static void lmtp_client_error(struct client *client, const char *state,
	const char *error)
{
	if (client->error == NULL) {
		client->state = state;
		client->error = error;
	}
}

static void rcpt_to_callback(enum lmtp_client_result result, const char *reply,
	void *context)
{
	struct client *client = context;

	if (result != LMTP_CLIENT_RESULT_OK) {
		if (reply[0] != '5')
			client->tempfail = TRUE;
		lmtp_client_error(client, "RCPT", reply);
		lmtp_client_send_finished(client);
	}
}

static void data_callback(enum lmtp_client_result result, const char *reply,
	void *context)
{
	struct client *client = context;

	if (result != LMTP_CLIENT_RESULT_OK) {
		if (reply[0] != '5')
			client->tempfail = TRUE;
		lmtp_client_error(client, "DATA", reply);
		lmtp_client_send_finished(client);
	} else {
		client->success = TRUE;
	}
}

static struct mail_user *client_raw_user_create(
	const struct setting_parser_info *set_info)
{
	void **sets;

	sets = master_service_settings_get_others(master_service);
	return raw_storage_create_from_set(set_info, sets[0]);
}

static void client_read_settings(struct client *client,
	struct mail_deliver_context *ctx,
	struct mail_storage_service_ctx *storage_service,
	const struct setting_parser_info **set_info)
{
	const struct setting_parser_context *set_parser;
	struct lda_settings *lda_set;
	const char *error;

	if (mail_storage_service_read_settings(storage_service,
			&client->service_input, ctx->pool, set_info,
			&set_parser, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	lda_set = master_service_settings_parser_get_others(
		master_service, set_parser)[1];
	settings_var_expand(&lda_setting_parser_info, lda_set, ctx->pool,
		mail_storage_service_get_var_expand_table(storage_service,
			&client->service_input));
	ctx->set = lda_set;
}

static struct mail *client_raw_mail_open(struct mail_deliver_context *ctx,
	const char *path)
{
	static const char *wanted_headers[] = {
		"From", "To", "Message-ID", "Subject", "Return-Path",
		NULL
	};
	struct mailbox *box;
	struct mailbox_transaction_context *trans;
	struct mailbox_header_lookup_ctx *headers_ctx;
	struct mail *raw_mail;
	struct istream *input;
	const char *envelope_sender;
	time_t mtime;
	int ret;

	envelope_sender = ctx->src_envelope_sender != NULL ?
		ctx->src_envelope_sender : DEFAULT_ENVELOPE_SENDER;
	if (path == NULL) {
		input = create_raw_stream(ctx, STDIN_FILENO, &mtime);
		i_stream_set_name(input, "stdin");
		ret = raw_mailbox_alloc_stream(ctx->dest_user, input, mtime,
			envelope_sender, &box);
		i_stream_unref(&input);
	} else {
		ret = raw_mailbox_alloc_path(ctx->dest_user, path, (time_t)-1,
				envelope_sender, &box);
	}
	if (ret < 0) {
		i_fatal("Can't open delivery mail as raw: %s",
			mailbox_get_last_error(box, NULL));
	}

	trans = mailbox_transaction_begin(box, 0);
	headers_ctx = mailbox_header_lookup_init(box, wanted_headers);
	raw_mail = mail_alloc(trans, 0, headers_ctx);
	mailbox_header_lookup_unref(&headers_ctx);
	mail_set_seq(raw_mail, 1);
	return raw_mail;
}

static struct istream *get_filtered_mail_stream(struct mail *_mail)
{
        static const char *hide_headers[] = {
		"Return-Path"
	};
	struct istream *input;

	if (mail_get_stream(_mail, NULL, NULL, &input) < 0)
		return NULL;

	return i_stream_create_header_filter(input,
		HEADER_FILTER_EXCLUDE, hide_headers, N_ELEMENTS(hide_headers),
		*null_header_filter_callback, (void *)NULL);
}

static void failure_exit_callback(int *status)
{
	/* we want all our exit codes to be sysexits.h compatible.
	   if we failed because of a logging related error, we most likely
	   aren't writing to stderr, so try writing there to give some kind of
	   a clue what's wrong. FATAL_LOGOPEN failure already wrote to
	   stderr, so don't duplicate it. */
	switch (*status) {
	case FATAL_LOGWRITE:
		fputs("Failed to write to log file", stderr);
		break;
	case FATAL_LOGERROR:
		fputs("Internal logging error", stderr);
		break;
	case FATAL_LOGOPEN:
	case FATAL_OUTOFMEM:
	case FATAL_EXEC:
	case FATAL_DEFAULT:
		break;
	default:
		return;
	}
	*status = EX_TEMPFAIL;
}

static void print_help(void)
{
	printf(
"Usage: dovecot-rda [-c <config file>] [-a <address>] [-p <path>]\n"
"                   [-f <envelope sender>] [-P SMTP|LMTP] [-e] [-k] host:port\n");
}

int main(int argc, char *argv[])
{
	struct mail_deliver_context ctx;
	struct lmtp_client_settings lmtp_client_set;
	struct lmtp_client *lmtp_client;
	struct ioloop *ioloop;
	struct istream *input;
	struct client client;
	const struct setting_parser_info *set_info;
	enum lmtp_client_protocol protocol = LMTP_CLIENT_PROTOCOL_LMTP;
	struct mail_storage_service_ctx *storage_service;
	enum mail_storage_service_flags storage_service_flags =
		MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT |
		MAIL_STORAGE_SERVICE_FLAG_USE_SYSEXITS;
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_DONT_LOG_TO_STDERR;
	const struct setting_parser_info *set_roots[] = {
		&lda_setting_parser_info,
		NULL
	};
	const char *host, *envelope_sender, *path = NULL;
	bool stderr_rejection = FALSE;
	in_port_t port;
	string_t *mail_log_prefix;
	int c;

	i_set_failure_exit_callback(failure_exit_callback);

	master_service = master_service_init("rda", service_flags,
		&argc, &argv, "a:ef:p:P:r:");

	memset(&ctx, 0, sizeof(ctx));
	ctx.session = mail_deliver_session_init();
	ctx.pool = ctx.session->pool;
	ctx.timeout_secs = LDA_SUBMISSION_TIMEOUT_SECS;
	ctx.delivery_time_started = ioloop_timeval;

	memset(&client, 0, sizeof(client));
	client.service_input.module = "lda";
	client.service_input.service = "rda";
	client.service_input.username = "";

	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'a':
			/* original recipient address */
			ctx.dest_addr = optarg;
			break;
		case 'e':
			stderr_rejection = TRUE;
			break;
		case 'f':
			/* envelope sender address */
			ctx.src_envelope_sender =
				p_strdup(ctx.pool, address_sanitize(optarg));
			break;
		case 'p':
			/* path */
			path = t_abspath(optarg);
			break;
		case 'P':
			/* protocol */
			if (strcasecmp(optarg, "SMTP") == 0)
				protocol = LMTP_CLIENT_PROTOCOL_SMTP;
			else if (strcasecmp(optarg, "LMTP") == 0)
				protocol = LMTP_CLIENT_PROTOCOL_LMTP;
			else
				i_fatal_status(EX_USAGE, "Invalid protocol: %s",
					optarg);
			break;
		case 'r':
			/* final recipient address */
			ctx.final_dest_addr = optarg;
			break;
		default:
			print_help();
			return EX_USAGE;
		}
	}

	host = argv[optind++];
	if (host == NULL) {
		print_help();
		i_fatal_status(EX_USAGE, "LMTP/SMTP host:port missing");
	}
	if (net_str2hostport(host, DEFAULT_LMTP_PORT, &host, &port) < 0)
		i_fatal_status(EX_USAGE, "Invalid LMTP/SMTP host: %s", host);

	if (optind != argc) {
		print_help();
		i_fatal_status(EX_USAGE, "Unknown argument: %s", argv[optind]);
	}

	master_service_init_finish(master_service);

	storage_service = mail_storage_service_init(master_service, set_roots,
		storage_service_flags);

	client_read_settings(&client, &ctx, storage_service, &set_info);
	ctx.dest_user = client_raw_user_create(set_info);
	ctx.src_mail = client_raw_mail_open(&ctx, path);

	set_dest_addr(&ctx, "-a parameter");
	if (ctx.dest_addr == NULL) {
		i_fatal_status(EX_USAGE,
			"recipient address parameter (-a address) not given");
	}

	/* set log prefix */
	mail_log_prefix = t_str_new(256);
	client.service_input.username = ctx.dest_addr;
	var_expand(mail_log_prefix, ctx.dest_user->set->mail_log_prefix,
		mail_storage_service_get_var_expand_table(storage_service,
			&client.service_input));
	master_service_init_log(master_service, str_c(mail_log_prefix));

	memset(&lmtp_client_set, 0, sizeof(lmtp_client_set));
	envelope_sender = mail_deliver_get_return_address(&ctx);
	lmtp_client_set.mail_from = envelope_sender == NULL ? "<>" :
		t_strconcat("<", envelope_sender, ">", NULL);
	lmtp_client_set.my_hostname = ctx.set->hostname;
	lmtp_client_set.timeout_secs = LDA_SUBMISSION_TIMEOUT_SECS;

	ioloop = io_loop_create();
	lmtp_client = lmtp_client_init(&lmtp_client_set,
		lmtp_client_send_finished, &client);

	if (lmtp_client_connect_tcp(lmtp_client, protocol, host, port) < 0) {
		lmtp_client_deinit(&lmtp_client);
		io_loop_destroy(&ioloop);
		i_fatal_status(EX_TEMPFAIL, "Couldn't connect to %s:%u",
			host, port);
	}

	lmtp_client_add_rcpt(lmtp_client, ctx.dest_addr, rcpt_to_callback,
		data_callback, &client);

	if ((input = get_filtered_mail_stream(ctx.src_mail)) == NULL)
		i_fatal_status(EX_TEMPFAIL, "Unable to read mail from mailbox");
	lmtp_client_send(lmtp_client, input);
	i_stream_unref(&input);

	if (!client.finished)
		io_loop_run(ioloop);
	io_loop_destroy(&ioloop);

	if (!client.success) {
		if (stderr_rejection) {
			/* write to stderr also for tempfails so that MTA
			   can log the reason if it wants to. */
			fprintf(stderr, "%s\n", client.error);
		}
		if (client.tempfail)
			return EX_TEMPFAIL;

		ctx.dsn = TRUE;
		mail_deliver_log(&ctx, "rejected: %s",
			str_sanitize(client.error, 512));

		if (stderr_rejection)
			return EX_NOPERM;
		if (mail_send_rejection(&ctx, ctx.dest_addr, client.error) != 0)
			return EX_TEMPFAIL;
	} else {
		mail_deliver_log(&ctx, "delivered mail to %s://%s:%u",
			(protocol == LMTP_CLIENT_PROTOCOL_LMTP) ? "lmtp" : "smtp",
			host, port);
	}

	{
		struct mailbox_transaction_context *t =
			ctx.src_mail->transaction;
		struct mailbox *box = ctx.src_mail->box;

		mail_free(&ctx.src_mail);
		mailbox_transaction_rollback(&t);
		mailbox_free(&box);
	}

	mail_user_unref(&ctx.dest_user);
	mail_deliver_session_deinit(&ctx.session);

	mail_storage_service_deinit(&storage_service);
	master_service_deinit(&master_service);
        return EX_OK;
}
